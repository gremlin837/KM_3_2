"""
orchestrator/orchestrator.py
Оркестратор — брокер сообщений между клиентом и сервером.

Роль:
  • Принимает запросы от клиента (порт 8001).
  • Ставит запросы в очередь (asyncio.Queue) — гарантирует порядок.
  • Следит за перегрузкой:
      – мягкий rate-limit: > N запросов за окно → 429
      – жёсткий блок: > block_threshold запросов за окно → IP блокируется навсегда
        (п. 4.1.3: «если с одного IP летит миллион запросов — заблокировать IP»)
  • Форвардит валидные запросы на сервер (порт 8000) через httpx.
  • Логирует все события аудита согласно п. 3.3.

Запуск:
    cd project
    uvicorn orchestrator.orchestrator:app --host 127.0.0.1 --port 8001
"""

import time
import asyncio
import logging
from collections import defaultdict, deque
from typing import Dict, Deque, Set

import httpx
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse

from database import config
from audit_service import AuditSystemFactory

# ── логгер ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [ORCH] %(levelname)s %(message)s")
log = logging.getLogger("orchestrator")

# ── FastAPI приложение ───────────────────────────────────────────────────────
app = FastAPI(title="TES Orchestrator / Message Broker", version="1.0")

# ── URL основного сервера ────────────────────────────────────────────────────
SERVER_BASE = f"http://{config.server_host}:{config.server_port}"

# ── Система аудита оркестратора ──────────────────────────────────────────────
_audit_service, _rotation_mgr, _ = AuditSystemFactory.create_default_system(
    db_path="audit_orchestrator.db",
    max_size_mb=config.audit_max_size_mb
)

# ── Очередь сообщений ────────────────────────────────────────────────────────
# asyncio.Queue — буфер между приёмом запросов и их обработкой.
# Если очередь заполнена (>queue_max_size) — отвечаем 503.
_queue: asyncio.Queue = asyncio.Queue(maxsize=config.queue_max_size)


# ── Структуры rate-limit / блокировки ───────────────────────────────────────
class IPGuard:
    """
    Следит за частотой запросов с каждого IP.

    Мягкий лимит  : config.rate_limit_max  за config.rate_limit_window сек → 429
    Жёсткий блок  : config.block_threshold за config.block_window_sec  сек → 403
                    IP заносится в _blocked_ips (персистентный в рамках сессии).

    п. 4.1.3 ТЗ: «При использовании API должен использоваться механизм
    ограничения частоты запросов для предотвращения атаки на основе
    перегрузки сервера (DDoS)»
    """

    def __init__(self):
        # {ip: deque of timestamps} — скользящее окно для мягкого лимита
        self._soft: Dict[str, Deque[float]] = defaultdict(deque)
        # {ip: deque of timestamps} — скользящее окно для жёсткого блока
        self._hard: Dict[str, Deque[float]] = defaultdict(deque)
        # Навсегда заблокированные IP
        self._blocked: Set[str] = set()

    def check(self, ip: str) -> tuple[bool, str, int]:
        """
        Возвращает (allowed: bool, reason: str, http_code: int).
        """
        now = time.monotonic()

        # 1. Жёсткая блокировка
        if ip in self._blocked:
            log.warning("BLOCKED IP attempt: %s", ip)
            return False, f"IP {ip} заблокирован за DDoS-активность.", 403

        # 2. Очищаем устаревшие записи жёсткого окна
        hard_window = config.block_window_sec
        hard_q = self._hard[ip]
        while hard_q and now - hard_q[0] > hard_window:
            hard_q.popleft()

        hard_q.append(now)

        if len(hard_q) > config.block_threshold:
            # Превышен порог → блокируем IP навсегда (в рамках сессии)
            self._blocked.add(ip)
            log.critical("IP PERMANENTLY BLOCKED: %s (%d rps)", ip, len(hard_q))
            _audit_service.log_api_request(
                "SYSTEM", "/orchestrator/block", "BLOCK",
                403, 0.0
            )
            return False, (
                f"IP {ip} заблокирован: превышен порог "
                f"{config.block_threshold} запросов за {hard_window} сек."
            ), 403

        # 3. Мягкий rate-limit
        soft_window = config.rate_limit_window
        soft_q = self._soft[ip]
        while soft_q and now - soft_q[0] > soft_window:
            soft_q.popleft()

        if len(soft_q) >= config.rate_limit_max:
            log.warning("Rate-limit hit: %s (%d req / %ds)",
                        ip, len(soft_q), soft_window)
            return False, (
                f"Превышен лимит {config.rate_limit_max} "
                f"запросов за {soft_window} сек. Подождите."
            ), 429

        soft_q.append(now)
        return True, "OK", 200

    def get_blocked_ips(self) -> list[str]:
        return list(self._blocked)

    def unblock_ip(self, ip: str) -> bool:
        if ip in self._blocked:
            self._blocked.discard(ip)
            self._hard[ip].clear()
            log.info("IP unblocked by admin: %s", ip)
            return True
        return False


ip_guard = IPGuard()


# ── Middleware: rate-limit на каждый входящий запрос ────────────────────────
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"

    # Исключаем служебные эндпоинты оркестратора от проверки
    if request.url.path.startswith("/orch/"):
        return await call_next(request)

    allowed, reason, code = ip_guard.check(ip)
    if not allowed:
        _audit_service.log_auth_failed("unknown", ip, reason)
        return JSONResponse(
            status_code=code,
            content={"detail": reason, "ip": ip}
        )
    return await call_next(request)


# ── Фоновая задача: воркер очереди ──────────────────────────────────────────
async def queue_worker():
    """
    Брокер сообщений: забирает задачи из очереди и отправляет на сервер.
    Гарантирует упорядоченную обработку и защищает сервер от пиковых нагрузок.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            task = await _queue.get()
            method   = task["method"]
            path     = task["path"]
            payload  = task.get("payload")
            headers  = task.get("headers", {})
            future: asyncio.Future = task["future"]
            t0 = time.monotonic()
            try:
                resp = await client.request(
                    method,
                    f"{SERVER_BASE}{path}",
                    json=payload,
                    headers=headers
                )
                future.set_result(resp)
                elapsed = (time.monotonic() - t0) * 1000
                log.info("→ server %s %s [%d] %.1fms",
                         method, path, resp.status_code, elapsed)
                _audit_service.log_api_request(
                    headers.get("X-Username", "unknown"),
                    path, method, resp.status_code, elapsed
                )
            except Exception as exc:
                log.error("Queue worker error: %s", exc)
                future.set_exception(exc)
            finally:
                _queue.task_done()


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(queue_worker())
    _rotation_mgr.auto_check()
    log.info("Orchestrator started. Server: %s", SERVER_BASE)
    log.info("Block threshold: %d req / %ds",
             config.block_threshold, config.block_window_sec)


# ── Универсальный proxy-эндпоинт ────────────────────────────────────────────
async def _enqueue_and_wait(method: str, path: str,
                             payload: dict | None,
                             headers: dict) -> httpx.Response:
    """
    Кладёт запрос в очередь и ждёт результата.
    Если очередь переполнена — 503.
    """
    loop = asyncio.get_event_loop()
    future: asyncio.Future = loop.create_future()
    task = {
        "method": method, "path": path,
        "payload": payload, "headers": headers,
        "future": future
    }
    try:
        _queue.put_nowait(task)
    except asyncio.QueueFull:
        raise HTTPException(
            status_code=503,
            detail="Сервер перегружен. Очередь заполнена. Повторите позже."
        )
    return await future


# ── API эндпоинты (проксирование к серверу) ─────────��───────────────────────

@app.post("/api/auth/login")
async def proxy_login(request: Request):
    body = await request.json()
    resp = await _enqueue_and_wait(
        "POST", "/api/auth/login", body,
        {"Content-Type": "application/json",
         "X-Forwarded-For": request.client.host if request.client else ""}
    )
    return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.post("/api/auth/change-password")
async def proxy_change_password(request: Request):
    body    = await request.json()
    token   = request.headers.get("Authorization", "")
    ip      = request.client.host if request.client else ""
    resp = await _enqueue_and_wait(
        "POST", "/api/auth/change-password", body,
        {"Content-Type": "application/json",
         "Authorization": token, "X-Forwarded-For": ip}
    )
    return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.post("/api/calculate")
async def proxy_calculate(request: Request):
    body  = await request.json()
    token = request.headers.get("Authorization", "")
    ip    = request.client.host if request.client else ""

    # Извлекаем имя пользователя из токена для аудита
    try:
        import jwt as _jwt
        pl = _jwt.decode(token.replace("Bearer ", ""),
                         config.jwt_secret,
                         algorithms=[config.jwt_algorithm])
        username = pl.get("sub", "unknown")
    except Exception:
        username = "unknown"

    resp = await _enqueue_and_wait(
        "POST", "/api/calculate", body,
        {"Content-Type": "application/json",
         "Authorization": token,
         "X-Forwarded-For": ip,
         "X-Username": username}
    )
    _audit_service.log_interface_input(username, "/api/calculate", body)
    return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.post("/api/analyze/temperature")
async def proxy_temp_analysis(request: Request):
    body  = await request.json()
    token = request.headers.get("Authorization", "")
    ip    = request.client.host if request.client else ""
    resp  = await _enqueue_and_wait(
        "POST", "/api/analyze/temperature", body,
        {"Content-Type": "application/json",
         "Authorization": token, "X-Forwarded-For": ip}
    )
    return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.get("/api/audit/events")
async def proxy_audit_events(request: Request):
    token = request.headers.get("Authorization", "")
    ip    = request.client.host if request.client else ""
    params = dict(request.query_params)
    resp  = await _enqueue_and_wait(
        "GET", "/api/audit/events?" + "&".join(f"{k}={v}" for k,v in params.items()),
        None,
        {"Authorization": token, "X-Forwarded-For": ip}
    )
    return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.get("/api/admin/users")
async def proxy_get_users(request: Request):
    token = request.headers.get("Authorization", "")
    ip    = request.client.host if request.client else ""
    resp  = await _enqueue_and_wait(
        "GET", "/api/admin/users", None,
        {"Authorization": token, "X-Forwarded-For": ip}
    )
    return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.post("/api/admin/users")
async def proxy_create_user(request: Request):
    body  = await request.json()
    token = request.headers.get("Authorization", "")
    ip    = request.client.host if request.client else ""
    resp  = await _enqueue_and_wait(
        "POST", "/api/admin/users", body,
        {"Content-Type": "application/json",
         "Authorization": token, "X-Forwarded-For": ip}
    )
    return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.delete("/api/admin/users/{username}")
async def proxy_delete_user(username: str, request: Request):
    token = request.headers.get("Authorization", "")
    ip    = request.client.host if request.client else ""
    resp  = await _enqueue_and_wait(
        "DELETE", f"/api/admin/users/{username}", None,
        {"Authorization": token, "X-Forwarded-For": ip}
    )
    return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.post("/api/admin/users/{username}/reset-password")
async def proxy_reset_pwd(username: str, request: Request):
    body  = await request.json()
    token = request.headers.get("Authorization", "")
    ip    = request.client.host if request.client else ""
    resp  = await _enqueue_and_wait(
        "POST", f"/api/admin/users/{username}/reset-password", body,
        {"Content-Type": "application/json",
         "Authorization": token, "X-Forwarded-For": ip}
    )
    return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.post("/api/admin/users/{username}/lock")
async def proxy_lock(username: str, request: Request):
    body  = await request.json()
    token = request.headers.get("Authorization", "")
    ip    = request.client.host if request.client else ""
    resp  = await _enqueue_and_wait(
        "POST", f"/api/admin/users/{username}/lock", body,
        {"Content-Type": "application/json",
         "Authorization": token, "X-Forwarded-For": ip}
    )
    return JSONResponse(status_code=resp.status_code, content=resp.json())


# ── Служебные эндпоинты оркестратора (не проксируются) ──────────────────────

@app.get("/orch/health")
async def health():
    """Проверка работоспособности оркестратора."""
    return {
        "status": "ok",
        "queue_size": _queue.qsize(),
        "queue_max": config.queue_max_size,
        "blocked_ips_count": len(ip_guard.get_blocked_ips()),
        "server_url": SERVER_BASE
    }


@app.get("/orch/blocked-ips")
async def get_blocked_ips(request: Request):
    """Список заблокированных IP (только для диагностики)."""
    return {"blocked_ips": ip_guard.get_blocked_ips()}


@app.post("/orch/unblock/{ip_address}")
async def unblock_ip(ip_address: str, request: Request):
    """Разблокировать IP (администратор вызывает вручную)."""
    ok = ip_guard.unblock_ip(ip_address)
    if ok:
        _audit_service.log_admin_action(
            "system", f"unblock_ip_{ip_address}", {"ip": ip_address}
        )
        return {"detail": f"IP {ip_address} разблокирован"}
    raise HTTPException(status_code=404, detail="IP не найден в списке блокировок")