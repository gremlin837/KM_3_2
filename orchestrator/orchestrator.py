"""orchestrator/orchestrator.py
Оркестратор — брокер сообщений между клиентом и сервером (порт 8001).
Запуск: uvicorn orchestrator:app --host 127.0.0.1 --port 8001 itnoMPEI12345!  Admin@12345
"""
import time, asyncio, logging, jwt
from collections import defaultdict, deque
from typing import Dict, Deque, Set
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

from storage.database import config
from audit.audit_service import AuditSystemFactory

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ORCH] %(levelname)s %(message)s")
log = logging.getLogger("orchestrator")

SERVER_BASE = f"http://{config.server_host}:{config.server_port}"
_audit, _rot_mgr, _ = AuditSystemFactory.create_default_system(db_path="../audit_orchestrator.db", max_size_mb=config.audit_max_size_mb)
_queue: asyncio.Queue = asyncio.Queue(maxsize=config.queue_max_size)
_background_tasks = set()

class IPGuard:
    def __init__(self):
        self._soft: Dict[str, Deque[float]] = defaultdict(deque)
        self._hard: Dict[str, Deque[float]] = defaultdict(deque)
        self._blocked: Set[str] = set()

    def check(self, ip: str):
        now = time.monotonic()
        if ip in self._blocked:
            return False, f"IP {ip} заблокирован за DDoS-активность.", 403

        hard_q = self._hard[ip]
        while hard_q and now - hard_q[0] > config.block_window_sec: hard_q.popleft()
        hard_q.append(now)
        if len(hard_q) > config.block_threshold:
            self._blocked.add(ip)
            return False, f"IP {ip} заблокирован: превышен порог {config.block_threshold} за {config.block_window_sec} сек.", 403

        soft_q = self._soft[ip]
        while soft_q and now - soft_q[0] > config.rate_limit_window: soft_q.popleft()
        if len(soft_q) >= config.rate_limit_max:
            return False, f"Превышен лимит {config.rate_limit_max} за {config.rate_limit_window} сек.", 429
        soft_q.append(now)
        return True, "OK", 200

    def get_blocked_ips(self): return list(self._blocked)
    def unblock_ip(self, ip: str) -> bool:
        if ip in self._blocked:
            self._blocked.discard(ip); self._hard[ip].clear()
            return True
        return False

ip_guard = IPGuard()

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(queue_worker())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    _rot_mgr.auto_check()
    log.info("Orchestrator started. Server: %s", SERVER_BASE)
    yield
    # Graceful shutdown: отправляем сигнал завершения и ждем
    try: _queue.put_nowait(None)
    except: pass
    await task

app = FastAPI(title="TES Orchestrator", version="1.0", lifespan=lifespan)

async def queue_worker():
    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            task = await _queue.get()
            if task is None: # Сигнал выхода
                _queue.task_done()
                break
            try:
                resp = await client.request(
                    task["method"], f"{SERVER_BASE}{task['path']}",
                    json=task.get("payload"), headers=task.get("headers", {})
                )
                task["future"].set_result(resp)
                _audit.log_api_request(task["headers"].get("X-Username", "unknown"), task["path"],
                                       task["method"], resp.status_code, 0.0)
            except Exception as exc:
                task["future"].set_exception(exc)
            finally:
                _queue.task_done()

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    ip = request.client.host or "unknown"
    if request.url.path.startswith("/orch/"):
        return await call_next(request)
    allowed, reason, code = ip_guard.check(ip)
    if not allowed:
        _audit.log_auth_failed("unknown", ip, reason)
        return JSONResponse(status_code=code, content={"detail": reason, "ip": ip})
    return await call_next(request)

async def _enqueue_and_wait(method: str, path: str, payload, headers: dict):
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    try:
        _queue.put_nowait({"method": method, "path": path, "payload": payload, "headers": headers, "future": future})
    except asyncio.QueueFull:
        raise HTTPException(status_code=503, detail="Сервер перегружен. Повторите позже.")
    return await future

# ── Прокси-эндпоинты ──
@app.post("/api/auth/login")
async def proxy_login(request: Request):
    body = await request.json()
    resp = await _enqueue_and_wait("POST", "/api/auth/login", body, {"Content-Type": "application/json", "X-Forwarded-For": request.client.host or ""})
    return JSONResponse(status_code=resp.status_code, content=resp.json())

@app.post("/api/auth/change-password")
async def proxy_change_pwd(request: Request):
    body = await request.json()
    resp = await _enqueue_and_wait("POST", "/api/auth/change-password", body, {"Content-Type": "application/json", "Authorization": request.headers.get("Authorization", ""), "X-Forwarded-For": request.client.host or ""})
    return JSONResponse(status_code=resp.status_code, content=resp.json())

@app.post("/api/calculate")
async def proxy_calc(request: Request):
    body = await request.json()
    token = request.headers.get("Authorization", "")
    try:
        pl = jwt.decode(token.replace("Bearer ", ""), config.jwt_secret, algorithms=[config.jwt_algorithm])
        username = pl.get("sub", "unknown")
    except: username = "unknown"
    headers = {"Content-Type": "application/json", "Authorization": token, "X-Forwarded-For": request.client.host or "", "X-Username": username}
    resp = await _enqueue_and_wait("POST", "/api/calculate", body, headers)
    _audit.log_interface_input(username, "/api/calculate", body)
    return JSONResponse(status_code=resp.status_code, content=resp.json())

@app.post("/api/analyze/temperature")
async def proxy_temp(request: Request):
    body = await request.json()
    resp = await _enqueue_and_wait("POST", "/api/analyze/temperature", body, {"Content-Type": "application/json", "Authorization": request.headers.get("Authorization", ""), "X-Forwarded-For": request.client.host or ""})
    return JSONResponse(status_code=resp.status_code, content=resp.json())

@app.get("/api/audit/events")
async def proxy_audit(request: Request):
    params = dict(request.query_params)
    qstr = "&".join(f"{k}={v}" for k,v in params.items())
    resp = await _enqueue_and_wait("GET", f"/api/audit/events?{qstr}" if qstr else "/api/audit/events", None, {"Authorization": request.headers.get("Authorization", ""), "X-Forwarded-For": request.client.host or ""})
    return JSONResponse(status_code=resp.status_code, content=resp.json())

@app.get("/api/admin/users")
async def proxy_users(request: Request):
    resp = await _enqueue_and_wait("GET", "/api/admin/users", None, {"Authorization": request.headers.get("Authorization", ""), "X-Forwarded-For": request.client.host or ""})
    return JSONResponse(status_code=resp.status_code, content=resp.json())

@app.post("/api/admin/users")
async def proxy_create(request: Request):
    body = await request.json()
    resp = await _enqueue_and_wait("POST", "/api/admin/users", body, {"Content-Type": "application/json", "Authorization": request.headers.get("Authorization", ""), "X-Forwarded-For": request.client.host or ""})
    return JSONResponse(status_code=resp.status_code, content=resp.json())

@app.delete("/api/admin/users/{username}")
async def proxy_delete(username: str, request: Request):
    resp = await _enqueue_and_wait("DELETE", f"/api/admin/users/{username}", None, {"Authorization": request.headers.get("Authorization", ""), "X-Forwarded-For": request.client.host or ""})
    return JSONResponse(status_code=resp.status_code, content=resp.json())

@app.post("/api/admin/users/{username}/reset-password")
async def proxy_reset(username: str, request: Request):
    body = await request.json()
    resp = await _enqueue_and_wait("POST", f"/api/admin/users/{username}/reset-password", body, {"Content-Type": "application/json", "Authorization": request.headers.get("Authorization", ""), "X-Forwarded-For": request.client.host or ""})
    return JSONResponse(status_code=resp.status_code, content=resp.json())

@app.post("/api/admin/users/{username}/lock")
async def proxy_lock(username: str, request: Request):
    body = await request.json()
    resp = await _enqueue_and_wait("POST", f"/api/admin/users/{username}/lock", body, {"Content-Type": "application/json", "Authorization": request.headers.get("Authorization", ""), "X-Forwarded-For": request.client.host or ""})
    return JSONResponse(status_code=resp.status_code, content=resp.json())

@app.get("/orch/health")
async def health():
    return {"status": "ok", "queue_size": _queue.qsize(), "server_url": SERVER_BASE}