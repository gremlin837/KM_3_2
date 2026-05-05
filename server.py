"""
server/server.py
Серверная часть на FastAPI (порт 8000).
Содержит: аутентификацию, расчёты, аудит, управление пользователями.
Скопировано и адаптировано из main_v2.py.

Запуск:
    cd project
    uvicorn server.server:app --host 127.0.0.1 --port 8000
"""

import time
from typing import Optional
from datetime import datetime

import jwt as _jwt
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from database import config, Database
from auth_system import AuthSystem
from audit_service import AuditSystemFactory
from calculator import calc_tes_efficiency, analyze_temperature

# ── Приложение ───────────────────────────────────────────────────────────────
app = FastAPI(title="TES Server API", version="1.0")

# ── Зависимости ──────────────────────────────────────────────────────────────
_auth       = AuthSystem()
_auth.create_admin_if_empty()

_audit_service, _rotation_mgr, _exporter = AuditSystemFactory.create_default_system(
    db_path="audit_events.db",
    max_size_mb=config.audit_max_size_mb
)
_audit_service.enabled_types = config.audit_enabled_types

security = HTTPBearer(auto_error=False)


def _decode_token(token: str) -> dict:
    try:
        return _jwt.decode(token, config.jwt_secret,
                           algorithms=[config.jwt_algorithm])
    except Exception:
        raise HTTPException(status_code=401, detail="Недействительный токен")


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    return _decode_token(credentials.credentials)


def require_admin(payload: dict = Depends(get_current_user)) -> dict:
    if not payload.get("is_admin"):
        raise HTTPException(status_code=403, detail="Требуются права администратора")
    return payload


# ── Pydantic модели ──────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class CalcRequest(BaseModel):
    total_load:              float = 400
    num_blocks:              int   = 2
    nominal_power_per_block: float = 300
    nominal_efficiency:      float = 0.38
    temp_c:                  float = 25
    humidity:                float = 60
    wind_speed:              float = 3
    wind_dir:                float = 90
    own_needs_coeff:         float = 0.05
    beta:                    float = 0.4

class TempAnalysisRequest(BaseModel):
    total_load:        float = 400
    num_blocks:        int   = 2
    nominal_power:     float = 300
    nominal_efficiency:float = 0.38
    humidity:          float = 60
    wind_speed:        float = 3
    wind_dir:          float = 90

class CreateUserRequest(BaseModel):
    username: str
    password: str
    is_admin: bool = False

class ResetPasswordRequest(BaseModel):
    new_password: str

class LockRequest(BaseModel):
    lock: bool


# ── Аутентификация ───────────────────────────────────────────────────────────

@app.post("/api/auth/login")
async def login(body: LoginRequest, request: Request):
    """
    Аутентификация пользователя.
    Возвращает JWT токен при успехе.
    Регистрирует события аудита согласно п. 3.3.1.
    """
    ip = request.headers.get("X-Forwarded-For", "127.0.0.1")
    t0 = time.monotonic()

    ok, msg, acc = _auth.auth(body.username, body.password)

    elapsed = (time.monotonic() - t0) * 1000
    _audit_service.log_api_request(
        body.username, "/api/auth/login", "POST",
        200 if ok else 401, elapsed
    )

    if not ok:
        if "Требуется смена пароля" in msg:
            # Сигнализируем клиенту, что нужна смена пароля
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"msg": msg, "need_change": True}
            )
        _audit_service.log_auth_failed(body.username, ip, msg)
        raise HTTPException(status_code=401, detail=msg)

    token = _auth.create_token(body.username, acc.is_admin)
    _audit_service.log_auth_login(body.username, ip, "API")
    _audit_service.log_api_auth_info(
        body.username, "password", "Bearer", True
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": body.username,
        "is_admin": acc.is_admin
    }


@app.post("/api/auth/logout")
async def logout(payload: dict = Depends(get_current_user)):
    _audit_service.log_auth_logout(payload["sub"], 0)
    return {"detail": "Выход выполнен"}


@app.post("/api/auth/change-password")
async def change_password(body: ChangePasswordRequest,
                          payload: dict = Depends(get_current_user)):
    """Смена пароля текущего пользователя (п. 3.2)."""
    username = payload["sub"]
    acc = _auth._load(username)
    if not acc:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    if not _auth.hasher.verify_password(body.old_password, acc.password):
        raise HTTPException(status_code=400, detail="Неверный текущий пароль")

    ok, msg = _auth.change(acc, body.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    _audit_service.log_user_data_change(username, ["password"], username)
    return {"detail": "Пароль изменён. Выполните вход заново."}


# ── Расчёты (математическое ядро) ────────────────────────────────────────────

@app.post("/api/calculate")
async def calculate(body: CalcRequest,
                    payload: dict = Depends(get_current_user)):
    """
    Расчёт эффективности ТЭС.
    Выходные данные согласно ТЗ:
      Нагрузка на энергоблок, КПД блока, КПД ТЭС брутто,
      Собственные нужды, КПД ТЭС нетто, Удельный расход топлива.
    """
    username = payload["sub"]
    t0 = time.monotonic()

    result = calc_tes_efficiency(
        total_load=body.total_load,
        num_blocks=body.num_blocks,
        nominal_power_per_block=body.nominal_power_per_block,
        nominal_efficiency=body.nominal_efficiency,
        temp_c=body.temp_c,
        humidity=body.humidity,
        wind_speed=body.wind_speed,
        wind_dir=body.wind_dir,
        own_needs_coeff=body.own_needs_coeff,
        beta=body.beta
    )

    # Формируем выходные данные согласно ТЗ
    output = {
        "Нагрузка на энергоблок":    round(result["load_per_block"], 2),
        "КПД блока":                 round(result["block_efficiency"] * 100, 2),
        "КПД ТЭС брутто":            round(result["efficiency_brutto"] * 100, 2),
        "Собственные нужды":         round(result["own_needs_percent"], 2),
        "КПД ТЭС нетто":             round(result["efficiency_netto"] * 100, 2),
        "Удельный расход топлива":   round(result["fuel_consumption"], 1),
    }

    elapsed = (time.monotonic() - t0) * 1000
    _audit_service.log_api_request(username, "/api/calculate", "POST", 200, elapsed)
    _audit_service.log_interface_input(username, "/api/calculate", body.model_dump())
    _audit_service.log_interface_output(username, "/api/calculate", str(output))

    return output


@app.post("/api/analyze/temperature")
async def temperature_analysis(body: TempAnalysisRequest,
                                payload: dict = Depends(get_current_user)):
    """Зависимость КПД от температуры для построения графиков."""
    temps, effs, fuels = analyze_temperature(
        total_load=body.total_load,
        num_blocks=body.num_blocks,
        nominal_power=body.nominal_power,
        nominal_efficiency=body.nominal_efficiency,
        humidity=body.humidity,
        wind_speed=body.wind_speed,
        wind_dir=body.wind_dir
    )
    return {
        "temperatures":       temps,
        "efficiencies_netto": effs,
        "fuel_rates":         fuels
    }


# ── Аудит ────────────────────────────────────────────────────────────────────

@app.get("/api/audit/events")
async def get_audit_events(
    limit: int = 100,
    event_type: Optional[str] = None,
    subject: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    payload: dict = Depends(get_current_user)
):
    """Получить журнал событий (п. 3.3). Только для авторизованных."""
    filters = {}
    if event_type: filters["event_type"] = event_type
    if subject:    filters["subject"]    = subject
    if date_from:  filters["date_from"]  = date_from
    if date_to:    filters["date_to"]    = date_to

    events = _audit_service.storage.get_events(
        filters=filters if filters else None, limit=limit
    )
    _audit_service.log_api_request(
        payload["sub"], "/api/audit/events", "GET", 200, 0
    )
    return [e.to_dict() for e in events]


# ── Управление пользователями (только администратор) ─────────────────────────

@app.get("/api/admin/users")
async def admin_get_users(payload: dict = Depends(require_admin)):
    """Список пользователей (п. 3.2)."""
    db = Database()
    users = db.all_users()
    # Убираем хеш пароля из ответа (п. 3.3.3)
    now = int(time.time())
    return [
        {
            "username":   u["username"],
            "is_admin":   bool(u["is_admin"]),
            "failed":     u["failed"],
            "locked":     u["locked_until"] > now,
            "need_change":bool(u["need_change"]),
            "created_at": datetime.fromtimestamp(
                u["created_at"] - config.time_offset * 3600
            ).strftime('%Y-%m-%d %H:%M') if u["created_at"] else "—",
            "last_login": datetime.fromtimestamp(
                u["last_login"] - config.time_offset * 3600
            ).strftime('%Y-%m-%d %H:%M') if u["last_login"] else "—",
        }
        for u in users
    ]


@app.post("/api/admin/users")
async def admin_create_user(body: CreateUserRequest,
                             payload: dict = Depends(require_admin)):
    """Создание пользователя администратором (п. 3.2)."""
    admin_acc = _auth._load(payload["sub"])
    dlg_acc   = type('Fake', (), {'is_admin': True})()

    # Проверка сложности пароля
    v, m = _auth._check_pwd(body.password, body.is_admin)
    if not v: raise HTTPException(status_code=400, detail=m)
    v, m = _auth._not_contain_user(body.password, body.username)
    if not v: raise HTTPException(status_code=400, detail=m)

    if _auth.db.get_user(body.username):
        raise HTTPException(status_code=409, detail="Пользователь уже существует")

    h  = _auth.hasher.hash_password(body.password)['hash']
    ok = _auth.db.create_user(body.username, h, body.is_admin)
    if not ok:
        raise HTTPException(status_code=500, detail="Ошибка создания пользователя")

    _audit_service.log_admin_action(
        payload["sub"], "create_user",
        {"created_user": body.username, "is_admin": body.is_admin}
    )
    return {"detail": f"Пользователь '{body.username}' создан"}


@app.delete("/api/admin/users/{username}")
async def admin_delete_user(username: str,
                             payload: dict = Depends(require_admin)):
    """Удаление пользователя (п. 3.2)."""
    if username == payload["sub"]:
        raise HTTPException(status_code=400, detail="Нельзя удалить себя")
    ok = _auth.db.delete(username)
    if not ok:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if username in _auth.cache:
        del _auth.cache[username]
    _audit_service.log_admin_action(
        payload["sub"], "delete_user", {"deleted_user": username}
    )
    return {"detail": f"Пользователь '{username}' удалён"}


@app.post("/api/admin/users/{username}/reset-password")
async def admin_reset_password(username: str, body: ResetPasswordRequest,
                                payload: dict = Depends(require_admin)):
    """Сброс пароля администратором (п. 3.2)."""
    admin_acc = _auth._load(payload["sub"])
    ok, msg   = _auth.admin_reset_password(admin_acc, username, body.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    _audit_service.log_user_data_change(
        username, ["password"], payload["sub"]
    )
    return {"detail": msg}


@app.post("/api/admin/users/{username}/lock")
async def admin_lock_user(username: str, body: LockRequest,
                           payload: dict = Depends(require_admin)):
    """Блокировка/разблокировка пользователя (п. 3.2)."""
    if username == payload["sub"] and body.lock:
        raise HTTPException(status_code=400, detail="Нельзя заблокировать себя")
    admin_acc = _auth._load(payload["sub"])
    ok, msg   = _auth.admin_set_lock(admin_acc, username, body.lock)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    _audit_service.log_admin_rights_change(
        payload["sub"], username,
        {"action": "lock" if body.lock else "unlock"}
    )
    return {"detail": f"Пользователь '{username}': {msg}"}


@app.on_event("startup")
async def _startup():
    _rotation_mgr.auto_check()