"""server/server.py
Серверная часть на FastAPI (порт 8000).
Содержит: аутентификацию, расчёты, аудит, управление пользователями.
Запуск: uvicorn server:app --host 127.0.0.1 --port 8000
"""
import time, re, bcrypt, jwt
from datetime import datetime, timedelta
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from storage.database import config, Database
from audit.audit_service import AuditSystemFactory
from math_core.calculator import calc_tes_efficiency, analyze_temperature

# ── Встроенная подсистема аутентификации (чтобы не зависеть от внешних файлов) ──
class BcryptHasher:
    def hash(self, pwd: str) -> str:
        return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=config.bcrypt_rounds)).decode()
    def verify(self, pwd: str, stored: str) -> bool:
        return bcrypt.checkpw(pwd.encode(), stored.encode())

class AuthSystem:
    def __init__(self):
        self.db = Database()
        self.hasher = BcryptHasher()
        self.cache = {}
        if not self.db.all_users():
            self.db.create_user("admin", self.hasher.hash("Admin@12345"), True)

    def _load(self, u):
        d = self.db.get_user(u)
        if not d: return None
        acc = type('User', (), {
            'username': u, 'password': d['hash'], 'is_admin': bool(d['is_admin']),
            'failed': d['failed'], 'locked_until': d['locked_until'], 'need_change': bool(d['need_change'])
        })()
        self.cache[u] = acc
        return acc

    def _save(self, acc):
        self.db.update(acc.username, hash=acc.password, is_admin=acc.is_admin,
                       failed=acc.failed, locked_until=acc.locked_until, need_change=acc.need_change)

    def _check_pwd(self, pwd, is_admin):
        mn = config.admin_min_length if is_admin else config.user_min_length
        pat = rf'[{re.escape(config.special_chars)}]'
        if len(pwd) < mn: return False, f"Мин. длина: {mn}"
        if not re.search(r'[A-Z]', pwd): return False, "Нужна заглавная буква"
        if not re.search(r'[a-z]', pwd): return False, "Нужна строчная буква"
        if not re.search(r'[0-9]', pwd): return False, "Нужна цифра"
        if not re.search(pat, pwd): return False, f"Нужен спецсимвол ({config.special_chars})"
        return True, "OK"

    def auth(self, u, pwd):
        acc = self.cache.get(u) or self._load(u)
        if not acc: return False, "Неверный логин или пароль", None
        now = int(time.time())
        if acc.locked_until > now:
            return False, f"Блокировка. Осталось ~{int((acc.locked_until - now)/60)} мин.", None
        elif acc.locked_until:
            acc.failed = acc.locked_until = 0; self._save(acc)
        if not self.hasher.verify(pwd, acc.password):
            acc.failed += 1
            if acc.failed >= config.max_attempts:
                acc.locked_until = now + config.lockout_minutes * 60
                self._save(acc)
                return False, f"Аккаунт заблокирован на {config.lockout_minutes} мин.", None
            self._save(acc)
            return False, f"Неверный пароль. Осталось: {config.max_attempts - acc.failed}", None
        acc.failed = acc.locked_until = 0
        self.db.update(acc.username, last_login=now + config.time_offset*3600)
        self._save(acc)
        if acc.need_change: return False, "Требуется смена пароля при первом входе", acc
        return True, "Успешный вход", acc

    def change(self, acc, new_pwd):
        v, m = self._check_pwd(new_pwd, acc.is_admin)
        if not v: return False, m
        if acc.username.lower() in new_pwd.lower(): return False, "Пароль содержит логин"
        acc.password = self.hasher.hash(new_pwd)
        acc.need_change = False
        self._save(acc)
        return True, "Пароль изменён"

    def create_token(self, username: str, is_admin: bool) -> str:
        payload = {"sub": username, "is_admin": is_admin,
                   "exp": datetime.utcnow() + timedelta(minutes=config.jwt_expire_minutes),
                   "iat": datetime.utcnow()}
        return jwt.encode(payload, config.jwt_secret, algorithm=config.jwt_algorithm)

# ── Инициализация ──
_auth = AuthSystem()
_audit, _rot_mgr, _ = AuditSystemFactory.create_default_system(
    db_path="../audit_server.db", max_size_mb=config.audit_max_size_mb
)
_audit.enabled_types = config.audit_enabled_types
security = HTTPBearer(auto_error=False)

@asynccontextmanager
async def lifespan(app: FastAPI):
    _rot_mgr.auto_check()
    yield

app = FastAPI(title="TES Server API", version="1.0", lifespan=lifespan)

# ── Зависимости ──
def decode_token(token: str) -> dict:
    try: return jwt.decode(token, config.jwt_secret, algorithms=[config.jwt_algorithm])
    except: raise HTTPException(status_code=401, detail="Недействительный токен")

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    if not credentials: raise HTTPException(status_code=401, detail="Требуется авторизация")
    return decode_token(credentials.credentials)

def require_admin(payload: dict = Depends(get_current_user)) -> dict:
    if not payload.get("is_admin"): raise HTTPException(status_code=403, detail="Требуются права администратора")
    return payload

# ── Pydantic модели ──
class LoginReq(BaseModel): username: str; password: str
class ChangePwdReq(BaseModel): old_password: str; new_password: str
class CalcReq(BaseModel):
    total_load: float = 400; num_blocks: int = 2; nominal_power_per_block: float = 300
    nominal_efficiency: float = 0.38; temp_c: float = 25; humidity: float = 60
    wind_speed: float = 3; wind_dir: float = 90; own_needs_coeff: float = 0.05; beta: float = 0.4
class TempReq(BaseModel):
    total_load: float = 400; num_blocks: int = 2; nominal_power: float = 300
    nominal_efficiency: float = 0.38; humidity: float = 60; wind_speed: float = 3; wind_dir: float = 90
class CreateUserReq(BaseModel): username: str; password: str; is_admin: bool = False
class ResetPwdReq(BaseModel): new_password: str
class LockReq(BaseModel): lock: bool

# ── Эндпоинты ──
@app.post("/api/auth/login")
async def login(body: LoginReq, request: Request):
    ip = request.client.host or "127.0.0.1"
    t0 = time.monotonic()
    ok, msg, acc = _auth.auth(body.username, body.password)
    elapsed = (time.monotonic() - t0) * 1000

    # Генерируем токен ДО проверки need_change, чтобы клиент мог выполнить смену
    token = _auth.create_token(body.username, acc.is_admin)

    _audit.log_api_request(body.username, "/api/auth/login", "POST", 200 if ok else 401, elapsed)

    if not ok:
        if "Требуется смена" in msg:
            _audit.log_auth_login(body.username, ip, "API")
            return {
                "access_token": token,
                "token_type": "bearer",
                "username": body.username,
                "is_admin": acc.is_admin,
                "need_change": True,
                "detail": msg
            }
        _audit.log_auth_failed(body.username, ip, msg)
        raise HTTPException(status_code=401, detail=msg)

    _audit.log_auth_login(body.username, ip, "API")
    _audit.log_api_auth_info(body.username, "password", "Bearer", True)
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": body.username,
        "is_admin": acc.is_admin,
        "need_change": False
    }

@app.post("/api/auth/change-password")
async def change_pwd(body: ChangePwdReq, payload: dict = Depends(get_current_user)):
    acc = _auth._load(payload["sub"])
    if not acc: raise HTTPException(status_code=404, detail="Пользователь не найден")
    if not _auth.hasher.verify(body.old_password, acc.password):
        raise HTTPException(status_code=400, detail="Неверный текущий пароль")
    ok, msg = _auth.change(acc, body.new_password)
    if not ok: raise HTTPException(status_code=400, detail=msg)
    _audit.log_user_data_change(payload["sub"], ["password"], payload["sub"])
    return {"detail": "Пароль изменён"}

@app.post("/api/calculate")
async def calc(body: CalcReq, payload: dict = Depends(get_current_user)):
    t0 = time.monotonic()
    d = body.model_dump() if hasattr(body, 'model_dump') else body.dict()
    res = calc_tes_efficiency(**d)
    out = {
        "Нагрузка на энергоблок": round(res["load_per_block"], 2),
        "КПД блока": round(res["block_efficiency"]*100, 2),
        "КПД ТЭС брутто": round(res["efficiency_brutto"]*100, 2),
        "Собственные нужды": round(res["own_needs_percent"], 2),
        "КПД ТЭС нетто": round(res["efficiency_netto"]*100, 2),
        "Удельный расход топлива": round(res["fuel_consumption"], 1)
    }
    elapsed = (time.monotonic() - t0) * 1000
    _audit.log_api_request(payload["sub"], "/api/calculate", "POST", 200, elapsed)
    return out

@app.post("/api/analyze/temperature")
async def temp_analysis(body: TempReq, payload: dict = Depends(get_current_user)):
    d = body.dict() if hasattr(body, 'dict') else body.model_dump()
    temps, effs, fuels = analyze_temperature(
        total_load=d["total_load"], num_blocks=d["num_blocks"], nominal_power=d["nominal_power"],
        nominal_efficiency=d["nominal_efficiency"], humidity=d["humidity"],
        wind_speed=d["wind_speed"], wind_dir=d["wind_dir"])
    return {"temperatures": temps, "efficiencies_netto": effs, "fuel_rates": fuels}

@app.get("/api/audit/events")
async def get_audit(limit: int = 100, event_type: Optional[str]=None, subject: Optional[str]=None,
                    date_from: Optional[str]=None, date_to: Optional[str]=None,
                    payload: dict = Depends(get_current_user)):
    filters = {}
    if event_type: filters["event_type"] = event_type
    if subject: filters["subject"] = subject
    if date_from: filters["date_from"] = date_from
    if date_to: filters["date_to"] = date_to
    events = _audit.storage.get_events(filters=filters or None, limit=limit)
    return [e.to_dict() for e in events]

@app.get("/api/admin/users")
async def admin_users(payload: dict = Depends(require_admin)):
    users = _auth.db.all_users()
    now = int(time.time())
    return [{
        "username": u["username"], "is_admin": bool(u["is_admin"]), "failed": u["failed"],
        "locked": u["locked_until"] > now, "need_change": bool(u["need_change"]),
        "created_at": datetime.fromtimestamp(u["created_at"]-config.time_offset*3600).strftime("%Y-%m-%d %H:%M") if u["created_at"] else "—",
        "last_login": datetime.fromtimestamp(u["last_login"]-config.time_offset*3600).strftime("%Y-%m-%d %H:%M") if u["last_login"] else "—"
    } for u in users]

@app.post("/api/admin/users")
async def admin_create(body: CreateUserReq, payload: dict = Depends(require_admin)):
    v, m = _auth._check_pwd(body.password, body.is_admin)
    if not v: raise HTTPException(status_code=400, detail=m)
    if _auth.db.get_user(body.username): raise HTTPException(status_code=409, detail="Существует")
    _auth.db.create_user(body.username, _auth.hasher.hash(body.password), body.is_admin)
    _audit.log_admin_action(payload["sub"], "create_user", {"user": body.username})
    return {"detail": f"Создан '{body.username}'"}

@app.delete("/api/admin/users/{username}")
async def admin_delete(username: str, payload: dict = Depends(require_admin)):
    if username == payload["sub"]: raise HTTPException(status_code=400, detail="Нельзя удалить себя")
    if not _auth.db.delete(username): raise HTTPException(status_code=404, detail="Не найден")
    _auth.cache.pop(username, None)
    _audit.log_admin_action(payload["sub"], "delete_user", {"user": username})
    return {"detail": f"Удалён '{username}'"}

@app.post("/api/admin/users/{username}/reset-password")
async def admin_reset(username: str, body: ResetPwdReq, payload: dict = Depends(require_admin)):
    acc = _auth._load(username)
    if not acc: raise HTTPException(status_code=404, detail="Не найден")
    v, m = _auth._check_pwd(body.new_password, acc.is_admin)
    if not v: raise HTTPException(status_code=400, detail=m)
    acc.password = _auth.hasher.hash(body.new_password)
    acc.need_change = True
    _auth._save(acc)
    _audit.log_user_data_change(username, ["password"], payload["sub"])
    return {"detail": "Сброшен"}

@app.post("/api/admin/users/{username}/lock")
async def admin_lock(username: str, body: LockReq, payload: dict = Depends(require_admin)):
    if username == payload["sub"] and body.lock: raise HTTPException(status_code=400, detail="Нельзя заблокировать себя")
    acc = _auth._load(username)
    if not acc: raise HTTPException(status_code=404, detail="Не найден")
    acc.locked_until = int(time.time()) + 10*365*24*3600 if body.lock else 0
    if not body.lock: acc.failed = 0
    _auth._save(acc)
    _audit.log_admin_rights_change(payload["sub"], username, {"action": "lock" if body.lock else "unlock"})
    return {"detail": "Заблокирован" if body.lock else "Разблокирован"}