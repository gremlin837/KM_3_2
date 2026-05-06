"""
auth/auth_system.py
Подсистема аутентификации и авторизации.
Скопировано из main_v2.py.
"""
import re
import time
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta

import bcrypt
import jwt  # PyJWT

from storage.database import config, Database


class BcryptHasher:
    """Хеширование паролей. Скопировано из main_v2.py."""

    def __init__(self):
        self.rounds = config.bcrypt_rounds

    def hash_password(self, pwd: str) -> dict:
        return {
            'hash': bcrypt.hashpw(
                pwd.encode(), bcrypt.gensalt(rounds=self.rounds)
            ).decode()
        }

    def verify_password(self, pwd: str, stored: str) -> bool:
        return bcrypt.checkpw(pwd.encode(), stored.encode())


class AuthSystem:
    """Система аутентификации. Скопировано и адаптировано из main_v2.py."""

    def __init__(self):
        self.db = Database()
        self.hasher = BcryptHasher()
        self.cache: Dict[str, object] = {}
        self._rate_limit_store: Dict[str, List[float]] = {}

    # ------------------------------------------------------------------
    # Rate limiting (п. 4.1.3) — для локального использования
    # ------------------------------------------------------------------
    def check_rate_limit(self, ip: str) -> Tuple[bool, str]:
        now = time.time()
        window = config.rate_limit_window
        max_req = config.rate_limit_max

        if ip not in self._rate_limit_store:
            self._rate_limit_store[ip] = []

        self._rate_limit_store[ip] = [
            t for t in self._rate_limit_store[ip] if now - t < window
        ]

        if len(self._rate_limit_store[ip]) >= max_req:
            return False, f"Превышен лимит ({max_req} за {window} сек)."

        self._rate_limit_store[ip].append(now)
        return True, "OK"

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------
    def _load(self, u):
        d = self.db.get_user(u)
        if not d:
            return None
        acc = type('User', (), {})()
        (acc.username, acc.password, acc.is_admin,
         acc.failed, acc.locked_until, acc.need_change) = (
            u, d['hash'], bool(d['is_admin']),
            d['failed'], d['locked_until'], bool(d['need_change'])
        )
        self.cache[u] = acc
        return acc

    def _save(self, acc):
        self.db.update(acc.username,
                       hash=acc.password,
                       is_admin=acc.is_admin,
                       failed=acc.failed,
                       locked_until=acc.locked_until,
                       need_change=acc.need_change)

    def _check_pwd(self, pwd: str, adm: bool) -> Tuple[bool, str]:
        mn = config.admin_min_length if adm else config.user_min_length
        pat = rf'[{re.escape(config.special_chars)}]'
        if len(pwd) < mn:          return False, f"Мин. длина: {mn}"
        if not re.search(r'[A-Z]', pwd): return False, "Нужна заглавная буква"
        if not re.search(r'[a-z]', pwd): return False, "Нужна строчная буква"
        if not re.search(r'[0-9]', pwd): return False, "Нужна цифра"
        if not re.search(pat, pwd):      return False, f"Нужен спецсимвол ({config.special_chars})"
        return True, "OK"

    def _not_contain_user(self, pwd: str, name: str) -> Tuple[bool, str]:
        return (
            (False, "Пароль содержит логин")
            if name.lower() in pwd.lower()
            else (True, "OK")
        )

    # ------------------------------------------------------------------
    # Основные методы
    # ------------------------------------------------------------------
    def auth(self, u: str, pwd: str) -> Tuple[bool, str, Optional[object]]:
        """Аутентификация пользователя. Скопировано из main_v2.py."""
        acc = self.cache.get(u) or self._load(u)
        if not acc:
            return False, "Неверный логин или пароль", None

        now = int(time.time())
        if acc.locked_until > now:
            rem = int((acc.locked_until - now) / 60)
            return False, f"Блокировка. Осталось ~{rem} мин.", None
        elif acc.locked_until:
            acc.failed = acc.locked_until = 0
            self._save(acc)

        if not self.hasher.verify_password(pwd, acc.password):
            acc.failed += 1
            if acc.failed >= config.max_attempts:
                acc.locked_until = int(
                    time.time() + config.lockout_minutes * 60
                )
                self._save(acc)
                return (False,
                        f"Аккаунт заблокирован на {config.lockout_minutes} мин.",
                        None)
            self._save(acc)
            return (False,
                    f"Неверный пароль. Осталось: {config.max_attempts - acc.failed}",
                    None)

        acc.failed = acc.locked_until = 0
        self.db.update(
            acc.username,
            last_login=int(time.time() + config.time_offset * 3600)
        )
        self._save(acc)

        if acc.need_change:
            return False, "Требуется смена пароля при первом входе", acc
        return True, "Успешный вход", acc

    def change(self, acc, new_pwd: str) -> Tuple[bool, str]:
        """Смена пароля. Скопировано из main_v2.py."""
        v, m = self._check_pwd(new_pwd, acc.is_admin)
        if not v: return False, m
        v, m = self._not_contain_user(new_pwd, acc.username)
        if not v: return False, m
        h = self.hasher.hash_password(new_pwd)
        acc.password, acc.need_change = h['hash'], False
        self._save(acc)
        return True, "Пароль изменён"

    def admin_reset_password(self, admin_acc, target_username: str,
                             new_pwd: str) -> Tuple[bool, str]:
        """Сброс пароля администратором. Скопировано из main_v2.py."""
        if not admin_acc.is_admin:
            return False, "Недостаточно прав"
        target = self._load(target_username)
        if not target:
            return False, "Пользователь не найден"
        v, m = self._check_pwd(new_pwd, target.is_admin)
        if not v: return False, m
        v, m = self._not_contain_user(new_pwd, target_username)
        if not v: return False, m
        h = self.hasher.hash_password(new_pwd)
        target.password = h['hash']
        target.need_change = True
        self._save(target)
        if target_username in self.cache:
            del self.cache[target_username]
        return True, "Пароль сброшен. Пользователю потребуется сменить пароль."

    def admin_set_lock(self, admin_acc, target_username: str,
                       lock: bool) -> Tuple[bool, str]:
        """Блокировка/разблокировка пользователя. Скопировано из main_v2.py."""
        if not admin_acc.is_admin:
            return False, "Недостаточно прав"
        target = self._load(target_username)
        if not target:
            return False, "Пользователь не найден"
        if lock:
            target.locked_until = int(time.time()) + 10 * 365 * 24 * 3600
        else:
            target.locked_until = 0
            target.failed = 0
        self._save(target)
        if target_username in self.cache:
            del self.cache[target_username]
        return True, "Заблокирован" if lock else "Разблокирован"

    def create_admin_if_empty(self):
        if not self.db.all_users():
            self.db.create_user(
                "admin",
                self.hasher.hash_password("Admin@12345")['hash'],
                True
            )
            print("Создан тестовый аккаунт: admin / Admin@12345")

    # ------------------------------------------------------------------
    # JWT токены (для API)
    # ------------------------------------------------------------------
    def create_token(self, username: str, is_admin: bool) -> str:
        """Создать JWT токен после успешного входа."""
        payload = {
            "sub": username,
            "is_admin": is_admin,
            "exp": datetime.utcnow() + timedelta(
                minutes=config.jwt_expire_minutes
            )
        }
        return jwt.encode(payload, config.jwt_secret,
                          algorithm=config.jwt_algorithm)

    def verify_token(self, token: str) -> Optional[dict]:
        """Проверить JWT токен. Возвращает payload или None."""
        try:
            payload = jwt.decode(token, config.jwt_secret,
                                 algorithms=[config.jwt_algorithm])
            return payload
        except Exception:
            return None

    # В конец класса AuthSystem:
    def create_token(self, username: str, is_admin: bool) -> str:
        """Генерация JWT токена для аутентифицированного пользователя."""
        import jwt as _jwt
        from datetime import datetime, timedelta

        payload = {
            "sub": username,
            "is_admin": is_admin,
            "exp": datetime.utcnow() + timedelta(hours=24),
            "iat": datetime.utcnow()
        }
        return _jwt.encode(payload, config.jwt_secret, algorithm=config.jwt_algorithm)