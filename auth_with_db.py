import time
import re
from datetime import datetime
from hash_bcrypt import BcryptHasher
from db_users import get_db
from config import config


class AuthSystem:
    def __init__(self, db_path=None):
        self.db = get_db(db_path)
        self.hasher = BcryptHasher(rounds=config.bcrypt_rounds)
        self._cache = {}
        self.max_attempts = config.max_attempts
        self.lockout_minutes = config.lockout_minutes
        self.user_min_len = config.user_min_length
        self.admin_min_len = config.admin_min_length
        self.special_chars = config.special_chars

    def _msk_time(self):
        return int(time.time() + config.time_offset * 3600)

    def _format_time(self, timestamp):
        if timestamp == 0:
            return "Никогда"
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

    def _check_pwd(self, pwd, is_admin):
        min_len = self.admin_min_len if is_admin else self.user_min_len
        pattern = rf'[{re.escape(self.special_chars)}]'

        if len(pwd) < min_len:
            return False, f"Длина {min_len}+ символов"
        if not re.search(r'[A-Z]', pwd):
            return False, "Нужна заглавная буква"
        if not re.search(r'[a-z]', pwd):
            return False, "Нужна строчная буква"
        if not re.search(r'[0-9]', pwd):
            return False, "Нужна цифра"
        if not re.search(pattern, pwd):
            return False, f"Нужен спецсимвол ({self.special_chars})"
        return True, "OK"

    def _not_contain_user(self, pwd, name):
        return (False, f"Пароль содержит '{name}'") if name.lower() in pwd.lower() else (True, "OK")

    def create(self, name, pwd, is_admin=False):
        if self.db.get_user(name):
            return False, "Пользователь уже существует"
        valid, msg = self._check_pwd(pwd, is_admin)
        if not valid: return False, msg
        valid, msg = self._not_contain_user(pwd, name)
        if not valid: return False, msg

        hashed = self.hasher.hash_password(pwd)
        if self.db.create_user(name, hashed['hash'], is_admin):
            acc = self._cache[name] = type('User', (), {})()
            acc.username, acc.password, acc.is_admin = name, hashed['hash'], is_admin
            acc.failed, acc.locked_until, acc.need_change = 0, 0, True
            return True, f"{'Админ' if is_admin else 'Пользователь'} '{name}' создан"
        return False, "Ошибка БД"

    def auth(self, name, pwd, ip=None):
        acc = self._cache.get(name) or self._load(name)
        if not acc:
            return False, "Неверный логин или пароль", None

        now = self._msk_time()
        if acc.locked_until > now:
            remaining = int((acc.locked_until - now) / 60)
            return False, f"Блокировка до {self._format_time(acc.locked_until)} (осталось {remaining} мин)", None
        elif acc.locked_until:
            acc.failed, acc.locked_until = 0, 0
            self._save(acc)

        if not self.hasher.verify_password(pwd, acc.password):
            acc.failed += 1
            if acc.failed >= self.max_attempts:
                acc.locked_until = self._msk_time() + (self.lockout_minutes * 60)
                self._save(acc)
                return False, f"Аккаунт заблокирован до {self._format_time(acc.locked_until)}", None
            self._save(acc)
            return False, f"Неверный пароль. Осталось попыток: {self.max_attempts - acc.failed}", None

        acc.failed, acc.locked_until = 0, 0
        self.db.update_last_login(name)
        self._save(acc)

        if acc.need_change:
            return False, "Требуется смена пароля при первом входе", acc

        role = "Админ" if acc.is_admin else "Пользователь"
        return True, f"Добро пожаловать, {name}! ({role})", acc

    def change(self, acc, new_pwd):
        valid, msg = self._check_pwd(new_pwd, acc.is_admin)
        if not valid: return False, msg
        valid, msg = self._not_contain_user(new_pwd, acc.username)
        if not valid: return False, msg

        hashed = self.hasher.hash_password(new_pwd)
        acc.password, acc.need_change = hashed['hash'], False
        self._save(acc)
        return True, "Пароль изменён"

    def admin_reset(self, admin_name, target_name, new_pwd):
        admin = self._cache.get(admin_name) or self._load(admin_name)
        if not admin or not admin.is_admin:
            return False, "Требуются права администратора"

        target = self._cache.get(target_name) or self._load(target_name)
        if not target:
            return False, "Пользователь не найден"

        valid, msg = self._check_pwd(new_pwd, target.is_admin)
        if not valid: return False, msg
        valid, msg = self._not_contain_user(new_pwd, target.username)
        if not valid: return False, msg

        hashed = self.hasher.hash_password(new_pwd)
        target.password, target.need_change = hashed['hash'], True
        target.failed, target.locked_until = 0, 0
        self._save(target)
        return True, f"Пароль для '{target_name}' сброшен. При входе потребуется смена."

    def _load(self, name):
        data = self.db.get_user(name)
        if not data: return None
        acc = type('User', (), {})()
        acc.username, acc.password, acc.is_admin = name, data['hash'], bool(data['is_admin'])
        acc.failed, acc.locked_until = data['failed'], data['locked_until']
        acc.need_change = bool(data['need_change'])
        self._cache[name] = acc
        return acc

    def _save(self, acc):
        self.db.update(acc.username, hash=acc.password, is_admin=acc.is_admin,
                       failed=acc.failed, locked_until=acc.locked_until, need_change=acc.need_change)

    def users(self):
        users = self.db.all_users()
        for u in users:
            u['created_at_readable'] = self._format_time(u['created_at'])
            u['last_login_readable'] = self._format_time(u['last_login'])
        return users

    def delete(self, name, admin_name):
        admin = self._cache.get(admin_name) or self._load(admin_name)
        if not admin or not admin.is_admin: return False, "Нет прав"
        return (True, f"{name} удалён") if self.db.delete(name) else (False, "Не найден")

    def user_info(self, name):
        data = self.db.get_user(name)
        if not data: return None
        return {
            'username': data['username'],
            'is_admin': bool(data['is_admin']),
            'failed_attempts': data['failed'],
            'locked_until': self._format_time(data['locked_until']),
            'created_at': self._format_time(data['created_at']),
            'last_login': self._format_time(data['last_login']),
            'need_change_password': bool(data['need_change'])
        }

    def get_config_info(self):
        """Возвращает текущие настройки из конфига"""
        return {
            'max_attempts': self.max_attempts,
            'lockout_minutes': self.lockout_minutes,
            'user_min_length': self.user_min_len,
            'admin_min_length': self.admin_min_len,
            'special_chars': self.special_chars,
            'timezone': config.timezone,
            'time_offset': config.time_offset,
            'bcrypt_rounds': config.bcrypt_rounds,
            'db_path': self.db.db_path
        }


# Тест
if __name__ == "__main__":
    import os

    os.remove("users.db") if os.path.exists("users.db") else None

    auth = AuthSystem()

    print("=" * 55)
    print("ТЕСТ С КОНФИГУРАЦИЕЙ ИЗ config.ini")
    print("=" * 55)

    # Показываем текущие настройки
    print("\n📋 ТЕКУЩИЕ НАСТРОЙКИ:")
    for k, v in auth.get_config_info().items():
        print(f"   {k}: {v}")

    # Тест работы
    print("\n🔧 ТЕСТ РАБОТЫ:")
    auth.create("ivan", "Iv@n12345")
    print("   ✅ Пользователь создан")

    _, msg, acc = auth.auth("ivan", "Iv@n12345")
    print(f"   ✅ {msg}")

    auth.change(acc, "N3wIv@n67890")
    print("   ✅ Пароль изменён")

    success, msg, _ = auth.auth("ivan", "N3wIv@n67890")
    print(f"   ✅ {msg}")

    info = auth.user_info("ivan")
    print(f"\n📊 ИНФОРМАЦИЯ:")
    print(f"   Создан: {info['created_at']}")
    print(f"   Последний вход: {info['last_login']}")

    print("\n" + "=" * 55)