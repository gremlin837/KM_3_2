import time
import re
from typing import Dict, Optional, Tuple


class UserAccount:
    def __init__(self, username: str, password: str, is_admin: bool = False):
        self.username = username
        self.password = password
        self.is_admin = is_admin
        self.failed_attempts = 0
        self.locked_until = 0
        self.password_change_required = True

    def is_locked(self) -> bool:
        if self.locked_until == 0:
            return False
        if time.time() >= self.locked_until:
            self.failed_attempts = 0
            self.locked_until = 0
            return False
        return True

    def lock_account(self):
        self.locked_until = time.time() + 15 * 60


class AuthenticationSystem:
    MAX_FAILED_ATTEMPTS = 3
    MIN_LENGTH_USER = 6
    MIN_LENGTH_ADMIN = 7

    def __init__(self):
        self.accounts: Dict[str, UserAccount] = {}

    def _validate_password_strength(self, password: str, is_admin: bool) -> Tuple[bool, str]:
        min_length = self.MIN_LENGTH_ADMIN if is_admin else self.MIN_LENGTH_USER

        if len(password) < min_length:
            return False, f"Длина пароля должна быть не менее {min_length} символов"

        if not re.search(r'[A-Z]', password):
            return False, "Пароль должен содержать заглавную букву (A-Z)"

        if not re.search(r'[a-z]', password):
            return False, "Пароль должен содержать строчную букву (a-z)"

        if not re.search(r'[0-9]', password):
            return False, "Пароль должен содержать цифру (0-9)"

        if not re.search(r'[~!@#$%^&*()_+\-=\[\]{};\\:|\",.<>/?]', password):
            return False, "Пароль должен содержать спецсимвол "

        return True, "OK"

    def _check_password_not_contain_username(self, password: str, username: str) -> Tuple[bool, str]:
        """Пароль не должен содержать идентификатор или его часть (как подстроку)"""
        username_lower = username.lower()
        password_lower = password.lower()

        # Проверка на полное совпадение или вхождение как подстроки
        if username_lower in password_lower:
            return False, f"Пароль не должен содержать идентификатор '{username}'"

        return True, "OK"

    def create_account(self, username: str, password: str, is_admin: bool = False) -> Tuple[bool, str]:
        if username in self.accounts:
            return False, "Пользователь с таким идентификатором уже существует"

        valid, msg = self._validate_password_strength(password, is_admin)
        if not valid:
            return False, msg

        valid, msg = self._check_password_not_contain_username(password, username)
        if not valid:
            return False, msg

        self.accounts[username] = UserAccount(username, password, is_admin)
        role = "Администратор" if is_admin else "Пользователь"
        return True, f"{role} '{username}' создан. Требуется смена пароля при первом входе."

    def authenticate(self, username: str, password: str) -> Tuple[bool, str, Optional[UserAccount]]:
        if username not in self.accounts:
            return False, "Неверный идентификатор или пароль", None

        account = self.accounts[username]

        if account.is_locked():
            remaining = int(account.locked_until - time.time())
            minutes = remaining // 60
            seconds = remaining % 60
            return False, f"Учётная запись заблокирована. Попробуйте через {minutes} мин {seconds} сек.", None

        if account.password != password:
            account.failed_attempts += 1
            remaining_attempts = self.MAX_FAILED_ATTEMPTS - account.failed_attempts

            if account.failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                account.lock_account()
                return False, f"Неверный пароль. Учётная запись заблокирована на 15 минут.", None
            else:
                return False, f"Неверный пароль. Осталось попыток: {remaining_attempts}", None

        account.failed_attempts = 0

        if account.password_change_required:
            return False, "Требуется смена пароля при первом входе в систему", account

        role = "Администратор" if account.is_admin else "Пользователь"
        return True, f"Аутентификация успешна. Добро пожаловать, {username}! (Роль: {role})", account

    def change_password_after_auth(self, account: UserAccount, new_password: str) -> Tuple[bool, str]:
        valid, msg = self._validate_password_strength(new_password, account.is_admin)
        if not valid:
            return False, msg

        valid, msg = self._check_password_not_contain_username(new_password, account.username)
        if not valid:
            return False, msg

        account.password = new_password
        account.password_change_required = False
        return True, "Пароль успешно изменён"

    def admin_reset_password(self, admin_username: str, target_username: str, new_password: str) -> Tuple[bool, str]:
        if admin_username not in self.accounts:
            return False, "Администратор не найден"

        admin = self.accounts[admin_username]
        if not admin.is_admin:
            return False, "Только администратор может сбрасывать пароли"

        if target_username not in self.accounts:
            return False, "Пользователь не найден"

        target = self.accounts[target_username]

        valid, msg = self._validate_password_strength(new_password, target.is_admin)
        if not valid:
            return False, msg

        valid, msg = self._check_password_not_contain_username(new_password, target.username)
        if not valid:
            return False, msg

        target.password = new_password
        target.password_change_required = True
        target.failed_attempts = 0
        target.locked_until = 0

        return True, f"Пароль для '{target_username}' сброшен. При следующем входе потребуется смена пароля."