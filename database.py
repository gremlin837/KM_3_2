"""
storage/database.py
Подсистема хранения данных — Config + Database.
Скопировано из main_v2.py.
"""
import os
import time
import configparser
import sqlite3
from contextlib import contextmanager
from typing import Optional, List


class Config:
    _instance = None

    def __new__(cls, path="config.ini"):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load(path)
        return cls._instance

    def _load(self, path):
        self.config = configparser.ConfigParser(interpolation=None)
        self.config.optionxform = str
        if not os.path.exists(path):
            self._create_default_config(path)
        self.config.read(path, encoding='utf-8')

    def _create_default_config(self, path):
        defaults = {
            'DATABASE': {'path': 'users.db'},
            'AUTH': {
                'max_attempts': '3',
                'lockout_minutes': '15',
                'rate_limit_window': '60',
                'rate_limit_max': '10'
            },
            'PASSWORD': {
                'user_min_length': '6',
                'admin_min_length': '7',
                'special_chars': '~!@#$%^&*'
            },
            'TIME': {'timezone': 'Europe/Moscow', 'offset_hours': '3'},
            'BCRYPT': {'rounds': '12'},
            'AUDIT': {
                'max_size_mb': '100',
                'retention_days': '90',
                'enabled_types': 'ALL'
            },
            # Настройки оркестратора (брокера сообщений)
            'ORCHESTRATOR': {
                'host': '127.0.0.1',
                'port': '8001',
                'block_threshold': '1000000',   # кол-во запросов → блокировка IP
                'block_window_sec': '60',        # окно наблюдения (сек)
                'queue_max_size': '10000',        # макс. размер очереди
            },
            'SERVER': {
                'host': '127.0.0.1',
                'port': '8000',
            },
            'JWT': {
                'secret_key': 'CHANGE_ME_IN_PRODUCTION_VERY_SECRET_KEY',
                'algorithm': 'HS256',
                'expire_minutes': '60',
            }
        }
        for section, values in defaults.items():
            self.config.add_section(section)
            for k, v in values.items():
                self.config.set(section, k, str(v))
        with open(path, 'w', encoding='utf-8') as f:
            self.config.write(f)

    # --- AUTH ---
    @property
    def db_path(self): return self.config.get('DATABASE', 'path', fallback='users.db')
    @property
    def max_attempts(self): return int(self.config.get('AUTH', 'max_attempts', fallback='3'))
    @property
    def lockout_minutes(self): return int(self.config.get('AUTH', 'lockout_minutes', fallback='15'))
    @property
    def rate_limit_window(self): return int(self.config.get('AUTH', 'rate_limit_window', fallback='60'))
    @property
    def rate_limit_max(self): return int(self.config.get('AUTH', 'rate_limit_max', fallback='10'))
    # --- PASSWORD ---
    @property
    def user_min_length(self): return int(self.config.get('PASSWORD', 'user_min_length', fallback='6'))
    @property
    def admin_min_length(self): return int(self.config.get('PASSWORD', 'admin_min_length', fallback='7'))
    @property
    def special_chars(self): return self.config.get('PASSWORD', 'special_chars', fallback='~!@#$%^&*')
    @property
    def time_offset(self): return int(self.config.get('TIME', 'offset_hours', fallback='3'))
    @property
    def bcrypt_rounds(self): return int(self.config.get('BCRYPT', 'rounds', fallback='12'))
    # --- AUDIT ---
    @property
    def audit_max_size_mb(self): return float(self.config.get('AUDIT', 'max_size_mb', fallback='100'))
    @property
    def audit_retention_days(self): return int(self.config.get('AUDIT', 'retention_days', fallback='90'))
    @property
    def audit_enabled_types(self):
        val = self.config.get('AUDIT', 'enabled_types', fallback='ALL')
        if val.strip().upper() == 'ALL':
            return None
        return [t.strip() for t in val.split(',')]
    # --- ORCHESTRATOR ---
    @property
    def orch_host(self): return self.config.get('ORCHESTRATOR', 'host', fallback='127.0.0.1')
    @property
    def orch_port(self): return int(self.config.get('ORCHESTRATOR', 'port', fallback='8001'))
    @property
    def block_threshold(self): return int(self.config.get('ORCHESTRATOR', 'block_threshold', fallback='1000000'))
    @property
    def block_window_sec(self): return int(self.config.get('ORCHESTRATOR', 'block_window_sec', fallback='60'))
    @property
    def queue_max_size(self): return int(self.config.get('ORCHESTRATOR', 'queue_max_size', fallback='10000'))
    # --- SERVER ---
    @property
    def server_host(self): return self.config.get('SERVER', 'host', fallback='127.0.0.1')
    @property
    def server_port(self): return int(self.config.get('SERVER', 'port', fallback='8000'))
    # --- JWT ---
    @property
    def jwt_secret(self): return self.config.get('JWT', 'secret_key', fallback='CHANGE_ME')
    @property
    def jwt_algorithm(self): return self.config.get('JWT', 'algorithm', fallback='HS256')
    @property
    def jwt_expire_minutes(self): return int(self.config.get('JWT', 'expire_minutes', fallback='60'))

    def save_audit_enabled_types(self, types: Optional[List[str]]):
        if not self.config.has_section('AUDIT'):
            self.config.add_section('AUDIT')
        val = 'ALL' if types is None else ','.join(types)
        self.config.set('AUDIT', 'enabled_types', val)
        with open("config.ini", 'w', encoding='utf-8') as f:
            self.config.write(f)


# Глобальный синглтон конфига
config = Config()


class Database:
    """Подсистема хранения пользователей. Скопировано из main_v2.py."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init(config.db_path)
        return cls._instance

    def _init(self, path):
        self.path = path
        with self._conn() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                failed INTEGER DEFAULT 0,
                locked_until INTEGER DEFAULT 0,
                need_change INTEGER DEFAULT 1,
                created_at INTEGER DEFAULT 0,
                last_login INTEGER DEFAULT 0
            )''')

    @contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()

    def _now(self):
        return int(time.time() + config.time_offset * 3600)

    def get_user(self, u):
        with self._conn() as c:
            row = c.execute('SELECT * FROM users WHERE username=?', (u,)).fetchone()
        return dict(row) if row else None

    def create_user(self, u, h, adm=False):
        with self._conn() as c:
            try:
                c.execute('INSERT INTO users VALUES (?,?,?,?,?,?,?,?)',
                          (u, h, 1 if adm else 0, 0, 0, 1,
                           self._now(), self._now()))
                return True
            except Exception:
                return False

    def update(self, u, **kw):
        fields = {'hash': 'hash', 'is_admin': 'is_admin', 'failed': 'failed',
                  'locked_until': 'locked_until', 'need_change': 'need_change',
                  'last_login': 'last_login'}
        up = [f"{fields[k]}=?" for k in kw if k in fields]
        if up:
            with self._conn() as c:
                c.execute(f"UPDATE users SET {','.join(up)} WHERE username=?",
                          [*kw.values(), u])

    def all_users(self):
        with self._conn() as c:
            return [dict(r) for r in c.execute('SELECT * FROM users')]

    def delete(self, u):
        with self._conn() as c:
            return c.execute('DELETE FROM users WHERE username=?', (u,)).rowcount > 0