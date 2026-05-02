import sqlite3
import time
from typing import Optional, List
from contextlib import contextmanager
from auth_tests.config import config


class Database:
    _instance = None

    def __new__(cls, db_path=None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_db(db_path or config.db_path)
        return cls._instance

    def _init_db(self, db_path):
        self.db_path = db_path
        with self._connect() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    hash TEXT NOT NULL,
                    is_admin INTEGER DEFAULT 0,
                    failed INTEGER DEFAULT 0,
                    locked_until INTEGER DEFAULT 0,
                    need_change INTEGER DEFAULT 1,
                    created_at INTEGER DEFAULT 0,
                    last_login INTEGER DEFAULT 0
                )
            ''')

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _msk_time(self):
        """Возвращает Unix timestamp с учётом смещения из конфига"""
        return int(time.time() + config.time_offset * 3600)

    def create_user(self, username: str, hash_pwd: str, is_admin=False) -> bool:
        with self._connect() as conn:
            try:
                now = self._msk_time()
                conn.execute('''
                    INSERT INTO users (username, hash, is_admin, created_at, last_login)
                    VALUES (?,?,?,?,?)
                ''', (username, hash_pwd, 1 if is_admin else 0, now, now))
                return True
            except:
                return False

    def get_user(self, username: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
            return dict(row) if row else None

    def update(self, username: str, **kwargs):
        fields = {'hash': 'hash', 'is_admin': 'is_admin', 'failed': 'failed',
                  'locked_until': 'locked_until', 'need_change': 'need_change',
                  'last_login': 'last_login'}
        updates = [f"{fields[k]}=?" for k in kwargs if k in fields]
        if updates:
            with self._connect() as conn:
                conn.execute(f"UPDATE users SET {','.join(updates)} WHERE username=?",
                             [*kwargs.values(), username])

    def update_last_login(self, username: str):
        with self._connect() as conn:
            conn.execute('UPDATE users SET last_login=? WHERE username=?',
                         (self._msk_time(), username))

    def all_users(self) -> List[dict]:
        with self._connect() as conn:
            return [dict(row) for row in
                    conn.execute('SELECT username, is_admin, created_at, last_login, failed, locked_until FROM users')]

    def delete(self, username: str) -> bool:
        with self._connect() as conn:
            return conn.execute('DELETE FROM users WHERE username=?', (username,)).rowcount > 0


get_db = lambda path=None: Database(path)