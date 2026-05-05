"""
main.py
Полный интерфейс + подсистема аутентификации (SQLite + bcrypt + Config)
+ Подсистема аудита (SQLite, ротация, экспорт)
+ Панель администратора + Управление пользователями
+ Rate limiting + UUID идентификаторы событий
+ Ротация по объёму файла
Запуск: python main.py
Зависимости: pip install PyQt6 matplotlib numpy bcrypt
"""
import sys
import os
import time
import re
import configparser
import sqlite3
import json
import gzip
import shutil
import csv
import uuid  # ИЗМЕНЕНО: добавлен импорт uuid для идентификаторов событий
from contextlib import contextmanager
from typing import Optional, Dict, List, Tuple, Any
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
import numpy as np

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QGroupBox, QLabel, QPushButton, QDoubleSpinBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QTabWidget, QHeaderView, QProgressBar, QMenuBar,
    QMessageBox, QComboBox, QFileDialog, QLineEdit, QDialog, QInputDialog,
    QCheckBox  # ИЗМЕНЕНО: добавлен QCheckBox для настройки детализации
)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt6.QtGui import QFont, QAction
import matplotlib

matplotlib.use("Qt5Agg")
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


# ============================================================================
# ПОДСИСТЕМА АУДИТА
# ============================================================================

class EventType(Enum):
    """Типы событий для регистрации согласно п. 3.3.1 ТЗ"""
    AUTH_LOGIN = "AUTH_LOGIN"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    AUTH_FAILED = "AUTH_FAILED"
    USER_DATA_CHANGE = "USER_DATA_CHANGE"
    ADMIN_ACTION = "ADMIN_ACTION"
    ADMIN_RIGHTS_CHANGE = "ADMIN_RIGHTS_CHANGE"
    ADMIN_PARAMS_CHANGE = "ADMIN_PARAMS_CHANGE"
    INTERFACE_INPUT = "INTERFACE_INPUT"
    INTERFACE_OUTPUT = "INTERFACE_OUTPUT"
    API_REQUEST = "API_REQUEST"
    API_AUTH_INFO = "API_AUTH_INFO"


@dataclass
class AuditEvent:
    """
    Структура события аудита (п. 3.3.2)
    Содержит все обязательные поля согласно ТЗ
    Исключает персональные данные согласно п. 3.3.3
    """
    event_id: Optional[int]
    timestamp: str
    event_type: str
    event_name: str
    component: str
    subject: str
    headers: Dict[str, Any]
    identifier: Optional[str] = None  # ИЗМЕНЕНО: теперь заполняется UUID

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'AuditEvent':
        return AuditEvent(**data)


class IAuditStorage(ABC):
    """Интерфейс хранилища событий (п. 3.3.4, 3.3.5)"""

    @abstractmethod
    def save_event(self, event: AuditEvent) -> bool:
        pass

    @abstractmethod
    def get_events(self, filters: Optional[Dict[str, Any]] = None,
                   limit: int = 100) -> List[AuditEvent]:
        pass

    @abstractmethod
    def rotate_logs(self, retention_days: int) -> bool:
        pass

    # ИЗМЕНЕНО: добавлен метод ротации по объёму файла (п. 3.3.6)
    @abstractmethod
    def rotate_logs_by_size(self, max_size_mb: float) -> bool:
        pass

    @abstractmethod
    def export_to_remote(self, remote_path: str) -> bool:
        pass

    @abstractmethod
    def get_db_size_mb(self) -> float:
        pass


class IAuditFilter(ABC):
    """Интерфейс фильтрации событий"""

    @abstractmethod
    def apply(self, events: List[AuditEvent]) -> List[AuditEvent]:
        pass


class SQLiteAuditStorage(IAuditStorage):
    """
    Реализация хранилища на SQLite
    Обеспечивает настраиваемую глубину хранения (п. 3.3.4)
    """

    def __init__(self, db_path: str = "audit_events.db"):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_name TEXT NOT NULL,
                    component TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    headers TEXT NOT NULL,
                    identifier TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON audit_events(event_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_subject ON audit_events(subject)")
            conn.commit()

    def save_event(self, event: AuditEvent) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_events
                    (timestamp, event_type, event_name, component, subject, headers, identifier)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.timestamp,
                    event.event_type,
                    event.event_name,
                    event.component,
                    event.subject,
                    json.dumps(event.headers, ensure_ascii=False),
                    event.identifier
                ))
                conn.commit()
                return True
        except Exception as e:
            print(f"Ошибка сохранения события: {e}")
            return False

    def get_events(self, filters: Optional[Dict[str, Any]] = None,
                   limit: int = 100) -> List[AuditEvent]:
        query = "SELECT * FROM audit_events WHERE 1=1"
        params = []

        if filters:
            if "event_type" in filters:
                query += " AND event_type = ?"
                params.append(filters["event_type"])
            if "subject" in filters:
                query += " AND subject = ?"
                params.append(filters["subject"])
            if "date_from" in filters:
                query += " AND timestamp >= ?"
                params.append(filters["date_from"])
            if "date_to" in filters:
                query += " AND timestamp <= ?"
                params.append(filters["date_to"])

        query += " ORDER BY event_id DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

        events = []
        for row in rows:
            events.append(AuditEvent(
                event_id=row[0],
                timestamp=row[1],
                event_type=row[2],
                event_name=row[3],
                component=row[4],
                subject=row[5],
                headers=json.loads(row[6]),
                identifier=row[7]
            ))
        return events

    def rotate_logs(self, retention_days: int) -> bool:
        """Ротация журналов по времени (п. 3.3.6)"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM audit_events WHERE timestamp < ?", (cutoff_date,))
                old_events = cursor.fetchall()

                if old_events:
                    archive_path = f"audit_archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json.gz"
                    archive_data = []
                    for row in old_events:
                        archive_data.append({
                            "event_id": row[0], "timestamp": row[1],
                            "event_type": row[2], "event_name": row[3],
                            "component": row[4], "subject": row[5],
                            "headers": json.loads(row[6]), "identifier": row[7]
                        })
                    with gzip.open(archive_path, 'wt', encoding='utf-8') as f:
                        json.dump(archive_data, f, ensure_ascii=False, indent=2)
                    cursor.execute("DELETE FROM audit_events WHERE timestamp < ?", (cutoff_date,))
                    conn.commit()

                cursor.execute("VACUUM")
                conn.commit()
            return True
        except Exception as e:
            print(f"Ошибка ротации журналов: {e}")
            return False

    # ИЗМЕНЕНО: добавлена ротация по объёму файла (п. 3.3.6)
    def rotate_logs_by_size(self, max_size_mb: float) -> bool:
        """
        Ротация журналов по объёму файла (п. 3.3.6).
        Удаляет самые старые 20% записей, если файл превышает max_size_mb.
        """
        try:
            current_size = self.get_db_size_mb()
            if current_size <= max_size_mb:
                return True  # Ротация не нужна

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Считаем общее количество записей
                total = cursor.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
                # Удаляем старейшие 20%
                to_delete = max(1, int(total * 0.20))

                cursor.execute("""
                    SELECT * FROM audit_events
                    ORDER BY event_id ASC LIMIT ?
                """, (to_delete,))
                old_events = cursor.fetchall()

                if old_events:
                    archive_path = (
                        f"audit_archive_size_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json.gz"
                    )
                    archive_data = [
                        {"event_id": r[0], "timestamp": r[1], "event_type": r[2],
                         "event_name": r[3], "component": r[4], "subject": r[5],
                         "headers": json.loads(r[6]), "identifier": r[7]}
                        for r in old_events
                    ]
                    with gzip.open(archive_path, 'wt', encoding='utf-8') as f:
                        json.dump(archive_data, f, ensure_ascii=False, indent=2)

                    ids = [r[0] for r in old_events]
                    cursor.execute(
                        f"DELETE FROM audit_events WHERE event_id IN ({','.join('?' * len(ids))})",
                        ids
                    )
                    conn.commit()

                cursor.execute("VACUUM")
                conn.commit()
            return True
        except Exception as e:
            print(f"Ошибка ротации по объёму: {e}")
            return False

    def get_db_size_mb(self) -> float:
        """Возвращает размер файла БД аудита в МБ"""
        if os.path.exists(self.db_path):
            return os.path.getsize(self.db_path) / (1024 * 1024)
        return 0.0

    def export_to_remote(self, remote_path: str) -> bool:
        """Отправка журналов на удаленный сервер (п. 3.3.5)"""
        try:
            export_file = f"audit_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            export_path = os.path.join(remote_path, export_file)
            os.makedirs(remote_path, exist_ok=True)
            shutil.copy2(self.db_path, export_path)
            return True
        except Exception as e:
            print(f"Ошибка экспорта на удаленный сервер: {e}")
            return False


class EventTypeFilter(IAuditFilter):
    def __init__(self, event_type: EventType):
        self.event_type = event_type.value

    def apply(self, events: List[AuditEvent]) -> List[AuditEvent]:
        return [e for e in events if e.event_type == self.event_type]


class DateRangeFilter(IAuditFilter):
    def __init__(self, date_from: str, date_to: str):
        self.date_from = date_from
        self.date_to = date_to

    def apply(self, events: List[AuditEvent]) -> List[AuditEvent]:
        return [e for e in events if self.date_from <= e.timestamp <= self.date_to]


class SubjectFilter(IAuditFilter):
    def __init__(self, subject: str):
        self.subject = subject

    def apply(self, events: List[AuditEvent]) -> List[AuditEvent]:
        return [e for e in events if e.subject == self.subject]


class CompositeFilter(IAuditFilter):
    def __init__(self, filters: List[IAuditFilter]):
        self.filters = filters

    def apply(self, events: List[AuditEvent]) -> List[AuditEvent]:
        result = events
        for filter_obj in self.filters:
            result = filter_obj.apply(result)
        return result


class AuditService:
    """Основной сервис для работы с аудитом"""

    def __init__(self, storage: IAuditStorage,
                 enabled_types: Optional[List[str]] = None):
        self.storage = storage
        # ИЗМЕНЕНО: настраиваемая детализация — список включённых типов событий (п. 3.3.4)
        self.enabled_types: Optional[List[str]] = enabled_types  # None = все включены

    # ИЗМЕНЕНО: вспомогательный метод — проверка, нужно ли логировать данный тип
    def _should_log(self, event_type: str) -> bool:
        if self.enabled_types is None:
            return True
        return event_type in self.enabled_types

    # ИЗМЕНЕНО: во всех методах добавлен identifier=str(uuid.uuid4()) (п. 3.3.2)
    def log_auth_login(self, username: str, ip_address: str, user_agent: str) -> bool:
        if not self._should_log(EventType.AUTH_LOGIN.value):
            return True
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.AUTH_LOGIN.value,
            event_name="Вход в систему",
            component="/auth/login",
            subject=username,
            headers={"ip": ip_address, "user_agent": user_agent, "method": "POST"},
            identifier=str(uuid.uuid4())  # ИЗМЕНЕНО
        )
        return self.storage.save_event(event)

    def log_auth_logout(self, username: str, session_duration: int) -> bool:
        if not self._should_log(EventType.AUTH_LOGOUT.value):
            return True
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.AUTH_LOGOUT.value,
            event_name="Выход из системы",
            component="/auth/logout",
            subject=username,
            headers={"session_duration_seconds": session_duration},
            identifier=str(uuid.uuid4())  # ИЗМЕНЕНО
        )
        return self.storage.save_event(event)

    def log_auth_failed(self, username: str, ip_address: str, reason: str) -> bool:
        if not self._should_log(EventType.AUTH_FAILED.value):
            return True
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.AUTH_FAILED.value,
            event_name="Ошибка аутентификации",
            component="/auth/login",
            subject=username,
            headers={"ip": ip_address, "reason": reason},
            identifier=str(uuid.uuid4())  # ИЗМЕНЕНО
        )
        return self.storage.save_event(event)

    def log_user_data_change(self, username: str, changed_fields: List[str],
                             changed_by: str) -> bool:
        if not self._should_log(EventType.USER_DATA_CHANGE.value):
            return True
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.USER_DATA_CHANGE.value,
            event_name="Изменение данных пользователя",
            component="user_profile",
            subject=changed_by,
            headers={"target_user": username, "changed_fields": changed_fields},
            identifier=str(uuid.uuid4())  # ИЗМЕНЕНО
        )
        return self.storage.save_event(event)

    def log_admin_action(self, admin: str, action: str,
                         details: Dict[str, Any]) -> bool:
        if not self._should_log(EventType.ADMIN_ACTION.value):
            return True
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.ADMIN_ACTION.value,
            event_name=f"Действие администратора: {action}",
            component="admin_panel",
            subject=admin,
            headers=details,
            identifier=str(uuid.uuid4())  # ИЗМЕНЕНО
        )
        return self.storage.save_event(event)

    def log_admin_rights_change(self, admin: str, target_user: str,
                                rights_changed: Dict[str, Any]) -> bool:
        if not self._should_log(EventType.ADMIN_RIGHTS_CHANGE.value):
            return True
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.ADMIN_RIGHTS_CHANGE.value,
            event_name="Изменение прав доступа",
            component="access_control",
            subject=admin,
            headers={"target_user": target_user, "rights_changed": rights_changed},
            identifier=str(uuid.uuid4())  # ИЗМЕНЕНО
        )
        return self.storage.save_event(event)

    def log_admin_params_change(self, admin: str, component: str,
                                params_changed: Dict[str, Any]) -> bool:
        if not self._should_log(EventType.ADMIN_PARAMS_CHANGE.value):
            return True
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.ADMIN_PARAMS_CHANGE.value,
            event_name="Изменение параметров системы",
            component=component,
            subject=admin,
            headers={"params_changed": params_changed},
            identifier=str(uuid.uuid4())  # ИЗМЕНЕНО
        )
        return self.storage.save_event(event)

    def log_interface_input(self, username: str, component: str,
                            input_data: Dict[str, Any]) -> bool:
        if not self._should_log(EventType.INTERFACE_INPUT.value):
            return True
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.INTERFACE_INPUT.value,
            event_name="Ввод данных через интерфейс",
            component=component,
            subject=username,
            headers={"input_summary": self._sanitize_data(input_data)},
            identifier=str(uuid.uuid4())  # ИЗМЕНЕНО
        )
        return self.storage.save_event(event)

    def log_interface_output(self, username: str, component: str,
                             output_summary: str) -> bool:
        if not self._should_log(EventType.INTERFACE_OUTPUT.value):
            return True
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.INTERFACE_OUTPUT.value,
            event_name="Вывод данных через интерфейс",
            component=component,
            subject=username,
            headers={"output_summary": output_summary},
            identifier=str(uuid.uuid4())  # ИЗМЕНЕНО
        )
        return self.storage.save_event(event)

    def log_api_request(self, username: str, endpoint: str, method: str,
                        status_code: int, response_time_ms: float) -> bool:
        if not self._should_log(EventType.API_REQUEST.value):
            return True
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.API_REQUEST.value,
            event_name="Запрос к API",
            component=endpoint,
            subject=username,
            headers={"method": method, "status_code": status_code,
                     "response_time_ms": response_time_ms},
            identifier=str(uuid.uuid4())  # ИЗМЕНЕНО
        )
        return self.storage.save_event(event)

    def log_api_auth_info(self, username: str, auth_method: str,
                          token_type: str, success: bool) -> bool:
        if not self._should_log(EventType.API_AUTH_INFO.value):
            return True
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.API_AUTH_INFO.value,
            event_name="Аутентификация API",
            component="/api/auth",
            subject=username,
            headers={"auth_method": auth_method, "token_type": token_type,
                     "success": success},
            identifier=str(uuid.uuid4())  # ИЗМЕНЕНО
        )
        return self.storage.save_event(event)

    def get_filtered_events(self, filters: List[IAuditFilter],
                            limit: int = 100) -> List[AuditEvent]:
        events = self.storage.get_events(limit=limit)
        composite = CompositeFilter(filters)
        return composite.apply(events)

    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Очистка данных от персональной информации (п. 3.3.3)"""
        sensitive_keys = ['password', 'pwd', 'fio', 'birth_date',
                          'passport', 'address', 'phone']
        sanitized = {}
        for key, value in data.items():
            if any(sens in key.lower() for sens in sensitive_keys):
                sanitized[key] = "***СКРЫТО***"
            else:
                sanitized[key] = value
        return sanitized


class LogRotationManager:
    """Менеджер ротации журналов (п. 3.3.6)"""

    # ИЗМЕНЕНО: добавлен параметр max_size_mb для ротации по объёму
    def __init__(self, storage: IAuditStorage,
                 retention_days: int = 90,
                 max_size_mb: float = 100.0):
        self.storage = storage
        self.retention_days = retention_days
        self.max_size_mb = max_size_mb  # ИЗМЕНЕНО

    def check_and_rotate(self) -> bool:
        """Ротация по времени"""
        return self.storage.rotate_logs(self.retention_days)

    # ИЗМЕНЕНО: новый метод ротации по объёму (п. 3.3.6)
    def check_and_rotate_by_size(self) -> bool:
        """Ротация по объёму файла"""
        return self.storage.rotate_logs_by_size(self.max_size_mb)

    # ИЗМЕНЕНО: автоматическая проверка обоих условий
    def auto_check(self) -> bool:
        """Автоматическая проверка: сначала по объёму, потом по времени"""
        size_ok = self.check_and_rotate_by_size()
        time_ok = self.check_and_rotate()
        return size_ok and time_ok

    def set_retention_period(self, days: int):
        self.retention_days = days

    def set_max_size_mb(self, mb: float):  # ИЗМЕНЕНО
        self.max_size_mb = mb


class AuditExporter:
    """Экспортер журналов на удаленный сервер (п. 3.3.5)"""

    def __init__(self, storage: IAuditStorage):
        self.storage = storage

    def export_to_json(self, events: List[AuditEvent], filepath: str) -> bool:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump([e.to_dict() for e in events], f,
                          ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"Ошибка экспорта в JSON: {e}")
            return False

    def export_to_csv(self, events: List[AuditEvent], filepath: str) -> bool:
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                if not events:
                    return True
                fieldnames = ['event_id', 'timestamp', 'event_type', 'event_name',
                              'component', 'subject', 'headers', 'identifier']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for event in events:
                    row = event.to_dict()
                    row['headers'] = json.dumps(row['headers'], ensure_ascii=False)
                    writer.writerow(row)
            return True
        except Exception as e:
            print(f"Ошибка экспорта в CSV: {e}")
            return False

    def send_to_remote_server(self, remote_path: str) -> bool:
        return self.storage.export_to_remote(remote_path)


class AuditSystemFactory:
    """Фабрика для создания компонентов системы аудита"""

    @staticmethod
    def create_default_system(db_path: str = "audit_events.db",
                              retention_days: int = 90,
                              max_size_mb: float = 100.0) -> tuple:
        storage = SQLiteAuditStorage(db_path)
        service = AuditService(storage)
        # ИЗМЕНЕНО: передаём max_size_mb в менеджер ротации
        rotation_manager = LogRotationManager(storage, retention_days, max_size_mb)
        exporter = AuditExporter(storage)
        return service, rotation_manager, exporter


# ============================================================================
# ПОДСИСТЕМА АУТЕНТИФИКАЦИИ
# ============================================================================

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
            'AUTH': {'max_attempts': '3', 'lockout_minutes': '15',
                     'rate_limit_window': '60',    # ИЗМЕНЕНО: окно rate limiting (сек)
                     'rate_limit_max': '10'},       # ИЗМЕНЕНО: макс. запросов в окне
            'PASSWORD': {'user_min_length': '6', 'admin_min_length': '7',
                         'special_chars': '~!@#$%^&*'},
            'TIME': {'timezone': 'Europe/Moscow', 'offset_hours': '3'},
            'BCRYPT': {'rounds': '12'},
            # ИЗМЕНЕНО: секция настройки аудита (п. 3.3.4)
            'AUDIT': {
                'max_size_mb': '100',
                'retention_days': '90',
                'enabled_types': 'ALL'   # ALL или список через запятую
            }
        }
        for section, values in defaults.items():
            self.config.add_section(section)
            for k, v in values.items():
                self.config.set(section, k, str(v))

        with open(path, 'w', encoding='utf-8') as f:
            self.config.write(f)

    @property
    def db_path(self): return self.config.get('DATABASE', 'path', fallback='users.db')
    @property
    def max_attempts(self): return int(self.config.get('AUTH', 'max_attempts', fallback='3'))
    @property
    def lockout_minutes(self): return int(self.config.get('AUTH', 'lockout_minutes', fallback='15'))
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
    # ИЗМЕНЕНО: свойства rate limiting
    @property
    def rate_limit_window(self): return int(self.config.get('AUTH', 'rate_limit_window', fallback='60'))
    @property
    def rate_limit_max(self): return int(self.config.get('AUTH', 'rate_limit_max', fallback='10'))
    # ИЗМЕНЕНО: свойства аудита
    @property
    def audit_max_size_mb(self): return float(self.config.get('AUDIT', 'max_size_mb', fallback='100'))
    @property
    def audit_retention_days(self): return int(self.config.get('AUDIT', 'retention_days', fallback='90'))
    @property
    def audit_enabled_types(self):
        val = self.config.get('AUDIT', 'enabled_types', fallback='ALL')
        if val.strip().upper() == 'ALL':
            return None  # None = все типы
        return [t.strip() for t in val.split(',')]

    def save_audit_enabled_types(self, types: Optional[List[str]]):
        """Сохранить настройку типов событий в config.ini"""
        if not self.config.has_section('AUDIT'):
            self.config.add_section('AUDIT')
        val = 'ALL' if types is None else ','.join(types)
        self.config.set('AUDIT', 'enabled_types', val)
        with open("config.ini", 'w', encoding='utf-8') as f:
            self.config.write(f)


config = Config()
import bcrypt


class BcryptHasher:
    def __init__(self): self.rounds = config.bcrypt_rounds

    def hash_password(self, pwd: str) -> dict:
        return {'hash': bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=self.rounds)).decode()}

    def verify_password(self, pwd: str, stored: str) -> bool:
        return bcrypt.checkpw(pwd.encode(), stored.encode())


class Database:
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
                username TEXT PRIMARY KEY, hash TEXT NOT NULL, is_admin INTEGER DEFAULT 0,
                failed INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0,
                need_change INTEGER DEFAULT 1, created_at INTEGER DEFAULT 0,
                last_login INTEGER DEFAULT 0)''')

    @contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        try:
            yield c; c.commit()
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
                          (u, h, 1 if adm else 0, 0, 0, 1, self._now(), self._now()))
                return True
            except:
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


class AuthSystem:
    def __init__(self):
        self.db = Database()
        self.hasher = BcryptHasher()
        self.cache: Dict[str, object] = {}
        # ИЗМЕНЕНО: rate limiting — словарь {ip: [(timestamp1), (timestamp2), ...]}
        self._rate_limit_store: Dict[str, List[float]] = {}

    # ИЗМЕНЕНО: метод проверки rate limit (п. 4.1.3)
    def check_rate_limit(self, ip: str) -> Tuple[bool, str]:
        """
        Проверяет, не превышен ли лимит запросов с данного IP.
        Возвращает (ok: bool, message: str).
        """
        now = time.time()
        window = config.rate_limit_window
        max_req = config.rate_limit_max

        if ip not in self._rate_limit_store:
            self._rate_limit_store[ip] = []

        # Очищаем старые записи за пределами окна
        self._rate_limit_store[ip] = [
            t for t in self._rate_limit_store[ip] if now - t < window
        ]

        if len(self._rate_limit_store[ip]) >= max_req:
            return False, f"Превышен лимит запросов ({max_req} за {window} сек). Подождите."

        self._rate_limit_store[ip].append(now)
        return True, "OK"

    def _load(self, u):
        d = self.db.get_user(u)
        if not d: return None
        acc = type('User', (), {})()
        acc.username, acc.password, acc.is_admin, acc.failed, acc.locked_until, acc.need_change = (
            u, d['hash'], bool(d['is_admin']), d['failed'], d['locked_until'], bool(d['need_change'])
        )
        self.cache[u] = acc
        return acc

    def _save(self, acc):
        self.db.update(acc.username, hash=acc.password, is_admin=acc.is_admin,
                       failed=acc.failed, locked_until=acc.locked_until,
                       need_change=acc.need_change)

    def _check_pwd(self, pwd, adm):
        mn = config.admin_min_length if adm else config.user_min_length
        pat = rf'[{re.escape(config.special_chars)}]'
        if len(pwd) < mn: return False, f"Мин. длина: {mn}"
        if not re.search(r'[A-Z]', pwd): return False, "Нужна заглавная буква"
        if not re.search(r'[a-z]', pwd): return False, "Нужна строчная буква"
        if not re.search(r'[0-9]', pwd): return False, "Нужна цифра"
        if not re.search(pat, pwd): return False, f"Нужен спецсимвол ({config.special_chars})"
        return True, "OK"

    def _not_contain_user(self, pwd, name):
        return (False, "Пароль содержит логин") if name.lower() in pwd.lower() else (True, "OK")

    def auth(self, u, pwd):
        acc = self.cache.get(u) or self._load(u)
        if not acc: return False, "Неверный логин или пароль", None
        now = int(time.time())
        if acc.locked_until > now:
            rem = int((acc.locked_until - now) / 60)
            return False, f"Блокировка. Осталось ~{rem} мин.", None
        elif acc.locked_until:
            acc.failed = acc.locked_until = 0; self._save(acc)

        if not self.hasher.verify_password(pwd, acc.password):
            acc.failed += 1
            if acc.failed >= config.max_attempts:
                acc.locked_until = int(time.time() + config.lockout_minutes * 60)
                self._save(acc)
                return False, f"Аккаунт заблокирован на {config.lockout_minutes} мин.", None
            self._save(acc)
            return False, f"Неверный пароль. Осталось: {config.max_attempts - acc.failed}", None

        acc.failed = acc.locked_until = 0
        self.db.update(acc.username, last_login=int(time.time() + config.time_offset * 3600))
        self._save(acc)

        if acc.need_change: return False, "Требуется смена пароля при первом входе", acc
        return True, "Успешный вход", acc

    def change(self, acc, new_pwd):
        v, m = self._check_pwd(new_pwd, acc.is_admin)
        if not v: return False, m
        v, m = self._not_contain_user(new_pwd, acc.username)
        if not v: return False, m
        h = self.hasher.hash_password(new_pwd)
        acc.password, acc.need_change = h['hash'], False
        self._save(acc)
        return True, "Пароль изменён"

    # ИЗМЕНЕНО: метод смены пароля администратором для другого пользователя (п. 3.2)
    def admin_reset_password(self, admin_acc, target_username: str,
                             new_pwd: str) -> Tuple[bool, str]:
        """Сброс пароля пользователю администратором."""
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
        target.need_change = True  # принудительная смена при следующем входе
        self._save(target)
        if target_username in self.cache:
            del self.cache[target_username]
        return True, "Пароль сброшен. Пользователю потребуется сменить пароль."

    # ИЗМЕНЕНО: метод ручной блокировки/разблокировки (п. 3.2)
    def admin_set_lock(self, admin_acc, target_username: str,
                       lock: bool) -> Tuple[bool, str]:
        """Блокировка/разблокировка пользователя администратором."""
        if not admin_acc.is_admin:
            return False, "Недостаточно прав"
        target = self._load(target_username)
        if not target:
            return False, "Пользователь не найден"
        if lock:
            target.locked_until = int(time.time()) + 10 * 365 * 24 * 3600  # ~10 лет
        else:
            target.locked_until = 0
            target.failed = 0
        self._save(target)
        if target_username in self.cache:
            del self.cache[target_username]
        return True, "Заблокирован" if lock else "Разблокирован"

    def create_admin_if_empty(self):
        if not self.db.all_users():
            self.db.create_user("admin", self.hasher.hash_password("Admin@12345")['hash'], True)
            print("Создан тестовый аккаунт: admin / Admin@12345")


# ============================================================================
# ИНТЕРФЕЙС
# ============================================================================

class LoginDialog(QDialog):
    def __init__(self, auth: AuthSystem, audit_service: AuditService):
        super().__init__()
        self.auth = auth
        self.audit_service = audit_service
        self.logged_account = None
        self.setWindowTitle("Вход в систему")
        self.resize(400, 260)
        self._setup_ui()

    def _setup_ui(self):
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("Логин")
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Идентификатор:", self.user_edit)
        form.addRow("Пароль:", self.pass_edit)
        lay.addLayout(form)
        self.status = QLabel()
        self.status.setStyleSheet("color:#d32f2f; font-weight:bold;")
        lay.addWidget(self.status)
        self.btn = QPushButton("Войти")
        self.btn.clicked.connect(self._try)
        lay.addWidget(self.btn)
        self.pass_edit.returnPressed.connect(self._try)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._check_lockout)
        self.locked_until = 0

    def _check_lockout(self):
        if self.locked_until > time.time():
            rem = int((self.locked_until - time.time()) / 60)
            self.status.setText(f"Блокировка. Авто-разблокировка через {rem} мин.")
        else:
            self.timer.stop()
            self.locked_until = 0
            self.status.clear()
            self.user_edit.setEnabled(True)
            self.pass_edit.setEnabled(True)
            self.btn.setText("Войти")
            self.btn.setEnabled(True)

    def _try(self):
        if self.locked_until > time.time(): return
        u, p = self.user_edit.text().strip(), self.pass_edit.text()
        if not u or not p:
            self.status.setText("Заполните поля")
            return

        # ИЗМЕНЕНО: проверка rate limit перед аутентификацией (п. 4.1.3)
        rate_ok, rate_msg = self.auth.check_rate_limit("127.0.0.1")
        if not rate_ok:
            self.status.setText(rate_msg)
            return

        ok, msg, acc = self.auth.auth(u, p)

        if ok:
            self.logged_account = acc
            self.audit_service.log_auth_login(u, "127.0.0.1", "PyQt6")
            self.accept()
        elif "Требуется смена" in msg:
            chg = ChangePasswordDialog(self.auth, acc)
            if chg.exec() == QDialog.DialogCode.Accepted:
                self.logged_account = acc
                self.audit_service.log_auth_login(u, "127.0.0.1", "PyQt6")
                self.audit_service.log_user_data_change(u, ["password"], u)
                self.accept()
            else:
                self.status.setText("Смена пароля отменена. Вход не выполнен.")
        else:
            self.status.setText(msg)
            self.pass_edit.clear()
            self.audit_service.log_auth_failed(u, "127.0.0.1", msg)
            if "заблокирован" in msg.lower():
                self.locked_until = acc.locked_until if acc else time.time() + 15 * 60
                self.timer.start(1000)
                self.user_edit.setEnabled(False)
                self.pass_edit.setEnabled(False)
                self.btn.setEnabled(False)
                self.btn.setText("Заблокировано")


class ChangePasswordDialog(QDialog):
    def __init__(self, auth: AuthSystem, account):
        super().__init__()
        self.auth, self.acc = auth, account
        self.setWindowTitle("Смена пароля (обязательно)")
        self.resize(360, 240)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.old = QLineEdit()
        self.old.setEchoMode(QLineEdit.EchoMode.Password)
        self.new = QLineEdit()
        self.new.setEchoMode(QLineEdit.EchoMode.Password)
        self.conf = QLineEdit()
        self.conf.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Текущий пароль:", self.old)
        form.addRow("Новый пароль:", self.new)
        form.addRow("Подтверждение:", self.conf)
        lay.addLayout(form)
        self.st = QLabel()
        self.st.setStyleSheet("color:#d32f2f;")
        lay.addWidget(self.st)
        btn = QPushButton("Сменить и продолжить")
        btn.clicked.connect(self._change)
        lay.addWidget(btn)

    def _change(self):
        if not self.hasher_verify(self.old.text(), self.acc.password):
            self.st.setText("Неверный текущий пароль")
            return
        if self.new.text() != self.conf.text():
            self.st.setText("Пароли не совпадают")
            return
        ok, msg = self.auth.change(self.acc, self.new.text())
        if ok:
            QMessageBox.information(self, "Успех", "Пароль изменён. Добро пожаловать в систему!")
            self.accept()
        else:
            self.st.setText(msg)

    def hasher_verify(self, pwd, stored):
        return bcrypt.checkpw(pwd.encode(), stored.encode())


# ИЗМЕНЕНО: новый диалог создания пользователя администратором
class CreateUserDialog(QDialog):
    """Диалог создания нового пользователя (только для администратора)"""

    def __init__(self, auth: AuthSystem, admin_acc, parent=None):
        super().__init__(parent)
        self.auth = auth
        self.admin_acc = admin_acc
        self.setWindowTitle("Создать пользователя")
        self.resize(360, 280)
        self._setup_ui()

    def _setup_ui(self):
        lay = QVBoxLayout(self)
        form = QFormLayout()

        self.edit_user = QLineEdit()
        self.edit_pwd = QLineEdit()
        self.edit_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit_pwd2 = QLineEdit()
        self.edit_pwd2.setEchoMode(QLineEdit.EchoMode.Password)
        self.chk_admin = QCheckBox("Администратор")

        form.addRow("Логин:", self.edit_user)
        form.addRow("Пароль:", self.edit_pwd)
        form.addRow("Подтверждение:", self.edit_pwd2)
        form.addRow("Роль:", self.chk_admin)
        lay.addLayout(form)

        self.lbl_status = QLabel()
        self.lbl_status.setStyleSheet("color:#d32f2f;")
        lay.addWidget(self.lbl_status)

        btn_box = QHBoxLayout()
        btn_ok = QPushButton("Создать")
        btn_ok.clicked.connect(self._create)
        btn_cancel = QPushButton("Отмена")
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_ok)
        btn_box.addWidget(btn_cancel)
        lay.addLayout(btn_box)

    def _create(self):
        u = self.edit_user.text().strip()
        p = self.edit_pwd.text()
        p2 = self.edit_pwd2.text()
        is_admin = self.chk_admin.isChecked()

        if not u:
            self.lbl_status.setText("Введите логин")
            return
        if p != p2:
            self.lbl_status.setText("Пароли не совпадают")
            return
        if self.auth.db.get_user(u):
            self.lbl_status.setText("Пользователь уже существует")
            return

        # Проверка сложности пароля
        v, m = self.auth._check_pwd(p, is_admin)
        if not v:
            self.lbl_status.setText(m)
            return
        v, m = self.auth._not_contain_user(p, u)
        if not v:
            self.lbl_status.setText(m)
            return

        h = self.auth.hasher.hash_password(p)['hash']
        ok = self.auth.db.create_user(u, h, is_admin)
        if ok:
            QMessageBox.information(self, "Успех",
                                    f"Пользователь '{u}' создан.\n"
                                    f"Роль: {'Администратор' if is_admin else 'Оператор'}\n"
                                    f"При первом входе потребуется смена пароля.")
            self.accept()
        else:
            self.lbl_status.setText("Ошибка создания пользователя")


# ИЗМЕНЕНО: новый диалог панели администратора
class AdminPanelDialog(QDialog):
    """
    Панель управления пользователями.
    Доступна только администраторам (п. 3.2).
    """

    def __init__(self, auth: AuthSystem, admin_acc,
                 audit_service: AuditService, parent=None):
        super().__init__(parent)
        self.auth = auth
        self.admin_acc = admin_acc
        self.audit_service = audit_service
        self.setWindowTitle("Управление пользователями (Администратор)")
        self.resize(800, 480)
        self._setup_ui()
        self._refresh()

    def _setup_ui(self):
        lay = QVBoxLayout(self)

        # Кнопки управления
        btn_row = QHBoxLayout()
        self.btn_create = QPushButton("➕ Создать пользователя")
        self.btn_delete = QPushButton("🗑 Удалить")
        self.btn_reset_pwd = QPushButton("🔑 Сбросить пароль")
        self.btn_lock = QPushButton("🔒 Заблокировать")
        self.btn_unlock = QPushButton("🔓 Разблокировать")
        self.btn_refresh = QPushButton("🔄 Обновить")

        for b in [self.btn_create, self.btn_delete, self.btn_reset_pwd,
                  self.btn_lock, self.btn_unlock, self.btn_refresh]:
            btn_row.addWidget(b)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        # Таблица пользователей
        self.tbl = QTableWidget(0, 7)
        self.tbl.setHorizontalHeaderLabels(
            ["Логин", "Роль", "Неудачных попыток",
             "Заблокирован", "Смена пароля", "Создан", "Последний вход"])
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        lay.addWidget(self.tbl)

        # Подключение кнопок
        self.btn_create.clicked.connect(self._create_user)
        self.btn_delete.clicked.connect(self._delete_user)
        self.btn_reset_pwd.clicked.connect(self._reset_pwd)
        self.btn_lock.clicked.connect(lambda: self._set_lock(True))
        self.btn_unlock.clicked.connect(lambda: self._set_lock(False))
        self.btn_refresh.clicked.connect(self._refresh)

    def _refresh(self):
        users = self.auth.db.all_users()
        self.tbl.setRowCount(0)
        now = int(time.time())
        for u in users:
            row = self.tbl.rowCount()
            self.tbl.insertRow(row)
            locked = u['locked_until'] > now
            lock_str = "ДА" if locked else "нет"
            need_chg = "ДА" if u['need_change'] else "нет"

            created_dt = datetime.fromtimestamp(u['created_at'] - config.time_offset * 3600
                                                ).strftime('%Y-%m-%d %H:%M') if u['created_at'] else "—"
            last_dt = datetime.fromtimestamp(u['last_login'] - config.time_offset * 3600
                                             ).strftime('%Y-%m-%d %H:%M') if u['last_login'] else "—"

            vals = [
                u['username'],
                "Администратор" if u['is_admin'] else "Оператор",
                str(u['failed']),
                lock_str,
                need_chg,
                created_dt,
                last_dt
            ]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if locked and col == 3:
                    item.setForeground(Qt.GlobalColor.red)
                self.tbl.setItem(row, col, item)

    def _selected_username(self) -> Optional[str]:
        rows = self.tbl.selectedItems()
        if not rows:
            QMessageBox.warning(self, "Ошибка", "Выберите пользователя в таблице.")
            return None
        return self.tbl.item(self.tbl.currentRow(), 0).text()

    def _create_user(self):
        dlg = CreateUserDialog(self.auth, self.admin_acc, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            # Аудит
            self.audit_service.log_admin_action(
                self.admin_acc.username, "create_user",
                {"created_by": self.admin_acc.username}
            )
            self._refresh()

    def _delete_user(self):
        username = self._selected_username()
        if not username: return
        if username == self.admin_acc.username:
            QMessageBox.warning(self, "Ошибка", "Нельзя удалить собственный аккаунт.")
            return
        reply = QMessageBox.question(
            self, "Подтверждение",
            f"Удалить пользователя '{username}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            ok = self.auth.db.delete(username)
            if ok:
                if username in self.auth.cache:
                    del self.auth.cache[username]
                self.audit_service.log_admin_action(
                    self.admin_acc.username, "delete_user",
                    {"deleted_user": username}
                )
                self._refresh()
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось удалить пользователя.")

    def _reset_pwd(self):
        username = self._selected_username()
        if not username: return

        new_pwd, ok = QInputDialog.getText(
            self, "Сброс пароля",
            f"Новый пароль для '{username}':",
            QLineEdit.EchoMode.Password
        )
        if not ok or not new_pwd:
            return

        result_ok, msg = self.auth.admin_reset_password(
            self.admin_acc, username, new_pwd
        )
        if result_ok:
            QMessageBox.information(self, "Успех", msg)
            self.audit_service.log_user_data_change(
                username, ["password"], self.admin_acc.username
            )
            self._refresh()
        else:
            QMessageBox.warning(self, "Ошибка", msg)

    def _set_lock(self, lock: bool):
        username = self._selected_username()
        if not username: return
        if username == self.admin_acc.username and lock:
            QMessageBox.warning(self, "Ошибка", "Нельзя заблокировать собственный аккаунт.")
            return
        result_ok, msg = self.auth.admin_set_lock(self.admin_acc, username, lock)
        if result_ok:
            QMessageBox.information(self, "Успех",
                                    f"Пользователь '{username}': {msg}")
            self.audit_service.log_admin_rights_change(
                self.admin_acc.username, username,
                {"action": "lock" if lock else "unlock"}
            )
            self._refresh()
        else:
            QMessageBox.warning(self, "Ошибка", msg)


# ИЗМЕНЕНО: новый диалог настройки детализации аудита (п. 3.3.4)
class AuditSettingsDialog(QDialog):
    """Настройка детализации аудита — включение/отключение типов событий"""

    def __init__(self, audit_service: AuditService, parent=None):
        super().__init__(parent)
        self.audit_service = audit_service
        self.setWindowTitle("Настройки аудита")
        self.resize(400, 420)
        self._setup_ui()

    def _setup_ui(self):
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Выберите типы событий для регистрации:"))

        self.checkboxes: Dict[str, QCheckBox] = {}
        enabled = self.audit_service.enabled_types  # None = все

        for et in EventType:
            chk = QCheckBox(et.value)
            chk.setChecked(enabled is None or et.value in enabled)
            self.checkboxes[et.value] = chk
            lay.addWidget(chk)

        # Кнопки "Выбрать все" / "Снять все"
        sel_row = QHBoxLayout()
        btn_all = QPushButton("Выбрать все")
        btn_none = QPushButton("Снять все")
        btn_all.clicked.connect(lambda: [c.setChecked(True) for c in self.checkboxes.values()])
        btn_none.clicked.connect(lambda: [c.setChecked(False) for c in self.checkboxes.values()])
        sel_row.addWidget(btn_all)
        sel_row.addWidget(btn_none)
        lay.addLayout(sel_row)

        # Настройка ротации по объёму
        lay.addWidget(QLabel("─" * 40))
        size_row = QFormLayout()
        self.sp_size = QDoubleSpinBox()
        self.sp_size.setRange(1, 10000)
        self.sp_size.setValue(config.audit_max_size_mb)
        self.sp_size.setSuffix(" МБ")
        size_row.addRow("Макс. размер БД:", self.sp_size)
        lay.addLayout(size_row)

        btn_box = QHBoxLayout()
        btn_ok = QPushButton("Применить")
        btn_ok.clicked.connect(self._apply)
        btn_cancel = QPushButton("Отмена")
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_ok)
        btn_box.addWidget(btn_cancel)
        lay.addLayout(btn_box)

    def _apply(self):
        selected = [k for k, v in self.checkboxes.items() if v.isChecked()]
        if len(selected) == len(EventType):
            self.audit_service.enabled_types = None  # все
        else:
            self.audit_service.enabled_types = selected

        # Сохраняем в config.ini
        config.save_audit_enabled_types(self.audit_service.enabled_types)

        # Размер для ротации
        # Применяется при следующей ротации через rotation_manager
        # Передаётся через родительское окно
        self._new_max_size = self.sp_size.value()
        self.accept()

    def get_new_max_size(self) -> float:
        return getattr(self, '_new_max_size', config.audit_max_size_mb)


class CalculationWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, inp):
        super().__init__()
        self.inp = inp

    def run(self):
        try:
            self.progress.emit(20)
            time.sleep(0.8)
            self.progress.emit(60)
            lb = self.inp["total_load"] / max(1, self.inp["num_blocks"])
            kt = (1 + 0.003 * (15 - self.inp["temp_c"]) if self.inp["temp_c"] <= 15
                  else 1 - 0.002 * (self.inp["temp_c"] - 15))
            kh = (1.0 if self.inp["humidity"] <= 60
                  else 1 - 0.0005 * (self.inp["humidity"] - 60))
            kws = 1 + 0.002 * min(self.inp["wind_speed"], 8)
            wd = self.inp["wind_dir"] % 360
            kwd = 0.99 if 0 <= wd <= 45 else (1.01 if 180 <= wd <= 225 else 1.00)
            k = kt * kh * kws * kwd
            eff = self.inp["nominal_efficiency"] * k
            lr = self.inp["total_load"] / (self.inp["num_blocks"] * self.inp["nominal_power"])
            eff_load = eff * (1 - self.inp["beta"] * (1 - lr) ** 2) if lr < 1 else eff
            own = self.inp.get("own_needs_coeff", 0.05)
            t = self.inp["temp_c"]
            if t > 25:
                own += 0.005 * (t - 25)
            elif t < 0:
                own += 0.003 * abs(t)
            en = eff_load * (1 - own)
            fuel = 123 / en if en > 0 else 999
            res = {
                "Нагрузка на энергоблок": round(lb, 2),
                "КПД блока": round(eff_load * 100, 2),
                "КПД ТЭС брутто": round(eff * 100, 2),
                "Собственные нужды": round(own * 100, 2),
                "КПД ТЭС нетто": round(en * 100, 2),
                "Удельный расход топлива": round(fuel, 1)
            }
            self.progress.emit(100)
            self.finished.emit(res)
        except Exception as e:
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    def __init__(self, account, auth_system, audit_service, rotation_manager, exporter):
        super().__init__()
        self.acc = account
        self.auth = auth_system
        self.audit_service = audit_service
        self.rotation_manager = rotation_manager
        self.exporter = exporter
        self._login_time = int(time.time())
        self._restart_login = False

        self.setWindowTitle(
            f"ТЭС: Оптимизация | {account.username} "
            f"[{'Админ' if account.is_admin else 'Оператор'}]"
        )
        self.resize(1000, 720)

        self._audit_filters: Dict[str, Any] = {}
        self._audit_limit = 100

        self._setup_ui()
        self._setup_signals()
        # ИЗМЕНЕНО: автоматическая проверка ротации при запуске
        self.rotation_manager.auto_check()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_lay = QVBoxLayout(central)

        mb = QMenuBar(self)
        self.setMenuBar(mb)
        acc_menu = mb.addMenu("Аккаунт")
        acc_menu.addAction("Сменить пароль", self._open_change_pwd)
        acc_menu.addSeparator()
        btn_logout = QAction("Выйти", self)
        btn_logout.triggered.connect(self._do_logout)
        acc_menu.addAction(btn_logout)

        # ИЗМЕНЕНО: меню администратора (только для is_admin)
        if self.acc.is_admin:
            admin_menu = mb.addMenu("Администратор")
            admin_menu.addAction("Управление пользователями", self._open_admin_panel)
            admin_menu.addAction("Настройки аудита", self._open_audit_settings)

        self.tabs = QTabWidget()
        main_lay.addWidget(self.tabs)

        # === ВКЛАДКА 1: РАСЧЁТ ===
        t1 = QWidget()
        l1 = QHBoxLayout(t1)
        inp_box = QGroupBox("Входные параметры")
        inp_form = QFormLayout(inp_box)

        self.sp_load = QDoubleSpinBox(); self.sp_load.setRange(1, 5000); self.sp_load.setValue(400)
        self.sp_blocks = QSpinBox(); self.sp_blocks.setRange(1, 20); self.sp_blocks.setValue(2)
        self.sp_np = QDoubleSpinBox(); self.sp_np.setRange(50, 1000); self.sp_np.setValue(300)
        self.sp_ne = QDoubleSpinBox(); self.sp_ne.setRange(0.1, 0.99); self.sp_ne.setSingleStep(0.01); self.sp_ne.setValue(0.38)
        self.sp_temp = QDoubleSpinBox(); self.sp_temp.setRange(-50, 60); self.sp_temp.setValue(25)
        self.sp_hum = QDoubleSpinBox(); self.sp_hum.setRange(0, 100); self.sp_hum.setValue(60)
        self.sp_ws = QDoubleSpinBox(); self.sp_ws.setRange(0, 50); self.sp_ws.setValue(3)
        self.sp_wd = QDoubleSpinBox(); self.sp_wd.setRange(0, 359); self.sp_wd.setValue(90)
        self.sp_beta = QDoubleSpinBox(); self.sp_beta.setRange(0.2, 0.6); self.sp_beta.setValue(0.4)
        self.sp_own = QDoubleSpinBox(); self.sp_own.setRange(0.01, 0.20); self.sp_own.setSingleStep(0.01); self.sp_own.setValue(0.05)

        for n, s in [("Общая нагрузка", self.sp_load), ("Блоки", self.sp_blocks),
                     ("Ном. мощность", self.sp_np), ("Ном. КПД", self.sp_ne),
                     ("Температура", self.sp_temp), ("Влажность", self.sp_hum),
                     ("Ветер скорость", self.sp_ws), ("Ветер направление", self.sp_wd),
                     ("β недогрузки", self.sp_beta), ("γ собств. нужд", self.sp_own)]:
            inp_form.addRow(n, s)

        self.btn_calc = QPushButton("▶ Рассчитать")
        self.btn_calc.setStyleSheet("background:#2196F3; color:white; padding:8px; font-weight:bold;")
        inp_form.addRow(self.btn_calc)
        l1.addWidget(inp_box)

        res_box = QGroupBox("Выходные данные")
        res_lay = QVBoxLayout(res_box)
        self.tbl = QTableWidget(6, 2)
        self.tbl.setHorizontalHeaderLabels(["Показатель", "Значение"])
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        for i, k in enumerate(["Нагрузка на энергоблок", "КПД блока", "КПД ТЭС брутто",
                                "Собственные нужды", "КПД ТЭС нетто", "Удельный расход топлива"]):
            self.tbl.setItem(i, 0, QTableWidgetItem(k))
            self.tbl.setItem(i, 1, QTableWidgetItem("—"))
        self.pb = QProgressBar()
        self.pb.hide()
        res_lay.addWidget(self.tbl)
        res_lay.addWidget(self.pb)
        l1.addWidget(res_box)
        self.tabs.addTab(t1, "Расчёт")

        # === ВКЛАДКА 2: ВАКУУМ ===
        t2 = QWidget()
        l2 = QVBoxLayout(t2)
        vac_box = QGroupBox("Оптимизация вакуума")
        vac_form = QFormLayout(vac_box)
        self.sp_cool = QDoubleSpinBox(); self.sp_cool.setRange(0, 40); self.sp_cool.setValue(25)
        self.sp_steam = QDoubleSpinBox(); self.sp_steam.setRange(50, 2000); self.sp_steam.setValue(400)
        vac_form.addRow("Темп. воды °C", self.sp_cool)
        vac_form.addRow("Расход пара кг/с", self.sp_steam)
        self.btn_vac = QPushButton("Найти оптимальный вакуум")
        vac_form.addRow(self.btn_vac)
        self.lbl_vac = QLabel("—")
        self.lbl_vac.setStyleSheet("font:14pt bold; color:#2e7d32;")
        vac_form.addRow(self.lbl_vac)
        l2.addWidget(vac_box)
        self.tabs.addTab(t2, "Вакуум")

        # === ВКЛАДКА 3: ГРАФИКИ ===
        t3 = QWidget()
        l3 = QVBoxLayout(t3)
        ch = QHBoxLayout()
        ch.addWidget(QLabel("График:"))
        self.combo = QComboBox()
        self.combo.addItems(["Теплоотдача & T", "КПД нетто & T", "Расход & T"])
        ch.addWidget(self.combo)
        self.btn_plot = QPushButton("Построить")
        self.btn_plot.setStyleSheet("background:#4CAF50; color:white;")
        ch.addWidget(self.btn_plot)
        ch.addStretch()
        l3.addLayout(ch)
        self.canvas = FigureCanvas(Figure(figsize=(9, 5), dpi=100))
        self.ax = self.canvas.figure.subplots()
        l3.addWidget(self.canvas)
        self.tabs.addTab(t3, "Визуализация")

        # === ВКЛАДКА 4: АУДИТ ===
        t4 = QWidget()
        l4 = QVBoxLayout(t4)

        at = QHBoxLayout()
        self.btn_audit_refresh = QPushButton("Обновить")
        self.btn_audit_export = QPushButton("Экспорт")
        self.btn_audit_filter = QPushButton("Фильтр")

        # ИЗМЕНЕНО: кнопки "Отправка", "Ротация" — только для администраторов (п. 3.2)
        self.btn_audit_send = QPushButton("Отправка")
        self.btn_audit_rotate = QPushButton("Ротация")

        for b in [self.btn_audit_refresh, self.btn_audit_export,
                  self.btn_audit_filter, self.btn_audit_send, self.btn_audit_rotate]:
            at.addWidget(b)

        # ИЗМЕНЕНО: скрываем admin-кнопки для обычных пользователей
        if not self.acc.is_admin:
            self.btn_audit_send.setEnabled(False)
            self.btn_audit_send.setToolTip("Только для администраторов")
            self.btn_audit_rotate.setEnabled(False)
            self.btn_audit_rotate.setToolTip("Только для администраторов")

        # ИЗМЕНЕНО: добавлена метка размера БД аудита
        self.lbl_audit_size = QLabel()
        at.addWidget(self.lbl_audit_size)
        at.addStretch()
        l4.addLayout(at)

        self.tbl_audit = QTableWidget(0, 8)  # ИЗМЕНЕНО: 8 колонок (добавлен Identifier)
        self.tbl_audit.setHorizontalHeaderLabels(
            ["ID", "Время", "Тип", "Субъект", "Объект",
             "Наименование", "Заголовки", "Идентификатор"])  # ИЗМЕНЕНО
        self.tbl_audit.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl_audit.verticalHeader().setVisible(False)
        self.tbl_audit.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        l4.addWidget(self.tbl_audit)

        self.tabs.addTab(t4, "Аудит")

    def _setup_signals(self):
        self.btn_calc.clicked.connect(self._calc)
        self.btn_vac.clicked.connect(self._vac)
        self.btn_plot.clicked.connect(self._plot)

        self.btn_audit_refresh.clicked.connect(self._audit_refresh)
        self.btn_audit_export.clicked.connect(self._audit_export)
        self.btn_audit_filter.clicked.connect(self._audit_filter)
        self.btn_audit_send.clicked.connect(self._audit_send)
        self.btn_audit_rotate.clicked.connect(self._audit_rotate)

        self.tabs.currentChanged.connect(self._on_tab_changed)

    def _on_tab_changed(self, index):
        if self.tabs.tabText(index) == "Аудит":
            self._audit_refresh()

    # ИЗМЕНЕНО: открытие панели администратора
    def _open_admin_panel(self):
        if not self.acc.is_admin:
            QMessageBox.warning(self, "Доступ запрещён",
                                "Панель администратора доступна только администраторам.")
            return
        dlg = AdminPanelDialog(self.auth, self.acc, self.audit_service, self)
        dlg.exec()

    # ИЗМЕНЕНО: открытие настроек аудита
    def _open_audit_settings(self):
        if not self.acc.is_admin:
            QMessageBox.warning(self, "Доступ запрещён", "Только для администраторов.")
            return
        dlg = AuditSettingsDialog(self.audit_service, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            new_size = dlg.get_new_max_size()
            self.rotation_manager.set_max_size_mb(new_size)
            self.audit_service.log_admin_params_change(
                self.acc.username, "audit_settings",
                {"enabled_types": self.audit_service.enabled_types,
                 "max_size_mb": new_size}
            )
            QMessageBox.information(self, "Настройки", "Настройки аудита сохранены.")

    # ------------------------------------------------------------------
    # Методы вкладки "Аудит"
    # ------------------------------------------------------------------

    def _audit_refresh(self):
        events = self.audit_service.storage.get_events(
            filters=self._audit_filters if self._audit_filters else None,
            limit=self._audit_limit
        )
        self._fill_audit_table(events)
        # ИЗМЕНЕНО: показываем размер БД
        size_mb = self.audit_service.storage.get_db_size_mb()
        self.lbl_audit_size.setText(f"БД аудита: {size_mb:.2f} МБ")

    def _fill_audit_table(self, events: List[AuditEvent]):
        self.tbl_audit.setRowCount(0)
        for event in events:
            row = self.tbl_audit.rowCount()
            self.tbl_audit.insertRow(row)
            headers_str = json.dumps(event.headers, ensure_ascii=False)
            values = [
                str(event.event_id) if event.event_id is not None else "—",
                event.timestamp[:19].replace("T", " "),
                event.event_type,
                event.subject,
                event.component,
                event.event_name,
                headers_str,
                event.identifier or "—"  # ИЗМЕНЕНО: показываем UUID
            ]
            for col, val in enumerate(values):
                self.tbl_audit.setItem(row, col, QTableWidgetItem(val))

    def _audit_export(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт журнала аудита", "",
            "JSON файлы (*.json);;CSV файлы (*.csv);;Все файлы (*)"
        )
        if not path:
            return

        events = self.audit_service.storage.get_events(
            filters=self._audit_filters if self._audit_filters else None,
            limit=self._audit_limit
        )

        if path.lower().endswith(".csv"):
            ok = self.exporter.export_to_csv(events, path)
        else:
            ok = self.exporter.export_to_json(events, path)

        if ok:
            QMessageBox.information(self, "Экспорт", f"Журнал успешно экспортирован:\n{path}")
            self.audit_service.log_admin_params_change(
                self.acc.username, "audit_export",
                {"file": path, "records": len(events)}
            )
        else:
            QMessageBox.warning(self, "Экспорт", "Ошибка при экспорте журнала.")

    def _audit_filter(self):
        dlg = AuditFilterDialog(self)
        dlg.set_filters(self._audit_filters, self._audit_limit)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._audit_filters, self._audit_limit = dlg.get_filters()
            self._audit_refresh()

    def _audit_send(self):
        # ИЗМЕНЕНО: проверка прав перед отправкой
        if not self.acc.is_admin:
            QMessageBox.warning(self, "Доступ запрещён", "Только для администраторов.")
            return
        path = QFileDialog.getExistingDirectory(
            self, "Выберите папку для отправки журнала"
        )
        if not path:
            return

        ok = self.exporter.send_to_remote_server(path)
        if ok:
            QMessageBox.information(
                self, "Отправка",
                f"База данных аудита скопирована в:\n{path}"
            )
            self.audit_service.log_admin_params_change(
                self.acc.username, "audit_send",
                {"remote_path": path}
            )
        else:
            QMessageBox.warning(self, "Отправка", "Ошибка при отправке журнала.")

    def _audit_rotate(self):
        # ИЗМЕНЕНО: проверка прав перед ротацией
        if not self.acc.is_admin:
            QMessageBox.warning(self, "Доступ запрещён", "Только для администраторов.")
            return

        # ИЗМЕНЕНО: предлагаем два режима ротации
        reply = QMessageBox.question(
            self, "Ротация журналов",
            "Выберите режим ротации:\n\n"
            "Yes — по времени (задать количество дней)\n"
            "No — по объёму файла",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No |
            QMessageBox.StandardButton.Cancel
        )

        if reply == QMessageBox.StandardButton.Cancel:
            return

        if reply == QMessageBox.StandardButton.Yes:
            days, ok = QInputDialog.getInt(
                self, "Ротация по времени",
                "Удалить записи старше (дней):",
                value=self.rotation_manager.retention_days,
                min=1, max=3650
            )
            if not ok:
                return
            self.rotation_manager.set_retention_period(days)
            result = self.rotation_manager.check_and_rotate()
            mode_str = f"по времени ({days} дней)"
        else:
            mb, ok = QInputDialog.getDouble(
                self, "Ротация по объёму",
                "Максимальный размер БД (МБ):",
                value=self.rotation_manager.max_size_mb,
                min=1, max=100000, decimals=1
            )
            if not ok:
                return
            self.rotation_manager.set_max_size_mb(mb)
            result = self.rotation_manager.check_and_rotate_by_size()
            mode_str = f"по объёму ({mb} МБ)"

        if result:
            QMessageBox.information(
                self, "Ротация",
                f"Ротация {mode_str} выполнена успешно."
            )
            self.audit_service.log_admin_params_change(
                self.acc.username, "audit_rotation",
                {"mode": mode_str}
            )
            self._audit_refresh()
        else:
            QMessageBox.warning(self, "Ротация", "Ошибка при выполнении ротации.")

    # ------------------------------------------------------------------
    # Остальные методы (без изменений)
    # ------------------------------------------------------------------

    def _do_logout(self):
        duration = int(time.time()) - self._login_time
        self.audit_service.log_auth_logout(self.acc.username, duration)
        self.close()

    def _open_change_pwd(self):
        dlg = ChangePasswordDialog(self.auth, self.acc)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.audit_service.log_user_data_change(
                self.acc.username, ["password"], self.acc.username
            )
            QMessageBox.information(self, "Успех",
                                    "Пароль изменён.\nТребуется повторная аутентификация.")
            self.close()

    def _validate(self):
        if self.sp_load.value() <= 0:
            QMessageBox.warning(self, "Ошибка", "Нагрузка > 0")
            return False
        if not (0 <= self.sp_hum.value() <= 100):
            QMessageBox.warning(self, "Ошибка", "Влажность 0-100%")
            return False
        if not (0 <= self.sp_wd.value() < 360):
            QMessageBox.warning(self, "Ошибка", "Ветер 0-359°")
            return False
        return True

    def _calc(self):
        if not self._validate(): return
        inp = {
            "total_load": self.sp_load.value(),
            "num_blocks": self.sp_blocks.value(),
            "nominal_power": self.sp_np.value(),
            "nominal_efficiency": self.sp_ne.value(),
            "temp_c": self.sp_temp.value(),
            "humidity": self.sp_hum.value(),
            "wind_speed": self.sp_ws.value(),
            "wind_dir": self.sp_wd.value(),
            "beta": self.sp_beta.value(),
            "own_needs_coeff": self.sp_own.value()
        }
        self.audit_service.log_interface_input(self.acc.username, "calc_params", inp)
        self.pb.show()
        self.pb.setValue(0)
        self.btn_calc.setEnabled(False)
        self.w = CalculationWorker(inp)
        self.w.finished.connect(self._on_res)
        self.w.error.connect(
            lambda m: (self.pb.hide(), self.btn_calc.setEnabled(True),
                       QMessageBox.critical(self, "Ошибка", m))
        )
        self.w.progress.connect(self.pb.setValue)
        self.w.start()

    def _on_res(self, r):
        self.pb.hide()
        self.btn_calc.setEnabled(True)
        for i in range(6):
            for k, v in r.items():
                if self.tbl.item(i, 0).text() == k:
                    self.tbl.setItem(i, 1, QTableWidgetItem(str(v)))
                    break
        self.audit_service.log_interface_output(
            self.acc.username, "calc_results",
            str({k: v for k, v in r.items()})
        )

    def _vac(self):
        t = self.sp_cool.value()
        result_text = f"Оптимальное разрежение: {round(4.5 - 0.02 * (t - 20), 2)} кПа"
        self.lbl_vac.setText(result_text)
        self.audit_service.log_interface_output(
            self.acc.username, "vacuum_calc", result_text
        )

    def _plot(self):
        self.ax.clear()
        idx = self.combo.currentIndex()
        T = np.arange(-30, 45, 5)
        if idx == 0:
            C = 1000 * (1 - 0.01 * (T - 15))
            self.ax.plot(T, C, 'b-o')
            self.ax.set_ylabel("МВт")
            self.ax.set_title("Теплоотдача")
        elif idx == 1:
            E = []
            for t in T:
                kt = 1 + 0.003 * (15 - t) if t <= 15 else 1 - 0.002 * (t - 15)
                kh = 1 if self.sp_hum.value() <= 60 else 1 - 0.0005 * (self.sp_hum.value() - 60)
                kws = 1 + 0.002 * min(self.sp_ws.value(), 8)
                wd = self.sp_wd.value() % 360
                kwd = 0.99 if 0 <= wd <= 45 else (1.01 if 180 <= wd <= 225 else 1)
                k = kt * kh * kws * kwd
                en = self.sp_ne.value() * k
                lr = self.sp_load.value() / (self.sp_blocks.value() * self.sp_np.value())
                eff = en * (1 - self.sp_beta.value() * (1 - lr) ** 2) if lr < 1 else en
                own = self.sp_own.value()
                if t > 25: own += 0.005 * (t - 25)
                elif t < 0: own += 0.003 * abs(t)
                E.append(eff * (1 - own) * 100)
            self.ax.plot(T, E, 'g-s')
            self.ax.set_ylabel("КПД нетто, %")
            self.ax.set_title("КПД vs T")
        else:
            F = []
            for t in T:
                kt = 1 + 0.003 * (15 - t) if t <= 15 else 1 - 0.002 * (t - 15)
                kh = 1 if self.sp_hum.value() <= 60 else 1 - 0.0005 * (self.sp_hum.value() - 60)
                kws = 1 + 0.002 * min(self.sp_ws.value(), 8)
                wd = self.sp_wd.value() % 360
                kwd = 0.99 if 0 <= wd <= 45 else (1.01 if 180 <= wd <= 225 else 1)
                k = kt * kh * kws * kwd
                en = self.sp_ne.value() * k
                lr = self.sp_load.value() / (self.sp_blocks.value() * self.sp_np.value())
                eff = en * (1 - self.sp_beta.value() * (1 - lr) ** 2) if lr < 1 else en
                own = self.sp_own.value()
                if t > 25: own += 0.005 * (t - 25)
                elif t < 0: own += 0.003 * abs(t)
                F.append(123 / (eff * (1 - own)) if eff * (1 - own) > 0 else 999)
            self.ax.plot(T, F, 'r-^')
            self.ax.set_ylabel("г/кВт·ч")
            self.ax.set_title("Расход vs T")

        self.ax.set_xlabel("T, °C")
        self.ax.grid(True, alpha=0.3)
        self.ax.axvline(15, color='orange', ls=':')
        self.canvas.draw_idle()

        self.audit_service.log_interface_output(
            self.acc.username, "visualization",
            f"График: {self.combo.currentText()}"
        )

    def closeEvent(self, event):
        """Обрабатывает нажатие на крестик (X)"""
        if not self._restart_login:
            # Закрытие через крестик → полный выход из приложения
            duration = int(time.time()) - self._login_time
            self.audit_service.log_auth_logout(self.acc.username, duration)
            # Завершаем процесс, чтобы цикл while True в __main__ не создавал новый LoginDialog
            import sys
            sys.exit(0)
        super().closeEvent(event)


# ============================================================================
# ДИАЛОГ ФИЛЬТРАЦИИ АУДИТА
# ============================================================================

class AuditFilterDialog(QDialog):
    """Диалог настройки фильтров для таблицы аудита"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Фильтр журнала аудита")
        self.resize(400, 300)
        self._setup_ui()

    def _setup_ui(self):
        lay = QVBoxLayout(self)
        form = QFormLayout()

        self.combo_type = QComboBox()
        self.combo_type.addItem("Все типы", "")
        for et in EventType:
            self.combo_type.addItem(et.value, et.value)
        form.addRow("Тип события:", self.combo_type)

        self.edit_subject = QLineEdit()
        self.edit_subject.setPlaceholderText("Имя пользователя (пусто = все)")
        form.addRow("Субъект:", self.edit_subject)

        self.edit_date_from = QLineEdit()
        self.edit_date_from.setPlaceholderText("YYYY-MM-DD (пусто = без ограничения)")
        form.addRow("Дата от:", self.edit_date_from)

        self.edit_date_to = QLineEdit()
        self.edit_date_to.setPlaceholderText("YYYY-MM-DD (пусто = без ограничения)")
        form.addRow("Дата до:", self.edit_date_to)

        self.sp_limit = QSpinBox()
        self.sp_limit.setRange(10, 10000)
        self.sp_limit.setValue(100)
        form.addRow("Макс. записей:", self.sp_limit)

        lay.addLayout(form)

        btn_box = QHBoxLayout()
        btn_ok = QPushButton("Применить")
        btn_ok.clicked.connect(self.accept)
        btn_reset = QPushButton("Сбросить")
        btn_reset.clicked.connect(self._reset)
        btn_cancel = QPushButton("Отмена")
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_ok)
        btn_box.addWidget(btn_reset)
        btn_box.addWidget(btn_cancel)
        lay.addLayout(btn_box)

    def _reset(self):
        self.combo_type.setCurrentIndex(0)
        self.edit_subject.clear()
        self.edit_date_from.clear()
        self.edit_date_to.clear()
        self.sp_limit.setValue(100)

    def set_filters(self, filters: Dict[str, Any], limit: int):
        self.sp_limit.setValue(limit)
        if "event_type" in filters:
            idx = self.combo_type.findData(filters["event_type"])
            if idx >= 0:
                self.combo_type.setCurrentIndex(idx)
        if "subject" in filters:
            self.edit_subject.setText(filters["subject"])
        if "date_from" in filters:
            self.edit_date_from.setText(filters["date_from"])
        if "date_to" in filters:
            self.edit_date_to.setText(filters["date_to"])

    def get_filters(self) -> Tuple[Dict[str, Any], int]:
        filters = {}
        event_type = self.combo_type.currentData()
        if event_type:
            filters["event_type"] = event_type
        subject = self.edit_subject.text().strip()
        if subject:
            filters["subject"] = subject
        date_from = self.edit_date_from.text().strip()
        if date_from:
            filters["date_from"] = date_from
        date_to = self.edit_date_to.text().strip()
        if date_to:
            filters["date_to"] = date_to
        return filters, self.sp_limit.value()


# ============================================================================
# ТОЧКА ВХОДА
# ============================================================================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))

    auth = AuthSystem()
    auth.create_admin_if_empty()

    # ИЗМЕНЕНО: передаём max_size_mb из config
    audit_service, rotation_manager, exporter = AuditSystemFactory.create_default_system(
        max_size_mb=config.audit_max_size_mb
    )
    # ИЗМЕНЕНО: применяем настройку типов событий из config.ini
    audit_service.enabled_types = config.audit_enabled_types

    while True:
        dlg = LoginDialog(auth, audit_service)
        if dlg.exec() != QDialog.DialogCode.Accepted or dlg.logged_account is None:
            sys.exit(0)

        main_win = MainWindow(
            dlg.logged_account, auth,
            audit_service, rotation_manager, exporter
        )
        main_win.show()
        app.exec()