"""
audit/audit_service.py
Подсистема аудита и логирования (п. 3.3).
"""
import os
import csv
import gzip
import json
import uuid
import shutil
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional


class EventType(Enum):
    """Типы событий согласно п. 3.3.1"""
    AUTH_LOGIN         = "AUTH_LOGIN"
    AUTH_LOGOUT        = "AUTH_LOGOUT"
    AUTH_FAILED        = "AUTH_FAILED"
    USER_DATA_CHANGE   = "USER_DATA_CHANGE"
    ADMIN_ACTION       = "ADMIN_ACTION"
    ADMIN_RIGHTS_CHANGE = "ADMIN_RIGHTS_CHANGE"
    ADMIN_PARAMS_CHANGE = "ADMIN_PARAMS_CHANGE"
    INTERFACE_INPUT    = "INTERFACE_INPUT"
    INTERFACE_OUTPUT   = "INTERFACE_OUTPUT"
    API_REQUEST        = "API_REQUEST"
    API_AUTH_INFO      = "API_AUTH_INFO"


@dataclass
class AuditEvent:
    """Структура события аудита (п. 3.3.2). Скопировано из main_v2.py."""
    event_id:   Optional[int]
    timestamp:  str
    event_type: str
    event_name: str
    component:  str
    subject:    str
    headers:    Dict[str, Any]
    identifier: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'AuditEvent':
        return AuditEvent(**data)


class IAuditStorage(ABC):
    @abstractmethod
    def save_event(self, event: AuditEvent) -> bool: ...
    @abstractmethod
    def get_events(self, filters: Optional[Dict[str, Any]] = None,
                   limit: int = 100) -> List[AuditEvent]: ...
    @abstractmethod
    def rotate_logs(self, retention_days: int) -> bool: ...
    @abstractmethod
    def rotate_logs_by_size(self, max_size_mb: float) -> bool: ...
    @abstractmethod
    def export_to_remote(self, remote_path: str) -> bool: ...
    @abstractmethod
    def get_db_size_mb(self) -> float: ...


class IAuditFilter(ABC):
    @abstractmethod
    def apply(self, events: List[AuditEvent]) -> List[AuditEvent]: ...


class SQLiteAuditStorage(IAuditStorage):
    """SQLite-хранилище событий. Скопировано из main_v2.py."""

    def __init__(self, db_path: str = "audit_events.db"):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp  TEXT    NOT NULL,
                    event_type TEXT    NOT NULL,
                    event_name TEXT    NOT NULL,
                    component  TEXT    NOT NULL,
                    subject    TEXT    NOT NULL,
                    headers    TEXT    NOT NULL,
                    identifier TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_ts   ON audit_events(timestamp)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_type ON audit_events(event_type)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_subj ON audit_events(subject)")
            conn.commit()

    def save_event(self, event: AuditEvent) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.cursor().execute("""
                    INSERT INTO audit_events
                    (timestamp,event_type,event_name,component,subject,headers,identifier)
                    VALUES (?,?,?,?,?,?,?)
                """, (event.timestamp, event.event_type, event.event_name,
                      event.component, event.subject,
                      json.dumps(event.headers, ensure_ascii=False),
                      event.identifier))
                conn.commit()
            return True
        except Exception as e:
            print(f"Ошибка сохранения события: {e}")
            return False

    def get_events(self, filters: Optional[Dict[str, Any]] = None,
                   limit: int = 100) -> List[AuditEvent]:
        query  = "SELECT * FROM audit_events WHERE 1=1"
        params = []
        if filters:
            if "event_type" in filters:
                query += " AND event_type = ?"; params.append(filters["event_type"])
            if "subject"    in filters:
                query += " AND subject = ?";    params.append(filters["subject"])
            if "date_from"  in filters:
                query += " AND timestamp >= ?"; params.append(filters["date_from"])
            if "date_to"    in filters:
                query += " AND timestamp <= ?"; params.append(filters["date_to"])
        query += " ORDER BY event_id DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            rows = conn.cursor().execute(query, params).fetchall()

        return [AuditEvent(
            event_id=r[0], timestamp=r[1], event_type=r[2],
            event_name=r[3], component=r[4], subject=r[5],
            headers=json.loads(r[6]), identifier=r[7]
        ) for r in rows]

    def rotate_logs(self, retention_days: int) -> bool:
        """Ротация по времени (п. 3.3.6). Скопировано из main_v2.py."""
        try:
            cutoff = (datetime.now() - timedelta(days=retention_days)).isoformat()
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                old = c.execute(
                    "SELECT * FROM audit_events WHERE timestamp < ?", (cutoff,)
                ).fetchall()
                if old:
                    arch = (f"audit_archive_"
                            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json.gz")
                    with gzip.open(arch, 'wt', encoding='utf-8') as f:
                        json.dump([{
                            "event_id": r[0], "timestamp": r[1],
                            "event_type": r[2], "event_name": r[3],
                            "component": r[4], "subject": r[5],
                            "headers": json.loads(r[6]), "identifier": r[7]
                        } for r in old], f, ensure_ascii=False, indent=2)
                    c.execute("DELETE FROM audit_events WHERE timestamp < ?", (cutoff,))
                    conn.commit()
                c.execute("VACUUM")
                conn.commit()
            return True
        except Exception as e:
            print(f"Ошибка ротации: {e}"); return False

    def rotate_logs_by_size(self, max_size_mb: float) -> bool:
        """Ротация по объёму (п. 3.3.6). Скопировано из main_v2.py."""
        try:
            if self.get_db_size_mb() <= max_size_mb:
                return True
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                total = c.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
                to_del = max(1, int(total * 0.20))
                old = c.execute(
                    "SELECT * FROM audit_events ORDER BY event_id ASC LIMIT ?",
                    (to_del,)
                ).fetchall()
                if old:
                    arch = (f"audit_archive_size_"
                            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json.gz")
                    with gzip.open(arch, 'wt', encoding='utf-8') as f:
                        json.dump([{
                            "event_id": r[0], "timestamp": r[1],
                            "event_type": r[2], "event_name": r[3],
                            "component": r[4], "subject": r[5],
                            "headers": json.loads(r[6]), "identifier": r[7]
                        } for r in old], f, ensure_ascii=False, indent=2)
                    ids = [r[0] for r in old]
                    c.execute(
                        f"DELETE FROM audit_events WHERE event_id IN"
                        f" ({','.join('?'*len(ids))})", ids
                    )
                    conn.commit()
                c.execute("VACUUM"); conn.commit()
            return True
        except Exception as e:
            print(f"Ошибка ротации по объёму: {e}"); return False

    def get_db_size_mb(self) -> float:
        if os.path.exists(self.db_path):
            return os.path.getsize(self.db_path) / (1024 * 1024)
        return 0.0

    def export_to_remote(self, remote_path: str) -> bool:
        try:
            os.makedirs(remote_path, exist_ok=True)
            dst = os.path.join(
                remote_path,
                f"audit_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            )
            shutil.copy2(self.db_path, dst)
            return True
        except Exception as e:
            print(f"Ошибка экспорта: {e}"); return False


# ---------- Фильтры ----------

class EventTypeFilter(IAuditFilter):
    def __init__(self, event_type: EventType): self.et = event_type.value
    def apply(self, events): return [e for e in events if e.event_type == self.et]


class DateRangeFilter(IAuditFilter):
    def __init__(self, date_from, date_to): self.df, self.dt = date_from, date_to
    def apply(self, events): return [e for e in events if self.df <= e.timestamp <= self.dt]


class SubjectFilter(IAuditFilter):
    def __init__(self, subject): self.s = subject
    def apply(self, events): return [e for e in events if e.subject == self.s]


class CompositeFilter(IAuditFilter):
    def __init__(self, filters): self.filters = filters
    def apply(self, events):
        r = events
        for f in self.filters: r = f.apply(r)
        return r


# ---------- Сервис ----------

class AuditService:
    """Основной сервис аудита. Скопировано из main_v2.py."""

    def __init__(self, storage: IAuditStorage,
                 enabled_types: Optional[List[str]] = None):
        self.storage = storage
        self.enabled_types: Optional[List[str]] = enabled_types

    def _should_log(self, et: str) -> bool:
        return self.enabled_types is None or et in self.enabled_types

    def _evt(self, et: EventType, name: str, component: str,
              subject: str, headers: dict) -> bool:
        if not self._should_log(et.value):
            return True
        return self.storage.save_event(AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=et.value, event_name=name,
            component=component, subject=subject,
            headers=headers, identifier=str(uuid.uuid4())
        ))

    def log_auth_login(self, username, ip, user_agent):
        return self._evt(EventType.AUTH_LOGIN, "Вход в систему",
                         "/auth/login", username,
                         {"ip": ip, "user_agent": user_agent, "method": "POST"})

    def log_auth_logout(self, username, session_duration):
        return self._evt(EventType.AUTH_LOGOUT, "Выход из системы",
                         "/auth/logout", username,
                         {"session_duration_seconds": session_duration})

    def log_auth_failed(self, username, ip, reason):
        return self._evt(EventType.AUTH_FAILED, "Ошибка аутентификации",
                         "/auth/login", username,
                         {"ip": ip, "reason": reason})

    def log_user_data_change(self, username, changed_fields, changed_by):
        return self._evt(EventType.USER_DATA_CHANGE, "Изменение данных пользователя",
                         "user_profile", changed_by,
                         {"target_user": username, "changed_fields": changed_fields})

    def log_admin_action(self, admin, action, details):
        return self._evt(EventType.ADMIN_ACTION,
                         f"Действие администратора: {action}",
                         "admin_panel", admin, details)

    def log_admin_rights_change(self, admin, target_user, rights_changed):
        return self._evt(EventType.ADMIN_RIGHTS_CHANGE, "Изменение прав доступа",
                         "access_control", admin,
                         {"target_user": target_user, "rights_changed": rights_changed})

    def log_admin_params_change(self, admin, component, params_changed):
        return self._evt(EventType.ADMIN_PARAMS_CHANGE, "Изменение параметров системы",
                         component, admin, {"params_changed": params_changed})

    def log_interface_input(self, username, component, input_data):
        return self._evt(EventType.INTERFACE_INPUT, "Ввод данных через интерфейс",
                         component, username,
                         {"input_summary": self._sanitize(input_data)})

    def log_interface_output(self, username, component, output_summary):
        return self._evt(EventType.INTERFACE_OUTPUT, "Вывод данных через интерфейс",
                         component, username, {"output_summary": output_summary})

    def log_api_request(self, username, endpoint, method, status_code, rt_ms):
        return self._evt(EventType.API_REQUEST, "Запрос к API",
                         endpoint, username,
                         {"method": method, "status_code": status_code,
                          "response_time_ms": rt_ms})

    def log_api_auth_info(self, username, auth_method, token_type, success):
        return self._evt(EventType.API_AUTH_INFO, "Аутентификация API",
                         "/api/auth", username,
                         {"auth_method": auth_method, "token_type": token_type,
                          "success": success})

    def _sanitize(self, data: dict) -> dict:
        sensitive = ['password', 'pwd', 'fio', 'birth_date',
                     'passport', 'address', 'phone']
        return {
            k: ("***СКРЫТО***"
                if any(s in k.lower() for s in sensitive)
                else v)
            for k, v in data.items()
        }

    def get_filtered_events(self, filters: List[IAuditFilter],
                             limit: int = 100) -> List[AuditEvent]:
        events = self.storage.get_events(limit=limit)
        return CompositeFilter(filters).apply(events)


class LogRotationManager:
    """Менеджер ротации (п. 3.3.6). Скопировано из main_v2.py."""

    def __init__(self, storage: IAuditStorage,
                 retention_days: int = 90, max_size_mb: float = 100.0):
        self.storage = storage
        self.retention_days = retention_days
        self.max_size_mb = max_size_mb

    def check_and_rotate(self):
        return self.storage.rotate_logs(self.retention_days)

    def check_and_rotate_by_size(self):
        return self.storage.rotate_logs_by_size(self.max_size_mb)

    def auto_check(self):
        return self.check_and_rotate_by_size() and self.check_and_rotate()

    def set_retention_period(self, days: int): self.retention_days = days
    def set_max_size_mb(self, mb: float):      self.max_size_mb = mb


class AuditExporter:
    """Экспортер журналов (п. 3.3.5). Скопировано из main_v2.py."""

    def __init__(self, storage: IAuditStorage):
        self.storage = storage

    def export_to_json(self, events, filepath):
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump([e.to_dict() for e in events], f,
                          ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"Ошибка JSON: {e}"); return False

    def export_to_csv(self, events, filepath):
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                if not events: return True
                fields = ['event_id','timestamp','event_type','event_name',
                          'component','subject','headers','identifier']
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader()
                for e in events:
                    row = e.to_dict()
                    row['headers'] = json.dumps(row['headers'], ensure_ascii=False)
                    w.writerow(row)
            return True
        except Exception as e:
            print(f"Ошибка CSV: {e}"); return False

    def send_to_remote_server(self, remote_path):
        return self.storage.export_to_remote(remote_path)


class AuditSystemFactory:
    """Фабрика системы аудита. Скопировано из main_v2.py."""

    @staticmethod
    def create_default_system(db_path="audit_events.db",
                              retention_days=90,
                              max_size_mb=100.0):
        storage  = SQLiteAuditStorage(db_path)
        service  = AuditService(storage)
        rotation = LogRotationManager(storage, retention_days, max_size_mb)
        exporter = AuditExporter(storage)
        return service, rotation, exporter