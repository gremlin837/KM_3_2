import json
import os
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from enum import Enum
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
import gzip
import shutil


# ============================================================================
# ПЕРЕЧИСЛЕНИЯ И СТРУКТУРЫ ДАННЫХ (п. 3.3.1)
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
    identifier: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'AuditEvent':
        return AuditEvent(**data)


# ============================================================================
# ИНТЕРФЕЙСЫ (SOLID: Interface Segregation Principle)
# ============================================================================

class IAuditStorage(ABC):
    """Интерфейс хранилища событий (п. 3.3.4, 3.3.5)"""
    
    @abstractmethod
    def save_event(self, event: AuditEvent) -> bool:
        """Сохранить событие в хранилище"""
        pass

    @abstractmethod
    def get_events(self, filters: Optional[Dict[str, Any]] = None, 
                   limit: int = 100) -> List[AuditEvent]:
        """Получить события с фильтрацией"""
        pass

    @abstractmethod
    def rotate_logs(self, retention_days: int) -> bool:
        """Ротация журналов (п. 3.3.6)"""
        pass

    @abstractmethod
    def export_to_remote(self, remote_path: str) -> bool:
        """Отправка на удаленный сервер (п. 3.3.5)"""
        pass


class IAuditFilter(ABC):
    """Интерфейс фильтрации событий"""
    
    @abstractmethod
    def apply(self, events: List[AuditEvent]) -> List[AuditEvent]:
        """Применить фильтр к списку событий"""
        pass


# ============================================================================
# ХРАНИЛИЩЕ НА ОСНОВЕ SQLite (SOLID: Dependency Inversion Principle)
# ============================================================================

class SQLiteAuditStorage(IAuditStorage):
    """
    Реализация хранилища на SQLite
    Обеспечивает настраиваемую глубину хранения (п. 3.3.4)
    """
    
    def __init__(self, db_path: str = "audit_events.db"):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Инициализация структуры БД"""
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
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_event_type ON audit_events(event_type)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_subject ON audit_events(subject)
            """)
            conn.commit()

    def save_event(self, event: AuditEvent) -> bool:
        """Сохранение события в БД"""
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
        """Получение событий с фильтрацией"""
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
        """
        Ротация журналов (п. 3.3.6)
        Архивирование и удаление старых записей
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM audit_events WHERE timestamp < ?
                """, (cutoff_date,))
                old_events = cursor.fetchall()

                if old_events:
                    archive_path = f"audit_archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json.gz"
                    archive_data = []
                    
                    for row in old_events:
                        archive_data.append({
                            "event_id": row[0],
                            "timestamp": row[1],
                            "event_type": row[2],
                            "event_name": row[3],
                            "component": row[4],
                            "subject": row[5],
                            "headers": json.loads(row[6]),
                            "identifier": row[7]
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

    def export_to_remote(self, remote_path: str) -> bool:
        """
        Отправка журналов на удаленный сервер (п. 3.3.5)
        В данной реализации - копирование в указанную директори��
        """
        try:
            export_file = f"audit_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            export_path = os.path.join(remote_path, export_file)
            
            os.makedirs(remote_path, exist_ok=True)
            shutil.copy2(self.db_path, export_path)
            
            return True
        except Exception as e:
            print(f"Ошибка экспорта на удаленный сервер: {e}")
            return False


# ============================================================================
# ФИЛЬТРЫ (SOLID: Open/Closed Principle)
# ============================================================================

class EventTypeFilter(IAuditFilter):
    """Фильтр по типу события"""
    
    def __init__(self, event_type: EventType):
        self.event_type = event_type.value

    def apply(self, events: List[AuditEvent]) -> List[AuditEvent]:
        return [e for e in events if e.event_type == self.event_type]


class DateRangeFilter(IAuditFilter):
    """Фильтр по диапазону дат"""
    
    def __init__(self, date_from: str, date_to: str):
        self.date_from = date_from
        self.date_to = date_to

    def apply(self, events: List[AuditEvent]) -> List[AuditEvent]:
        return [e for e in events if self.date_from <= e.timestamp <= self.date_to]


class SubjectFilter(IAuditFilter):
    """Фильтр по субъекту (пользователю)"""
    
    def __init__(self, subject: str):
        self.subject = subject

    def apply(self, events: List[AuditEvent]) -> List[AuditEvent]:
        return [e for e in events if e.subject == self.subject]


class CompositeFilter(IAuditFilter):
    """Композитный фильтр для объединения нескольких фильтров"""
    
    def __init__(self, filters: List[IAuditFilter]):
        self.filters = filters

    def apply(self, events: List[AuditEvent]) -> List[AuditEvent]:
        result = events
        for filter_obj in self.filters:
            result = filter_obj.apply(result)
        return result


# ============================================================================
# СЕРВИС АУДИТА (SOLID: Single Responsibility Principle)
# ============================================================================

class AuditService:
    """
    Основной сервис для работы с аудитом
    Обеспечивает регистрацию всех типов событий согласно п. 3.3.1
    """
    
    def __init__(self, storage: IAuditStorage):
        self.storage = storage

    def log_auth_login(self, username: str, ip_address: str, user_agent: str) -> bool:
        """Регистрация входа пользователя"""
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.AUTH_LOGIN.value,
            event_name="Вход в систему",
            component="/auth/login",
            subject=username,
            headers={
                "ip": ip_address,
                "user_agent": user_agent,
                "method": "POST"
            }
        )
        return self.storage.save_event(event)

    def log_auth_logout(self, username: str, session_duration: int) -> bool:
        """Регистрация выхода пользователя"""
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.AUTH_LOGOUT.value,
            event_name="Выход из системы",
            component="/auth/logout",
            subject=username,
            headers={
                "session_duration_seconds": session_duration
            }
        )
        return self.storage.save_event(event)

    def log_auth_failed(self, username: str, ip_address: str, reason: str) -> bool:
        """Регистрация неудачной попытки входа"""
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.AUTH_FAILED.value,
            event_name="Ошибка аутентификации",
            component="/auth/login",
            subject=username,
            headers={
                "ip": ip_address,
                "reason": reason
            }
        )
        return self.storage.save_event(event)

    def log_user_data_change(self, username: str, changed_fields: List[str], 
                            changed_by: str) -> bool:
        """Регистрация изменения данных пользователя"""
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.USER_DATA_CHANGE.value,
            event_name="Изменение данных пользователя",
            component="user_profile",
            subject=changed_by,
            headers={
                "target_user": username,
                "changed_fields": changed_fields
            }
        )
        return self.storage.save_event(event)

    def log_admin_rights_change(self, admin: str, target_user: str, 
                               rights_changed: Dict[str, Any]) -> bool:
        """Регистрация изменения прав доступа"""
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.ADMIN_RIGHTS_CHANGE.value,
            event_name="Изменение прав доступа",
            component="access_control",
            subject=admin,
            headers={
                "target_user": target_user,
                "rights_changed": rights_changed
            }
        )
        return self.storage.save_event(event)

    def log_admin_params_change(self, admin: str, component: str, 
                               params_changed: Dict[str, Any]) -> bool:
        """Регистрация изменения параметров системы"""
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.ADMIN_PARAMS_CHANGE.value,
            event_name="Изменение параметров системы",
            component=component,
            subject=admin,
            headers={
                "params_changed": params_changed
            }
        )
        return self.storage.save_event(event)

    def log_interface_input(self, username: str, component: str, 
                           input_data: Dict[str, Any]) -> bool:
        """Регистрация ввода данных через интерфейс"""
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.INTERFACE_INPUT.value,
            event_name="Ввод данных через интерфейс",
            component=component,
            subject=username,
            headers={
                "input_summary": self._sanitize_data(input_data)
            }
        )
        return self.storage.save_event(event)

    def log_interface_output(self, username: str, component: str, 
                            output_summary: str) -> bool:
        """Регистрация вывода данных через интерфейс"""
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.INTERFACE_OUTPUT.value,
            event_name="Вывод данных через интерфейс",
            component=component,
            subject=username,
            headers={
                "output_summary": output_summary
            }
        )
        return self.storage.save_event(event)

    def log_api_request(self, username: str, endpoint: str, method: str, 
                       status_code: int, response_time_ms: float) -> bool:
        """Регистрация запроса к API"""
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.API_REQUEST.value,
            event_name="Запрос к API",
            component=endpoint,
            subject=username,
            headers={
                "method": method,
                "status_code": status_code,
                "response_time_ms": response_time_ms
            }
        )
        return self.storage.save_event(event)

    def log_api_auth_info(self, username: str, auth_method: str, 
                         token_type: str, success: bool) -> bool:
        """Регистрация информации об аутентификации API"""
        event = AuditEvent(
            event_id=None,
            timestamp=datetime.now().isoformat(),
            event_type=EventType.API_AUTH_INFO.value,
            event_name="Аутентификация API",
            component="/api/auth",
            subject=username,
            headers={
                "auth_method": auth_method,
                "token_type": token_type,
                "success": success
            }
        )
        return self.storage.save_event(event)

    def get_filtered_events(self, filters: List[IAuditFilter], 
                           limit: int = 100) -> List[AuditEvent]:
        """Получение отфильтрованных событий"""
        events = self.storage.get_events(limit=limit)
        composite = CompositeFilter(filters)
        return composite.apply(events)

    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Очистка данных от персональной информации (п. 3.3.3)
        Удаляет пароли, ФИО, даты рождения и т.д.
        """
        sensitive_keys = ['password', 'pwd', 'fio', 'birth_date', 
                         'passport', 'address', 'phone']
        sanitized = {}
        for key, value in data.items():
            if any(sens in key.lower() for sens in sensitive_keys):
                sanitized[key] = "***СКРЫТО***"
            else:
                sanitized[key] = value
        return sanitized


# ============================================================================
# МЕНЕДЖЕР РОТАЦИИ (SOLID: Single Responsibility Principle)
# ============================================================================

class LogRotationManager:
    """
    Менеджер ротации журналов (п. 3.3.6)
    Обеспечивает автоматическую ротацию при достижении лимитов
    """
    
    def __init__(self, storage: IAuditStorage, retention_days: int = 90):
        self.storage = storage
        self.retention_days = retention_days

    def check_and_rotate(self) -> bool:
        """Проверка и выполнение ротации при необходимости"""
        return self.storage.rotate_logs(self.retention_days)

    def set_retention_period(self, days: int):
        """Настройка периода хранения"""
        self.retention_days = days


# ============================================================================
# ЭКСПОРТЕР (SOLID: Single Responsibility Principle)
# ============================================================================

class AuditExporter:
    """
    Экспортер журналов на удаленный сервер (п. 3.3.5)
    """
    
    def __init__(self, storage: IAuditStorage):
        self.storage = storage

    def export_to_json(self, events: List[AuditEvent], filepath: str) -> bool:
        """Экспорт событий в JSON"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump([e.to_dict() for e in events], f, 
                         ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"Ошибка экспорта в JSON: {e}")
            return False

    def export_to_csv(self, events: List[AuditEvent], filepath: str) -> bool:
        """Экспорт событий в CSV"""
        try:
            import csv
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
        """Отправка на удаленный сервер"""
        return self.storage.export_to_remote(remote_path)


# ============================================================================
# ФАБРИКА (SOLID: Dependency Inversion + Factory Pattern)
# ============================================================================

class AuditSystemFactory:
    """
    Фабрика для создания компонентов системы аудита
    Упрощает интеграцию в существующий код
    """
    
    @staticmethod
    def create_default_system(db_path: str = "audit_events.db", 
                             retention_days: int = 90) -> tuple:
        """
        Создание системы аудита с настройками по умолчанию
        Возвращает: (AuditService, LogRotationManager, AuditExporter)
        """
        storage = SQLiteAuditStorage(db_path)
        service = AuditService(storage)
        rotation_manager = LogRotationManager(storage, retention_days)
        exporter = AuditExporter(storage)
        
        return service, rotation_manager, exporter


# ============================================================================
# ПРИМЕР ИСПОЛЬЗОВАНИЯ ДЛЯ ИНТЕГРАЦИИ
# ============================================================================

if __name__ == "__main__":
    # Создание системы аудита
    audit_service, rotation_mgr, exporter = AuditSystemFactory.create_default_system()
    
    # Примеры регистрации событий
    audit_service.log_auth_login("engineer_ivanov", "192.168.1.50", "PyQt6/6.6.1")
    audit_service.log_api_request("engineer_ivanov", "/api/calculate", "POST", 200, 125.5)
    audit_service.log_interface_input("engineer_ivanov", "calc_params", 
                                     {"load": 450, "blocks": 2, "password": "secret123"})
    
    # Получение событий с фильтрацией
    filters = [EventTypeFilter(EventType.AUTH_LOGIN)]
    filtered_events = audit_service.get_filtered_events(filters, limit=50)
    
    # Экспорт событий
    all_events = audit_service.storage.get_events(limit=1000)
    exporter.export_to_json(all_events, "audit_export.json")
    exporter.export_to_csv(all_events, "audit_export.csv")
    
    # Ротация журналов
    rotation_mgr.check_and_rotate()
    
    # Отправка на удаленный сервер
    exporter.send_to_remote_server("./remote_backup")
    
    print(f"Зарегистрировано событий: {len(all_events)}")
    print(f"Отфильтрованных событий: {len(filtered_events)}")