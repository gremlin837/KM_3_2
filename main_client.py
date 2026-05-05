"""
client/main_client.py
Клиентская часть на PyQt6.
Общается с оркестратором (порт 8001), который является брокером сообщений.
Скопировано и адаптировано из main_v2.py.

Запуск:
    cd project
    python client/main_client.py

Зависимости:
    pip install PyQt6 matplotlib numpy bcrypt requests PyJWT httpx fastapi uvicorn bcrypt
"""

import sys
import os
import time
import json
import csv
import re

# Добавляем корень проекта в sys.path для импортов
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import requests
import numpy as np

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QFormLayout, QGroupBox, QLabel, QPushButton, QDoubleSpinBox,
    QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget, QHeaderView,
    QProgressBar, QMenuBar, QMessageBox, QComboBox, QFileDialog,
    QLineEdit, QDialog, QInputDialog, QCheckBox
)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt6.QtGui import QFont, QAction

import matplotlib
matplotlib.use("Qt5Agg")
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from database import config
from audit_service import AuditSystemFactory, EventType

# ── URL оркестратора (брокера сообщений) ─────────────────────────────────────
ORCH_URL = f"http://{config.orch_host}:{config.orch_port}"

# ── Локальная система аудита клиента ─────────────────────────────────────────
_audit_service, _rotation_mgr, _exporter = AuditSystemFactory.create_default_system(
    db_path="audit_client.db",
    max_size_mb=config.audit_max_size_mb
)
_audit_service.enabled_types = config.audit_enabled_types


# ── HTTP клиент ───────────────────────────────────────────────────────────────
class APIClient:
    """
    Тонкий клиент для взаимодействия с оркестратором.
    Все запросы идут через брокер сообщений (orchestrator).
    """

    def __init__(self):
        self.token: str = ""
        self.username: str = ""
        self.is_admin: bool = False
        self.session = requests.Session()

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def login(self, username: str, password: str) -> tuple[bool, str, bool]:
        """
        Аутентификация через оркестратор → сервер.
        Возвращает (ok, message, need_change).
        """
        try:
            r = self.session.post(
                f"{ORCH_URL}/api/auth/login",
                json={"username": username, "password": password},
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                self.token    = data["access_token"]
                self.username = data["username"]
                self.is_admin = data["is_admin"]
                return True, "Успешный вход", False
            elif r.status_code == 403:
                detail = r.json().get("detail", {})
                if isinstance(detail, dict) and detail.get("need_change"):
                    return False, detail.get("msg", "Требуется смена пароля"), True
                return False, r.json().get("detail", "Ошибка"), False
            else:
                return False, r.json().get("detail", "Ошибка"), False
        except requests.exceptions.ConnectionError:
            return False, "Нет связи с сервером. Запустите orchestrator и server.", False
        except Exception as e:
            return False, str(e), False

    def change_password(self, old_pwd: str, new_pwd: str) -> tuple[bool, str]:
        try:
            r = self.session.post(
                f"{ORCH_URL}/api/auth/change-password",
                json={"old_password": old_pwd, "new_password": new_pwd},
                headers=self._headers(), timeout=10
            )
            if r.status_code == 200:
                return True, r.json().get("detail", "OK")
            return False, r.json().get("detail", "Ошибка")
        except Exception as e:
            return False, str(e)

    def calculate(self, params: dict) -> tuple[bool, dict | str]:
        try:
            r = self.session.post(
                f"{ORCH_URL}/api/calculate",
                json=params, headers=self._headers(), timeout=15
            )
            if r.status_code == 200:
                return True, r.json()
            return False, r.json().get("detail", "Ошибка расчёта")
        except requests.exceptions.ConnectionError:
            return False, "Нет связи с оркестратором"
        except Exception as e:
            return False, str(e)

    def analyze_temperature(self, params: dict) -> tuple[bool, dict | str]:
        try:
            r = self.session.post(
                f"{ORCH_URL}/api/analyze/temperature",
                json=params, headers=self._headers(), timeout=15
            )
            if r.status_code == 200:
                return True, r.json()
            return False, r.json().get("detail", "Ошибка")
        except Exception as e:
            return False, str(e)

    def get_audit_events(self, limit=100, **filters) -> list:
        try:
            params = {"limit": limit}
            params.update(filters)
            r = self.session.get(
                f"{ORCH_URL}/api/audit/events",
                params=params, headers=self._headers(), timeout=10
            )
            if r.status_code == 200:
                return r.json()
            return []
        except Exception:
            return []

    def get_users(self) -> list:
        try:
            r = self.session.get(
                f"{ORCH_URL}/api/admin/users",
                headers=self._headers(), timeout=10
            )
            return r.json() if r.status_code == 200 else []
        except Exception:
            return []

    def create_user(self, username, password, is_admin) -> tuple[bool, str]:
        try:
            r = self.session.post(
                f"{ORCH_URL}/api/admin/users",
                json={"username": username, "password": password, "is_admin": is_admin},
                headers=self._headers(), timeout=10
            )
            if r.status_code == 200:
                return True, r.json().get("detail", "OK")
            return False, r.json().get("detail", "Ошибка")
        except Exception as e:
            return False, str(e)

    def delete_user(self, username) -> tuple[bool, str]:
        try:
            r = self.session.delete(
                f"{ORCH_URL}/api/admin/users/{username}",
                headers=self._headers(), timeout=10
            )
            if r.status_code == 200:
                return True, r.json().get("detail", "OK")
            return False, r.json().get("detail", "Ошибка")
        except Exception as e:
            return False, str(e)

    def reset_password(self, username, new_pwd) -> tuple[bool, str]:
        try:
            r = self.session.post(
                f"{ORCH_URL}/api/admin/users/{username}/reset-password",
                json={"new_password": new_pwd},
                headers=self._headers(), timeout=10
            )
            if r.status_code == 200:
                return True, r.json().get("detail", "OK")
            return False, r.json().get("detail", "Ошибка")
        except Exception as e:
            return False, str(e)

    def set_lock(self, username, lock: bool) -> tuple[bool, str]:
        try:
            r = self.session.post(
                f"{ORCH_URL}/api/admin/users/{username}/lock",
                json={"lock": lock},
                headers=self._headers(), timeout=10
            )
            if r.status_code == 200:
                return True, r.json().get("detail", "OK")
            return False, r.json().get("detail", "Ошибка")
        except Exception as e:
            return False, str(e)


api = APIClient()


# ── Диалог входа ─────────────────────────────────────────────────────────────
class LoginDialog(QDialog):
    """Диалог аутентификации. Адаптировано из main_v2.py."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Вход в систему — ТЭС")
        self.resize(400, 280)
        self._setup_ui()

    def _setup_ui(self):
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("<h3>Система оптимизации ТЭС</h3>"))

        form = QFormLayout()
        self.edit_user = QLineEdit()
        self.edit_user.setPlaceholderText("Логин")
        self.edit_pass = QLineEdit()
        self.edit_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit_pass.setPlaceholderText("Пароль (скрыт)")
        form.addRow("Идентификатор:", self.edit_user)
        form.addRow("Пароль:", self.edit_pass)
        lay.addLayout(form)

        self.lbl_status = QLabel()
        self.lbl_status.setStyleSheet("color:#d32f2f; font-weight:bold;")
        lay.addWidget(self.lbl_status)

        self.btn_login = QPushButton("Войти")
        self.btn_login.setStyleSheet(
            "background:#2196F3; color:white; padding:8px; font-weight:bold;"
        )
        self.btn_login.clicked.connect(self._try_login)
        self.edit_pass.returnPressed.connect(self._try_login)
        lay.addWidget(self.btn_login)

        lbl_hint = QLabel(
            "<small>Сервер: " + ORCH_URL + "</small>"
        )
        lbl_hint.setStyleSheet("color: gray;")
        lay.addWidget(lbl_hint)

        # Таймер блокировки — скопировано из main_v2.py
        self._locked_until = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._check_lockout)

    def _check_lockout(self):
        if self._locked_until > time.time():
            rem = int((self._locked_until - time.time()) / 60)
            self.lbl_status.setText(f"Блокировка. Авто-разблокировка ~через {rem} мин.")
        else:
            self._timer.stop()
            self._locked_until = 0
            self.lbl_status.clear()
            self.edit_user.setEnabled(True)
            self.edit_pass.setEnabled(True)
            self.btn_login.setEnabled(True)
            self.btn_login.setText("Войти")

    def _try_login(self):
        if self._locked_until > time.time():
            return
        u = self.edit_user.text().strip()
        p = self.edit_pass.text()
        if not u or not p:
            self.lbl_status.setText("Заполните оба поля")
            return

        self.btn_login.setEnabled(False)
        self.btn_login.setText("Подключение...")
        QApplication.processEvents()

        ok, msg, need_change = api.login(u, p)

        if ok:
            _audit_service.log_auth_login(u, "localhost", "PyQt6")
            self.accept()
        elif need_change:
            # Требуется смена пароля — показываем диалог
            dlg = ChangePasswordDialog()
            dlg.lbl_info.setText(f"Первый вход. Смените пароль для '{u}'.")
            if dlg.exec() == QDialog.DialogCode.Accepted:
                old_p = dlg.edit_old.text()
                new_p = dlg.edit_new.text()
                # Сначала логинимся без смены
                chg_ok, chg_msg = api.change_password(old_p, new_p)
                if chg_ok:
                    # Перелогиниваемся
                    ok2, msg2, _ = api.login(u, new_p)
                    if ok2:
                        _audit_service.log_auth_login(u, "localhost", "PyQt6")
                        _audit_service.log_user_data_change(u, ["password"], u)
                        self.accept()
                        return
                    self.lbl_status.setText(msg2)
                else:
                    self.lbl_status.setText(chg_msg)
            self.btn_login.setEnabled(True)
            self.btn_login.setText("Войти")
        else:
            self.lbl_status.setText(msg)
            self.edit_pass.clear()
            _audit_service.log_auth_failed(u, "localhost", msg)
            self.btn_login.setEnabled(True)
            self.btn_login.setText("Войти")

            if "заблокирован" in msg.lower():
                self._locked_until = time.time() + config.lockout_minutes * 60
                self._timer.start(1000)
                self.edit_user.setEnabled(False)
                self.edit_pass.setEnabled(False)
                self.btn_login.setEnabled(False)
                self.btn_login.setText("Заблокировано")


class ChangePasswordDialog(QDialog):
    """Диалог смены пароля. Адаптировано из main_v2.py."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Смена пароля")
        self.resize(360, 260)
        lay = QVBoxLayout(self)
        self.lbl_info = QLabel("Смените пароль:")
        self.lbl_info.setStyleSheet("font-weight:bold;")
        lay.addWidget(self.lbl_info)
        form = QFormLayout()
        self.edit_old  = QLineEdit(); self.edit_old.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit_new  = QLineEdit(); self.edit_new.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit_conf = QLineEdit(); self.edit_conf.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Текущий пароль:", self.edit_old)
        form.addRow("Новый пароль:",   self.edit_new)
        form.addRow("Подтверждение:",  self.edit_conf)
        lay.addLayout(form)
        self.lbl_st = QLabel()
        self.lbl_st.setStyleSheet("color:#d32f2f;")
        lay.addWidget(self.lbl_st)
        btn = QPushButton("Сменить и войти")
        btn.clicked.connect(self._change)
        lay.addWidget(btn)

    def _change(self):
        if self.edit_new.text() != self.edit_conf.text():
            self.lbl_st.setText("Пароли не совпадают")
            return
        self.accept()


# ── Диалог создания пользователя ─────────────────────────────────────────────
class CreateUserDialog(QDialog):
    """Адаптировано из main_v2.py."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Создать пользователя")
        self.resize(360, 260)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.edit_user  = QLineEdit()
        self.edit_pwd   = QLineEdit(); self.edit_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit_pwd2  = QLineEdit(); self.edit_pwd2.setEchoMode(QLineEdit.EchoMode.Password)
        self.chk_admin  = QCheckBox("Администратор")
        form.addRow("Логин:",          self.edit_user)
        form.addRow("Пароль:",         self.edit_pwd)
        form.addRow("Подтверждение:",  self.edit_pwd2)
        form.addRow("Роль:",           self.chk_admin)
        lay.addLayout(form)
        self.lbl_st = QLabel(); self.lbl_st.setStyleSheet("color:#d32f2f;")
        lay.addWidget(self.lbl_st)
        btn_box = QHBoxLayout()
        b_ok = QPushButton("Создать"); b_ok.clicked.connect(self._create)
        b_no = QPushButton("Отмена");  b_no.clicked.connect(self.reject)
        btn_box.addWidget(b_ok); btn_box.addWidget(b_no)
        lay.addLayout(btn_box)

    def _create(self):
        u  = self.edit_user.text().strip()
        p  = self.edit_pwd.text()
        p2 = self.edit_pwd2.text()
        if not u:    self.lbl_st.setText("Введите логин");        return
        if p != p2:  self.lbl_st.setText("Пароли не совпадают");  return
        ok, msg = api.create_user(u, p, self.chk_admin.isChecked())
        if ok:
            QMessageBox.information(self, "Успех", msg)
            self.accept()
        else:
            self.lbl_st.setText(msg)


# ── Панель администратора ─────────────────────────────────────────────────────
class AdminPanelDialog(QDialog):
    """Адаптировано из main_v2.py."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Управление пользователями")
        self.resize(820, 480)
        self._setup_ui()
        self._refresh()

    def _setup_ui(self):
        lay = QVBoxLayout(self)
        btn_row = QHBoxLayout()
        self.btn_create  = QPushButton("➕ Создать")
        self.btn_delete  = QPushButton("🗑 Удалить")
        self.btn_reset   = QPushButton("🔑 Сбросить пароль")
        self.btn_lock    = QPushButton("🔒 Заблокировать")
        self.btn_unlock  = QPushButton("🔓 Разблокировать")
        self.btn_refresh = QPushButton("🔄 Обновить")
        for b in [self.btn_create, self.btn_delete, self.btn_reset,
                  self.btn_lock, self.btn_unlock, self.btn_refresh]:
            btn_row.addWidget(b)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        self.tbl = QTableWidget(0, 7)
        self.tbl.setHorizontalHeaderLabels(
            ["Логин", "Роль", "Неудачных", "Заблокирован",
             "Смена пароля", "Создан", "Последний вход"])
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        lay.addWidget(self.tbl)

        self.btn_create.clicked.connect(self._create)
        self.btn_delete.clicked.connect(self._delete)
        self.btn_reset.clicked.connect(self._reset_pwd)
        self.btn_lock.clicked.connect(lambda: self._set_lock(True))
        self.btn_unlock.clicked.connect(lambda: self._set_lock(False))
        self.btn_refresh.clicked.connect(self._refresh)

    def _refresh(self):
        users = api.get_users()
        self.tbl.setRowCount(0)
        for u in users:
            row = self.tbl.rowCount()
            self.tbl.insertRow(row)
            locked = u.get("locked", False)
            vals = [
                u["username"],
                "Администратор" if u["is_admin"] else "Оператор",
                str(u.get("failed", 0)),
                "ДА" if locked else "нет",
                "ДА" if u.get("need_change") else "нет",
                u.get("created_at", "—"),
                u.get("last_login", "—")
            ]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if locked and col == 3:
                    item.setForeground(Qt.GlobalColor.red)
                self.tbl.setItem(row, col, item)

    def _selected(self):
        if not self.tbl.selectedItems():
            QMessageBox.warning(self, "Ошибка", "Выберите пользователя")
            return None
        return self.tbl.item(self.tbl.currentRow(), 0).text()

    def _create(self):
        dlg = CreateUserDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            _audit_service.log_admin_action(
                api.username, "create_user", {}
            )
            self._refresh()

    def _delete(self):
        u = self._selected()
        if not u: return
        if u == api.username:
            QMessageBox.warning(self, "Ошибка", "Нельзя удалить себя")
            return
        if QMessageBox.question(
            self, "Подтверждение", f"Удалить '{u}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            ok, msg = api.delete_user(u)
            if ok:
                _audit_service.log_admin_action(
                    api.username, "delete_user", {"deleted": u}
                )
                self._refresh()
            else:
                QMessageBox.warning(self, "Ошибка", msg)

    def _reset_pwd(self):
        u = self._selected()
        if not u: return
        new_pwd, ok = QInputDialog.getText(
            self, "Сброс пароля", f"Новый пароль для '{u}':",
            QLineEdit.EchoMode.Password
        )
        if not ok or not new_pwd: return
        res_ok, msg = api.reset_password(u, new_pwd)
        if res_ok:
            QMessageBox.information(self, "Успех", msg)
            _audit_service.log_user_data_change(u, ["password"], api.username)
            self._refresh()
        else:
            QMessageBox.warning(self, "Ошибка", msg)

    def _set_lock(self, lock: bool):
        u = self._selected()
        if not u: return
        if u == api.username and lock:
            QMessageBox.warning(self, "Ошибка", "Нельзя заблокировать себя")
            return
        res_ok, msg = api.set_lock(u, lock)
        if res_ok:
            QMessageBox.information(self, "Успех", f"'{u}': {msg}")
            _audit_service.log_admin_rights_change(
                api.username, u,
                {"action": "lock" if lock else "unlock"}
            )
            self._refresh()
        else:
            QMessageBox.warning(self, "Ошибка", msg)


# ── Диалог настроек аудита ────────────────────────────────────────────────────
class AuditSettingsDialog(QDialog):
    """Адаптировано из main_v2.py."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки аудита")
        self.resize(400, 440)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Типы событий для регистрации:"))

        self.checkboxes: dict = {}
        enabled = _audit_service.enabled_types
        for et in EventType:
            chk = QCheckBox(et.value)
            chk.setChecked(enabled is None or et.value in enabled)
            self.checkboxes[et.value] = chk
            lay.addWidget(chk)

        sel_row = QHBoxLayout()
        b_all  = QPushButton("Выбрать все")
        b_none = QPushButton("Снять все")
        b_all.clicked.connect(lambda: [c.setChecked(True)  for c in self.checkboxes.values()])
        b_none.clicked.connect(lambda: [c.setChecked(False) for c in self.checkboxes.values()])
        sel_row.addWidget(b_all); sel_row.addWidget(b_none)
        lay.addLayout(sel_row)

        lay.addWidget(QLabel("─" * 40))
        size_form = QFormLayout()
        self.sp_size = QDoubleSpinBox()
        self.sp_size.setRange(1, 10000); self.sp_size.setValue(config.audit_max_size_mb)
        self.sp_size.setSuffix(" МБ")
        size_form.addRow("Макс. размер БД:", self.sp_size)
        lay.addLayout(size_form)

        btn_box = QHBoxLayout()
        b_ok = QPushButton("Применить"); b_ok.clicked.connect(self._apply)
        b_no = QPushButton("Отмена");    b_no.clicked.connect(self.reject)
        btn_box.addWidget(b_ok); btn_box.addWidget(b_no)
        lay.addLayout(btn_box)

    def _apply(self):
        selected = [k for k, v in self.checkboxes.items() if v.isChecked()]
        _audit_service.enabled_types = (
            None if len(selected) == len(EventType) else selected
        )
        config.save_audit_enabled_types(_audit_service.enabled_types)
        self._new_max_size = self.sp_size.value()
        self.accept()

    def get_new_max_size(self): return getattr(self, '_new_max_size', config.audit_max_size_mb)


# ── Воркер расчётов ───────────────────────────────────────────────────────────
class CalculationWorker(QThread):
    """Выполняет HTTP-запрос к серверу в фоне. Адаптировано из main_v2.py."""
    finished = pyqtSignal(dict)
    error    = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, params: dict):
        super().__init__()
        self.params = params

    def run(self):
        self.progress.emit(20)
        ok, result = api.calculate(self.params)
        self.progress.emit(80)
        if ok:
            self.progress.emit(100)
            self.finished.emit(result)
        else:
            self.error.emit(str(result))


# ── Диалог фильтрации аудита ──────────────────────────────────────────────────
class AuditFilterDialog(QDialog):
    """Скопировано из main_v2.py."""

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
        self.edit_subject  = QLineEdit(); self.edit_subject.setPlaceholderText("Все")
        self.edit_date_from = QLineEdit(); self.edit_date_from.setPlaceholderText("YYYY-MM-DD")
        self.edit_date_to   = QLineEdit(); self.edit_date_to.setPlaceholderText("YYYY-MM-DD")
        self.sp_limit = QSpinBox(); self.sp_limit.setRange(10, 10000); self.sp_limit.setValue(100)
        form.addRow("Субъект:",     self.edit_subject)
        form.addRow("Дата от:",     self.edit_date_from)
        form.addRow("Дата до:",     self.edit_date_to)
        form.addRow("Макс. записей:", self.sp_limit)
        lay.addLayout(form)
        btn_box = QHBoxLayout()
        b_ok = QPushButton("Применить"); b_ok.clicked.connect(self.accept)
        b_rst = QPushButton("Сбросить");  b_rst.clicked.connect(self._reset)
        b_no = QPushButton("Отмена");    b_no.clicked.connect(self.reject)
        btn_box.addWidget(b_ok); btn_box.addWidget(b_rst); btn_box.addWidget(b_no)
        lay.addLayout(btn_box)

    def _reset(self):
        self.combo_type.setCurrentIndex(0)
        self.edit_subject.clear()
        self.edit_date_from.clear()
        self.edit_date_to.clear()
        self.sp_limit.setValue(100)

    def get_filters(self):
        filters = {}
        et = self.combo_type.currentData()
        if et: filters["event_type"] = et
        s = self.edit_subject.text().strip()
        if s: filters["subject"] = s
        df = self.edit_date_from.text().strip()
        if df: filters["date_from"] = df
        dt = self.edit_date_to.text().strip()
        if dt: filters["date_to"] = dt
        return filters, self.sp_limit.value()


# ── Главное окно ──────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    """Основное окно. Адаптировано из main_v2.py."""

    def __init__(self):
        super().__init__()
        self._login_time = int(time.time())
        self._audit_filters = {}
        self._audit_limit   = 100

        self.setWindowTitle(
            f"ТЭС: Оптимизация | {api.username} "
            f"[{'Админ' if api.is_admin else 'Оператор'}]"
        )
        self.resize(1050, 740)
        self._setup_ui()
        self._rotation_mgr = _rotation_mgr
        self._rotation_mgr.auto_check()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_lay = QVBoxLayout(central)

        # --- Меню ---
        mb = QMenuBar(self)
        self.setMenuBar(mb)
        acc_menu = mb.addMenu("Аккаунт")
        acc_menu.addAction("Сменить пароль", self._change_pwd)
        acc_menu.addSeparator()
        acc_menu.addAction("Выйти", self._logout)

        if api.is_admin:
            adm_menu = mb.addMenu("Администратор")
            adm_menu.addAction("Управление пользователями", self._admin_panel)
            adm_menu.addAction("Настройки аудита", self._audit_settings)

        self.tabs = QTabWidget()
        main_lay.addWidget(self.tabs)

        self._build_tab_calc()
        self._build_tab_vacuum()
        self._build_tab_charts()
        self._build_tab_audit()

        self.tabs.currentChanged.connect(self._on_tab)

    # --- Вкладка 1: Расчёт ---
    def _build_tab_calc(self):
        t = QWidget(); l = QHBoxLayout(t)

        inp = QGroupBox("Входные параметры"); f = QFormLayout(inp)
        self.sp_load   = QDoubleSpinBox(); self.sp_load.setRange(1, 5000);   self.sp_load.setValue(400)
        self.sp_blocks = QSpinBox();       self.sp_blocks.setRange(1, 20);   self.sp_blocks.setValue(2)
        self.sp_np     = QDoubleSpinBox(); self.sp_np.setRange(50, 1000);    self.sp_np.setValue(300)
        self.sp_ne     = QDoubleSpinBox(); self.sp_ne.setRange(0.1, 0.99);   self.sp_ne.setSingleStep(0.01); self.sp_ne.setValue(0.38)
        self.sp_temp   = QDoubleSpinBox(); self.sp_temp.setRange(-50, 60);   self.sp_temp.setValue(25)
        self.sp_hum    = QDoubleSpinBox(); self.sp_hum.setRange(0, 100);     self.sp_hum.setValue(60)
        self.sp_ws     = QDoubleSpinBox(); self.sp_ws.setRange(0, 50);       self.sp_ws.setValue(3)
        self.sp_wd     = QDoubleSpinBox(); self.sp_wd.setRange(0, 359);      self.sp_wd.setValue(90)
        self.sp_beta   = QDoubleSpinBox(); self.sp_beta.setRange(0.2, 0.6);  self.sp_beta.setValue(0.4)
        self.sp_own    = QDoubleSpinBox(); self.sp_own.setRange(0.01, 0.20); self.sp_own.setSingleStep(0.01); self.sp_own.setValue(0.05)

        for name, sp in [
            ("Общая нагрузка (МВт)", self.sp_load),
            ("Блоки",               self.sp_blocks),
            ("Ном. мощность (МВт)", self.sp_np),
            ("Ном. КПД",            self.sp_ne),
            ("Температура (°C)",    self.sp_temp),
            ("Влажность (%)",       self.sp_hum),
            ("Ветер скорость (м/с)",self.sp_ws),
            ("Ветер направление (°)",self.sp_wd),
            ("β недогрузки",        self.sp_beta),
            ("γ собств. нужд",      self.sp_own)
        ]:
            f.addRow(name, sp)

        self.btn_calc = QPushButton("▶ Рассчитать")
        self.btn_calc.setStyleSheet(
            "background:#2196F3; color:white; padding:8px; font-weight:bold;"
        )
        f.addRow(self.btn_calc)
        l.addWidget(inp)

        res = QGroupBox("Выходные данные"); rl = QVBoxLayout(res)
        self.tbl_res = QTableWidget(6, 2)
        self.tbl_res.setHorizontalHeaderLabels(["Показатель", "Значение"])
        self.tbl_res.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl_res.verticalHeader().setVisible(False)
        self.tbl_res.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        for i, k in enumerate([
            "Нагрузка на энергоблок", "КПД блока", "КПД ТЭС брутто",
            "Собственные нужды",      "КПД ТЭС нетто", "Удельный расход топлива"
        ]):
            self.tbl_res.setItem(i, 0, QTableWidgetItem(k))
            self.tbl_res.setItem(i, 1, QTableWidgetItem("—"))

        self.pb = QProgressBar(); self.pb.hide()
        rl.addWidget(self.tbl_res); rl.addWidget(self.pb)
        l.addWidget(res)

        self.btn_calc.clicked.connect(self._calc)
        self.tabs.addTab(t, "Расчёт")

    # --- Вкладка 2: Вакуум ---
    def _build_tab_vacuum(self):
        t = QWidget(); l = QVBoxLayout(t)
        vb = QGroupBox("Оптимизация вакуума"); f = QFormLayout(vb)
        self.sp_cool  = QDoubleSpinBox(); self.sp_cool.setRange(0, 40);   self.sp_cool.setValue(25)
        self.sp_steam = QDoubleSpinBox(); self.sp_steam.setRange(50, 2000);self.sp_steam.setValue(400)
        f.addRow("Темп. воды °C",   self.sp_cool)
        f.addRow("Расход пара кг/с", self.sp_steam)
        self.btn_vac = QPushButton("Найти оптимальный вакуум")
        f.addRow(self.btn_vac)
        self.lbl_vac = QLabel("—")
        self.lbl_vac.setStyleSheet("font:14pt bold; color:#2e7d32;")
        f.addRow(self.lbl_vac)
        l.addWidget(vb)
        self.btn_vac.clicked.connect(self._vac)
        self.tabs.addTab(t, "Вакуум")

    # --- Вкладка 3: Визуализация ---
    def _build_tab_charts(self):
        t = QWidget(); l = QVBoxLayout(t)
        ch = QHBoxLayout()
        ch.addWidget(QLabel("График:"))
        self.combo = QComboBox()
        self.combo.addItems(["Теплоотдача & T", "КПД нетто & T", "Расход & T"])
        ch.addWidget(self.combo)
        self.btn_plot = QPushButton("Построить")
        self.btn_plot.setStyleSheet("background:#4CAF50; color:white;")
        ch.addWidget(self.btn_plot); ch.addStretch()
        l.addLayout(ch)
        self.canvas = FigureCanvas(Figure(figsize=(9, 5), dpi=100))
        self.ax = self.canvas.figure.subplots()
        l.addWidget(self.canvas)
        self.btn_plot.clicked.connect(self._plot)
        self.tabs.addTab(t, "Визуализация")

    # --- Вкладка 4: Аудит ---
    def _build_tab_audit(self):
        t = QWidget(); l = QVBoxLayout(t)
        at = QHBoxLayout()
        self.btn_aud_ref  = QPushButton("Обновить")
        self.btn_aud_exp  = QPushButton("Экспорт")
        self.btn_aud_flt  = QPushButton("Фильтр")
        self.btn_aud_snd  = QPushButton("Отправка")
        self.btn_aud_rot  = QPushButton("Ротация")

        for b in [self.btn_aud_ref, self.btn_aud_exp, self.btn_aud_flt,
                  self.btn_aud_snd, self.btn_aud_rot]:
            at.addWidget(b)

        if not api.is_admin:
            self.btn_aud_snd.setEnabled(False)
            self.btn_aud_snd.setToolTip("Только для администраторов")
            self.btn_aud_rot.setEnabled(False)
            self.btn_aud_rot.setToolTip("Только для администраторов")

        self.lbl_audit_size = QLabel()
        at.addWidget(self.lbl_audit_size); at.addStretch()
        l.addLayout(at)

        self.tbl_audit = QTableWidget(0, 8)
        self.tbl_audit.setHorizontalHeaderLabels(
            ["ID", "Время", "Тип", "Субъект", "Объект",
             "Наименование", "Заголовки", "Идентификатор"])
        self.tbl_audit.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl_audit.verticalHeader().setVisible(False)
        self.tbl_audit.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        l.addWidget(self.tbl_audit)

        self.btn_aud_ref.clicked.connect(self._audit_refresh)
        self.btn_aud_exp.clicked.connect(self._audit_export)
        self.btn_aud_flt.clicked.connect(self._audit_filter)
        self.btn_aud_snd.clicked.connect(self._audit_send)
        self.btn_aud_rot.clicked.connect(self._audit_rotate)
        self.tabs.addTab(t, "Аудит")

    # ── Обработчики ──────────────────────────────────────────────────────────

    def _on_tab(self, idx):
        if self.tabs.tabText(idx) == "Аудит":
            self._audit_refresh()

    def _logout(self):
        duration = int(time.time()) - self._login_time
        _audit_service.log_auth_logout(api.username, duration)
        self.close()

    def _change_pwd(self):
        dlg = ChangePasswordDialog(self)
        dlg.lbl_info.setText("Смена пароля:")
        if dlg.exec() == QDialog.DialogCode.Accepted:
            ok, msg = api.change_password(
                dlg.edit_old.text(), dlg.edit_new.text()
            )
            if ok:
                _audit_service.log_user_data_change(
                    api.username, ["password"], api.username
                )
                QMessageBox.information(
                    self, "Успех",
                    "Пароль изменён.\nВыполните вход заново."
                )
                self.close()
            else:
                QMessageBox.warning(self, "Ошибка", msg)

    def _admin_panel(self):
        AdminPanelDialog(self).exec()

    def _audit_settings(self):
        dlg = AuditSettingsDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            new_sz = dlg.get_new_max_size()
            _rotation_mgr.set_max_size_mb(new_sz)
            _audit_service.log_admin_params_change(
                api.username, "audit_settings",
                {"enabled_types": _audit_service.enabled_types,
                 "max_size_mb": new_sz}
            )
            QMessageBox.information(self, "Настройки", "Настройки аудита сохранены.")

    def _calc(self):
        if self.sp_load.value() <= 0:
            QMessageBox.warning(self, "Ошибка", "Нагрузка > 0")
            return

        params = {
            "total_load":              self.sp_load.value(),
            "num_blocks":              self.sp_blocks.value(),
            "nominal_power_per_block": self.sp_np.value(),
            "nominal_efficiency":      self.sp_ne.value(),
            "temp_c":                  self.sp_temp.value(),
            "humidity":                self.sp_hum.value(),
            "wind_speed":              self.sp_ws.value(),
            "wind_dir":                self.sp_wd.value(),
            "beta":                    self.sp_beta.value(),
            "own_needs_coeff":         self.sp_own.value()
        }
        _audit_service.log_interface_input(api.username, "calc_params", params)
        self.pb.show(); self.pb.setValue(0)
        self.btn_calc.setEnabled(False)
        self.w = CalculationWorker(params)
        self.w.finished.connect(self._on_result)
        self.w.error.connect(lambda m: (
            self.pb.hide(), self.btn_calc.setEnabled(True),
            QMessageBox.critical(self, "Ошибка расчёта", m)
        ))
        self.w.progress.connect(self.pb.setValue)
        self.w.start()

    def _on_result(self, r: dict):
        self.pb.hide()
        self.btn_calc.setEnabled(True)
        for i in range(self.tbl_res.rowCount()):
            key = self.tbl_res.item(i, 0).text()
            if key in r:
                self.tbl_res.setItem(i, 1, QTableWidgetItem(str(r[key])))
        _audit_service.log_interface_output(
            api.username, "calc_results", str(r)
        )

    def _vac(self):
        t = self.sp_cool.value()
        txt = f"Оптимальное разрежение: {round(4.5 - 0.02*(t-20), 2)} кПа"
        self.lbl_vac.setText(txt)
        _audit_service.log_interface_output(api.username, "vacuum_calc", txt)

    def _plot(self):
        """Построение графиков. Адаптировано из main_v2.py."""
        self.ax.clear()
        idx = self.combo.currentIndex()

        # Для температурного анализа — запрашиваем данные с сервера
        if idx in (1, 2):
            ok, data = api.analyze_temperature({
                "total_load":         self.sp_load.value(),
                "num_blocks":         self.sp_blocks.value(),
                "nominal_power":      self.sp_np.value(),
                "nominal_efficiency": self.sp_ne.value(),
                "humidity":           self.sp_hum.value(),
                "wind_speed":         self.sp_ws.value(),
                "wind_dir":           self.sp_wd.value()
            })
            if not ok:
                QMessageBox.warning(self, "Ошибка", str(data))
                return
            T     = data["temperatures"]
            effs  = data["efficiencies_netto"]
            fuels = data["fuel_rates"]

            if idx == 1:
                self.ax.plot(T, effs, 'g-s', linewidth=2)
                self.ax.set_ylabel("КПД нетто, %")
                self.ax.set_title("КПД ТЭС нетто vs Температура")
            else:
                self.ax.plot(T, fuels, 'r-^', linewidth=2)
                self.ax.set_ylabel("г/кВт·ч")
                self.ax.set_title("Удельный расход топлива vs Температура")
        else:
            # Теплоотдача — локальный расчёт
            T = list(range(-30, 45, 5))
            C = [1000 * (1 - 0.01 * (t - 15)) for t in T]
            self.ax.plot(T, C, 'b-o', linewidth=2)
            self.ax.set_ylabel("МВт")
            self.ax.set_title("Теплоотводящая способность vs Температура")

        self.ax.set_xlabel("Температура, °C")
        self.ax.grid(True, alpha=0.3)
        self.ax.axvline(15, color='orange', ls=':', label='T=15°C')
        self.ax.legend()
        self.canvas.draw_idle()

        _audit_service.log_interface_output(
            api.username, "visualization", self.combo.currentText()
        )

    # ── Аудит ────────────────────────────────────────────────────────────────

    def _audit_refresh(self):
        events = api.get_audit_events(self._audit_limit, **self._audit_filters)
        self.tbl_audit.setRowCount(0)
        for ev in events:
            row = self.tbl_audit.rowCount()
            self.tbl_audit.insertRow(row)
            headers_str = json.dumps(ev.get("headers", {}), ensure_ascii=False)
            for col, val in enumerate([
                str(ev.get("event_id", "—")),
                str(ev.get("timestamp", ""))[:19].replace("T", " "),
                ev.get("event_type", ""),
                ev.get("subject", ""),
                ev.get("component", ""),
                ev.get("event_name", ""),
                headers_str,
                ev.get("identifier", "—")
            ]):
                self.tbl_audit.setItem(row, col, QTableWidgetItem(val))

        size_mb = _audit_service.storage.get_db_size_mb()
        self.lbl_audit_size.setText(f"БД аудита: {size_mb:.2f} МБ")

    def _audit_export(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт журнала", "",
            "JSON файлы (*.json);;CSV файлы (*.csv)"
        )
        if not path: return
        events = _audit_service.storage.get_events(
            filters=self._audit_filters if self._audit_filters else None,
            limit=self._audit_limit
        )
        ok = (_exporter.export_to_csv(events, path)
              if path.lower().endswith(".csv")
              else _exporter.export_to_json(events, path))
        if ok:
            QMessageBox.information(self, "Экспорт", f"Экспортировано:\n{path}")
        else:
            QMessageBox.warning(self, "Экспорт", "Ошибка экспорта")

    def _audit_filter(self):
        dlg = AuditFilterDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._audit_filters, self._audit_limit = dlg.get_filters()
            self._audit_refresh()

    def _audit_send(self):
        if not api.is_admin:
            QMessageBox.warning(self, "Доступ запрещён", "Только для администраторов")
            return
        path = QFileDialog.getExistingDirectory(self, "Выберите папку")
        if not path: return
        ok = _exporter.send_to_remote_server(path)
        QMessageBox.information(self, "Отправка",
                                "Успешно" if ok else "Ошибка отправки")

    def _audit_rotate(self):
        if not api.is_admin:
            QMessageBox.warning(self, "Доступ запрещён", "Только для администраторов")
            return
        reply = QMessageBox.question(
            self, "Ротация",
            "Yes — по времени (дни)\nNo — по объёму (МБ)",
            QMessageBox.StandardButton.Yes |
            QMessageBox.StandardButton.No |
            QMessageBox.StandardButton.Cancel
        )
        if reply == QMessageBox.StandardButton.Cancel: return
        if reply == QMessageBox.StandardButton.Yes:
            days, ok = QInputDialog.getInt(
                self, "Дни", "Удалить старше (дней):",
                value=_rotation_mgr.retention_days, min=1, max=3650
            )
            if not ok: return
            _rotation_mgr.set_retention_period(days)
            _rotation_mgr.check_and_rotate()
        else:
            mb, ok = QInputDialog.getDouble(
                self, "МБ", "Макс. размер (МБ):",
                value=_rotation_mgr.max_size_mb, min=1, decimals=1
            )
            if not ok: return
            _rotation_mgr.set_max_size_mb(mb)
            _rotation_mgr.check_and_rotate_by_size()
        self._audit_refresh()

    def closeEvent(self, event):
        duration = int(time.time()) - self._login_time
        _audit_service.log_auth_logout(api.username, duration)
        sys.exit(0)


# ── Точка входа ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app_qt = QApplication(sys.argv)
    app_qt.setFont(QFont("Segoe UI", 10))

    while True:
        dlg = LoginDialog()
        if dlg.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)

        win = MainWindow()
        win.show()
        app_qt.exec()