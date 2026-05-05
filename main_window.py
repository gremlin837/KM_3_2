"""
main_app.py
Полный интерфейс + подсистема аутентификации (SQLite + bcrypt + Config)
Запуск: python main_app.py
Зависимости: pip install PyQt6 matplotlib numpy bcrypt
"""
import sys
import os
import time
import re
import configparser
import sqlite3
from contextlib import contextmanager
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta
import numpy as np

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QGroupBox, QLabel, QPushButton, QDoubleSpinBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QTabWidget, QHeaderView, QProgressBar, QMenuBar,
    QMessageBox, QComboBox, QFileDialog, QLineEdit, QDialog
)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt6.QtGui import QFont, QAction
import matplotlib

matplotlib.use("Qt5Agg")
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure



# ПОДСИСТЕМА АУТЕНТИФИКАЦИИ



class Config:
    _instance = None

    def __new__(cls, path="config.ini"):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load(path)
        return cls._instance

    def _load(self, path):
        # Отключаем интерполяцию, чтобы '%' и '$' не вызывали ошибку
        self.config = configparser.ConfigParser(interpolation=None)
        self.config.optionxform = str  # сохраняем регистр ключей

        if not os.path.exists(path):
            self._create_default_config(path)

        self.config.read(path, encoding='utf-8')

    def _create_default_config(self, path):
        # Безопасное создание секций и ключей
        defaults = {
            'DATABASE': {'path': 'users.db'},
            'AUTH': {'max_attempts': '3', 'lockout_minutes': '15'},
            'PASSWORD': {'user_min_length': '6', 'admin_min_length': '7', 'special_chars': '~!@#$%^&*'},
            'TIME': {'timezone': 'Europe/Moscow', 'offset_hours': '3'},
            'BCRYPT': {'rounds': '12'}
        }
        for section, values in defaults.items():
            self.config.add_section(section)
            for k, v in values.items():
                self.config.set(section, k, str(v))

        with open(path, 'w', encoding='utf-8') as f:
            self.config.write(f)

    # Явные свойства с fallback на случай, если файл повреждён
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

# Глобальный экземпляр (вызывается один раз)
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
                need_change INTEGER DEFAULT 1, created_at INTEGER DEFAULT 0, last_login INTEGER DEFAULT 0)''')

    @contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path);
        c.row_factory = sqlite3.Row
        try:
            yield c; c.commit()
        finally:
            c.close()

    def _now(self):
        return int(time.time() + config.time_offset * 3600)

    def get_user(self, u):
        with self._conn() as c: row = c.execute('SELECT * FROM users WHERE username=?', (u,)).fetchone()
        return dict(row) if row else None

    def create_user(self, u, h, adm=False):
        with self._conn() as c:
            try:
                c.execute('INSERT INTO users VALUES (?,?,?,?,?,?,?,?)',
                          (u, h, 1 if adm else 0, 0, 0, 1, self._now(), self._now())); return True
            except:
                return False

    def update(self, u, **kw):
        fields = {'hash': 'hash', 'is_admin': 'is_admin', 'failed': 'failed', 'locked_until': 'locked_until',
                  'need_change': 'need_change', 'last_login': 'last_login'}
        up = [f"{fields[k]}=?" for k in kw if k in fields]
        if up:
            with self._conn() as c: c.execute(f"UPDATE users SET {','.join(up)} WHERE username=?", [*kw.values(), u])

    def all_users(self):
        with self._conn() as c: return [dict(r) for r in c.execute('SELECT * FROM users')]

    def delete(self, u):
        with self._conn() as c: return c.execute('DELETE FROM users WHERE username=?', (u,)).rowcount > 0


class AuthSystem:
    def __init__(self):
        self.db = Database()
        self.hasher = BcryptHasher()
        self.cache: Dict[str, object] = {}

    def _load(self, u):
        d = self.db.get_user(u)
        if not d: return None
        acc = type('User', (), {})()
        acc.username, acc.password, acc.is_admin, acc.failed, acc.locked_until, acc.need_change = u, d['hash'], bool(
            d['is_admin']), d['failed'], d['locked_until'], bool(d['need_change'])
        self.cache[u] = acc
        return acc

    def _save(self, acc):
        self.db.update(acc.username, hash=acc.password, is_admin=acc.is_admin, failed=acc.failed,
                       locked_until=acc.locked_until, need_change=acc.need_change)

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

    def create_admin_if_empty(self):
        if not self.db.all_users():
            self.db.create_user("admin", self.hasher.hash_password("Admin@12345")['hash'], True)
            print("Создан тестовый аккаунт: admin / Admin@12345")



# 🖥ИНТЕРФЕЙС (адаптирован под AuthSystem)

class LoginDialog(QDialog):
    def __init__(self, auth: AuthSystem):
        super().__init__()
        self.auth = auth
        self.logged_account = None  # Сюда сохраняем объект пользователя
        self.setWindowTitle("Вход в систему")
        self.resize(400, 260)
        self._setup_ui()

    def _setup_ui(self):
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.user_edit = QLineEdit();
        self.user_edit.setPlaceholderText("Логин")
        self.pass_edit = QLineEdit();
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Идентификатор:", self.user_edit)
        form.addRow("Пароль:", self.pass_edit)
        lay.addLayout(form)
        self.status = QLabel();
        self.status.setStyleSheet("color:#d32f2f; font-weight:bold;")
        lay.addWidget(self.status)
        self.btn = QPushButton("Войти");
        self.btn.clicked.connect(self._try)
        lay.addWidget(self.btn)
        self.pass_edit.returnPressed.connect(self._try)
        self.timer = QTimer(self);
        self.timer.timeout.connect(self._check_lockout)
        self.locked_until = 0

    def _check_lockout(self):
        if self.locked_until > time.time():
            rem = int((self.locked_until - time.time()) / 60)
            self.status.setText(f"Блокировка. Авто-разблокировка через {rem} мин.")
        else:
            self.timer.stop();
            self.locked_until = 0;
            self.status.clear()
            self.user_edit.setEnabled(True);
            self.pass_edit.setEnabled(True)
            self.btn.setText("Войти");
            self.btn.setEnabled(True)

    def _try(self):
        if self.locked_until > time.time(): return
        u, p = self.user_edit.text().strip(), self.pass_edit.text()
        if not u or not p: self.status.setText("Заполните поля"); return

        ok, msg, acc = self.auth.auth(u, p)

        if ok:
            self.logged_account = acc  #  Сохраняем ДО закрытия
            self.accept()
        elif "Требуется смена" in msg:
            chg = ChangePasswordDialog(self.auth, acc)
            if chg.exec() == QDialog.DialogCode.Accepted:
                self.logged_account = acc  #  Сохраняем после смены пароля
                self.accept()
            else:
                self.status.setText("Смена пароля отменена. Вход не выполнен.")
        else:
            self.status.setText(msg)
            self.pass_edit.clear()
            if "заблокирован" in msg.lower():
                self.locked_until = acc.locked_until if acc else time.time() + 15 * 60
                self.timer.start(1000)
                self.user_edit.setEnabled(False);
                self.pass_edit.setEnabled(False)
                self.btn.setEnabled(False);
                self.btn.setText("Заблокировано")


class ChangePasswordDialog(QDialog):
    def __init__(self, auth: AuthSystem, account):
        super().__init__()
        self.auth, self.acc = auth, account
        self.setWindowTitle("Смена пароля (обязательно)")
        self.resize(360, 240)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.old = QLineEdit();
        self.old.setEchoMode(QLineEdit.EchoMode.Password)
        self.new = QLineEdit();
        self.new.setEchoMode(QLineEdit.EchoMode.Password)
        self.conf = QLineEdit();
        self.conf.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Текущий пароль:", self.old)
        form.addRow("Новый пароль:", self.new)
        form.addRow("Подтверждение:", self.conf)
        lay.addLayout(form)
        self.st = QLabel();
        self.st.setStyleSheet("color:#d32f2f;")
        lay.addWidget(self.st)
        btn = QPushButton("Сменить и продолжить");
        btn.clicked.connect(self._change)
        lay.addWidget(btn)

    def _change(self):
        if not self.hasher_verify(self.old.text(), self.acc.password):
            self.st.setText("Неверный текущий пароль");
            return
        if self.new.text() != self.conf.text():
            self.st.setText("Пароли не совпадают");
            return
        ok, msg = self.auth.change(self.acc, self.new.text())
        if ok:
            QMessageBox.information(self, "Успех", "Пароль изменён. Добро пожаловать в систему!")
            self.accept()
        else:
            self.st.setText(msg)

    def hasher_verify(self, pwd, stored):
        import bcrypt
        return bcrypt.checkpw(pwd.encode(), stored.encode())


class CalculationWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, inp):
        super().__init__(); self.inp = inp

    def run(self):
        try:
            self.progress.emit(20);
            time.sleep(0.8);
            self.progress.emit(60)
            lb = self.inp["total_load"] / max(1, self.inp["num_blocks"])
            kt = 1 + 0.003 * (15 - self.inp["temp_c"]) if self.inp["temp_c"] <= 15 else 1 - 0.002 * (
                        self.inp["temp_c"] - 15)
            kh = 1.0 if self.inp["humidity"] <= 60 else 1 - 0.0005 * (self.inp["humidity"] - 60)
            kws = 1 + 0.002 * min(self.inp["wind_speed"], 8)
            wd = self.inp["wind_dir"] % 360;
            kwd = 0.99 if 0 <= wd <= 45 else (1.01 if 180 <= wd <= 225 else 1.00)
            k = kt * kh * kws * kwd;
            eff = self.inp["nominal_efficiency"] * k
            lr = self.inp["total_load"] / (self.inp["num_blocks"] * self.inp["nominal_power"])
            eff_load = eff * (1 - self.inp["beta"] * (1 - lr) ** 2) if lr < 1 else eff
            own = self.inp.get("own_needs_coeff", 0.05)
            t = self.inp["temp_c"]
            if t > 25:
                own += 0.005 * (t - 25)
            elif t < 0:
                own += 0.003 * abs(t)
            en = eff_load * (1 - own);
            fuel = 123 / en if en > 0 else 999
            res = {"Нагрузка на энергоблок": round(lb, 2), "КПД блока": round(eff_load * 100, 2),
                   "КПД ТЭС брутто": round(eff * 100, 2),
                   "Собственные нужды": round(own * 100, 2), "КПД ТЭС нетто": round(en * 100, 2),
                   "Удельный расход топлива": round(fuel, 1)}
            self.progress.emit(100);
            self.finished.emit(res)
        except Exception as e:
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    def __init__(self, account, auth_system):
        super().__init__()
        self.acc = account
        self.auth = auth_system  # Ссылка на систему аутентификации
        self.setWindowTitle(
            f"ТЭС: Оптимизация | {account.username} [{('Админ' if account.is_admin else 'Оператор')}]")
        self.resize(1000, 720)

        # 1. Сначала создаём ВСЕ виджеты
        self._setup_ui()
        # 2. Только потом подключаем сигналы
        self._setup_signals()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_lay = QVBoxLayout(central)

        # Меню аккаунта
        mb = QMenuBar(self)
        self.setMenuBar(mb)
        acc_menu = mb.addMenu("Аккаунт")
        acc_menu.addAction("Сменить пароль", self._open_change_pwd)
        acc_menu.addSeparator()
        btn_logout = QAction("Выйти", self)
        btn_logout.triggered.connect(self._do_logout)
        acc_menu.addAction(btn_logout)

        self.tabs = QTabWidget()
        main_lay.addWidget(self.tabs)

        # === ВКЛАДКА 1: РАСЧЁТ ===
        t1 = QWidget()
        l1 = QHBoxLayout(t1)
        inp_box = QGroupBox("Входные параметры")
        inp_form = QFormLayout(inp_box)

        self.sp_load = QDoubleSpinBox();
        self.sp_load.setRange(1, 5000);
        self.sp_load.setValue(400)
        self.sp_blocks = QSpinBox();
        self.sp_blocks.setRange(1, 20);
        self.sp_blocks.setValue(2)
        self.sp_np = QDoubleSpinBox();
        self.sp_np.setRange(50, 1000);
        self.sp_np.setValue(300)
        self.sp_ne = QDoubleSpinBox();
        self.sp_ne.setRange(0.1, 0.99);
        self.sp_ne.setSingleStep(0.01);
        self.sp_ne.setValue(0.38)
        self.sp_temp = QDoubleSpinBox();
        self.sp_temp.setRange(-50, 60);
        self.sp_temp.setValue(25)
        self.sp_hum = QDoubleSpinBox();
        self.sp_hum.setRange(0, 100);
        self.sp_hum.setValue(60)
        self.sp_ws = QDoubleSpinBox();
        self.sp_ws.setRange(0, 50);
        self.sp_ws.setValue(3)
        self.sp_wd = QDoubleSpinBox();
        self.sp_wd.setRange(0, 359);
        self.sp_wd.setValue(90)
        self.sp_beta = QDoubleSpinBox();
        self.sp_beta.setRange(0.2, 0.6);
        self.sp_beta.setValue(0.4)
        self.sp_own = QDoubleSpinBox();
        self.sp_own.setRange(0.01, 0.20);
        self.sp_own.setSingleStep(0.01);
        self.sp_own.setValue(0.05)

        for n, s in [("Общая нагрузка", self.sp_load), ("Блоки", self.sp_blocks), ("Ном. мощность", self.sp_np),
                     ("Ном. КПД", self.sp_ne), ("Температура", self.sp_temp), ("Влажность", self.sp_hum),
                     ("Ветер скорость", self.sp_ws), ("Ветер направление", self.sp_wd),
                     ("β недогрузки", self.sp_beta), ("γ собств. нужд", self.sp_own)]:
            inp_form.addRow(n, s)

        # Кнопка создаётся ЗДЕСЬ и привязывается к self
        self.btn_calc = QPushButton("▶ Рассчитать")
        self.btn_calc.setStyleSheet("background:#2196F3; color:white; padding:8px; font-weight:bold;")
        inp_form.addRow(self.btn_calc)
        l1.addWidget(inp_box)

        # Результаты
        res_box = QGroupBox("Выходные данные")
        res_lay = QVBoxLayout(res_box)
        self.tbl = QTableWidget(6, 2)
        self.tbl.setHorizontalHeaderLabels(["Показатель", "Значение"])
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        for i, k in enumerate(
                ["Нагрузка на энергоблок", "КПД блока", "КПД ТЭС брутто", "Собственные нужды", "КПД ТЭС нетто",
                 "Удельный расход топлива"]):
            self.tbl.setItem(i, 0, QTableWidgetItem(k))
            self.tbl.setItem(i, 1, QTableWidgetItem("—"))
        self.pb = QProgressBar();
        self.pb.hide()
        res_lay.addWidget(self.tbl);
        res_lay.addWidget(self.pb)
        l1.addWidget(res_box)
        self.tabs.addTab(t1, "Расчёт")

        # === ВКЛАДКА 2: ВАКУУМ ===
        t2 = QWidget();
        l2 = QVBoxLayout(t2)
        vac_box = QGroupBox("Оптимизация вакуума");
        vac_form = QFormLayout(vac_box)
        self.sp_cool = QDoubleSpinBox();
        self.sp_cool.setRange(0, 40);
        self.sp_cool.setValue(25)
        self.sp_steam = QDoubleSpinBox();
        self.sp_steam.setRange(50, 2000);
        self.sp_steam.setValue(400)
        vac_form.addRow("Темп. воды °C", self.sp_cool);
        vac_form.addRow("Расход пара кг/с", self.sp_steam)
        self.btn_vac = QPushButton("Найти оптимальный вакуум")  # Привязка к self
        vac_form.addRow(self.btn_vac)
        self.lbl_vac = QLabel("—");
        self.lbl_vac.setStyleSheet("font:14pt bold; color:#2e7d32;")
        vac_form.addRow(self.lbl_vac)
        l2.addWidget(vac_box)
        self.tabs.addTab(t2, "Вакуум")

        # === ВКЛАДКА 3: ГРАФИКИ ===
        t3 = QWidget();
        l3 = QVBoxLayout(t3)
        ch = QHBoxLayout();
        ch.addWidget(QLabel("График:"))
        self.combo = QComboBox();
        self.combo.addItems(["Теплоотдача & T", "КПД нетто & T", "Расход & T"])
        ch.addWidget(self.combo)
        self.btn_plot = QPushButton("Построить")  # Привязка к self
        self.btn_plot.setStyleSheet("background:#4CAF50; color:white;")
        ch.addWidget(self.btn_plot);
        ch.addStretch()
        l3.addLayout(ch)
        self.canvas = FigureCanvas(Figure(figsize=(9, 5), dpi=100))
        self.ax = self.canvas.figure.subplots()
        l3.addWidget(self.canvas)
        self.tabs.addTab(t3, "Визуализация")

        # === ВКЛАДКА 4: АУДИТ (ЗАГЛУШКА) ===
        t4 = QWidget();
        l4 = QVBoxLayout(t4)
        at = QHBoxLayout()
        btns = [QPushButton("Обновить"), QPushButton("Экспорт"), QPushButton("Фильтр"), QPushButton("Отправка")]
        for b in btns: b.clicked.connect(lambda: self._stub("Аудит"))
        for b in btns: at.addWidget(b)
        at.addStretch();
        l4.addLayout(at)
        self.tbl_audit = QTableWidget(5, 7)
        self.tbl_audit.setHorizontalHeaderLabels(
            ["ID", "Время", "Тип", "Субъект", "Объект", "Наименование", "Заголовки"])
        self.tbl_audit.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl_audit.verticalHeader().setVisible(False)
        for i, r in enumerate([("1001", "10:15", "AUTH", "admin", "/login", "Вход", "IP:192.168.1.5"),
                               ("1002", "10:16", "API", "admin", "/calc", "Расчёт", "POST 200"),
                               ("1003", "10:20", "MODIFY", "admin", "params", "Изменение", "load=450"),
                               ("1004", "10:25", "AUTH_FAIL", "test", "/login", "Ошибка", "invalid_pwd"),
                               ("1005", "10:30", "CONFIG", "admin_sys", "audit", "Настройки", "ret=90d")]):
            self.tbl_audit.insertRow(i)
            [self.tbl_audit.setItem(i, j, QTableWidgetItem(v)) for j, v in enumerate(r)]
        l4.addWidget(self.tbl_audit)
        self.tabs.addTab(t4, "Аудит")

    def _setup_signals(self):
        # Все кнопки точно существуют благодаря порядку вызова в __init__
        self.btn_calc.clicked.connect(self._calc)
        self.btn_vac.clicked.connect(self._vac)
        self.btn_plot.clicked.connect(self._plot)

    def _do_logout(self):
        self.close()

    def _open_change_pwd(self):
        dlg = ChangePasswordDialog(self.auth, self.acc)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            QMessageBox.information(self, "Успех", "Пароль изменён.\nТребуется повторная аутентификация.")
            self.close()

    def _stub(self, t):
        QMessageBox.information(self, t, f"Функционал '{t}' будет подключен после интеграции с backend.")

    def _validate(self):
        if self.sp_load.value() <= 0: QMessageBox.warning(self, "Ошибка", "Нагрузка > 0"); return False
        if not (0 <= self.sp_hum.value() <= 100): QMessageBox.warning(self, "Ошибка", "Влажность 0-100%"); return False
        if not (0 <= self.sp_wd.value() < 360): QMessageBox.warning(self, "Ошибка", "Ветер 0-359°"); return False
        return True

    def _calc(self):
        if not self._validate(): return
        inp = {"total_load": self.sp_load.value(), "num_blocks": self.sp_blocks.value(),
               "nominal_power": self.sp_np.value(),
               "nominal_efficiency": self.sp_ne.value(), "temp_c": self.sp_temp.value(),
               "humidity": self.sp_hum.value(),
               "wind_speed": self.sp_ws.value(), "wind_dir": self.sp_wd.value(), "beta": self.sp_beta.value(),
               "own_needs_coeff": self.sp_own.value()}
        self.pb.show();
        self.pb.setValue(0);
        self.btn_calc.setEnabled(False)
        self.w = CalculationWorker(inp)
        self.w.finished.connect(self._on_res)
        self.w.error.connect(
            lambda m: (self.pb.hide(), self.btn_calc.setEnabled(True), QMessageBox.critical(self, "Ошибка", m)))
        self.w.progress.connect(self.pb.setValue)
        self.w.start()

    def _on_res(self, r):
        self.pb.hide();
        self.btn_calc.setEnabled(True)
        for i in range(6):
            for k, v in r.items():
                if self.tbl.item(i, 0).text() == k:
                    self.tbl.setItem(i, 1, QTableWidgetItem(str(v)));
                    break

    def _vac(self):
        t = self.sp_cool.value()
        self.lbl_vac.setText(f"Оптимальное разрежение: {round(4.5 - 0.02 * (t - 20), 2)} кПа")

    def _plot(self):
        self.ax.clear();
        idx = self.combo.currentIndex()
        T = np.arange(-30, 45, 5)
        if idx == 0:
            C = 1000 * (1 - 0.01 * (T - 15))
            self.ax.plot(T, C, 'b-o');
            self.ax.set_ylabel("МВт");
            self.ax.set_title("Теплоотдача")
        elif idx == 1:
            E = []
            for t in T:
                kt = 1 + 0.003 * (15 - t) if t <= 15 else 1 - 0.002 * (t - 15)
                kh = 1 if self.sp_hum.value() <= 60 else 1 - 0.0005 * (self.sp_hum.value() - 60)
                kws = 1 + 0.002 * min(self.sp_ws.value(), 8)
                wd = self.sp_wd.value() % 360;
                kwd = 0.99 if 0 <= wd <= 45 else (1.01 if 180 <= wd <= 225 else 1)
                k = kt * kh * kws * kwd;
                en = self.sp_ne.value() * k
                lr = self.sp_load.value() / (self.sp_blocks.value() * self.sp_np.value())
                eff = en * (1 - self.sp_beta.value() * (1 - lr) ** 2) if lr < 1 else en
                own = self.sp_own.value()
                if t > 25:
                    own += 0.005 * (t - 25)
                elif t < 0:
                    own += 0.003 * abs(t)
                E.append(eff * (1 - own) * 100)
            self.ax.plot(T, E, 'g-s');
            self.ax.set_ylabel("КПД нетто, %");
            self.ax.set_title("КПД vs T")
        else:
            F = []
            for t in T:
                kt = 1 + 0.003 * (15 - t) if t <= 15 else 1 - 0.002 * (t - 15)
                kh = 1 if self.sp_hum.value() <= 60 else 1 - 0.0005 * (self.sp_hum.value() - 60)
                kws = 1 + 0.002 * min(self.sp_ws.value(), 8)
                wd = self.sp_wd.value() % 360;
                kwd = 0.99 if 0 <= wd <= 45 else (1.01 if 180 <= wd <= 225 else 1)
                k = kt * kh * kws * kwd;
                en = self.sp_ne.value() * k
                lr = self.sp_load.value() / (self.sp_blocks.value() * self.sp_np.value())
                eff = en * (1 - self.sp_beta.value() * (1 - lr) ** 2) if lr < 1 else en
                own = self.sp_own.value()
                if t > 25:
                    own += 0.005 * (t - 25)
                elif t < 0:
                    own += 0.003 * abs(t)
                F.append(123 / (eff * (1 - own)) if eff * (1 - own) > 0 else 999)
            self.ax.plot(T, F, 'r-^');
            self.ax.set_ylabel("г/кВт·ч");
            self.ax.set_title("Расход vs T")
        self.ax.set_xlabel("T, °C");
        self.ax.grid(True, alpha=0.3);
        self.ax.axvline(15, color='orange', ls=':')
        self.canvas.draw_idle()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))

    auth = AuthSystem()
    auth.create_admin_if_empty()

    while True:
        dlg = LoginDialog(auth)
        if dlg.exec() != QDialog.DialogCode.Accepted or dlg.logged_account is None:
            sys.exit(0)

        # Передаём auth в главное окно
        main_win = MainWindow(dlg.logged_account, auth)
        main_win.show()
        app.exec()  # Ждёт закрытия главного окна