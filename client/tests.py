
import sys
import time
import numpy as np

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QGroupBox, QLabel, QPushButton, QDoubleSpinBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QTabWidget, QHeaderView, QProgressBar, QMenuBar,
    QMessageBox, QComboBox
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont, QAction
import matplotlib
matplotlib.use("Qt5Agg")  # Совместимо с PyQt6
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


# АСИНХРОННЫЙ РАБОЧИЙ ПОТОК (сервер + оркестратор)

class CalculationWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, inputs: dict):
        super().__init__()
        self.inputs = inputs

    def run(self):
        try:
            self.progress.emit(20)
            time.sleep(0.8)  # Имитация задержки сети/очереди
            self.progress.emit(60)

            # Демо-расчёт на основе формул из скрипта
            load_block = self.inputs["total_load"] / max(1, self.inputs["num_blocks"])
            k_temp = 1 + 0.003 * (15 - self.inputs["temp_c"]) if self.inputs["temp_c"] <= 15 else 1 - 0.002 * (self.inputs["temp_c"] - 15)
            k_hum = 1.0 if self.inputs["humidity"] <= 60 else 1 - 0.0005 * (self.inputs["humidity"] - 60)
            k_wind_s = 1 + 0.002 * min(self.inputs["wind_speed"], 8)
            angle = self.inputs["wind_dir"] % 360
            k_wind_d = 0.99 if 0 <= angle <= 45 else (1.01 if 180 <= angle <= 225 else 1.00)

            k = k_temp * k_hum * k_wind_s * k_wind_d
            eff_nom = self.inputs["nominal_efficiency"] * k

            load_ratio = self.inputs["total_load"] / (self.inputs["num_blocks"] * self.inputs["nominal_power"])
            beta = self.inputs["beta"]
            eff_load = eff_nom * (1 - beta * (1 - load_ratio)**2) if load_ratio < 1 else eff_nom

            own_needs = self.inputs.get("own_needs_coeff", 0.05)
            t = self.inputs["temp_c"]
            if t > 25: own_needs += 0.005 * (t - 25)
            elif t < 0: own_needs += 0.003 * abs(t)

            eff_netto = eff_load * (1 - own_needs)
            fuel = 123 / eff_netto if eff_netto > 0 else float('inf')

            result = {
                "Нагрузка на энергоблок": round(load_block, 2),
                "КПД блока": round(eff_load * 100, 2),
                "КПД ТЭС брутто": round(eff_nom * 100, 2),
                "Собственные нужды": round(own_needs * 100, 2),
                "КПД ТЭС нетто": round(eff_netto * 100, 2),
                "Удельный расход топлива": round(fuel, 1)
            }
            self.progress.emit(100)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


# ГЛАВНОЕ ОКНО (ТЕСТОВАЯ ВЕРСИЯ)

class MainWindow(QMainWindow):
    def __init__(self, username: str = "test_user", role: str = "operator"):
        super().__init__()
        self.username = username
        self.role = role
        self.setWindowTitle(f"ТЭС: Оптимизация эффективности | {username} [{role.upper()}] (TEST MODE)")
        self.resize(1000, 720)
        self._setup_ui()
        self._setup_signals()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_lay = QVBoxLayout(central)

        # Меню аккаунта
        menu_bar = QMenuBar(self)
        self.setMenuBar(menu_bar)
        acc_menu = menu_bar.addMenu("Аккаунт")
        acc_menu.addAction("Сменить пароль", self._show_stub_dialog)
        acc_menu.addSeparator()
        acc_menu.addAction("Выйти", self.close)

        self.tabs = QTabWidget()
        main_lay.addWidget(self.tabs)

        #  ВКЛАДКА 1: РАСЧЁТ
        tab1 = QWidget()
        lay1 = QHBoxLayout(tab1)

        # Ввод
        inp_box = QGroupBox("Входные параметры")
        inp_form = QFormLayout(inp_box)
        self.spin_load = QDoubleSpinBox(); self.spin_load.setRange(1, 5000); self.spin_load.setValue(400)
        self.spin_blocks = QSpinBox(); self.spin_blocks.setRange(1, 20); self.spin_blocks.setValue(2)
        self.spin_nom_pow = QDoubleSpinBox(); self.spin_nom_pow.setRange(50, 1000); self.spin_nom_pow.setValue(300)
        self.spin_nom_eff = QDoubleSpinBox(); self.spin_nom_eff.setRange(0.1, 0.99); self.spin_nom_eff.setSingleStep(0.01); self.spin_nom_eff.setValue(0.38)
        self.spin_temp = QDoubleSpinBox(); self.spin_temp.setRange(-50, 60); self.spin_temp.setValue(25)
        self.spin_hum = QDoubleSpinBox(); self.spin_hum.setRange(0, 100); self.spin_hum.setValue(60)
        self.spin_wind_s = QDoubleSpinBox(); self.spin_wind_s.setRange(0, 50); self.spin_wind_s.setValue(3)
        self.spin_wind_d = QDoubleSpinBox(); self.spin_wind_d.setRange(0, 359); self.spin_wind_d.setValue(90)
        self.spin_beta = QDoubleSpinBox(); self.spin_beta.setRange(0.2, 0.6); self.spin_beta.setValue(0.4)
        self.spin_own_needs = QDoubleSpinBox(); self.spin_own_needs.setRange(0.01, 0.20); self.spin_own_needs.setSingleStep(0.01); self.spin_own_needs.setValue(0.05)

        for lbl, spin in [
            ("Общая нагрузка ТЭС, МВт", self.spin_load), ("Количество блоков", self.spin_blocks),
            ("Номинальная мощность блока, МВт", self.spin_nom_pow), ("Номинальный КПД", self.spin_nom_eff),
            ("Температура воздуха, °C", self.spin_temp), ("Влажность, %", self.spin_hum),
            ("Скорость ветра, м/с", self.spin_wind_s), ("Направление ветра, °", self.spin_wind_d),
            ("Коэфф. недогрузки (β)", self.spin_beta), ("Коэфф. собственных нужд", self.spin_own_needs)]:
            inp_form.addRow(lbl, spin)

        self.btn_calc = QPushButton("Рассчитать эффективность")
        self.btn_calc.setStyleSheet("background-color: #2196F3; color: white; padding: 8px; font-weight: bold;")
        inp_form.addRow(self.btn_calc)
        lay1.addWidget(inp_box)

        # Вывод
        res_box = QGroupBox("Выходные данные (строго по ТЗ)")
        res_lay = QVBoxLayout(res_box)
        self.table_res = QTableWidget(6, 2)
        self.table_res.setHorizontalHeaderLabels(["Показатель", "Значение"])
        self.table_res.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_res.verticalHeader().setVisible(False)
        self.table_res.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        output_keys = [
            "Нагрузка на энергоблок", "КПД блока", "КПД ТЭС брутто",
            "Собственные нужды", "КПД ТЭС нетто", "Удельный расход топлива"
        ]
        for i, key in enumerate(output_keys):
            self.table_res.setItem(i, 0, QTableWidgetItem(key))
            self.table_res.setItem(i, 1, QTableWidgetItem("—"))

        self.progress = QProgressBar()
        self.progress.hide()
        res_lay.addWidget(self.table_res)
        res_lay.addWidget(self.progress)
        lay1.addWidget(res_box)
        self.tabs.addTab(tab1, "Расчёт эффективности")

        # ВКЛАДКА 2: ВАКУУМ
        tab2 = QWidget()
        lay2 = QVBoxLayout(tab2)
        vac_box = QGroupBox("Оптимизация разрежения в конденсаторе (п. 1.1.2.2)")
        vac_form = QFormLayout(vac_box)
        self.spin_cool_temp = QDoubleSpinBox(); self.spin_cool_temp.setRange(0, 40); self.spin_cool_temp.setValue(25)
        self.spin_steam = QDoubleSpinBox(); self.spin_steam.setRange(50, 2000); self.spin_steam.setValue(400)
        vac_form.addRow("Темп. охлаждающей воды, °C", self.spin_cool_temp)
        vac_form.addRow("Расход пара, кг/с", self.spin_steam)
        self.btn_vac = QPushButton("Найти оптимальный вакуум")
        vac_form.addRow(self.btn_vac)
        self.label_vac_res = QLabel("Результат: —"); self.label_vac_res.setStyleSheet("font-size: 14pt; color: #2e7d32; font-weight: bold;")
        vac_form.addRow(self.label_vac_res)
        lay2.addWidget(vac_box)
        self.tabs.addTab(tab2, "Вакуум-оптимизация")

        # ВКЛАДКА 3: ГРАФИКИ
        tab3 = QWidget()
        lay3 = QVBoxLayout(tab3)

        # Панель управления графиками
        chart_ctrl = QHBoxLayout()
        chart_ctrl.addWidget(QLabel("Выберите график:"))
        self.combo_chart = QComboBox()
        self.combo_chart.addItems([
            "Теплоотдача & Температура",
            "КПД нетто & Температура воздуха",
            "Расход топлива & Температура воздуха"
        ])
        self.combo_chart.setMinimumWidth(350)
        chart_ctrl.addWidget(self.combo_chart)
        self.btn_plot = QPushButton("Построить")
        self.btn_plot.setStyleSheet("background-color: #4CAF50; color: white; padding: 6px 16px;")
        chart_ctrl.addWidget(self.btn_plot)
        chart_ctrl.addStretch()
        lay3.addLayout(chart_ctrl)

        self.canvas = FigureCanvas(Figure(figsize=(9, 5), dpi=100))
        self.ax = self.canvas.figure.subplots()
        lay3.addWidget(self.canvas)
        self.tabs.addTab(tab3, "Визуализация")

        #  ВКЛАДКА 4: АУДИТ И СОБЫТИЯ
        tab_audit = QWidget()
        lay_audit = QVBoxLayout(tab_audit)

        # Панель управления
        audit_toolbar = QHBoxLayout()
        btn_refresh = QPushButton("Обновить журнал")
        btn_export = QPushButton("Экспорт в CSV")
        btn_filter = QPushButton("Фильтр по типу")
        btn_remote = QPushButton("Отправить на удалённый сервер")

        for btn in (btn_refresh, btn_export, btn_filter, btn_remote):
            btn.clicked.connect(self._show_stub_dialog)
            btn.setStyleSheet("padding: 6px; background-color: #ECEFF1; border: 1px solid #B0BEC5;")
            audit_toolbar.addWidget(btn)
        audit_toolbar.addStretch()
        lay_audit.addLayout(audit_toolbar)

        # Таблица событий ( п. 3.3.2 ТЗ)
        self.table_audit = QTableWidget(0, 7)
        self.table_audit.setHorizontalHeaderLabels([
            "ID", "Дата/Время", "Тип события", "Субъект (пользователь)",
            "Объект доступа", "Наименование", "Служебные заголовки"
        ])
        self.table_audit.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_audit.verticalHeader().setVisible(False)
        self.table_audit.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table_audit.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_audit.setStyleSheet("QTableWidget::item { padding: 4px; }")
        lay_audit.addWidget(self.table_audit)

        # Демо-данные (имитация подсистемы аудита)
        demo_events = [
            ("1001", "2024-05-20 10:15:30", "AUTH_SUCCESS", "engineer_ivanov", "/auth/login", "Вход в систему",
             "IP: 192.168.1.50 | UA: PyQt6/6.6.1"),
            ("1002", "2024-05-20 10:16:12", "API_QUERY", "engineer_ivanov", "/api/calculate", "Запрос расчёта",
             "method: POST | status: 200"),
            ("1003", "2024-05-20 10:20:45", "DATA_MODIFY", "engineer_ivanov", "calc_params", "Изменение параметров",
             "load=450 | blocks=2"),
            ("1004", "2024-05-20 10:25:00", "AUTH_FAIL", "test_user", "/auth/login", "Ошибка аутентификации",
             "IP: 10.0.0.15 | reason: invalid_pwd"),
            ("1005", "2024-05-20 10:30:15", "CONFIG_CHANGE", "admin_sysop", "settings/audit",
             "Изменение параметров хранения", "retention=90d | rotation=enabled"),
        ]
        for i, row in enumerate(demo_events):
            self.table_audit.insertRow(i)
            for j, val in enumerate(row):
                self.table_audit.setItem(i, j, QTableWidgetItem(val))

        # Информационная плашка
        info_lbl = QLabel("Режим эмуляции. Подключение к серверу аудита будет добавлено после реализации backend.")
        info_lbl.setStyleSheet("color: #607D8B; font-style: italic; padding: 4px;")
        lay_audit.addWidget(info_lbl)

        self.tabs.addTab(tab_audit, "Аудит и события")

    def _setup_signals(self):
        self.btn_calc.clicked.connect(self._run_calculation)
        self.btn_vac.clicked.connect(self._run_vacuum_opt)
        self.btn_plot.clicked.connect(self._plot_selected_chart)

    
    # ВАЛИДАЦИЯ
    
    def _validate_inputs(self) -> bool:
        if self.spin_load.value() <= 0:
            QMessageBox.warning(self, "Ошибка", "Нагрузка должна быть > 0"); return False
        if not (0 <= self.spin_hum.value() <= 100):
            QMessageBox.warning(self, "Ошибка", "Влажность: 0–100%"); return False
        if not (0 <= self.spin_wind_d.value() < 360):
            QMessageBox.warning(self, "Ошибка", "Направление ветра: 0–359°"); return False
        max_load = self.spin_blocks.value() * self.spin_nom_pow.value() * 1.15
        if self.spin_load.value() > max_load:
            ans = QMessageBox.question(self, "Предупреждение",
                                       f"Нагрузка превышает номинал ({max_load:.0f} МВт).\nОграничить до максимума?")
            if ans == QMessageBox.StandardButton.Yes:
                self.spin_load.setValue(max_load)
            else:
                return False
        return True


    # РАСЧЁТ

    def _run_calculation(self):
        if not self._validate_inputs(): return
        inputs = {
            "total_load": self.spin_load.value(), "num_blocks": self.spin_blocks.value(),
            "nominal_power": self.spin_nom_pow.value(), "nominal_efficiency": self.spin_nom_eff.value(),
            "temp_c": self.spin_temp.value(), "humidity": self.spin_hum.value(),
            "wind_speed": self.spin_wind_s.value(), "wind_dir": self.spin_wind_d.value(),
            "beta": self.spin_beta.value(), "own_needs_coeff": self.spin_own_needs.value()
        }
        self.progress.show(); self.progress.setValue(0); self.btn_calc.setEnabled(False)

        self.worker = CalculationWorker(inputs)
        self.worker.finished.connect(self._on_calc_finished)
        self.worker.error.connect(self._on_calc_error)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.start()

    def _on_calc_finished(self, result: dict):
        self.progress.hide(); self.btn_calc.setEnabled(True)
        for i in range(6):
            for key, val in result.items():
                if self.table_res.item(i, 0).text() == key:
                    self.table_res.setItem(i, 1, QTableWidgetItem(f"{val}"))
                    break
        QMessageBox.information(self, "Успех", "Расчёт завершён")

    def _on_calc_error(self, msg: str):
        self.progress.hide(); self.btn_calc.setEnabled(True)
        QMessageBox.critical(self, "Ошибка", f"Ошибка вычислений:\n{msg}")

    # ВАКУУМ

    def _run_vacuum_opt(self):
        t = self.spin_cool_temp.value()
        opt = round(4.5 - 0.02 * (t - 20), 2)
        self.label_vac_res.setText(f"Оптимальное разрежение: {opt} кПа")


    # ГРАФИКИ

    def _plot_selected_chart(self):
        self.ax.clear()
        idx = self.combo_chart.currentIndex()
        if idx == 0:
            self._plot_heat_capacity()
        elif idx == 1:
            self._plot_efficiency_vs_temp()
        elif idx == 2:
            self._plot_fuel_vs_temp()
        self.canvas.draw_idle()

    def _plot_heat_capacity(self):
        """ТЗ 1.1.2.3: Теплоотводящая способность & Температура"""
        temps = np.arange(-30, 45, 5)
        capacity = 1000 * (1.0 - 0.01 * (temps - 15))

        self.ax.plot(temps, capacity, 'b-o', linewidth=2, markersize=6, label='Градирня')
        self.ax.set_title("Зависимость теплоотводящей способности от температуры наружного воздуха", fontsize=12)
        self.ax.set_xlabel("Температура воздуха, °C")
        self.ax.set_ylabel("Теплоотводящая способность, МВт")
        self.ax.grid(True, alpha=0.3)
        self.ax.axhline(y=1000, color='gray', linestyle='--', alpha=0.5, label='Номинал')
        self.ax.legend()

    def _plot_efficiency_vs_temp(self):
        """Доп.: КПД нетто & Температура воздуха"""
        temps = np.arange(-30, 45, 5)
        effs = []
        nom_eff = self.spin_nom_eff.value()

        for t in temps:
            k_temp = 1 + 0.003 * (15 - t) if t <= 15 else 1 - 0.002 * (t - 15)
            k_hum = 1.0 if self.spin_hum.value() <= 60 else 1 - 0.0005 * (self.spin_hum.value() - 60)
            k_wind_s = 1 + 0.002 * min(self.spin_wind_s.value(), 8)
            angle = self.spin_wind_d.value() % 360
            k_wind_d = 0.99 if 0 <= angle <= 45 else (1.01 if 180 <= angle <= 225 else 1.00)
            k = k_temp * k_hum * k_wind_s * k_wind_d
            eff_nom = nom_eff * k
            load_ratio = self.spin_load.value() / (self.spin_blocks.value() * self.spin_nom_pow.value())
            beta = self.spin_beta.value()
            eff_load = eff_nom * (1 - beta * (1 - load_ratio) ** 2) if load_ratio < 1 else eff_nom
            own_needs = self.spin_own_needs.value()
            if t > 25: own_needs += 0.005 * (t - 25)
            elif t < 0: own_needs += 0.003 * abs(t)
            eff_netto = eff_load * (1 - own_needs)
            effs.append(eff_netto * 100)

        self.ax.plot(temps, effs, 'g-s', linewidth=2, markersize=5)
        self.ax.set_title("Зависимость КПД ТЭС нетто от температуры наружного воздуха", fontsize=12)
        self.ax.set_xlabel("Температура воздуха, °C")
        self.ax.set_ylabel("КПД нетто, %")
        self.ax.grid(True, alpha=0.3)
        self.ax.axvline(x=15, color='orange', linestyle=':', alpha=0.5, label='Номинальная температура')
        self.ax.legend()

    def _plot_fuel_vs_temp(self):
        """Удельный расход топлива & Температура воздуха"""
        temps = np.arange(-30, 45, 5)
        fuels = []
        nom_eff = self.spin_nom_eff.value()

        for t in temps:
            k_temp = 1 + 0.003 * (15 - t) if t <= 15 else 1 - 0.002 * (t - 15)
            k_hum = 1.0 if self.spin_hum.value() <= 60 else 1 - 0.0005 * (self.spin_hum.value() - 60)
            k_wind_s = 1 + 0.002 * min(self.spin_wind_s.value(), 8)
            angle = self.spin_wind_d.value() % 360
            k_wind_d = 0.99 if 0 <= angle <= 45 else (1.01 if 180 <= angle <= 225 else 1.00)
            k = k_temp * k_hum * k_wind_s * k_wind_d
            eff_nom = nom_eff * k
            load_ratio = self.spin_load.value() / (self.spin_blocks.value() * self.spin_nom_pow.value())
            beta = self.spin_beta.value()
            eff_load = eff_nom * (1 - beta * (1 - load_ratio) ** 2) if load_ratio < 1 else eff_nom
            own_needs = self.spin_own_needs.value()
            if t > 25: own_needs += 0.005 * (t - 25)
            elif t < 0: own_needs += 0.003 * abs(t)
            eff_netto = eff_load * (1 - own_needs)
            fuel = 123 / eff_netto if eff_netto > 0 else float('inf')
            fuels.append(fuel)

        self.ax.plot(temps, fuels, 'r-^', linewidth=2, markersize=5)
        self.ax.set_title("Зависимость удельного расхода топлива от температуры наружного воздуха", fontsize=12)
        self.ax.set_xlabel("Температура воздуха, °C")
        self.ax.set_ylabel("Расход топлива, г у.т./кВт·ч")
        self.ax.grid(True, alpha=0.3)
        self.ax.axvline(x=15, color='orange', linestyle=':', alpha=0.5, label='Номинальная температура')
        self.ax.legend()

    def _show_stub_dialog(self):
        QMessageBox.information(self, "Информация", "Диалог смены пароля будет подключен после интеграции с server/auth/.\nСейчас используется тестовый режим.")


# ТОЧКА ВХОДА

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    main_window = MainWindow(username="engineer_ivanov", role="operator")
    main_window.show()
    sys.exit(app.exec())
