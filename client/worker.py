import time
from PyQt6.QtCore import QThread, pyqtSignal


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
            time.sleep(0.8) # Имитация задержки сети/очереди
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