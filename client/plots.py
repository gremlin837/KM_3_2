import numpy as np


def plot_heat_capacity(self):
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


def plot_efficiency_vs_temp(self):
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
        if t > 25:
            own_needs += 0.005 * (t - 25)
        elif t < 0:
            own_needs += 0.003 * abs(t)
        eff_netto = eff_load * (1 - own_needs)
        effs.append(eff_netto * 100)

    self.ax.plot(temps, effs, 'g-s', linewidth=2, markersize=5)
    self.ax.set_title("Зависимость КПД ТЭС нетто от температуры наружного воздуха", fontsize=12)
    self.ax.set_xlabel("Температура воздуха, °C")
    self.ax.set_ylabel("КПД нетто, %")
    self.ax.grid(True, alpha=0.3)
    self.ax.axvline(x=15, color='orange', linestyle=':', alpha=0.5, label='Номинальная температура')
    self.ax.legend()


def plot_fuel_vs_temp(self):
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
        if t > 25:
            own_needs += 0.005 * (t - 25)
        elif t < 0:
            own_needs += 0.003 * abs(t)
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