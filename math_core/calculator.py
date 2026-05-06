"""
math_core/calculator.py
Математическое ядро — расчёты эффективности ТЭС
"""
import numpy as np


# ============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (ПОПРАВКИ)
# ============================================================================

def temp_correction(temp_c: float) -> float:
    """Поправка на температуру воздуха"""
    if temp_c <= 15:
        return 1 + 0.003 * (15 - temp_c)
    else:
        return 1 - 0.002 * (temp_c - 15)


def humidity_correction(humidity: float) -> float:
    """Поправка на влажность"""
    if humidity <= 60:
        return 1.0
    else:
        return 1 - 0.0005 * (humidity - 60)


def wind_speed_correction(speed: float) -> float:
    """Поправка на скорость ветра (м/с)"""
    if speed <= 8:
        return 1 + 0.002 * speed
    else:
        return 1 + 0.002 * 8


def wind_direction_correction(direction_deg: float) -> float:
    """Поправка на направление ветра (градусы)"""
    angle = direction_deg % 360
    if 0 <= angle <= 45:
        return 0.99
    elif 180 <= angle <= 225:
        return 1.01
    else:
        return 1.00


def load_correction(current_power: float, nominal_power: float,
                    base_efficiency: float, beta: float = 0.4) -> float:
    """Поправка КПД на частичную нагрузку"""
    load_ratio = current_power / nominal_power
    if load_ratio >= 1:
        return base_efficiency
    return base_efficiency * (1 - beta * (1 - load_ratio) ** 2)


# ============================================================================
# ОСНОВНЫЕ РАСЧЁТНЫЕ ФУНКЦИИ
# ============================================================================

def calc_block_efficiency(power_mw: float, nominal_power: float,
                          nominal_efficiency: float, temp_c: float,
                          humidity: float, wind_speed: float,
                          wind_dir: float, beta: float = 0.4) -> float:
    """Расчёт КПД одного блока с учётом всех факторов"""
    k = (temp_correction(temp_c) *
         humidity_correction(humidity) *
         wind_speed_correction(wind_speed) *
         wind_direction_correction(wind_dir))
    efficiency_at_nominal = nominal_efficiency * k
    actual_efficiency = load_correction(power_mw, nominal_power,
                                        efficiency_at_nominal, beta)
    return actual_efficiency


def calc_tes_efficiency(total_load: float, num_blocks: int,
                        nominal_power_per_block: float,
                        nominal_efficiency: float,
                        temp_c: float, humidity: float,
                        wind_speed: float, wind_dir: float,
                        own_needs_coeff: float = 0.05,
                        beta: float = 0.4) -> dict:
    """
    Расчёт эффективности ТЭС.
    Возвращает словарь с результатами согласно ТЗ:
      - load_per_block, block_efficiency, efficiency_brutto,
        efficiency_netto, fuel_consumption, own_needs_percent
    """
    load_per_block = total_load / num_blocks

    if load_per_block > nominal_power_per_block:
        load_per_block = nominal_power_per_block

    block_efficiency = calc_block_efficiency(
        load_per_block, nominal_power_per_block, nominal_efficiency,
        temp_c, humidity, wind_speed, wind_dir, beta
    )

    total_power_brutto = num_blocks * load_per_block
    efficiency_brutto = block_efficiency

    own_needs = own_needs_coeff
    if temp_c > 25:
        own_needs += 0.005 * (temp_c - 25)
    elif temp_c < 0:
        own_needs += 0.003 * abs(temp_c)

    own_needs_power = total_power_brutto * own_needs
    total_power_netto = total_power_brutto - own_needs_power
    efficiency_netto = efficiency_brutto * (1 - own_needs)
    fuel_consumption = 123 / efficiency_netto if efficiency_netto > 0 else float('inf')

    return {
        'load_per_block': load_per_block,
        'block_efficiency': block_efficiency,
        'efficiency_brutto': efficiency_brutto,
        'efficiency_netto': efficiency_netto,
        'fuel_consumption': fuel_consumption,
        'total_power_brutto': total_power_brutto,
        'total_power_netto': total_power_netto,
        'own_needs_power': own_needs_power,
        'own_needs_percent': own_needs * 100
    }


def analyze_temperature(total_load: float, num_blocks: int,
                        nominal_power: float, nominal_efficiency: float,
                        humidity: float, wind_speed: float,
                        wind_dir: float) -> tuple:
    """Анализ зависимости КПД от температуры"""
    temps = np.arange(-20, 41, 5)
    efficiencies, fuel_rates = [], []

    for t in temps:
        res = calc_tes_efficiency(total_load, num_blocks, nominal_power,
                                  nominal_efficiency, float(t),
                                  humidity, wind_speed, wind_dir)
        efficiencies.append(res['efficiency_netto'] * 100)
        fuel_rates.append(res['fuel_consumption'])

    return temps.tolist(), efficiencies, fuel_rates


def analyze_load_distribution(total_load: float, nominal_power: float,
                               nominal_efficiency: float, temp_c: float,
                               humidity: float, wind_speed: float,
                               wind_dir: float) -> list:
    """Анализ эффективности при разном количестве блоков"""
    results = []
    for n in [1, 2, 3, 4]:
        if n * nominal_power >= total_load:
            res = calc_tes_efficiency(total_load, n, nominal_power,
                                      nominal_efficiency, temp_c,
                                      humidity, wind_speed, wind_dir)
            results.append({
                'blocks': n,
                'load_per_block': res['load_per_block'],
                'load_percent': (res['load_per_block'] / nominal_power) * 100,
                'efficiency': res['efficiency_netto'] * 100,
                'fuel_rate': res['fuel_consumption']
            })
    return results