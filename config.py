import configparser
import os


class Config:
    _instance = None

    def __new__(cls, config_path="config.ini"):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load(config_path)
        return cls._instance

    def _load(self, config_path):
        self.config = configparser.ConfigParser()
        self.config.optionxform = str  # Сохраняем регистр ключей

        # Если файла нет - создаём с значениями по умолчанию
        if not os.path.exists(config_path):
            self._create_default_config(config_path)

        self.config.read(config_path, encoding='utf-8')

    def _create_default_config(self, config_path):
        self.config['DATABASE'] = {'path': 'users.db'}
        self.config['AUTH'] = {'max_attempts': '3', 'lockout_minutes': '15'}
        self.config['PASSWORD'] = {
            'user_min_length': '6',
            'admin_min_length': '7',
            'special_chars': '~!@#$%^&*'
        }
        self.config['TIME'] = {'timezone': 'Europe/Moscow', 'offset_hours': '3'}
        self.config['BCRYPT'] = {'rounds': '12'}

        with open(config_path, 'w', encoding='utf-8') as f:
            self.config.write(f)

    @property
    def db_path(self):
        return self.config['DATABASE']['path']

    @property
    def max_attempts(self):
        return int(self.config['AUTH']['max_attempts'])

    @property
    def lockout_minutes(self):
        return int(self.config['AUTH']['lockout_minutes'])

    @property
    def user_min_length(self):
        return int(self.config['PASSWORD']['user_min_length'])

    @property
    def admin_min_length(self):
        return int(self.config['PASSWORD']['admin_min_length'])

    @property
    def special_chars(self):
        # Получаем строку как есть, без интерполяции
        return self.config.get('PASSWORD', 'special_chars', raw=True)

    @property
    def timezone(self):
        return self.config['TIME']['timezone']

    @property
    def time_offset(self):
        return int(self.config['TIME']['offset_hours'])

    @property
    def bcrypt_rounds(self):
        return int(self.config['BCRYPT']['rounds'])


# Глобальный экземпляр
config = Config()

# Тест
if __name__ == "__main__":
    print("Конфиг загружен:")
    print(f"  special_chars: {config.special_chars}")
    print(f"  max_attempts: {config.max_attempts}")
    print(f"  db_path: {config.db_path}")