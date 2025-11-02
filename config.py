import os
import base64
import hashlib
from cryptography.fernet import Fernet


class Config:
    """Общая конфигурация для клиента и сервера"""

    # Безопасность
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production')

    # Ключ шифрования (ДОЛЖЕН БЫТЬ ОДИНАКОВЫМ НА КЛИЕНТЕ И СЕРВЕРЕ)
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'your-32-byte-encryption-key-here-1234567890!')

    # Генерация Fernet ключа на основе ENCRYPTION_KEY
    @classmethod
    def get_fernet_key(cls):
        return base64.urlsafe_b64encode(
            hashlib.sha256(cls.ENCRYPTION_KEY.encode()).digest()
        )

    @classmethod
    def get_fernet(cls):
        return Fernet(cls.get_fernet_key())

    # Настройки сервера
    SERVER_HOST = os.environ.get('SERVER_HOST', 'localhost')
    SERVER_PORT = os.environ.get('SERVER_PORT', '5000')
    SERVER_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"

    # Настройки базы данных
    DATA_DIR = "collected_data"
    DB_NAME = "devices.db"

    # JWT настройки
    JWT_ACCESS_TOKEN_EXPIRES_HOURS = 24