# security_middleware.py
from flask import request, abort
import logging


class SecurityMiddleware:
    def __init__(self, app, allowed_networks=None):
        self.app = app
        self.allowed_networks = allowed_networks or ['192.168.0.0/24']  # Только локальная сеть
        self.logger = logging.getLogger('security')

    def __call__(self, environ, start_response):
        # Проверяем IP клиента
        client_ip = environ.get('REMOTE_ADDR')

        # Разрешаем доступ только из доверенных сетей
        if not self.is_ip_allowed(client_ip):
            self.logger.warning(f"Blocked access from: {client_ip}")
            abort(403)  # Forbidden

        return self.app(environ, start_response)

    def is_ip_allowed(self, ip):
        # Простая проверка - разрешаем только локальные адреса
        # В продакшене нужно настроить более сложную логику
        return ip.startswith('192.168.') or ip.startswith('127.') or ip == '::1'