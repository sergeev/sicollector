#!/usr/bin/env python3
"""
Скрипт для запуска безопасного сервера
"""

import os
import sys

# Добавляем текущую директорию в путь для импортов
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from secure_server import app

if __name__ == '__main__':
    print("🚀 Запуск безопасного сервера...")
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )