import os
import subprocess
import sys


def start_production_server():
    """Запуск сервера в production режиме с Gunicorn"""

    # Проверяем наличие gunicorn
    try:
        import gunicorn
    except ImportError:
        print("Gunicorn не установлен. Установите: pip install gunicorn")
        return

    # Параметры запуска
    host = os.environ.get('HOST', '0.0.0.0')
    port = os.environ.get('PORT', '5000')
    workers = os.environ.get('WORKERS', '4')

    cmd = [
        'gunicorn',
        '--bind', f'{host}:{port}',
        '--workers', workers,
        '--timeout', '120',
        '--access-logfile', '-',
        '--error-logfile', '-',
        'wsgi:app'
    ]

    print(f"Запуск production сервера на {host}:{port}")
    print(f"Workers: {workers}")
    print("Для остановки нажмите Ctrl+C")

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nОстановка сервера...")
    except Exception as e:
        print(f"Ошибка запуска: {e}")


if __name__ == '__main__':
    start_production_server()