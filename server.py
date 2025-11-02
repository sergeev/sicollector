from flask import Flask, render_template, request, jsonify, send_from_directory
import json
import os
from datetime import datetime
import sqlite3
from threading import Lock
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Блокировка для потокобезопасности БД
db_lock = Lock()

# Папки для данных
DATA_DIR = "collected_data"
DB_PATH = os.path.join(DATA_DIR, "devices.db")
os.makedirs(DATA_DIR, exist_ok=True)


def init_database():
    """Инициализация базы данных"""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT UNIQUE,
                computer_name TEXT,
                mac_address TEXT,
                cpu_info TEXT,
                gpu_info TEXT,
                memory_info TEXT,
                disk_info TEXT,
                os_info TEXT,
                architecture TEXT,
                python_version TEXT,
                ip_address TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    logger.info("Database initialized")


def save_device_data(data):
    """Сохранение или обновление данных устройства"""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        try:
            # Проверяем существование устройства
            cursor.execute('SELECT id FROM devices WHERE device_id = ?', (data['device_id'],))
            existing = cursor.fetchone()

            if existing:
                # Обновляем существующую запись
                cursor.execute('''
                    UPDATE devices SET 
                    computer_name = ?, mac_address = ?, cpu_info = ?, gpu_info = ?,
                    memory_info = ?, disk_info = ?, os_info = ?, architecture = ?,
                    python_version = ?, ip_address = ?, last_updated = CURRENT_TIMESTAMP
                    WHERE device_id = ?
                ''', (
                    data['computer_name'], data['mac_address'], data['cpu_info'],
                    data['gpu_info'], data['memory_info'], data['disk_info'],
                    data['os_info'], data['architecture'], data['python_version'],
                    request.remote_addr, data['device_id']
                ))
            else:
                # Вставляем новую запись
                cursor.execute('''
                    INSERT INTO devices 
                    (device_id, computer_name, mac_address, cpu_info, gpu_info,
                     memory_info, disk_info, os_info, architecture, python_version, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    data['device_id'], data['computer_name'], data['mac_address'],
                    data['cpu_info'], data['gpu_info'], data['memory_info'],
                    data['disk_info'], data['os_info'], data['architecture'],
                    data['python_version'], request.remote_addr
                ))

            conn.commit()
            logger.info(f"Data saved for device: {data['device_id']}")
            return True

        except Exception as e:
            logger.error(f"Error saving device data: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()


def get_all_devices():
    """Получение всех устройств"""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM devices 
            ORDER BY last_updated DESC
        ''')
        devices = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return devices


def get_device(device_id):
    """Получение конкретного устройства"""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM devices WHERE device_id = ?', (device_id,))
        device = cursor.fetchone()
        conn.close()

        return dict(device) if device else None


@app.route('/')
def index():
    """Главная страница со списком устройств"""
    devices = get_all_devices()
    return render_template('index.html', devices=devices)


@app.route('/device/<device_id>')
def device_detail(device_id):
    """Страница с детальной информацией об устройстве"""
    device = get_device(device_id)
    if not device:
        return "Device not found", 404
    return render_template('device_detail.html', device=device)


@app.route('/api/submit', methods=['POST'])
def submit_data():
    """API endpoint для отправки данных с клиентов"""
    try:
        data = request.get_json()

        # Валидация обязательных полей
        required_fields = ['device_id', 'computer_name', 'mac_address', 'cpu_info']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Сохраняем данные
        if save_device_data(data):
            return jsonify({'status': 'success', 'message': 'Data received successfully'})
        else:
            return jsonify({'error': 'Failed to save data'}), 500

    except Exception as e:
        logger.error(f"Error in submit_data: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/devices')
def api_devices():
    """API endpoint для получения списка устройств"""
    devices = get_all_devices()
    return jsonify(devices)


@app.route('/api/device/<device_id>')
def api_device(device_id):
    """API endpoint для получения данных конкретного устройства"""
    device = get_device(device_id)
    if device:
        return jsonify(device)
    else:
        return jsonify({'error': 'Device not found'}), 404


@app.route('/static/<path:filename>')
def static_files(filename):
    """Статические файлы"""
    return send_from_directory('static', filename)


if __name__ == '__main__':
    # Инициализация БД при запуске
    init_database()

    # Создаем папку для шаблонов если её нет
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)

    # Запуск сервера
    print("Starting server on http://0.0.0.0:5000")
    print("Access the dashboard at http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)