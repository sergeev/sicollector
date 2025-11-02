from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
import json
import os
from datetime import datetime, timedelta
import sqlite3
from threading import Lock
import logging

from config import Config

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Конфигурация Flask
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config['JWT_SECRET_KEY'] = Config.JWT_SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=Config.JWT_ACCESS_TOKEN_EXPIRES_HOURS)

# Инициализация расширений
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# Блокировка для потокобезопасности БД
db_lock = Lock()

# Папки для данных
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, Config.DATA_DIR)
DB_PATH = os.path.join(DATA_DIR, Config.DB_NAME)
os.makedirs(DATA_DIR, exist_ok=True)

# Инициализация Fernet для шифрования
fernet = Config.get_fernet()


def get_db_connection():
    """Создание подключения к базе данных"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Инициализация базы данных"""
    logger.info(f"Initializing database at: {DB_PATH}")

    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Таблица устройств
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

            # Таблица пользователей для авторизации
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Создаем администратора по умолчанию
            admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
            cursor.execute('''
                INSERT OR IGNORE INTO users (username, password_hash) 
                VALUES (?, ?)
            ''', ('admin', admin_password))

            conn.commit()
            logger.info("Database tables created successfully")

            # Проверяем существование таблиц
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            logger.info(f"Available tables: {[table[0] for table in tables]}")

        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()


def save_device_data(data):
    """Сохранение или обновление данных устройства"""
    with db_lock:
        conn = get_db_connection()
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
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT * FROM devices 
                ORDER BY last_updated DESC
            ''')
            devices = [dict(row) for row in cursor.fetchall()]
            return devices
        except Exception as e:
            logger.error(f"Error getting devices: {e}")
            return []
        finally:
            conn.close()


def get_device(device_id):
    """Получение конкретного устройства"""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute('SELECT * FROM devices WHERE device_id = ?', (device_id,))
            device = cursor.fetchone()
            return dict(device) if device else None
        except Exception as e:
            logger.error(f"Error getting device {device_id}: {e}")
            return None
        finally:
            conn.close()


def authenticate_user(username, password):
    """Аутентификация пользователя"""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[2], password):
            return {'id': user[0], 'username': user[1]}
        return None
    except Exception as e:
        logger.error(f"Error authenticating user {username}: {e}")
        return None
    finally:
        conn.close()


def encrypt_data(data):
    """Шифрование данных"""
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        encrypted = fernet.encrypt(data)
        return encrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        raise


def decrypt_data(encrypted_data):
    """Дешифрование данных"""
    try:
        logger.info(f"Attempting to decrypt data, length: {len(encrypted_data)}")

        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('utf-8')

        decrypted = fernet.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        logger.error(f"Data sample (first 100 chars): {encrypted_data[:100] if encrypted_data else 'None'}")
        raise


# Инициализация базы данных при старте
try:
    init_database()
    logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")


@app.route('/')
def index():
    """Главная страница со списком устройств"""
    try:
        devices = get_all_devices()
        return render_template('index.html', devices=devices)
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        return "Server error", 500


@app.route('/device/<device_id>')
def device_detail(device_id):
    """Страница с детальной информацией об устройстве"""
    try:
        device = get_device(device_id)
        if not device:
            return "Device not found", 404
        return render_template('device_detail.html', device=device)
    except Exception as e:
        logger.error(f"Error in device_detail route: {e}")
        return "Server error", 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Аутентификация пользователя"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        user = authenticate_user(username, password)
        if user:
            access_token = create_access_token(identity=user['username'])
            return jsonify({
                'access_token': access_token,
                'username': user['username']
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/secure/submit', methods=['POST'])
@jwt_required()
def secure_submit_data():
    """Безопасный endpoint для отправки данных с клиентов"""
    try:
        current_user = get_jwt_identity()
        logger.info(f"Data submission from user: {current_user}")

        # Проверяем зашифрованные данные
        if not request.data:
            return jsonify({'error': 'No data provided'}), 400

        logger.info(f"Received encrypted data length: {len(request.data)}")

        # Дешифруем данные
        try:
            encrypted_data = request.get_data().decode('utf-8')
            logger.info(f"Decoding encrypted data, sample: {encrypted_data[:100]}...")

            decrypted_data = decrypt_data(encrypted_data)
            logger.info(f"Successfully decrypted data, length: {len(decrypted_data)}")

            data = json.loads(decrypted_data)
            logger.info(f"Successfully parsed JSON data for device: {data.get('device_id', 'Unknown')}")

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error after decryption: {e}")
            logger.error(f"Decrypted data sample: {decrypted_data[:200] if 'decrypted_data' in locals() else 'N/A'}")
            return jsonify({'error': 'Invalid JSON data after decryption'}), 400
        except Exception as e:
            logger.error(f"Decryption/parsing error: {e}")
            return jsonify({'error': 'Invalid or corrupted data'}), 400

        # Валидация обязательных полей
        required_fields = ['device_id', 'computer_name', 'mac_address', 'cpu_info']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Сохраняем данные
        if save_device_data(data):
            return jsonify({
                'status': 'success',
                'message': 'Data received and saved successfully',
                'received_by': current_user
            })
        else:
            return jsonify({'error': 'Failed to save data'}), 500

    except Exception as e:
        logger.error(f"Error in secure_submit_data: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/devices')
@jwt_required()
def api_devices():
    """API endpoint для получения списка устройств (требуется авторизация)"""
    try:
        devices = get_all_devices()
        return jsonify(devices)
    except Exception as e:
        logger.error(f"Error in api_devices: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/device/<device_id>')
@jwt_required()
def api_device(device_id):
    """API endpoint для получения данных конкретного устройства"""
    try:
        device = get_device(device_id)
        if device:
            return jsonify(device)
        else:
            return jsonify({'error': 'Device not found'}), 404
    except Exception as e:
        logger.error(f"Error in api_device: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/admin')
def admin_panel():
    """Панель администратора"""
    return render_template('admin.html')


@app.route('/health')
def health_check():
    """Проверка здоровья сервера"""
    try:
        # Проверяем подключение к базе данных
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        conn.close()

        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'encryption': 'configured',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e)
        }), 500


@app.route('/api/test/encryption', methods=['POST'])
def test_encryption():
    """Тестовый endpoint для проверки шифрования"""
    try:
        test_data = {"test": "Hello, World!", "timestamp": datetime.now().isoformat()}
        encrypted = encrypt_data(json.dumps(test_data))
        decrypted = decrypt_data(encrypted)

        return jsonify({
            'original': test_data,
            'encrypted_sample': encrypted[:50] + '...',
            'decrypted': json.loads(decrypted),
            'success': True
        })
    except Exception as e:
        logger.error(f"Encryption test failed: {e}")
        return jsonify({'error': str(e), 'success': False}), 500


if __name__ == '__main__':
    # Создаем папки если их нет
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)

    # Запуск сервера
    print("=" * 60)
    print("🔒 Secure System Information Server")
    print("=" * 60)
    print(f"Server URL: {Config.SERVER_URL}")
    print(f"Database: {DB_PATH}")
    print(f"Encryption: {'✅ Configured' if Config.ENCRYPTION_KEY else '❌ Not configured'}")
    print("Default admin credentials: admin / admin123")
    print("=" * 60)

    try:
        app.run(
            host=Config.SERVER_HOST,
            port=int(Config.SERVER_PORT),
            debug=True
        )
    except Exception as e:
        logger.error(f"Server failed to start: {e}")