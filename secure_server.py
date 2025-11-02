from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
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
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'web_login'
login_manager.login_message = 'Пожалуйста, войдите для доступа к этой странице.'

# Блокировка для потокобезопасности БД
db_lock = Lock()

# Папки для данных
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, Config.DATA_DIR)
DB_PATH = os.path.join(DATA_DIR, Config.DB_NAME)
os.makedirs(DATA_DIR, exist_ok=True)

# Инициализация Fernet для шифрования
fernet = Config.get_fernet()


# Модель пользователя для Flask-Login
class User(UserMixin):
    def __init__(self, id, username, is_admin=False):
        self.id = id
        self.username = username
        self.is_admin = bool(is_admin)  # Преобразуем в boolean


def get_db_connection():
    """Создание подключения к базе данных"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@login_manager.user_loader
def load_user(user_id):
    """Загрузка пользователя для Flask-Login"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    conn.close()

    if user_data:
        # Исправление: используем индексацию вместо метода get
        is_admin = user_data['is_admin'] if 'is_admin' in user_data.keys() else False
        return User(user_data['id'], user_data['username'], is_admin)
    return None


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
                    is_admin BOOLEAN DEFAULT 0,
                    is_active BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Создаем администратора по умолчанию
            admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
            cursor.execute('''
                INSERT OR IGNORE INTO users (username, password_hash, is_admin) 
                VALUES (?, ?, ?)
            ''', ('admin', admin_password, 1))

            conn.commit()
            logger.info("Database tables created successfully")

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
            devices = []
            for row in cursor.fetchall():
                # Преобразуем sqlite3.Row в обычный словарь
                devices.append(dict(row))
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


def get_all_users():
    """Получение всех пользователей"""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute('SELECT id, username, is_admin, is_active, created_at FROM users')
            users = []
            for row in cursor.fetchall():
                users.append(dict(row))
            return users
        except Exception as e:
            logger.error(f"Error getting users: {e}")
            return []
        finally:
            conn.close()


def authenticate_user(username, password):
    """Аутентификация пользователя"""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,))
        user_row = cursor.fetchone()

        if user_row and bcrypt.check_password_hash(user_row['password_hash'], password):
            # Исправление: используем индексацию вместо метода get
            is_admin = user_row['is_admin'] if 'is_admin' in user_row.keys() else False
            return User(user_row['id'], user_row['username'], is_admin)
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
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('utf-8')
        decrypted = fernet.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        raise


# Инициализация базы данных при старте
try:
    init_database()
    logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")


# ==================== ВЕБ-МАРШРУТЫ С АВТОРИЗАЦИЕЙ ====================

@app.route('/')
@login_required
def index():
    """Главная страница панели управления"""
    try:
        devices_count = len(get_all_devices())
        users_count = len(get_all_users())
        return render_template('dashboard.html',
                               devices_count=devices_count,
                               users_count=users_count,
                               current_user=current_user)
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        flash('Ошибка загрузки данных', 'error')
        return render_template('dashboard.html', current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def web_login():
    """Страница входа в веб-интерфейс"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))

        user = authenticate_user(username, password)
        if user:
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            flash(f'Добро пожаловать, {username}!', 'success')
            return redirect(next_page or url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def web_logout():
    """Выход из системы"""
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('web_login'))


@app.route('/devices')
@login_required
def web_devices():
    """Страница со списком устройств"""
    try:
        devices = get_all_devices()
        return render_template('devices.html', devices=devices, current_user=current_user)
    except Exception as e:
        logger.error(f"Error in web_devices route: {e}")
        flash('Ошибка загрузки устройств', 'error')
        return render_template('devices.html', devices=[], current_user=current_user)


@app.route('/device/<device_id>')
@login_required
def device_detail(device_id):
    """Страница с детальной информацией об устройстве"""
    try:
        device = get_device(device_id)
        if not device:
            flash('Устройство не найдено', 'error')
            return redirect(url_for('web_devices'))
        return render_template('device_detail.html', device=device, current_user=current_user)
    except Exception as e:
        logger.error(f"Error in device_detail route: {e}")
        flash('Ошибка загрузки устройства', 'error')
        return redirect(url_for('web_devices'))


@app.route('/users')
@login_required
def web_users():
    """Страница управления пользователями (только для админов)"""
    if not current_user.is_admin:
        flash('Доступ запрещен. Требуются права администратора.', 'error')
        return redirect(url_for('index'))

    try:
        users = get_all_users()
        return render_template('users.html', users=users, current_user=current_user)
    except Exception as e:
        logger.error(f"Error in web_users route: {e}")
        flash('Ошибка загрузки пользователей', 'error')
        return render_template('users.html', users=[], current_user=current_user)


@app.route('/settings')
@login_required
def web_settings():
    """Страница настроек"""
    return render_template('settings.html', current_user=current_user)


# ==================== API МАРШРУТЫ ====================

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """API аутентификация для клиентов"""
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
            access_token = create_access_token(identity=user.username)
            return jsonify({
                'access_token': access_token,
                'username': user.username
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
        current_api_user = get_jwt_identity()
        logger.info(f"Data submission from user: {current_api_user}")

        if not request.data:
            return jsonify({'error': 'No data provided'}), 400

        # Дешифруем данные
        try:
            encrypted_data = request.get_data().decode('utf-8')
            decrypted_data = decrypt_data(encrypted_data)
            data = json.loads(decrypted_data)
        except Exception as e:
            logger.error(f"Decryption error: {e}")
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
                'received_by': current_api_user
            })
        else:
            return jsonify({'error': 'Failed to save data'}), 500

    except Exception as e:
        logger.error(f"Error in secure_submit_data: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/devices')
@jwt_required()
def api_devices():
    """API endpoint для получения списка устройств"""
    try:
        devices = get_all_devices()
        return jsonify(devices)
    except Exception as e:
        logger.error(f"Error in api_devices: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/health')
def health_check():
    """Проверка здоровья сервера"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        conn.close()

        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e)
        }), 500


if __name__ == '__main__':
    # Создаем папки если их нет
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)

    # Запуск сервера
    print("=" * 60)
    print("🔒 Secure System Information Server with Web Auth")
    print("=" * 60)
    print(f"Server URL: {Config.SERVER_URL}")
    print(f"Web Login: {Config.SERVER_URL}/login")
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