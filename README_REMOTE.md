# Документация по системе сбора системной информации

## Обзор системы

Система состоит из двух основных компонентов:
- **Сервер** - веб-приложение на Flask для приема, хранения и отображения данных
- **Клиент** - desktop-приложение на Tkinter для сбора и отправки системной информации

### Основные возможности
- Сбор аппаратных характеристик компьютера (CPU, GPU, память, диски, MAC-адрес)
- Безопасная передача данных с шифрованием
- JWT аутентификация
- Веб-интерфейс для просмотра данных
- Кроссплатформенная работа (Windows, Linux, macOS)

---

## Требования к системе

### Аппаратные требования
- **Сервер**: 512MB RAM, 1GB свободного места
- **Клиент**: 256MB RAM, 100MB свободного места

### Программные требования
- Python 3.7 или выше
- Поддерживаемые ОС: Windows 7+, Ubuntu 16.04+, macOS 10.12+

---

## Установка и настройка

### 1. Установка зависимостей

Создайте файл `requirements.txt`:
```txt
psutil>=7.1.2
pyinstaller>=6.16.0
requests>=2.32.5
flask>=3.1.2
flask-jwt-extended>=4.7.1
flask-bcrypt>=1.0.1
cryptography>=46.0.3
gunicorn>=23.0.0
pycryptodome>=3.23.0
```

Установите зависимости:
```bash
pip install -r requirements.txt
```

### 2. Структура файлов проекта

```
system-info-collector/
├── config.py                 # Общая конфигурация
├── secure_server.py          # Серверная часть
├── secure_client.py          # Клиентская часть
├── run_server.py            # Скрипт запуска сервера
├── wsgi.py                  # WSGI для production
├── gunicorn_config.py       # Конфигурация Gunicorn
├── requirements.txt         # Зависимости
├── collected_data/          # Данные (создается автоматически)
│   └── devices.db          # База данных SQLite
├── templates/              # HTML шаблоны
│   ├── index.html
│   └── device_detail.html
└── static/                 # Статические файлы (CSS, JS)
```

### 3. Конфигурация

#### Файл config.py
```python
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'your-32-byte-encryption-key-here-1234567890!')
    SERVER_HOST = os.environ.get('SERVER_HOST', 'localhost')
    SERVER_PORT = os.environ.get('SERVER_PORT', '5000')
```

#### Переменные окружения для production
```bash
export SECRET_KEY="your-very-secure-secret-key-2024"
export JWT_SECRET_KEY="your-jwt-secret-key-2024"
export ENCRYPTION_KEY="your-32-byte-encryption-key-here-1234567890!"
export SERVER_HOST="0.0.0.0"
export SERVER_PORT="5000"
```

---

## Развертывание сервера

### 1. Режим разработки

```bash
# Простой запуск
python secure_server.py

# Или через скрипт запуска
python run_server.py
```

Сервер будет доступен по адресу: `http://localhost:5000`

### 2. Production режим с Gunicorn

```bash
# Прямой запуск
gunicorn --bind 0.0.0.0:5000 --workers 4 secure_server:app

# С конфигурационным файлом
gunicorn -c gunicorn_config.py secure_server:app
```

### 3. Docker развертывание

Создайте `Dockerfile`:
```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "secure_server:app"]
```

Сборка и запуск:
```bash
docker build -t system-info-server .
docker run -d -p 5000:5000 --name system-info-server system-info-server
```

### 4. Развертывание на хостингах

#### Heroku
Создайте `Procfile`:
```
web: gunicorn --bind 0.0.0.0:$PORT --workers 4 secure_server:app
```

#### PythonAnywhere
- Загрузите файлы через веб-интерфейс
- Настройте WSGI конфигурацию
- Укажите путь к `wsgi.py`

### 5. Настройка обратного прокси (nginx)

Пример конфигурации nginx:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Развертывание клиента

### 1. Запуск из исходного кода

```bash
python secure_client.py
```

### 2. Сборка в исполняемый файл

#### Для Windows:
```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name="SystemInfoClient" secure_client.py
```

#### Для Linux:
```bash
pip install pyinstaller
pyinstaller --onefile --name="SystemInfoClient" secure_client.py
```

#### Для macOS:
```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name="SystemInfoClient" secure_client.py
```

### 3. Настройка клиента

При первом запуске:
1. Введите URL сервера (например: `http://your-server.com:5000`)
2. Нажмите "Тест подключения" для проверки связи
3. Нажмите "Тест шифрования" для проверки безопасности
4. Авторизуйтесь с логином `admin` и паролем `admin123`
5. Сканируйте систему и отправляйте данные

---

## Администрирование

### Учетные данные по умолчанию
- **Логин**: `admin`
- **Пароль**: `admin123`

### Смена пароля администратора

Через SQLite консоль:
```bash
sqlite3 collected_data/devices.db
UPDATE users SET password_hash = '<new_hash>' WHERE username = 'admin';
```

Или создайте скрипт смены пароля `change_password.py`:
```python
from secure_server import bcrypt, get_db_connection

def change_password(username, new_password):
    conn = get_db_connection()
    cursor = conn.cursor()
    password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    cursor.execute('UPDATE users SET password_hash = ? WHERE username = ?', 
                   (password_hash, username))
    conn.commit()
    conn.close()
    print(f"Password changed for user: {username}")

if __name__ == '__main__':
    change_password('admin', 'new_secure_password_2024')
```

### Мониторинг работы системы

#### Проверка здоровья сервера
```bash
curl http://your-server:5000/health
```

#### Просмотр логов
```bash
# Логи сервера (при запуске через gunicorn)
tail -f logs/server.log

# Логи клиента
# Находятся в стандартном выводе или файле логов клиента
```

### Резервное копирование данных

```bash
# Копирование базы данных
cp collected_data/devices.db backup/devices_$(date +%Y%m%d).db

# Автоматическое резервное копирование (cron)
0 2 * * * cp /path/to/collected_data/devices.db /backup/devices_$(date +\%Y\%m\%d).db
```

---

## Безопасность

### Критические настройки безопасности

1. **Замените все ключи по умолчанию** в production среде:
   - `SECRET_KEY`
   - `JWT_SECRET_KEY` 
   - `ENCRYPTION_KEY`

2. **Настройка брандмауэра**:
   ```bash
   # Разрешить только порт 5000
   ufw allow 5000
   ufw enable
   ```

3. **Использование HTTPS**:
   - Настройте SSL сертификат (Let's Encrypt)
   - Используйте reverse proxy с HTTPS

### Рекомендации по безопасности

1. Регулярно обновляйте зависимости
2. Используйте сложные пароли
3. Ограничьте доступ к серверу по IP при необходимости
4. Регулярно делайте бэкапы базы данных

---

## Устранение неполадок

### Частые проблемы и решения

#### 1. Ошибка "no such table"
```bash
# Удалите и пересоздайте базу данных
rm -f collected_data/devices.db
python secure_server.py
```

#### 2. Ошибки шифрования
- Убедитесь, что `ENCRYPTION_KEY` одинаков на клиенте и сервере
- Используйте функцию "Тест шифрования" в клиенте

#### 3. Ошибки подключения
- Проверьте настройки firewall
- Убедитесь, что сервер запущен на правильном IP и порту
- Проверьте настройки DNS, если используется доменное имя

#### 4. Ошибки при сборке EXE
```bash
# Убедитесь, что все зависимости установлены
pip install -r requirements.txt

# Попробуйте собрать с явным указанием скрытых импортов
pyinstaller --onefile --hidden-import=psutil --hidden-import=requests secure_client.py
```

### Логирование

Сервер и клиент используют подробное логирование. Уровень логирования можно настроить в коде:

```python
import logging
logging.basicConfig(level=logging.INFO)  # DEBUG, INFO, WARNING, ERROR
```

---

## Мониторинг и масштабирование

### Мониторинг производительности

Добавьте endpoint для мониторинга:
```python
@app.route('/api/stats')
@jwt_required()
def get_stats():
    devices_count = len(get_all_devices())
    # Дополнительная статистика
    return jsonify({
        'devices_count': devices_count,
        'server_uptime': get_uptime(),
        'memory_usage': get_memory_usage()
    })
```

### Масштабирование

Для высоких нагрузок:
1. Используйте PostgreSQL вместо SQLite
2. Добавьте балансировщик нагрузки
3. Настройке кэширование
4. Используйте несколько worker процессов в Gunicorn

---

## Дополнительные возможности

### Интеграция с системами мониторинга

Добавьте поддержку Prometheus метрик:
```python
from prometheus_client import Counter, generate_latest

devices_submitted = Counter('devices_submitted', 'Total devices submitted')

@app.route('/metrics')
def metrics():
    return generate_latest()
```

### Расширение собираемых данных

Для добавления новых типов данных модифицируйте функцию сбора информации в клиенте и соответствующие таблицы в базе данных.

---

## Поддержка и обновления

### Процесс обновления

1. Остановите сервер
2. Сделайте бэкап базы данных
3. Обновите код
4. Запустите сервер
5. Проверьте работоспособность

### Получение помощи

При возникновении проблем:
1. Проверьте логи сервера и клиента
2. Убедитесь в правильности конфигурации
3. Проверьте совместимость версий

---

## Заключение

Система готова к использованию в production среде после выполнения всех шагов настройки безопасности. Регулярно обновляйте компоненты системы и следите за безопасностью.

Для дополнительной информации обращайтесь к документации используемых библиотек:
- Flask: https://flask.palletsprojects.com/
- JWT: https://flask-jwt-extended.readthedocs.io/
- Gunicorn: https://docs.gunicorn.org/
- PyInstaller: https://pyinstaller.org/

**Важно**: Всегда тестируйте обновления в тестовой среде перед развертыванием в production!