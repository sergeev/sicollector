from secure_server import app

# Принудительная инициализация базы данных при запуске через WSGI
if __name__ == "__main__":
    app.run()