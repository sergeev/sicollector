# check_public_access.py
import requests
import socket


def check_access():
    print("🔍 Проверка доступности сервера...")

    addresses = [
        ("Локальный доступ", "http://localhost:5000/health"),
        ("Внутренняя сеть", "http://0.0.0.0:5000/health"),
        ("Внешний доступ", "http://0.0.0.0:5000/health")
    ]

    for name, url in addresses:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                print(f"✅ {name}: ДОСТУПЕН - {url}")
            else:
                print(f"⚠️  {name}: Ошибка {response.status_code} - {url}")
        except requests.exceptions.RequestException as e:
            print(f"❌ {name}: НЕДОСТУПЕН - {url}")
            print(f"   Причина: {e}")


def get_network_info():
    print("\n🌐 Сетевая информация:")
    try:
        # Получаем локальный IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print(f"📍 Имя компьютера: {hostname}")
        print(f"📍 Локальный IP: {local_ip}")

        # Пытаемся получить внешний IP
        try:
            external_ip = requests.get('https://api.ipify.org', timeout=5).text
            print(f"🌍 Внешний IP: {external_ip}")
        except:
            print("🌍 Внешний IP: Не удалось определить")

    except Exception as e:
        print(f"❌ Ошибка получения сетевой информации: {e}")


if __name__ == '__main__':
    get_network_info()
    print("\n" + "=" * 50)
    check_access()