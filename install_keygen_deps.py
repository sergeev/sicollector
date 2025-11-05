# install_keygen_deps.py
import subprocess
import sys
import os


def install_requirements():
    """Установка необходимых зависимостей"""
    requirements = [
        'cryptography>=41.0.0',
        'pyinstaller>=5.0.0'
    ]

    print("📦 Установка зависимостей для Key Generator...")

    for package in requirements:
        try:
            print(f"⬇️  Установка {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"✅ {package} установлен успешно")
        except subprocess.CalledProcessError as e:
            print(f"❌ Ошибка установки {package}: {e}")
            return False

    print("🎉 Все зависимости установлены успешно!")
    return True


def check_dependencies():
    """Проверка установленных зависимостей"""
    required_packages = {
        'cryptography': 'cryptography',
        'pyinstaller': 'PyInstaller'
    }

    missing = []
    for import_name, package_name in required_packages.items():
        try:
            __import__(import_name)
            print(f"✅ {package_name} обнаружен")
        except ImportError:
            print(f"❌ {package_name} не найден")
            missing.append(package_name)

    return missing


if __name__ == '__main__':
    print("🔍 Проверка зависимостей...")
    missing_packages = check_dependencies()

    if missing_packages:
        print(f"\n❌ Отсутствуют пакеты: {', '.join(missing_packages)}")
        response = input("Установить автоматически? (y/N): ")
        if response.lower() in ['y', 'yes', 'д', 'да']:
            install_requirements()
    else:
        print("\n🎉 Все зависимости установлены!")