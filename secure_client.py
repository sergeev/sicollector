import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import uuid
import psutil
import subprocess
import platform
import random
import string
from datetime import datetime
import requests
import json
import threading
import logging

from config import Config

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecureSystemInfoCollector:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure System Information Collector")
        self.root.geometry("800x700")
        self.root.resizable(True, True)

        # Настройки сервера
        self.server_url = Config.SERVER_URL
        self.jwt_token = None
        self.current_user = None

        # Инициализация Fernet для шифрования
        self.fernet = Config.get_fernet()

        # Переменные для хранения данных
        self.system_data = {}
        self.device_id = ""

        self.setup_ui()

    def setup_ui(self):
        # Основной фрейм
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Заголовок
        title_label = ttk.Label(main_frame, text="🔒 Secure System Information Collector",
                                font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # Фрейм настроек сервера
        server_frame = ttk.LabelFrame(main_frame, text="Настройки сервера", padding="10")
        server_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))

        ttk.Label(server_frame, text="URL сервера:").grid(row=0, column=0, sticky=tk.W)
        self.server_url_entry = ttk.Entry(server_frame, width=50)
        self.server_url_entry.insert(0, self.server_url)
        self.server_url_entry.grid(row=0, column=1, padx=(10, 0), sticky=(tk.W, tk.E))

        test_server_btn = ttk.Button(server_frame, text="Тест подключения",
                                     command=self.test_server_connection)
        test_server_btn.grid(row=0, column=2, padx=(10, 0))

        # Фрейм аутентификации
        auth_frame = ttk.LabelFrame(main_frame, text="🔐 Аутентификация", padding="10")
        auth_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))

        ttk.Label(auth_frame, text="Логин:").grid(row=0, column=0, sticky=tk.W)
        self.username_entry = ttk.Entry(auth_frame, width=20)
        self.username_entry.insert(0, "admin")
        self.username_entry.grid(row=0, column=1, padx=(10, 0), sticky=(tk.W, tk.E))

        ttk.Label(auth_frame, text="Пароль:").grid(row=0, column=2, padx=(20, 0), sticky=tk.W)
        self.password_entry = ttk.Entry(auth_frame, width=20, show="*")
        self.password_entry.insert(0, "admin123")
        self.password_entry.grid(row=0, column=3, padx=(10, 0), sticky=(tk.W, tk.E))

        login_btn = ttk.Button(auth_frame, text="Войти",
                               command=self.login)
        login_btn.grid(row=0, column=4, padx=(10, 0))

        self.auth_status_label = ttk.Label(auth_frame, text="❌ Не авторизован", foreground="red")
        self.auth_status_label.grid(row=0, column=5, padx=(10, 0))

        # Фрейм для кнопок
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=(0, 15), sticky=(tk.W, tk.E))

        # Кнопка сканирования
        self.scan_button = ttk.Button(button_frame, text="🔍 Сканировать систему",
                                      command=self.scan_system)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))

        # Кнопка сохранения в файл
        self.save_button = ttk.Button(button_frame, text="💾 Сохранить в файл",
                                      command=self.save_to_file,
                                      state="disabled")
        self.save_button.pack(side=tk.LEFT, padx=(0, 10))

        # Кнопка безопасной отправки
        self.secure_send_button = ttk.Button(button_frame, text="🚀 Безопасная отправка",
                                             command=self.secure_send_to_server,
                                             state="disabled")
        self.secure_send_button.pack(side=tk.LEFT, padx=(0, 10))

        # Кнопка теста шифрования
        self.test_encryption_btn = ttk.Button(button_frame, text="🔐 Тест шифрования",
                                              command=self.test_encryption)
        self.test_encryption_btn.pack(side=tk.LEFT, padx=(0, 10))

        # Метка статуса
        self.status_label = ttk.Label(button_frame, text="Готов к сканированию")
        self.status_label.pack(side=tk.LEFT, padx=(20, 0))

        # Область для вывода результатов
        results_frame = ttk.LabelFrame(main_frame, text="Результаты сканирования", padding="5")
        results_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        self.results_text = scrolledtext.ScrolledText(results_frame,
                                                      width=80,
                                                      height=25,
                                                      font=("Consolas", 9))
        self.results_text.pack(fill=tk.BOTH, expand=True)

        # Фрейм с информацией
        info_frame = ttk.Frame(main_frame)
        info_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E))

        user_info = f"Пользователь: {self.current_user}" if self.current_user else "Не авторизован"
        info_label = ttk.Label(info_frame,
                               text=f"© Secure System Info Collector | {user_info}",
                               font=("Arial", 8), foreground="gray")
        info_label.pack(side=tk.RIGHT)

        # Настройка весов для растягивания
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        server_frame.columnconfigure(1, weight=1)
        auth_frame.columnconfigure(1, weight=1)
        auth_frame.columnconfigure(3, weight=1)

    def encrypt_data(self, data):
        """Шифрование данных перед отправкой"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            encrypted = self.fernet.encrypt(data)
            return encrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise

    def decrypt_data(self, encrypted_data):
        """Дешифрование данных (для получения ответов)"""
        try:
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode('utf-8')
            decrypted = self.fernet.decrypt(encrypted_data)
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise

    def generate_device_id(self):
        """Генерирует случайный ID устройства"""
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    def get_mac_address(self):
        """Получает MAC-адрес основного сетевого интерфейса"""
        try:
            mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
            return ':'.join([mac[i:i + 2] for i in range(0, 12, 2)])
        except:
            return "Не удалось получить MAC-адрес"

    def get_cpu_info(self):
        """Получает информацию о процессоре"""
        try:
            if platform.system() == "Windows":
                return platform.processor()
            elif platform.system() == "Linux":
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if line.strip() and line.startswith('model name'):
                            return line.split(':')[1].strip()
            elif platform.system() == "Darwin":  # macOS
                cmd = ['sysctl', '-n', 'machdep.cpu.brand_string']
                return subprocess.check_output(cmd).decode().strip()
            return platform.processor()
        except:
            return "Не удалось получить информацию о процессоре"

    def get_gpu_info(self):
        """Получает информацию о GPU"""
        try:
            if platform.system() == "Windows":
                cmd = ['wmic', 'path', 'win32_VideoController', 'get', 'name']
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
                gpus = [line.strip() for line in output.decode('utf-8', errors='ignore').split('\n') if line.strip()]
                return ', '.join(gpus[1:]) if len(gpus) > 1 else "Не найдено"
            elif platform.system() == "Linux":
                try:
                    cmd = "lspci | grep -i vga"
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
                    gpus = [line.split(': ')[-1].strip() for line in output.decode('utf-8').split('\n') if line.strip()]
                    return ', '.join(gpus)
                except:
                    return "lspci не доступен"
            elif platform.system() == "Darwin":  # macOS
                cmd = "system_profiler SPDisplaysDataType | grep -i chipset"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
                return output.decode('utf-8').strip()
            else:
                return "Не поддерживается для данной ОС"
        except Exception as e:
            return f"Не удалось получить информацию: {str(e)}"

    def get_memory_info(self):
        """Получает информацию об оперативной памяти в ГБ"""
        try:
            mem = psutil.virtual_memory()
            return f"{mem.total / (1024 ** 3):.2f} GB"
        except:
            return "Не удалось получить информацию о памяти"

    def get_disk_info(self):
        """Получает информацию о дисках"""
        try:
            partitions = psutil.disk_partitions()
            disk_info = []
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info.append(
                        f"{partition.device} ({partition.mountpoint}) - {usage.total / (1024 ** 3):.1f} GB")
                except:
                    continue
            return "\n".join(disk_info) if disk_info else "Не удалось получить информацию о дисках"
        except:
            return "Не удалось получить информацию о дисках"

    def get_system_info(self):
        """Получает основную информацию о системе"""
        return {
            "OS": f"{platform.system()} {platform.release()}",
            "Computer Name": platform.node(),
            "Architecture": platform.architecture()[0],
            "Python Version": platform.python_version()
        }

    def scan_system(self):
        """Выполняет сканирование системы"""
        self.status_label.config(text="Сканирование...")
        self.scan_button.config(state="disabled")
        self.save_button.config(state="disabled")
        self.secure_send_button.config(state="disabled")
        self.root.update()

        try:
            # Генерируем ID устройства
            self.device_id = self.generate_device_id()

            # Собираем информацию о системе
            system_info = self.get_system_info()

            # Собираем всю информацию
            self.system_data = {
                "device_id": self.device_id,
                "os_info": system_info["OS"],
                "computer_name": system_info["Computer Name"],
                "architecture": system_info["Architecture"],
                "python_version": system_info["Python Version"],
                "mac_address": self.get_mac_address(),
                "cpu_info": self.get_cpu_info(),
                "gpu_info": self.get_gpu_info(),
                "memory_info": self.get_memory_info(),
                "disk_info": self.get_disk_info(),
                "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "client_version": "Secure Client v1.0"
            }

            # Форматируем вывод
            output = self.format_output()

            # Выводим результаты
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, output)

            # Активируем кнопки
            self.save_button.config(state="normal")
            if self.jwt_token:
                self.secure_send_button.config(state="normal")
            self.status_label.config(text="Сканирование завершено успешно!")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка при сканировании: {str(e)}")
            self.status_label.config(text="Ошибка сканирования")
        finally:
            self.scan_button.config(state="normal")

    def format_output(self):
        """Форматирует вывод данных в текстовое поле"""
        output = "=" * 60 + "\n"
        output += "🔒 SECURE SYSTEM INFORMATION COLLECTOR\n"
        output += "=" * 60 + "\n\n"

        output += "▸ ОС И СИСТЕМА:\n"
        output += "  • Device ID:      {}\n".format(self.system_data['device_id'])
        output += "  • OS:             {}\n".format(self.system_data['os_info'])
        output += "  • Computer Name:  {}\n".format(self.system_data['computer_name'])
        output += "  • Architecture:   {}\n".format(self.system_data['architecture'])
        output += "  • Python Version: {}\n".format(self.system_data['python_version'])
        output += "  • Scan Time:      {}\n".format(self.system_data['scan_timestamp'])

        output += "\n▸ АППАРАТНОЕ ОБЕСПЕЧЕНИЕ:\n"
        output += "  • MAC Address:    {}\n".format(self.system_data['mac_address'])
        output += "  • CPU:            {}\n".format(self.system_data['cpu_info'])
        output += "  • GPU:            {}\n".format(self.system_data['gpu_info'])
        output += "  • Total Memory:   {}\n".format(self.system_data['memory_info'])

        output += "\n▸ ДИСКИ:\n"
        disks = self.system_data['disk_info'].split('\n')
        for disk in disks:
            output += "  • {}\n".format(disk)

        output += "\n" + "=" * 60 + "\n"
        output += "Generated by Secure System Info Collector\n"
        output += f"User: {self.current_user or 'Not authenticated'}\n"

        return output

    def save_to_file(self):
        """Сохраняет данные в файл"""
        if not self.system_data:
            messagebox.showwarning("Предупреждение", "Сначала выполните сканирование системы!")
            return

        filename = filedialog.asksaveasfilename(
            title="Сохранить информацию о системе",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"secure_system_info_{self.device_id}.txt"
        )

        if filename:
            try:
                output = self.format_output()
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(output)
                messagebox.showinfo("Успех", f"Информация сохранена в файл:\n{filename}")
                self.status_label.config(text=f"Сохранено: {filename.split('/')[-1]}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {str(e)}")

    def test_server_connection(self):
        """Тестирует подключение к серверу"""
        self.server_url = self.server_url_entry.get().strip()
        if not self.server_url:
            messagebox.showwarning("Предупреждение", "Введите URL сервера")
            return

        def test_connection():
            try:
                self.status_label.config(text="Тестирование подключения...")
                response = requests.get(f"{self.server_url}/health", timeout=5)
                if response.status_code == 200:
                    health_data = response.json()
                    self.status_label.config(text="✅ Сервер доступен")
                    messagebox.showinfo("Успех",
                                        f"Сервер доступен и отвечает!\n"
                                        f"Статус: {health_data.get('status', 'Unknown')}\n"
                                        f"База данных: {health_data.get('database', 'Unknown')}\n"
                                        f"Шифрование: {health_data.get('encryption', 'Unknown')}")
                else:
                    self.status_label.config(text="❌ Ошибка подключения")
                    messagebox.showerror("Ошибка", f"Сервер ответил с кодом: {response.status_code}")
            except requests.exceptions.RequestException as e:
                self.status_label.config(text="❌ Ошибка подключения")
                messagebox.showerror("Ошибка", f"Не удалось подключиться к серверу:\n{str(e)}")

        threading.Thread(target=test_connection, daemon=True).start()

    def login(self):
        """Аутентификация на сервере"""
        self.server_url = self.server_url_entry.get().strip()
        if not self.server_url:
            messagebox.showwarning("Предупреждение", "Введите URL сервера")
            return

        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showwarning("Предупреждение", "Введите логин и пароль")
            return

        def do_login():
            try:
                self.status_label.config(text="Аутентификация...")

                # Отправляем запрос на аутентификацию
                response = requests.post(
                    f"{self.server_url}/api/auth/login",
                    json={'username': username, 'password': password},
                    timeout=10
                )

                if response.status_code == 200:
                    result = response.json()
                    self.jwt_token = result.get('access_token')
                    self.current_user = result.get('username')
                    self.auth_status_label.config(text=f"✅ {self.current_user}", foreground="green")
                    self.status_label.config(text="Аутентификация успешна!")

                    # Обновляем информацию в интерфейсе
                    self.update_user_info()

                    # Активируем кнопку отправки если есть данные
                    if self.system_data:
                        self.secure_send_button.config(state="normal")

                    messagebox.showinfo("Успех", "Аутентификация прошла успешно!")

                else:
                    self.auth_status_label.config(text="❌ Ошибка авторизации", foreground="red")
                    self.status_label.config(text="Ошибка аутентификации")
                    messagebox.showerror("Ошибка",
                                         f"Ошибка аутентификации: {response.json().get('error', 'Unknown error')}")

            except requests.exceptions.RequestException as e:
                self.auth_status_label.config(text="❌ Ошибка подключения", foreground="red")
                self.status_label.config(text="Ошибка подключения")
                messagebox.showerror("Ошибка", f"Не удалось подключиться к серверу:\n{str(e)}")
            except Exception as e:
                self.auth_status_label.config(text="❌ Ошибка", foreground="red")
                self.status_label.config(text="Ошибка аутентификации")
                messagebox.showerror("Ошибка", f"Произошла непредвиденная ошибка:\n{str(e)}")

        threading.Thread(target=do_login, daemon=True).start()

    def update_user_info(self):
        """Обновляет информацию о пользователе в интерфейсе"""
        for widget in self.root.grid_slaves(row=5):
            if isinstance(widget, ttk.Frame):
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Label) and "©" in child.cget("text"):
                        user_info = f"Пользователь: {self.current_user}" if self.current_user else "Не авторизован"
                        child.config(text=f"© Secure System Info Collector | {user_info}")

    def test_encryption(self):
        """Тестирует шифрование с сервером"""
        self.server_url = self.server_url_entry.get().strip()
        if not self.server_url:
            messagebox.showwarning("Предупреждение", "Введите URL сервера")
            return

        def do_test():
            try:
                self.status_label.config(text="Тестирование шифрования...")

                response = requests.post(
                    f"{self.server_url}/api/test/encryption",
                    timeout=10
                )

                if response.status_code == 200:
                    result = response.json()
                    if result.get('success'):
                        self.status_label.config(text="✅ Шифрование работает корректно")
                        messagebox.showinfo("Успех",
                                            "Шифрование настроено корректно!\n\n"
                                            "Клиент и сервер используют одинаковые ключи.")
                    else:
                        self.status_label.config(text="❌ Ошибка шифрования")
                        messagebox.showerror("Ошибка", f"Ошибка шифрования: {result.get('error', 'Unknown error')}")
                else:
                    self.status_label.config(text="❌ Ошибка теста")
                    messagebox.showerror("Ошибка", f"Сервер ответил с кодом: {response.status_code}")

            except requests.exceptions.RequestException as e:
                self.status_label.config(text="❌ Ошибка подключения")
                messagebox.showerror("Ошибка", f"Не удалось подключиться к серверу:\n{str(e)}")
            except Exception as e:
                self.status_label.config(text="❌ Ошибка теста")
                messagebox.showerror("Ошибка", f"Произошла непредвиденная ошибка:\n{str(e)}")

        threading.Thread(target=do_test, daemon=True).start()

    def secure_send_to_server(self):
        """Безопасная отправка данных на сервер с шифрованием"""
        if not self.system_data:
            messagebox.showwarning("Предупреждение", "Сначала выполните сканирование системы!")
            return

        if not self.jwt_token:
            messagebox.showwarning("Предупреждение", "Сначала выполните аутентификацию!")
            return

        self.server_url = self.server_url_entry.get().strip()
        if not self.server_url:
            messagebox.showwarning("Предупреждение", "Введите URL сервера")
            return

        def send_data():
            try:
                self.status_label.config(text="🔒 Шифрование и отправка данных...")
                self.secure_send_button.config(state="disabled")

                # Подготавливаем данные для отправки
                data_to_send = {
                    "device_id": self.system_data["device_id"],
                    "computer_name": self.system_data["computer_name"],
                    "mac_address": self.system_data["mac_address"],
                    "cpu_info": self.system_data["cpu_info"],
                    "gpu_info": self.system_data["gpu_info"],
                    "memory_info": self.system_data["memory_info"],
                    "disk_info": self.system_data["disk_info"],
                    "os_info": self.system_data["os_info"],
                    "architecture": self.system_data["architecture"],
                    "python_version": self.system_data["python_version"],
                    "client_version": self.system_data["client_version"]
                }

                logger.info(f"Preparing to send data for device: {data_to_send['device_id']}")

                # Шифруем данные
                json_data = json.dumps(data_to_send, ensure_ascii=False)
                logger.info(f"JSON data length: {len(json_data)}")

                encrypted_data = self.encrypt_data(json_data)
                logger.info(f"Encrypted data length: {len(encrypted_data)}")

                # Отправляем POST запрос с JWT токеном и зашифрованными данными
                response = requests.post(
                    f"{self.server_url}/api/secure/submit",
                    data=encrypted_data,
                    headers={
                        'Content-Type': 'text/plain',
                        'Authorization': f'Bearer {self.jwt_token}'
                    },
                    timeout=15
                )

                if response.status_code == 200:
                    result = response.json()
                    if result.get('status') == 'success':
                        self.status_label.config(text="✅ Данные успешно отправлены и сохранены!")
                        messagebox.showinfo("Успех",
                                            f"Данные успешно отправлены на сервер!\n"
                                            f"Принято пользователем: {result.get('received_by', 'Unknown')}")
                    else:
                        self.status_label.config(text="❌ Ошибка отправки")
                        messagebox.showerror("Ошибка", f"Ошибка сервера: {result.get('error', 'Unknown error')}")
                else:
                    self.status_label.config(text="❌ Ошибка отправки")
                    error_msg = response.json().get('error', 'Unknown error')
                    messagebox.showerror("Ошибка", f"Сервер ответил с кодом {response.status_code}: {error_msg}")

            except requests.exceptions.RequestException as e:
                self.status_label.config(text="❌ Ошибка подключения")
                messagebox.showerror("Ошибка", f"Не удалось отправить данные на сервер:\n{str(e)}")
            except Exception as e:
                self.status_label.config(text="❌ Ошибка отправки")
                messagebox.showerror("Ошибка", f"Произошла непредвиденная ошибка:\n{str(e)}")
            finally:
                self.secure_send_button.config(state="normal")

        threading.Thread(target=send_data, daemon=True).start()


def main():
    # Проверяем наличие необходимых библиотек
    try:
        import psutil
        import requests
        from cryptography.fernet import Fernet
    except ImportError as e:
        print(f"Ошибка: Не установлены необходимые библиотеки: {e}")
        print("Установите их с помощью: pip install -r requirements.txt")
        input("Нажмите Enter для выхода...")
        return

    # Создаем и запускаем приложение
    root = tk.Tk()
    app = SecureSystemInfoCollector(root)
    root.mainloop()


if __name__ == "__main__":
    main()