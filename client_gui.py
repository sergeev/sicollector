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


class SystemInfoCollector:
    def __init__(self, root):
        self.root = root
        self.root.title("System Information Collector v2.0")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        # Настройки сервера
        self.server_url = "http://localhost:5000"

        # Переменные для хранения данных
        self.system_data = {}
        self.device_id = ""

        self.setup_ui()

    def setup_ui(self):
        # Основной фрейм
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Заголовок
        title_label = ttk.Label(main_frame, text="System Information Collector v2.0",
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

        # Фрейм для кнопок
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=(0, 15), sticky=(tk.W, tk.E))

        # Кнопка сканирования
        self.scan_button = ttk.Button(button_frame, text="🔍 Сканировать систему",
                                      command=self.scan_system)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))

        # Кнопка сохранения в файл
        self.save_button = ttk.Button(button_frame, text="💾 Сохранить в файл",
                                      command=self.save_to_file,
                                      state="disabled")
        self.save_button.pack(side=tk.LEFT, padx=(0, 10))

        # Кнопка отправки на сервер
        self.send_button = ttk.Button(button_frame, text="📡 Отправить на сервер",
                                      command=self.send_to_server,
                                      state="disabled")
        self.send_button.pack(side=tk.LEFT, padx=(0, 10))

        # Метка статуса
        self.status_label = ttk.Label(button_frame, text="Готов к сканированию")
        self.status_label.pack(side=tk.LEFT, padx=(20, 0))

        # Область для вывода результатов
        results_frame = ttk.LabelFrame(main_frame, text="Результаты сканирования", padding="5")
        results_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        self.results_text = scrolledtext.ScrolledText(results_frame,
                                                      width=80,
                                                      height=25,
                                                      font=("Consolas", 9))
        self.results_text.pack(fill=tk.BOTH, expand=True)

        # Фрейм с информацией
        info_frame = ttk.Frame(main_frame)
        info_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E))

        info_label = ttk.Label(info_frame, text="© System Info Collector v2.0 - Клиент-серверная версия",
                               font=("Arial", 8), foreground="gray")
        info_label.pack(side=tk.RIGHT)

        # Настройка весов для растягивания
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        server_frame.columnconfigure(1, weight=1)

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
        self.send_button.config(state="disabled")
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
                "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            # Форматируем вывод
            output = self.format_output()

            # Выводим результаты
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, output)

            # Активируем кнопки
            self.save_button.config(state="normal")
            self.send_button.config(state="normal")
            self.status_label.config(text="Сканирование завершено успешно!")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка при сканировании: {str(e)}")
            self.status_label.config(text="Ошибка сканирования")
        finally:
            self.scan_button.config(state="normal")

    def format_output(self):
        """Форматирует вывод данных в текстовое поле"""
        output = "=" * 60 + "\n"
        output += "SYSTEM INFORMATION COLLECTOR v2.0\n"
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
        output += "Generated by System Info Collector v2.0\n"

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
            initialfile=f"system_info_{self.device_id}.txt"
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
                response = requests.get(f"{self.server_url}/", timeout=5)
                if response.status_code == 200:
                    self.status_label.config(text="✅ Сервер доступен")
                    messagebox.showinfo("Успех", "Сервер доступен и отвечает!")
                else:
                    self.status_label.config(text="❌ Ошибка подключения")
                    messagebox.showerror("Ошибка", f"Сервер ответил с кодом: {response.status_code}")
            except requests.exceptions.RequestException as e:
                self.status_label.config(text="❌ Ошибка подключения")
                messagebox.showerror("Ошибка", f"Не удалось подключиться к серверу:\n{str(e)}")

        # Запускаем в отдельном потоке чтобы не блокировать UI
        threading.Thread(target=test_connection, daemon=True).start()

    def send_to_server(self):
        """Отправляет данные на сервер"""
        if not self.system_data:
            messagebox.showwarning("Предупреждение", "Сначала выполните сканирование системы!")
            return

        self.server_url = self.server_url_entry.get().strip()
        if not self.server_url:
            messagebox.showwarning("Предупреждение", "Введите URL сервера")
            return

        def send_data():
            try:
                self.status_label.config(text="Отправка данных на сервер...")
                self.send_button.config(state="disabled")

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
                    "python_version": self.system_data["python_version"]
                }

                # Отправляем POST запрос
                response = requests.post(
                    f"{self.server_url}/api/submit",
                    json=data_to_send,
                    timeout=10
                )

                if response.status_code == 200:
                    result = response.json()
                    if result.get('status') == 'success':
                        self.status_label.config(text="✅ Данные успешно отправлены на сервер!")
                        messagebox.showinfo("Успех", "Данные успешно отправлены на сервер!")
                    else:
                        self.status_label.config(text="❌ Ошибка отправки")
                        messagebox.showerror("Ошибка", f"Ошибка сервера: {result.get('error', 'Unknown error')}")
                else:
                    self.status_label.config(text="❌ Ошибка отправки")
                    messagebox.showerror("Ошибка", f"Сервер ответил с кодом: {response.status_code}")

            except requests.exceptions.RequestException as e:
                self.status_label.config(text="❌ Ошибка подключения")
                messagebox.showerror("Ошибка", f"Не удалось отправить данные на сервер:\n{str(e)}")
            except Exception as e:
                self.status_label.config(text="❌ Ошибка отправки")
                messagebox.showerror("Ошибка", f"Произошла непредвиденная ошибка:\n{str(e)}")
            finally:
                self.send_button.config(state="normal")

        # Запускаем в отдельном потоке
        threading.Thread(target=send_data, daemon=True).start()


def main():
    # Проверяем наличие необходимых библиотек
    try:
        import psutil
        import requests
    except ImportError as e:
        print(f"Ошибка: Не установлены необходимые библиотеки: {e}")
        print("Установите их с помощью: pip install -r requirements.txt")
        input("Нажмите Enter для выхода...")
        return

    # Создаем и запускаем приложение
    root = tk.Tk()
    app = SystemInfoCollector(root)
    root.mainloop()


if __name__ == "__main__":
    main()