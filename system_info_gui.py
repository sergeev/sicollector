import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import uuid
import psutil
import subprocess
import platform
import random
import string


class SystemInfoCollector:
    def __init__(self, root):
        self.root = root
        self.root.title("Сборщик системной информации")
        self.root.geometry("600x500")
        self.root.resizable(True, True)

        # Переменные для хранения данных
        self.system_data = {}
        self.device_id = ""

        self.setup_ui()

    def setup_ui(self):
        # Основной фрейм
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Заголовок
        title_label = ttk.Label(main_frame, text="Сборщик системной информации",
                                font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # Кнопка сканирования
        self.scan_button = ttk.Button(main_frame, text="Сканировать систему",
                                      command=self.scan_system)
        self.scan_button.grid(row=1, column=0, columnspan=2, pady=(0, 10))

        # Область для вывода результатов
        results_label = ttk.Label(main_frame, text="Результаты сканирования:",
                                  font=("Arial", 10, "bold"))
        results_label.grid(row=2, column=0, sticky=tk.W, pady=(10, 5))

        self.results_text = scrolledtext.ScrolledText(main_frame,
                                                      width=70,
                                                      height=20,
                                                      font=("Consolas", 9))
        self.results_text.grid(row=3, column=0, columnspan=2, pady=(0, 10))

        # Фрейм для кнопок сохранения
        save_frame = ttk.Frame(main_frame)
        save_frame.grid(row=4, column=0, columnspan=2, pady=10)

        # Кнопка сохранения
        self.save_button = ttk.Button(save_frame, text="Сохранить в файл",
                                      command=self.save_to_file,
                                      state="disabled")
        self.save_button.pack(side=tk.LEFT, padx=(0, 10))

        # Метка статуса
        self.status_label = ttk.Label(save_frame, text="Готов к сканированию")
        self.status_label.pack(side=tk.LEFT)

        # Настройка весов строк и столбцов для растягивания
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)

    def generate_device_id(self):
        """Генерирует случайный ID устройства"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

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
            return "\n  ".join(disk_info) if disk_info else "Не удалось получить информацию о дисках"
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
        self.root.update()

        try:
            # Генерируем ID устройства
            self.device_id = self.generate_device_id()

            # Собираем информацию о системе
            system_info = self.get_system_info()

            # Собираем всю информацию
            self.system_data = {
                "Device ID": self.device_id,
                "OS": system_info["OS"],
                "Computer Name": system_info["Computer Name"],
                "Architecture": system_info["Architecture"],
                "Python Version": system_info["Python Version"],
                "MAC Address": self.get_mac_address(),
                "CPU": self.get_cpu_info(),
                "GPU": self.get_gpu_info(),
                "Total Memory": self.get_memory_info(),
                "Disks": self.get_disk_info()
            }

            # Форматируем вывод
            output = "=== System Information ===\n"
            output += f"Device ID: {self.system_data['Device ID']}\n"
            output += f"OS: {self.system_data['OS']}\n"
            output += f"Computer Name: {self.system_data['Computer Name']}\n"
            output += f"Architecture: {self.system_data['Architecture']}\n"
            output += f"Python Version: {self.system_data['Python Version']}\n\n"

            output += "=== Hardware Information ===\n"
            output += f"MAC Address: {self.system_data['MAC Address']}\n"
            output += f"CPU: {self.system_data['CPU']}\n"
            output += f"GPU: {self.system_data['GPU']}\n"
            output += f"Total Memory: {self.system_data['Total Memory']}\n\n"

            output += "=== Disk Information ===\n"
            output += f"Disks:\n  {self.system_data['Disks']}\n\n"

            output += f"Generated by System Info Collector\n"
            output += f"Scan timestamp: {platform.python_version()}"

            # Выводим результаты
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, output)

            # Активируем кнопку сохранения
            self.save_button.config(state="normal")
            self.status_label.config(text="Сканирование завершено успешно!")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка при сканировании: {str(e)}")
            self.status_label.config(text="Ошибка сканирования")
            self.scan_button.config(state="normal")

    def save_to_file(self):
        """Сохраняет данные в файл"""
        if not self.system_data:
            messagebox.showwarning("Предупреждение", "Сначала выполните сканирование системы!")
            return

        # Диалог выбора файла для сохранения
        filename = filedialog.asksaveasfilename(
            title="Сохранить информацию о системе",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"system_info_{self.device_id}.txt"
        )

        if filename:
            try:
                # Форматируем данные для сохранения
                output = "=== System Information ===\n"
                for key, value in self.system_data.items():
                    if key == "Disks":
                        output += f"\n=== Disk Information ===\n"
                        output += f"Disks:\n  {value}\n"
                    else:
                        if key == "Device ID":
                            output += f"\n=== System Information ===\n"
                        elif key == "MAC Address":
                            output += f"\n=== Hardware Information ===\n"
                        output += f"{key}: {value}\n"

                output += f"\nGenerated by System Info Collector\n"

                # Сохраняем в файл
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(output)

                messagebox.showinfo("Успех", f"Информация сохранена в файл:\n{filename}")
                self.status_label.config(text=f"Сохранено: {filename.split('/')[-1]}")

            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {str(e)}")


def main():
    # Проверяем наличие необходимых библиотек
    try:
        import psutil
    except ImportError:
        print("Ошибка: Не установлена библиотека psutil.")
        print("Установите её с помощью: pip install psutil")
        return

    # Создаем и запускаем приложение
    root = tk.Tk()
    app = SystemInfoCollector(root)
    root.mainloop()


if __name__ == "__main__":
    main()