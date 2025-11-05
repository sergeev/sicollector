# key_generator.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import secrets
import base64
import string
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os


class SecurityKeyGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Генератор ключей безопасности")
        self.root.geometry("800x700")
        self.root.resizable(True, True)
        self.root.configure(bg='#f0f0f0')

        # Стили
        self.setup_styles()
        self.setup_ui()

    def setup_styles(self):
        style = ttk.Style()
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#f0f0f0')
        style.configure('Subtitle.TLabel', font=('Arial', 12, 'bold'), background='#f0f0f0')
        style.configure('Key.TLabel', font=('Consolas', 10), background='#f8f9fa', relief='solid', padding=5)
        style.configure('Success.TButton', font=('Arial', 10, 'bold'), background='#28a745')
        style.configure('Primary.TButton', font=('Arial', 10, 'bold'), background='#007bff')

    def setup_ui(self):
        # Основной фрейм
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Заголовок
        title_label = ttk.Label(main_frame, text="🔐 Генератор ключей безопасности", style='Title.TLabel')
        title_label.pack(pady=(0, 20))

        # Информация о безопасности
        info_frame = ttk.LabelFrame(main_frame, text="ℹ️ Важная информация", padding="15")
        info_frame.pack(fill=tk.X, pady=(0, 20))

        info_text = (
            "Этот инструмент генерирует криптографически безопасные ключи для вашего приложения.\n\n"
            "• SECRET_KEY: используется Flask для защиты сессий\n"
            "• JWT_SECRET_KEY: для подписи JWT токенов\n"
            "• ENCRYPTION_KEY: для шифрования данных Fernet\n\n"
            "⚠️  НИКОГДА не используйте ключи по умолчанию в продакшене!\n"
            "⚠️  Храните ключи в безопасном месте и не коммитьте в Git!"
        )

        info_label = ttk.Label(info_frame, text=info_text, justify=tk.LEFT, background='#fff3cd',
                               font=('Arial', 9), relief='solid', padding=10)
        info_label.pack(fill=tk.X)

        # Фрейм настроек генерации
        settings_frame = ttk.LabelFrame(main_frame, text="⚙️ Настройки генерации", padding="15")
        settings_frame.pack(fill=tk.X, pady=(0, 20))

        # Парольная фраза (опционально)
        ttk.Label(settings_frame, text="Парольная фраза (опционально):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.passphrase_var = tk.StringVar()
        passphrase_entry = ttk.Entry(settings_frame, textvariable=self.passphrase_var, width=50, show="•")
        passphrase_entry.grid(row=0, column=1, padx=(10, 0), sticky=tk.W + tk.E, pady=5)

        # Длина ключей
        ttk.Label(settings_frame, text="Длина SECRET_KEY:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.secret_key_length = tk.IntVar(value=24)
        ttk.Spinbox(settings_frame, from_=16, to=64, textvariable=self.secret_key_length, width=10).grid(row=1,
                                                                                                         column=1,
                                                                                                         sticky=tk.W,
                                                                                                         padx=(10, 0),
                                                                                                         pady=5)

        ttk.Label(settings_frame, text="Длина JWT_SECRET_KEY:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.jwt_key_length = tk.IntVar(value=32)
        ttk.Spinbox(settings_frame, from_=16, to=64, textvariable=self.jwt_key_length, width=10).grid(row=2, column=1,
                                                                                                      sticky=tk.W,
                                                                                                      padx=(10, 0),
                                                                                                      pady=5)

        settings_frame.columnconfigure(1, weight=1)

        # Кнопки генерации
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Button(button_frame, text="🎲 Сгенерировать случайные ключи",
                   command=self.generate_random_keys, style='Primary.TButton').pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(button_frame, text="🔑 Сгенерировать из парольной фразы",
                   command=self.generate_from_passphrase).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(button_frame, text="🔄 Обновить все ключи",
                   command=self.refresh_all_keys).pack(side=tk.LEFT)

        # Область вывода ключей
        keys_frame = ttk.LabelFrame(main_frame, text="🔑 Сгенерированные ключи", padding="15")
        keys_frame.pack(fill=tk.BOTH, expand=True)

        # SECRET_KEY
        ttk.Label(keys_frame, text="SECRET_KEY:", style='Subtitle.TLabel').grid(row=0, column=0, sticky=tk.W,
                                                                                pady=(0, 5))
        self.secret_key_var = tk.StringVar()
        secret_key_entry = ttk.Entry(keys_frame, textvariable=self.secret_key_var, font=('Consolas', 9), width=80)
        secret_key_entry.grid(row=1, column=0, sticky=tk.W + tk.E, pady=(0, 10))
        ttk.Button(keys_frame, text="📋 Копировать",
                   command=lambda: self.copy_to_clipboard(self.secret_key_var.get())).grid(row=1, column=1,
                                                                                           padx=(10, 0))

        # JWT_SECRET_KEY
        ttk.Label(keys_frame, text="JWT_SECRET_KEY:", style='Subtitle.TLabel').grid(row=2, column=0, sticky=tk.W,
                                                                                    pady=(0, 5))
        self.jwt_key_var = tk.StringVar()
        jwt_key_entry = ttk.Entry(keys_frame, textvariable=self.jwt_key_var, font=('Consolas', 9), width=80)
        jwt_key_entry.grid(row=3, column=0, sticky=tk.W + tk.E, pady=(0, 10))
        ttk.Button(keys_frame, text="📋 Копировать",
                   command=lambda: self.copy_to_clipboard(self.jwt_key_var.get())).grid(row=3, column=1, padx=(10, 0))

        # ENCRYPTION_KEY
        ttk.Label(keys_frame, text="ENCRYPTION_KEY:", style='Subtitle.TLabel').grid(row=4, column=0, sticky=tk.W,
                                                                                    pady=(0, 5))
        self.encryption_key_var = tk.StringVar()
        encryption_key_entry = ttk.Entry(keys_frame, textvariable=self.encryption_key_var, font=('Consolas', 9),
                                         width=80)
        encryption_key_entry.grid(row=5, column=0, sticky=tk.W + tk.E, pady=(0, 10))
        ttk.Button(keys_frame, text="📋 Копировать",
                   command=lambda: self.copy_to_clipboard(self.encryption_key_var.get())).grid(row=5, column=1,
                                                                                               padx=(10, 0))

        # Fernet Key (вычисляемый)
        ttk.Label(keys_frame, text="Fernet Key (вычисляется из ENCRYPTION_KEY):", style='Subtitle.TLabel').grid(row=6,
                                                                                                                column=0,
                                                                                                                sticky=tk.W,
                                                                                                                pady=(
                                                                                                                0, 5))
        self.fernet_key_var = tk.StringVar()
        fernet_key_entry = ttk.Entry(keys_frame, textvariable=self.fernet_key_var, font=('Consolas', 9), width=80)
        fernet_key_entry.grid(row=7, column=0, sticky=tk.W + tk.E, pady=(0, 10))
        ttk.Button(keys_frame, text="📋 Копировать",
                   command=lambda: self.copy_to_clipboard(self.fernet_key_var.get())).grid(row=7, column=1,
                                                                                           padx=(10, 0))

        keys_frame.columnconfigure(0, weight=1)

        # Кнопки экспорта
        export_frame = ttk.Frame(main_frame)
        export_frame.pack(fill=tk.X, pady=(20, 0))

        ttk.Button(export_frame, text="💾 Экспорт в .env файл",
                   command=self.export_to_env, style='Success.TButton').pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(export_frame, text="📄 Показать конфигурацию Python",
                   command=self.show_python_config).pack(side=tk.LEFT)

        # Генерируем начальные ключи
        self.generate_random_keys()

    def generate_secure_random(self, length):
        """Генерация криптографически безопасной случайной строки"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def derive_key_from_passphrase(self, passphrase, salt=None, length=32):
        """Производный ключ из парольной фразы"""
        if salt is None:
            salt = secrets.token_bytes(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        return key.decode('utf-8')

    def generate_random_keys(self):
        """Генерация полностью случайных ключей"""
        try:
            # SECRET_KEY
            secret_key = self.generate_secure_random(self.secret_key_length.get())
            self.secret_key_var.set(secret_key)

            # JWT_SECRET_KEY
            jwt_key = self.generate_secure_random(self.jwt_key_length.get())
            self.jwt_key_var.set(jwt_key)

            # ENCRYPTION_KEY (32 bytes для Fernet)
            encryption_key = self.generate_secure_random(32)
            self.encryption_key_var.set(encryption_key)

            # Вычисляем Fernet key
            self.update_fernet_key()

            messagebox.showinfo("Успех", "Ключи сгенерированы успешно!")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка генерации ключей: {str(e)}")

    def generate_from_passphrase(self):
        """Генерация ключей на основе парольной фразы"""
        passphrase = self.passphrase_var.get().strip()

        if not passphrase:
            messagebox.showwarning("Предупреждение", "Введите парольную фразу")
            return

        try:
            # SECRET_KEY
            secret_key = self.derive_key_from_passphrase(passphrase, length=self.secret_key_length.get())
            self.secret_key_var.set(secret_key[:self.secret_key_length.get()])

            # JWT_SECRET_KEY
            jwt_salt = secrets.token_bytes(16)
            jwt_key = self.derive_key_from_passphrase(passphrase + "JWT", salt=jwt_salt,
                                                      length=self.jwt_key_length.get())
            self.jwt_key_var.set(jwt_key[:self.jwt_key_length.get()])

            # ENCRYPTION_KEY
            encryption_salt = secrets.token_bytes(16)
            encryption_key = self.derive_key_from_passphrase(passphrase + "ENC", salt=encryption_salt, length=32)
            self.encryption_key_var.set(encryption_key)

            # Вычисляем Fernet key
            self.update_fernet_key()

            messagebox.showinfo("Успех", "Ключи сгенерированы из парольной фразы!")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка генерации ключей: {str(e)}")

    def update_fernet_key(self):
        """Обновление Fernet key на основе ENCRYPTION_KEY"""
        try:
            encryption_key = self.encryption_key_var.get()
            if encryption_key:
                # Используем тот же алгоритм что и в config.py
                import hashlib
                fernet_key = base64.urlsafe_b64encode(
                    hashlib.sha256(encryption_key.encode()).digest()
                ).decode('utf-8')
                self.fernet_key_var.set(fernet_key)
        except Exception as e:
            self.fernet_key_var.set(f"Ошибка вычисления: {str(e)}")

    def refresh_all_keys(self):
        """Обновление всех ключей"""
        self.generate_random_keys()

    def copy_to_clipboard(self, text):
        """Копирование текста в буфер обмена"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Успех", "Ключ скопирован в буфер обмена!")

    def export_to_env(self):
        """Экспорт ключей в .env файл"""
        if not all([self.secret_key_var.get(), self.jwt_key_var.get(), self.encryption_key_var.get()]):
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте ключи")
            return

        env_content = f"""# Файл окружения для Secure System Info Collector
# Сгенерировано: {self.get_current_timestamp()}

# Безопасность - НИКОГДА не используйте значения по умолчанию в продакшене!
SECRET_KEY={self.secret_key_var.get()}
JWT_SECRET_KEY={self.jwt_key_var.get()}
ENCRYPTION_KEY={self.encryption_key_var.get()}

# Настройки сервера
SERVER_HOST=localhost
SERVER_PORT=5000

# Дополнительные настройки
DEBUG=False
"""

        # Показываем содержимое и предлагаем сохранить
        self.show_export_dialog(env_content, "environment file (.env)", "environment.env")

    def show_python_config(self):
        """Показать конфигурацию Python"""
        if not all([self.secret_key_var.get(), self.jwt_key_var.get(), self.encryption_key_var.get()]):
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте ключи")
            return

        python_config = f'''# Конфигурация безопасности для config.py
# Сгенерировано: {self.get_current_timestamp()}

import os

class Config:
    """Общая конфигурация для клиента и сервера"""

    # Безопасность
    SECRET_KEY = '{self.secret_key_var.get()}'
    JWT_SECRET_KEY = '{self.jwt_key_var.get()}'
    ENCRYPTION_KEY = '{self.encryption_key_var.get()}'

    # Настройки сервера
    SERVER_HOST = os.environ.get('SERVER_HOST', 'localhost')
    SERVER_PORT = os.environ.get('SERVER_PORT', '5000')
    SERVER_URL = f"http://{{SERVER_HOST}}:{{SERVER_PORT}}"

    # Настройки базы данных
    DATA_DIR = "collected_data"
    DB_NAME = "devices.db"

    # JWT настройки
    JWT_ACCESS_TOKEN_EXPIRES_HOURS = 24

    # Flask-Login настройки
    SESSION_PROTECTION = 'strong'
    REMEMBER_COOKIE_DURATION = 3600

    @classmethod
    def get_fernet_key(cls):
        import base64
        import hashlib
        return base64.urlsafe_b64encode(
            hashlib.sha256(cls.ENCRYPTION_KEY.encode()).digest()
        )

    @classmethod
    def get_fernet(cls):
        from cryptography.fernet import Fernet
        return Fernet(cls.get_fernet_key())
'''

        self.show_export_dialog(python_config, "Python configuration", "security_config.py")

    def show_export_dialog(self, content, file_type, default_filename):
        """Показать диалог экспорта"""
        # Создаем новое окно для предпросмотра
        preview_window = tk.Toplevel(self.root)
        preview_window.title(f"Экспорт {file_type}")
        preview_window.geometry("700x500")
        preview_window.transient(self.root)
        preview_window.grab_set()

        ttk.Label(preview_window, text=f"Содержимое {file_type}:").pack(anchor=tk.W, padx=20, pady=(20, 5))

        text_widget = scrolledtext.ScrolledText(preview_window, wrap=tk.WORD, width=80, height=20)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        text_widget.insert(1.0, content)
        text_widget.config(state=tk.DISABLED)

        button_frame = ttk.Frame(preview_window)
        button_frame.pack(fill=tk.X, padx=20, pady=10)

        def save_file():
            filename = tk.filedialog.asksaveasfilename(
                title=f"Сохранить {file_type}",
                defaultextension=".env" if file_type == "environment file (.env)" else ".py",
                filetypes=[("All files", "*.*")],
                initialfile=default_filename
            )
            if filename:
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(content)
                    messagebox.showinfo("Успех", f"Файл сохранен: {filename}")
                    preview_window.destroy()
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Ошибка сохранения: {str(e)}")

        def copy_content():
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            messagebox.showinfo("Успех", "Содержимое скопировано в буфер обмена!")

        ttk.Button(button_frame, text="💾 Сохранить в файл",
                   command=save_file, style='Success.TButton').pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(button_frame, text="📋 Копировать содержимое",
                   command=copy_content).pack(side=tk.LEFT)

        ttk.Button(button_frame, text="Закрыть",
                   command=preview_window.destroy).pack(side=tk.RIGHT)

    def get_current_timestamp(self):
        """Получить текущую метку времени"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def main():
    """Основная функция запуска приложения"""
    try:
        # Проверяем наличие необходимых библиотек
        import secrets
        import base64
        import hashlib
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        root = tk.Tk()
        app = SecurityKeyGenerator(root)
        root.mainloop()

    except ImportError as e:
        print(f"Ошибка: Не установлены необходимые библиотеки: {e}")
        print("Установите их с помощью: pip install cryptography")
        input("Нажмите Enter для выхода...")


if __name__ == "__main__":
    main()