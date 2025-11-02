# build.py - Скрипт для сборки EXE-файла
import PyInstaller.__main__
import os


def build_exe():
    # Параметры для PyInstaller
    params = [
        'system_info_gui.py',  # основной файл программы
        '--onefile',  # создать один исполняемый файл
        '--windowed',  # скрыть консоль (оконное приложение)
        '--name=SystemInfoCollector',  # имя исполняемого файла
        '--icon=icon.ico',  # иконка (опционально)
        '--add-data=tcl;tcl',  # для корректной работы Tkinter
        '--add-data=tk;tk',
        '--clean',  # очистка временных файлов
    ]

    PyInstaller.__main__.run(params)


if __name__ == '__main__':
    build_exe()