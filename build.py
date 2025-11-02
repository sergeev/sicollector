import PyInstaller.__main__
import os
import sys


def build_exe():
    script_name = "system_info_gui.py"
    app_name = "SystemInfoCollector"

    params = [
        script_name,
        '--onefile',
        '--windowed',
        f'--name={app_name}',
        '--clean',
        '--noconfirm',
    ]

    # Добавляем иконку если она существует
    if os.path.exists("icon.ico"):
        params.append('--icon=icon.ico')

    print(f"Building {app_name}.exe...")
    PyInstaller.__main__.run(params)


if __name__ == '__main__':
    build_exe()