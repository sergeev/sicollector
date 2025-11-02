# Сборщик системной информации

Программа для сбора информации о системе с графическим интерфейсом.

## Возможности

- Сканирование аппаратных характеристик компьютера
- Определение MAC-адреса, CPU, GPU, памяти и дисков
- Сохранение результатов в текстовый файл
- Простой графический интерфейс
- Поддержка MacOS/Windows/Linux
# Запуск в сыром виде
```bash
python system_info_gui.py    
```
# Пошаговая инструкция сборки:

#### 1 Установите необходимые библиотеки:
``` bash 
pip install -r requirements.txt
```
#### 2 Сохраните код программы в файл system_info_gui.py

#### 3 Создайте файл сборки build.py (код выше)

#### 4 Выполните сборку:
```bash
python build.py
```
#### Или вручную через PyInstaller:
```bash
pyinstaller --onefile --windowed --name=SystemInfoCollector --clean system_info_gui.py 
```

#### 5 EXE-файл будет создан в папке dist/SystemInfoCollector.exe
