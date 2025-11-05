## 📋 Инструкция по использованию:
## Для всех платформ:
Установите зависимости:

``` bash
pip install -r requirements_keygen.txt
```
## или
``` bash
python install_keygen_deps.py
```
## Запустите сборку для вашей платформы:

## Универсальный сборщик (автоопределение платформы)
```bash 
python build_keygen_all.py
```
## Или конкретный сборщик:
```bash
python build_keygen_windows.py
python build_keygen_macos.py  
python build_keygen_linux.py
```

## Особенности для каждой платформы:
- Windows: Создает .exe файл
- macOS: Создает .app bundle + опционально .dmg
- Linux: Создает исполняемый файл + опционально AppImage

## 📁 Структура после сборки:
```code
 dist/
├── SecurityKeyGenerator.exe      # Windows
├── SecurityKeyGenerator.app/     # macOS  
└── SecurityKeyGenerator          # Linux
```
