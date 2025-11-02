import PyInstaller.__main__

PyInstaller.__main__.run([
    'client_gui.py',
    '--onefile',
    '--windowed',
    '--name=SystemInfoClient',
    '--hidden-import=psutil',
    '--hidden-import=requests',
    '--clean'
])