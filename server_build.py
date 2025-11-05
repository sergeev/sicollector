import PyInstaller.__main__

PyInstaller.__main__.run([
    'server.py',
    '--onefile',
    '--name=SystemInfoServer',
    '--add-data=templates;templates',
    '--hidden-import=flask',
    '--clean'
])