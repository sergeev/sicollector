#!/usr/bin/env python3
"""
Скрипт для проверки и восстановления базы данных
"""

import os
import sqlite3
import sys
from secure_server import init_database, DB_PATH, DATA_DIR


def check_database():
    """Проверка состояния базы данных"""
    print(f"Checking database at: {DB_PATH}")

    if not os.path.exists(DB_PATH):
        print("❌ Database file does not exist")
        return False

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Проверяем существование таблиц
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()

        table_names = [table[0] for table in tables]
        print(f"Found tables: {table_names}")

        required_tables = ['devices', 'users']
        missing_tables = [table for table in required_tables if table not in table_names]

        if missing_tables:
            print(f"❌ Missing tables: {missing_tables}")
            return False

        # Проверяем данные в таблице users
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        print(f"Users in database: {user_count}")

        conn.close()
        print("✅ Database is healthy")
        return True

    except Exception as e:
        print(f"❌ Database check failed: {e}")
        return False


def repair_database():
    """Восстановление базы данных"""
    print("Repairing database...")

    try:
        # Переименовываем старую базу (если существует)
        if os.path.exists(DB_PATH):
            backup_path = DB_PATH + '.backup'
            os.rename(DB_PATH, backup_path)
            print(f"Backed up old database to: {backup_path}")

        # Создаем новую базу
        init_database()
        print("✅ Database repaired successfully")
        return True

    except Exception as e:
        print(f"❌ Database repair failed: {e}")
        return False


if __name__ == '__main__':
    print("Database Check and Repair Tool")
    print("=" * 40)

    if not check_database():
        print("\nAttempting to repair database...")
        if repair_database():
            print("Repair completed successfully")
        else:
            print("Repair failed")
            sys.exit(1)
    else:
        print("No repair needed")