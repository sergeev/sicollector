from secure_server import bcrypt, get_db_connection

def change_password(username, new_password):
    conn = get_db_connection()
    cursor = conn.cursor()
    password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    cursor.execute('UPDATE users SET password_hash = ? WHERE username = ?',
                   (password_hash, username))
    conn.commit()
    conn.close()
    print(f"Password changed for user: {username}")

change_password('admin', 'new_secure_password')