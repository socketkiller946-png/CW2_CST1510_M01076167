from app.data.db import connect_database
import pandas as pd

def get_user_by_username(username):
    """Retrieve user by username."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_all_users():
    """Get all users as DataFrame."""
    conn = connect_database()
    df = pd.read_sql_query('SELECT id, username, role, created_at FROM users', conn)
    conn.close()
    return df

def insert_user(username, password_hash, role='user'):
    """Insert new user."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', (username, password_hash, role))
    conn.commit()
    conn.close()

def update_user_role(username, new_role):
    """Update a user's role."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET role = ? WHERE username = ?', (new_role, username))
    conn.commit()
    conn.close()

def delete_user(username):
    """Delete a user by username."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()

def update_user_password(username, new_password_hash):
    """Update a user's password hash."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password_hash = ? WHERE username = ?', (new_password_hash, username))
    conn.commit()
    conn.close()