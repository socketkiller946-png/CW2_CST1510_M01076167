def create_users_table(conn):
    """Create users table."""
    cursor = conn.cursor()
    create_table_sql = "\n    CREATE TABLE IF NOT EXISTS users (\n        id INTEGER PRIMARY KEY AUTOINCREMENT,\n        username TEXT NOT NULL UNIQUE,\n        password_hash TEXT NOT NULL,\n        role TEXT DEFAULT 'user',\n        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n    )\n    "
    cursor.execute(create_table_sql)
    conn.commit()
    print('Users table created successfully!')

def create_cyber_incidents_table(conn):
    """Create cyber_incidents table."""
    cursor = conn.cursor()
    create_table_sql = '\n    CREATE TABLE IF NOT EXISTS cyber_incidents (\n        id INTEGER PRIMARY KEY AUTOINCREMENT,\n        date TEXT ,\n        incident_type TEXT ,\n        severity TEXT ,\n        status TEXT ,\n        description TEXT,\n        reported_by TEXT ,\n        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n    )\n    '
    cursor.execute(create_table_sql)
    conn.commit()
    print('Cyber_Incidents table created successfully!')

def create_datasets_metadata_table(conn):
    """Create datasets metadata table."""
    cursor = conn.cursor()
    create_table_sql = '\n    CREATE TABLE IF NOT EXISTS datasets_metadata (\n        id INTEGER PRIMARY KEY AUTOINCREMENT,\n        dataset_name TEXT NOT NULL,\n        category TEXT ,\n        source TEXT ,\n        last_updated TEXT,\n        record_count INTEGER,\n        file_size_mb REAL,\n        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n    )\n    '
    cursor.execute(create_table_sql)
    conn.commit()
    print('Datasets metadata table created successfully!')

def create_it_tickets_table(conn):
    """Create it tickets table."""
    cursor = conn.cursor()
    create_table_sql = '\n    CREATE TABLE IF NOT EXISTS it_tickets(\n        id INTEGER PRIMARY KEY AUTOINCREMENT,\n        ticket_id TEXT UNIQUE NOT NULL,\n        priority TEXT,\n        status TEXT,\n        category TEXT,\n        subject TEXT NOT NULL,\n        description TEXT,\n        created_date TEXT,\n        resolved_date TEXT,\n        assigned_to TEXT,\n        resolution_time_hours INTEGER,\n        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n    )\n    '
    cursor.execute(create_table_sql)
    conn.commit()
    print('It_tickets table created successfully!')

def create_all_tables(conn):
    """
Create all tables."""
    create_users_table(conn)
    create_cyber_incidents_table(conn)
    create_datasets_metadata_table(conn)
    create_it_tickets_table(conn)