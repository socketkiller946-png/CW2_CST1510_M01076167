import pandas as pd

def insert_dataset(conn, dataset_name, record_count, file_size_mb, source, last_updated):
    cursor = conn.cursor()
    cursor.execute('INSERT INTO datasets_metadata (dataset_name, record_count, file_size_mb, source, last_updated)       '
                   'VALUES (?, ?, ?, ?, ?)\n    ', (dataset_name, record_count, file_size_mb, source, last_updated))
    conn.commit()
    return cursor.lastrowid

def get_all_datasets(conn):
    return pd.read_sql_query('SELECT * FROM datasets_metadata ORDER BY id DESC', conn)

def delete_dataset(conn, id):
    cursor = conn.cursor()
    cursor.execute('DELETE FROM datasets_metadata WHERE id = ?', (id,))
    conn.commit()
    return cursor.rowcount

def count_by_owner(conn):
    query = 'SELECT source AS owner, COUNT(*) AS total FROM datasets_metadata GROUP BY source ORDER BY total DESC    '
    return pd.read_sql_query(query, conn)

def biggest_datasets(conn, min_records=10000):
    query = 'SELECT *     FROM datasets_metadata   WHERE record_count > ?  ORDER BY record_count DESC    '
    return pd.read_sql_query(query, conn, params=(min_records,))