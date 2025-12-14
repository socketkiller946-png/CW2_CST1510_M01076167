import pandas as pd

def insert_ticket(conn, ticket_id, priority, status, category, subject, description, assigned_to=None, resolution_time_hours=None, created_date=None, resolved_date=None):
    cursor = conn.cursor()
    cursor.execute('\n        INSERT INTO it_tickets\n        (ticket_id, priority, status, category, subject, description,\n         created_date, resolved_date, assigned_to, resolution_time_hours)\n        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n    ', (ticket_id, priority, status, category, subject, description, created_date, resolved_date, assigned_to, resolution_time_hours))
    conn.commit()
    return cursor.lastrowid

def get_all_tickets(conn):
    return pd.read_sql_query('SELECT * FROM it_tickets ORDER BY ticket_id DESC', conn)

def update_ticket_status(conn, ticket_id, new_status):
    cursor = conn.cursor()
    cursor.execute('\n        UPDATE it_tickets\n        SET status = ?\n        WHERE ticket_id = ?\n    ', (new_status, ticket_id))
    conn.commit()
    return cursor.rowcount

def delete_ticket(conn, ticket_id):
    cursor = conn.cursor()
    cursor.execute('DELETE FROM it_tickets WHERE ticket_id = ?', (ticket_id,))
    conn.commit()
    return cursor.rowcount

def count_tickets_by_priority(conn):
    query = '\n        SELECT priority, COUNT(*) AS count\n        FROM it_tickets\n        GROUP BY priority\n        ORDER BY count DESC\n    '
    return pd.read_sql_query(query, conn)

def assign_to(conn, ticket_id, staff_name):
    """
Assign a ticket to a specific staff member.
"""
    cursor = conn.cursor()
    cursor.execute('\n                   UPDATE it_tickets\n                   SET assigned_to = ?\n                   WHERE ticket_id = ?\n                   ', (staff_name, ticket_id))
    conn.commit()
    return cursor.rowcount

def close_ticket(conn, ticket_id, resolution_time_hours=None):
    """
Close a ticket and optionally update the resolution time.
"""
    cursor = conn.cursor()
    if resolution_time_hours is not None:
        cursor.execute("\n                       UPDATE it_tickets\n                       SET status                = 'Closed',\n                           resolution_time_hours = ?\n                       WHERE ticket_id = ?\n                       ", (resolution_time_hours, ticket_id))
    conn.commit()
    return cursor.rowcount