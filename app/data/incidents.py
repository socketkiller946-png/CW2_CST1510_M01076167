import pandas as pd

def insert_incident(conn, date, incident_type, severity, status, description, reported_by=None):
    """Insert new incident."""
    cursor = conn.cursor()
    cursor.execute('INSERT INTO cyber_incidents (date, incident_type, severity, status, description, reported_by)'
                   'VALUES (?, ?, ?, ?, ?, ?)    ',
                   (date, incident_type, severity, status, description, reported_by))
    conn.commit()
    incident_id = cursor.lastrowid
    return incident_id

def get_all_incidents(conn):
    """Get all incidents as DataFrame."""
    df = pd.read_sql_query('SELECT * FROM cyber_incidents ORDER BY id DESC',
                           conn)
    return df

def update_incident_status(conn, incident_id, new_status):
    """
Update the status of an incident.
"""
    cursor = conn.cursor()
    cursor.execute('UPDATE cyber_incidents SET status = ? WHERE id = ?',
                   (new_status, incident_id))
    conn.commit()
    return cursor.rowcount

def delete_incident(conn, incident_id):
    """
Delete an incident from the database.
"""
    cursor = conn.cursor()
    cursor.execute('DELETE FROM cyber_incidents WHERE id = ?',
                   (incident_id,))
    conn.commit()
    return cursor.rowcount

def get_incidents_by_type_count(conn):
    """
Count incidents by type.
Uses: SELECT, FROM, GROUP BY, ORDER BY
"""
    query = ('SELECT incident_type, COUNT(*) as count FROM cyber_incidents GROUP BY incident_type ORDER BY count DESC')
    df = pd.read_sql_query(query, conn)
    return df

def get_high_severity_by_status(conn):
    """
Count high severity incidents by status.
Uses: SELECT, FROM, WHERE, GROUP BY, ORDER BY
"""
    query = ("SELECT status, COUNT(*) as count FROM cyber_incidents WHERE severity = 'High' GROUP BY status ORDER BY count DESC\n    ")
    df = pd.read_sql_query(query, conn)
    return df