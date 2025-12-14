import pandas as pd
from pathlib import Path
from app.data.db import connect_database
from app.data.schema import create_all_tables
from app.services.user_service import migrate_users_from_file,login_user,register_user
from app.data.incidents import get_all_incidents,insert_incident


def load_csv_to_table(csv_path, table_name):
    """
    Load a CSV file into a database table.
    """
    csv_path = Path(csv_path)

    if not csv_path.exists():
        print(f"  File not found: {csv_path}")
        return 0

    try:
        # Read CSV file using pandas
        df = pd.read_csv(csv_path)

        # Rename columns to match database schema
        if table_name == "cyber_incidents":
            df = df.rename(columns={
                'incident_id': 'id',
                'timestamp': 'date',
                'category': 'incident_type'
            })
            df = df[['id', 'date', 'incident_type', 'severity', 'status', 'description']]

        elif table_name == "datasets_metadata":
            df = df.rename(columns={
                'dataset_id': 'id',
                'name': 'dataset_name',
                'rows': 'record_count',
                'columns': 'file_size_mb',
                'uploaded_by': 'source'
            })
            df = df[['id', 'dataset_name', 'record_count', 'file_size_mb', 'source']]

        elif table_name == "it_tickets":
            df = df.rename(columns={
                'description': 'subject',
                'created_at': 'created_date'
            })
            df = df[['ticket_id', 'priority', 'status', 'assigned_to', 'subject', 'created_date']]

        # Connect to database
        conn = connect_database()

        # Insert data into table
        df.to_sql(table_name, conn, if_exists='append', index=False)
        conn.close()

        row_count = len(df)
        print(f"   Loaded {row_count} rows into {table_name}")
        return row_count

    except Exception as e:
        print(f"   Error: {e}")
        return 0



def main():
    print("=" * 60)
    print("Week 8: Database Demo")
    print("=" * 60)

    # 1. Setup database
    conn = connect_database()
    create_all_tables(conn)

    # 2. Migrate users
    migrate_users_from_file(conn)

    # 3. Test authentication
    success, msg = register_user("alice", "SecurePass123!", "analyst")
    print(msg)

    success, msg = login_user("alice", "SecurePass123!")
    print(msg)

    # 4. Test CRUD
    incident_id = insert_incident(
        conn,
        "2024-11-05",
        "Phishing",
        "High",
        "Open",
        "Suspicious email detected",
        "alice"
    )
    print(f"Created incident #{incident_id}")

    # 5. Query data
    df = get_all_incidents(conn)
    print(f"Total incidents: {len(df)}")
    conn.close()


def setup_database_complete():
    """
    Complete database setup:
    1. Connect to database
    2. Create all tables
    3. Migrate users from users.txt
    4. Load CSV data for all domains
    5. Verify setup
    """
    print("\n" + "=" * 60)
    print("STARTING COMPLETE DATABASE SETUP")
    print("=" * 60)

    # Step 1: Connect
    print("\n[1/5] Connecting to database...")
    conn = connect_database()
    print("       Connected")

    # Step 2: Create tables
    print("\n[2/5] Creating database tables...")
    create_all_tables(conn)

    # Step 3: Migrate users
    print("\n[3/5] Migrating users from users.txt...")
    user_count = migrate_users_from_file(conn)
    print(f"       Migrated {user_count} users")

    # Step 4: Load CSV data
    print("\n[4/5] Loading CSV data...")
    print("-" * 80)
    total_rows = 0

    print("Loading cyber_incidents.csv...")
    rows = load_csv_to_table("DATA/cyber_incidents.csv", "cyber_incidents")
    total_rows += rows

    print("Loading datasets_metadata.csv...")
    rows = load_csv_to_table("DATA/datasets_metadata.csv", "datasets_metadata")
    total_rows += rows

    print("Loading it_tickets.csv...")
    rows = load_csv_to_table("DATA/it_tickets.csv", "it_tickets")
    total_rows += rows


    # Step 5: Verify
    print("\n[5/5] Verifying database setup...")
    cursor = conn.cursor()

    # Count rows in each table
    tables = ['users', 'cyber_incidents', 'datasets_metadata', 'it_tickets']
    print("\n Database Summary:")
    print(f"{'Table':<25} {'Row Count':<15}")
    print("-" * 40)

    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"{table:<25} {count:<15}")

    conn.close()

    print("\n" + "=" * 60)
    print(" DATABASE SETUP COMPLETE!")
    print("=" * 60)
    print(f"\n Database location: DATA/intelligence_platform.db")
    print("\nYou're ready for Week 9 (Streamlit web interface)!")






if __name__ == "__main__":
    main()
    # Run the complete setup
    setup_database_complete()

