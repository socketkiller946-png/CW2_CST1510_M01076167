import streamlit as st
import pandas as pd
import numpy as np
from pathlib import Path
from app.data.db import connect_database
from app.data.incidents import get_all_incidents
from app.data.datasets import get_all_datasets,count_by_owner,biggest_datasets
import altair as alt  # Added for the pie/donut chart
from app.data.tickets import get_all_tickets,count_tickets_by_priority,assign_to

# --- DATABASE CONFIGURATION ---
DB_PATH = Path("DATA") / "intelligence_platform.db"


# --- helper to be robust on missing columns ---
def safe_col(df, col, default=np.nan):
    return df[col] if col in df.columns else pd.Series([default] * len(df), index=df.index, name=col)

def to_datetime_safe(s):
    try:
        return pd.to_datetime(s, errors="coerce")
    except Exception:
        return pd.to_datetime(pd.Series([np.nan]*len(s)), errors="coerce")


def fetch_data():
    """Fetches data from all three tables and returns pandas DataFrames."""
    conn = connect_database()
    try:
        # 1. Fetch Incidents
        incidents = get_all_incidents(conn)

        # 2. Fetch Datasets
        df_datasets = get_all_datasets(conn)

        # 3. Fetch IT Tickets
        df_tickets = get_all_tickets(conn)

    except Exception as e:
        st.error(f"Error reading database: {e}")
    finally:
        conn.close()

    return incidents, df_datasets, df_tickets


# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Domain Analytics",
    layout="wide",
    page_icon="📊"
)

# --- GUARD PATTERN ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""

if not st.session_state.logged_in:
    st.error("You must be logged in to view the dashboard.")
    if st.button("Go to login page"):
        st.switch_page("Home.py")  # Ensure Home.py exists
    st.stop()

# --- HEADER & REFRESH ---
col_header, col_btn = st.columns([6, 1])
with col_header:
    st.title("Analytics Dashboard")
    st.success(f"Hello, **{st.session_state.username}**! You are logged in.")
with col_btn:
    # This button forces a script rerun, fetching fresh data from DB
    if st.button("🔄 Refresh Data"):
        st.rerun()

# --- LOAD DATA ---
incidents, df_datasets, df_tickets = fetch_data()

# Tabs to switch between domains
tab_cyber, tab_ds, tab_it = st.tabs(["🔒 Cybersecurity", "🧠 Data Science", "⚙️ IT Operations"])

# --- CYBERSECURITY DASHBOARD (Table: incidents) ---
with tab_cyber:
    st.subheader("Security Incidents Overview")

    if not incidents.empty:
        # Metrics derived from real data
        total_incidents = len(incidents)
        # Assuming there is a 'status' column. If not, remove the filter.
        active_threats = len(incidents[incidents['status'] == 'Open']) if 'status' in incidents.columns else 0
        critical_threats = len(
            incidents[incidents['severity'] == 'Critical']) if 'severity' in incidents.columns else 0

        if "prev_active" not in st.session_state:
            st.session_state.prev_active = active_threats

        if "prev_critical" not in st.session_state:
            st.session_state.prev_critical = critical_threats

        delta_active = active_threats - st.session_state.prev_active
        delta_critical = critical_threats - st.session_state.prev_critical

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Incidents Logged", total_incidents)
        with col2:
            st.metric("Active Threats", active_threats,delta=delta_active, delta_color="inverse")
        with col3:
            st.metric("Critical Severity", critical_threats, delta=delta_critical, delta_color="inverse")
            st.caption(f"Last change: {abs(delta_critical)}")

        st.session_state.prev_active = active_threats
        st.session_state.prev_critical = critical_threats

        # Dynamic Chart: Incidents by Type
        st.subheader("Threat Distribution")

        # count occurrences and bar chart
        counts = incidents["incident_type"].value_counts()

        categories = [
            "Malware",
            "Misconfiguration",
            "Phishing",
            "Unauthorized Access",
            "DDoS"
        ]
        chart_data = pd.DataFrame({
            "Type": categories,
            "Count": [counts.get(cat, 0) for cat in categories]
        })

        st.bar_chart(chart_data, x="Type", y="Count")

        # Show raw data
        with st.expander("View Raw Incident Data"):
            st.dataframe(incidents)
    else:
        st.info("No data found in 'incidents' table.")

# --- DATA SCIENCE DASHBOARD (Table: database) ---
with tab_ds:
    st.subheader("DataScience Datasets")

    if not df_datasets.empty:
        # --- Metrics (Standard) ---
        st.header("Overall Dataset Metrics")
        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Total Datasets", len(df_datasets))
        with col2:
            total_records = df_datasets['record_count'].sum()
            st.metric("Total Records Across All Datasets", f"{total_records:,}")
        with col3:
            total_size = df_datasets['file_size_mb'].sum()
            st.metric("Total Disk Usage (MB)", f"{total_size:,} MB")

        st.markdown("---")

        # --- Dynamic Data Fetch for Charts ---
        df_owner_counts = pd.DataFrame()
        df_biggest_datasets = pd.DataFrame()

        try:
            with connect_database() as conn:
                df_owner_counts = count_by_owner(conn)
                df_biggest_datasets = biggest_datasets(conn, min_records=50000)
        except Exception as e:
            st.warning(f"SQL error: {e}")

        # --- Chart Visualizations ---

        st.header("Dataset Visualizations")

        chart_col1, chart_col2 = st.columns(2)

        # 1. Dataset Ownership Distribution (Bar Chart remains simple)
        with chart_col1:
            st.subheader("Dataset Ownership Distribution")
            if not df_owner_counts.empty:
                # Bar chart for ownership (using your `count_by_owner` result)
                # Using a simple hex color for the bar chart
                st.bar_chart(df_owner_counts, x='owner', y='total')
                st.caption("Count of datasets managed by each source role.")
            else:
                st.info("No ownership data to display.")

        # 2. File Size Distribution by Dataset (FIXED: Simplified Altair Donut Chart)
        with chart_col2:
            st.subheader("File Size Distribution")

            # Prepare data for Altair (uses the original df_datasets)
            pie_data = df_datasets[['dataset_name', 'file_size_mb']]

            # Create the Donut Chart using Altair
            base = alt.Chart(pie_data).encode(
                theta=alt.Theta("file_size_mb", stack=True)
            )

            # --- SIMPLIFICATION APPLIED HERE ---
            # Removed the problematic 'scale=alt.Scale(range='viridis'))' argument.
            # Altair now uses its default, simple, and valid categorical color range.
            pie = base.mark_arc(outerRadius=120, innerRadius=60).encode(
                color=alt.Color("dataset_name", title="Dataset Name"),  # Altair handles colors automatically here
                order=alt.Order("file_size_mb", sort="descending"),
                tooltip=["dataset_name", alt.Tooltip("file_size_mb", format=".1f")]
            ).properties(
                title='Proportion of Total Storage Used (MB)'
            )

            st.altair_chart(pie, use_container_width=True)
            st.caption("Visualizes storage footprint of individual datasets.")

        st.markdown("---")

        # --- New Section: Biggest Datasets (Table remains simple) ---
        st.subheader("Large Datasets Overview (>$50,000$ Records)")
        if not df_biggest_datasets.empty:
            # Display a table of the largest datasets
            st.dataframe(df_biggest_datasets, use_container_width=True)
        else:
            st.info("No datasets found exceeding the $50,000$ record threshold.")

        st.markdown("---")

        # --- 5. Raw Data Display (Table remains simple) ---
        st.header("Raw Dataset Metadata Table")
        with st.expander("View Raw Incident Data"):
            st.dataframe(df_datasets)
    else:
        st.info("No data found in the datasets table.")

# --- IT OPERATIONS DASHBOARD (Table: tickets) ---
with tab_it:
    st.subheader("IT Support Tickets")

    if not df_tickets.empty:
        # Normalize/parse types
        df = df_tickets.copy()

        # Ensure essential columns exist
        for col in ["ticket_id", "priority", "status", "category", "subject", "description",
                    "created_date", "resolved_date", "assigned_to", "resolution_time_hours", "created_at"]:
            if col not in df.columns:
                df[col] = np.nan

        # Parse dates
        df["created_date"] = to_datetime_safe(df["created_date"])
        df["resolved_date"] = to_datetime_safe(df["resolved_date"])
        df["created_at"] = to_datetime_safe(df["created_at"])

        # Compute resolution_time_hours if missing/NaN and resolved_date exists
        # Prefer existing value if present
        need_rt = df["resolution_time_hours"].isna() & df["resolved_date"].notna() & df["created_date"].notna()
        df.loc[need_rt, "resolution_time_hours"] = (
                (df.loc[need_rt, "resolved_date"] - df.loc[need_rt, "created_date"]).dt.total_seconds() / 3600.0
        )

        # Basic KPIs
        total_tickets = len(df)
        open_tickets = (df["status"] == "Open").sum() if "status" in df.columns else 0
        closed_tickets = (df["status"] == "Resolved").sum() if "status" in df.columns else 0

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Tickets", total_tickets)
        with col2:
            st.metric("Open Tickets", int(open_tickets), delta=f"{int(open_tickets)} pending", delta_color="inverse")
        with col3:
            st.metric("Resolved Tickets", int(closed_tickets))

        # SLA assumptions (customize as needed)
        SLA_HOURS = {"Critical": 4, "High": 8, "Medium": 24, "Low": 48}
        # Compute SLA breach only for resolved tickets with resolution_time_hours
        df_resolved = df[(df["status"] == "Resolved") & df["resolution_time_hours"].notna()].copy()
        df_resolved["sla_target"] = df_resolved["priority"].map(SLA_HOURS).fillna(np.nan)
        df_resolved["sla_breached"] = (df_resolved["resolution_time_hours"] > df_resolved["sla_target"])

        # SLA KPIs
        avg_res_time = df_resolved["resolution_time_hours"].mean()
        median_res_time = df_resolved["resolution_time_hours"].median()
        breach_rate = (df_resolved["sla_breached"].mean() * 100.0) if not df_resolved.empty else np.nan

        col4, col5, col6 = st.columns(3)
        with col4:
            st.metric("Avg Resolution (hrs)", f"{avg_res_time:.1f}" if pd.notna(avg_res_time) else "—")
        with col5:
            st.metric("Median Resolution (hrs)", f"{median_res_time:.1f}" if pd.notna(median_res_time) else "—")
        with col6:
            st.metric("SLA Breach Rate", f"{breach_rate:.1f}%" if pd.notna(breach_rate) else "—")

        st.divider()

        # --- Priority distribution from DB function ---
        st.subheader("Tickets by Priority")
        try:
            df_pri = count_tickets_by_priority(conn)  # columns: priority, count
            st.bar_chart(df_pri.set_index("priority")["count"])
        except Exception as e:
            st.warning(f"Could not load priority distribution from DB: {e}")
            # fallback using current df
            fallback_pri = df["priority"].fillna("Unknown").value_counts()
            st.bar_chart(fallback_pri)

        # --- Tickets over time (created per week) ---
        st.subheader("Ticket Creation Trend")
        df_time = df.copy()
        df_time["created_week"] = df_time["created_date"].dt.to_period("W").dt.start_time
        created_per_week = df_time.groupby("created_week")["ticket_id"].count().sort_index()
        st.line_chart(created_per_week, height=220)

        # --- Assignment UI (uses assign_to function) ---
        st.subheader("Assign Ticket")
        # Choose ticket (filter to open/unassigned first, but allow all)
        ticket_options = df["ticket_id"].dropna().astype(int).tolist()
        default_ticket = ticket_options[0] if ticket_options else None

        # Staff list from existing assignments
        staff_list = sorted(df["assigned_to"].dropna().unique().tolist())
        staff_list = [s for s in staff_list if str(s).strip() != ""]  # remove empties
        # Add a manual entry option
        staff_choice = st.selectbox("Assign to", options=staff_list + ["— Other —"], index=0 if staff_list else None)
        other_staff = st.text_input("Other staff (if not in list)", value="") if staff_choice == "— Other —" else None

        selected_ticket = st.selectbox("Ticket ID", options=ticket_options, index=ticket_options.index(
            default_ticket) if default_ticket in ticket_options else 0)

        # button for refresh page
        col_assign, col_refresh = st.columns([1, 1])

        with col_assign:
            if st.button("Assign", use_container_width=True):
                staff_name = other_staff if (staff_choice == "— Other —" and other_staff.strip()) else staff_choice
                if not staff_name or staff_name == "— Other —":
                    st.warning("Please provide a valid staff name.")
                else:
                    try:
                        updated = assign_to(conn, int(selected_ticket), str(staff_name))
                        if updated > 0:
                            st.success(f"Ticket {selected_ticket} assigned to {staff_name}.")
                            # Optional: Add a suggestion to refresh
                            st.info("Click 'Refresh Data' to view the updated ticket status.")
                        else:
                            st.info("No rows updated. Verify the ticket ID exists.")
                    except Exception as e:
                        st.error(f"Assignment failed: {e}")

        with col_refresh:
            # Refresh button using st.rerun()
            if st.button("Refresh Data", use_container_width=True):
                st.rerun()
            st.caption("Refresh data after assignment")
        # =========================================================================

        st.divider()
        # --- Details table ---
        with st.expander("View Ticket Details"):
            st.dataframe(df_tickets)

    else:
        st.info("No data found in 'tickets' table.")


# ---------------- LOGOUT ----------------
st.divider()
if st.button("Log out"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.info("You have been logged out.")
    st.switch_page("Home.py")