import streamlit as st
import pandas as pd
from datetime import date
from app.data.db import connect_database
from app.data.incidents import get_all_incidents, insert_incident, update_incident_status, delete_incident
from app.data.datasets import get_all_datasets, insert_dataset, delete_dataset
from app.data.tickets import get_all_tickets, insert_ticket, update_ticket_status, delete_ticket

st.set_page_config(page_title="Dashboard", page_icon="📊", layout="wide")

# ---------------- AUTH GUARD ----------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""

if not st.session_state.logged_in:
    st.error("You must be logged in to view the dashboard.")
    if st.button("Go to login page"):
        st.switch_page("Home.py")
    st.stop()

# ---------------- DB CONNECTION ----------------
conn = connect_database()
user = st.session_state.username or None


def load_data(load_func, error_msg, cols=None):
    """Generic function to load data from a database function."""
    try:
        df = load_func(conn)
        return df.copy()
    except Exception as e:
        st.error(f"Error {error_msg}: {e}")
        return pd.DataFrame(columns=cols if cols else [])

col_header, col_button_right = st.columns([6, 1])

with col_header:
    # The original header title
    st.title("Domain Dashboard")

with col_button_right:
    # refresh button
    if st.button("🔄 Refresh Data"):
        st.rerun()
st.success(f"Hello, **{user}**! You are logged in.")
st.divider()

# ---------------- TABS IMPLEMENTATION ----------------
tab_incidents, tab_datasets, tab_tickets = st.tabs(
    ["🔒 Cyber Incidents", "🧠 Data Science", "⚙️ IT Operations"]
)


# CYBER INCIDENTS TAB
with tab_incidents:
    st.subheader("Cyber Incidents Management")

    incidents = load_data(
        get_all_incidents,
        "loading incidents",
        ["id", "date", "incident_type", "severity", "status", "description", "reported_by"]
    )

    # Show table
    if not incidents.empty:
        st.markdown("##### All Incidents")
        st.dataframe(incidents, use_container_width=True)
    else:
        st.info("No cyber incidents found.")

    st.divider()

    # ---------------- CREATE INCIDENT ----------------
    with st.form("new_incident_form"):
        st.subheader("➕ Add new incident")
        col_t, col_s = st.columns(2)
        title = col_t.text_input("Incident Title", key="inc_new_title")
        date_input = col_t.date_input("Incident Date", key="inc_new_date", value=date.today())
        description = col_t.text_input("Incident Description", key="inc_new_description")

        severity = col_s.selectbox("Severity", ["Low", "Medium", "High", "Critical"], key="inc_new_severity")
        status = col_s.selectbox("Status", ["Open", "In Progress", "Resolved"], key="inc_new_status")

        submit_create = st.form_submit_button("Add Incident")

    if submit_create:
        try:
            insert_incident(conn, date_input.isoformat(), title, severity, status, description, reported_by=user)
            st.success("Incident added successfully.")
            st.caption("Click refresh button at the top to see changes.")
        except Exception as e:
            st.error(f"Failed to add incident: {e}")

    st.divider()

    # Prepare selection lists for update/delete
    if not incidents.empty:
        incidents["display_name"] = incidents["id"].astype(str) + " - " + incidents["description"].fillna("")
        incident_map = incidents.set_index("id")["display_name"].to_dict()

        # Columns for update/delete
        update_col, delete_col = st.columns(2)

        # ---------------- UPDATE INCIDENT ----------------
        with update_col:
            st.subheader("✏️ Update Incident Status")


            # Helper to get the ID from the selected display name
            def get_selected_id(choice, mapping):
                return int([k for k, v in mapping.items() if v == choice][0])


            update_choice = st.selectbox(
                "Select incident to update",
                options=list(incident_map.values()),
                key="inc_update_select"
            )
            selected_update_id = get_selected_id(update_choice, incident_map)

            current_status = incidents.loc[incidents["id"] == selected_update_id, "status"].iloc[0]
            with st.form("update_form"):
                st.markdown(f"**Selected:** {update_choice}  \n_Current status:_ **{current_status}**")
                new_status = st.selectbox(
                    "New Status",
                    ["Open", "In Progress", "Resolved"],
                    index=["Open", "In Progress", "Resolved"].index(current_status) if current_status in ["Open",
                                                                                                          "In Progress",
                                                                                                          "Resolved"] else 0,
                    key="inc_update_status_select"
                )
                update_submit = st.form_submit_button("Update Incident")

            if update_submit:
                try:
                    rows = update_incident_status(conn, selected_update_id, new_status)
                    if rows:
                        st.success(f"Incident {selected_update_id} updated to '{new_status}'.")
                        st.caption("Click refresh button at the top to see changes.")
                    else:
                        st.warning(f"No rows updated. Incident {selected_update_id} may not exist.")
                except Exception as e:
                    st.error(f"Failed to update: {e}")


        # ---------------- DELETE INCIDENT ----------------
        with delete_col:
            st.subheader("🗑️ Delete Incident")

            delete_choice = st.selectbox(
                "Select incident to delete",
                options=list(incident_map.values()),
                key="inc_delete_select"
            )
            selected_delete_id = get_selected_id(delete_choice, incident_map)

            st.warning(f"You're about to delete: **{delete_choice}**")
            if st.button("PERMANENTLY DELETE", key="inc_delete_btn"):
                try:
                    rows = delete_incident(conn, selected_delete_id)
                    if rows:
                        st.success(f"Incident {selected_delete_id} deleted.")
                        st.caption("Click refresh button at the top to see changes.")
                    else:
                        st.warning(f"No rows deleted. Incident {selected_delete_id} may not exist.")
                except Exception as e:
                    st.error(f"Failed to delete: {e}")
    else:
        st.info("Incident update/delete controls will appear once incidents exist.")


# DATASETS TAB
with tab_datasets:
    st.subheader("Dataset Management")
    datasets = load_data(
        get_all_datasets,
        "loading datasets",
        ["id", "dataset_name","category","rows","columns","uploaded_by","upload_date"]
    )

    if not datasets.empty:
        st.markdown("##### All Datasets")
        # Ensure correct column names are displayed from your image
        st.dataframe(datasets.rename(columns={'rows': 'record_count', 'columns': 'file_size_mb', 'uploaded_by' : 'source'}),
                     use_container_width=True)
    else:
        st.info("No datasets found.")

    st.divider()

    # ---------------- CREATE DATASET ----------------
    with st.form("new_dataset_form"):
        st.subheader("➕ Register new dataset")
        col_n, col_d = st.columns(2)

        dataset_name = col_n.text_input("Dataset Name", key="data_new_name")
        record_count = col_n.slider("Record Count",
            min_value=0,
            max_value=1000000,
            value=1000,
            step=1000,  # Use steps for large range navigation
            key="data_new_rows")

        file_size_mb = col_d.slider(
            "File Size (MB)",
            min_value=1,
            max_value=200,
            value=10,  # Set a reasonable default value
            format="%d",
            key="data_new_cols")

        created_at = col_d.date_input("Last Updated Date", value=date.today(), key="data_new_date")

        submit_dataset_create = st.form_submit_button("Register Dataset")

    if submit_dataset_create:
        try:
            # We map local variables back to the function's expected parameter names.
            insert_dataset(conn,dataset_name,record_count,file_size_mb,user,created_at.isoformat())
            st.success("Dataset registered successfully.")
            st.caption("Click refresh button at the top to see changes.")
        except Exception as e:
            st.error(f"Failed to register dataset: {e}")

    st.divider()

    # ---------------- DELETE DATASET ----------------
    if not datasets.empty:
        st.subheader("🗑️ Delete Dataset")

        # Use ID and name for selection
        datasets["display_name"] = datasets["id"].astype(str) + " - " + datasets["dataset_name"]
        dataset_map = datasets.set_index("id")["display_name"].to_dict()  # Using 'id' for the map key

        delete_choice = st.selectbox(
            "Select dataset to delete",
            options=list(dataset_map.values()),
            key="data_delete_select"
        )
        selected_delete_id = get_selected_id(delete_choice, dataset_map)

        st.warning(f"You're about to delete: **{delete_choice}**")
        if st.button("PERMANENTLY DELETE DATASET", key="data_delete_btn"):
            try:
                # delete_dataset function uses dataset_id which we assume maps to 'id' from the DataFrame
                rows = delete_dataset(conn, selected_delete_id)
                if rows:
                    st.success(f"Dataset {selected_delete_id} deleted.")
                    st.caption("Click refresh button at the top to see changes.")
                else:
                    st.warning(f"No rows deleted.")
            except Exception as e:
                st.error(f"Failed to delete dataset: {e}")
    else:
        st.info("Dataset delete controls will appear once datasets exist.")


# IT TICKETS TAB
with tab_tickets:
    tickets = load_data(
        get_all_tickets,
        "loading tickets",
        ["ticket_id", "priority", "status", "category", "subject", "description", "assigned_to", "resolution_time_hours", "created_date"]
    )

    if tickets.empty:
        st.info("No tickets found.")
    else:
        tickets["ticket_id"] = tickets["ticket_id"].astype(int)
        st.subheader("All Tickets")
        st.dataframe(tickets, use_container_width=True)

    st.divider()

    # CREATE Tickets
    st.subheader("➕ Create New IT Ticket")

    with st.form("new_ticket_form"):
        # new required subject
        subject = st.text_input("Subject", placeholder="Short summary...")

        # safe next ticket_id
        if not tickets.empty:
            next_ticket_id = int(tickets["ticket_id"].max()) + 1
        else:
            next_ticket_id = 2000

        st.markdown(f"**New Ticket ID:** `{next_ticket_id}`")

        col1, col2 = st.columns(2)

        priority = col1.selectbox("Priority", ["Low", "Medium", "High", "Critical"])
        category = col1.selectbox("Category", ["Software", "Hardware", "Network", "Other"])

        status = col2.selectbox(
            "Initial Status",
            ["Open", "In Progress", "Resolved", "Waiting for User"],
        )

        assigned_to = col2.selectbox(
            "Assign To",
            ["IT_Support_A", "IT_Support_B", "IT_Support_C", "Unassigned"],
        )

        resolution_hours = st.slider(
            "Resolution Time (Hours)",
            min_value=1,  # Start at 1 hour
            max_value=200,  # End at 200 hours
            value=24,  # Set a reasonable default value, e.g., 24 hours
            step=1,  # Slider moves in 1-hour increments
            format="%d hours"  # Display format with "hours"
        )

        description = st.text_area("Description", placeholder="Describe the IT issue...")
        created_date = st.date_input("Creation Date", value=date.today())

        submit_create_ticket = st.form_submit_button("Create Ticket")

        if submit_create_ticket:
            insert_ticket(
                conn,
                ticket_id=next_ticket_id,
                priority=priority,
                status=status,
                category=category,
                subject=subject,
                description=description,
                assigned_to=assigned_to,
                resolution_time_hours=int(resolution_hours),
                created_date=str(created_date)
            )

            st.success("Ticket created successfully.")
            st.caption("Click refresh button at the top to see changes.")

    st.divider()


    # UPDATE Tickets
    if not tickets.empty:
        st.subheader("✏️ Update Ticket Status")

        tickets["description"] = tickets["description"].fillna("No description")

        labels = tickets["ticket_id"].astype(str) + " - " + tickets["description"]
        ticket_select_update = st.selectbox("Pick ticket", labels)

        if ticket_select_update:
            selected_ticket_id = int(ticket_select_update.split(" - ")[0])
            ticket_row = tickets[tickets["ticket_id"] == selected_ticket_id].iloc[0]
            current_status = ticket_row["status"]

            new_status = st.selectbox(
                "New Status",
                ["Open", "In Progress", "Resolved", "Waiting for User"],
                index=["Open", "In Progress", "Resolved", "Waiting for User"].index(
                    current_status if current_status in ["Open", "In Progress", "Resolved", "Waiting for User"]
                    else "Open"
                ),
            )

            if st.button("Update Status"):
                update_ticket_status(conn, selected_ticket_id, new_status)
                st.success("Ticket updated successfully.")
                st.caption("Click refresh button at the top to see changes.")

    st.divider()


    # DELETE Tickets
    if not tickets.empty:
        st.subheader("🗑 Delete Ticket")

        labels_del = tickets["ticket_id"].astype(str) + " - " + tickets["description"]
        ticket_select_delete = st.selectbox("Pick ticket to delete", labels_del)

        if st.button("DELETE TICKET PERMANENTLY"):
            delete_ticket_id = int(ticket_select_delete.split(" - ")[0])
            delete_ticket(conn, delete_ticket_id)
            st.success("Ticket deleted successfully.")
            st.caption("Click refresh button at the top to see changes.")


# ---------------- LOGOUT ----------------
st.divider()
if st.button("Log out"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.info("You have been logged out.")
    st.switch_page("Home.py")