
import streamlit as st
import bcrypt
from app.data.db import connect_database
from app.data.db import DB_PATH
from app.data.users import (
    get_user_by_username, insert_user,
    get_all_users, delete_user,
    update_user_password, update_user_role
)

def hash_password(password):
    # Hash the password using a strong algorithm (bcrypt)
    # The default cost factor is 12 (2^12 iterations)
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

conn = connect_database(DB_PATH)

st.set_page_config(page_title="⚙️ Settings Dashboard", page_icon="📊", layout="wide")

# ---------------- AUTH GUARD ----------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""

# check role
is_admin = st.session_state.get("role") == "admin"

if not st.session_state.logged_in:
    st.error("You must be logged in to view the dashboard.")
    if st.button("Go to login page"):
        st.switch_page("Home.py")
    st.stop()

st.title("⚙️ Settings Dashboard")
st.success(f"Hello, **{st.session_state.username}**! You are logged in.")

col_header, col_button_right = st.columns([6, 1])

with col_header:
    # The original header title
    st.header("👤 User Management")

with col_button_right:
    # refresh button
    if st.button("🔄 Refresh Data"):
        st.rerun()

# Define all possible user roles (customize this list for your application)
USER_ROLES = ["user", "admin", "viewer", "manager"]

# Fetch the user data
df_users = get_all_users()

if df_users.empty:
    st.info("No users found in the database.")
else:
    # 1. Display User Table
    st.subheader("Current Users")
    # Drop the password_hash column if it was retrieved (it should not be displayed)
    if "password_hash" in df_users.columns:
        df_users = df_users.drop(columns=["password_hash"])

    st.dataframe(df_users, hide_index=True, use_container_width=True)

    st.divider()

    # 2. Controls for User Actions
    st.subheader("Actions")

    # Select a user for actions
    user_list = df_users["username"].tolist()

    # Create the first row (User Selection and Change Role)
    col_select, col_role = st.columns(2)

    # Create the second row (Change Password and Delete User)
    col_pwd, col_delete = st.columns(2)

    # --- Column 1 (Top Left) ---
    with col_select:
        selected_user = st.selectbox(
            "Select User for Action",
            options=user_list,
            index=user_list.index(st.session_state.username) if st.session_state.username in user_list else 0
        )
        # Prevent user from deleting/changing their own role if they are the only admin
        is_self = selected_user == st.session_state.username

    # --- Column 2 (Top Right) ---
    with col_role:
        st.markdown("##### Change Role")
        new_role = st.selectbox(
            f"Set new role for {selected_user}",
            options=USER_ROLES,
            key=f"role_{selected_user}"
        )
        if st.button("Update Role", key=f"btn_role_{selected_user}", use_container_width=True):
            try:
                update_user_role(selected_user, new_role)
                st.success(f"Role for **{selected_user}** updated to **{new_role}**.")
                st.caption("Click refresh button at the top to see changes.")
            except Exception as e:
                st.error(f"Error updating role: {e}")

    # --- Column 3 (Bottom Left) ---
    with col_pwd:
        st.markdown("##### Change Password")
        new_password = st.text_input(
            "Enter new password",
            type="password",
            key=f"pwd_{selected_user}"
        )

        if st.button("Change Password", key=f"btn_pwd_{selected_user}", use_container_width=True):
            if len(new_password) < 6:
                st.warning("Password must be at least 6 characters.")
            else:
                try:
                    hashed_pwd = hash_password(new_password)
                    update_user_password(selected_user, hashed_pwd)
                    st.success(f"Password for **{selected_user}** updated.")
                    st.caption("Click refresh button at the top to see changes.")
                except Exception as e:
                    st.error(f"Error changing password: {e}")

    # --- Column 4 (Bottom Right) ---
    with col_delete:
        st.markdown("##### Delete User")
        st.caption("Permanent action.")
        # Ensure user can't delete themselves
        if is_self:
            st.warning("Cannot delete yourself!")
        else:
            # Use a session state variable for confirmation visibility
            if f"confirm_delete_{selected_user}" not in st.session_state:
                st.session_state[f"confirm_delete_{selected_user}"] = False

            # Display the main Delete button
            if st.button("Delete", key=f"btn_del_{selected_user}", use_container_width=True):
                # Toggle confirmation visibility when Delete is clicked
                st.session_state[f"confirm_delete_{selected_user}"] = True

            # Display the confirmation button if the flag is set
            if st.session_state[f"confirm_delete_{selected_user}"]:
                st.warning(f"Are you sure you want to delete **{selected_user}**?")

                col_confirm, col_cancel = st.columns(2)

                with col_confirm:
                    if st.button(f"Yes, Delete {selected_user}", key=f"confirm_del_{selected_user}",
                                 use_container_width=True):
                        try:
                            delete_user(selected_user)
                            st.success(f"User **{selected_user}** deleted.")
                            st.caption("Click refresh button at the top to see changes.")
                            # Hide the confirmation prompt after success
                            st.session_state[f"confirm_delete_{selected_user}"] = False
                        except Exception as e:
                            st.error(f"Error deleting user: {e}")
                            # Hide the confirmation prompt after error
                            st.session_state[f"confirm_delete_{selected_user}"] = False

                with col_cancel:
                    if st.button("Cancel", key=f"cancel_del_{selected_user}", use_container_width=True):
                        # Hide the confirmation prompt if canceled
                        st.session_state[f"confirm_delete_{selected_user}"] = False
                        st.rerun()  # Rerun to clear the buttons

    st.divider()

# 3. Add New User (Optional feature)
st.subheader("➕ Add New User")
with st.form("new_user_form"):
    col_u, col_p, col_r = st.columns(3)

    new_username = col_u.text_input("Username")
    new_password = col_p.text_input("Password", type="password")
    new_role = col_r.selectbox("Role", options=USER_ROLES)

    submitted = st.form_submit_button("Create User")

    if submitted:
        if get_user_by_username(new_username):
            st.error(f"User **{new_username}** already exists.")
        elif len(new_username) < 3 or len(new_password) < 6:
            st.warning("Username must be at least 3 chars, Password 6+ chars.")
        else:
            try:
                hashed_pwd = hash_password(new_password)
                insert_user(new_username, hashed_pwd, new_role)
                st.success(f"User **{new_username}** created with role **{new_role}**.")
                st.caption("Click refresh button at the top to see changes.")
            except Exception as e:
                st.error(f"Creation failed: {e}")

# ---------------- LOGOUT ----------------
st.divider()
if st.button("Log out"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.info("You have been logged out.")
    st.switch_page("Home.py")

