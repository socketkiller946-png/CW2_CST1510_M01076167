import streamlit as st
from app.data.db import connect_database, DB_PATH
from app.data.users import get_user_by_username, insert_user
import bcrypt

conn = connect_database(DB_PATH)

st.set_page_config(page_title="Login / Register", page_icon="🔑 ", layout="centered")

# ---- session state ----
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""

st.title("🔐 Welcome")

# already logged in
if st.session_state.logged_in:
    st.success(f"Logged in as **{st.session_state.username}**")
    if st.button("Go to Dashboard"):
        st.switch_page("pages/1_Dashboard.py")
    st.stop()

tab_login, tab_register = st.tabs(["Login", "Register"])

# -------- LOGIN ----------
with tab_login:
    st.subheader("Login")
    login_username = st.text_input("Username")
    login_password = st.text_input("Password", type="password")

    if st.button("Log in", type="primary"):
        user = get_user_by_username(login_username)

        if user:
            # to access third element of row
            stored_hash = user[2]

            if bcrypt.checkpw(login_password.encode(), stored_hash.encode()):
                st.session_state.logged_in = True
                st.session_state.username = login_username
                st.success(f"Welcome {login_username}! 😄")
                st.switch_page("pages/1_Dashboard.py")
            else:
                st.error("Invalid password")
        else:
            st.error("User does not exist")


# -------- REGISTER ----------
with tab_register:
    st.subheader("Register")
    new_username = st.text_input("Choose a username")
    new_password = st.text_input("Choose a password", type="password")
    confirm_password = st.text_input("Confirm password", type="password")

    if st.button("Create account"):
        if not new_username or not new_password:
            st.warning("Fill all fields!")
            st.stop()

        if new_password != confirm_password:
            st.error("Passwords do not match")
            st.stop()

        if get_user_by_username(new_username):
            st.error("Username already exists!")
            st.stop()

        if not (3 <= len(new_username) <= 20):
            st.error("Username must be between 3 and 20 characters.")
            st.stop()

        if not (6 <= len(new_password) <= 50):
            st.error("Password must be between 6 and 50 characters.")
            st.stop()

        # bcrypt hash
        hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

        insert_user(new_username, hashed)

        st.success("Account created!")
        st.info("Go to Login tab")
