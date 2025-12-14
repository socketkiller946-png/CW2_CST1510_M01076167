import streamlit as st
from google import genai
from google.genai.errors import APIError
from google.genai import types  # Import types for GenerateContentConfig
import pandas as pd
import json

# --- Database Functions  ---
from app.data.db import connect_database
from app.data.incidents import get_all_incidents
from app.data.datasets import get_all_datasets
from app.data.tickets import get_all_tickets

# ----------------- PAGE CONFIG & AUTH GUARD -----------------
st.set_page_config(page_title="AI Assistant Dashboard", page_icon="🧠", layout="wide")

if "logged_in" not in st.session_state or not st.session_state.logged_in:
    st.error("You must be logged in to view the AI Assistant.")
    if st.button("Go to login page"):
        st.switch_page("Home.py")
    st.stop()

st.title("🧠 AI Domain Assistant (Gemini)")
st.caption(
    "Ask questions about Cybersecurity, Data Science, or IT Operations. The assistant has access to live data.")
st.success(f"Hello, **{st.session_state.username}**! You are logged in.")

# ----------------- GENAI CLIENT SETUP -----------------
try:
    # Initialize the Gemini client using the key stored in secrets.toml
    API_KEY = st.secrets["GEMINI_API_KEY"]
    client = genai.Client(api_key=API_KEY)
except (KeyError, ValueError):
    st.error(
        " **Configuration Error:** `GEMINI_API_KEY` not found in `.streamlit/secrets.toml`. Please configure your key.")
    st.stop()
except Exception as e:
    st.error(f" **Client Error:** Error initializing GenAI client: {e}")
    st.stop()


# ----------------- DATA RETRIEVAL -----------------
def get_incident_data_as_context():
    """
    Connects to the database, fetches all incidents, and formats the data
    as a concise JSON string for the AI model
    """
    try:
        conn = connect_database()
        df = get_all_incidents(conn)
        df2 = get_all_tickets(conn)
        conn.close()

        if not df.empty:
            # Prepare contextual data
            df_context = df[['id', 'incident_type', 'severity', 'status', 'description', 'reported_by']]
            return df_context.to_json(orient='records', indent=2)
        else:
            return "No active data found in the database."

    except Exception as e:
        # Provide a clean message to the AI even if DB fails
        st.warning(f"Warning: Error fetching data: {e}")
        return "Error: Could not retrieve data from the database. Answers will be based on general knowledge."

def get_datasets_data_as_context():
    """
    Connects to the database, fetches all datasets, and formats the data
    as a concise JSON string for the AI model
    """
    try:
        conn = connect_database()
        df = get_all_datasets(conn)
        conn.close()

        if not df.empty:
            # Prepare contextual data
            df_context = df[['id', 'dataset_name', 'source', 'last_updated', 'record_count', 'file_size_mb']]
            return df_context.to_json(orient='records', indent=2)
        else:
            return "No datasets record found in the database."

    except Exception as e:
        # Provide a clean message to the AI even if DB fails
        st.warning(f"Warning: Error fetching data: {e}")
        return "Error: Could not retrieve data from the database. Answers will be based on general knowledge."

def get_tickets_data_as_context():
    """
    Connects to the database, fetches all tickets, and formats the data
    as a concise JSON string for the AI model
    """
    try:
        conn = connect_database()
        df = get_all_tickets(conn)
        conn.close()

        if not df.empty:
            # Prepare contextual data
            df_context = df[['id', 'priority', 'status', 'subject', 'assigned_to', 'created_date']]
            return df_context.to_json(orient='records', indent=2)
        else:
            return "No IT Ticket record found in the database."

    except Exception as e:
        # Provide a clean message to the AI even if DB fails
        st.warning(f"Warning: Error fetching data: {e}")
        return "Error: Could not retrieve data from the database. Answers will be based on general knowledge."


# Fetch the live data (runs once or when cache expires)
incident_data_context = get_incident_data_as_context()
datasets_data_context = get_datasets_data_as_context()
tickets_data_context = get_tickets_data_as_context()


DOMAIN_PROMPT = f"""
You are a Multi-Domain Intelligence Platform Assistant.

Your expertise spans the following domains:
- Cybersecurity
- Data Science
- IT Operations

You have access to LIVE system data provided below.

CYBERSECURITY INCIDENT DATA
{incident_data_context}

DATA SCIENCE DATASETS
{datasets_data_context}

IT OPERATIONS TICKETS
{tickets_data_context}

INSTRUCTIONS:
1. Use the relevant live domain data when answering questions about incidents, datasets, or IT tickets.
2. Always base summaries, statistics, or recommendations on the provided data.
3. Clearly indicate which domain your answer is based on.
4. If a domain has no available records, clearly inform the user.
5. If a question is outside the scope of the live data (e.g., theoretical questions), answer using general knowledge and ignore the database context.
6. Use the provided LIVE INCIDENT DATA to answer questions about 'incidents', 'severity', or 'status'.
7. Use the provided DATA SCIENCE DATASETS to answer questions about 'dataset_name', 'source', 'recorded_count', or 'file_size_mb'.
8. Use the provided IT OPERATIONS TICKETS to answer questions about 'tickets', 'priority', 'status', 'resolution_time_hours' or 'assigned_to'.
"""

# ----------------- CHAT HISTORY INITIALIZATION -----------------

# Initialize history, but only store the user/model messages for the API call
if "gemini_messages" not in st.session_state:
    # We use this structure for convenient display and history management
    st.session_state["gemini_messages"] = []

# ----------------- DISPLAY CHAT HISTORY -----------------

# The system prompt is ONLY for the API and is not shown in the chat history
for message in st.session_state.gemini_messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# ----------------- CHAT INPUT AND GENERATION -----------------

if prompt := st.chat_input("Ask me about a security incident, datascience datasets or it operations tickets..."):
    # 1. Add user message to history and display
    st.session_state.gemini_messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # 2. Prepare messages for the API
    # The Gemini API expects 'user' and 'model' roles in the contents list.
    api_messages = [
        {"role": m["role"], "parts": [{"text": m["content"]}]}
        for m in st.session_state.gemini_messages
    ]

    # 3. Create the configuration object for the System Prompt
    config = types.GenerateContentConfig(
        system_instruction=DOMAIN_PROMPT
    )
    try:
        # 4. Call the Gemini API
        with st.chat_message("assistant"):
            # Use streaming for a better user experience
            response_stream = client.models.generate_content_stream(
                model="gemini-2.5-flash",
                contents=api_messages,
                config=config  # Pass the system prompt via config
            )

            full_response = ""
            # Create a container to hold the streaming response
            placeholder = st.empty()

            for chunk in response_stream:
                if chunk.text:
                    full_response += chunk.text
                    placeholder.markdown(full_response + "▌")  # Show typing indicator

            placeholder.markdown(full_response)  # Final response without indicator

        # 5. Add the full response to session history
        st.session_state.gemini_messages.append({"role": "model", "content": full_response})

    except APIError as e:
        st.error(f"GenAI API Error: Please check your API key and usage limits. ({e})")
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")

# ----------------- SIDEBAR UTILITIES -----------------
with st.sidebar:
    st.subheader("Chat Options")

    # Clear chat button
    if st.button("Clear Chat History", type="secondary"):
        st.session_state["gemini_messages"] = []
        st.rerun()

    # Message Counter
    num_messages = len(st.session_state.gemini_messages)
    st.caption(f"Total messages: {num_messages}")


# ---------------- LOGOUT ----------------
st.divider()
if st.button("Log out"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.info("You have been logged out.")
    st.switch_page("Home.py")