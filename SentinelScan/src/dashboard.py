import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px

st.set_page_config(page_title="Security Dashboard", layout="wide")

st.title("🛡️ Pro Security Suite: Network Dashboard")

# 1. Database Connection
def get_data():
    conn = sqlite3.connect("security_suite.db")
    df = pd.read_sql_query("SELECT * FROM scans", conn)
    conn.close()
    # If the column is missing for some reason, fill it with 'LOW'
    if 'risk' not in df.columns:
        df['risk'] = 'LOW'
    return df

df = get_data()

# 2. Sidebar Filters
target_filter = st.sidebar.multiselect("Select Target IP", options=df['target'].unique())
if target_filter:
    df = df[df['target'].isin(target_filter)]

# 3. Key Metrics
col1, col2, col3 = st.columns(3)
col1.metric("Total Scans", len(df))
col2.metric("Open Ports", len(df[df['status'] == 'OPEN']))
col3.metric("Critical Risks", len(df[df['risk'] == 'HIGH']))

# 4. Charts
st.subheader("Port Status Distribution")
fig = px.pie(df, names='status', title="Scan Results Overview")
st.plotly_chart(fig, use_container_width=True)

# 5. Data Table
st.subheader("Scan History Log")
st.dataframe(df)

if st.button("Refresh Data"):
    st.rerun()