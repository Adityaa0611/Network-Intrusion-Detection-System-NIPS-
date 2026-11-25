import streamlit as st
import pandas as pd
import time
import os

st.set_page_config(page_title="AI-NIPS SOC Dashboard", layout="wide", page_icon="🛡️")
st.title("🛡️ SOC Operations Dashboard: AI-Driven Intrusion Prevention")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "data", "live_logs.csv")

def load_data():
    try:
        if os.path.exists(LOG_PATH):
            df = pd.read_csv(LOG_PATH)
            return df
        return pd.DataFrame(columns=["Time", "IP", "Port", "Type", "Action"])
    except:
        return pd.DataFrame(columns=["Time", "IP", "Port", "Type", "Action"])

placeholder = st.empty()

while True:
    df = load_data()
    
    with placeholder.container():
        if not df.empty:
            col1, col2, col3 = st.columns(3)
            col1.metric("🔍 Total Network Flows", len(df))
            col2.metric("🛑 Malicious Hosts Banned", len(df[df['Action'] == 'BANNED']))
            col3.metric("🚨 Anomalies Detected", len(df[df['Type'] != 'NORMAL']))
            
            st.markdown("---")
            
            col_chart, col_table = st.columns([1, 2])
            
            with col_chart:
                st.subheader("📊 Attack Distribution")
                type_counts = df['Type'].value_counts()
                st.bar_chart(type_counts)
            
            with col_table:
                st.subheader("📡 Live Threat Ingress Stream")
                st.dataframe(df.tail(15).iloc[::-1], use_container_width=True, hide_index=True)
                
        else:
            st.info("⏳ Monitoring network traffic... Run `python src/nips_engine.py` to stream live packets.")
            
    time.sleep(1)
