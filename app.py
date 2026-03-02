import streamlit as st
import pandas as pd
from sklearn.preprocessing import StandardScaler
from nfstream import NFStreamer #type:ignore
import joblib
import numpy as np
import scapy.all as scapy
import time
import os
import psutil
import subprocess
from multiprocessing import freeze_support 

# --- Phase 1 & 2 Helper Functions ---

def get_network_interfaces():
    """Fetches all available network interfaces on the machine."""
    return list(psutil.net_if_addrs().keys())

def get_process_by_port(port):
    """
    Finds the local Process ID (PID) and Name utilizing a specific port.
    """
    if pd.isna(port) or port == 0:
        return None, "N/A"
        
    for conn in psutil.net_connections(kind='inet'):
        # FIXED: Check length and use index [1] to satisfy Pylance's tuple type checking
        if conn.laddr and len(conn.laddr) > 1 and conn.laddr[1] == port:
            try:
                if conn.pid is not None:
                    process = psutil.Process(conn.pid)
                    return process.pid, process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return conn.pid, "Restricted/System"
                
    return None, "Not Found (Closed)"

def block_ip_firewall(ip_address):
    """
    Agent Task Placeholder: Adds a Windows Firewall rule to block the IP.
    Note: Requires Streamlit to be run as Administrator!
    """
    try:
        rule_name = f"WinGuardian_Block_{ip_address}"
        command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip_address}'
        # Uncomment the line below to actually execute the block (USE WITH CAUTION)
        # subprocess.run(command, shell=True, check=True)
        return True
    except Exception as e:
        return False

# --- Core ML Functions ---

@st.cache_resource
def load_assets():
    """Loads the trained model, scaler, and feature list."""
    try:
        model = joblib.load('nstream_model.pkl')
        scaler = joblib.load('nstream_scaler.pkl')
        features = joblib.load('nstream_features.pkl')
    except FileNotFoundError:
        st.error("Model assets not found! Please run 'train_new_model.py' first.")
        st.stop()
    return model, scaler, features

# --- Main App Execution ---

if __name__ == '__main__':
    freeze_support()
    
    st.set_page_config(page_title="AeroGuard IDS", page_icon="🛡️", layout="wide")
    
    st.title("🛡️ AeroGuard IDS: Live System & Network Analysis")
    st.markdown("Captures live network traffic, flags anomalies using ML, and traces them to local processes.")
    
    model, scaler, features_list = load_assets()

    # --- Sidebar Configuration ---
    st.sidebar.header("Configuration")
    
    # Phase 1: Dynamic Interface Selection
    interfaces = get_network_interfaces()
    selected_interface = st.sidebar.selectbox("Select Network Interface:", interfaces, index=0)
    
    CAPTURE_FILE = "live_capture.pcap"
    
    # Phase 5 hook: "Panic Button"
    st.sidebar.divider()
    st.sidebar.subheader("Advanced Analysis")
    if st.sidebar.button("🚨 Analyze Last 10 Mins (Panic Button)"):
        st.sidebar.info("This feature is planned for Phase 3: Rolling Buffer Implementation.")

    # --- Main Capture Logic ---
    if st.button("Start 10-Second Live Capture", type="primary"):

        if os.path.exists(CAPTURE_FILE):
            os.remove(CAPTURE_FILE)
            
        try:
            with st.spinner(f"Sniffing live traffic on '{selected_interface}' for 10 seconds..."):
                packets = scapy.sniff(iface=selected_interface, timeout=10)
                scapy.wrpcap(CAPTURE_FILE, packets)
            st.success(f"Capture complete! Saved {len(packets)} packets.")
            
        except PermissionError:
            st.error("PERMISSION ERROR! Scapy could not capture. Please re-run the terminal/IDE as Administrator.")
            st.stop()
        except Exception as e:
            st.error(f"An error occurred during Scapy capture: {e}")
            st.stop()

        # FIXED: Initialize as an empty DataFrame to satisfy Pylance Type Checking
        live_flows_df = pd.DataFrame()
        
        try:
            with st.spinner(f"Analyzing flows from '{CAPTURE_FILE}' with NFStream..."):
                streamer = NFStreamer(source=CAPTURE_FILE)
                extracted_df = streamer.to_pandas()
                
                # Safely assign only if data exists
                if extracted_df is not None:
                    live_flows_df = extracted_df
                    
        except Exception as e:
            st.error(f"An error occurred during Nfstream analysis: {e}")
            st.stop()

        if live_flows_df.empty:
            st.warning("No network flows were captured. Check your network activity or try a different interface.")
            st.stop()
            
        st.success(f"Analysis complete! Processed {len(live_flows_df)} unique flows.")

        # --- ML Inference ---
        available_features_in_live = [f for f in features_list if f in live_flows_df.columns]
        if not available_features_in_live:
            st.error("The captured traffic did not contain any of the features the model was trained on.")
            st.stop()

        X_live = live_flows_df[available_features_in_live].copy()
        X_live.replace([np.inf, -np.inf], np.nan, inplace=True)
        X_live.fillna(0, inplace=True)

        X_live_scaled = scaler.transform(X_live)
        predictions = model.predict(X_live_scaled)

        live_flows_df['Prediction'] = ["Anomaly" if p == -1 else "Normal" for p in predictions]
        anomalies_df = live_flows_df[live_flows_df['Prediction'] == "Anomaly"].copy()

        col1, col2 = st.columns(2)
        col1.metric("Total Flows Processed", len(live_flows_df))
        col2.metric("Anomalies Detected", len(anomalies_df), delta_color="inverse")

        # --- Post-Detection & Response ---
        if len(anomalies_df) > 0:
            st.subheader("🚨 Anomalies Detected!")
            
            with st.spinner("Mapping network flows to local processes..."):
                pids = []
                process_names = []
                for port in anomalies_df['src_port']:
                    pid, name = get_process_by_port(port)
                    pids.append(pid)
                    process_names.append(name)
                
                anomalies_df['Local_PID'] = pids
                anomalies_df['Process_Name'] = process_names

            # Display the enriched data safely
            display_columns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'Local_PID', 'Process_Name']
            
            # Ensure columns exist before displaying to prevent any lingering strict Pylance warnings
            safe_display_cols = [col for col in display_columns if col in anomalies_df.columns]
            st.dataframe(anomalies_df[safe_display_cols], use_container_width=True)

            # Phase 4 & Post-Detection Hooks
            st.subheader("Action Center")
            action_col1, action_col2 = st.columns(2)
            
            with action_col1:
                if st.button("🧠 Send Metadata to LLM for Root Cause Analysis"):
                    st.info("LLM Integration pending (Phase 4). This will package the above row metadata into JSON and prompt the AI.")
            
            with action_col2:
                if st.button("🛑 Isolate Malicious IPs (Agent Task)"):
                    st.warning("Agent containment triggered! (Placeholder: Ensure you run as Admin to execute firewall commands).")

            st.divider()
            st.write("You can download the full capture to analyze these anomalies in Wireshark.")
            with open(CAPTURE_FILE, "rb") as f:
                st.download_button(
                    label="Download anomalous_capture.pcap",
                    data=f,
                    file_name="anomalous_capture.pcap",
                    mime="application/vnd.pcap"
                )
        else:
            st.success("✅ No anomalies detected in this batch. System looks clean.")
            
        with st.expander("Show All Processed Flows (Normal & Anomalous)"):
            st.dataframe(live_flows_df)