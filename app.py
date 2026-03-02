import streamlit as st
import pandas as pd
from nfstream import NFStreamer #type:ignore
import joblib
import numpy as np
import scapy.all as scapy
import os
import psutil
import subprocess
import json
from multiprocessing import freeze_support
from llm_integration import LLMIntegrator #type:ignore
from containment_agent import ContainmentAgent #type:ignore

# --- Phase 1 & 2 Helper Functions ---

def get_network_interfaces():
    """Fetches all available network interfaces on the machine."""
    return list(psutil.net_if_addrs().keys())

def load_whitelist():
    """Phase 2: Loads the trusted IP whitelist to reduce ML overhead."""
    try:
        with open('whitelist.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return [] # Return empty list if no whitelist exists

def get_process_by_port(port):
    """
    Finds the local Process ID (PID) and Name utilizing a specific port.
    """
    if pd.isna(port) or port == 0:
        return None, "N/A"
        
    for conn in psutil.net_connections(kind='inet'):
        # FIXED: Check length and use index [1] to satisfy Pylance
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
    """
    try:
        rule_name = f"AeroGuard_Block_{ip_address}"
        command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip_address}'
        # subprocess.run(command, shell=True, check=True)
        return True
    except Exception as e:
        return False

# --- Core ML Functions ---

@st.cache_resource
def load_assets():
    """Phase 2: Loads the trained model, scaler, feature list, and label encoder."""
    try:
        model = joblib.load('nstream_model.pkl')
        scaler = joblib.load('nstream_scaler.pkl')
        features = joblib.load('nstream_features.pkl')
        app_encoder = joblib.load('nstream_app_encoder.pkl')
    except FileNotFoundError:
        st.error("Model assets not found! Please run 'train_new_model.py' first.")
        st.stop()
    return model, scaler, features, app_encoder

# --- LLM Configuration ---

def load_llm_config():
    """Loads LLM configuration and initializes integrator."""
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            return config.get('llm_config', {})
    except FileNotFoundError:
        return {'mode': 'local'}

# --- Main App Execution ---

if __name__ == '__main__':
    freeze_support()
    
    st.set_page_config(page_title="AeroGuard IDS", page_icon="🛡️", layout="wide")
    
    st.title("🛡️ AeroGuard IDS: Live System Analysis")
    st.markdown("Captures live network traffic, flags anomalies using Phase 2 ML, and traces them to local processes.")
    
    model, scaler, features_list, app_encoder = load_assets()
    whitelist_ips = load_whitelist()
    llm_config = load_llm_config()
    llm_provider = LLMIntegrator()
    containment_agent = ContainmentAgent()

    # --- Sidebar Configuration ---
    st.sidebar.header("Configuration")
    
    # NEW: LLM Mode Selection
    st.sidebar.subheader("🧠 Phase 3: LLM Root Cause Analysis")
    llm_mode = st.sidebar.radio(
        "Select LLM Provider:",
        options=["Local (Ollama)", "Cloud (Gemini API)"],
        index=0 if llm_config.get('mode') == 'local' else 1,
        help="Local: Privacy-first, requires Ollama. Cloud: Faster, needs API key."
    )
    
    # Save user selection to config
    llm_config['mode'] = 'local' if llm_mode == "Local (Ollama)" else 'gemini'
    with open('config.json', 'w') as f:
        json.dump({'llm_config': llm_config}, f, indent=2)
    
    llm_provider.mode = llm_config['mode']
    
    interfaces = get_network_interfaces()
    selected_interface = st.sidebar.selectbox("Select Network Interface:", interfaces, index=0)
    
    CAPTURE_FILE = "live_capture.pcap"
    
    st.sidebar.divider()
    st.sidebar.subheader("Advanced Analysis")
    if st.sidebar.button("🚨 Analyze Last 10 Mins (Panic Button)"):
        st.sidebar.info("Triggering background analysis of 'rolling_capture.pcap' (Requires start_rolling_capture.bat to be running).")

    st.sidebar.divider()
    st.sidebar.markdown(f"**Trusted IPs Loaded:** {len(whitelist_ips)}")

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

        # FIXED: Initialize as empty DataFrame to satisfy Pylance Type Checking
        live_flows_df = pd.DataFrame()
        
        try:
            with st.spinner(f"Analyzing flows from '{CAPTURE_FILE}' with NFStream..."):
                streamer = NFStreamer(source=CAPTURE_FILE)
                extracted_df = streamer.to_pandas()
                
                if extracted_df is not None:
                    live_flows_df = extracted_df
                    
        except Exception as e:
            st.error(f"An error occurred during Nfstream analysis: {e}")
            st.stop()

        if live_flows_df.empty:
            st.warning("No network flows were captured. Check your network activity or try a different interface.")
            st.stop()
            
        st.success(f"Analysis complete! Processed {len(live_flows_df)} raw flows.")

        # --- Phase 2: Preprocessing & Filtering ---
        
        # 1. Filter out whitelisted IP addresses to save ML computation
        initial_count = len(live_flows_df)
        live_flows_df = live_flows_df[~live_flows_df['dst_ip'].isin(whitelist_ips)].copy()
        filtered_count = initial_count - len(live_flows_df)
        
        if filtered_count > 0:
            st.info(f"🛡️ Skipped ML analysis for {filtered_count} flows heading to trusted IPs (Whitelist applied).")

        if live_flows_df.empty:
            st.success("✅ All captured traffic matched trusted whitelist IPs. System looks clean.")
            st.stop()

        # 2. Encode application_name safely (handles unseen applications gracefully)
        if 'application_name' in live_flows_df.columns:
            # Convert to string and handle unseen labels by mapping them to -1
            known_classes = set(app_encoder.classes_)
            live_flows_df['app_name_encoded'] = live_flows_df['application_name'].astype(str).apply(
                lambda x: app_encoder.transform([x])[0] if x in known_classes else -1
            ) # type: ignore

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
        col1.metric("Flows Analyzed by ML", len(live_flows_df))
        col2.metric("Anomalies Detected", len(anomalies_df), delta_color="inverse")

        # --- Post-Detection & Response (UPDATED) ---
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

            display_columns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'application_name', 'Local_PID', 'Process_Name']
            safe_display_cols = [col for col in display_columns if col in anomalies_df.columns]
            st.dataframe(anomalies_df[safe_display_cols], use_container_width=True)

            # Phase 3: LLM Root Cause Analysis
            st.subheader("🧠 Phase 3: Root Cause Analysis")
            
            selected_anomaly_idx = st.selectbox(
                "Select an anomaly to analyze:",
                range(len(anomalies_df)),
                format_func=lambda i: f"Flow {i+1}: {anomalies_df.iloc[i]['dst_ip']}:{anomalies_df.iloc[i]['dst_port']}"
            )
            
            if st.button("🔍 Analyze with LLM", type="primary"):
                selected_row = anomalies_df.iloc[selected_anomaly_idx]
                flow_dict = selected_row.to_dict()
                
                with st.spinner(f"Querying {llm_mode} for analysis..."):
                    analysis = llm_provider.analyze_anomaly(flow_dict)
                
                st.markdown("### 📋 LLM Analysis Result")
                st.info(analysis)
                
                # Display used LLM mode
            mode_badge = "🏠 Local Ollama" if llm_mode == "Local (Ollama)" else "☁️ Gemini Cloud"

            st.divider()
            
            # Phase 4: Active Agent Containment
            st.subheader("🛑 Phase 4: Active Containment")
            
            # Show containment agent status
            with st.expander("Containment System Status"):
                status = containment_agent.get_containment_status()
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**OS:** {status['os']}")
                    st.write(f"**Admin Privileged:** {status['admin_privileged']}")
                with col2:
                    st.write(f"**Firewall Available:** {status['firewall_available']}")
                    st.write(f"**Process Control:** {status['process_control_available']}")
                
                if not status['admin_privileged']:
                    st.warning("⚠️ Run as Administrator for full containment capabilities")
            
            action_col1, action_col2, action_col3 = st.columns(3)
            
            with action_col1:
                if st.button("🛑 Block Malicious IP", key="block_ips"):
                    selected_row = anomalies_df.iloc[selected_anomaly_idx]
                    dst_ip = selected_row.get('dst_ip', 'Unknown')
                    
                    with st.spinner(f"Blocking {dst_ip}..."):
                        agent = ContainmentAgent()
                        success, message = agent.block_ip(dst_ip, direction="both")
                    
                    if success:
                        st.success(message)
                    else:
                        st.error(message)
            
            with action_col2:
                if st.button("⏸️  Suspend Process", key="suspend_proc"):
                    selected_row = anomalies_df.iloc[selected_anomaly_idx]
                    pid = selected_row.get('Local_PID')
                    
                    if pd.isna(pid) or pid is None:
                        st.warning("Cannot suspend: Process ID not identified")
                    else:
                        with st.spinner(f"Suspending PID {pid}..."):
                            agent = ContainmentAgent()
                            success, message = agent.isolate_process(int(pid), action="suspend")
                        
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
            
            with action_col3:
                if st.button("⚡ Terminate Process", key="kill_proc"):
                    selected_row = anomalies_df.iloc[selected_anomaly_idx]
                    pid = selected_row.get('Local_PID')
                    
                    if pd.isna(pid) or pid is None:
                        st.warning("Cannot terminate: Process ID not identified")
                    else:
                        st.warning(f"⚠️ This will terminate PID {pid}. Confirmation required.")
            
            st.divider()
            
            # Export & Analysis
            st.subheader("📊 Export & Analysis")
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("Download capture for Wireshark analysis:")
                with open(CAPTURE_FILE, "rb") as f:
                    st.download_button(
                        label="📥 anomalous_capture.pcap",
                        data=f,
                        file_name="anomalous_capture.pcap",
                        mime="application/vnd.pcap"
                    )
            
            with col2:
                display_cols_for_csv = [col for col in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'application_name', 'Local_PID', 'Process_Name'] if col in anomalies_df.columns]
                csv = anomalies_df[display_cols_for_csv].to_csv(index=False)
                st.download_button(
                    label="📋 Anomalies Report (CSV)",
                    data=csv,
                    file_name="anomalies_report.csv",
                    mime="text/csv"
                )
        else:
            st.success("✅ No anomalies detected in this batch. System looks clean.")
            
        with st.expander("Show All ML-Processed Flows (Normal & Anomalous)"):
            st.dataframe(live_flows_df)