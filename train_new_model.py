import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from nfstream import NFStreamer #type:ignore
import joblib
import numpy as np
import scapy.all as scapy
import time
import os
import psutil
import json
from multiprocessing import freeze_support

def get_network_interfaces():
    """Fetches all available network interfaces on the machine."""
    return list(psutil.net_if_addrs().keys())

def create_default_whitelist():
    """Phase 2: Creates a JSON whitelist of trusted IPs to reduce ML overhead."""
    whitelist_file = "whitelist.json"
    default_ips = [
        "8.8.8.8", "8.8.4.4",       # Google DNS
        "1.1.1.1", "1.0.0.1",       # Cloudflare DNS
        "255.255.255.255",          # Broadcast
        "127.0.0.1"                 # Localhost
    ]
    # In a real scenario, you'd dynamically add the local subnet/gateway here
    
    if not os.path.exists(whitelist_file):
        with open(whitelist_file, 'w') as f:
            json.dump(default_ips, f, indent=4)
        print(f"[*] Created default trusted IP whitelist at '{whitelist_file}'.")
    else:
        print(f"[*] Whitelist '{whitelist_file}' already exists.")

def generate_dumpcap_script(interface_name):
    """
    Phase 2: Generates a batch script for the 'Panic Button' rolling buffer.
    dumpcap writes to a ring buffer, keeping only the last 10 minutes (600 seconds) of traffic.
    """
    script_name = "start_rolling_capture.bat"
    # -b duration:600 sets the file to rotate every 10 mins
    # -w rolling_capture.pcap sets the output file
    # -q keeps it quiet
    bat_content = f'@echo off\necho Starting 10-minute rolling background capture on {interface_name}...\n"C:\\Program Files\\Wireshark\\dumpcap.exe" -i "{interface_name}" -b duration:600 -w rolling_capture.pcap -q\n'
    
    with open(script_name, 'w') as f:
        f.write(bat_content)
    print(f"[*] Created '{script_name}' for background rolling capture.")

if __name__ == '__main__':
    freeze_support() 

    print("=== AeroGuard IDS: Baseline Model Training (Phase 2) ===")
    print("Starting 'normal' traffic capture for 60 seconds...")
    print("Please browse the web normally to create a baseline of YOUR network behavior.\n")

    # --- Setup Phase 2 Assets ---
    create_default_whitelist()

    # --- Dynamic Interface Selection ---
    interfaces = get_network_interfaces()
    print("Available Network Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")
    
    try:
        selection = int(input("\nEnter the number of the interface you want to monitor (e.g., 0): "))
        if 0 <= selection < len(interfaces):
            INTERFACE_NAME = interfaces[selection]
        else:
            print("Invalid selection. Defaulting to the first interface.")
            INTERFACE_NAME = interfaces[0]
    except ValueError:
        print("Invalid input. Defaulting to the first interface.")
        INTERFACE_NAME = interfaces[0]

    # Generate the panic button background script for the chosen interface
    generate_dumpcap_script(INTERFACE_NAME)

    CAPTURE_FILE = "temp_baseline_capture.pcap"

    # --- Packet Capture ---
    print(f"\nStarting Scapy sniffer on '{INTERFACE_NAME}' for 60 seconds...")
    print("Packets will be captured in memory... Do some normal web browsing now!")
    
    try:
        packets = scapy.sniff(iface=INTERFACE_NAME, timeout=60)
                    
        print("\nCapture complete. Saving packets to temporary file...")
        scapy.wrpcap(CAPTURE_FILE, packets)
        print(f"Captured packets saved to '{CAPTURE_FILE}'.")
        
    except PermissionError:
        print("\n\n--- PERMISSION ERROR ---")
        print("Scapy requires elevated privileges to capture packets.")
        print("Please re-run this terminal or IDE as Administrator.")
        exit()
    except Exception as e:
        print(f"\n\nAn error occurred during Scapy capture: {e}")
        print("This may be a missing Npcap/WinPcap driver issue.")
        exit()

    # --- Feature Extraction via NFStream ---
    print(f"Analyzing flows from '{CAPTURE_FILE}'...")
    
    normal_flows_df = pd.DataFrame() 

    try:
        streamer = NFStreamer(source=CAPTURE_FILE)
        extracted_df = streamer.to_pandas()
        
        if extracted_df is not None:
            normal_flows_df = extracted_df
            
    except Exception as e:
        print(f"\n\nAn error occurred during Nfstream analysis: {e}")
        exit()

    try:
        os.remove(CAPTURE_FILE)
    except Exception as e:
        print(f"Warning: Could not remove {CAPTURE_FILE}. {e}")

    if normal_flows_df.empty:
        print("\nError: No flows were processed. DataFrame is empty.")
        print("Please ensure you are connected to the internet and generating traffic, then try again.")
        exit()
        
    print(f"Analysis complete. Collected {len(normal_flows_df)} network flows.")

    # --- Phase 2: Feature Engineering & Preprocessing ---
    
    # 1. Encode the categorical 'application_name' feature
    if 'application_name' in normal_flows_df.columns:
        label_encoder = LabelEncoder()
        
        # Extract to a variable first to keep typing clean
        app_names_series = normal_flows_df['application_name'].astype(str)
        normal_flows_df['application_name'] = app_names_series
        
        # FIXED: Use Python's built-in list() instead of .tolist() to satisfy Pylance
        encoded_array = label_encoder.fit_transform(app_names_series)
        normal_flows_df['app_name_encoded'] = list(encoded_array) #type: ignore
        
        joblib.dump(label_encoder, 'nstream_app_encoder.pkl')
        print("[*] Encoded 'application_name' and saved LabelEncoder.")

    # 2. Expanded feature list including Phase 2 additions
    features_to_use = [
        'protocol',                 # Added: Int representing TCP(6), UDP(17), etc.
        'bidirectional_tcp_flags',  # Added: Int representing TCP connection states
        'dst_port',
        'bidirectional_duration_ms',
        'bidirectional_packets',
        'bidirectional_bytes',
        'src2dst_packets',
        'src2dst_bytes',
        'dst2src_packets',
        'dst2src_bytes'
    ]
    
    # Add our encoded application name to the training features if it exists
    if 'app_name_encoded' in normal_flows_df.columns:
        features_to_use.append('app_name_encoded')

    available_features = [f for f in features_to_use if f in normal_flows_df.columns]
    
    if 'dst_port' not in available_features:
        print("CRITICAL ERROR: 'dst_port' is missing from the extracted features.")
        exit()
    
    if not available_features:
         print("Error: None of the selected features were found. Exiting.")
         exit()

    X_train = normal_flows_df[available_features].copy() 

    # Handle infinite values and NaNs
    X_train.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_train.fillna(0, inplace=True)

    # Scale the features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    # --- ML Model Training ---
    print("\nTraining new Isolation Forest model on captured traffic...")
    
    new_model = IsolationForest(
        n_estimators=100, 
        contamination=0.05, 
        random_state=42 
    )

    new_model.fit(X_train_scaled) 

    # --- Save Assets ---
    joblib.dump(new_model, 'nstream_model.pkl')
    joblib.dump(scaler, 'nstream_scaler.pkl')
    joblib.dump(available_features, 'nstream_features.pkl')

    print("\n=== Success ===")
    print("Saved ML models, encoders, and configuration files.")
    print("You are now ready to update and run 'app.py' to monitor live traffic.")