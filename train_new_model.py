import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from nfstream import NFStreamer #type:ignore
import joblib
import numpy as np
import scapy.all as scapy
import time
import os
import psutil
from multiprocessing import freeze_support

def get_network_interfaces():
    """Fetches all available network interfaces on the machine."""
    return list(psutil.net_if_addrs().keys())

if __name__ == '__main__':
    # Required if you plan to compile this to an .exe later (Phase 5)
    freeze_support() 

    print("=== WinGuardian: Baseline Model Training ===")
    print("Starting 'normal' traffic capture for 60 seconds...")
    print("Please browse the web normally to create a baseline of YOUR network behavior.\n")

    # --- Phase 1: Dynamic Interface Selection ---
    interfaces = get_network_interfaces()
    print("Available Network Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")
    
    # Prompt the user to select an interface
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

    CAPTURE_FILE = "temp_baseline_capture.pcap"

    # --- Packet Capture ---
    print(f"\nStarting Scapy sniffer on '{INTERFACE_NAME}' for 60 seconds...")
    print("Packets will be captured in memory... Do some normal web browsing now!")
    
    try:
        # Sniff traffic for 60 seconds
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
    
    # FIXED: Initialize as an empty DataFrame so Pylance knows the exact type
    normal_flows_df = pd.DataFrame() 

    try:
        streamer = NFStreamer(source=CAPTURE_FILE)
        extracted_df = streamer.to_pandas()
        
        # Only assign if NFStream successfully returned data
        if extracted_df is not None:
            normal_flows_df = extracted_df
            
    except Exception as e:
        print(f"\n\nAn error occurred during Nfstream analysis: {e}")
        print("This could be a corrupted capture file.")
        exit()

    # Clean up the temporary PCAP file
    try:
        os.remove(CAPTURE_FILE)
        print(f"Removed temporary file '{CAPTURE_FILE}'.")
    except Exception as e:
        print(f"Warning: Could not remove {CAPTURE_FILE}. {e}")

    # Because we initialized it as pd.DataFrame(), Pylance knows .empty is valid
    if normal_flows_df.empty:
        print("\nError: No flows were processed. DataFrame is empty.")
        print("Please ensure you are connected to the internet and generating traffic, then try again.")
        exit()
        
    # Pylance now knows this is a DataFrame, so len() is valid
    print(f"Analysis complete. Collected {len(normal_flows_df)} network flows.")

    # --- Data Preprocessing ---
    # We stick to single-flow (nstream) features to ensure real-time speeds
    features_to_use = [
        'dst_port',
        'bidirectional_duration_ms',
        'bidirectional_packets',
        'bidirectional_bytes',
        'src2dst_packets',
        'src2dst_bytes',
        'dst2src_packets',
        'dst2src_bytes'
    ]

    # Pylance now knows .columns is valid
    available_features = [f for f in features_to_use if f in normal_flows_df.columns]
    
    if 'dst_port' not in available_features:
        print("CRITICAL ERROR: 'dst_port' is missing from the extracted features.")
        exit()
    
    if not available_features:
         print("Error: None of the selected features were found. Exiting.")
         exit()
    elif len(available_features) < len(features_to_use):
        print(f"Warning: Not all desired features were found. Using only: {available_features}")

    # Pylance now knows subscripting [...] is valid
    X_train = normal_flows_df[available_features].copy() 

    # Handle infinite values and NaNs that can occur in division-based network features
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

    print("New model trained successfully!")

    # --- Save Assets ---
    joblib.dump(new_model, 'nstream_model.pkl')
    joblib.dump(scaler, 'nstream_scaler.pkl')
    joblib.dump(available_features, 'nstream_features.pkl')

    print("\n=== Success ===")
    print("Saved 'nstream_model.pkl', 'nstream_scaler.pkl', and 'nstream_features.pkl'.")
    print("You are now ready to run 'streamlit run app.py' to monitor live traffic.")