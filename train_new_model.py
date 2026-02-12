import pandas as pd
from sklearn.neighbors import LocalOutlierFactor # Using the new model
from sklearn.preprocessing import StandardScaler
from nfstream import NFStreamer #type:ignore
import joblib
import numpy as np
import scapy.all as scapy
import time
import os
from multiprocessing import freeze_support

if __name__ == '__main__':
    freeze_support() 

    print("Starting 'normal' traffic capture for 60 seconds...")
    print("Please browse the web normally to create a baseline.")

    INTERFACE_NAME = "Wi-Fi"
    CAPTURE_FILE = "temp_capture.pcap"

    print(f"Starting Scapy sniffer on '{INTERFACE_NAME}' for 60 seconds...")
    print("Packets will be captured in memory...")
    try:
        packets = scapy.sniff(iface=INTERFACE_NAME, 
                              timeout=60)
                    
        print("\nCapture complete. Saving packets to file...")
        scapy.wrpcap(CAPTURE_FILE, packets)
        print(f"Captured packets saved to '{CAPTURE_FILE}'.")
        
    except PermissionError:
        print("\n\n--- PERMISSION ERROR ---")
        print("Scapy could not capture. Please re-run as Administrator.")
        exit()
    except Exception as e:
        print(f"\n\nAn error occurred during Scapy capture: {e}")
        print("This may be a Scapy/Npcap driver issue.")
        exit()

    print(f"Analyzing flows from '{CAPTURE_FILE}'...")
    try:
        streamer = NFStreamer(source=CAPTURE_FILE)
        normal_flows_df = streamer.to_pandas()
        
    except Exception as e:
        print(f"\n\nAn error occurred during Nfstream analysis: {e}")
        print("This could be a corrupted capture file.")
        exit()

    try:
        os.remove(CAPTURE_FILE)
        print(f"Removed temporary file '{CAPTURE_FILE}'.")
    except Exception as e:
        print(f"Warning: Could not remove {CAPTURE_FILE}. {e}")

    if normal_flows_df.empty:
        print("Error: No flows were processed. DataFrame is empty.")
        print("Please check your network activity and try again.")
        exit()
        
    print(f"Analysis complete. Collected {len(normal_flows_df)} flows.")

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

    available_features = [f for f in features_to_use if f in normal_flows_df.columns]
    
    if 'dst_port' not in available_features:
        print("CRITICAL ERROR: 'dst_port' is not in the list of columns.")
        print("Available columns:", normal_flows_df.columns.tolist())
        exit()
    
    if not available_features:
         print("Error: None of the selected features were found. Exiting.")
         exit()
    elif len(available_features) < len(features_to_use):
        print(f"Warning: Not all desired features were found. Using only: {available_features}")

    X_train = normal_flows_df[available_features].copy() 

    X_train.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_train.fillna(0, inplace=True)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    print("Training new model on captured traffic...")
    
    new_model = LocalOutlierFactor(n_neighbors=20, 
                                 contamination=0.05, 
                                 novelty=True)

    new_model.fit(X_train_scaled) 

    print("New model trained successfully!")

    joblib.dump(new_model, 'nstream_model.pkl')
    joblib.dump(scaler, 'nstream_scaler.pkl')
    joblib.dump(available_features, 'nstream_features.pkl')

    print("Saved 'nstream_model.pkl', 'nstream_scaler.pkl', and 'nstream_features.pkl'.")
    print("\n--- All Done! You are now ready for the live app.py script. ---")