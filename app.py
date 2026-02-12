import streamlit as st
import pandas as pd
from sklearn.preprocessing import StandardScaler
from nfstream import NFStreamer #type:ignore
import joblib
import numpy as np
import scapy.all as scapy
import time
import os
from multiprocessing import freeze_support 

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

if __name__ == '__main__':
    freeze_support()
    
    st.title("🛡️ Live Network Anomaly Detector")
    st.write("This app captures live network traffic, analyzes it with a LocalOutlierFactor model, and reports anomalies.")
    
    model, scaler, features_list = load_assets()


    INTERFACE_NAME = "Wi-Fi"
    CAPTURE_FILE = "live_capture.pcap"
    
    if st.button("Start 10-Second Live Capture"):

        if os.path.exists(CAPTURE_FILE):
            os.remove(CAPTURE_FILE)
            
        try:
            with st.spinner(f"Sniffing live traffic on '{INTERFACE_NAME}' for 10 seconds..."):
                packets = scapy.sniff(iface=INTERFACE_NAME, 
                                      timeout=10)
                scapy.wrpcap(CAPTURE_FILE, packets)
            st.success(f"Capture complete! Saved {len(packets)} packets.")
            
        except PermissionError:
            st.error("PERMISSION ERROR! Scapy could not capture. Please re-run as Administrator.")
            st.stop()
        except Exception as e:
            st.error(f"An error occurred during Scapy capture: {e}")
            st.stop()

        try:
            with st.spinner(f"Analyzing flows from '{CAPTURE_FILE}'..."):
                streamer = NFStreamer(source=CAPTURE_FILE)
                live_flows_df = streamer.to_pandas()
        except Exception as e:
            st.error(f"An error occurred during Nfstream analysis: {e}")
            st.stop()

        if live_flows_df.empty:
            st.warning("No network flows were captured. Try again.")
            st.stop()
            
        st.success(f"Analysis complete! Found {len(live_flows_df)} flows.")

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
        anomalies_df = live_flows_df[live_flows_df['Prediction'] == "Anomaly"]

        st.metric("Total Flows Processed", len(live_flows_df))
        st.metric("Anomalies Detected", len(anomalies_df))

        if len(anomalies_df) > 0:
            st.subheader("🚨 Anomalies Detected!")
            st.write("The following network flows were flagged as anomalous by the model:")

            st.dataframe(anomalies_df[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'application_name']])

            st.subheader("Download PCAP for Analysis")
            st.write("You can download the full 10-second capture to analyze these anomalies in Wireshark.")
            with open(CAPTURE_FILE, "rb") as f:
                st.download_button(
                    label="Download anomalous_capture.pcap",
                    data=f,
                    file_name="anomalous_capture.pcap",
                    mime="application/vnd.pcap"
                )
        else:
            st.success("✅ No anomalies detected in this batch.")
            
        with st.expander("Show All Processed Flows"):
            st.dataframe(live_flows_df[['src_ip', 'dst_ip', 'protocol', 'application_name', 'Prediction']])

#cd "C:\Program Files (x86)\Nmap"
#.\nmap.exe -p 1-1024 8.8.8.8 
#streamlit run app.py