import os
import time
import socketio
import requests
import pandas as pd
import psutil
import tkinter as tk
from tkinter import ttk
from scapy.all import AsyncSniffer, wrpcap
from nfstream import NFStreamer # type: ignore

# Configuration
CLOUD_SERVER_URL = "http://localhost:5000"  
TEMP_PCAP_FILE = "temp_capture.pcap"
TEMP_FEATURE_FILE = "temp_features.pkl"
SELECTED_INTERFACE = None

# Initialize SocketIO Client
sio = socketio.Client(logger=False, engineio_logger=False)

def get_network_interfaces():
    return list(psutil.net_if_addrs().keys())

def setup_interface_gui():
    """Pops up a small graphical window for the user to select their interface."""
    global SELECTED_INTERFACE
    interfaces = get_network_interfaces()
    
    root = tk.Tk()
    root.title("AeroGuard Setup")
    root.geometry("320x150")
    
    tk.Label(root, text="Select your active Network Interface:").pack(pady=15)
    
    combo = ttk.Combobox(root, values=interfaces, state="readonly", width=30)
    combo.pack()
    if interfaces:
        combo.current(0)
        
    def on_select():
        global SELECTED_INTERFACE
        SELECTED_INTERFACE = combo.get()
        root.destroy()
        
    tk.Button(root, text="Start AeroGuard Agent", bg="#3b82f6", fg="white", command=on_select).pack(pady=15)
    
    # Keep the window open until the user clicks start
    root.mainloop()

# ... [Keep your exact existing extract_features() and upload_and_cleanup() functions here] ...
def extract_features(pcap_path, output_pkl_path):
    sio.emit('agent_progress', {'status': 'Analyzing packet flows with NFStream...'})
    print(f"Analyzing flows from '{pcap_path}'...")
    try:
        streamer = NFStreamer(source=pcap_path)
        extracted_df = streamer.to_pandas()
        if extracted_df is None or extracted_df.empty:
            sio.emit('agent_progress', {'status': 'No network flows detected.'})
            return False
        columns_to_keep = ['src_ip', 'dst_ip', 'application_name', 'protocol', 'bidirectional_tcp_flags', 'dst_port', 'bidirectional_duration_ms', 'bidirectional_packets', 'bidirectional_bytes', 'src2dst_packets', 'src2dst_bytes', 'dst2src_packets', 'dst2src_bytes']
        available_columns = [col for col in columns_to_keep if col in extracted_df.columns]
        clean_df = extracted_df[available_columns].copy()
        clean_df.to_pickle(output_pkl_path)
        return True
    except Exception as e:
        sio.emit('agent_progress', {'status': f'Extraction Error: {str(e)}'})
        return False

def upload_and_cleanup():
    sio.emit('agent_progress', {'status': 'Uploading to AeroGuard Cloud...'})
    upload_url = f"{CLOUD_SERVER_URL}/upload_features"
    try:
        with open(TEMP_FEATURE_FILE, 'rb') as f:
            files = {'file': (TEMP_FEATURE_FILE, f, 'application/octet-stream')}
            response = requests.post(upload_url, files=files)
        if response.status_code == 200:
            sio.emit('agent_progress', {'status': 'Upload complete. Cloud is analyzing...'})
    except Exception as e:
        sio.emit('agent_progress', {'status': 'Connection error during upload.'})

    if os.path.exists(TEMP_PCAP_FILE): os.remove(TEMP_PCAP_FILE)
    if os.path.exists(TEMP_FEATURE_FILE): os.remove(TEMP_FEATURE_FILE)

@sio.event
def connect():
    print(f"Connected to AeroGuard Cloud at {CLOUD_SERVER_URL}")

@sio.on('trigger_agent_capture')
def on_trigger_capture(data):
    if not SELECTED_INTERFACE:
        return
        
    duration_minutes = int(data.get('duration', 1))
    duration_seconds = duration_minutes * 60
    
    try:
        # Start sniffing asynchronously
        sniffer = AsyncSniffer(iface=SELECTED_INTERFACE)
        sniffer.start()
        
        # Live countdown timer loop
        for i in range(duration_seconds):
            if not sio.connected:
                # Silently attempt reconnect if dropped
                try: sio.connect(CLOUD_SERVER_URL, transports=['websocket', 'polling'])
                except: pass
                
            percent = int((i / duration_seconds) * 100)
            time_left = duration_seconds - i
            sio.emit('agent_progress', {'status': f'Capturing... {percent}% ({time_left}s remaining)'})
            time.sleep(1)
            
        sniffer.stop()
        packets = sniffer.results
        wrpcap(TEMP_PCAP_FILE, packets)
        
        success = extract_features(TEMP_PCAP_FILE, TEMP_FEATURE_FILE)
        
        if success:
            upload_and_cleanup()
        else:
            if os.path.exists(TEMP_PCAP_FILE): os.remove(TEMP_PCAP_FILE)
            
    except Exception as e:
        if sio.connected:
            sio.emit('agent_progress', {'status': f'Capture Error: Ensure Admin rights. {str(e)}'})

if __name__ == '__main__':
    # 1. Show the GUI first
    setup_interface_gui()
    
    # 2. Connect in the background
    if SELECTED_INTERFACE:
        try:
            sio.connect(CLOUD_SERVER_URL, transports=['websocket', 'polling'], wait_timeout=10)
            print("Agent running in background...")
            sio.wait()
        except Exception as e:
            print("Failed to connect to cloud.")