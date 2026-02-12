# IDS

# Network Intrusion Detection System (IDS)

An AI-powered system designed to monitor network traffic and detect anomalies in real-time. This project uses Machine Learning to classify network packets as "Normal" or "Malicious."

##  Key Features
- **Live Traffic Monitoring:** Uses Scapy to capture and inspect network packets.
- **Machine Learning Engine:** Utilizes a Random Forest (or similar) classifier to identify threats.
- **Web Dashboard:** (Optional) Integrated Flask server to visualize live system analysis.

##  Setup Instructions

### 1. Prerequisites
Ensure you have Python 3.8+ installed. You may also need to install `npcap` (for Windows) or `libpcap` (for Linux) to allow packet capturing.

### 2. Install Dependencies
```bash
pip install -r requirements.txt