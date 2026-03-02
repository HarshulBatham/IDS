# 🛡️ AeroGuard IDS (Live Network Anomaly Detector)

AeroGuard is a lightweight, machine-learning-powered Intrusion Detection System (IDS) designed for edge execution. It monitors live local network traffic, flags statistical anomalies using an Isolation Forest model, and traces malicious flows back to the local software processes generating them.

## 🚀 Key Features
* **Real-Time Interface Sniffing:** Dynamically binds to active network adapters (Wi-Fi, Ethernet) to capture traffic.
* **Flow-Based ML Detection:** Translates raw packets into statistical flows using NFStream, ensuring high-speed analysis without deep payload inspection.
* **Process Attribution:** Automatically maps anomalous outbound network connections to local Process IDs (PIDs).
* **AI-Ready Architecture:** Designed to export sanitized flow metadata to Large Language Models (LLMs) for human-readable root cause analysis.
* **Privacy First:** The core ML detection runs 100% locally and offline. 

## ⚙️ Installation & Setup

**Prerequisites:**
You must have a packet capture driver installed on your host system:
* **Windows:** Install [Npcap](https://npcap.com/) (Ensure "Install Npcap in WinPcap API-compatible Mode" is checked).
* **Linux:** Install `tcpdump` (`sudo apt install tcpdump`).

**Environment Setup:**
1. Clone the repository and navigate to the directory.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt