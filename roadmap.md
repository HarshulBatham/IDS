# 🗺️ Project Roadmap: AeroGuard IDS

## Phase 1: Core Foundation (Completed)
- [x] Memory-based packet capture using Scapy.
- [x] Flow extraction utilizing NFStream.
- [x] Baseline ML training using Isolation Forest.
- [x] Streamlit web UI for live monitoring and manual capture triggers.
- [x] Local Port-to-PID mapping to identify offending processes.

## Phase 2: Feature Engineering & Detection Upgrades
- [x] Refine NFStream feature extraction to include `protocol`, `application_name`, and `tcp_flags`.
- [x] Implement a rolling buffer using `dumpcap` for the "Last 10-Minute Panic Button".
- [x] Add known-good IP whitelisting (local DNS, Microsoft, Google) to reduce ML CPU overhead.

## Phase 3: Intelligent Root Cause Analysis
- [x] Build a metadata parser to strip payloads and format flow headers into JSON.
- [x] Integrate an LLM interface.
    - *Option A:* Connect to local Ollama instance for offline, private analysis.
    - *Option B:* Connect to Gemini API for cloud-based analysis.
- [x] UI Update: Add a dedicated "Threat Intel" tab in Streamlit to display LLM reasoning.

## Phase 4: Active Agent Containment
- [x] Finalize local firewall OS commands (`netsh` for Windows, `iptables` for Linux).
- [x] Allow users to click "Isolate Process" to suspend or terminate a malicious PID via `psutil`.
- [x] Real-time containment status dashboard showing admin privileges and firewall availability.

## Phase 5: Deployment & Backend Infrastructure (Future Monetization)
- [x] Compile Python codebase into a standalone `.exe` using PyInstaller with component selection.
- [x] Create an Inno Setup `.iss` installer with component selection (Lightweight vs. Full + Ollama).
- [x] Build a FastAPI backend proxy to handle cloud LLM requests, user authentication, and subscription rate-limiting.
- [x] JWT-based authentication with tier-based rate limiting (Free/Pro/Enterprise).
- [x] Analytics logging and user profile management endpoints.

## Future UI/UX Enhancements
- Switch from Streamlit to a desktop-native UI framework (like PyQt or CustomTkinter) for lower RAM usage.
- Add real-time line charts showing bytes/sec and packet rates.
- Add an "Export to PacketsTotal" button for cloud PCAP viewing.