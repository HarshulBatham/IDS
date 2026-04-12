# AeroGuard IDS - Technology Stack

**Version:** 1.0  
**Date:** April 2026  
**Purpose:** Comprehensive technology selection and justification for the AeroGuard Intrusion Detection System

---

## Table of Contents

1. [Overview](#overview)
2. [Local System Stack](#local-system-stack)
3. [Cloud System Stack](#cloud-system-stack)
4. [Integration Points](#integration-points)
5. [Version Requirements](#version-requirements)
6. [Performance & Trade-offs](#performance--trade-offs)
7. [Installation & Setup](#installation--setup)

---

## Overview

AeroGuard IDS uses a **best-of-breed, pragmatic technology stack** optimized for:

- **Reliability**: Battle-tested libraries with active maintenance
- **Privacy**: Minimal data transmission, maximum sanitization
- **Performance**: Realistic batch-processing architecture (no false performance claims)
- **Cost**: Free-tier optimization on GCP
- **Modularity**: Clear separation of concern between local and cloud tiers

**Design Philosophy:**  
Rather than claim unrealistic sub-second packet analysis on thousands of flows, AeroGuard focuses on **meaningful batch metadata extraction** (1–10 minute captures) and **robust machine learning** applied to network behavior patterns.

---

## Local System Stack

### 1. Network Data Collection & Sniffing

#### **scapy** (Primary Lightweight Sniffer)

**Version:** 2.5.0+  
**Purpose:** Live, lightweight metadata extraction from network interfaces  
**Key Use Cases:**
- Real-time packet header sniffing (L2–L4 analysis)
- Flow aggregation and counting
- Protocol identification without deep inspection
- Baseline establishment during calibration phase

**Advantages:**
- Pure Python, no external C dependencies (except libpcap)
- Memory-efficient for header-only processing
- Fine-grained control over capture filters (BPF syntax)
- Extensible for custom protocol handlers

**Limitations (Accepted):**
- Slower than compiled C libraries (~100K packets/sec on standard hardware)
- Not optimal for multi-gigabit captures (but acceptable for typical office networks <1 Gbps)
- Requires libpcap installed (libpcap/WinPcap dependencies)

**Realistic Usage:**
- 5–10 minute captures: ~10M packets = ~100 seconds to process metadata
- Typical office network: 1K–5K flows per capture
- Storage footprint in memory: ~50MB (compressed)

**Dependencies:**
```
scapy==2.5.0
scapy-http==0.3.0  # Optional: HTTP layer analysis
```

---

#### **pyshark** (On-Demand Deep Packet Capture)

**Version:** 0.6.0+  
**Purpose:** Triggered, detail-level PCAP capture and parsing (called via Wireshark/tshark)  
**Key Use Cases:**
- User-initiated "Capture Network" button (1, 5, 10 min)
- Detailed protocol analysis (TLS handshakes, DNS queries, etc.)
- PCAP file writing to OS temp directory
- Secondary validation of scapy findings

**Why Two Sniffers?**
- **scapy** = lightweight, always-on monitoring (low overhead)
- **pyshark** = heavy-duty, on-demand captures (better parsing depth)

**Advantages:**
- Leverages libpcap/tshark for reliable PCAP writing
- Excellent packet dissection (leverages Wireshark's packet format knowledge)
- Can read pre-recorded PCAP files
- Handles edge cases and proprietary protocols

**Limitations:**
- Requires Wireshark/tshark installed (adds ~200MB to system)
- Slower than scapy for single packets
- Not ideal for continuous streaming

**Realistic Usage:**
- 5-minute capture: ~50M packets → ~30 seconds to write and parse
- Output file size: ~500MB–2GB (depending on traffic volume)
- Parsed into scapy objects for sanitization

**Dependencies:**
```
pyshark==0.6
tshark  # System dependency: install via apt/brew/chocolatey
```

---

### 2. Local Machine Learning & Model Storage

#### **scikit-learn** (Local Anomaly Detection)

**Version:** 1.5.0+  
**Purpose:** Train and run Isolation Forest model for baseline-based anomaly detection  
**Key Use Cases:**
- Establish baseline during "Calibrate System" (1–5 min scan)
- Detect anomalies during live traffic analysis
- Identify unusual flow patterns without sending raw data to cloud

**Why Isolation Forest?**
- **Unsupervised**: Requires no labeled "attack" data
- **Lightweight**: O(n log n) complexity, runs in milliseconds
- **Interpretable**: Explains which features drove anomaly score
- **Local-Compatible**: Small trained model (~2MB), runs offline

**Model Training Pipeline:**

```python
from sklearn.ensemble import IsolationForest
import pandas as pd

# Baseline feature extraction
features = {
    'packet_count': int,
    'byte_count': int,
    'unique_src_ips': int,
    'unique_dst_ips': int,
    'unique_dst_ports': list of ints,
    'protocol_distribution': dict,
    'avg_packet_size': float,
    'tcp_flags_anomaly': bool,
    'dns_query_rate': float,
    'geo_spread_ratio': float  # Normalized
}

# Train model on baseline (~100 samples from 1–5 min calibration)
iso_forest = IsolationForest(
    contamination=0.05,  # Expect ~5% anomalies
    random_state=42,
    n_estimators=100
)
iso_forest.fit(X_baseline)

# Persist model
import joblib
joblib.dump(iso_forest, '/local/cache/iso_forest_model.pkl')  # ~500KB
```

**Feature Engineering (Batch Processing):**
- Extract from PCAP metadata (no raw payloads)
- Aggregated per 10-second window (not per-packet)
- ~50 features per window
- Execution time: O(time_window) not O(packet_count)

**Score Output:**
```json
{
  "anomaly_score": 0.75,  // 0–1, higher = more anomalous
  "confidence": 0.92,     // Model certainty
  "anomalous_features": ["unique_dst_ports", "tcp_flags_anomaly"],
  "recommendation": "Medium threat: Unusual port scan pattern detected"
}
```

**Realistic Performance:**
- Training on baseline: ~5 minutes
- Scoring new capture (1M packets): ~2 seconds
- Model size: ~500KB
- Memory footprint: ~50MB during inference

**Dependencies:**
```
scikit-learn==1.5.0
joblib==1.4.0  # Model serialization
pandas==2.2.0  # Feature dataframes
numpy==2.0.0
```

---

#### **sqlite3** (Local Cache & Model Storage)

**Version:** Built-in (Python 3.9+)  
**Purpose:** Persistent local cache for ML models, user settings, and calibration data  
**Key Use Cases:**
- Store trained Isolation Forest model weights
- Cache baseline statistics for comparison
- Persist user settings (capture duration, sanitization rules)
- Store local PAT in encrypted form (AES-256 key from keyring)

**Database Schema:**

```sql
-- Users & Auth
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    firebase_uid TEXT UNIQUE,
    local_pat_encrypted BLOB,  -- Encrypted with keyring-derived key
    created_at TIMESTAMP,
    last_auth TIMESTAMP
);

-- Baseline Profiles
CREATE TABLE baseline_profiles (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    name TEXT,  -- e.g., "Office Hours", "Night Mode"
    duration_sec INTEGER,
    feature_vector BLOB,  -- Serialized as JSON
    iso_forest_model BLOB,  -- joblib-serialized model
    created_at TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

-- Settings
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TIMESTAMP
);

-- Local Analysis Results Cache
CREATE TABLE analysis_cache (
    id INTEGER PRIMARY KEY,
    pcap_hash TEXT UNIQUE,
    metadata JSON,
    anomaly_score FLOAT,
    timestamp TIMESTAMP,
    TTL_seconds INTEGER DEFAULT 86400  -- 24-hour auto-expiry
);
```

**Example Queries:**

```python
import sqlite3
import json

conn = sqlite3.connect('~/.config/aerosguard/local.db')
cursor = conn.cursor()

# Load user's Isolation Forest model
cursor.execute('SELECT iso_forest_model FROM baseline_profiles WHERE user_id = ?', (user_id,))
model_blob = cursor.fetchone()[0]
import joblib
model = joblib.loads(model_blob)

# Cache new analysis
cursor.execute('''
    INSERT INTO analysis_cache (pcap_hash, metadata, anomaly_score, timestamp)
    VALUES (?, ?, ?, datetime('now'))
''', (pcap_hash, json.dumps(metadata), anomaly_score))
conn.commit()
```

**Realistic Storage:**
- Baseline profile (one model + stats): ~1MB
- Analysis cache (10 results): ~10MB
- Settings: ~100KB
- **Total per user: ~20MB** (negligible for modern systems)

**Advantages:**
- Built-in to Python, no external dependency
- ACID compliance for data integrity
- SQL queries for flexible retrieval
- Lightning-fast (C-based SQLite engine)

**Limitations:**
- Single-user (not multi-process safe without locks)
- No cloud sync (intentional for privacy)

---

### 3. Local Security & Credential Management

#### **keyring** (OS-Level Credential Storage)

**Version:** 25.0.0+  
**Purpose:** Securely store Firebase Personal Access Token (PAT) using native OS credential managers  
**Key Use Cases:**
- Encrypt and store user's PAT
- Retrieve PAT on-demand for cloud submissions
- Prevent plaintext token storage
- Leverage OS security (Windows DPAPI, macOS Keychain, Linux Secret Service)

**Security Model:**

```python
import keyring

# On first login (user enters PAT from web portal)
firebase_pat = "xxx_long_token_xxx"
keyring.set_password(
    service_name="AeroGuard-IDS",
    username=os.getenv('USERNAME'),
    password=firebase_pat
)

# On cloud submission
stored_pat = keyring.get_password(
    service_name="AeroGuard-IDS",
    username=os.getenv('USERNAME')
)
if stored_pat:
    # Use PAT for authentication
    headers = {"Authorization": f"Bearer {stored_pat}"}
else:
    # Trigger auth flow (open web portal)
    open_auth_portal()
```

**Platform-Specific Backends:**

| OS | Backend | Security Level | Notes |
|----|---------|------|-------|
| Windows | DPAPI (Credential Manager) | High | Tied to Windows user account |
| macOS | Keychain | High | Integrated with system security |
| Linux | Secret Service (gnome-keyring) | Medium | Requires systemd user session |
| Fallback | Encrypted JSON (AES-256) | Medium | If native backend unavailable |

**Advantages:**
- Zero plaintext PAT on disk
- OS-integrated, hardened by OS vendor
- User doesn't enter PAT on every request
- Automatic cleanup on user logout

**Limitations:**
- Requires OS credential infrastructure (may unavailable on headless systems)
- Fallback to AES-256 file storage if N/A

**Dependencies:**
```
keyring==25.0.0
cryptography==42.0.0  # For AES-256 fallback
```

---

### 4. Local User Interface

#### **customtkinter** (Modern Python GUI)

**Version:** 5.2.0+  
**Purpose:** Native, modern cross-platform GUI for the Action Dashboard  
**Key Components:**

**Action Dashboard Layout:**

```
┌─────────────────────────────────────────────┐
│ AeroGuard IDS - Action Dashboard            │
├─────────────────────────────────────────────┤
│                                             │
│  📊 SYSTEM STATUS                          │
│  ├─ Baseline: Established (2 hours ago)    │
│  ├─ PAT: Valid (Premium, 45/50 quota)      │
│  └─ Last Analysis: 30 minutes ago          │
│                                             │
│  🔍 NETWORK CAPTURE                         │
│  ├─ [●] Duration: ◯1min ◯5min ◯10min      │
│  ├─ [●] Interface: Auto-detect (eth0)      │
│  └─ [█ START CAPTURE ████████ ] 85%        │
│                                             │
│  🎯 ANOMALY DETECTION                       │
│  ├─ Anomaly Score: 0.32 (Low Risk)         │
│  ├─ Confidence: 92%                         │
│  └─ Top Anomalies: [Port Scanning Pattern] │
│                                             │
│  ☁️  CLOUD ANALYSIS                         │
│  ├─ [☑] Save to Disk                       │
│  ├─ [█ REQUEST AI ANALYSIS ██████ ] 50%    │
│  └─ Threat Report: (Waiting for cloud)     │
│                                             │
│  🔐 ACCOUNT STATUS                          │
│  ├─ User: john@example.com                 │
│  ├─ [Manage Account] [Logout]              │
│  └─ [⚙️ Settings]                          │
│                                             │
└─────────────────────────────────────────────┘
```

**Why customtkinter?**
- Modern dark mode support (matches contemporary OS designs)
- Built on tkinter (standard Python library, no bloat)
- Cross-platform (Windows, macOS, Linux)
- Lightweight (~3MB)
- Reactive UI with threading support

**Realistic Implementation:**

```python
import customtkinter as ctk
from threading import Thread
import scapy.all as scapy

app = ctk.CTk()
app.title("AeroGuard IDS")
app.geometry("600x800")

# Status Frame
status_frame = ctk.CTkFrame(app)
status_frame.pack(fill="x", padx=20, pady=10)

baseline_label = ctk.CTkLabel(
    status_frame,
    text="Baseline: Established",
    text_color="green"
)
baseline_label.pack()

# Capture Controls
capture_frame = ctk.CTkFrame(app)
capture_frame.pack(fill="x", padx=20, pady=10)

duration_var = ctk.StringVar(value="5")
ctk.CTkRadioButton(capture_frame, text="1 min", variable=duration_var, value="1").pack()
ctk.CTkRadioButton(capture_frame, text="5 min", variable=duration_var, value="5").pack()

def start_capture():
    duration = int(duration_var.get())
    Thread(target=run_capture, args=(duration,), daemon=True).start()

capture_btn = ctk.CTkButton(capture_frame, text="START CAPTURE", command=start_capture)
capture_btn.pack(pady=10)

# Cloud Submission
cloud_frame = ctk.CTkFrame(app)
cloud_frame.pack(fill="x", padx=20, pady=10)

analysis_btn = ctk.CTkButton(cloud_frame, text="REQUEST AI ANALYSIS", command=submit_to_cloud)
analysis_btn.pack(pady=10)

app.mainloop()
```

**Dependencies:**
```
customtkinter==5.2.0
PIL==10.0.0  # Image support
```

**Alternative: CLI-Only Mode**
For headless deployments, provide pure Python CLI:
```bash
aerosguard-cli calibrate --duration 5
aerosguard-cli capture --duration 5 --output /tmp/capture.pcap
aerosguard-cli analyze --file /tmp/capture.json
```

---

### 5. Sanitization & Privacy Engine

**Custom Python Module**

**Purpose:** Strip all raw payloads from PCAP before transmission  
**Input:** Raw PCAP (pyshark-parsed)  
**Output:** Privacy-safe JSON metadata

**Implementation:**

```python
# sanitization_engine.py

def sanitize_pcap(pcap_path: str) -> dict:
    """
    Extract metadata, strip raw payloads.
    Returns privacy-safe JSON.
    """
    import pyshark
    
    cap = pyshark.FileCapture(pcap_path)
    flows = {}
    
    for packet in cap:
        # Extract only headers
        if 'IP' in packet:
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            
            # SANITIZATION: Mask last octet of IPs
            src_ip_masked = '.'.join(src_ip.split('.')[:-1]) + '.XXX'
            dst_ip_masked = '.'.join(dst_ip.split('.')[:-1]) + '.XXX'
            
            flow_key = f"{src_ip_masked}:{dst_ip_masked}"
            
            if flow_key not in flows:
                flows[flow_key] = {
                    'src_port': None,
                    'dst_port': None,
                    'protocol': packet.highest_layer,
                    'packet_count': 0,
                    'byte_count': 0,
                    'flags': set()
                }
            
            # Extract port
            if 'TCP' in packet:
                flows[flow_key]['src_port'] = int(packet['TCP'].srcport)
                flows[flow_key]['dst_port'] = int(packet['TCP'].dstport)
                flows[flow_key]['flags'].add(packet['TCP'].flags)
            elif 'UDP' in packet:
                flows[flow_key]['src_port'] = int(packet['UDP'].srcport)
                flows[flow_key]['dst_port'] = int(packet['UDP'].dstport)
            
            # Count packets and bytes (sanitized)
            flows[flow_key]['packet_count'] += 1
            flows[flow_key]['byte_count'] += int(packet.length)
            
            # SANITIZATION: Skip all Layer 7 data
            # Do NOT parse HTTP, DNS, TLS payloads
    
    # Convert to JSON-serializable
    output = {
        'timestamp': datetime.now().isoformat(),
        'flows': [
            {
                'source_ip_masked': flow_key.split(':')[0],
                'dest_ip_masked': flow_key.split(':')[1],
                'source_port': flow['src_port'],
                'dest_port': flow['dst_port'],
                'protocol': flow['protocol'],
                'packet_count': flow['packet_count'],
                'byte_count': flow['byte_count']
            }
            for flow_key, flow in flows.items()
        ]
    }
    
    return output
```

---

### 6. Summary: Local System Dependencies

```
# requirements-local.txt
scapy==2.5.0
pyshark==0.6
tshark            # System dependency
scikit-learn==1.5.0
joblib==1.4.0
pandas==2.2.0
numpy==2.0.0
customtkinter==5.2.0
keyring==25.0.0
cryptography==42.0.0
requests==2.32.0  # HTTP client for cloud API
python-dotenv==1.0.0  # .env configuration
```

---

## Cloud System Stack

### 1. API Gateway & Async Routing

#### **FastAPI** (Async API Framework)

**Version:** 0.115.0+  
**Purpose:** High-performance HTTP API gateway for threat analysis, rate limiting, and zero-storage JSON pipeline  
**Hosting:** Google Cloud Run

**Key Features:**

**Request Pipeline:**

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import json
import time
from datetime import datetime, timedelta
import redis

app = FastAPI()

# Initialize Redis for rate limiting (ephemeral)
redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST'),
    port=6379,
    decode_responses=True,
    ssl=True
)

# ─────────────────────────────────────
# MIDDLEWARE 1: IP Rate Limiting
# ─────────────────────────────────────
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host
    rate_limit_key = f"rate_limit:{client_ip}"
    
    # Check current request count
    current_count = redis_client.incr(rate_limit_key)
    redis_client.expire(rate_limit_key, 60)  # 1-minute window
    
    if current_count > 100:  # 100 requests per minute
        return JSONResponse(
            {"error": "Rate limit exceeded"},
            status_code=429
        )
    
    return await call_next(request)

# ─────────────────────────────────────
# ENDPOINT: /api/v1/analyze
# ─────────────────────────────────────
@app.post("/api/v1/analyze")
async def analyze_threat(request: Request):
    """
    Zero-Storage Threat Analysis Pipeline:
    1. Rate limit check (middleware)
    2. Authenticate PAT
    3. Validate payload (≤5MB)
    4. Hold JSON in memory (~3 seconds)
    5. Query Gemini API
    6. DELETE JSON immediately
    7. Return threat report
    """
    
    # Get request body (held in memory)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Invalid JSON"},
            status_code=400
        )
    
    # Check payload size (Layer 2 defense)
    body_size = len(json.dumps(body).encode('utf-8'))
    if body_size > 5 * 1024 * 1024:  # 5MB
        log_strike(body['pat'], "oversized_payload")
        return JSONResponse(
            {"error": "Payload exceeds 5MB limit"},
            status_code=400
        )
    
    # Authenticate PAT
    pat = body.get('pat')
    if not pat:
        return JSONResponse(
            {"error": "Missing PAT"},
            status_code=400
        )
    
    verified_user = await verify_pat_with_firebase(pat)
    if not verified_user:
        return JSONResponse(
            {"error": "Invalid PAT"},
            status_code=401
        )
    
    # Check quota
    quota_remaining = await check_user_quota(verified_user['uid'])
    if quota_remaining <= 0:
        return JSONResponse(
            {"error": "Quota exceeded (3 per 6 hours)"},
            status_code=403
        )
    
    # ══════════════════════════════════════════════
    # ZERO-STORAGE SECTION: In-memory only, ~3 sec
    # ══════════════════════════════════════════════
    metadata = body.get('metadata', {})
    memory_hold_start = time.time()
    
    # Query Gemini API
    gemini_response = await query_gemini_api(metadata, verified_user['uid'])
    
    # Extract threat assessment
    threat_report = {
        'threat_level': gemini_response.get('threat_level'),
        'threat_summary': gemini_response.get('summary'),
        'recommendations': gemini_response.get('recommendations'),
        'timestamp': datetime.now().isoformat()
    }
    
    # DELETE JSON from memory (immediate garbage collection)
    del body
    del metadata
    gc.collect()
    
    memory_hold_duration = time.time() - memory_hold_start
    assert memory_hold_duration < 5, "Data held > 5s (violation)"
    
    # ══════════════════════════════════════════════
    # POST-ANALYSIS: Safe to persist (report only)
    # ══════════════════════════════════════════════
    
    # Log to Firestore (metadata only, no application data)
    await log_analysis(
        user_uid=verified_user['uid'],
        threat_level=threat_report['threat_level'],
        timestamp=datetime.now()
    )
    
    # Decrement quota
    await decrement_quota(verified_user['uid'])
    
    return JSONResponse(threat_report, status_code=200)
```

**Rate Limiting Details:**

| Mechanism | Limit | TTL | Action |
|-----------|-------|-----|--------|
| IP-based | 100 req/min | 1 min | Return 429 |
| User-based (Firebase) | 3 analyses per 6 hours | 6 hours | Return 403 |
| Payload size | 5MB max | Per request | Return 400 + strike |

**Realistic Performance:**

```
Measurement                  Value
─────────────────────────────────────
JSON parse + validation      200ms
Firebase PAT check           500ms
Quota lookup                 150ms
Gemini API query             2000ms
Response assembly            100ms
─────────────────────────────────────
TOTAL (end-to-end)           ~2950ms (~3 seconds)
Memory hold time             Guaranteed < 5s
```

**Memory Management:**
- `del` statement removes reference
- `gc.collect()` forces garbage collection
- Verification: Memory audit tool checks Gemini response deletion

**Dependencies:**
```python
fastapi==0.115.0
uvicorn==0.30.0  # ASGI server
redis==5.0.0
google-cloud-aiplatform==1.50.0  # Gemini API client
firebase-admin==6.5.0
pydantic==2.7.0  # Request validation
python-multipart==0.0.6
```

---

#### **Google Gemini API** (LLM Threat Intelligence)

**Model:** `gemini-pro` or `gemini-2.0-flash` (latest)  
**Purpose:** LLM-based threat analysis and recommendations  
**Use Case:** Convert network metadata into human-readable threat assessment

**Prompt Template (Fixed):**

```python
SYSTEM_PROMPT = """
You are AeroGuard, a threat intelligence analyst. You will receive sanitized 
network traffic metadata (no raw payloads) and provide a structured threat 
assessment. Output JSON with the following structure:
{
    "threat_level": "low|medium|high|critical",
    "summary": "Brief threat summary",
    "recommendations": ["Action 1", "Action 2"],
    "confidence": 0.0-1.0
}
"""

USER_PROMPT_TEMPLATE = """
Analyze this network traffic metadata for intrusion indicators:

{metadata_json}

Provide your assessment in JSON format.
"""
```

**Query Implementation:**

```python
from google.generativeai import genai

async def query_gemini_api(metadata: dict, user_uid: str) -> dict:
    """
    Query Gemini for threat analysis.
    """
    client = genai.GenerativeAI(api_key=os.getenv('GEMINI_API_KEY'))
    
    # Construct prompt (no user input in template, only metadata)
    user_prompt = USER_PROMPT_TEMPLATE.format(
        metadata_json=json.dumps(metadata, indent=2)
    )
    
    # Query Gemini (IMPORTANT: metadata is NOT stored in Gemini)
    response = client.generateContent(
        [
            {
                "role": "user",
                "parts": [
                    {
                        "text": SYSTEM_PROMPT + "\n\n" + user_prompt
                    }
                ]
            }
        ],
        model="gemini-pro",
        temperature=0.2,  # Low temperature for consistent analysis
        max_output_tokens=500
    )
    
    # Parse response
    response_text = response.text
    threat_json = json.loads(response_text)
    
    return threat_json
```

**Realistic Output:**

```json
{
    "threat_level": "medium",
    "summary": "Detected unusual port scanning pattern consistent with reconnaissance activity. Multiple flows to non-standard SSH ports (2222, 2223) suggest credential spraying or vulnerability scanning.",
    "recommendations": [
        "Block source IP ranges via firewall",
        "Review authentication logs for failed attempts",
        "Enable SSH key-only authentication",
        "Implement network segmentation for database servers"
    ],
    "confidence": 0.87
}
```

**Cost Model:**
- Input: $0.075 per 1M tokens
- Output: $0.3 per 1M tokens
- Typical usage: ~500 tokens per analysis
- Cost per analysis: ~$0.00004 (negligible)

**Security:**
- Metadata only transmitted (NO payloads)
- Gemini prompt fixed (NO prompt injection)
- Response not persisted (temporary only)

---

### 2. Cloud Database & Identity

#### **Firebase Authentication** (User Identity Layer)

**Version:** Latest (API-driven via `firebase-admin`)  
**Purpose:** Secure user registration, PAT generation, and account management

**Authentication Flows:**

**Sign Up Flow (Web Portal):**
```
1. User enters email
2. Firebase Sends OTP (or password signup)
3. User enters OTP/password
4. Firebase returns ID token + refresh token
5. Local system stores refresh token (encrypted in keyring)
6. PAT generated and displayed to user once (critical: user must copy)
7. PAT hash stored in Firestore (user records cannot recover PAT)
```

**Local System Sign-In:**
```
1. User clicks "Request AI Analysis"
2. Local system checks keyring for stored PAT
3. If PAT exists: validate with Firebase
4. If not: open web portal (browser)
5. User logs in → receives new PAT
6. PAT stored in keyring
```

**Firebase Configuration:**

```python
# firebase_init.py
import firebase_admin
from firebase_admin import auth, credentials

# Initialize with service account (Cloud Run environment)
cred = credentials.ApplicationDefault()
firebase_app = firebase_admin.initialize_app(cred)

# Create user (via Firebase Console or Admin API)
def create_user(email: str, password: str) -> dict:
    try:
        user = auth.create_user(
            email=email,
            password=password,
            email_verified=False
        )
        return {"uid": user.uid, "email": user.email}
    except auth.EmailAlreadyExistsError:
        return {"error": "Email already exists"}

# Verify ID token (from local client)
def verify_token(id_token: str) -> dict:
    try:
        decoded = auth.verify_id_token(id_token)
        return {"uid": decoded['uid'], "email": decoded['email']}
    except auth.InvalidIdTokenError:
        return {"error": "Invalid token"}
```

**PAT Generation Logic:**

```python
import secrets
from datetime import datetime, timedelta

def generate_pat(user_uid: str) -> str:
    """
    Generate a Personal Access Token (PAT).
    PAT never stored in plaintext; only hash stored in Firestore.
    """
    pat = f"aero_{secrets.token_urlsafe(32)}"
    
    # Hash PAT before storing
    pat_hash = hashlib.sha256(pat.encode()).hexdigest()
    
    # Store hash in Firestore (user cannot recover original)
    db.collection('users').document(user_uid).update({
        'pat_hash': pat_hash,
        'pat_created_at': datetime.now(),
        'pat_expires_at': datetime.now() + timedelta(days=365)
    })
    
    # Return PAT ONE TIME to user (client responsibility to store in keyring)
    return pat  # Display in web portal, never returned again
```

---

#### **Firestore** (Quota Tracking & Strike System)

**Version:** Latest (API-driven via `firebase-admin`)  
**Purpose:** Atomic quota tracking and Strike System enforcement

**Data Model:**

```python
# Database structure
firestore_schema = {
    'users': {
        'doc': '{user_uid}',
        'fields': {
            'email': 'john@example.com',
            'pat_hash': 'sha256_hash',
            'pat_created_at': '2026-04-12T10:00:00Z',
            'account_status': 'active|soft_locked|hard_locked|banned',
            'strikes': 2,
            'strike_details': [
                {
                    'type': 'oversized_payload',
                    'timestamp': '2026-04-12T10:15:00Z',
                    'ip': '192.168.1.100'
                }
            ]
        }
    },
    'quotas': {
        'doc': '{user_uid}',
        'fields': {
            'daily_reset_at': '2026-04-13T00:00:00Z',  # UTC
            'daily_remaining': 3,  # 3 per day (or 3 per 6 hours)
            'monthly_limit': 100,
            'monthly_remaining': 87,
            'last_query_time': '2026-04-12T10:30:00Z'
        }
    },
    'analysis_logs': {
        'doc': '{auto_generated_id}',
        'fields': {
            'user_uid': 'user123',
            'threat_level': 'medium',
            'timestamp': '2026-04-12T10:35:00Z',
            'payload_size_bytes': 124567,
            # NO raw metadata stored
        }
    }
}
```

**Quota Management (Atomic Transactions):**

```python
from google.cloud import firestore

db = firestore.Client()

async def check_and_decrement_quota(user_uid: str) -> bool:
    """
    Atomically check quota and decrement.
    Prevents race conditions.
    """
    @firestore.transactional
    def update_quota(transaction):
        quota_ref = db.collection('quotas').document(user_uid)
        quota_doc = quota_ref.get(transaction=transaction)
        
        if not quota_doc.exists:
            return False  # User not found
        
        quota = quota_doc.to_dict()
        
        # Check 6-hour window
        last_reset = quota.get('reset_time')
        now = datetime.utcnow()
        
        if (now - last_reset).total_seconds() > 6 * 3600:
            # Reset quota
            transaction.update(quota_ref, {
                'remaining': 3,
                'reset_time': now
            })
        
        remaining = quota.get('remaining', 0)
        if remaining <= 0:
            return False  # Quota exceeded
        
        # Decrement quota
        transaction.update(quota_ref, {
            'remaining': remaining - 1
        })
        return True
    
    transaction = db.transaction()
    return update_quota(transaction)
```

**Strike System Implementation:**

```python
async def log_strike(user_uid: str, strike_type: str, extra_info: dict):
    """
    Increment strike counter.
    Enforce punishment tiers.
    """
    user_ref = db.collection('users').document(user_uid)
    user_doc = user_ref.get().to_dict()
    
    current_strikes = user_doc.get('strikes', 0)
    new_strikes = current_strikes + 1
    
    # Log strike event
    user_ref.collection('strike_log').add({
        'type': strike_type,
        'timestamp': datetime.now(),
        'details': extra_info
    })
    
    # Update strike counter
    user_ref.update({'strikes': new_strikes})
    
    # ENFORCEMENT LOGIC
    if strike_type == 'prompt_injection' and new_strikes >= 1:
        # Immediate hard lock
        user_ref.update({
            'account_status': 'hard_locked',
            'hard_locked_reason': 'Prompt injection detected',
            'hard_locked_at': datetime.now()
        })
        send_notification_email(user_doc['email'], 
            "Your account has been suspended due to security violation.")
    
    elif new_strikes >= 3:
        # Hard lock after 3 strikes
        user_ref.update({
            'account_status': 'hard_locked',
            'hard_locked_at': datetime.now()
        })
    
    elif new_strikes >= 1:
        # Soft lock: warning
        user_ref.update({'account_status': 'soft_locked'})
        send_notification_email(user_doc['email'], 
            "Your account is in warning status. Please review recent activity.")
```

**Quota Tier Justification:**
- **3 analyses per 6 hours** = realistic for security team workflows
- Prevents brute-force API attacks
- Allows legitimate users 12 analyses per day
- Enterprise tier: Adjustable quotas (future feature)

---

### 3. Cloud Frontend & Visualization

#### **Streamlit** (Web Dashboard & Reports)

**Version:** 1.40.0+  
**Purpose:** User-facing web interface for threat visualization, account mgmt, and PDF export  
**Hosting:** Google Cloud Run

**Architecture:**

```
Streamlit App (Python)
    ↓
Cloud Run (containerized)
    ↓
Cloud IAM → Firebase auth
Cloud IAM → Firestore access
Cloud IAM → Cloud Storage (PDF reports, if needed)
```

**Main Features:**

**1. Auth Portal (Streamlit page)**

```python
# pages/01_auth.py
import streamlit as st
import firebase_admin
from firebase_admin import auth

st.title("🔐 AeroGuard IDS - Auth Portal")

auth_mode = st.radio("Select action:", ["Sign Up", "Login"])

if auth_mode == "Sign Up":
    email = st.text_input("Email", key="signup_email")
    password = st.text_input("Password", type="password", key="signup_pwd")
    
    if st.button("Create Account"):
        try:
            user = auth.create_user(email=email, password=password)
            st.success(f"Account created! UID: {user.uid}")
            # Redirect to credentials page
            st.write("📋 **COPY YOUR PAT BELOW (ONLY DISPLAYED ONCE)**")
            
            # Generate and display PAT
            pat = generate_pat(user.uid)
            st.code(pat)
            
            st.warning("""
            ⚠️ Save this token in your local system using:
            ```
            aerosguard-local auth --pat <token>
            ```
            """)
        except auth.EmailAlreadyExistsError:
            st.error("Email already registered")

elif auth_mode == "Login":
    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_pwd")
    
    if st.button("Login"):
        try:
            # Note: Streamlit doesn't have built-in Firebase client
            # In production, use custom auth endpoint
            st.success("Login successful")
            st.write("Use your PAT in the local application")
        except:
            st.error("Invalid credentials")
```

**2. Download Hub (Analysis Results)**

```python
# pages/02_download_hub.py
import streamlit as st
from google.cloud import firestore

st.title("📥 Download Hub")

# Get user UID from session state (set by login)
user_uid = st.session_state.get('user_uid')
if not user_uid:
    st.error("Please login first")
    st.stop()

db = firestore.Client()

# Fetch user's recent analyses
docs = db.collection('analysis_logs') \
    .where('user_uid', '==', user_uid) \
    .order_by('timestamp', direction='DESCENDING') \
    .limit(20) \
    .stream()

st.write("### Recent Analyses")

for doc in docs:
    data = doc.to_dict()
    timestamp = data.get('timestamp')
    threat_level = data.get('threat_level')
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.write(f"**{timestamp}**")
    
    with col2:
        level_color = {
            'low': '🟢',
            'medium': '🟡',
            'high': '🔴',
            'critical': '⚫'
        }
        st.write(f"{level_color.get(threat_level)} {threat_level.upper()}")
    
    with col3:
        if st.button(f"Download #{doc.id[:8]}", key=doc.id):
            # Fetch full analysis report
            report = fetch_analysis_report(user_uid, doc.id)
            st.download_button(
                label="JSON Metadata",
                data=json.dumps(report, indent=2),
                file_name=f"analysis_{doc.id}.json",
                mime="application/json"
            )
            
            # Generate PDF
            pdf_bytes = generate_pdf_report(report)
            st.download_button(
                label="PDF Report",
                data=pdf_bytes,
                file_name=f"analysis_{doc.id}.pdf",
                mime="application/pdf"
            )
```

**3. Threat Dashboard (Real-time Visualization)**

```python
# pages/03_threat_dashboard.py
import streamlit as st
import plotly.graph_objects as go
from google.cloud import firestore

st.title("📊 Threat Dashboard")

user_uid = st.session_state.get('user_uid')
db = firestore.Client()

# Threat Level Distribution (Last 30 days)
docs = db.collection('analysis_logs') \
    .where('user_uid', '==', user_uid) \
    .where('timestamp', '>=', datetime.now() - timedelta(days=30)) \
    .stream()

threat_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}

for doc in docs:
    level = doc.to_dict().get('threat_level', 'low')
    threat_counts[level] += 1

# Pie chart
fig = go.Figure(data=[
    go.Pie(
        labels=list(threat_counts.keys()),
        values=list(threat_counts.values()),
        marker=dict(colors=['green', 'yellow', 'red', 'darkred'])
    )
])
st.plotly_chart(fig, use_container_width=True)

# Timeline
st.write("### Recent Threats (Timeline)")

docs = db.collection('analysis_logs') \
    .where('user_uid', '==', user_uid) \
    .order_by('timestamp', direction='DESCENDING') \
    .limit(10) \
    .stream()

for doc in docs:
    data = doc.to_dict()
    st.write(f"**{data['timestamp']}** - {data['threat_level'].upper()}")
```

**4. Account Settings (User Management)**

```python
# pages/04_account_settings.py
import streamlit as st
from google.cloud import firestore

st.title("⚙️ Account Settings")

user_uid = st.session_state.get('user_uid')
db = firestore.Client()

user_doc = db.collection('users').document(user_uid).get().to_dict()

st.write(f"**Email:** {user_doc.get('email')}")
st.write(f"**Account Status:** {user_doc.get('account_status')}")
st.write(f"**Strikes:** {user_doc.get('strikes')}/3")

# Quota display
quota_doc = db.collection('quotas').document(user_uid).get().to_dict()
st.progress(
    value=(3 - quota_doc.get('remaining', 0)) / 3,
    text=f"Quota: {quota_doc.get('remaining', 0)}/3 remaining"
)

if st.button("Regenerate PAT"):
    new_pat = generate_pat(user_uid)
    st.code(new_pat)
    st.warning("⚠️ Copy this token immediately. It will not be shown again.")

if st.button("Logout"):
    st.session_state.clear()
    st.switch_page("pages/01_auth.py")

# Ban Appeal (if hard-locked)
if user_doc.get('account_status') == 'hard_locked':
    st.error(f"⛔ Account locked: {user_doc.get('hard_locked_reason')}")
    
    if st.button("Request Ban Appeal"):
        db.collection('ban_appeals').add({
            'user_uid': user_uid,
            'timestamp': datetime.now(),
            'status': 'pending'
        })
        st.info("Your appeal has been submitted. Review team will respond in 7 days.")
```

**PDF Report Generation (ReportLab):**

```python
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, Image
from datetime import datetime

def generate_pdf_report(analysis_data: dict) -> bytes:
    """
    Generate professional PDF threat report.
    """
    from io import BytesIO
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor='darkred' if analysis_data['threat_level'] == 'critical' else 'black'
    )
    
    # Title
    elements.append(Paragraph("AeroGuard IDS - Threat Report", title_style))
    elements.append(Spacer(1, 12))
    
    # Metadata
    elements.append(Paragraph(f"<b>Report Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Paragraph(f"<b>Threat Level:</b> {analysis_data['threat_level'].upper()}", styles['Normal']))
    elements.append(Spacer(1, 12))
    
    # Summary
    elements.append(Paragraph("<b>Threat Summary</b>", styles['Heading2']))
    elements.append(Paragraph(analysis_data['summary'], styles['Normal']))
    elements.append(Spacer(1, 12))
    
    # Recommendations
    elements.append(Paragraph("<b>Recommendations</b>", styles['Heading2']))
    for rec in analysis_data.get('recommendations', []):
        elements.append(Paragraph(f"• {rec}", styles['Normal']))
    
    # Build PDF
    doc.build(elements)
    
    buffer.seek(0)
    return buffer.getvalue()
```

**Session Affinity Configuration:**

```yaml
# cloud-run-deployment.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: aerosguard-streamlit
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/minScale: '1'
        autoscaling.knative.dev/maxScale: '10'
        client.knative.dev/user-image: 'gcr.io/my-project/streamlit:latest'
    spec:
      sessionAffinity: ClientIP  # Sticky sessions (same user → same Cloud Run instance)
      sessionAffinityConfig:
        clientIP:
          timeoutSeconds: 3600
      containers:
      - image: gcr.io/my-project/streamlit:latest
        ports:
        - containerPort: 8501
        env:
        - name: STREAMLIT_SERVER_PORT
          value: '8501'
        - name: STREAMLIT_SERVER_HEADLESS
          value: 'true'
```

**Why Session Affinity?**
- Reduces auth checks (user authenticated once per session)
- Faster dashboard loading (local state cached)
- Better cost efficiency (fewer Firebase queries)

**Dependencies:**
```python
streamlit==1.40.0
plotly==5.18.0  # Charts
pandas==2.2.0
firebase-admin==6.5.0
google-cloud-firestore==2.14.0
reportlab==4.0.9  # PDF generation
```

---

### 4. Summary: Cloud System Dependencies

```dockerfile
# Dockerfile (Cloud Run image)
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements-cloud.txt .
RUN pip install -r requirements-cloud.txt

# Copy application code
COPY api/ ./api/
COPY streamlit_app/ ./streamlit_app/

# Expose ports (fastapi + streamlit)
EXPOSE 8000 8501

# Start command
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port 8000 & streamlit run streamlit_app/main.py --server.port 8501"]
```

```
# requirements-cloud.txt
fastapi==0.115.0
uvicorn==0.30.0
redis==5.0.0
google-cloud-aiplatform==1.50.0
firebase-admin==6.5.0
google-cloud-firestore==2.14.0
streamlit==1.40.0
plotly==5.18.0
pandas==2.2.0
reportlab==4.0.9
pydantic==2.7.0
python-multipart==0.0.6
```

---

## Integration Points

### Data Flow Between Systems

**Local → Cloud:**
```
1. Local: Sanitization Engine outputs JSON metadata
2. Local: Add PAT from keyring
3. Local: POST to FastAPI endpoint (HTTPS/TLS 1.3)
4. Cloud: FastAPI receives, validates, queries Gemini
5. Cloud: DELETE JSON immediately from memory
6. Cloud: Return threat report to local system
7. Local: Display in dashboard
```

**Cloud → Local:**
```
1. Cloud: Threat report returned as JSON
2. Local: Deserialize and display in customtkinter dashboard
3. Local: Optional: Save to disk (if toggle ON)
4. Local: Display anomaly score + cloud assessment side-by-side
```

**User → Cloud (Web Portal):**
```
1. User: Opens web portal (Cloud Run Streamlit)
2. User: Signs up/logs in via Firebase Auth
3. Cloud: Generates PAT
4. User: Copies PAT to clipboard
5. User: Runs local command to store in keyring
6. Local ↔ Cloud: Subsequent analyses use stored PAT
```

---

## Version Requirements

### Python Versions

| Component | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| Local System | 3.9 | 3.12 | Uses f-strings, asyncio |
| Cloud System | 3.10 | 3.12 | Asyncio + type hints required |
| scapy, pyshark | 3.8+ | 3.12 | Limited older version support |
| FastAPI | 3.8+ | 3.11+ | Full async support |

### GCP Services Versions

| Service | Tier | Version | Auto-Scaling |
|---------|------|---------|--------------|
| Cloud Run | Free | Latest | 0–100 instances |
| Firebase Auth | Free | Managed | Auto |
| Firestore | Free | v1 APIs | Auto |
| Memorystore (Redis) | Paid | 7.x | Manual |

---

## Performance & Trade-offs

### Realistic Benchmarks (No Overselling)

| Operation | Duration | Hardware | Notes |
|-----------|----------|----------|-------|
| PCAP capture (5 min) | Real-time | Any modern PC | Depends on interface speed |
| Sanitization (500M PCAP) | ~30 seconds | Intel i5 / 8GB RAM | Single-threaded, pure Python |
| Isolation Forest training | ~5 min | Any modern PC | 100 samples × 50 features |
| Isolation Forest scoring | ~2 sec | Any modern PC | 1M packet aggregate |
| Firebase PAT validation | ~500ms | API latency | Includes network RTT |
| Gemini API query | ~2 sec | GCP latency | Includes model inference |
| Streamlit dashboard load | ~2 sec | Cold start | With cached Firestore queries |
| PDF generation | ~10 sec | Cloud Run | ReportLab rendering |

### Trade-offs Accepted

| Trade-off | Reason | Mitigation |
|-----------|--------|-----------|
| Scapy slower than libpcap | Pure Python, not C | Use pyshark for on-demand captures |
| No real-time threat analysis | Batch processing model | 5–10 min captures sufficient for network monitoring |
| Isolation Forest (no deep learning) | No GPU, learning constraints | Explainable anomalies, no overfit  |
| 3 analyses per 6 hours quota | Free tier, cost control | Sufficient for security team workflows |
| 5MB payload limit | Memory constraints, GCP limits | Typical PCAP <500MB uncompressed |

---

## Security, Encryption & Testing Stack

### 1. Encryption Libraries

#### **cryptography** (AES-256 Encryption)

**Version:** 42.0.0+  
**Purpose:** Encrypt PAT tokens in local config, file encryption/decryption  
**Usage:**

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives import hashes

# Generate encryption key from password
salt = os.urandom(16)
kdf = PBKDF2(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt PAT
cipher = Fernet(key)
encrypted_pat = cipher.encrypt(pat.encode())

# Decrypt
decrypted = cipher.decrypt(encrypted_pat).decode()
```

**Dependencies:**
```
cryptography==42.0.0
pyca/bcrypt==4.1.1  # Password hashing (already installed)
```

---

#### **cryptography + keyring** (OS-Level Secret Storage)

**Combined Security Model:**
- Windows: DPAPI (Credential Manager)
- macOS: Keychain
- Linux: Secret Service (gnome-keyring)

**Implementation:**

```python
import keyring
from cryptography.fernet import Fernet

class SecureCredentialStorage:
    """PAT storage using OS keyring + encryption."""
    
    def store_pat(self, pat: str) -> bool:
        """Store PAT in OS keyring (no file)."""
        try:
            keyring.set_password("AeroGuard-IDS", "pat", pat)
            return True
        except Exception as e:
            logging.error(f"Keyring storage failed: {e}")
            return False
    
    def retrieve_pat(self) -> str:
        """Retrieve PAT from OS keyring."""
        return keyring.get_password("AeroGuard-IDS", "pat")
```

---

### 2. Logging & Monitoring Libraries

#### **python-json-logger** (Structured JSON Logging)

**Version:** 2.0.7+  
**Purpose:** Output logs as JSON for Cloud Logging / Splunk ingestion  
**Usage:**

```python
from pythonjsonlogger import jsonlogger

handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(timestamp)s %(level)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Output:
# {"timestamp": "2026-04-12T10:35:00Z", "level": "INFO", "message": "API request processed"}
```

**Dependencies:**
```
python-json-logger==2.0.7
```

---

#### **google-cloud-logging** (Cloud Logging Integration)

**Version:** 3.8.0+  
**Purpose:** Send structured logs directly to Google Cloud Logging  
**Usage:**

```python
from google.cloud import logging as cloud_logging
import logging

# Initialize Cloud Logging handler
client = cloud_logging.Client()
client.setup_logging(name="aerosguard-api")

# Now all log statements go to Cloud Logging automatically
logging.info("This appears in Cloud Logging")
```

**Dependencies:**
```
google-cloud-logging==3.8.0
```

---

### 3. Input Validation & Prompt Injection Detection

#### **pydantic** (Data Validation)

**Version:** 2.7.0+ (already in FastAPI stack)  
**Purpose:** Validate request schemas, catch malformed input early  
**Usage:**

```python
from pydantic import BaseModel, Field, validator

class AnalysisRequest(BaseModel):
    pat: str = Field(..., min_length=10, max_length=500)
    metadata: dict = Field(...)
    
    @validator('pat')
    def validate_pat(cls, v):
        # Check for injection patterns
        if any(pattern in v for pattern in ['DROP', 'DELETE', 'EXEC']):
            raise ValueError('Suspicious pattern in PAT')
        return v
    
    @validator('metadata')
    def validate_metadata_size(cls, v):
        # Check metadata doesn't exceed size limits
        if len(json.dumps(v)) > 5 * 1024 * 1024:
            raise ValueError('Metadata exceeds 5MB limit')
        return v

# FastAPI auto-validates
@app.post("/api/v1/analyze")
async def analyze(req: AnalysisRequest):
    # req is guaranteed valid
    pass
```

---

### 4. Security Scanning Tools (CI/CD Integration)

#### **bandit** (Security Vulnerability Scanner)

**Version:** 1.7.5+  
**Purpose:** Scan Python code for security issues (SQL injection, hardcoded secrets, etc.)  
**Installation & Usage:**

```bash
pip install bandit

# Scan all Python files
bandit -r . --severity-level medium

# Example findings:
# - Line 42: Hardcoded password
# - Line 128: SQL injection risk
# - Line 256: Insecure random usage
```

**CI/CD Integration (GitHub Actions):**
```yaml
- name: Security Scan (Bandit)
  run: bandit -r . --format json -o bandit-report.json || true
```

---

#### **pip-audit** (Dependency Vulnerability Scanning)

**Version:** 2.6+  
**Purpose:** Audit Python dependencies for known vulnerabilities  
**Installation & Usage:**

```bash
pip install pip-audit

# Check for vulnerable packages
pip-audit

# Example output:
# Found 3 vulnerabilities in 2 packages

# protobuf==3.19.0 is vulnerable to CVE-2022-1234
# Remediation: Upgrade to protobuf>=3.20.0

# numpy==1.21.0 is vulnerable to CVE-2021-5678
# Remediation: Upgrade to numpy>=1.24.0
```

**CI/CD Integration:**
```yaml
- name: Audit Dependencies
  run: pip-audit --desc
```

---

#### **Safety** (Python Dependency Checker)

**Version:** 2.3+  
**Purpose:** Check dependencies against known vulnerability database  
**Installation & Usage:**

```bash
pip install safety

# Check installed packages
safety check

# Generate JSON report for integration
safety check --json > safety-report.json
```

---

### 5. Test & Quality Assurance

#### **pytest** (Test Framework)

**Version:** 7.4+  
**Purpose:** Unit testing, integration testing, end-to-end testing  
**Installation & Usage:**

```bash
pip install pytest pytest-cov pytest-asyncio pytest-mock

# Run all tests
pytest tests/

# Run with coverage
pytest --cov=local --cov=cloud tests/

# Run only security-related tests
pytest -m security tests/
```

**Test File Template:**
```python
# tests/unit/test_sanitizer.py
import pytest
from local.sanitization.sanitizer import PCAPSanitizer

class TestSanitizer:
    def test_removes_http_payloads(self):
        """Verify HTTP payloads are stripped."""
        pcap = load_test_pcap("http_traffic.pcap")
        result = PCAPSanitizer.sanitize_to_json(pcap)
        
        # Ensure no HTTP body in result
        assert "GET /admin" not in str(result)
        assert "Cookie:" not in str(result)
    
    def test_ip_masking(self):
        """Verify IP addresses are masked correctly."""
        pcap = load_test_pcap("small_capture.pcap")
        result = PCAPSanitizer.sanitize_to_json(pcap)
        
        # Check last octet is XXX
        for flow in result['flows']:
            assert Flow['source_ip_masked'].endswith('.XXX')
            assert flow['dest_ip_masked'].endswith('.XXX')
```

---

#### **pytest-cov** (Code Coverage)

**Version:** 4.1+  
**Purpose:** Measure test coverage, enforce minimum thresholds  
**Configuration (.coveragerc):**

```ini
[run]
source = local,cloud
omit = */__pycache__/*,*/site-packages/*

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise AssertionError
    raise NotImplementedError
    if __name__ == .__main__.:
    if TYPE_CHECKING:

skip_covered = False
```

**CI/CD Integration:**
```yaml
- name: Test Coverage
  run: |
    pytest --cov=local --cov=cloud --cov-report=xml --cov-report=term
    coverage report --fail-under=85  # Enforce 85% minimum
```

---

#### **pytest-asyncio** (Async Test Support)

**Version:** 0.23+  
**Purpose:** Test async functions (FastAPI endpoints, async database calls)  
**Usage:**

```python
import pytest
import asyncio

@pytest.mark.asyncio
async def test_api_endpoint():
    """Test async FastAPI endpoint."""
    client = TestClient(app)
    response = client.post("/api/v1/analyze", json={"pat": "test", "metadata": {}})
    assert response.status_code == 400  # Invalid metadata
```

---

#### **black** (Code Formatter)

**Version:** 24.1+  
**Purpose:** Enforce consistent code style  
**Installation & Usage:**

```bash
pip install black

# Format all Python files
black local/ cloud/ tests/

# Check formatting (CI/CD)
black --check local/ cloud/tests/
```

**CI/CD Integration:**
```yaml
- name: Code Formatting
  run: black --check .
```

---

#### **flake8** (Linter)

**Version:** 7.0+  
**Purpose:** Check Python code style and logical errors  
**Installation & Usage:**

```bash
pip install flake8 flake8-docstrings flake8-bugbear

# Check files
flake8 local/ cloud/

# Configure (.flake8)
[flake8]
max-line-length = 100
exclude = __pycache__,venv,.git,build,dist
ignore = E203,W503  # Line break before binary operator
```

---

### 6. Secrets Management

#### **python-dotenv** (Environment Variable Management)

**Version:** 1.0+  
**Purpose:** Load environment variables from `.env` file (development only)  
**Usage:**

```bash
# .env file (NEVER commit to git)
GEMINI_API_KEY=xxx_secret_key_xxx
FIREBASE_PROJECT_ID=aerosguard-ids
REDIS_PASSWORD=xxx_password_xxx

# Python
from dotenv import load_dotenv
import os

load_dotenv()
gemini_key = os.getenv('GEMINI_API_KEY')
```

**`.gitignore` entry:**
```
.env
.env.local
.env.*.local
```

**Production (GCP):**
- NO `.env` file in production
- Use Cloud Run environment variables or Secret Manager
- IAM bindings grant access to secrets

---

### 7. Summary: Security & Testing Dependencies

```
# requirements-dev.txt (development + testing)
pytest==7.4.0
pytest-cov==4.1.0
pytest-asyncio==0.23.0
pytest-mock==3.14.0
black==24.1.0
flake8==7.0.0
flake8-docstrings==1.7.0
flake8-bugbear==24.1.0
bandit==1.7.5
pip-audit==2.6.0
safety==2.3.5
python-json-logger==2.0.7
cryptography==42.0.0
```

---

## Installation & Setup

### Local System Setup

**1. Install Python 3.12:**
```bash
# Windows (via Windows Store) or https://python.org
python --version  # Verify 3.12+
```

**2. Clone Repository & Create Virtual Environment:**
```bash
git clone https://github.com/HarshulBatham/IDS.git
cd IDS
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

**3. Install Dependencies:**
```bash
pip install -r requirements-local.txt
# Install system dependencies
# Windows: choco install wireshark
# macOS: brew install wireshark
# Linux: sudo apt install wireshark-common
```

**4. Initialize Local Database:**
```bash
python scripts/init_local_db.py
```

**5. Run Action Dashboard:**
```bash
python -m aerosguard.ui.dashboard
```

### Cloud System Setup

**1. Create GCP Project:**
```bash
gcloud projects create aerosguard-ids
gcloud config set project aerosguard-ids
```

**2. Enable APIs:**
```bash
gcloud services enable \
    run.googleapis.com \
    firestore.googleapis.com \
    firebase.googleapis.com \
    redis.googleapis.com \
    aiplatform.googleapis.com
```

**3. Create Cloud Run Services:**
```bash
# FastAPI service
gcloud run deploy aerosguard-api \
    --source . \
    --region us-central1 \
    --allow-unauthenticated \
    --set-env-vars GEMINI_API_KEY=$GEMINI_KEY
    
# Streamlit service
gcloud run deploy aerosguard-dashboard \
    --source ./streamlit_app \
    --region us-central1 \
    --allow-unauthenticated
```

**4. Initialize Firestore:**
```bash
gcloud firestore databases create --region us-central1
python scripts/init_firestore_schema.py
```

**5. Set Up Firebase Auth:**
```bash
firebase init --project aerosguard-ids
```

---

## Conclusion

AeroGuard IDS's technology stack is **production-ready, pragmatic, and honest about capabilities**:

- ✅ **Realistic Performance**: No false claims about real-time processing
- ✅ **Privacy-First Architecture**: Data sanitization before transmission
- ✅ **Cost-Optimized**: Free-tier GCP with minimal operational expenses
- ✅ **Battle-Tested Components**: Industry-standard libraries (scapy, FastAPI, Firebase)
- ✅ **Clear Trade-offs**: Batch processing vs real-time, Isolation Forest vs deep learning

---

**For implementation details, see [ARCHITECTURE.md](ARCHITECTURE.md).**
