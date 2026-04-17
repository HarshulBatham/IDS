# AeroGuard IDS - Implementation Roadmap

**Version:** 1.0  
**Date:** April 2026  
**Purpose:** Master phase-by-phase implementation guide for building AeroGuard IDS from the ground up

---

## Overview

This document provides a **step-by-step implementation roadmap** organized into 5 phases. Each phase builds upon the previous one, ensuring:

1. **Local features work offline first** (Phases 1–2)
2. **Cloud infrastructure is robust** (Phase 3)
3. **User-facing features are polished** (Phases 4–5)

**Key Principles:**
- Test each phase independently before moving to the next
- No cloud dependencies until Phase 3
- Local system should function as a standalone tool through Phase 2
- Integration testing critical at Phase 4 boundaries

---

## Table of Contents

1. [Phase 1: Local Data Engine](#phase-1-local-data-engine)
2. [Phase 2: Local ML & Sanitization](#phase-2-local-ml--sanitization)
3. [Phase 3: Cloud IAM & Backend](#phase-3-cloud-iam--backend)
4. [Phase 4: Cloud Frontend & Gemini Integration](#phase-4-cloud-frontend--gemini-integration)
5. [Phase 5: Polishing & Export](#phase-5-polishing--export)
6. [Testing Strategy](#testing-strategy)
7. [Deployment Checklist](#deployment-checklist)

---

## Phase 1: Local Data Engine

**Timeline:** Week 1–2  
**Objective:** Build stable, offline-capable network packet capture and temp file management  
**Dependencies:** scapy (pure Python packet capture), Python stdlib (tempfile, os)  
**Deliverable:** Standalone Python module that captures network traffic and spools to OS temp without crashing or exhausting RAM

### Key Modules & Functions to Implement

#### 1. **Startup Janitor** (`local/janitor.py`)

Secure cleanup of residual PCAP and temp files on system boot.

**Functions to Write:**

```python
# local/janitor.py

def enumerate_residual_files(temp_dir: str) -> list[Path]:
    """
    Scan OS temp directory for stale AeroGuard files.
    Return list of .pcap, .json, and temp lock files.
    
    Args:
        temp_dir: Platform-specific temp path (e.g., /tmp or %TEMP%)
    
    Returns:
        List of Path objects to be cleaned
    """
    pass

def secure_delete_file(file_path: Path, passes: int = 7) -> bool:
    """
    Securely overwrite file contents (Gutmann algorithm, 7 passes)
    before deletion.
    
    Args:
        file_path: File to delete
        passes: Number of overwrite passes (default 7)
    
    Returns:
        True if successful, False if failed
    """
    pass

def run_startup_janitor() -> dict:
    """
    Execute janitor on system boot.
    Log deletions for audit trail.
    
    Returns:
        {'deleted_count': int, 'failed_count': int, 'log': str}
    """
    pass

def register_startup_hook() -> bool:
    """
    Register janitor to run on system startup (platform-specific).
    Windows: Create scheduled task via Windows Task Scheduler
    macOS: Install launchd plist
    Linux: Add to /etc/init.d or systemd service
    
    Returns:
        True if registration successful
    """
    pass
```

**Testing:**
- Create mock temp files → run janitor → confirm deletion
- Verify no crashes on empty temp directories
- Timeout handling (janitor must complete in <5 seconds)

---

#### 2. **Network Interface Detection** (`local/network/interface_detector.py`)

Auto-detect capture-capable network interfaces.

**Functions to Write:**

```python
# local/network/interface_detector.py

def get_active_interfaces() -> list[dict]:
    """
    List all active network interfaces capable of packet capture.
    Use psutil + scapy to identify viable interfaces.
    
    Returns:
        [
            {
                'name': 'eth0',
                'ip': '192.168.1.100',
                'mac': '00:11:22:33:44:55',
                'status': 'up',
                'mtu': 1500,
                'is_loopback': False
            },
            ...
        ]
    """
    pass

def select_interface_interactive() -> str:
    """
    Prompt user to select capture interface (CLI or GUI dropdown).
    
    Returns:
        Interface name (e.g., 'eth0' or 'Ethernet' on Windows)
    """
    pass

def validate_capture_capability(interface: str) -> bool:
    """
    Verify interface can be used for packet capture.
    Test with a 1-second scapy sniff.
    
    Args:
        interface: Interface name
    
    Returns:
        True if capture-capable
    """
    pass

def get_interface_mtu(interface: str) -> int:
    """
    Retrieve Maximum Transmission Unit for interface.
    Used to estimate spooler buffer size.
    
    Args:
        interface: Interface name
    
    Returns:
        MTU in bytes (default 1500)
    """
    pass
```

**Testing:**
- Run on Windows, macOS, Linux → verify interface detection
- Test with disconnected interfaces → filter them out
- Mock interface list for unit tests

---

#### 3. **Scapy Lightweight Sniffer** (`local/network/scapy_sniffer.py`)

Live, real-time packet header sniffing (no deep inspection).

**Functions to Write:**

```python
# local/network/scapy_sniffer.py

class ScapySniffer:
    """
    Lightweight packet header sniffer using scapy.
    Runs continuously, aggregates flow statistics.
    """
    
    def __init__(self, interface: str, packet_buffer_size: int = 10000):
        self.interface = interface
        self.packet_buffer = deque(maxlen=packet_buffer_size)
        self.flow_stats = {}
        self.is_sniffing = False
    
    def packet_callback(self, packet) -> None:
        """
        Process individual packet (called by scapy for each packet).
        Extract L3/L4 headers (IP, TCP, UDP, ICMP).
        Aggregate into flow statistics.
        
        Args:
            packet: scapy Packet object
        """
        pass
    
    def start_sniffing_threaded(self) -> Thread:
        """
        Start packet capture in background thread.
        Return thread object for join/control.
        
        Returns:
            Thread running scapy.sniff()
        """
        pass
    
    def stop_sniffing(self) -> dict:
        """
        Stop capture and return aggregated statistics.
        
        Returns:
            {
                'packet_count': int,
                'flow_count': int,
                'bytes_total': int,
                'active_flows': {...}
            }
        """
        pass
    
    def get_flow_statistics(self) -> dict:
        """
        Return current flow statistics (snapshot).
        Non-blocking, for real-time dashboard updates.
        
        Returns:
            {
                'src_ip:dst_ip:protocol': {
                    'packet_count': int,
                    'bytes': int,
                    'ports': (src_port, dst_port),
                    'last_seen': timestamp
                },
                ...
            }
        """
        pass
```

**Testing:**
- Capture on active network interface → verify packet count > 0
- Mock packet objects → test flow aggregation
- Thread safety: concurrent calls to get_flow_statistics()
- Memory: long-running capture (10 min) → RAM stable at ~50MB

---

#### 4. **Scapy Packet Sniffer** (`local/network/scapy_sniffer.py`)

Pure Python packet capture for local network monitoring, written directly to OS temp files.

**Overview:**

The ScapySniffer uses Scapy (pure Python library) for packet capture. No system dependencies required (no tshark/Wireshark).
Writes directly to OS temp directory. Prevents RAM exhaustion during long captures.

**Key Features:**
- Thread-safe sniffing with live statistics
- Real-time flow tracking and aggregation
- Graceful shutdown and cleanup
- Cross-platform (Windows/macOS/Linux)
- No external system binaries needed

**Testing:**
- Capture 1/5/10 minutes → verify flow statistics
- Interrupt capture (Ctrl+C) → verify graceful shutdown
- Thread safety: concurrent reads from statistics
- Memory: long-running capture (1 hour) → RAM stable

---

## Phase 2: Local ML & Sanitization

**Timeline:** Week 3–4  
**Objective:** Build baseline calibration, anomaly detection, and PCAP → JSON sanitization  
**Dependencies:** scikit-learn, sqlite3, pandas, numpy  
**Deliverable:** Complete offline anomaly detection pipeline with persistent model storage

### Key Modules & Functions to Implement

#### 1. **Feature Extraction Engine** (`local/ml/feature_extractor.py`)

Extract meaningful features from PCAP metadata for ML model.

**Functions to Write:**

```python
# local/ml/feature_extractor.py

class FeatureExtractor:
    """
    Convert PCAP into feature vectors for ML.
    Batch processing (aggregate per 10-second windows).
    No raw payloads examined.
    """
    
    def __init__(self, window_size_sec: int = 10):
        self.window_size = window_size_sec
        self.feature_list = []
    
    def extract_features_from_pcap(self, pcap_path: str) -> pd.DataFrame:
        """
        Parse PCAP and extract features in batches.
        Return pandas DataFrame (rows = time windows, cols = features).
        
        Args:
            pcap_path: Path to PCAP file
        
        Returns:
            DataFrame with columns: [
                'packet_count', 'byte_count', 'unique_src_ips',
                'unique_dst_ips', 'unique_dst_ports', 'tcp_flag_count',
                'udp_flag_count', 'icmp_count', 'avg_packet_size',
                'protocol_entropy', 'port_range_spread', ...
            ]
        """
        pass
    
    def compute_packet_window_features(self, packets: list) -> dict:
        """
        Compute features for a 10-second window of packets.
        Helper function called by extract_features_from_pcap().
        
        Args:
            packets: List of packet dicts (IP src/dst, port, protocol)
        
        Returns:
            {
                'packet_count': int,
                'byte_count': int,
                'unique_src_ips': int,
                'unique_dst_ips': int,
                'unique_dst_ports': int,
                'avg_packet_size': float,
                'tcp_flag_count': int,
                ...
            }
        """
        pass
    
    def normalize_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize feature values (z-score normalization).
        Ensure ML model sees consistent ranges.
        
        Args:
            df: Feature DataFrame
        
        Returns:
            Normalized DataFrame
        """
        pass

def parse_pcap_to_flows(pcap_path: str) -> list[dict]:
    """
    Parse PCAP file using Scapy into flow tuples.
    Return list of flow metadata (no payloads).
    
    Args:
        pcap_path: Path to PCAP file
    
    Returns:
        [
            {
                'src_ip': '192.168.1.100',
                'dst_ip': '205.244.80.50',
                'src_port': 54321,
                'dst_port': 443,
                'protocol': 'TCP',
                'packet_count': 156,
                'byte_count': 89234,
                'timestamp': '2026-04-12T10:30:00Z'
            },
            ...
        ]
    """
    pass
```

**Testing:**
- Extract features from known PCAP files → verify feature count = expected
- Normalize features → verify mean=0, std=1
- Mock PCAP parsing → test feature computation on synthetic data
- Performance: 500M PCAP → <30 seconds

---

#### 2. **Isolation Forest Model** (`local/ml/anomaly_detector.py`)

Train and run unsupervised anomaly detection using scikit-learn.

**Functions to Write:**

```python
# local/ml/anomaly_detector.py

class IsolationForestModel:
    """
    Wrapper around scikit-learn's Isolation Forest.
    Train on baseline, score new captures.
    """
    
    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
        self.contamination = contamination  # Expected anomaly rate
        self.n_estimators = n_estimators
        self.model = None
        self.feature_scaler = None
    
    def train_on_baseline(self, feature_df: pd.DataFrame) -> dict:
        """
        Train Isolation Forest on baseline capture features.
        Called during "Calibrate System" phase (1–5 min capture).
        
        Args:
            feature_df: Feature DataFrame from baseline PCAP
        
        Returns:
            {
                'model_size_bytes': int,
                'training_samples': int,
                'model_id': str,
                'timestamp': str
            }
        """
        pass
    
    def score_anomalies(self, feature_df: pd.DataFrame) -> dict:
        """
        Score new features for anomalies.
        Return anomaly scores per sample + aggregated metrics.
        
        Args:
            feature_df: Feature DataFrame
        
        Returns:
            {
                'anomaly_scores': list[float],  # 0–1, higher = more anomalous
                'anomalous_samples': int,
                'mean_anomaly_score': float,
                'max_anomaly_score': float,
                'anomaly_threshold': float
            }
        """
        pass
    
    def explain_anomalies(self, feature_df: pd.DataFrame, 
                         anomaly_scores: list[float]) -> dict:
        """
        Identify which features drove anomaly scores.
        Explainability for user understanding.
        
        Args:
            feature_df: Feature DataFrame
            anomaly_scores: Scores from score_anomalies()
        
        Returns:
            {
                'top_anomalous_features': ['unique_dst_ports', 'port_range_spread'],
                'feature_importance': {...},
                'interpretation': "Unusual port scanning pattern detected"
            }
        """
        pass
    
    def get_model_info(self) -> dict:
        """
        Return metadata about trained model.
        
        Returns:
            {
                'n_trees': int,
                'contamination': float,
                'training_date': str,
                'baseline_packet_count': int
            }
        """
        pass
```

**Testing:**
- Train on synthetic baseline features → verify model creation
- Score synthetic anomalies (different distribution) → verify high scores
- Score baseline features → verify low scores (no false positives)
- Model serialization: save/load from disk

---

#### 3. **Sanitization Engine** (`local/sanitization/sanitizer.py`)

Strip raw payloads from PCAP, output JSON metadata.

**Functions to Write:**

```python
# local/sanitization/sanitizer.py

class PCAPSanitizer:
    """
    Convert raw PCAP to privacy-safe JSON metadata.
    Strip all Layer 7 data (payloads, passwords, keys, etc.).
    """
    
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.metadata = None
        self.sanitization_report = {}
    
    def sanitize_to_json(self) -> dict:
        """
        Main entry point: parse PCAP and output JSON.
        
        Args:
            None (uses self.pcap_path)
        
        Returns:
            {
                'capture_metadata': {...},
                'flows': [...],
                'sanitization_report': {
                    'payloads_stripped': int,
                    'http_requests_removed': int,
                    'dns_queries_removed': int,
                    'encryption_applied': bool
                }
            }
        """
        pass
    
    def mask_ip_address(self, ip: str) -> str:
        """
        Mask last octet of IP for privacy.
        Example: 192.168.1.100 → 192.168.1.XXX
        
        Args:
            ip: IP address string
        
        Returns:
            Masked IP address
        """
        pass
    
    def extract_flow_headers_only(self, packet) -> dict:
        """
        Extract only L3/L4 headers from packet.
        Skip all application-layer data.
        
        Args:
            packet: Scapy Packet object
        
        Returns:
            {
                'src_ip': '192.168.1.100',
                'dst_ip': '205.244.80.50',
                'src_port': 54321,
                'dst_port': 443,
                'protocol': 'TCP',
                'flags': ['SYN', 'ACK'],
                'length': 1234
            }
        """
        pass
    
    def aggregate_flows(self, packet_list: list) -> dict:
        """
        Aggregate individual packets into flows.
        Group by (src_ip, dst_ip, src_port, dst_port, protocol).
        
        Args:
            packet_list: List of packet header dicts
        
        Returns:
            {
                'flow_key_1': {
                    'packet_count': int,
                    'byte_count': int,
                    'duration_sec': float,
                    'flags': [...]
                },
                ...
            }
        """
        pass

def validate_sanitization(json_metadata: dict) -> bool:
    """
    Verify no raw payloads present in JSON.
    Scan for suspicious keys/values (base64, hex, etc.).
    
    Args:
        json_metadata: Sanitized JSON output
    
    Returns:
        True if clean (no payloads detected)
    """
    pass

def estimate_data_leakage(pcap_path: str, json_metadata: dict) -> dict:
    """
    Estimate what information remains in JSON vs stripped.
    For audit/transparency reporting.
    
    Args:
        pcap_path: Original PCAP
        json_metadata: Sanitized JSON
    
    Returns:
        {
            'original_size_bytes': int,
            'sanitized_size_bytes': int,
            'reduction_percent': float,
            'sensitivity_score': 0-100  # Lower = safer
        }
    """
    pass
```

**Testing:**
- Sanitize PCAP with HTTP traffic → verify no HTTP payloads in JSON
- Sanitize PCAP with DNS queries → verify no DNS query strings
- IP masking: verify last octet becomes XXX
- Size reduction: sanitized JSON < 10% of raw PCAP size
- False positive check: legitimate flow data preserved

---

#### 4. **SQLite Local Cache** (`local/storage/sqlite_cache.py`)

Persist ML models and user settings locally.

**Functions to Write:**

```python
# local/storage/sqlite_cache.py

class LocalCache:
    """
    SQLite-based persistent storage for models, settings, and baseline data.
    Creates encrypted database file.
    """
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or get_default_cache_path()
        self.connection = None
        self.init_database()
    
    def init_database(self) -> None:
        """
        Create SQLite schema on first run.
        Initialize tables: users, baselines, models, settings, cache.
        """
        pass
    
    def save_baseline_profile(self, user_id: str, capture_name: str, 
                            feature_df: pd.DataFrame, 
                            isolation_forest_model) -> str:
        """
        Save baseline profile including ML model to DB.
        Serialize model using joblib.
        
        Args:
            user_id: Local user identifier
            capture_name: User-friendly name (e.g., "Office Hours")
            feature_df: Features from baseline PCAP
            isolation_forest_model: Trained scikit-learn model
        
        Returns:
            Profile ID (UUID)
        """
        pass
    
    def load_baseline_profile(self, profile_id: str) -> dict:
        """
        Retrieve baseline profile and ML model from DB.
        Deserialize model using joblib.
        
        Args:
            profile_id: Profile UUID
        
        Returns:
            {
                'profile_id': str,
                'capture_name': str,
                'created_at': timestamp,
                'isolation_forest_model': object,
                'feature_df': pd.DataFrame
            }
        """
        pass
    
    def save_analysis_result(self, user_id: str, pcap_hash: str, 
                            metadata: dict, anomaly_score: float) -> str:
        """
        Cache analysis result for quick retrieval.
        Set TTL (e.g., 24 hours).
        
        Args:
            user_id: Local user
            pcap_hash: SHA256 hash of PCAP file
            metadata: Sanitized JSON metadata
            anomaly_score: Anomaly score from Isolation Forest
        
        Returns:
            Cache entry ID
        """
        pass
    
    def get_user_settings(self, user_id: str) -> dict:
        """
        Retrieve user settings (capture duration, interface, etc.).
        
        Args:
            user_id: Local user
        
        Returns:
            {
                'preferred_interface': 'eth0',
                'preferred_capture_duration': 300,
                'auto_save_to_disk': False,
                'sanitization_strict': True
            }
        """
        pass
    
    def set_user_settings(self, user_id: str, settings: dict) -> bool:
        """
        Save user settings to DB.
        
        Args:
            user_id: Local user
            settings: Settings dict
        
        Returns:
            True if successful
        """
        pass

def get_default_cache_path() -> str:
    """
    Get platform-specific cache directory path.
    Windows: %APPDATA%\AeroGuard\cache.db
    macOS: ~/Library/Caches/AeroGuard/cache.db
    Linux: ~/.cache/aerosguard/cache.db
    
    Returns:
        Absolute path to cache.db
    """
    pass

def calculate_pcap_hash(pcap_path: str) -> str:
    """
    Compute SHA256 hash of PCAP file (for caching/dedup).
    
    Args:
        pcap_path: Path to PCAP file
    
    Returns:
        SHA256 hex digest
    """
    pass
```

**Testing:**
- Create baseline → save to DB → load from DB → verify model equality
- Save settings → modify → load → verify persistence
- Hash calculation: same file → same hash
- Database integrity: test with large models (~5MB)

---

### Phase 2 Acceptance Criteria

- ✅ Feature extraction produces consistent feature vectors
- ✅ Isolation Forest trains in < 5 minutes on baseline
- ✅ Anomaly scoring completes in < 2 seconds for typical capture
- ✅ Sanitization removes all raw payloads (validation audit)
- ✅ SQLite persists models and settings reliably
- ✅ Entire pipeline (capture → features → anomaly score → JSON) works offline
- ✅ Unit tests for all functions (>90% coverage)

---

## Phase 3: Cloud IAM & Backend

**Timeline:** Week 5–6  
**Objective:** Build Firebase auth, Firestore quota tracking, and FastAPI gateway with 3-tier threat mitigation  
**Dependencies:** firebase-admin, fastapi, uvicorn, redis, google-cloud-aiplatform  
**Deliverable:** Production-ready cloud backend with zero-storage JSON pipeline

### Key Modules & Functions to Implement

#### 1. **Firebase Authentication & Setup** (`cloud/auth/firebase_setup.py`)

Initialize Firebase Auth, create users, manage PATs.

**Functions to Write:**

```python
# cloud/auth/firebase_setup.py

class FirebaseAuthManager:
    """
    Manage Firebase Authentication for AeroGuard.
    Handle user signup, login, PAT generation/validation.
    """
    
    def __init__(self):
        self.firebase_app = self._init_firebase()
        self.auth_client = auth.Client(credential=self.firebase_app.credential)
    
    def _init_firebase(self):
        """
        Initialize Firebase app from environment variables.
        Return authenticated Firebase app object.
        
        Returns:
            firebase_admin.App instance
        """
        pass
    
    def create_user_account(self, email: str, password: str) -> dict:
        """
        Create new Firebase user account.
        Generate initial PAT.
        
        Args:
            email: User email address
            password: User password (plain, will be hashed by Firebase)
        
        Returns:
            {
                'uid': str,
                'email': str,
                'pat': str,  # ONE-TIME DISPLAY ONLY
                'pat_created_at': timestamp
            }
        
        Raises:
            ValueError if email already exists
        """
        pass
    
    def generate_pat(self, user_uid: str) -> str:
        """
        Generate new Personal Access Token for user.
        Store hash in Firestore (not original token).
        
        Args:
            user_uid: Firebase user UID
        
        Returns:
            PAT string (displayed once to user)
        """
        pass
    
    def verify_pat(self, user_uid: str, pat_plain: str) -> bool:
        """
        Verify PAT against stored hash.
        Called by FastAPI gateway on submission.
        
        Args:
            user_uid: Firebase user UID
            pat_plain: PAT from request header
        
        Returns:
            True if PAT valid
        """
        pass
    
    def get_user_by_email(self, email: str) -> dict:
        """
        Look up user by email (for login).
        
        Args:
            email: User email
        
        Returns:
            {'uid': str, 'email': str, 'created_at': timestamp}
        
        Raises:
            ValueError if user not found
        """
        pass
    
    def revoke_pat(self, user_uid: str) -> bool:
        """
        Invalidate user's PAT (for logout/security).
        
        Args:
            user_uid: Firebase user UID
        
        Returns:
            True if successful
        """
        pass
```

**Testing:**
- Create user → verify UID generated
- Generate PAT → verify one-time display (hash in DB)
- Verify valid PAT → returns True
- Verify invalid PAT → returns False
- Lookup by email → correct UID returned

---

#### 2. **Firestore Quota & Strike System** (`cloud/storage/firestore_manager.py`)

Initialize Firestore schema, manage quotas and strike counters.

**Functions to Write:**

```python
# cloud/storage/firestore_manager.py

class FirestoreManager:
    """
    Manage Firestore database for AeroGuard.
    Quota tracking, strike system, analysis logging.
    """
    
    def __init__(self):
        self.db = firestore.Client()
        self.init_schema()
    
    def init_schema(self) -> None:
        """
        Create Firestore collections and indexes on first run.
        Define schema for users, quotas, analysis_logs, strike_log.
        Set up automatic TTL for ephemeral caches.
        """
        pass
    
    def create_user_quota(self, user_uid: str, tier: str = 'free') -> None:
        """
        Initialize quota document for new user.
        Set 3 analyses per 6 hours (free tier).
        
        Args:
            user_uid: Firebase user UID
            tier: 'free' or 'premium' (for future)
        """
        pass
    
    def check_and_decrement_quota(self, user_uid: str) -> dict:
        """
        Atomically check quota and decrement if available.
        Use Firestore transaction to prevent race conditions.
        Reset quota every 6 hours.
        
        Args:
            user_uid: Firebase user UID
        
        Returns:
            {
                'quota_available': bool,
                'remaining': int,
                'reset_time': timestamp,
                'daily_limit': int
            }
        
        Raises:
            FirebaseQuotaExceeded if quota exceeded
        """
        pass
    
    def log_analysis(self, user_uid: str, threat_level: str, 
                    payload_size_bytes: int) -> str:
        """
        Log successful analysis to Firestore.
        Store only metadata (no application data).
        
        Args:
            user_uid: Firebase user UID
            threat_level: 'low'|'medium'|'high'|'critical'
            payload_size_bytes: Size of submitted JSON
        
        Returns:
            Document ID
        """
        pass
    
    def get_user_account_status(self, user_uid: str) -> dict:
        """
        Retrieve user account status and strike info.
        
        Args:
            user_uid: Firebase user UID
        
        Returns:
            {
                'account_status': 'active'|'soft_locked'|'hard_locked'|'banned',
                'strikes': int,
                'strike_details': [...],
                'pat_hash': str,
                'created_at': timestamp
            }
        """
        pass
    
    def log_strike(self, user_uid: str, strike_type: str, 
                  extra_info: dict) -> None:
        """
        Log strike event and enforce punishment.
        Implements strike system escalation.
        
        Args:
            user_uid: Firebase user UID
            strike_type: 'malformed_json'|'oversized_payload'|
                        'rate_limit'|'prompt_injection'|'data_scraping'
            extra_info: {'ip': str, 'details': str, ...}
        """
        pass
    
    def escalate_to_soft_lock(self, user_uid: str) -> None:
        """
        Soft lock account (1–2 strikes).
        User receives warning email.
        Valid requests still processed.
        
        Args:
            user_uid: Firebase user UID
        """
        pass
    
    def escalate_to_hard_lock(self, user_uid: str, reason: str) -> None:
        """
        Hard lock account (≥3 strikes or prompt injection).
        Suspend all API access.
        Send notification email.
        
        Args:
            user_uid: Firebase user UID
            reason: Explanation for lock
        """
        pass
    
    def request_ban_appeal(self, user_uid: str, message: str) -> str:
        """
        Create ban appeal request (for hard-locked users).
        
        Args:
            user_uid: Firebase user UID
            message: User's appeal message
        
        Returns:
            Appeal ID
        """
        pass
```

**Testing:**
- Create quota → verify initial 3 remaining
- Decrement quota → verify count decreases
- Quota reset: simulate 6+ hours → verify reset
- Strike logging: log 5 strikes → verify hard lock
- Appeal creation: verify document stored

---

#### 3. **FastAPI Gateway with Rate Limiting (Layer 1)** (`cloud/api/rate_limiter.py`)

IP-based request throttling using Redis.

**Functions to Write:**

```python
# cloud/api/rate_limiter.py

class IPRateLimiter:
    """
    IP-based rate limiting for FastAPI.
    Uses Redis for ephemeral counters.
    Limit: 100 requests per minute per IP.
    """
    
    def __init__(self, redis_host: str, redis_port: int, 
                rate_limit_rpm: int = 100):
        self.redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            decode_responses=True,
            ssl=True
        )
        self.rate_limit_rpm = rate_limit_rpm
    
    async def check_rate_limit(self, client_ip: str) -> dict:
        """
        Check if client IP has exceeded rate limit.
        Increment counter in Redis (TTL: 1 minute).
        
        Args:
            client_ip: Client IP address
        
        Returns:
            {
                'allowed': bool,
                'current_count': int,
                'limit': int,
                'reset_in_seconds': int
            }
        
        Raises:
            RateLimitExceeded if quota exceeded
        """
        pass
    
    async def get_client_ip(self, request: Request) -> str:
        """
        Extract client IP from request.
        Handle X-Forwarded-For (cloud proxy scenarios).
        
        Args:
            request: FastAPI Request object
        
        Returns:
            Client IP address
        """
        pass
    
    def reset_rate_limit_for_ip(self, client_ip: str) -> bool:
        """
        Administrative function: reset rate limit for IP (whitelist).
        
        Args:
            client_ip: Client IP address
        
        Returns:
            True if successful
        """
        pass
```

**Testing:**
- Submit 100 requests/min from IP → all allowed
- Submit 101st request → rejected with 429
- Wait >60 sec → counter resets
- Mock Redis operations → verify key expiration

---

#### 4. **FastAPI Payload Validator (Layer 2)** (`cloud/api/validator.py`)

JSON schema validation and payload size limit enforcement.

**Functions to Write:**

```python
# cloud/api/validator.py

class PayloadValidator:
    """
    Validate and sanitize incoming API requests.
    Check payload size (≤5MB), schema, malformed JSON.
    """
    
    MAX_PAYLOAD_SIZE = 5 * 1024 * 1024  # 5MB
    
    EXPECTED_SCHEMA = {
        "type": "object",
        "required": ["pat", "metadata"],
        "properties": {
            "pat": {"type": "string"},
            "metadata": {
                "type": "object",
                "required": ["capture_metadata", "flows"],
                "properties": {
                    "capture_metadata": {"type": "object"},
                    "flows": {"type": "array"}
                }
            }
        }
    }
    
    @staticmethod
    def validate_request(body: dict) -> dict:
        """
        Validate request body against schema.
        Check size, structure, and required fields.
        
        Args:
            body: Request JSON body
        
        Returns:
            {'valid': bool, 'errors': [str]}
        """
        pass
    
    @staticmethod
    def check_payload_size(body_bytes: int) -> dict:
        """
        Check if payload exceeds 5MB limit.
        
        Args:
            body_bytes: Size of request body in bytes
        
        Returns:
            {'valid': bool, 'size_mb': float, 'limit_mb': float}
        """
        pass
    
    @staticmethod
    def detect_malformed_json(body_text: str) -> dict:
        """
        Attempt to parse JSON and report errors.
        Catch and log malformed requests.
        
        Args:
            body_text: Raw request text
        
        Returns:
            {'is_valid_json': bool, 'error': str|None}
        """
        pass
    
    @staticmethod
    def detect_prompt_injection(pat: str, metadata: dict) -> bool:
        """
        Heuristic detection of prompt injection attempts.
        Check for suspicious keywords (SQL, shell, code execution, etc.).
        
        Args:
            pat: User's PAT (shouldn't contain code)
            metadata: Metadata dict
        
        Returns:
            True if suspicious pattern detected
        """
        pass

# Define schema validation function
def validate_json_schema(data: dict, schema: dict) -> tuple[bool, list]:
    """
    Validate JSON against schema using jsonschema library.
    
    Args:
        data: Data to validate
        schema: JSON schema dict
    
    Returns:
        (is_valid, error_list)
    """
    pass
```

**Testing:**
- Submit valid JSON < 5MB → passes
- Submit JSON > 5MB → rejected with 400
- Submit malformed JSON → rejected with 400
- Submit JSON with prompt injection keywords → flagged
- Missing required fields → rejected

---

#### 5. **FastAPI Zero-Storage Analysis Pipeline (Layer 3)** (`cloud/api/gateway.py`)

Main API endpoint with 3-layer defense and in-memory processing.

**Functions to Write:**

```python
# cloud/api/gateway.py

app = FastAPI()

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """
    FastAPI middleware for IP-based rate limiting.
    Check rate limit before processing request.
    """
    pass

@app.post("/api/v1/analyze")
async def analyze_threat(request: Request) -> dict:
    """
    Main endpoint for threat analysis.
    
    Processing pipeline:
    1. Rate limit check (Layer 1: IP-based)
    2. PAT authentication
    3. Payload size validation (Layer 2: 5MB max)
    4. Quota check (read from Firestore)
    5. JSON schema validation
    6. [ZERO-STORAGE ZONE] Hold metadata in memory ~3 seconds
    7. Query Gemini API with metadata
    8. DELETE metadata from memory (immediate)
    9. Log analysis result (metadata only)
    10. Decrement quota (Firestore transaction)
    11. Return threat report
    
    Args:
        request: FastAPI Request
    
    Returns:
        {
            'threat_level': 'low'|'medium'|'high'|'critical',
            'threat_summary': str,
            'recommendations': [str],
            'timestamp': str
        }
    """
    pass

async def authenticate_pat(pat: str) -> dict:
    """
    Validate PAT with Firebase.
    Return user UID.
    
    Args:
        pat: Personal Access Token from request
    
    Returns:
        {'uid': str, 'email': str}
    
    Raises:
        InvalidAuthError if PAT invalid
    """
    pass

async def query_gemini_api(metadata: dict, user_uid: str) -> dict:
    """
    Query Google Gemini for threat intelligence.
    Data held in memory only (~3 sec).
    CRITICAL: Immediately delete metadata after response.
    
    Args:
        metadata: Sanitized JSON metadata (dict)
        user_uid: User UID (for logging only)
    
    Returns:
        {
            'threat_level': str,
            'summary': str,
            'recommendations': [str],
            'confidence': float
        }
    """
    pass

async def delete_sensitive_data(metadata: dict) -> bool:
    """
    Force deletion of sensitive data from memory.
    Call del, gc.collect() to ensure cleanup.
    
    Args:
        metadata: Dict to delete
    
    Returns:
        True if successful
    """
    pass

@app.post("/api/v1/health")
async def health_check() -> dict:
    """
    Health check endpoint (no auth required).
    Verify all dependencies (Firebase, Redis, Gemini).
    
    Returns:
        {'status': 'ok'|'degraded', 'components': {...}}
    """
    pass

@app.get("/metrics")
async def get_metrics() -> dict:
    """
    Internal metrics endpoint (auth required).
    Return request count, error rates, quota usage.
    
    Returns:
        {'requests_today': int, 'errors_today': int, ...}
    """
    pass
```

**Testing:**
- Valid request → 200 OK with threat report
- Invalid PAT → 401 Unauthorized
- Oversized payload → 400 Bad Request + strike
- Quota exceeded → 403 Forbidden
- Rate limit exceeded → 429 Too Many Requests
- Prompt injection detected → 400 + hard lock
- Memory audit: verify metadata deleted after 5 seconds

---

#### 6. **Strike System Enforcement** (`cloud/security/strike_system.py`)

Implement graduated punishment for abuse.

**Functions to Write:**

```python
# cloud/security/strike_system.py

class StrikeSystem:
    """
    Graduated enforcement system for misbehavior.
    Warning (1–2 strikes) → Hard Lock (≥3 strikes).
    """
    
    STRIKE_VALUES = {
        'malformed_json': 1,
        'oversized_payload': 1,
        'rate_limit': 2,
        'prompt_injection': 3,
        'data_scraping': 3
    }
    
    @staticmethod
    def add_strike(user_uid: str, strike_type: str, 
                  extra_info: dict = None) -> dict:
        """
        Add strike to user account.
        Automatically escalate if threshold exceeded.
        
        Args:
            user_uid: Firebase user UID
            strike_type: Type of violation
            extra_info: Additional context (IP, details)
        
        Returns:
            {
                'new_strike_count': int,
                'action_taken': 'warning'|'soft_lock'|'hard_lock',
                'message': str
            }
        """
        pass
    
    @staticmethod
    def handle_soft_lock(user_uid: str) -> None:
        """
        Soft lock: warning state.
        User receives email warning.
        Valid API requests still processed.
        Malformed requests dropped with 15-min cooldown.
        
        Args:
            user_uid: Firebase user UID
        """
        pass
    
    @staticmethod
    def handle_hard_lock(user_uid: str, reason: str) -> None:
        """
        Hard lock: account suspended.
        All API requests rejected.
        Send notification email.
        Enable ban appeal process.
        
        Args:
            user_uid: Firebase user UID
            reason: Explanation for suspension
        """
        pass
    
    @staticmethod
    def process_ban_appeal(appeal_id: str, approved: bool, 
                          admin_notes: str) -> None:
        """
        Process ban appeal (manual admin operation).
        Either reinstate account or deny appeal.
        
        Args:
            appeal_id: Appeal document ID
            approved: Boolean approval decision
            admin_notes: Admin's explanation
        """
        pass
```

**Testing:**
- Log 1 strike → soft lock
- Soft lock: valid request → allowed, malformed → dropped
- Log 3+ strikes → hard lock
- Hard lock: all requests → 403 Forbidden
- Appeal process: create, approve, reinstate account

---

### Phase 3 Acceptance Criteria

- ✅ Firebase Auth creates users and generates PATs
- ✅ Firestore quotas track and reset correctly (6-hour window)
- ✅ Redis rate limiting blocks >100 req/min per IP
- ✅ Payload validator enforces 5MB limit
- ✅ Strike system soft locks at 1–2 strikes, hard locks at ≥3
- ✅ Zero-storage pipeline: metadata deleted within 5s of Gemini query
- ✅ All API endpoints have comprehensive error handling
- ✅ Memory audit confirms no data persisted after request
- ✅ Integration tests: full request → response → deletion cycle

---

## Phase 4: Cloud Frontend & Gemini Integration

**Timeline:** Week 7–8  
**Objective:** Build Streamlit web portal, auth flow, and Gemini threat intelligence  
**Dependencies:** streamlit, plotly, google-generativeai, firebase-admin  
**Deliverable:** User-facing web application with threat dashboard and local PAT integration

### Key Modules & Functions to Implement

#### 1. **Streamlit Web Application Setup** (`cloud/ui/streamlit_app.py`)

Main Streamlit application with multi-page structure.

**Functions to Write:**

```python
# cloud/ui/streamlit_app.py

import streamlit as st
from google.cloud import firestore
from firebase_admin import auth
import json

# ──────────────────────────────────────────────
# SESSION STATE & INITIALIZATION
# ──────────────────────────────────────────────

def init_session_state() -> None:
    """
    Initialize Streamlit session state variables.
    Persist authentication and UI state across reruns.
    """
    pass

def is_user_authenticated() -> bool:
    """
    Check if current user is authenticated.
    Verify session token with Firebase.
    
    Returns:
        True if authenticated
    """
    pass

def get_current_user() -> dict:
    """
    Get authenticated user's info.
    
    Returns:
        {'uid': str, 'email': str}
    """
    pass

# ──────────────────────────────────────────────
# AUTHENTICATION PORTAL (pages/01_auth.py)
# ──────────────────────────────────────────────

def render_auth_page() -> None:
    """
    Render authentication portal (signup/login).
    Called by Streamlit page: pages/01_auth.py
    """
    pass

def handle_signup(email: str, password: str) -> dict:
    """
    Create new Firebase user account.
    Generate and display PAT (one-time only).
    
    Args:
        email: User email
        password: User password
    
    Returns:
        {
            'success': bool,
            'uid': str,
            'pat': str,  # Display and log to user
            'error': str|None
        }
    """
    pass

def handle_login(email: str, password: str) -> dict:
    """
    Authenticate existing user.
    Return session token for subsequent requests.
    
    Args:
        email: User email
        password: User password
    
    Returns:
        {
            'success': bool,
            'uid': str,
            'session_token': str,
            'error': str|None
        }
    """
    pass

# ──────────────────────────────────────────────
# DOWNLOAD HUB (pages/02_download_hub.py)
# ──────────────────────────────────────────────

def render_download_hub() -> None:
    """
    List user's recent analyses with download options.
    Called by: pages/02_download_hub.py
    """
    pass

def fetch_user_analyses(user_uid: str, limit: int = 20) -> list[dict]:
    """
    Retrieve user's recent analyses from Firestore.
    
    Args:
        user_uid: Firebase user UID
        limit: Max results to return
    
    Returns:
        [
            {
                'id': str,
                'timestamp': str,
                'threat_level': str,
                'payload_size_bytes': int,
                'metadata': dict
            },
            ...
        ]
    """
    pass

def download_analysis_as_json(analysis_id: str) -> str:
    """
    Format analysis result as JSON for download.
    
    Args:
        analysis_id: Analysis document ID
    
    Returns:
        JSON string (can be streamed to user)
    """
    pass
```

**Testing:**
- Signup → verify user created in Firebase
- Login → verify session established
- Fetch analyses → verify Firestore query
- Download JSON → verify format correct

---

#### 2. **Threat Dashboard & Visualization** (`cloud/ui/pages/03_threat_dashboard.py`)

Real-time threat timeline and statistics.

**Functions to Write:**

```python
# cloud/ui/pages/03_threat_dashboard.py

def render_threat_dashboard() -> None:
    """
    Render threat visualization dashboard.
    Displays threat timeline, statistics, and alerts.
    """
    pass

def fetch_threat_statistics(user_uid: str, days: int = 30) -> dict:
    """
    Get threat distribution from last N days.
    
    Args:
        user_uid: Firebase user UID
        days: Time window
    
    Returns:
        {
            'threat_levels': {
                'low': int,
                'medium': int,
                'high': int,
                'critical': int
            },
            'total_analyses': int,
            'average_threat_score': float
        }
    """
    pass

def render_threat_pie_chart(threat_counts: dict) -> None:
    """
    Display pie chart of threat distribution.
    Use plotly for interactivity.
    
    Args:
        threat_counts: Dict with 'low', 'medium', 'high', 'critical'
    """
    pass

def render_threat_timeline(analyses: list[dict]) -> None:
    """
    Display timeline of recent threats (newest first).
    Interactive: click for details.
    
    Args:
        analyses: List of analysis results
    """
    pass

def render_threat_heatmap(analyses: list[dict]) -> None:
    """
    Heatmap of threat level by day/hour.
    Identifies patterns over time.
    
    Args:
        analyses: List of analyses with timestamps
    """
    pass
```

**Testing:**
- Render dashboard for user with 10 analyses → verify charts
- Threat pie chart → verify percentages sum to 100%
- Timeline → verify chronological order
- Empty data → graceful fallback message

---

#### 3. **Account Settings & Management** (`cloud/ui/pages/04_account_settings.py`)

User account management, quota display, ban appeals.

**Functions to Write:**

```python
# cloud/ui/pages/04_account_settings.py

def render_account_settings() -> None:
    """
    Render account settings page.
    Shows user info, quota, strikes, PAT management.
    """
    pass

def display_account_info() -> None:
    """
    Show user email, account status, join date.
    Edit password link.
    """
    pass

def display_quota_status(user_uid: str) -> None:
    """
    Show current quota usage as progress bar.
    Display: "2/3 analyses used, reset in 4 hours"
    
    Args:
        user_uid: Firebase user UID
    """
    pass

def display_strike_status(user_uid: str) -> None:
    """
    Show strike count and recent violations.
    If soft-locked: warning message
    If hard-locked: suspension notice + appeal button
    
    Args:
        user_uid: Firebase user UID
    """
    pass

def regenerate_pat(user_uid: str) -> str:
    """
    Generate new PAT for user.
    Invalidate old PAT.
    Display one-time for user to copy.
    
    Args:
        user_uid: Firebase user UID
    
    Returns:
        New PAT string
    """
    pass

def submit_ban_appeal(user_uid: str, message: str) -> dict:
    """
    Create ban appeal request (for hard-locked users).
    
    Args:
        user_uid: Firebase user UID
        message: User's appeal text
    
    Returns:
        {
            'appeal_id': str,
            'submitted_at': timestamp,
            'message': 'Appeal submitted. Review in 7 days.'
        }
    """
    pass

def render_ban_appeal_form() -> None:
    """
    Form for appealing account suspension.
    Only shown if user is hard-locked.
    """
    pass
```

**Testing:**
- Account info display → verify user email shown
- Quota at 2/3 → verify progress bar at ~67%
- 2 strikes → soft lock message shown
- 3+ strikes → hard lock message + appeal form
- Regenerate PAT → verify new PAT displayed

---

#### 4. **Gemini API Prompt Engineering** (`cloud/ml/gemini_handler.py`)

Structured prompts and response parsing for threat intelligence.

**Functions to Write:**

```python
# cloud/ml/gemini_handler.py

class GeminiThreatAnalyzer:
    """
    Wrapper around Gemini API for threat intelligence.
    Structured prompts, response parsing, result caching.
    """
    
    SYSTEM_PROMPT = """
    You are AeroGuard, a network security threat analyst. 
    You will receive sanitized network traffic metadata (NO raw payloads) 
    and provide a structured threat assessment.
    
    Analyze for:
    1. Port scanning patterns (unusual port sequences)
    2. Anomalous traffic volume (spikes, unusual ratios)
    3. Geolocation anomalies (traffic from unexpected regions)
    4. Protocol violations (incorrect flag sequences, malformed packets)
    5. Potential botnet communication (beaconing patterns)
    
    Output MUST be valid JSON: {
        "threat_level": "low|medium|high|critical",
        "summary": "Brief threat summary",
        "indicators": ["indicator 1", "indicator 2"],
        "recommendations": ["action 1", "action 2"],
        "confidence": 0.0-1.0
    }
    """
    
    def __init__(self):
        self.client = genai.GenerativeAI(api_key=os.getenv('GEMINI_API_KEY'))
    
    def construct_user_prompt(self, metadata: dict) -> str:
        """
        Build user prompt from sanitized metadata.
        NO user input in prompt template (injection prevention).
        
        Args:
            metadata: Sanitized JSON metadata
        
        Returns:
            User prompt string
        """
        pass
    
    async def query_gemini(self, metadata: dict) -> dict:
        """
        Query Gemini API with metadata.
        Parse response into structured threat report.
        
        Args:
            metadata: Sanitized JSON metadata
        
        Returns:
            {
                'threat_level': str,
                'summary': str,
                'indicators': [str],
                'recommendations': [str],
                'confidence': float,
                'raw_response': str  # For debugging
            }
        
        Timeout: 10 seconds (protective against API hangs)
        """
        pass
    
    @staticmethod
    def parse_gemini_response(response_text: str) -> dict:
        """
        Parse Gemini's JSON response.
        Validate structure and extract fields.
        Fallback: Return safe default if parsing fails.
        
        Args:
            response_text: Raw API response
        
        Returns:
            Structured dict (validated)
        """
        pass
    
    @staticmethod
    def validate_threat_report(report: dict) -> bool:
        """
        Verify threat report has all required fields.
        Ensure threat_level is valid enum.
        
        Args:
            report: Threat report dict
        
        Returns:
            True if valid
        """
        pass
    
    @staticmethod
    def sanitize_gemini_output(report: dict) -> dict:
        """
        Ensure Gemini's output contains no raw data.
        Final sanitization check before returning to user.
        
        Args:
            report: Threat report from Gemini
        
        Returns:
            Sanitized report
        """
        pass

def map_gemini_threat_level(gemini_level: str) -> str:
    """
    Map Gemini's threat terminology to AeroGuard's enum.
    Ensure consistent threat naming across system.
    
    Args:
        gemini_level: Gemini's threat classification
    
    Returns:
        Normalized: 'low'|'medium'|'high'|'critical'
    """
    pass
```

**Testing:**
- Query Gemini with port scan metadata → threat_level='medium'|'high'
- Query Gemini with normal traffic → threat_level='low'
- Malformed response → fallback to safe default
- Timeout (>10s) → return error safely
- Response validation: all required fields present

---

#### 5. **Local System PAT Flow** (`cloud/ui/pat_local_integration.py`)

Guide user to store PAT in local system securely.

**Functions to Write:**

```python
# cloud/ui/pat_local_integration.py

def display_pat_setup_instructions(pat: str) -> None:
    """
    Show user how to store PAT in local system.
    Provide copy-to-clipboard button.
    Display platform-specific setup command.
    
    Args:
        pat: Personal Access Token (one-time display)
    """
    pass

def generate_pat_setup_command(pat: str, os_name: str) -> str:
    """
    Generate platform-specific command to store PAT locally.
    Windows: aerosguard-cli auth --pat <token>
    macOS/Linux: aerosguard-cli auth --pat <token>
    
    Args:
        pat: PAT token
        os_name: Operating system ('windows'|'macos'|'linux')
    
    Returns:
        Shell command as string
    """
    pass

def render_pat_warning() -> None:
    """
    Display prominent warning:
    "This token is shown ONLY ONCE.
    Copy it now and store it in your local system.
    Cannot be recovered if lost."
    """
    pass

def verify_pat_stored_in_local(user_uid: str) -> dict:
    """
    Verify that user has successfully stored PAT locally.
    Prompt with: "Have you stored the PAT? [Yes] [Show again]"
    Only proceed if user confirms.
    
    Args:
        user_uid: Firebase user UID
    
    Returns:
        {'pat_confirmed_stored': bool, 'timestamp': str}
    """
    pass
```

**Testing:**
- Display setup instructions → verify clear and complete
- Generate command → verify correct OS-specific format
- Show warning → verify prominent (red color/bold)
- Verification prompt → confirm user understands

---

#### 6. **PDF Report Generation** (`cloud/ui/pdf_reporter.py`)

Professional threat reports as PDFs.

**Functions to Write:**

```python
# cloud/ui/pdf_reporter.py

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, Image, PageBreak

class PDFReporter:
    """
    Generate professional threat reports as PDFs.
    Uses ReportLab for rendering.
    """
    
    def __init__(self, analysis_data: dict, user_email: str):
        self.analysis = analysis_data
        self.user_email = user_email
        self.doc = None
        self.elements = []
    
    def generate_pdf(self) -> bytes:
        """
        Create PDF report from analysis data.
        Return as bytes for download.
        
        Returns:
            PDF file bytes
        """
        pass
    
    def add_title_page(self) -> None:
        """
        Add cover page with AeroGuard logo, title, timestamp.
        """
        pass
    
    def add_executive_summary(self) -> None:
        """
        Add summary: threat level, key findings, top recommendations.
        """
        pass
    
    def add_threat_analysis(self) -> None:
        """
        Add detailed threat analysis section.
        Include Gemini's indicators and confidence score.
        """
        pass
    
    def add_network_metadata(self) -> None:
        """
        Add network capture metadata table.
        Flows, protocols, packet counts (sanitized).
        """
        pass
    
    def add_recommendations(self) -> None:
        """
        Add actionable remediation recommendations.
        Structured as numbered list.
        """
        pass
    
    def add_footer(self) -> None:
        """
        Add footer: AeroGuard branding, report date, user email.
        """
        pass
    
    def add_page_break(self) -> None:
        """
        Insert page break.
        """
        pass

def create_styled_table(data: list[list], headers: list[str]) -> Table:
    """
    Create ReportLab Table with consistent styling.
    
    Args:
        data: 2D list of cell values
        headers: Column header names
    
    Returns:
        ReportLab Table object
    """
    pass

def embed_logo_image(logo_path: str, width_inches: float = 2) -> Image:
    """
    Load and scale AeroGuard logo for PDF.
    
    Args:
        logo_path: Path to logo image
        width_inches: Desired width in inches
    
    Returns:
        ReportLab Image object
    """
    pass
```

**Testing:**
- Create PDF from sample analysis → verify file created
- Open PDF → verify content readable (title, threat level, recommendations)
- File size → verify reasonable (<5MB even for large reports)
- Download → verify user can download from Streamlit

---

### Phase 4 Acceptance Criteria

- ✅ Signup/login flow works end-to-end
- ✅ PAT generated and displayed one-time
- ✅ Download Hub lists and downloads analyses
- ✅ Threat dashboard renders charts (pie, timeline)
- ✅ Account settings show quota and strikes
- ✅ Bad appeals accessible (only when hard-locked)
- ✅ Gemini queries return valid threat reports
- ✅ PDF generation produces readable reports
- ✅ Local PAT integration instructions clear and actionable
- ✅ Session Affinity enabled (Cloud Run config)

---

## Phase 5: Polishing & Export

**Timeline:** Week 9–10  
**Objective:** UI refinement, PDF enhancements, end-to-end testing, documentation  
**Deliverable:** Production-ready, polished system with comprehensive documentation

### Key Modules & Functions to Implement

#### 1. **UI Refinement** (`local/ui/dashboard_refinement.py`)

Polish customtkinter dashboard with icons, notifications, animations.

**Functions to Write:**

```python
# local/ui/dashboard_refinement.py

def add_system_status_widget() -> ctk.CTkFrame:
    """
    Add status frame showing:
    - Baseline status (established/not established)
    - PAT validity
    - Quota remaining
    - Last analysis time
    
    Returns:
        Configured CTkFrame
    """
    pass

def add_animated_progress_bar(parent: ctk.CTk, max_value: int) -> ctk.CTkProgressBar:
    """
    Create progress bar with animation during capture.
    Updates every 100ms during capture/analysis.
    
    Args:
        parent: Parent widget
        max_value: Max progress value
    
    Returns:
        Animated progress bar
    """
    pass

def add_notification_center() -> None:
    """
    Toast notifications for events:
    - "Capture started"
    - "Anomaly detected!"
    - "Cloud analysis successful"
    - "Error: Rate limited"
    
    Display in corner of dashboard.
    Auto-dismiss after 5 seconds.
    """
    pass

def add_dark_mode_toggle() -> None:
    """
    Add theme toggle (light/dark mode).
    Store preference in SQLite settings.
    """
    pass

def add_help_tooltips() -> None:
    """
    Hover tooltips on buttons:
    - "Calibrate System" → "Establish baseline... (1-5 min)"
    - "Capture Network" → "Record packets for analysis"
    - etc.
    """
    pass

def add_keyboard_shortcuts() -> None:
    """
    Register keyboard shortcuts:
    Ctrl+C = Stop capture
    Ctrl+S = Save current results
    Ctrl+Q = Quit
    """
    pass
```

**Testing:**
- Status widget → verify updates in real-time
- Progress bar → verify animation smooth (no stuttering)
- Notifications → verify appear and dismiss
- Theme toggle → verify persists on restart
- Keyboard shortcuts → verify responsive

---

#### 2. **Advanced PDF Features** (`cloud/ui/pdf_reporter_advanced.py`)

Enhance PDF with charts, anomaly highlights, executive summary.

**Functions to Write:**

```python
# cloud/ui/pdf_reporter_advanced.py

class AdvancedPDFReporter:
    """
    Enhanced PDF generation with charts and graphics.
    """
    
    def add_threat_gauge_chart(self) -> None:
        """
        Add visual "threat gauge" (0–100 scale).
        Red/yellow/green zones.
        Current threat level highlighted.
        """
        pass
    
    def add_anomaly_indicators_box(self) -> None:
        """
        Highlight top anomalous features.
        Box format: 
        [!] Port Scanning Pattern Detected
        [!] Unusual Traffic Volume
        """
        pass
    
    def add_timeline_chart(self) -> None:
        """
        Timeline chart of threat level over last 30 days.
        Line graph with threat spikes marked.
        """
        pass
    
    def add_protocol_distribution_pie(self) -> None:
        """
        Pie chart of protocol distribution (TCP/UDP/ICMP).
        From captured metadata.
        """
        pass
    
    def add_recommendations_with_icons(self) -> None:
        """
        Recommendations with priority icons:
        [CRITICAL] Action needed immediately
        [HIGH] Important
        [MEDIUM] Consider
        [LOW] Optional
        """
        pass
    
    def add_appendix_raw_metadata(self) -> None:
        """
        Optional appendix with raw flow metadata.
        Format as table for reference.
        """
        pass

def generate_chart_image(chart_type: str, data: dict) -> bytes:
    """
    Generate chart as image for PDF embedding.
    Use plotly to PNG or matplotlib.
    
    Args:
        chart_type: 'gauge'|'timeline'|'pie'
        data: Chart data
    
    Returns:
        Image file bytes
    """
    pass
```

**Testing:**
- Gauge chart renders → verify color zones accurate
- Timeline chart → verify data points correct
- Pie chart → verify slices proportional
- PDF with charts → verify readable and colors print

---

#### 3. **CLI Enhancement** (`local/cli/cli_commands.py`)

Build robust CLI for headless deployments.

**Functions to Write:**

```python
# local/cli/cli_commands.py

import click

@click.group()
def cli():
    """AeroGuard IDS Command-Line Interface"""
    pass

@cli.command()
@click.option('--duration', type=int, default=5, help='Calibration duration (min)')
def calibrate(duration):
    """
    Calibrate system with baseline capture.
    
    Usage:
        aerosguard calibrate --duration 5
    """
    pass

@cli.command()
@click.option('--duration', type=int, default=5, help='Capture duration (sec)')
@click.option('--interface', type=str, help='Network interface')
@click.option('--output', type=str, help='Output PCAP path')
def capture(duration, interface, output):
    """
    Capture network traffic.
    
    Usage:
        aerosguard capture --duration 5 --output /tmp/capture.pcap
    """
    pass

@cli.command()
@click.option('--file', type=str, required=True, help='PCAP file path')
@click.option('--output', type=str, help='Output JSON path')
def analyze(file, output):
    """
    Analyze local PCAP (offline).
    
    Usage:
        aerosguard analyze --file /tmp/capture.pcap --output /tmp/result.json
    """
    pass

@cli.command()
@click.option('--file', type=str, required=True, help='JSON metadata path')
def submit_cloud(file):
    """
    Submit analysis to cloud for Gemini threat intelligence.
    
    Usage:
        aerosguard submit-cloud --file /tmp/result.json
    """
    pass

@cli.command()
@click.option('--pat', type=str, required=True, help='Personal Access Token')
def auth(pat):
    """
    Store PAT in system keyring.
    
    Usage:
        aerosguard auth --pat xxx_token_xxx
    """
    pass

@cli.command()
def status():
    """
    Display system status (baseline, PAT, quota, last analysis).
    
    Usage:
        aerosguard status
    """
    pass

# Main entry point
if __name__ == '__main__':
    cli()
```

**Testing:**
- `aerosguard calibrate` → baseline created
- `aerosguard capture` → PCAP file written
- `aerosguard analyze` → JSON output created
- `aerosguard submit-cloud` → submission successful
- `aerosguard status` → info displayed
- `aerosguard --help` → all commands listed

---

#### 4. **Integration Testing** (`tests/integration/test_full_pipeline.py`)

End-to-end tests covering entire system.

**Functions to Write:**

```python
# tests/integration/test_full_pipeline.py

import pytest
import tempfile
import time
from pathlib import Path

class TestFullPipeline:
    """
    End-to-end integration tests.
    Test local system → cloud system → results.
    """
    
    def test_local_to_cloud_analysis(self):
        """
        FULL PIPELINE:
        1. Create temp PCAP (mock data)
        2. Extract features locally
        3. Score anomalies (Isolation Forest)
        4. Sanitize to JSON
        5. Submit to cloud API (mock)
        6. Receive threat report
        7. Verify report structure
        """
        pass
    
    def test_offline_analysis_without_cloud(self):
        """
        Test local system works completely offline.
        No cloud endpoint calls.
        """
        pass
    
    def test_quota_enforcement_on_cloud_submission(self):
        """
        1. Submit 3 analyses (quota limit)
        2. Verify 4th submission rejected (403)
        3. Wait 6 hours (simulate)
        4. Verify quota reset
        5. 5th submission accepted
        """
        pass
    
    def test_strike_system_escalation(self):
        """
        1. Send malformed JSON → log strike
        2. Send oversized payload (5MB+) → log strike
        3. Verify account soft-locked
        4. Send valid JSON → still processed
        5. Send prompt injection → hard lock
        6. Subsequent requests → 403 Forbidden
        """
        pass
    
    def test_zero_storage_guarantee(self):
        """
        1. Send analysis to cloud
        2. Monitor memory usage before/after
        3. Verify memory released within 5 seconds
        4. Check Gemini query happens
        5. Verify no residual data in logs
        """
        pass
    
    def test_sanitization_accuracy(self):
        """
        1. Create PCAP with HTTP traffic (contains secrets)
        2. Sanitize
        3. Search JSON for sensitive strings
        4. Verify NO passwords, keys, API keys found
        """
        pass
    
    def test_user_signup_to_first_analysis(self):
        """
        USER JOURNEY:
        1. Signup on web portal
        2. Receive PAT
        3. Store PAT locally (via CLI)
        4. Calibrate system
        5. Capture network
        6. Analyze locally
        7. Submit to cloud
        8. View results on dashboard
        """
        pass
```

**Testing:**
- Run full pipeline → success
- Run offline (no cloud) → success
- Quota enforcement → 403 on 4th request
- Strike count → escalation at 3 strikes
- Memory audit → no data persisted
- Sanitization → no sensitive strings in JSON

---

#### 5. **Documentation** (`docs/`)

Comprehensive user and developer documentation.

**Files to Create:**

```
docs/
├── USER_GUIDE.md          # How to use AeroGuard (end-user)
├── INSTALLATION.md        # Setup instructions (local + cloud)
├── API_REFERENCE.md       # FastAPI endpoint documentation
├── ARCHITECTURE.md        # System design (already created)
├── TECH_STACK.md          # Technology choices (already created)
├── TROUBLESHOOTING.md     # Common issues and fixes
├── SECURITY.md            # Security model and threat mitigations
├── FAQ.md                 # Frequently asked questions
└── DEVELOPMENT.md         # Development setup for contributors
```

**Functions to Document:**

```python
# For each function/class created, automatically generate docs via:
# 1. Docstring (required)
# 2. Type hints (required)
# 3. Example usage
# 4. Error handling notes

# Use tool: sphinx-autodoc to generate API docs from docstrings
# Use tool: pytest-cov for coverage reports
# Use tool: black for code formatting
# Use tool: pylint for code quality checks
```

**Testing Documentation:**
- Read-through for clarity
- Follow installation guide → successful setup
- Follow user guide → successful analysis
- Follow API reference → correct endpoint usage

---

### Phase 5 Acceptance Criteria

- ✅ Dashboard UI polished (icons, notifications, animations)
- ✅ PDF reports include charts and visualizations
- ✅ CLI commands functional and documented
- ✅ Integration tests pass (full pipeline)
- ✅ Offline analysis works without cloud
- ✅ Quota enforcement verified end-to-end
- ✅ Strike system escalation tested
- ✅ Zero-storage guarantee verified (memory audit)
- ✅ Sanitization verified (no sensitive data in JSON)
- ✅ User journey tested (signup → analysis → results)
- ✅ All docstrings present and accurate
- ✅ Code coverage > 80%
- ✅ All documentation complete and reviewed

---

## Testing Strategy

### Unit Testing
- **Framework:** `pytest`
- **Coverage Target:** >90%
- **Location:** `tests/unit/` (one test file per module)
- **Example:** `test_scapy_sniffer.py`, `test_isolation_forest.py`, etc.

### Integration Testing
- **Framework:** `pytest`
- **Location:** `tests/integration/`
- **Scope:** Full pipelines (local-to-cloud, offline analysis, etc.)
- **Test Data:** Mock PCAP files, synthetic network metadata

### Load Testing
- **Framework:** `locust` (cloud load testing)
- **Scenarios:**
  - 100 concurrent users submitting analyses
  - Rate limit enforcement under load
  - Gemini API response time (SLA: <5 sec)

### Security Testing
- **OWASP Top 10** vulnerability checks
- **Penetration Testing:** Prompt injection, payload manipulation
- **Fuzzing:** Malformed JSON, oversized payloads
- **Memory Audits:** Verify zero-storage guarantee

### UI Testing (Manual)
- Cross-browser (Chrome, Firefox, Safari)
- Responsive design (desktop, tablet, mobile)
- Keyboard accessibility
- Dark mode compatibility

---

## Deployment Checklist

### Pre-Production (Local System)
- [ ] Unit tests passing (>90% coverage)
- [ ] Offline functionality verified
- [ ] Installer created (PyInstaller)
- [ ] Startup Janitor works on boot
- [ ] Keyring integration tested (Windows/macOS/Linux)

### Pre-Production (Cloud System)
- [ ] Firebase project created
- [ ] Firestore schema initialized
- [ ] Redis Memorystore running
- [ ] Cloud Run services deployed (FastAPI + Streamlit)
- [ ] Gemini API key configured
- [ ] Storage: No persistent user data (audit passed)

### Security & Compliance
- [ ] SSL/TLS certificates valid (HTTPS only)
- [ ] IAM roles configured (least privilege)
- [ ] Rate limiting tested (100 req/min enforced)
- [ ] Strike system tested (soft/hard locks working)
- [ ] Sanitization verified (no payloads in JSON)
- [ ] Zero-storage verified (memory audit passed)

### Documentation & Support
- [ ] USER_GUIDE.md complete
- [ ] INSTALLATION.md tested (successful setup)
- [ ] API_REFERENCE.md published
- [ ] TROUBLESHOOTING.md populated
- [ ] All docstrings in code reviewed

### Soft Launch
- [ ] Beta test with 10 trusted users
- [ ] Collect feedback
- [ ] Fix critical issues
- [ ] Prepare public release

### Public Release
- [ ] GitHub repository public
- [ ] Documentation live
- [ ] Installer downloadable
- [ ] Landing page with download link
- [ ] Twitter/announcement

---

## Timeline Summary

| Phase | Duration | Key Deliverable |
|-------|----------|-----------------|
| Phase 1 | Week 1–2 | Local Data Engine (capture & spooling) |
| Phase 2 | Week 3–4 | Local ML & Sanitization (anomaly detection) |
| Phase 3 | Week 5–6 | Cloud IAM & Backend (FastAPI gateway) |
| Phase 4 | Week 7–8 | Cloud Frontend & Gemini (web dashboard) |
| Phase 5 | Week 9–10 | Polishing & Export (UI, docs, testing) |
| **Total** | **10 weeks** | **Production-Ready AeroGuard IDS** |

---

## Success Criteria (Overall)

✅ **Functionality:**
- Local offline analysis works standalone
- Cloud submission and Gemini integration functional
- Web portal allows signup, login, PAT management
- Threat reports generated and downloadable as JSON/PDF

✅ **Performance:**
- Baseline calibration: <5 min
- Anomaly scoring: <2 sec
- Cloud analysis (Gemini query): <5 sec
- Memory hold time: ≤3 sec (then deleted)

✅ **Security:**
- No raw payloads transmitted to cloud
- Zero persistent storage in cloud pipeline
- Rate limiting enforces 100 req/min per IP
- Strike system soft-locks at 1-2 strikes, hard-locks at ≥3

✅ **Reliability:**
- No crashes or memory leaks (1-hour stress test)
- Graceful error handling (all functions have try/except)
- Comprehensive logging for debugging

✅ **Documentation:**
- Every function has docstring
- User guide complete and tested
- Architecture and tech stack documented
- API endpoints documented with examples

---

**Ready to start building! Begin with Phase 1: Local Data Engine.**
