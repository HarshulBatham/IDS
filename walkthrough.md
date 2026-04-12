# AeroGuard IDS — Security Audit & Phase 1 Walkthrough

## Part A: Security Vulnerability Fixes

Five critical vulnerabilities were identified and fixed across the project's markdown documentation.

### Summary of Fixes

| # | Vulnerability | Severity | File(s) Modified | Fix Applied |
|---|---|---|---|---|
| 1 | **OOM DoS** via `request.json()` before size check | Critical | `TECH_STACK.md` | Stream-read body with 5MB hard cap *before* JSON parse |
| 2 | **IP Spoofing** in rate limiter (Cloud Run proxy) | High | `TECH_STACK.md` | Extract real IP from `X-Forwarded-For` header |
| 3 | **Weak PBKDF2** (100k iterations) | Medium | `ARCHITECTURE.md`, `TECH_STACK.md`, `ROADMAP_AND_CI.md` | Updated to 600,000 iterations (OWASP 2023+) |
| 4 | **Ineffective Gutmann SSD deletion** | Medium | `ARCHITECTURE.md`, `ROADMAP_AND_CI.md` | SSD-aware single zero-pass + OS FDE + RAM-backed tmpfs |
| 5 | **Naive regex prompt injection** blocklist | Medium | `ARCHITECTURE.md`, `ROADMAP_AND_CI.md` | Pydantic schema + `<DATA>` isolation + Gemini structured output |

**Bonus:** Added `pip-audit` dependency vulnerability scanning to the CI/CD pipeline in `ROADMAP_AND_CI.md`.

### Key Diffs

#### OOM DoS Prevention ([TECH_STACK.md](file:///d:/github/project/IDS/TECH_STACK.md))
```diff
-    body = await request.json()
-    body_size = len(json.dumps(body).encode('utf-8'))
-    if body_size > 5 * 1024 * 1024:
+    content_length = request.headers.get('content-length')
+    if content_length and int(content_length) > 5 * 1024 * 1024:
+        return JSONResponse({"error": "Payload exceeds 5MB"}, status_code=400)
+    body_bytes = b''
+    async for chunk in request.stream():
+        body_bytes += chunk
+        if len(body_bytes) > 5 * 1024 * 1024:
+            return JSONResponse({"error": "Payload exceeds 5MB"}, status_code=400)
+    body = json.loads(body_bytes)
```

#### Prompt Injection Defense ([ARCHITECTURE.md](file:///d:/github/project/IDS/ARCHITECTURE.md))
```diff
-class PromptInjectionDetector:
-    DANGEROUS_PATTERNS = [r'(?i)(?:delete|drop|...)']
+# Defense-in-depth: Schema → Data Isolation → Structured Output
+class FlowMetadata(BaseModel):
+    source_port: int = Field(..., ge=0, le=65535)  # Strict schema
+
+response_mime_type="application/json"   # Gemini structured output
+response_schema=THREAT_REPORT_SCHEMA    # No free-text exfiltration
```

---

## Part B: Phase 1 Implementation — Local Data Engine

### Project Structure Created

```
IDS/
├── local/
│   ├── __init__.py
│   ├── janitor.py                          # Startup Janitor
│   └── network/
│       ├── __init__.py
│       ├── interface_detector.py           # Network Interface Detection
│       ├── scapy_sniffer.py                # Lightweight Packet Sniffer
│       └── pyshark_spooler.py              # PCAP Disk Spooler
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   ├── __init__.py
│   │   ├── test_janitor.py                 # 16 tests
│   │   ├── test_interface_detector.py      # 19 tests
│   │   ├── test_scapy_sniffer.py           # 12 tests
│   │   └── test_pyshark_spooler.py         # 17 tests
│   └── integration/
│       └── __init__.py
├── requirements-local.txt
└── requirements-dev.txt
```

### Module Breakdown

#### 1. Startup Janitor — [janitor.py](file:///d:/github/project/IDS/local/janitor.py)

| Function | Purpose |
|---|---|
| `get_aerosguard_temp_dir()` | Platform-specific temp dir (Linux `/dev/shm`, Windows `%TEMP%`) |
| `enumerate_residual_files()` | Scan for stale `.pcap`, `.json`, `.lock`, `.tmp` files |
| `secure_delete_file()` | SSD-aware deletion: single zero-pass + `unlink` |
| `run_startup_janitor()` | Full cleanup lifecycle with audit logging |
| `register_startup_hook()` | Cross-platform auto-start (schtasks / launchd / systemd) |

#### 2. Interface Detector — [interface_detector.py](file:///d:/github/project/IDS/local/network/interface_detector.py)

| Function | Purpose |
|---|---|
| `get_active_interfaces()` | List active non-loopback interfaces via psutil |
| `validate_capture_capability()` | Test-sniff to verify capture permissions |
| `select_interface_interactive()` | CLI prompt for interface selection |
| `get_interface_mtu()` | Read MTU for buffer sizing |
| `_is_wireless_interface()` | Heuristic Wi-Fi detection for UI hints |

#### 3. Scapy Sniffer — [scapy_sniffer.py](file:///d:/github/project/IDS/local/network/scapy_sniffer.py)

| Feature | Detail |
|---|---|
| **Thread-safe** | Background thread with `threading.Lock` for all shared state |
| **Circular buffer** | `deque(maxlen=N)` prevents unbounded memory growth |
| **Flow aggregation** | Groups packets by `src_ip:dst_ip` with counts, bytes, TCP flags |
| **Non-blocking stats** | `get_flow_statistics()` and `get_capture_summary()` for live dashboards |
| **Graceful stop** | `stop_sniffing()` returns final aggregate stats as JSON-serializable dict |

#### 4. PyShark Spooler — [pyshark_spooler.py](file:///d:/github/project/IDS/local/network/pyshark_spooler.py)

| Feature | Detail |
|---|---|
| **Shell injection prevention** | `subprocess.Popen(cmd_list, shell=False)` |
| **Disk spooling** | Writes directly to temp file (no RAM buffering for large captures) |
| **PCAP validation** | Magic-byte checks for libpcap and pcapng formats |
| **Progress monitoring** | File-size polling without packet parsing |
| **Secure temp storage** | Linux: `/dev/shm` (RAM-backed), others: OS temp with `0o600` perms |

### Test Results

```
============================= 64 passed in 0.67s ==============================
```

| Test Suite | Tests | Status |
|---|---|---|
| `test_janitor.py` | 16 | ✅ All passed |
| `test_interface_detector.py` | 19 | ✅ All passed |
| `test_scapy_sniffer.py` | 12 | ✅ All passed |
| `test_pyshark_spooler.py` | 17 | ✅ All passed |
| **Total** | **64** | **✅ 0 failures, 0 warnings** |

---

## What's Next: Phase 2

Phase 2 covers **ML & Sanitization** (Weeks 3–4 per ROADMAP):

| Module | File | Key Functions |
|---|---|---|
| Feature Extractor | `local/ml/feature_extractor.py` | Extract 50 statistical features from flow data |
| Anomaly Detector | `local/ml/anomaly_detector.py` | Isolation Forest training, scoring, and explanation |
| PCAP Sanitizer | `local/sanitization/sanitizer.py` | Strip L7 payloads, mask IPs, validate JSON output |
| SQLite Cache | `local/storage/sqlite_cache.py` | Persist baselines, settings, and analysis results |

> [!TIP]
> Say **"Start Phase 2"** when you're ready to proceed with ML and sanitization implementation.
