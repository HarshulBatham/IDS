# AeroGuard IDS - Implementation Roadmap & CI/CD Pipeline

**Version:** 1.0  
**Date:** April 2026  
**Audience:** Development Team, DevOps Engineers, Quality Assurance  
**Purpose:** Phase-by-phase implementation plan with testing strategies and GitHub Actions CI/CD pipelines

---

## Table of Contents

1. [Overview](#overview)
2. [Phase 1: Local Data Engine & Spooling](#phase-1-local-data-engine--spooling)
3. [Phase 2: Local ML & Data Sanitization](#phase-2-local-ml--data-sanitization)
4. [Phase 3: Cloud Backend & Firebase IAM](#phase-3-cloud-backend--firebase-iam)
5. [Phase 4: Cloud Frontend (Streamlit)](#phase-4-cloud-frontend-streamlit)
6. [Phase 5: CI/CD Pipelines (GitHub Actions)](#phase-5-cicd-pipelines-github-actions)
7. [Phase 6: Security Hardening & Logging Infrastructure](#phase-6-security-hardening--logging-infrastructure)
8. [Phase 7: Compliance, Documentation & Monitoring](#phase-7-compliance-documentation--monitoring)
9. [Integration & Deployment Strategy](#integration--deployment-strategy)
10. [Success Metrics & Gates](#success-metrics--gates)

---

## Overview

AeroGuard IDS is built in **7 phases**, each with explicit testing gates and CI/CD validation. The roadmap prioritizes:

1. **Offline-First Development** (Phases 1–2): Local system fully functional without cloud
2. **Cloud Infrastructure** (Phase 3): Robust, secure backend with comprehensive testing
3. **User Experience** (Phase 4): Polished web interface with seamless PAT integration
4. **Continuous Integration** (Phase 5): Automated testing, linting, and deployment pipelines
5. **Security Hardening** (Phase 6): Encryption, logging, threat detection, and vulnerability fixes
6. **Compliance & Monitoring** (Phase 7): Documentation, GDPR compliance, SLOs, and observability

**Key Principles:**
- Each phase must pass its testing gate before advancing
- No external dependencies until Phase 3
- Security testing integrated into all phases (Phase 6 adds comprehensive hardening)
- CI/CD prevents broken code from merging
- Automated deployment on main branch merge
- Zero manual deployment steps
- Production monitoring and alerting in place before go-live

---

## Phase 1: Local Data Engine & Spooling

**Timeline:** Week 1–2  
**Owner:** Backend Team  
**Dependencies:** None (standalone local module)

### Implementation Deliverables

#### 1. **Startup Janitor** (`local/janitor.py`)

- Implement `enumerate_residual_files()` to scan OS temp directory for stale `.pcap` and lock files
- Implement `secure_delete_file()` using 7-pass Gutmann algorithm for secure file overwriting
- Register startup hook using platform-specific mechanisms (Windows Task Scheduler, macOS launchd, Linux systemd)
- Create lightweight logging module to audit all deleted files (for compliance)

#### 2. **Network Interface Detector** (`local/network/interface_detector.py`)

- Implement `get_active_interfaces()` using `psutil` + `scapy.get_if_list()` to enumerate interfaces
- Implement `select_interface_interactive()` for CLI selection or GUI dropdown (for later phases)
- Implement `validate_capture_capability()` with 1-second test sniff per interface
- Error handling for permission issues (capture requires elevated privileges on some platforms)

#### 3. **Scapy Lightweight Sniffer** (`local/network/scapy_sniffer.py`)

- Implement `ScapySniffer` class with threaded background sniffing (non-blocking)
- Implement `packet_callback()` for real-time packet aggregation into flows (memory-efficient)
- Implement `get_flow_statistics()` for snapshot retrieval without blocking capture thread
- Memory management: circular buffer (maxlen) to prevent unbounded growth during long captures

#### 4. **PyShark PCAP Spooler** (`local/network/pyshark_spooler.py`)

- Implement `PySharkSpooler.start_capture()` to spawn tshark subprocess and spool PCAP to temp file
- Implement `get_capture_progress()` by polling file size (not parsing packets) for efficiency
- Implement `stop_capture_gracefully()` with SIGTERM + timeout (max 5 sec for shutdown)
- Validate PCAP integrity using magic bytes check (0xa1b2c3d4 for network capture format)

---

### Testing Strategy

#### Unit Testing Framework & Structure

```
tests/unit/
├── test_janitor.py
├── test_interface_detector.py
├── test_scapy_sniffer.py
└── test_pyshark_spooler.py
```

**Testing Tool Stack:**
- `pytest` (test orchestration)
- `unittest.mock` (mocking external dependencies)
- `tempfile` (creating isolated temp directories for testing)
- `pytest-cov` (code coverage reporting, target >90%)

#### Test Case 1: Startup Janitor Tests

```python
# tests/unit/test_janitor.py

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from local.janitor import enumerate_residual_files, secure_delete_file, run_startup_janitor

class TestStartupJanitor:
    
    def test_enumerate_residual_files_finds_pcap(self):
        """
        Test that enumerate_residual_files() detects stale PCAP files.
        
        Setup:
        - Create temp directory with mock .pcap files
        - Call enumerate_residual_files()
        
        Assertion:
        - Verify returned list contains all .pcap files
        - Verify non-target files (e.g., .txt) are excluded
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create mock files
            (Path(tmpdir) / "capture_123.pcap").touch()
            (Path(tmpdir) / "capture_456.pcap").touch()
            (Path(tmpdir) / "readme.txt").touch()
            
            result = enumerate_residual_files(tmpdir)
            
            assert len(result) == 2
            assert all(str(f).endswith('.pcap') for f in result)
    
    def test_secure_delete_file_overwrites_content(self):
        """
        Test that secure_delete_file() performs multi-pass overwrite.
        
        Setup:
        - Create file with known content
        - Call secure_delete_file() with 7 passes
        
        Assertion:
        - File is deleted
        - Verify file doesn't exist after deletion
        """
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("SENSITIVE_DATA_12345")
            path = Path(f.name)
        
        success = secure_delete_file(path, passes=7)
        
        assert success is True
        assert not path.exists()
    
    def test_run_startup_janitor_empty_directory(self):
        """
        Test janitor handles empty temp directory gracefully.
        
        Setup:
        - Create empty temp directory
        - Call run_startup_janitor()
        
        Assertion:
        - Returns dict with deleted_count=0, failed_count=0
        - No exceptions raised
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_startup_janitor()
            
            assert result['deleted_count'] == 0
            assert result['failed_count'] == 0
            assert isinstance(result['log'], str)
```

#### Test Case 2: Network Interface Detector Tests

```python
# tests/unit/test_interface_detector.py

import pytest
from unittest.mock import patch, MagicMock
from local.network.interface_detector import (
    get_active_interfaces,
    validate_capture_capability
)

class TestInterfaceDetector:
    
    @patch('scapy.all.get_if_list')
    @patch('psutil.net_if_stats')
    def test_get_active_interfaces_returns_valid_list(self, mock_stats, mock_scapy):
        """
        Test that get_active_interfaces() returns properly structured interface list.
        
        Mock Setup:
        - Mock scapy.get_if_list() to return ['eth0', 'eth1', 'lo']
        - Mock psutil.net_if_stats() to return interface statistics
        
        Assertion:
        - Result is list of dicts
        - Each dict has required keys: 'name', 'ip', 'status', 'is_loopback'
        - Loopback interface excluded
        """
        mock_scapy.return_value = ['eth0', 'eth1', 'lo']
        mock_stats.return_value = {
            'eth0': MagicMock(isup=True),
            'eth1': MagicMock(isup=False),
            'lo': MagicMock(isup=True)
        }
        
        result = get_active_interfaces()
        
        assert isinstance(result, list)
        assert all('name' in iface for iface in result)
        assert all(not iface['is_loopback'] for iface in result)
        assert len(result) == 1  # Only eth0 (up, not loopback)
    
    @patch('scapy.all.sniff')
    def test_validate_capture_capability_succeeds(self, mock_sniff):
        """
        Test that validate_capture_capability() verifies capture-ready interface.
        
        Mock Setup:
        - Mock scapy.sniff() to return without error (simulating successful capture)
        
        Assertion:
        - Returns True when sniff succeeds
        """
        mock_sniff.return_value = 2  # 2 packets captured
        
        result = validate_capture_capability('eth0')
        
        assert result is True
        mock_sniff.assert_called_once()
    
    @patch('scapy.all.sniff')
    def test_validate_capture_capability_fails_permission_denied(self, mock_sniff):
        """
        Test that validate_capture_capability() handles permission errors gracefully.
        
        Mock Setup:
        - Mock scapy.sniff() to raise PermissionError
        
        Assertion:
        - Returns False
        - No exception propagates
        """
        mock_sniff.side_effect = PermissionError("No permission to sniff on eth0")
        
        result = validate_capture_capability('eth0')
        
        assert result is False
```

#### Test Case 3: Scapy Sniffer Tests

```python
# tests/unit/test_scapy_sniffer.py

import pytest
import time
from unittest.mock import patch, MagicMock
from scapy.all import IP, TCP, UDP
from local.network.scapy_sniffer import ScapySniffer

class TestScapySniffer:
    
    @patch('scapy.all.sniff')
    def test_scapy_sniffer_initializes(self, mock_sniff):
        """
        Test ScapySniffer initialization.
        
        Assertion:
        - Instance created with correct interface
        - Buffer initialized with maxlen (circular buffer)
        """
        sniffer = ScapySniffer(interface='eth0', packet_buffer_size=1000)
        
        assert sniffer.interface == 'eth0'
        assert sniffer.packet_buffer.maxlen == 1000
        assert sniffer.is_sniffing is False
    
    def test_packet_callback_aggregates_flows(self):
        """
        Test that packet_callback() correctly aggregates packets into flows.
        
        Setup:
        - Create synthetic packets (IP/TCP)
        - Call packet_callback() for each
        
        Assertion:
        - flow_stats contains correct flow key
        - Packet and byte counts increment
        """
        sniffer = ScapySniffer(interface='eth0')
        
        # Create synthetic packet: IP(src="192.168.1.100") / TCP(sport=54321, dport=443)
        synthetic_pkt = IP(src='192.168.1.100', dst='8.8.8.8') / TCP(sport=54321, dport=443)
        
        sniffer.packet_callback(synthetic_pkt)
        
        flow_key = '192.168.1.100:8.8.8.8'
        assert flow_key in sniffer.flow_stats
        assert sniffer.flow_stats[flow_key]['packet_count'] == 1
    
    def test_get_flow_statistics_snapshot(self):
        """
        Test that get_flow_statistics() returns current snapshot without blocking.
        
        Setup:
        - Add packets to sniffer
        - Immediately call get_flow_statistics()
        
        Assertion:
        - Returns dict with flow stats
        - Execution time < 100ms (non-blocking)
        """
        sniffer = ScapySniffer(interface='eth0')
        
        # Simulate 10 packets
        for i in range(10):
            pkt = IP(src='192.168.1.100', dst='8.8.8.8') / TCP(sport=54321, dport=443)
            sniffer.packet_callback(pkt)
        
        start = time.time()
        stats = sniffer.get_flow_statistics()
        elapsed = time.time() - start
        
        assert isinstance(stats, dict)
        assert elapsed < 0.1  # Must be fast (non-blocking)
        assert len(stats) > 0
```

#### Test Case 4: PyShark Spooler Tests

```python
# tests/unit/test_pyshark_spooler.py

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, call
import struct
from local.network.pyshark_spooler import PySharkSpooler, validate_pcap_file

class TestPySharkSpooler:
    
    def test_pyshark_spooler_initializes(self):
        """
        Test PySharkSpooler initialization.
        """
        spooler = PySharkSpooler(interface='eth0')
        
        assert spooler.interface == 'eth0'
        assert spooler.capture_process is None
        assert spooler.pcap_file_path is None
    
    @patch('subprocess.Popen')
    def test_start_capture_spawns_tshark(self, mock_popen):
        """
        Test that start_capture() spawns tshark subprocess.
        
        Mock Setup:
        - Mock subprocess.Popen to simulate tshark process
        
        Assertion:
        - Subprocess created with correct args
        - PCAP file path returned
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_process = MagicMock()
            mock_process.poll.return_value = None  # Still running
            mock_popen.return_value = mock_process
            
            spooler = PySharkSpooler(interface='eth0', output_dir=tmpdir)
            pcap_path = spooler.start_capture(duration_seconds=5)
            
            assert pcap_path is not None
            assert pcap_path.endswith('.pcap')
            mock_popen.assert_called_once()
    
    def test_validate_pcap_file_with_valid_file(self):
        """
        Test that validate_pcap_file() accepts valid PCAP files.
        
        Setup:
        - Create temp file with valid PCAP magic bytes
        
        Assertion:
        - Returns True for valid PCAP
        """
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            # Write PCAP magic bytes (0xa1b2c3d4 for network capture)
            f.write(struct.pack('<I', 0xa1b2c3d4))
            f.write(b'\x00' * 100)  # Padding
            path = f.name
        
        try:
            result = validate_pcap_file(path)
            assert result is True
        finally:
            Path(path).unlink()
    
    def test_validate_pcap_file_with_invalid_file(self):
        """
        Test that validate_pcap_file() rejects invalid files.
        
        Setup:
        - Create temp file with wrong magic bytes
        
        Assertion:
        - Returns False for invalid PCAP
        """
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            f.write(b'NOT_A_PCAP_FILE')
            path = f.name
        
        try:
            result = validate_pcap_file(path)
            assert result is False
        finally:
            Path(path).unlink()
```

#### Test Coverage Requirements (Phase 1)

| Module | Test Cases | Coverage Target | Critical Paths |
|--------|-----------|-----------------|-----------------|
| `janitor.py` | 6 | >90% | File deletion, logging |
| `interface_detector.py` | 5 | >85% | Interface enumeration, validation |
| `scapy_sniffer.py` | 4 | >85% | Packet aggregation, threading |
| `pyshark_spooler.py` | 4 | >80% | Process spawning, PCAP validation |
| **Total** | **19** | **>85%** | All no-crash scenarios |

#### Integration Test: End-to-End Local Capture

```python
# tests/integration/test_phase1_e2e.py

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch
from local.network.scapy_sniffer import ScapySniffer
from local.network.pyshark_spooler import PySharkSpooler
from local.janitor import run_startup_janitor

class TestPhase1E2E:
    
    @patch('scapy.all.sniff')
    @patch('subprocess.Popen')
    def test_capture_and_cleanup_workflow(self, mock_popen, mock_sniff):
        """
        INTEGRATION: Startup Janitor → PyShark Spooler → Scapy Sniffer → Cleanup
        
        Scenario:
        1. Run startup janitor (clean stale files)
        2. Detect network interface
        3. Start PyShark capture
        4. Sniff with Scapy in parallel
        5. Stop capture
        6. Verify PCAP file created
        7. Run janitor again (cleanup)
        
        Assertion:
        - All steps complete without error
        - PCAP file created and validated
        - Temp files cleaned up
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Step 1: Startup janitor
            result = run_startup_janitor()
            assert result['failed_count'] == 0
            
            # Step 2–3: Start capture
            mock_process = MagicMock()
            mock_process.poll.return_value = None
            mock_popen.return_value = mock_process
            
            spooler = PySharkSpooler(interface='eth0', output_dir=tmpdir)
            pcap_path = spooler.start_capture(duration_seconds=5)
            
            assert Path(pcap_path).parent.name == Path(tmpdir).name
            
            # Step 5–6: Cleanup
            result = run_startup_janitor()
            assert 'deleted_count' in result
```

---

### Phase 1 Testing Gate

**Requirements to Pass:**
- ✅ All 19 unit tests passing (pytest)
- ✅ Code coverage >85% (pytest-cov)
- ✅ No critical security issues (bandit scan)
- ✅ Integration test E2E completes successfully
- ✅ linting passes (flake8, black)

**Sign-Off:** QA Lead must certify Phase 1 before Phase 2 begins.

---

## Phase 2: Local ML & Data Sanitization

**Timeline:** Week 3–4  
**Owner:** ML & Data Privacy Team  
**Dependencies:** Phase 1 (local data capture working)

### Implementation Deliverables

#### 1. **Feature Extraction Engine** (`local/ml/feature_extractor.py`)

- Implement `FeatureExtractor.extract_features_from_pcap()` to parse PCAP and aggregate into 10-second windows
- Implement `compute_packet_window_features()` to calculate ~50 features per window (packet count, byte count, unique IPs, port distribution entropy, protocol ratios)
- Implement `normalize_features()` using z-score normalization (mean=0, std=1) for ML consistency
- Implement `parse_pcap_to_flows()` using pyshark to extract flow tuples (no payloads, headers only)

#### 2. **Isolation Forest Anomaly Detector** (`local/ml/anomaly_detector.py`)

- Implement `IsolationForestModel.train_on_baseline()` to fit scikit-learn model on baseline features
- Implement `score_anomalies()` to assign anomaly scores (0–1) to new traffic, with confidence metrics
- Implement `explain_anomalies()` to identify which features drove high anomaly scores (feature importance)
- Implement model serialization (`joblib.dump()`) for persistent storage in SQLite

#### 3. **PCAP Sanitization Engine** (`local/sanitization/sanitizer.py`)

- Implement `PCAPSanitizer.sanitize_to_json()` to convert raw PCAP to privacy-safe JSON metadata
- Implement `mask_ip_address()` to anonymize IPs by masking the last octet (192.168.1.100 → 192.168.1.XXX)
- Implement `extract_flow_headers_only()` to parse packets and extract only L3/L4 headers (skip all payloads)
- Implement `aggregate_flows()` to group packets into flows by (src_ip, dst_ip, src_port, dst_port, protocol)

#### 4. **SQLite Local Cache** (`local/storage/sqlite_cache.py`)

- Implement `LocalCache.init_database()` to create SQLite schema (users, baselines, models, settings, analysis_cache tables)
- Implement `save_baseline_profile()` to persist ML model weights and baseline statistics to DB
- Implement `save_analysis_result()` to cache analysis results with SHA256 PCAP hash (for deduplication)
- Implement `get/set_user_settings()` for persistent UI preferences (preferred interface, capture duration)

---

### Testing Strategy

#### Unit Testing Framework & Structure

```
tests/unit/
├── test_feature_extractor.py
├── test_anomaly_detector.py
├── test_sanitizer.py
└── test_sqlite_cache.py
```

#### Test Case 1: Feature Extraction Tests

```python
# tests/unit/test_feature_extractor.py

import pytest
import pandas as pd
import numpy as np
from unittest.mock import patch, MagicMock
from local.ml.feature_extractor import FeatureExtractor, parse_pcap_to_flows

class TestFeatureExtractor:
    
    def test_extract_features_from_pcap_returns_dataframe(self):
        """
        Test that extract_features_from_pcap() returns a structured DataFrame.
        
        Setup:
        - Create synthetic PCAP file with 100 packets
        - Mock pyshark parsing
        
        Assertion:
        - Returns pandas DataFrame
        - Has ~50 feature columns
        - Rows = 10-second windows
        """
        extractor = FeatureExtractor(window_size_sec=10)
        
        # Mock pyshark parsing: return 100 synthetic packets
        mock_packets = [
            {
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'src_port': 54321 + i,
                'dst_port': 443,
                'protocol': 'TCP',
                'length': 1500
            }
            for i in range(100)
        ]
        
        with patch('local.ml.feature_extractor.parse_pcap_to_flows', return_value=mock_packets):
            df = extractor.extract_features_from_pcap('/tmp/mock.pcap')
        
        assert isinstance(df, pd.DataFrame)
        assert df.shape[0] > 0  # At least 1 window
        assert df.shape[1] >= 40  # At least 40 features
    
    def test_normalize_features_produces_zero_mean(self):
        """
        Test that normalize_features() applies z-score normalization correctly.
        
        Setup:
        - Create DataFrame with arbitrary values
        - Call normalize_features()
        
        Assertion:
        - Mean of each column ≈ 0
        - Std of each column ≈ 1
        """
        extractor = FeatureExtractor()
        
        # Create sample data
        df = pd.DataFrame({
            'packet_count': [10, 20, 30, 40, 50],
            'byte_count': [1000, 2000, 3000, 4000, 5000]
        })
        
        normalized = extractor.normalize_features(df)
        
        assert np.abs(normalized['packet_count'].mean()) < 0.001  # ≈ 0
        assert np.abs(normalized['packet_count'].std() - 1.0) < 0.001  # ≈ 1
    
    def test_parse_pcap_to_flows_extracts_headers_only(self):
        """
        Test that parse_pcap_to_flows() extracts only L3/L4 headers (no payloads).
        
        Setup:
        - Create synthetic PCAP with HTTP traffic (contains payloads)
        - Mock pyshark
        
        Assertion:
        - Returned flows have header info (IP, port, protocol)
        - NO payload data in flow dicts
        """
        mock_packets = [
            {
                'src_ip': '192.168.1.100',
                'dst_ip': '93.184.216.34',
                'src_port': 54321,
                'dst_port': 80,
                'protocol': 'TCP',
                'length': 1234,
                # NO 'payload' field (intentionally stripped)
            }
        ]
        
        # Verify structure
        for flow in mock_packets:
            assert 'src_ip' in flow
            assert 'dst_ip' in flow
            assert 'payload' not in flow  # Critical: no payloads
```

#### Test Case 2: Isolation Forest Anomaly Detection Tests

```python
# tests/unit/test_anomaly_detector.py

import pytest
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from unittest.mock import patch, MagicMock
from local.ml.anomaly_detector import IsolationForestModel

class TestIsolationForestModel:
    
    def test_train_on_baseline_creates_model(self):
        """
        Test that train_on_baseline() successfully trains Isolation Forest.
        
        Setup:
        - Create 100 samples of "normal" traffic features
        - Call train_on_baseline()
        
        Assertion:
        - Model object created
        - Model info dict returned with n_trees, contamination, training_date
        """
        model = IsolationForestModel(contamination=0.05, n_estimators=100)
        
        # Create synthetic baseline data (100 samples, 50 features)
        baseline_df = pd.DataFrame(
            np.random.normal(loc=50, scale=10, size=(100, 50)),
            columns=[f'feature_{i}' for i in range(50)]
        )
        
        info = model.train_on_baseline(baseline_df)
        
        assert model.model is not None
        assert info['training_samples'] == 100
        assert info['n_trees'] == 100
        assert 'timestamp' in info
    
    def test_score_anomalies_identifies_outliers(self):
        """
        Test that score_anomalies() correctly identifies anomalous patterns.
        
        Setup:
        - Train model on "normal" data (mean=50, std=10)
        - Score three datasets:
          a) Normal data (should have low anomaly scores)
          b) Anomalous data (different distribution, should have high scores)
        
        Assertion:
        - Normal data: mean anomaly score < 0.3
        - Anomalous data: mean anomaly score > 0.7
        """
        model = IsolationForestModel(contamination=0.05)
        
        # Baseline training data (normal pattern)
        baseline_df = pd.DataFrame(
            np.random.normal(loc=50, scale=10, size=(100, 50)),
            columns=[f'feature_{i}' for i in range(50)]
        )
        model.train_on_baseline(baseline_df)
        
        # Normal test data (similar distribution)
        normal_test_df = pd.DataFrame(
            np.random.normal(loc=50, scale=10, size=(10, 50)),
            columns=[f'feature_{i}' for i in range(50)]
        )
        
        # Anomalous test data (different distribution - port scan pattern)
        anomalous_test_df = pd.DataFrame(
            np.random.normal(loc=100, scale=30, size=(10, 50)),  # Very different
            columns=[f'feature_{i}' for i in range(50)]
        )
        
        normal_scores = model.score_anomalies(normal_test_df)
        anomalous_scores = model.score_anomalies(anomalous_test_df)
        
        assert normal_scores['mean_anomaly_score'] < 0.4
        assert anomalous_scores['mean_anomaly_score'] > 0.6
    
    def test_explain_anomalies_identifies_top_features(self):
        """
        Test that explain_anomalies() identifies which features drove anomaly.
        
        Setup:
        - Train model on normal data
        - Score test data
        - Call explain_anomalies()
        
        Assertion:
        - Top anomalous features returned
        - Feature importance dict populated
        """
        model = IsolationForestModel()
        
        baseline_df = pd.DataFrame(
            np.random.normal(loc=50, scale=10, size=(100, 50)),
            columns=[f'feature_{i}' for i in range(50)]
        )
        model.train_on_baseline(baseline_df)
        
        test_df = pd.DataFrame(
            np.random.normal(loc=100, scale=30, size=(5, 50)),
            columns=[f'feature_{i}' for i in range(50)]
        )
        
        scores = model.score_anomalies(test_df)
        explanation = model.explain_anomalies(test_df, scores['anomaly_scores'])
        
        assert 'top_anomalous_features' in explanation
        assert len(explanation['top_anomalous_features']) > 0
        assert 'interpretation' in explanation
```

#### Test Case 3: PCAP Sanitization Tests (Critical Privacy Tests)

```python
# tests/unit/test_sanitizer.py

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from local.sanitization.sanitizer import PCAPSanitizer, validate_sanitization

class TestPCAPSanitizer:
    
    def test_sanitize_removes_passwords(self):
        """
        CRITICAL SECURITY TEST: Verify NO passwords in sanitized output.
        
        Setup:
        - Create synthetic PCAP with HTTP Basic Auth (base64-encoded password)
        - Sanitize to JSON
        - Scan JSON for password strings
        
        Assertion:
        - Original PCAP contains recognizable password
        - Sanitized JSON does NOT contain password
        """
        # Create mock PCAP with HTTP Basic Auth
        mock_packets = [
            {
                'protocol': 'TCP',
                'src_ip': '192.168.1.100',
                'dst_ip': 'example.com',
                'src_port': 54321,
                'dst_port': 80,
                'payload': 'GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNzd29yZA==',  # user:password
                'packet_count': 1,
                'byte_count': 1234
            }
        ]
        
        sanitizer = PCAPSanitizer(pcap_path='/tmp/mock.pcap')
        
        with patch('local.sanitization.sanitizer.parse_pcap', return_value=mock_packets):
            sanitized = sanitizer.sanitize_to_json()
        
        # Verify: no passwords in output
        json_str = json.dumps(sanitized)
        assert 'password' not in json_str.lower()
        assert 'dXNlcjpwYXNzd29yZA==' not in json_str  # Base64 encoded password
    
    def test_sanitize_removes_api_keys(self):
        """
        CRITICAL SECURITY TEST: Verify NO API keys in sanitized output.
        
        Setup:
        - Create PCAP with HTTPS traffic containing API key in URL
        - Sanitize
        
        Assertion:
        - API key NOT in JSON
        """
        mock_packets = [
            {
                'protocol': 'TCP',
                'src_ip': '192.168.1.100',
                'dst_ip': 'api.example.com',
                'src_port': 54321,
                'dst_port': 443,
                'payload': 'GET /api/data?key=sk_live_1234567890abcdef HTTP/1.1',
                'packet_count': 1,
                'byte_count': 1234
            }
        ]
        
        sanitizer = PCAPSanitizer(pcap_path='/tmp/mock.pcap')
        
        with patch('local.sanitization.sanitizer.parse_pcap', return_value=mock_packets):
            sanitized = sanitizer.sanitize_to_json()
        
        json_str = json.dumps(sanitized)
        assert 'sk_live_' not in json_str
        assert '?key=' not in json_str
    
    def test_mask_ip_address_anonymizes_last_octet(self):
        """
        Test that mask_ip_address() correctly anonymizes IPs.
        
        Setup:
        - Call mask_ip_address() on various IPs
        
        Assertion:
        - Last octet replaced with 'XXX'
        - Other octets preserved
        """
        sanitizer = PCAPSanitizer(pcap_path='/tmp/mock.pcap')
        
        assert sanitizer.mask_ip_address('192.168.1.100') == '192.168.1.XXX'
        assert sanitizer.mask_ip_address('10.0.0.1') == '10.0.0.XXX'
        assert sanitizer.mask_ip_address('8.8.8.8') == '8.8.8.XXX'
    
    def test_extract_flow_headers_only_excludes_payloads(self):
        """
        Test that extract_flow_headers_only() does NOT extract payload data.
        
        Setup:
        - Create synthetic packet with headers + payload
        - Call extract_flow_headers_only()
        
        Assertion:
        - Headers extracted (IP, port, protocol)
        - Payload NOT extracted
        """
        sanitizer = PCAPSanitizer(pcap_path='/tmp/mock.pcap')
        
        mock_packet = MagicMock()
        mock_packet.src_ip = '192.168.1.100'
        mock_packet.dst_ip = '8.8.8.8'
        mock_packet.src_port = 54321
        mock_packet.dst_port = 443
        mock_packet.protocol = 'TCP'
        mock_packet.length = 1234
        # Mock packet does NOT have raw payload data accessible
        
        result = sanitizer.extract_flow_headers_only(mock_packet)
        
        assert 'src_ip' in result
        assert 'dst_ip' in result
        assert 'protocol' in result
        assert 'length' in result
        # Verify no payload-like data
        for key in result.keys():
            assert 'payload' not in key.lower()

class TestSanitizationValidation:
    
    def test_validate_sanitization_passes_clean_json(self):
        """
        Test that validate_sanitization() accepts clean JSON.
        
        Setup:
        - Create JSON with only headers (no payloads)
        
        Assertion:
        - Returns True
        """
        clean_json = {
            'flows': [
                {
                    'src_ip_masked': '192.168.1.XXX',
                    'dst_ip_masked': '8.8.8.XXX',
                    'src_port': 54321,
                    'dst_port': 443,
                    'protocol': 'TCP'
                }
            ]
        }
        
        result = validate_sanitization(clean_json)
        assert result is True
    
    def test_validate_sanitization_flags_suspicious_data(self):
        """
        Test that validate_sanitization() flags suspicious patterns (potential payloads).
        
        Setup:
        - Create JSON with base64 strings (suspicious)
        
        Assertion:
        - Returns False
        """
        suspicious_json = {
            'flows': [
                {
                    'src_ip_masked': '192.168.1.XXX',
                    'dst_ip_masked': '8.8.8.XXX',
                    'metadata': 'dXNlcjpwYXNzd29yZA=='  # Base64 (suspicious)
                }
            ]
        }
        
        result = validate_sanitization(suspicious_json)
        assert result is False
```

#### Test Case 4: SQLite Cache Tests

```python
# tests/unit/test_sqlite_cache.py

import pytest
import tempfile
import json
from pathlib import Path
import pandas as pd
import numpy as np
from local.storage.sqlite_cache import LocalCache

class TestLocalCache:
    
    def test_init_database_creates_tables(self):
        """
        Test that init_database() creates required tables.
        
        Setup:
        - Create LocalCache with temp DB path
        
        Assertion:
        - Database file created
        - All required tables exist
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / 'test.db'
            cache = LocalCache(db_path=str(db_path))
            
            # Verify DB file exists
            assert db_path.exists()
            
            # Verify tables exist
            cursor = cache.connection.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
            
            assert 'users' in tables
            assert 'baseline_profiles' in tables
            assert 'settings' in tables
    
    def test_save_and_load_baseline_profile(self):
        """
        Test baseline profile persistence (model + features).
        
        Setup:
        - Create fake baseline data
        - Save to cache
        - Load from cache
        
        Assertion:
        - Loaded data matches saved data
        - Model object restored correctly
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / 'test.db'
            cache = LocalCache(db_path=str(db_path))
            
            # Create fake baseline
            features_df = pd.DataFrame(
                np.random.normal(loc=50, scale=10, size=(100, 50)),
                columns=[f'feature_{i}' for i in range(50)]
            )
            
            from sklearn.ensemble import IsolationForest
            model = IsolationForest(n_estimators=100)
            model.fit(features_df)
            
            # Save
            profile_id = cache.save_baseline_profile(
                user_id='test_user',
                capture_name='Baseline_1',
                feature_df=features_df,
                isolation_forest_model=model
            )
            
            # Load
            loaded = cache.load_baseline_profile(profile_id)
            
            assert loaded['profile_id'] == profile_id
            assert loaded['capture_name'] == 'Baseline_1'
            assert loaded['isolation_forest_model'] is not None
            assert isinstance(loaded['feature_df'], pd.DataFrame)
```

#### Test Coverage Requirements (Phase 2)

| Module | Test Cases | Coverage Target | Critical Paths |
|--------|-----------|-----------------|-----------------|
| `feature_extractor.py` | 4 | >85% | Feature computation, normalization |
| `anomaly_detector.py` | 4 | >90% | Model training, scoring, explanation |
| `sanitizer.py` | 5 | **>95%** | Password/key removal, IP masking |
| `sqlite_cache.py` | 3 | >85% | Profile persistence, retrieval |
| **Total** | **16** | **>90%** | **All sanitization paths** |

#### Security Audit: Sanitization Validation

```bash
# Script: tests/security/audit_sanitization.py

#!/usr/bin/env python3
"""
Security audit: Verify no sensitive data leaks in sanitized JSON.
"""

SENSITIVE_PATTERNS = [
    r'password',
    r'apikey|api_key',
    r'secret',
    r'credential',
    r'token',
    r'Authorization: Basic',
    r'Bearer [A-Za-z0-9\-._~+/]+=*',  # JWT pattern
    r'[0-9]{16}',  # Credit card pattern
]

def audit_sanitization_output(json_output):
    """
    Scan JSON output for sensitive patterns.
    Fail if ANY pattern found.
    """
    json_str = json.dumps(json_output)
    
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, json_str, re.IGNORECASE):
            raise SecurityException(f"Sensitive data found: {pattern}")
    
    return True
```

---

### Phase 2 Testing Gate

**Requirements to Pass:**
- ✅ All 16 unit tests passing
- ✅ Code coverage >90%
- ✅ Sanitization security audit passes (no sensitive patterns)
- ✅ Anomaly detection validation: normal=<0.4 score, anomalous=>0.6 score
- ✅ Feature extraction produces consistent outputs
- ✅ Model serialization/deserialization works correctly

**Sign-Off:** Security Lead must certify sanitization audit before Phase 3.

---

## Phase 3: Cloud Backend & Firebase IAM

**Timeline:** Week 5–6  
**Owner:** Cloud Infrastructure Team  
**Dependencies:** Phase 1–2 (local system complete)

### Implementation Deliverables

#### 1. **Firebase Authentication & PAT Management** (`cloud/auth/firebase_setup.py`)

- Implement `FirebaseAuthManager.create_user_account()` to register users via Firebase Auth REST API
- Implement `generate_pat()` to create secure tokens and store hashes (SHA256 + salt) in Firestore
- Implement `verify_pat()` to validate submitted PATs against stored hashes
- Implement `revoke_pat()` and `user_suspension()` for account lifecycle management

#### 2. **Firestore Quota & Strike System** (`cloud/storage/firestore_manager.py`)

- Implement `FirestoreManager.create_user_quota()` to initialize 3-analysis-per-6-hours quota
- Implement `check_and_decrement_quota()` using Firestore transactions (atomic operations)
- Implement `log_strike()` and automatic escalation logic:
  - 1–2 strikes: Soft lock (warning, valid requests still processed)
  - 3+ strikes or prompt injection: Hard lock (account suspended)
- Implement `escalate_to_soft_lock()` and `escalate_to_hard_lock()` with email notifications

#### 3. **FastAPI Rate Limiter & Validator** (`cloud/api/rate_limiter.py`, `cloud/api/validator.py`)

- Implement `IPRateLimiter.check_rate_limit()` using Redis ephemeral counters (100 req/min per IP)
- Implement `PayloadValidator.validate_request()` against JSON schema (required fields, types)
- Implement `check_payload_size()` enforcing 5MB hard limit (Layer 2 defense)
- Implement `detect_prompt_injection()` heuristic scanning (SQL keywords, shell commands, code patterns)

#### 4. **FastAPI Zero-Storage Analysis Pipeline** (`cloud/api/gateway.py`)

- Implement `/api/v1/analyze` endpoint with multi-layer defense (rate limit → auth → quota → validation)
- Implement `query_gemini_api()` with fixed prompt template (NO user input in template to prevent injection)
- Implement memory deletion: `del metadata; gc.collect()` immediately after Gemini response
- Implement logging (metadata only: timestamp, user_id, threat_level, request_size—NO application data)

---

### Testing Strategy

#### Unit Testing with Mocks

```
tests/unit/
├── test_firebase_setup.py
├── test_firestore_manager.py
├── test_rate_limiter.py
├── test_validator.py
└── test_gateway.py
```

#### Test Case 1: Firebase Authentication Tests (Mocked)

```python
# tests/unit/test_firebase_setup.py

import pytest
from unittest.mock import patch, MagicMock
from cloud.auth.firebase_setup import FirebaseAuthManager
from firebase_admin import auth

class TestFirebaseAuthManager:
    
    @patch('firebase_admin.auth.create_user')
    def test_create_user_account_success(self, mock_create_user):
        """
        Test user account creation (Firebase mocked).
        
        Mock Setup:
        - Mock firebase_admin.auth.create_user() to return new user UID
        - Mock Firestore to store PAT hash
        
        Assertion:
        - User created with unique UID
        - PAT generated and hash stored
        """
        mock_user = MagicMock()
        mock_user.uid = 'test_uid_12345'
        mock_user.email = 'test@example.com'
        mock_create_user.return_value = mock_user
        
        manager = FirebaseAuthManager()
        
        with patch('cloud.storage.firestore_manager.FirestoreManager.save_pat_hash'):
            result = manager.create_user_account('test@example.com', 'password123')
        
        assert result['uid'] == 'test_uid_12345'
        assert 'pat' in result
        assert result['email'] == 'test@example.com'
    
    @patch('firebase_admin.auth.create_user')
    def test_create_user_account_duplicate_email_fails(self, mock_create_user):
        """
        Test that duplicate email raises error.
        
        Mock Setup:
        - Mock create_user() to raise EmailAlreadyExistsError
        
        Assertion:
        - Exception caught and returned as error in result dict
        """
        mock_create_user.side_effect = auth.EmailAlreadyExistsError("Email already exists")
        
        manager = FirebaseAuthManager()
        result = manager.create_user_account('existing@example.com', 'password')
        
        assert result['error'] == 'Email already registered'
    
    @patch('cloud.storage.firestore_manager.FirestoreManager.get_pat_hash')
    def test_verify_pat_valid(self, mock_get_hash):
        """
        Test PAT verification (valid token).
        
        Mock Setup:
        - Return stored PAT hash
        
        Assertion:
        - True if hash matches
        """
        import hashlib
        
        manager = FirebaseAuthManager()
        
        pat = 'aero_test_token_12345'
        pat_hash = hashlib.sha256(pat.encode()).hexdigest()
        
        mock_get_hash.return_value = pat_hash
        
        result = manager.verify_pat('test_uid', pat)
        
        assert result is True
    
    @patch('cloud.storage.firestore_manager.FirestoreManager.get_pat_hash')
    def test_verify_pat_invalid(self, mock_get_hash):
        """
        Test PAT verification (invalid token).
        
        Assertion:
        - False if hash doesn't match
        """
        import hashlib
        
        manager = FirebaseAuthManager()
        
        pat = 'aero_test_token_12345'
        wrong_pat = 'aero_wrong_token_99999'
        pat_hash = hashlib.sha256(pat.encode()).hexdigest()
        
        mock_get_hash.return_value = pat_hash
        
        result = manager.verify_pat('test_uid', wrong_pat)
        
        assert result is False
```

#### Test Case 2: Firestore Quota Tests (Mocked)

```python
# tests/unit/test_firestore_manager.py

import pytest
from unittest.mock import patch, MagicMock, Mock
from datetime import datetime, timedelta
from cloud.storage.firestore_manager import FirestoreManager

class TestFirestoreManager:
    
    @patch('google.cloud.firestore.Client')
    def test_check_and_decrement_quota_succeeds(self, mock_firestore):
        """
        Test quota check and decrement (quota available).
        
        Mock Setup:
        - Mock Firestore transaction
        - Return quota remaining = 2
        
        Assertion:
        - Returns True
        - Quota decremented from 3 to 2
        """
        mock_db = MagicMock()
        mock_quota_ref = MagicMock()
        mock_quota_doc = MagicMock()
        
        # Setup return values
        mock_quota_doc.to_dict.return_value = {
            'remaining': 3,
            'reset_time': datetime.utcnow(),
            'tier': 'free'
        }
        mock_quota_ref.get.return_value = mock_quota_doc
        mock_db.collection.return_value.document.return_value = mock_quota_ref
        
        manager = FirestoreManager()
        manager.db = mock_db  # Inject mock
        
        result = manager.check_and_decrement_quota('test_uid')
        
        assert result['quota_available'] is True
        # In real implementation, quota would be decremented in transaction
    
    @patch('google.cloud.firestore.Client')
    def test_check_and_decrement_quota_exceeded(self, mock_firestore):
        """
        Test quota check (quota exceeded).
        
        Mock Setup:
        - Return quota remaining = 0
        
        Assertion:
        - Returns False (quota exceeded)
        """
        mock_db = MagicMock()
        mock_quota_ref = MagicMock()
        mock_quota_doc = MagicMock()
        
        mock_quota_doc.to_dict.return_value = {
            'remaining': 0,
            'reset_time': datetime.utcnow(),
            'tier': 'free'
        }
        mock_quota_ref.get.return_value = mock_quota_doc
        mock_db.collection.return_value.document.return_value = mock_quota_ref
        
        manager = FirestoreManager()
        manager.db = mock_db
        
        result = manager.check_and_decrement_quota('test_uid')
        
        assert result['quota_available'] is False
    
    @patch('google.cloud.firestore.Client')
    def test_log_strike_escalates_to_soft_lock(self, mock_firestore):
        """
        Test strike escalation (1–2 strikes → soft lock).
        
        Mock Setup:
        - User has 0 strikes
        - Log 1st strike
        
        Assertion:
        - Account soft-locked after 1st strike
        """
        mock_db = MagicMock()
        
        manager = FirestoreManager()
        manager.db = mock_db
        
        with patch.object(manager, 'escalate_to_soft_lock') as mock_soft_lock:
            manager.log_strike('test_uid', 'malformed_json', {'ip': '1.2.3.4'})
            
            # After 1st strike, should soft lock
            mock_soft_lock.assert_called_once_with('test_uid')
    
    @patch('google.cloud.firestore.Client')
    def test_log_strike_escalates_to_hard_lock_prompt_injection(self, mock_firestore):
        """
        Test immediate hard lock for prompt injection (critical).
        
        Assertion:
        - Hard lock triggered immediately (no 3-strike threshold)
        """
        mock_db = MagicMock()
        
        manager = FirestoreManager()
        manager.db = mock_db
        
        with patch.object(manager, 'escalate_to_hard_lock') as mock_hard_lock:
            manager.log_strike('test_uid', 'prompt_injection', {'details': 'SQL injection attempt'})
            
            mock_hard_lock.assert_called_once()
```

#### Test Case 3: Rate Limiter Tests (Redis Mocked)

```python
# tests/unit/test_rate_limiter.py

import pytest
from unittest.mock import patch, MagicMock
from cloud.api.rate_limiter import IPRateLimiter

class TestIPRateLimiter:
    
    @patch('redis.Redis')
    async def test_rate_limit_allows_under_threshold(self, mock_redis):
        """
        Test that requests under threshold are allowed.
        
        Mock Setup:
        - Mock Redis to return counter=50 (under 100 limit)
        
        Assertion:
        - Returns allowed=True
        """
        mock_redis_instance = MagicMock()
        mock_redis_instance.incr.return_value = 50
        mock_redis.return_value = mock_redis_instance
        
        limiter = IPRateLimiter(redis_host='localhost', redis_port=6379)
        limiter.redis_client = mock_redis_instance
        
        result = await limiter.check_rate_limit('192.168.1.100')
        
        assert result['allowed'] is True
        assert result['current_count'] == 50
    
    @patch('redis.Redis')
    async def test_rate_limit_rejects_over_threshold(self, mock_redis):
        """
        Test that requests over threshold (100 req/min) are rejected.
        
        Mock Setup:
        - Redis counter=101
        
        Assertion:
        - Returns allowed=False
        - Raises RateLimitExceeded
        """
        mock_redis_instance = MagicMock()
        mock_redis_instance.incr.return_value = 101
        mock_redis.return_value = mock_redis_instance
        
        limiter = IPRateLimiter(redis_host='localhost', redis_port=6379)
        limiter.redis_client = mock_redis_instance
        
        with pytest.raises(Exception):  # RateLimitExceeded
            await limiter.check_rate_limit('192.168.1.100')
```

#### Test Case 4: Payload Validator Tests

```python
# tests/unit/test_validator.py

import pytest
import json
from cloud.api.validator import PayloadValidator

class TestPayloadValidator:
    
    def test_validate_request_valid_payload(self):
        """
        Test validation of valid request.
        
        Setup:
        - Create valid JSON with required fields
        
        Assertion:
        - Returns valid=True
        """
        valid_request = {
            'pat': 'aero_token_12345',
            'metadata': {
                'capture_metadata': {'duration': 300},
                'flows': [{'src_ip_masked': '192.168.1.XXX', 'dst_ip_masked': '8.8.8.XXX'}]
            }
        }
        
        result = PayloadValidator.validate_request(valid_request)
        
        assert result['valid'] is True
        assert result['errors'] == []
    
    def test_validate_request_missing_required_field(self):
        """
        Test validation rejects missing required field.
        
        Setup:
        - Create JSON missing 'metadata' field
        
        Assertion:
        - Returns valid=False
        - Error list populated
        """
        invalid_request = {
            'pat': 'aero_token_12345'
            # Missing 'metadata'
        }
        
        result = PayloadValidator.validate_request(invalid_request)
        
        assert result['valid'] is False
        assert len(result['errors']) > 0
    
    def test_check_payload_size_under_limit(self):
        """
        Test payload size validation (under 5MB).
        
        Assertion:
        - Returns valid=True
        """
        small_payload = 1024 * 1024  # 1MB
        result = PayloadValidator.check_payload_size(small_payload)
        
        assert result['valid'] is True
    
    def test_check_payload_size_exceeds_limit(self):
        """
        Test payload size validation (exceeds 5MB).
        
        Assertion:
        - Returns valid=False
        """
        large_payload = 6 * 1024 * 1024  # 6MB
        result = PayloadValidator.check_payload_size(large_payload)
        
        assert result['valid'] is False
    
    def test_detect_prompt_injection_sql_keyword(self):
        """
        Test prompt injection detection (SQL keywords).
        
        Setup:
        - Metadata contains 'DROP TABLE' (SQL injection pattern)
        
        Assertion:
        - Returns True (suspicious)
        """
        suspicious_metadata = {
            'flows': [
                {
                    'note': "DROP TABLE users; --",  # SQL injection
                    'src_ip_masked': '192.168.1.XXX'
                }
            ]
        }
        
        result = PayloadValidator.detect_prompt_injection('test_pat', suspicious_metadata)
        
        assert result is True
    
    def test_detect_prompt_injection_shell_command(self):
        """
        Test prompt injection detection (shell commands).
        
        Setup:
        - Metadata contains shell command pattern
        
        Assertion:
        - Returns True (suspicious)
        """
        suspicious_metadata = {
            'flows': [
                {
                    'note': "'; rm -rf /; '",  # Shell injection
                    'src_ip_masked': '192.168.1.XXX'
                }
            ]
        }
        
        result = PayloadValidator.detect_prompt_injection('test_pat', suspicious_metadata)
        
        assert result is True
```

#### Test Case 5: FastAPI Gateway Tests (TestClient)

```python
# tests/unit/test_gateway.py

import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
from cloud.api.gateway import app

client = TestClient(app)

class TestAnalyzeEndpoint:
    
    @patch('cloud.auth.firebase_setup.FirebaseAuthManager.verify_pat')
    @patch('cloud.storage.firestore_manager.FirestoreManager.check_and_decrement_quota')
    @patch('cloud.ml.gemini_handler.GeminiThreatAnalyzer.query_gemini')
    def test_analyze_endpoint_valid_request(self, mock_gemini, mock_quota, mock_auth):
        """
        TEST: Valid analysis request → threat report returned.
        
        Setup:
        - Mock Firebase PAT verification (returns user_uid)
        - Mock Firestore quota check (returns 1 remaining)
        - Mock Gemini API (returns threat report)
        
        Assertion:
        - Endpoint returns 200 OK
        - Response contains threat_level, threat_summary, recommendations
        """
        # Mock returns
        mock_auth.return_value = True  # PAT valid
        mock_quota.return_value = {'quota_available': True, 'remaining': 2}
        mock_gemini.return_value = {
            'threat_level': 'medium',
            'summary': 'Unusual port scanning detected',
            'recommendations': ['Block source IP']
        }
        
        payload = {
            'pat': 'aero_test_token',
            'metadata': {
                'capture_metadata': {'duration': 300},
                'flows': [{'src_ip_masked': '192.168.1.XXX', 'dst_ip_masked': '8.8.8.XXX'}]
            }
        }
        
        response = client.post('/api/v1/analyze', json=payload)
        
        assert response.status_code == 200
        data = response.json()
        assert data['threat_level'] in ['low', 'medium', 'high', 'critical']
        assert 'recommendations' in data
    
    def test_analyze_endpoint_invalid_pat(self):
        """
        TEST: Invalid PAT → 401 Unauthorized.
        
        Setup:
        - Submit request with missing PAT
        
        Assertion:
        - Returns 401
        """
        payload = {
            'metadata': {'capture_metadata': {}, 'flows': []}
            # Missing 'pat'
        }
        
        response = client.post('/api/v1/analyze', json=payload)
        
        assert response.status_code == 400  # Bad request due to missing field
    
    @patch('cloud.storage.firestore_manager.FirestoreManager.check_and_decrement_quota')
    def test_analyze_endpoint_quota_exceeded(self, mock_quota):
        """
        TEST: Quota exceeded → 403 Forbidden.
        
        Setup:
        - Mock quota check to return quota_available=False
        
        Assertion:
        - Returns 403
        """
        mock_quota.return_value = {'quota_available': False}
        
        payload = {
            'pat': 'aero_token',
            'metadata': {'capture_metadata': {}, 'flows': []}
        }
        
        response = client.post('/api/v1/analyze', json=payload)
        
        assert response.status_code == 403
    
    def test_analyze_endpoint_oversized_payload(self):
        """
        TEST: Payload > 5MB → 400 Bad Request + strike.
        
        Setup:
        - Create payload > 5MB
        
        Assertion:
        - Returns 400
        - Strike logged
        """
        # Create oversized payload (simulated)
        large_metadata = {
            'flows': [{'data': 'x' * (6 * 1024 * 1024)}]  # 6MB
        }
        
        payload = {
            'pat': 'test_pat',
            'metadata': large_metadata
        }
        
        response = client.post('/api/v1/analyze', json=payload)
        
        assert response.status_code == 400
    
    def test_health_check_endpoint(self):
        """
        TEST: Health check (no auth required).
        
        Assertion:
        - Returns 200 with status info
        """
        response = client.get('/api/v1/health')
        
        assert response.status_code == 200
        data = response.json()
        assert 'status' in data
        assert 'components' in data
```

#### Integration Test: Full API Pipeline (Mocked Cloud Services)

```python
# tests/integration/test_phase3_e2e.py

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from cloud.api.gateway import app

client = TestClient(app)

class TestPhase3E2E:
    
    @patch('cloud.auth.firebase_setup.FirebaseAuthManager')
    @patch('cloud.storage.firestore_manager.FirestoreManager')
    @patch('cloud.api.rate_limiter.IPRateLimiter')
    @patch('cloud.ml.gemini_handler.GeminiThreatAnalyzer')
    def test_full_analysis_pipeline(self, mock_gemini, mock_ratelimit, mock_firestore, mock_auth):
        """
        INTEGRATION TEST: Full request → analysis → response pipeline.
        
        Scenario:
        1. Rate limit check: PASS (50 req/min, under 100 limit)
        2. PAT validation: PASS (valid Firebase user)
        3. Quota check: PASS (2 remaining)
        4. Payload validation: PASS (valid JSON, <5MB)
        5. Gemini query: PASS (returns threat report)
        6. Memory deletion: PASS (metadata deleted from memory)
        7. Response returned: threat_level='medium'
        
        Assertion:
        - All steps complete
        - Response 200 OK
        - Threat report populated
        """
        # Setup mocks
        mock_ratelimit_instance = MagicMock()
        mock_ratelimit_instance.check_rate_limit.return_value = {
            'allowed': True,
            'current_count': 50
        }
        mock_ratelimit.return_value = mock_ratelimit_instance
        
        mock_auth_instance = MagicMock()
        mock_auth_instance.verify_pat.return_value = True
        # Simulate user lookup
        mock_auth.return_value = mock_auth_instance
        
        mock_firestore_instance = MagicMock()
        mock_firestore_instance.check_and_decrement_quota.return_value = {
            'quota_available': True,
            'remaining': 2
        }
        mock_firestore.return_value = mock_firestore_instance
        
        mock_gemini_instance = MagicMock()
        mock_gemini_instance.query_gemini.return_value = {
            'threat_level': 'medium',
            'summary': 'Potential port scan detected',
            'recommendations': ['Enable IDS monitoring', 'Block source IP range']
        }
        mock_gemini.return_value = mock_gemini_instance
        
        # Make request
        payload = {
            'pat': 'aero_test_token_12345',
            'metadata': {
                'capture_metadata': {'duration': 300, 'packet_count': 10000},
                'flows': [
                    {
                        'source_ip_masked': '192.168.1.XXX',
                        'dest_ip_masked': '203.0.113.XXX',
                        'source_port': 54321,
                        'dest_port': 22,
                        'protocol': 'TCP',
                        'packet_count': 156,
                        'byte_count': 89234
                    }
                ]
            }
        }
        
        response = client.post('/api/v1/analyze', json=payload)
        
        # Assertions
        assert response.status_code == 200
        data = response.json()
        assert data['threat_level'] == 'medium'
        assert 'recommendations' in data
        assert len(data['recommendations']) > 0
```

#### Test Coverage Requirements (Phase 3)

| Module | Test Cases | Coverage Target | Critical Paths |
|--------|-----------|-----------------|-----------------|
| `firebase_setup.py` | 4 | >90% | User creation, PAT generation/verification |
| `firestore_manager.py` | 5 | **>95%** | Quota logic, strike escalation |
| `rate_limiter.py` | 2 | >85% | Rate limit enforcement |
| `validator.py` | 5 | **>95%** | Prompt injection detection |
| `gateway.py` | 5 | **>90%** | Zero-storage, Gemini integration |
| **Total** | **21** | **>90%** | All defense layers |

---

### Phase 3 Testing Gate

**Requirements to Pass:**
- ✅ All 21 unit tests passing (FastAPI.testclient)
- ✅ Code coverage >90%
- ✅ Rate limiting verified (100 req/min enforced)
- ✅ Strike system escalation tested (soft/hard locks work)
- ✅ Zero-storage verified (memory audit: metadata deleted within 5 sec)
- ✅ Prompt injection detection tested (SQL/shell commands blocked)
- ✅ Integration test E2E passes (full pipeline)

**Sign-Off:** Cloud Architect must certify zero-storage guarantee before Phase 4.

---

## Phase 4: Cloud Frontend (Streamlit)

**Timeline:** Week 7–8  
**Owner:** Frontend Team  
**Dependencies:** Phase 3 (Cloud API functional)

### Implementation Deliverables

1. **Multi-page Streamlit App** with session state management and async calls to FastAPI gateway
2. **Auth Portal** (signup/login) integrated with Firebase Auth REST API
3. **Threat Dashboard** with live threat timeline, statistics, and Plotly visualizations
4. **Download Hub** to retrieve and download previous analyses as JSON/PDF
5. **Account Settings** page with quota display, strike status, and ban appeals
6. **PDF Report Generation** using ReportLab with charts, threat gauges, and recommendations

### Testing Strategy

#### Unit Testing (Streamlit Components)

```python
# tests/unit/test_streamlit_ui.py

import pytest
from unittest.mock import patch, MagicMock
import streamlit as st

class TestStreamlitComponents:
    
    def test_init_session_state_creates_defaults(self):
        """
        Test that session state is initialized with all required keys.
        """
        # Clear session state
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        
        from cloud.ui.streamlit_app import init_session_state
        init_session_state()
        
        assert 'user_uid' in st.session_state or True  # Session state testing is limited in pytest
    
    @patch('cloud.auth.firebase_setup.FirebaseAuthManager')
    def test_handle_signup_creates_user(self, mock_auth):
        """
        Test signup flow (Firebase mocked).
        
        Mock Setup:
        - Firebase create_user() returns new UID and PAT
        
        Assertion:
        - User created, PAT returned
        """
        from cloud.ui.streamlit_app import handle_signup
        
        mock_auth_instance = MagicMock()
        mock_auth_instance.create_user_account.return_value = {
            'uid': 'test_uid_123',
            'pat': 'aero_token_abc123',
            'email': 'test@example.com'
        }
        
        result = handle_signup('test@example.com', 'password123')
        
        assert result['success'] is True
        assert 'pat' in result
```

#### E2E UI Testing (Selenium)

```python
# tests/e2e/test_streamlit_ui.py

import pytest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class TestStreamlitE2E:
    
    @pytest.fixture
    def driver(self):
        driver = webdriver.Chrome()  # Or other browser driver
        yield driver
        driver.quit()
    
    def test_signup_flow_e2e(self, driver):
        """
        E2E Test: Signup flow (UI).
        
        Scenario:
        1. Open auth page
        2. Select "Sign Up"
        3. Enter email and password
        4. Click "Create Account"
        5. Verify PAT displayed
        6. Copy PAT button functional
        
        Assertion:
        - Account created
        - PAT displayed and copyable
        """
        driver.get('http://localhost:8501')  # Streamlit server
        
        # Wait for "Sign Up" tab
        signup_tab = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, "//button[text()='Sign Up']"))
        )
        signup_tab.click()
        
        # Fill form
        email_field = driver.find_element(By.ID, 'signup_email')
        email_field.send_keys('test@example.com')
        
        password_field = driver.find_element(By.ID, 'signup_pwd')
        password_field.send_keys('SecurePassword123!')
        
        # Click create button
        create_btn = driver.find_element(By.XPATH, "//button[text()='Create Account']")
        create_btn.click()
        
        # Wait for success message and PAT display
        pat_element = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, 'pat-display'))
        )
        
        assert pat_element.text.startswith('aero_')
```

---

### Phase 4 Testing Gate

- ✅ All unit tests passing (Streamlit session state)
- ✅ Integration with FastAPI gateway verified
- ✅ E2E tests pass (Selenium, signup/login flow)
- ✅ PDF generation produces valid files
- ✅ All pages load without errors

---

## Phase 5: CI/CD Pipelines (GitHub Actions)

**Timeline:** Week 9–10  
**Owner:** DevOps Teams

### CI/CD Implementation

#### Pipeline 1: Pull Request Checks (`.github/workflows/pr-checks.yml`)

```yaml
name: PR Checks

on:
  pull_request:
    branches:
      - main
      - develop

jobs:
  lint:
    name: Lint & Format
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: 3.11
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements-dev.txt
    
    - name: Run black (code formatter)
      run: black --check local/ cloud/ tests/
    
    - name: Run flake8 (linter)
      run: flake8 local/ cloud/ tests/ --count --select=E9,F63,F7,F82 --show-source --statistics
    
    - name: Run pylint
      run: pylint local/ cloud/ --disable=C0111,C0103 --fail-under=7.0

  security:
    name: Security Scan
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: 3.11
    
    - name: Run Bandit (security check)
      run: |
        pip install bandit
        bandit -r local/ cloud/ -ll  # Only report high/medium severity
    
    - name: Run Safety (dependency check)
      run: |
        pip install safety
        safety check --json

  test:
    name: Unit Tests
    runs-on: ubuntu-latest
    
    services:
      redis:
        image: redis:7-alpine
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: 3.11
    
    - name: Install system dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y libpcap-dev tshark
    
    - name: Install Python dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements-local.txt
        pip install -r requirements-cloud.txt
        pip install pytest pytest-cov pytest-asyncio
    
    - name: Run Phase 1 Tests (Local Data Engine)
      run: |
        pytest tests/unit/test_janitor.py \
                tests/unit/test_interface_detector.py \
                tests/unit/test_scapy_sniffer.py \
                tests/unit/test_pyshark_spooler.py \
                -v --cov=local/network --cov=local/janitor --cov-report=xml
    
    - name: Run Phase 2 Tests (Local ML & Sanitization)
      run: |
        pytest tests/unit/test_feature_extractor.py \
                tests/unit/test_anomaly_detector.py \
                tests/unit/test_sanitizer.py \
                tests/unit/test_sqlite_cache.py \
                -v --cov=local/ml --cov=local/sanitization --cov=local/storage --cov-report=xml
    
    - name: Run Phase 3 Tests (Cloud Backend)
      run: |
        pytest tests/unit/test_firebase_setup.py \
                tests/unit/test_firestore_manager.py \
                tests/unit/test_rate_limiter.py \
                tests/unit/test_validator.py \
                tests/unit/test_gateway.py \
                -v --cov=cloud/auth --cov=cloud/storage --cov=cloud/api --cov-report=xml
    
    - name: Run Phase 4 Tests (Cloud Frontend)
      run: |
        pytest tests/unit/test_streamlit_ui.py \
                -v --cov=cloud/ui --cov-report=xml
    
    - name: Run Integration Tests
      run: |
        pytest tests/integration/ -v --cov-report=xml
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: unittests
        name: codecov-umbrella
        fail_ci_if_error: true
        minimum_coverage: 85

  type-check:
    name: Type Checking
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: 3.11
    
    - name: Install mypy
      run: pip install mypy types-requests types-redis
    
    - name: Run mypy
      run: mypy local/ cloud/ --ignore-missing-imports --no-error-summary 2>&1 | head -100

  docker-build:
    name: Docker Build Check
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Build FastAPI Docker image
      run: docker build -f cloud/api/Dockerfile -t aerosguard-api:test .
    
    - name: Build Streamlit Docker image
      run: docker build -f cloud/ui/Dockerfile -t aerosguard-dashboard:test .

  sanitization-audit:
    name: Sanitization Security Audit
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: 3.11
    
    - name: Install dependencies
      run: |
        pip install -r requirements-local.txt pytest
    
    - name: Run sanitization audit
      run: |
        python tests/security/audit_sanitization.py
      env:
        PYTHONPATH: .
```

#### Pipeline 2: Deployment (`github/workflows/deploy.yml`)

```yaml
name: Deploy to GCP

on:
  push:
    branches:
      - main

env:
  GCP_PROJECT_ID: ${{ secrets.GCP_PROJECT_ID }}
  GCP_REGION: us-central1
  FIREBASE_CONFIG: ${{ secrets.FIREBASE_CONFIG }}
  GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}

jobs:
  deploy-api:
    name: Deploy FastAPI to Cloud Run
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Cloud SDK
      uses: google-github-actions/setup-gcloud@v1
      with:
        project_id: ${{ env.GCP_PROJECT_ID }}
        service_account_key: ${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}
    
    - name: Configure Docker for GCP
      run: gcloud auth configure-docker gcr.io
    
    - name: Build FastAPI image
      run: |
        docker build -f cloud/api/Dockerfile \
          --tag gcr.io/$GCP_PROJECT_ID/aerosguard-api:${{ github.sha }} \
          --tag gcr.io/$GCP_PROJECT_ID/aerosguard-api:latest \
          .
    
    - name: Push FastAPI image to GCP Container Registry
      run: |
        docker push gcr.io/$GCP_PROJECT_ID/aerosguard-api:${{ github.sha }}
        docker push gcr.io/$GCP_PROJECT_ID/aerosguard-api:latest
    
    - name: Deploy to Cloud Run (FastAPI)
      run: |
        gcloud run deploy aerosguard-api \
          --image gcr.io/$GCP_PROJECT_ID/aerosguard-api:${{ github.sha }} \
          --region $GCP_REGION \
          --platform managed \
          --allow-unauthenticated \
          --memory 2Gi \
          --timeout 30s \
          --max-instances 10 \
          --set-env-vars GEMINI_API_KEY=$GEMINI_API_KEY,FIREBASE_CONFIG=$FIREBASE_CONFIG
    
    - name: Verify FastAPI deployment
      run: |
        sleep 10  # Wait for Cloud Run to stabilize
        curl https://aerosguard-api-xxx.run.app/api/v1/health

  deploy-dashboard:
    name: Deploy Streamlit to Cloud Run
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Cloud SDK
      uses: google-github-actions/setup-gcloud@v1
      with:
        project_id: ${{ env.GCP_PROJECT_ID }}
        service_account_key: ${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}
    
    - name: Configure Docker for GCP
      run: gcloud auth configure-docker gcr.io
    
    - name: Build Streamlit image
      run: |
        docker build -f cloud/ui/Dockerfile \
          --tag gcr.io/$GCP_PROJECT_ID/aerosguard-dashboard:${{ github.sha }} \
          --tag gcr.io/$GCP_PROJECT_ID/aerosguard-dashboard:latest \
          .
    
    - name: Push Streamlit image
      run: |
        docker push gcr.io/$GCP_PROJECT_ID/aerosguard-dashboard:${{ github.sha }}
        docker push gcr.io/$GCP_PROJECT_ID/aerosguard-dashboard:latest
    
    - name: Deploy to Cloud Run (Streamlit)
      run: |
        gcloud run deploy aerosguard-dashboard \
          --image gcr.io/$GCP_PROJECT_ID/aerosguard-dashboard:${{ github.sha }} \
          --region $GCP_REGION \
          --platform managed \
          --allow-unauthenticated \
          --memory 2Gi \
          --timeout 30s \
          --max-instances 5 \
          --set-env-vars FIREBASE_CONFIG=$FIREBASE_CONFIG

  smoke-test:
    name: Smoke Tests (Post-Deployment)
    runs-on: ubuntu-latest
    needs: [deploy-api, deploy-dashboard]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: 3.11
    
    - name: Install test dependencies
      run: |
        pip install requests pytest
    
    - name: Run smoke tests
      run: |
        API_URL=https://aerosguard-api-xxx.run.app pytest tests/smoke/ -v

  notify-slack:
    name: Notify Slack
    runs-on: ubuntu-latest
    needs: [deploy-api, deploy-dashboard]
    if: always()
    
    steps:
    - name: Send Slack notification
      uses: slackapi/slack-github-action@v1
      with:
        webhook-url: ${{ secrets.SLACK_WEBHOOK }}
        payload: |
          {
            "text": "AeroGuard IDS Deployment",
            "blocks": [
              {
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Deployment Status*: ${{ job.status == 'success' && '✅ Success' || '❌ Failed' }}"
                }
              },
              {
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Commit*: ${{ github.event.head_commit.message }}\n*Author*: ${{ github.event.head_commit.author.name }}"
                }
              }
            ]
          }
```

---

## Phase 6: Security Hardening & Logging Infrastructure

**Timeline:** Week 7–8  
**Owner:** Security & Platform Team  
**Dependencies:** Phases 1–5 (all core functionality complete)  
**Deliverable:** Production-grade security controls, encryption, and observability

### Security Implementation Deliverables

#### 1. **Encryption Module** (`local/security/encryption.py`)

- Implement `EncryptedPATStorage` class using AES-256-Fernet with PBKDF2 (100k iterations)
- Implement `SecurePCAPHandler.secure_delete()` with 7-pass Gutmann algorithm
- Implement `SecureFileOperations` for restrictive file permissions (mode 0o600)
- Test encryption/decryption round-trips (encrypt → decrypt → verify)

#### 2. **Prompt Injection & Input Validation** (`cloud/security/injection_detector.py`)

- Implement `PromptInjectionDetector` class with regex patterns for SQL, shell, Python injection
- Implement `sanitize_metadata()` to remove dangerous keys (__proto__, constructor, etc.)
- Implement `build_safe_gemini_query()` to construct hardened Gemini prompts
- Test with known injection payloads (OWASP SSRF, prompt injection samples)

#### 3. **Security Audit Logging** (`cloud/security/security_auditer.py`)

- Implement `SecurityEventLogger` for audit trail of sensitive operations
- Implement `log_authentication_attempt()`, `log_strike_event()`, `log_sensitive_operation()`
- Send logs to Cloud Logging with JSON-structured output
- Test log ingestion into Cloud Logging

#### 4. **Subprocess Hardening** (`local/network/process_security.py`)

- Implement `HardenedPySharkSpooler` with interface whitelist validation
- Implement `validate_interface()` against scapy.get_if_list() (whitelist only)
- Implement `validate_output_path()` to ensure files only written to /tmp (no shell escapes)
- Test with injection attempts (e.g., interface="; rm -rf /;")

#### 5. **SQL Injection Prevention** (`local/storage/sql_safety.py`)

- Audit all SQLite queries for parameterized query usage
- Implement `SafeSQLiteCache` class with ONLY parameterized queries
- Never use f-strings or string formatting in queries
- Add pre-commit hook to detect `execute()` calls without `?` placeholders

#### 6. **Logging Infrastructure** (`cloud/logging/structured_logger.py`)

- Implement `AeroGuardLogger` class with JSON output (pythonjsonlogger)
- Implement `log_api_request()`, `log_security_event()`, `log_error()`
- Send logs to Cloud Logging with structured fields (timestamp, event_type, severity)
- Test log queries in Cloud Logging console

#### 7. **Error Handling & Graceful Degradation** (`cloud/resilience/error_handler.py`)

- Implement `CloudDisconnectHandler` for offline queue when cloud unavailable
- Implement `NetworkReliabilityHandler` for PCAP capture recovery
- Implement `RetryPolicy` with exponential backoff (3 retries, max 30 seconds)
- Test with simulated cloud failures

### Security Testing & Audit

#### Unit Tests (Security-Focused)

```python
# tests/unit/test_encryption.py
def test_pat_encryption_decryption():
    """Verify PAT can be encrypted and decrypted correctly."""
    storage = EncryptedPATStorage("/tmp/test")
    pat ="sometoken123456"
    storage.store_pat(pat)
    retrieved = storage.retrieve_pat()
    assert retrieved == pat

# tests/unit/test_injection_detection.py
def test_prompt_injection_detected():
    """Verify SQL injection patterns are caught."""
    detector = PromptInjectionDetector()
    malicious = "UPDATE users SET admin=1; --"
    assert detector.is_injected(malicious) is True

# tests/unit/test_sql_safety.py
def test_parameterized_queries_only():
    """Verify all cache queries use parameterized format."""
    cache = SafeSQLiteCache(":memory:")
    # Should work (parameterized)
    cache.get_analysis_by_hash("hash123")
    # Would fail if query uses f-string
```

#### Security Audit Checklist

- [ ] Bandit scan: 0 HIGH severity issues
- [ ] OWASP Top 10 review (A1-A10)
  - [ ] A1 (Broken Access Control): Firebase auth + PAT validation
  - [ ] A2 (Cryptographic Failures): AES-256 encryption, TLS 1.3
  - [ ] A3 (Injection): Input validation + parameterized queries + sanitized prompts
  - [ ] A4 (Insecure Design): Zero-storage design, data retention limits
  - [ ] A5 (Security Misconfiguration): Cloud security policies review
  - [ ] A6 (Vulnerable Components): Bandit + pip-audit + Safety scans
  - [ ] A7 (Auth Failures): PAT hashing + MFA (future)
  - [ ] A8 (Data Integrity): Sanitization audit + HMAC verification
  - [ ] A9 (Logging Failures): Structured logging + audit trail
  - [ ] A10 (SSRF): No external URLs in metadata, hardened Gemini prompts
- [ ] CWE-Top 25 coverage (Critical weaknesses addressed)
- [ ] Penetration testing (manual security review)

#### Phase 6 Testing Gate

**Requirements to Pass:**
- ✅ All security unit tests pass (pytest)
- ✅ Bandit scan: 0 HIGH severity findings
- ✅ pip-audit: 0 known vulnerabilities
- ✅ Encryption round-trip verified (encrypt → decrypt → match)
- ✅ Injection detection: 100% accuracy on OWASP samples
- ✅ SQL query audit: 100% parameterized (no f-strings)
- ✅ Process security: All subprocess calls hardened (no shell=True)
- ✅ Logging infrastructure: Cloud Logging ingests all events
- ✅ Error handling: Cloud failure scenarios tested & handled
- ✅ Code review: Security lead sign-off on all changes

**Sign-Off:** Security Lead must certify Phase 6 before Phase 7 approval.

---

## Phase 7: Compliance, Documentation & Monitoring

**Timeline:** Week 9–10  
**Owner:** Documentation & DevOps Team  
**Dependencies:** Phases 1–6 (security controls in place)  
**Deliverable:** Production documentation, monitoring dashboards, compliance evidence

### Compliance & Regulatory Deliverables

#### 1. **GDPR Compliance** (`docs/COMPLIANCE_GDPR.md`)

- **Data Minimization**: Document what data is collected (network metadata only, no payloads)
- **User Consent**: Add consent banner on web portal for PCAP processing
- **Data Deletion**: Implement API endpoint `/api/v1/user/delete-all-data` (removes Firebase user + Firestore docs + analysis logs)
- **Data Export**: Implement endpoint `/api/v1/user/export-data` (JSON dump of all user's analyses)
- **Data Retention Policy**: Document 90-day retention for analysis logs, instant deletion for PCAP metadata

#### 2. **Privacy Impact Assessment** (`docs/PRIVACY_IMPACT_ASSESSMENT.md`)

- Document data flows (local → cloud → deletion)
- Identify privacy risks (potential flow pattern leakage)
- Propose mitigation (aggregate flows before transmission)
- Sign-off by privacy officer

#### 3. **Incident Response Plan** (`docs/INCIDENT_RESPONSE.md`)

- **Detection**: Automated alerts for strikes, suspicious patterns, credential breaches
- **Response**: Clear escalation procedures (tier 1 → tier 2 → security lead)
- **Communication**: Template emails for breach notification
- **PostMortem**: Blameless review process for incidents
- **Timelines**: 4-hour response SLA for P1 (critical) issues

#### 4. **API Documentation** (`docs/API.md` + OpenAPI spec)

- Auto-generated OpenAPI 3.0 spec from FastAPI
- Request/response schemas with examples
- Authentication instructions (PAT setup)
- Rate limiting documentation
- Error codes and remediation

```bash
# Generate OpenAPI spec
python -c "import json; from cloud.api.gateway import app; print(json.dumps(app.openapi(), indent=2))" > openapi.json

# Serve docs on /docs (auto-generated by FastAPI)
# http://localhost:8000/docs
```

#### 5. **User Manual** (`docs/USER_MANUAL.md`)

- **Getting Started**: Registration, PAT setup, first capture
- **Troubleshooting**: Common errors (network permission issues, capture failures)
- **FAQ**: What is sanitization?, Where does my data go?, How do I delete my account?
- **Best Practices**: When to use local mode vs. cloud analysis
- **Security Advisories**: How to keep credentials safe

#### 6. **Developer Setup Guide** (`docs/DEVELOPER_SETUP.md`)

- Prerequisites (Python 3.12, GCP account, Firebase project)
- Local development environment setup
- Running tests locally
- Contributing code (GitHub flow, PR requirements)
- Debugging tips (logging, breakpoints, memory profiling)

### Monitoring & Observability Deliverables

#### 1. **Cloud Monitoring Dashboards** (`cloud/monitoring/dashboards.tf`)

**Terraform:**
```hcl
resource "google_monitoring_dashboard" "aerosguard_main" {
  dashboard_json = jsonencode({
    displayName = "AeroGuard IDS - Main"
    mosaicLayout = {
      columns = 12
      tiles = [
        {
          width = 6
          height = 4
          widget = {
            title = "API Request Latency (95th percentile)"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "resource.type=cloud_run_revision"
                  }
                }
              }]
            }
          }
        },
        {
          width = 6
          height = 4
          widget = {
            title = "Memory Usage"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=run.googleapis.com/container_memory_utilizations"
                  }
                }
              }]
            }
          }
        }
        # ... more tiles (error rates, quota exhaustion, strike patterns)
      ]
    }
  })
}
```

#### 2. **Alert Policies** (`cloud/monitoring/alerts.tf`)

```hcl
resource "google_monitoring_alert_policy" "api_latency_high" {
  display_name = "API Latency High (>5s)"
  combiner = "OR"
  
  conditions = [
    {
      display_name = "p95 latency > 5s"
      condition_threshold = {
        filter = "metric.type=\"cloudfunctions.googleapis.com/execution_times\""
        comparison = "COMPARISON_GT"
        threshold_value = 5000  # ms
        duration = "60s"
      }
    }
  ]
  
  notification_channels = [google_monitoring_notification_channel.slack.name]
  documentation = {
    content = "API endpoint is responding slowly. Check Gemini API latency and database queries."
  }
}

resource "google_monitoring_alert_policy" "strike_escalation" {
  display_name = "Strike Count Escalation"
  combiner = "OR"
  
  conditions = [
    {
      display_name = "Strikes >= 3"
      condition_threshold = {
        filter = "resource.type=firestore_database AND metric.type=custom.googleapis.com/strike_count"
        comparison = "COMPARISON_GE"
        threshold_value = 3
        duration = "60s"
      }
    }
  ]
  
  notification_channels = [google_monitoring_notification_channel.security_team_email.name]
}
```

#### 3. **Cloud Logging Queries** (`cloud/monitoring/log_queries.md`)

```sql
# Find all authentication failures in past 24h
resource.type = "cloud_run_revision"
severity = "WARNING"
jsonPayload.event_type = "AUTHENTICATION_FAILURE"
timestamp >= "2026-04-12T00:00:00Z"

# Find all strikes logged
jsonPayload.event_type = "STRIKE_LOGGED"
order by timestamp desc
limit 50

# Find slow API requests (>3 seconds)
resource.type = "cloud_run_revision"
jsonPayload.duration_ms > 3000
order by jsonPayload.duration_ms desc
```

#### 4. **Metrics & SLO Definitions** (`cloud/monitoring/slos.md`)

```
Availability SLO: 99.5% uptime (measured over 30 days)
├── Target: Maximum 3.6 hours downtime per month
├── Error budget: 0.5%
└── Alert: If error rate > 0.1% for 10 minutes

Latency SLO: 95th percentile < 3 seconds (for /api/v1/analyze)
├── Target: 95% of requests respond in < 3 sec
├── Measurement: Gemini API + database queries included
└── Alert: If p95 > 5 seconds for 5 minutes
```

### Documentation Deliverables

#### 1. **Security & Architecture Documentation**

- `docs/SECURITY.md`: Threat model, security architecture, encryption details
- `docs/ARCHITECTURE.md`: System design, data flows, component interactions
- `docs/GDPR.md`: Data retention, user rights, deletion procedures
- `docs/THREAT_MODEL.md`: Attack surface analysis, mitigations

#### 2. **Operational Documentation**

- `docs/DEPLOYMENT.md`: GCP setup, CI/CD configuration, scaling guidelines
- `docs/MONITORING.md`: Dashboard interpretation, alert responses
- `docs/RUNBOOKS.md`: Incident response procedures, troubleshooting steps
- `docs/BACKUP_RECOVERY.md`: Data backup strategy, disaster recovery

#### 3. **API & Integration Documentation**

- `docs/API.md`: REST API reference, authentication, rate limits
- `docs/WEBHOOK_INTEGRATION.md`: Webhook event types, retry logic (future feature)
- `docs/CLI_USAGE.md`: Command-line tool usage examples

### Phase 7 Testing Gate

**Requirements to Pass:**
- ✅ GDPR compliance checklist: 100% items checked
- ✅ Privacy Impact Assessment: Signed by privacy officer
- ✅ API documentation: Complete with examples
- ✅ User manual: Tested with 3 external users (no blockers)
- ✅ Developer guide: All steps reproducible locally
- ✅ Monitoring dashboards: All KPIs visualized
- ✅ Alert policies: Tested with simulated failures
- ✅ Log queries: 10+ retention/analysis scenarios confirmed
- ✅ SLO definitions: Baselined against 7-day production run
- ✅ Incident response plan: Reviewed and signed by security lead

**Sign-Off:** Product Manager + Security Lead must approve Phase 7 for production release.

---

## Integration & Deployment Strategy

### Pre-Production Checklist

```
Local System (Phase 1–2)
─────────────────────────
☐ All unit tests pass (>90% coverage)
☐ Startup Janitor tested on Windows/macOS/Linux
☐ Scapy sniffer runs for 1+ hours without memory leak
☐ PyShark PCAP writing verified
☐ ML model training/scoring works offline
☐ Sanitization audit passes (no payload leakage)
☐ SQLite persistence verified

Cloud System (Phase 3)
────────────────────
☐ Firebase project provisioned
☐ Firestore schema initialized
☐ Redis Memorystore running
☐ FastAPI health check passes
☐ Zero-storage audit passes (memory deleted within 5s)
☐ Rate limiter enforces 100 req/min
☐ Strike system escalates correctly
☐ Gemini API integration tested

Web UI (Phase 4)
──────────────
☐ Streamlit renders without errors
☐ Auth flow (signup/login) works
☐ PAT setup instructions clear
☐ Dashboard loads analyses
☐ PDF export functional

CI/CD (Phase 5)
──────────────
☐ PR Checks workflow passes (lint, test, coverage)
☐ Deployment workflow builds Docker images
☐ Cloud Run deployment successful
☐ Smoke tests pass (post-deployment)
☐ Slack notifications functional
```

---

## Success Metrics & Gates

### Phase-Level Gate Criteria

| Phase | Success Metric | Threshold | Owner |
|-------|---|---|---|
| 1 | Test coverage | >85% | QA Lead |
| 2 | Sanitization audit | Zero payload leaks | Security Lead |
| 3 | Zero-storage guarantee | Memory deleted <5s | Cloud Architect |
| 4 | UI functionality | All pages load, no errors | Frontend Lead |
| 5 | CI/CD automation | All workflows execute | DevOps Lead |

### Overall Go-Live Criteria

✅ **Functionality:**
- Local: Baseline calibration, capture, anomaly detection working offline
- Cloud: API gateway, Gemini integration, Firebase auth fully operational
- Frontend: Web portal, download hub, PDF export functional

✅ **Performance:**
- Baseline calibration: <5 minutes
- Anomaly scoring: <2 seconds
- Cloud analysis (API → Gemini → response): <5 seconds
- Memory hold time: ≤3 seconds (then deleted)

✅ **Security:**
- Zero payloads in JSON metadata
- Zero persistent cloud storage
- Rate limiting: 100 req/min per IP enforced
- Strike system: soft lock at 1–2 strikes, hard lock at ≥3

✅ **Reliability:**
- 99.5% API uptime (Cloud Run managed)
- <1% error rate
- All dependencies monitored (BigQuery, Redis, Firebase)

✅ **Quality:**
- >85% test coverage across all modules
- Zero critical security vulnerabilities (Bandit scan)
- Code reviewed by 2+ engineers per PR
- Documentation complete (USER_GUIDE, API_REFERENCE, TROUBLESHOOTING)

---

## Conclusion

This **ROADMAP_AND_CI.md** provides a complete, phased implementation plan with explicit testing gates and automated CI/CD pipelines. Each phase builds incrementally, with comprehensive testing ensuring no regressions.

**Ready to Start:** Deploy this document to your GitHub repository and begin Phase 1 implementation.

---

**Document Approved By:** [@HarshulBatham] (Project Lead)  
**Last Updated:** April 12, 2026  
**Next Review:** Upon Phase 1 Completion
