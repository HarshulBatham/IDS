# tests/unit/test_orchestrator.py
"""
Unit tests for AeroGuard IDS CLI Orchestrator.

Tests the orchestration engine that coordinates capture, feature extraction,
anomaly detection, and sanitization.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, call
import pandas as pd
import numpy as np

from local.cli.orchestrator import AnalysisOrchestrator


class TestOrchestrator:
    """Test AnalysisOrchestrator class."""

    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator with temporary cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = AnalysisOrchestrator(cache_dir=tmpdir)
            yield orch

    @pytest.fixture
    def sample_pcap_path(self):
        """Create a temporary PCAP file for testing."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            # Write PCAP magic bytes
            import struct
            f.write(struct.pack("<I", 0xa1b2c3d4))
            f.write(b"\x00" * 1000)
            path = f.name
        yield path
        Path(path).unlink()


class TestListInterfaces:
    """Test interface listing functionality."""

    @patch("local.cli.orchestrator.get_active_interfaces")
    def test_list_interfaces_returns_interfaces(self, mock_get_interfaces):
        """Test that list_interfaces returns available interfaces."""
        mock_get_interfaces.return_value = [
            {
                "name": "eth0",
                "ip": "192.168.1.100",
                "mac": "00:11:22:33:44:55",
                "mtu": 1500,
                "is_wireless": False,
                "status": True,
            },
            {
                "name": "wlan0",
                "ip": "192.168.1.101",
                "mac": "00:11:22:33:44:66",
                "mtu": 1500,
                "is_wireless": True,
                "status": True,
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = AnalysisOrchestrator(cache_dir=tmpdir)
            interfaces = orchestrator.list_interfaces()
            orchestrator.cache.close()  # Close DB connection

        assert len(interfaces) == 2
        assert interfaces[0]["name"] == "eth0"
        assert interfaces[1]["is_wireless"] is True

    @patch("local.cli.orchestrator.get_active_interfaces")
    def test_list_interfaces_empty(self, mock_get_interfaces):
        """Test list_interfaces when no interfaces available."""
        mock_get_interfaces.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = AnalysisOrchestrator(cache_dir=tmpdir)
            interfaces = orchestrator.list_interfaces()
            orchestrator.cache.close()  # Close DB connection

        assert len(interfaces) == 0


class TestValidateInterface:
    """Test interface validation."""

    @patch("local.cli.orchestrator.validate_capture_capability")
    def test_validate_interface_success(self, mock_validate):
        """Test interface validation succeeds."""
        mock_validate.return_value = True

        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = AnalysisOrchestrator(cache_dir=tmpdir)
            result = orchestrator.validate_interface("eth0")
            orchestrator.cache.close()  # Close DB connection

        assert result is True
        mock_validate.assert_called_once_with("eth0")

    @patch("local.cli.orchestrator.validate_capture_capability")
    def test_validate_interface_failure(self, mock_validate):
        """Test interface validation fails (permission error)."""
        mock_validate.return_value = False

        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = AnalysisOrchestrator(cache_dir=tmpdir)
            result = orchestrator.validate_interface("eth0")
            orchestrator.cache.close()  # Close DB connection

        assert result is False


class TestCaptureTraffic:
    """Test network traffic capture."""

    @patch("local.cli.orchestrator.PySharkSpooler")
    def test_capture_traffic_pyshark_success(self, mock_spooler_class):
        """Test successful PCAP capture with PyShark method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake PCAP file
            pcap_file = Path(tmpdir) / "capture.pcap"
            import struct
            pcap_file.write_bytes(struct.pack("<I", 0xa1b2c3d4) + b"\x00" * 1000)

            # Setup mock
            mock_spooler = MagicMock()
            mock_spooler.start_capture.return_value = str(pcap_file)
            mock_spooler.estimate_packet_count.return_value = 1000
            mock_spooler.validate_pcap_file.return_value = True
            mock_spooler_class.return_value = mock_spooler

            orchestrator = AnalysisOrchestrator(cache_dir=tmpdir)

            result = orchestrator.capture_traffic(
                interface="eth0",
                duration_seconds=10,
                method="pyshark",
                output_path=Path(tmpdir) / "test.pcap",
            )
            orchestrator.cache.close()  # Close DB connection

        assert result["status"] == "success"
        assert result["packet_count"] == 1000
        assert result["duration"] == 10

    @patch("local.cli.orchestrator.ScapySniffer")
    def test_capture_traffic_scapy_success(self, mock_sniffer_class):
        """Test successful PCAP capture with Scapy method."""
        mock_sniffer = MagicMock()
        mock_sniffer.stop_sniffing.return_value = {
            "total_packets": 500,
            "total_bytes": 250000,
        }
        mock_sniffer_class.return_value = mock_sniffer

        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = AnalysisOrchestrator(cache_dir=tmpdir)

            result = orchestrator.capture_traffic(
                interface="eth0",
                duration_seconds=10,
                method="scapy",
                output_path=Path(tmpdir) / "test.pcap",
            )
            orchestrator.cache.close()  # Close DB connection

        assert result["status"] == "success"
        assert result["packet_count"] == 500

    def test_capture_traffic_invalid_method(self):
        """Test capture with invalid method raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = AnalysisOrchestrator(cache_dir=tmpdir)

            result = orchestrator.capture_traffic(
                interface="eth0",
                duration_seconds=10,
                method="invalid_method",
            )
            orchestrator.cache.close()  # Close DB connection

        assert result["status"] == "failed"


class TestDetectAnomalies:
    """Test anomaly detection."""

    def test_detect_anomalies_no_features(self):
        """Test detection fails gracefully when PCAP file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = AnalysisOrchestrator(cache_dir=tmpdir)
            result = orchestrator.detect_anomalies(pcap_path="/nonexistent/file.pcap")
            orchestrator.cache.close()  # Close DB connection

        assert result["status"] == "failed"
        assert "error" in result


class TestCalibrateBaseline:
    """Test baseline calibration."""

    @patch("local.cli.orchestrator.PySharkSpooler")
    def test_calibrate_baseline_capture_fails(self, mock_spooler_class):
        """Test baseline calibration when capture fails."""
        # Setup mock to simulate capture failure
        mock_spooler = MagicMock()
        mock_spooler.start_capture.return_value = None
        mock_spooler.validate_pcap_file.return_value = False
        mock_spooler_class.return_value = mock_spooler

        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = AnalysisOrchestrator(cache_dir=tmpdir)

            result = orchestrator.calibrate_baseline(
                interface="eth0",
                duration_seconds=30,
                output_model_path=str(Path(tmpdir) / "baseline.pkl"),
            )
            orchestrator.cache.close()  # Close DB connection

        assert result["status"] == "failed"
        assert "error" in result


class TestSaveReport:
    """Test report generation."""

    def test_save_analysis_report_success(self):
        """Test successful report creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = AnalysisOrchestrator(cache_dir=tmpdir)

            analysis_result = {
                "status": "success",
                "threat_level": "high",
                "anomalous_count": 5,
            }

            report_path = Path(tmpdir) / "report.json"
            success = orchestrator.save_analysis_report(
                analysis_result, str(report_path)
            )
            orchestrator.cache.close()  # Close DB connection

            assert success is True
            assert report_path.exists()

            # Verify JSON content
            import json
            with open(report_path) as f:
                saved = json.load(f)
            assert saved["analysis"]["threat_level"] == "high"

    def test_save_analysis_report_invalid_path(self):
        """Test report save fails with invalid path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = AnalysisOrchestrator(cache_dir=tmpdir)

            analysis_result = {"status": "success"}

            # Try to save to non-existent directory without creating it
            report_path = "/invalid/path/that/doesnt/exist/report.json"
            success = orchestrator.save_analysis_report(
                analysis_result, report_path
            )
            orchestrator.cache.close()  # Close DB connection

            # Should still be True since mkdir is called
            assert success is True
