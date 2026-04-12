# tests/unit/test_pyshark_spooler.py
"""
Unit tests for the AeroGuard IDS PyShark PCAP Spooler.

All tshark subprocess calls are mocked. Tests verify capture lifecycle,
PCAP file validation, and progress monitoring without network access.
"""

import os
import struct
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from local.network.pyshark_spooler import (
    PySharkSpooler,
    validate_pcap_file,
    estimate_packet_count,
    PCAP_MAGIC_LE,
    PCAPNG_MAGIC,
)


def _write_valid_pcap_header(path: str) -> None:
    """Write a minimal valid PCAP header to a file."""
    with open(path, "wb") as f:
        # PCAP global header (24 bytes)
        f.write(struct.pack("<I", PCAP_MAGIC_LE))  # Magic number
        f.write(struct.pack("<HH", 2, 4))           # Version major/minor
        f.write(struct.pack("<iIII", 0, 0, 65535, 1))  # TZ, sigfigs, snaplen, linktype


class TestPySharkSpoolerStartCapture:
    """Tests for PySharkSpooler.start_capture()."""

    @patch("local.network.pyshark_spooler.subprocess.Popen")
    def test_starts_capture_successfully(self, mock_popen):
        """Verify tshark is spawned with correct arguments."""
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Still running
        mock_popen.return_value = mock_process

        with tempfile.TemporaryDirectory() as tmpdir:
            spooler = PySharkSpooler(interface="eth0", output_dir=tmpdir)
            pcap_path = spooler.start_capture(duration_seconds=60)

            assert pcap_path is not None
            assert pcap_path.endswith(".pcap")

            # Verify tshark called with list args (no shell injection)
            mock_popen.assert_called_once()
            call_args = mock_popen.call_args
            assert call_args.kwargs.get("shell") is False

            # Verify command structure
            cmd = call_args.args[0]
            assert cmd[0] == "tshark"
            assert "-i" in cmd
            assert "eth0" in cmd

    @patch("local.network.pyshark_spooler.subprocess.Popen")
    def test_rejects_concurrent_captures(self, mock_popen):
        """Verify RuntimeError when starting duplicate capture."""
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Still running
        mock_popen.return_value = mock_process

        with tempfile.TemporaryDirectory() as tmpdir:
            spooler = PySharkSpooler(interface="eth0", output_dir=tmpdir)
            spooler.start_capture(duration_seconds=60)

            with pytest.raises(RuntimeError, match="already in progress"):
                spooler.start_capture(duration_seconds=60)

    def test_rejects_invalid_duration(self):
        """Verify ValueError for durations outside 1-3600 range."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spooler = PySharkSpooler(interface="eth0", output_dir=tmpdir)

            with pytest.raises(ValueError, match="between 1 and 3600"):
                spooler.start_capture(duration_seconds=0)

            with pytest.raises(ValueError, match="between 1 and 3600"):
                spooler.start_capture(duration_seconds=5000)

    @patch("local.network.pyshark_spooler.subprocess.Popen", side_effect=FileNotFoundError)
    def test_raises_when_tshark_missing(self, mock_popen):
        """Verify FileNotFoundError when tshark is not installed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spooler = PySharkSpooler(interface="eth0", output_dir=tmpdir)

            with pytest.raises(FileNotFoundError, match="tshark not found"):
                spooler.start_capture(duration_seconds=60)


class TestPySharkSpoolerProgress:
    """Tests for PySharkSpooler.get_capture_progress()."""

    @patch("local.network.pyshark_spooler.subprocess.Popen")
    def test_reports_running_state(self, mock_popen):
        """Verify progress reports running status."""
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Still running
        mock_popen.return_value = mock_process

        with tempfile.TemporaryDirectory() as tmpdir:
            spooler = PySharkSpooler(interface="eth0", output_dir=tmpdir)
            spooler.start_capture(duration_seconds=60)

            progress = spooler.get_capture_progress()

            assert progress["is_running"] is True
            assert "file_size_mb" in progress
            assert "elapsed_seconds" in progress
            assert progress["duration_seconds"] == 60

    def test_reports_stopped_when_no_capture(self):
        """Verify progress reports stopped when no capture is running."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spooler = PySharkSpooler(interface="eth0", output_dir=tmpdir)

            progress = spooler.get_capture_progress()

            assert progress["is_running"] is False


class TestPySharkSpoolerStop:
    """Tests for PySharkSpooler.stop_capture_gracefully()."""

    @patch("local.network.pyshark_spooler.subprocess.Popen")
    def test_terminates_process(self, mock_popen):
        """Verify tshark process is terminated on stop."""
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Still running
        mock_popen.return_value = mock_process

        with tempfile.TemporaryDirectory() as tmpdir:
            spooler = PySharkSpooler(interface="eth0", output_dir=tmpdir)
            spooler.start_capture(duration_seconds=60)

            result = spooler.stop_capture_gracefully()

            mock_process.terminate.assert_called_once()
            assert result is not None

    def test_returns_none_path_when_no_capture(self):
        """Verify stop returns None when nothing is running."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spooler = PySharkSpooler(interface="eth0", output_dir=tmpdir)

            result = spooler.stop_capture_gracefully()

            assert result is None


class TestValidatePcapFile:
    """Tests for validate_pcap_file()."""

    def test_validates_standard_pcap(self):
        """Verify standard PCAP (libpcap) magic bytes pass."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            _write_valid_pcap_header(f.name)
            path = f.name

        try:
            assert validate_pcap_file(path) is True
        finally:
            os.unlink(path)

    def test_validates_pcapng(self):
        """Verify pcapng magic bytes pass."""
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            f.write(struct.pack("<I", PCAPNG_MAGIC))
            f.write(b"\x00" * 20)
            path = f.name

        try:
            assert validate_pcap_file(path) is True
        finally:
            os.unlink(path)

    def test_rejects_invalid_file(self):
        """Verify non-PCAP file is rejected."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False, mode="w") as f:
            f.write("This is not a PCAP file at all.")
            path = f.name

        try:
            assert validate_pcap_file(path) is False
        finally:
            os.unlink(path)

    def test_rejects_empty_file(self):
        """Verify empty file (0 bytes) is rejected."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name

        try:
            assert validate_pcap_file(path) is False
        finally:
            os.unlink(path)

    def test_rejects_too_small_file(self):
        """Verify file < 4 bytes is rejected."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"\x00\x01")
            path = f.name

        try:
            assert validate_pcap_file(path) is False
        finally:
            os.unlink(path)

    def test_rejects_nonexistent_file(self):
        """Verify missing file returns False."""
        assert validate_pcap_file("/nonexistent/path/file.pcap") is False


class TestEstimatePacketCount:
    """Tests for estimate_packet_count()."""

    def test_estimates_from_file_size(self):
        """Verify rough packet count estimate is reasonable."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            # Write ~50000 bytes of data (24-byte header + 49976 payload)
            f.write(b"\x00" * 50000)
            path = f.name

        try:
            count = estimate_packet_count(path)
            # (50000 - 24) / 500 ≈ 99
            assert 90 <= count <= 110
        finally:
            os.unlink(path)

    def test_returns_zero_for_nonexistent_file(self):
        """Verify 0 for missing file."""
        assert estimate_packet_count("/nonexistent/file.pcap") == 0

    def test_returns_zero_for_small_file(self):
        """Verify 0 when file is smaller than header."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"\x00" * 10)
            path = f.name

        try:
            count = estimate_packet_count(path)
            assert count == 0
        finally:
            os.unlink(path)
