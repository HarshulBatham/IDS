# tests/unit/test_interface_detector.py
"""
Unit tests for the AeroGuard IDS Network Interface Detector.

All hardware-dependent calls (psutil, scapy) are mocked to ensure
tests run reliably in CI without network access.
"""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from collections import namedtuple

from local.network.interface_detector import (
    get_active_interfaces,
    _is_loopback_interface,
    _is_loopback_name,
    _is_wireless_interface,
    validate_capture_capability,
    get_interface_mtu,
)


# Mock data structures matching psutil's API
MockStat = namedtuple("MockStat", ["isup", "mtu"])
MockAddr = namedtuple("MockAddr", ["family", "address"])


class MockFamily:
    """Simulate psutil address family enum."""
    def __init__(self, name):
        self.name = name


def _build_psutil_mocks(stats_dict, addrs_dict):
    """
    Create a mock psutil module with net_if_stats and net_if_addrs.
    Returns a context manager pair for patching both functions.
    """
    return (
        patch("local.network.interface_detector.psutil.net_if_stats", return_value=stats_dict),
        patch("local.network.interface_detector.psutil.net_if_addrs", return_value=addrs_dict),
        patch("local.network.interface_detector._HAS_PSUTIL", True),
    )


class TestGetActiveInterfaces:
    """Tests for get_active_interfaces()."""

    def test_returns_active_non_loopback_interfaces(self):
        """Verify only active, non-loopback interfaces are returned."""
        stats = {
            "eth0": MockStat(isup=True, mtu=1500),
            "lo": MockStat(isup=True, mtu=65536),
            "wlan0": MockStat(isup=True, mtu=1500),
            "docker0": MockStat(isup=False, mtu=1500),
        }
        addrs = {
            "eth0": [
                MockAddr(family=MockFamily("AF_INET"), address="192.168.1.100"),
                MockAddr(family=MockFamily("AF_LINK"), address="00:11:22:33:44:55"),
            ],
            "lo": [
                MockAddr(family=MockFamily("AF_INET"), address="127.0.0.1"),
            ],
            "wlan0": [
                MockAddr(family=MockFamily("AF_INET"), address="192.168.1.101"),
            ],
            "docker0": [
                MockAddr(family=MockFamily("AF_INET"), address="172.17.0.1"),
            ],
        }

        p1, p2, p3 = _build_psutil_mocks(stats, addrs)
        with p1, p2, p3:
            result = get_active_interfaces()

        names = [iface["name"] for iface in result]
        assert "eth0" in names
        assert "wlan0" in names
        assert "lo" not in names
        assert "docker0" not in names

    def test_extracts_ip_and_mac(self):
        """Verify IP and MAC are correctly extracted from psutil data."""
        stats = {"eth0": MockStat(isup=True, mtu=1500)}
        addrs = {
            "eth0": [
                MockAddr(family=MockFamily("AF_INET"), address="10.0.0.5"),
                MockAddr(family=MockFamily("AF_LINK"), address="AA:BB:CC:DD:EE:FF"),
            ],
        }

        p1, p2, p3 = _build_psutil_mocks(stats, addrs)
        with p1, p2, p3:
            result = get_active_interfaces()

        assert len(result) == 1
        assert result[0]["ip"] == "10.0.0.5"
        assert result[0]["mac"] == "AA:BB:CC:DD:EE:FF"

    def test_handles_no_ip_address(self):
        """Verify 'N/A' is used when no IP is available."""
        stats = {"eth0": MockStat(isup=True, mtu=1500)}
        addrs = {"eth0": []}

        p1, p2, p3 = _build_psutil_mocks(stats, addrs)
        with p1, p2, p3:
            result = get_active_interfaces()

        assert len(result) == 1
        assert result[0]["ip"] == "N/A"
        assert result[0]["mac"] == "N/A"

    def test_detects_wireless_interface(self):
        """Verify wireless interfaces are flagged."""
        stats = {"wlan0": MockStat(isup=True, mtu=1500)}
        addrs = {
            "wlan0": [
                MockAddr(family=MockFamily("AF_INET"), address="192.168.1.50"),
            ],
        }

        p1, p2, p3 = _build_psutil_mocks(stats, addrs)
        with p1, p2, p3:
            result = get_active_interfaces()

        assert len(result) == 1
        assert result[0]["is_wireless"] is True


class TestLoopbackDetection:
    """Tests for _is_loopback_interface() and _is_loopback_name()."""

    def test_lo_is_loopback(self):
        assert _is_loopback_name("lo") is True

    def test_lo0_is_loopback(self):
        assert _is_loopback_name("lo0") is True

    def test_eth0_is_not_loopback(self):
        assert _is_loopback_name("eth0") is False

    def test_loopback_by_address(self):
        addr = MockAddr(family=MockFamily("AF_INET"), address="127.0.0.1")
        assert _is_loopback_interface("some_iface", [addr]) is True

    def test_non_loopback_address(self):
        addr = MockAddr(family=MockFamily("AF_INET"), address="192.168.1.1")
        assert _is_loopback_interface("eth0", [addr]) is False


class TestWirelessDetection:
    """Tests for _is_wireless_interface()."""

    def test_wlan_detected(self):
        assert _is_wireless_interface("wlan0") is True

    def test_wifi_detected(self):
        assert _is_wireless_interface("Wi-Fi") is True

    def test_wlp_detected(self):
        assert _is_wireless_interface("wlp3s0") is True

    def test_eth_not_wireless(self):
        assert _is_wireless_interface("eth0") is False

    def test_docker_not_wireless(self):
        assert _is_wireless_interface("docker0") is False


class TestValidateCaptureCapability:
    """Tests for validate_capture_capability()."""

    @patch("local.network.interface_detector.scapy_sniff")
    def test_valid_interface_returns_true(self, mock_sniff):
        """Verify a working interface returns True."""
        mock_sniff.return_value = [MagicMock()]

        result = validate_capture_capability("eth0")

        assert result is True
        mock_sniff.assert_called_once()

    @patch("local.network.interface_detector.scapy_sniff", side_effect=PermissionError("No root"))
    def test_permission_denied_returns_false(self, mock_sniff):
        """Verify PermissionError returns False (not root)."""
        result = validate_capture_capability("eth0")

        assert result is False

    @patch("local.network.interface_detector.scapy_sniff", side_effect=OSError("No such device"))
    def test_invalid_device_returns_false(self, mock_sniff):
        """Verify nonexistent device returns False."""
        result = validate_capture_capability("nonexistent0")

        assert result is False


class TestGetInterfaceMTU:
    """Tests for get_interface_mtu()."""

    @patch("local.network.interface_detector.psutil")
    def test_returns_correct_mtu(self, mock_psutil):
        """Verify MTU is read from psutil."""
        mock_psutil.net_if_stats.return_value = {
            "eth0": MockStat(isup=True, mtu=9000),
        }

        mtu = get_interface_mtu("eth0")

        assert mtu == 9000

    @patch("local.network.interface_detector.psutil")
    def test_returns_default_for_unknown_interface(self, mock_psutil):
        """Verify default 1500 for unknown interface."""
        mock_psutil.net_if_stats.return_value = {}

        mtu = get_interface_mtu("nonexistent0")

        assert mtu == 1500
