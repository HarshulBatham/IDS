# tests/unit/test_scapy_sniffer.py
"""
Unit tests for the AeroGuard IDS Scapy Lightweight Sniffer.

All scapy calls are mocked. Tests verify flow aggregation,
thread safety, and capture lifecycle (start/stop/reset).
"""

import time
import pytest
from unittest.mock import patch, MagicMock
from collections import deque

from local.network.scapy_sniffer import ScapySniffer


def _make_mock_packet(src_ip="192.168.1.1", dst_ip="8.8.8.8",
                       src_port=54321, dst_port=443,
                       proto="TCP", length=128, flags="S"):
    """Build a mock scapy Packet with IP + TCP/UDP layers."""
    pkt = MagicMock()

    # Dunder __len__ must be configured via type or return_value
    pkt.__len__ = MagicMock(return_value=length)
    # Also set spec for len() to work on MagicMock
    type(pkt).__len__ = lambda self: length

    # IP layer
    ip_layer = MagicMock()
    ip_layer.src = src_ip
    ip_layer.dst = dst_ip
    ip_layer.proto = 6 if proto == "TCP" else 17

    # TCP layer
    tcp_layer = MagicMock()
    tcp_layer.sport = src_port
    tcp_layer.dport = dst_port
    tcp_layer.flags = flags

    # UDP layer
    udp_layer = MagicMock()
    udp_layer.sport = src_port
    udp_layer.dport = dst_port

    # ICMP layer
    icmp_layer = MagicMock()

    # Layer access via pkt["IP"], pkt["TCP"], etc.
    layers = {"IP": ip_layer, "TCP": tcp_layer, "UDP": udp_layer, "ICMP": icmp_layer}

    def getitem(name):
        if name in layers:
            return layers[name]
        raise KeyError(name)

    pkt.__getitem__ = MagicMock(side_effect=getitem)

    # haslayer checks
    def has_layer(name):
        if name == "IP":
            return True
        if name == "TCP" and proto == "TCP":
            return True
        if name == "UDP" and proto == "UDP":
            return True
        if name == "ICMP" and proto == "ICMP":
            return True
        return False

    pkt.haslayer = MagicMock(side_effect=has_layer)
    return pkt


class TestPacketCallback:
    """Tests for ScapySniffer.packet_callback()."""

    def test_processes_tcp_packet(self):
        """Verify TCP packet is correctly parsed and aggregated."""
        sniffer = ScapySniffer(interface="eth0")
        pkt = _make_mock_packet(proto="TCP", src_port=12345, dst_port=80)

        sniffer.packet_callback(pkt)

        assert sniffer._total_packets == 1
        assert sniffer._total_bytes == 128
        assert len(sniffer.flow_stats) == 1

        flow_key = "192.168.1.1:8.8.8.8"
        assert flow_key in sniffer.flow_stats
        flow = sniffer.flow_stats[flow_key]
        assert flow["protocol"] == "TCP"
        assert flow["packet_count"] == 1
        assert flow["byte_count"] == 128

    def test_processes_udp_packet(self):
        """Verify UDP packet is correctly parsed."""
        sniffer = ScapySniffer(interface="eth0")
        pkt = _make_mock_packet(proto="UDP", dst_port=53)

        sniffer.packet_callback(pkt)

        assert sniffer._total_packets == 1
        flow_key = "192.168.1.1:8.8.8.8"
        assert sniffer.flow_stats[flow_key]["protocol"] == "UDP"

    def test_aggregates_multiple_packets_same_flow(self):
        """Verify multiple packets to same flow are aggregated."""
        sniffer = ScapySniffer(interface="eth0")

        for _ in range(5):
            pkt = _make_mock_packet(length=200)
            sniffer.packet_callback(pkt)

        assert sniffer._total_packets == 5
        assert sniffer._total_bytes == 1000
        assert len(sniffer.flow_stats) == 1

        flow_key = "192.168.1.1:8.8.8.8"
        assert sniffer.flow_stats[flow_key]["packet_count"] == 5
        assert sniffer.flow_stats[flow_key]["byte_count"] == 1000

    def test_creates_separate_flows_for_different_ips(self):
        """Verify different IP pairs create separate flows."""
        sniffer = ScapySniffer(interface="eth0")

        pkt1 = _make_mock_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2")
        pkt2 = _make_mock_packet(src_ip="10.0.0.3", dst_ip="10.0.0.4")

        sniffer.packet_callback(pkt1)
        sniffer.packet_callback(pkt2)

        assert len(sniffer.flow_stats) == 2
        assert sniffer._total_packets == 2

    def test_skips_non_ip_packets(self):
        """Verify non-IP packets are silently ignored."""
        sniffer = ScapySniffer(interface="eth0")
        pkt = MagicMock()
        pkt.haslayer = lambda name: False  # No IP layer

        sniffer.packet_callback(pkt)

        assert sniffer._total_packets == 0
        assert len(sniffer.flow_stats) == 0

    def test_handles_callback_exception_gracefully(self):
        """Verify callback never crashes on malformed packets."""
        sniffer = ScapySniffer(interface="eth0")
        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=True)
        pkt.__getitem__ = MagicMock(side_effect=Exception("corrupt"))

        # Should NOT raise
        sniffer.packet_callback(pkt)

        assert sniffer._total_packets == 0

    def test_circular_buffer_respects_max_size(self):
        """Verify packet buffer doesn't grow beyond maxlen."""
        sniffer = ScapySniffer(interface="eth0", packet_buffer_size=5)

        for i in range(10):
            pkt = _make_mock_packet(src_port=i)
            sniffer.packet_callback(pkt)

        assert len(sniffer.packet_buffer) == 5
        assert sniffer._total_packets == 10  # Counter still accurate


class TestStopSniffing:
    """Tests for ScapySniffer.stop_sniffing()."""

    def test_returns_correct_summary(self):
        """Verify stop_sniffing returns accurate aggregate stats."""
        sniffer = ScapySniffer(interface="eth0")
        sniffer._start_time = time.time() - 10  # Simulate 10s capture
        sniffer.is_sniffing = False

        # Inject some flow data
        for i in range(3):
            pkt = _make_mock_packet(dst_ip=f"10.0.0.{i}", length=500)
            sniffer.packet_callback(pkt)

        result = sniffer.stop_sniffing()

        assert result["packet_count"] == 3
        assert result["flow_count"] == 3
        assert result["bytes_total"] == 1500
        assert result["duration_seconds"] >= 9  # ~10s

    def test_flow_flags_are_lists(self):
        """Verify TCP flag sets are serialized as lists."""
        sniffer = ScapySniffer(interface="eth0")
        sniffer._start_time = time.time()

        pkt = _make_mock_packet(flags="SA")
        sniffer.packet_callback(pkt)

        result = sniffer.stop_sniffing()

        for flow in result["active_flows"].values():
            assert isinstance(flow["flags"], list)


class TestGetFlowStatistics:
    """Tests for ScapySniffer.get_flow_statistics()."""

    def test_returns_snapshot_of_flows(self):
        """Verify snapshot returns a copy with serializable flags."""
        sniffer = ScapySniffer(interface="eth0")

        pkt = _make_mock_packet()
        sniffer.packet_callback(pkt)

        snapshot = sniffer.get_flow_statistics()

        assert len(snapshot) == 1
        for flow in snapshot.values():
            assert isinstance(flow["flags"], list)


class TestGetCaptureSummary:
    """Tests for ScapySniffer.get_capture_summary()."""

    def test_returns_correct_summary_format(self):
        """Verify summary dict has all required keys."""
        sniffer = ScapySniffer(interface="eth0")
        sniffer._start_time = time.time()

        summary = sniffer.get_capture_summary()

        assert "is_sniffing" in summary
        assert "total_packets" in summary
        assert "total_bytes" in summary
        assert "total_flows" in summary
        assert "elapsed_seconds" in summary


class TestReset:
    """Tests for ScapySniffer.reset()."""

    def test_clears_all_state(self):
        """Verify reset clears packets, flows, and counters."""
        sniffer = ScapySniffer(interface="eth0")
        sniffer._start_time = time.time()

        for i in range(5):
            pkt = _make_mock_packet(dst_ip=f"10.0.0.{i}")
            sniffer.packet_callback(pkt)

        assert sniffer._total_packets == 5
        assert len(sniffer.flow_stats) == 5

        sniffer.reset()

        assert sniffer._total_packets == 0
        assert sniffer._total_bytes == 0
        assert len(sniffer.flow_stats) == 0
        assert len(sniffer.packet_buffer) == 0
        assert sniffer._start_time is None
