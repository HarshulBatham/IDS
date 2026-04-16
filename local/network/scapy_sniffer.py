# local/network/scapy_sniffer.py
"""
AeroGuard IDS - Scapy Lightweight Sniffer

Live, real-time packet header sniffing using scapy.
Aggregates flow statistics without deep packet inspection.
Runs in a background thread with a memory-safe circular buffer.
"""

import logging
import time
import threading
from collections import deque
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ScapySniffer:
    """
    Lightweight packet header sniffer using scapy.

    Captures packets on a given interface, extracts L3/L4 headers,
    and aggregates into flow statistics. Uses a circular buffer to
    prevent unbounded memory growth during long captures.

    Thread-safe: flow statistics can be read from the main thread
    while sniffing continues in the background.
    """

    def __init__(self, interface: str, packet_buffer_size: int = 10000):
        """
        Initialize the sniffer.

        Args:
            interface: Network interface name to sniff on.
            packet_buffer_size: Maximum number of packet summaries to
                                retain in the circular buffer.
        """
        self.interface = interface
        self.packet_buffer = deque(maxlen=packet_buffer_size)
        self.flow_stats: Dict[str, Dict[str, Any]] = {}
        self.is_sniffing = False
        self._stop_event = threading.Event()
        self._sniff_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Aggregate counters
        self._total_packets = 0
        self._total_bytes = 0
        self._start_time: Optional[float] = None

    def packet_callback(self, packet) -> None:
        """
        Process an individual packet captured by scapy.

        Extracts L3/L4 header fields (IP src/dst, ports, protocol,
        TCP flags) and aggregates the information into per-flow
        statistics. No application-layer (L7) data is inspected.

        Args:
            packet: A scapy Packet object.
        """
        try:
            # Only process IP-layer packets
            if not packet.haslayer("IP"):
                return

            ip_layer = packet["IP"]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto  # 6=TCP, 17=UDP, 1=ICMP
            pkt_len = len(packet)

            src_port = 0
            dst_port = 0
            tcp_flags = ""

            if packet.haslayer("TCP"):
                tcp_layer = packet["TCP"]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                tcp_flags = str(tcp_layer.flags)
                proto_name = "TCP"
            elif packet.haslayer("UDP"):
                udp_layer = packet["UDP"]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                proto_name = "UDP"
            elif packet.haslayer("ICMP"):
                proto_name = "ICMP"
            else:
                proto_name = f"IP({proto})"

            # Build flow key
            flow_key = f"{src_ip}:{dst_ip}"

            # Packet summary for the circular buffer
            pkt_summary = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto_name,
                "length": pkt_len,
                "tcp_flags": tcp_flags,
                "timestamp": time.time(),
            }

            with self._lock:
                self.packet_buffer.append(pkt_summary)
                self._total_packets += 1
                self._total_bytes += pkt_len

                # Aggregate into flow stats
                if flow_key not in self.flow_stats:
                    self.flow_stats[flow_key] = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": proto_name,
                        "packet_count": 0,
                        "byte_count": 0,
                        "flags": set(),
                        "first_seen": time.time(),
                        "last_seen": time.time(),
                    }

                flow = self.flow_stats[flow_key]
                flow["packet_count"] += 1
                flow["byte_count"] += pkt_len
                flow["last_seen"] = time.time()
                if tcp_flags:
                    flow["flags"].add(tcp_flags)

        except Exception as exc:
            # Never crash the sniffer callback
            logger.debug("Packet processing error: %s", exc)

    def start_sniffing_threaded(self) -> threading.Thread:
        """
        Start packet capture in a background thread.

        Returns:
            The Thread object running the sniff loop.

        Raises:
            RuntimeError: If sniffing is already active.
        """
        if self.is_sniffing:
            raise RuntimeError("Sniffer is already running.")

        self._stop_event.clear()
        self._start_time = time.time()
        self.is_sniffing = True

        def _sniff_loop():
            try:
                from scapy.all import sniff

                logger.info("Starting scapy sniff on %s", self.interface)
                sniff(
                    iface=self.interface,
                    prn=self.packet_callback,
                    store=False,  # Don't keep packets in memory
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
            except Exception as exc:
                logger.error("Sniff error on %s: %s", self.interface, exc)
            finally:
                self.is_sniffing = False
                logger.info("Sniff stopped on %s", self.interface)

        self._sniff_thread = threading.Thread(
            target=_sniff_loop, name="AeroGuard-ScapySniffer", daemon=True
        )
        self._sniff_thread.start()
        return self._sniff_thread

    def stop_sniffing(self) -> Dict:
        """
        Stop the capture and return aggregated statistics.

        Returns:
            Summary dict with capture results:
            {
                'packet_count': int,
                'flow_count': int,
                'bytes_total': int,
                'duration_seconds': float,
                'active_flows': {flow_key: flow_data, ...}
            }
        """
        self._stop_event.set()

        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=5.0)

        self.is_sniffing = False

        with self._lock:
            duration = time.time() - self._start_time if self._start_time else 0

            # Convert sets to lists for JSON serialization
            flows_copy = {}
            for k, v in self.flow_stats.items():
                flow = dict(v)
                flow["flags"] = list(flow.get("flags", set()))
                flows_copy[k] = flow

            return {
                "packet_count": self._total_packets,
                "flow_count": len(self.flow_stats),
                "bytes_total": self._total_bytes,
                "duration_seconds": round(duration, 2),
                "active_flows": flows_copy,
            }

    def get_flow_statistics(self) -> Dict:
        """
        Return a snapshot of current flow statistics.

        This method is non-blocking and thread-safe, designed
        for real-time dashboard updates while capture is ongoing.

        Returns:
            Dictionary of flow_key → flow_data mappings.
        """
        with self._lock:
            snapshot = {}
            for k, v in self.flow_stats.items():
                flow = dict(v)
                flow["flags"] = list(flow.get("flags", set()))
                snapshot[k] = flow
            return snapshot

    def get_capture_summary(self) -> Dict:
        """
        Return a high-level summary of the current capture state.

        Returns:
            {
                'is_sniffing': bool,
                'total_packets': int,
                'total_bytes': int,
                'total_flows': int,
                'elapsed_seconds': float
            }
        """
        with self._lock:
            elapsed = time.time() - self._start_time if self._start_time else 0
            return {
                "is_sniffing": self.is_sniffing,
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "total_flows": len(self.flow_stats),
                "elapsed_seconds": round(elapsed, 2),
            }

    def reset(self) -> None:
        """Clear all captured data and counters."""
        with self._lock:
            self.packet_buffer.clear()
            self.flow_stats.clear()
            self._total_packets = 0
            self._total_bytes = 0
            self._start_time = None
