# local/ml/feature_extractor.py
"""
AeroGuard IDS - Feature Extraction Engine

Extracts ~50 statistical features from PCAP metadata for ML model training.
Aggregates packets into time windows and computes flow-level features
without inspecting application-layer payloads.
"""

import logging
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Default time window for feature aggregation (seconds)
DEFAULT_WINDOW_SIZE = 10


class FeatureExtractor:
    """
    Extract ML-ready features from PCAP packet flows.

    Converts raw packet headers into statistical features suitable for
    anomaly detection (Isolation Forest). Features are aggregated per
    time window to create baseline profiles.
    """

    def __init__(self, window_size: int = DEFAULT_WINDOW_SIZE):
        """
        Initialize the feature extractor.

        Args:
            window_size: Duration of aggregation window in seconds.
        """
        self.window_size = window_size
        self.flows: Dict[str, Dict] = {}
        self.windows: List[Dict] = []

    def extract_features_from_scapy_sniffer(
        self, sniffer_stats: Dict
    ) -> List[Dict]:
        """
        Extract features from a ScapySniffer capture summary.

        Args:
            sniffer_stats: Output from ScapySniffer.stop_sniffing().
                          Contains active_flows, packet_count, duration.

        Returns:
            List of feature dicts, one per time window aggregation.
        """
        if not sniffer_stats or "active_flows" not in sniffer_stats:
            logger.warning("Invalid sniffer stats provided")
            return []

        flows_raw = sniffer_stats.get("active_flows", {})
        packet_count = sniffer_stats.get("packet_count", 0)
        byte_count = sniffer_stats.get("bytes_total", 0)

        # Convert ScapySniffer format to feature extraction format
        # ScapySniffer has "protocol" (single), but _compute_flow_features expects "protocols" (dict)
        flows = {}
        for flow_key, flow_data in flows_raw.items():
            flows[flow_key] = {
                "src_ip": flow_data.get("src_ip"),
                "dst_ip": flow_data.get("dst_ip"),
                "packet_count": flow_data.get("packet_count", 0),
                "byte_count": flow_data.get("byte_count", 0),
                "protocols": {flow_data.get("protocol", "UNKNOWN"): flow_data.get("packet_count", 0)},
                "src_ports": {flow_data.get("src_port", 0)} if flow_data.get("src_port", 0) > 0 else set(),
                "dst_ports": {flow_data.get("dst_port", 0)} if flow_data.get("dst_port", 0) > 0 else set(),
            }

        # Compute features from aggregated flows
        features = self._compute_flow_features(flows, packet_count, byte_count)
        return [features]  # Return as list for consistency with PCAP extraction

    def extract_features_from_pcap(self, pcap_path: str) -> List[Dict]:
        """
        Extract features from a PCAP file using Scapy.

        Note: PCAP parsing is deprecated. Use extract_features_from_scapy_sniffer()
        with live capture instead for better performance and no external dependencies.

        Args:
            pcap_path: Path to PCAP file.

        Returns:
            List of feature dicts, one per time window.

        Raises:
            FileNotFoundError: If PCAP file doesn't exist.
        """
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        try:
            from scapy.all import rdpcap, IP
        except ImportError:
            logger.error("Scapy not installed. Cannot parse PCAP.")
            return []

        windows_features = []

        try:
            packets = rdpcap(pcap_path)
            
            # Simple aggregation: compute features for entire PCAP
            flows = {}
            total_packets = len(packets)
            total_bytes = sum(len(pkt) for pkt in packets)

            for pkt in packets:
                try:
                    if IP in pkt:
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        pkt_len = len(pkt)

                        flow_key = f"{src_ip}:{dst_ip}"
                        if flow_key not in flows:
                            flows[flow_key] = {
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "packet_count": 0,
                                "byte_count": 0,
                                "protocols": defaultdict(int),
                            }

                        flows[flow_key]["packet_count"] += 1
                        flows[flow_key]["byte_count"] += pkt_len

                        # Determine protocol
                        proto_name = "IP"
                        if pkt.haslayer("TCP"):
                            proto_name = "TCP"
                        elif pkt.haslayer("UDP"):
                            proto_name = "UDP"
                        elif pkt.haslayer("ICMP"):
                            proto_name = "ICMP"

                        flows[flow_key]["protocols"][proto_name] += 1
                except Exception:
                    continue

            # Compute aggregate features
            features = self._compute_flow_features(
                flows, total_packets, total_bytes
            )
            windows_features.append(features)

            logger.info(
                f"Extracted features from {len(packets)} packets in {pcap_path}"
            )
            return windows_features

        except Exception as exc:
            logger.error(f"Error extracting features from PCAP: {exc}")
            return []

    def _compute_flow_features(
        self, flows: Dict[str, Dict], packet_count: int, byte_count: int
    ) -> Dict:
        """
        Compute ~50 statistical features from flow data.

        Args:
            flows: Dict of flow_key → flow_stats.
            packet_count: Total packets in window.
            byte_count: Total bytes in window.

        Returns:
            Dict of feature_name → value.
        """
        features = {
            # Basic counts
            "packet_count": packet_count,
            "byte_count": byte_count,
            "flow_count": len(flows),
            "avg_packet_size": (
                byte_count / packet_count if packet_count > 0 else 0
            ),

            # Flow diversity
            "unique_src_ips": len(set(f["src_ip"] for f in flows.values())),
            "unique_dst_ips": len(set(f["dst_ip"] for f in flows.values())),
            "unique_protocols": len(
                set(p for f in flows.values() for p in f["protocols"].keys())
            ),

            # Protocol distribution
            "tcp_packets": sum(
                f["protocols"].get("TCP", 0) for f in flows.values()
            ),
            "udp_packets": sum(
                f["protocols"].get("UDP", 0) for f in flows.values()
            ),
            "icmp_packets": sum(
                f["protocols"].get("ICMP", 0) for f in flows.values()
            ),
            "other_packets": packet_count
            - sum(
                f["protocols"].get("TCP", 0)
                + f["protocols"].get("UDP", 0)
                + f["protocols"].get("ICMP", 0)
                for f in flows.values()
            ),
        }

        # Port diversity
        all_src_ports = set()
        all_dst_ports = set()
        src_port_counts = defaultdict(int)
        dst_port_counts = defaultdict(int)

        for flow in flows.values():
            all_src_ports.update(flow.get("src_ports", set()))
            all_dst_ports.update(flow.get("dst_ports", set()))

            for p in flow.get("src_ports", set()):
                src_port_counts[p] += 1
            for p in flow.get("dst_ports", set()):
                dst_port_counts[p] += 1

        features.update({
            "unique_src_ports": len(all_src_ports),
            "unique_dst_ports": len(all_dst_ports),
            "src_port_entropy": self._entropy(src_port_counts),
            "dst_port_entropy": self._entropy(dst_port_counts),
        })

        # Byte distribution stats
        if flows:
            byte_values = [f["byte_count"] for f in flows.values()]
            features.update({
                "byte_mean": np.mean(byte_values),
                "byte_median": np.median(byte_values),
                "byte_std": np.std(byte_values),
                "byte_max": np.max(byte_values),
                "byte_min": np.min(byte_values),
            })
        else:
            features.update({
                "byte_mean": 0,
                "byte_median": 0,
                "byte_std": 0,
                "byte_max": 0,
                "byte_min": 0,
            })

        # Packet count distribution stats
        if flows:
            pkt_values = [f["packet_count"] for f in flows.values()]
            features.update({
                "packet_mean": np.mean(pkt_values),
                "packet_median": np.median(pkt_values),
                "packet_std": np.std(pkt_values),
                "packet_max": np.max(pkt_values),
                "packet_min": np.min(pkt_values),
            })
        else:
            features.update({
                "packet_mean": 0,
                "packet_median": 0,
                "packet_std": 0,
                "packet_max": 0,
                "packet_min": 0,
            })

        # Ratio features
        if packet_count > 0:
            features["tcp_ratio"] = features["tcp_packets"] / packet_count
            features["udp_ratio"] = features["udp_packets"] / packet_count
            features["icmp_ratio"] = features["icmp_packets"] / packet_count
        else:
            features["tcp_ratio"] = 0
            features["udp_ratio"] = 0
            features["icmp_ratio"] = 0

        if byte_count > 0:
            features["flow_bytes_ratio"] = (
                sum(f["byte_count"] for f in flows.values()) / byte_count if flows else 0
            )
        else:
            features["flow_bytes_ratio"] = 0

        # Density features
        if len(flows) > 0:
            features["bytes_per_flow"] = byte_count / len(flows)
            features["packets_per_flow"] = packet_count / len(flows)
        else:
            features["bytes_per_flow"] = 0
            features["packets_per_flow"] = 0

        # Port scan detection heuristic
        destination_ips = [f["dst_ip"] for f in flows.values()]
        destination_ip_counts = defaultdict(int)
        for ip in destination_ips:
            destination_ip_counts[ip] += 1

        features["max_flows_to_single_dst"] = (
            max(destination_ip_counts.values()) if destination_ip_counts else 0
        )
        features["unique_dst_per_src"] = (
            len(destination_ip_counts) / max(len(flows), 1)
        )

        # Normalize features to 0-1 range (will be z-score normalized later)
        return features

    @staticmethod
    def _entropy(counts: Dict) -> float:
        """
        Compute Shannon entropy of a distribution.

        Args:
            counts: Dict mapping values to counts.

        Returns:
            Entropy value.
        """
        if not counts:
            return 0.0

        total = sum(counts.values())
        if total == 0:
            return 0.0

        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / total
                entropy -= p * np.log2(p)

        return entropy

    def normalize_features(
        self, features_list: List[Dict]
    ) -> Tuple[pd.DataFrame, Dict[str, Tuple[float, float]]]:
        """
        Normalize features using z-score normalization.

        Args:
            features_list: List of feature dicts.

        Returns:
            Tuple of (normalized DataFrame, dict of mean/std for each feature).
        """
        df = pd.DataFrame(features_list)

        # Compute mean and std for each feature
        means = df.mean()
        stds = df.std()
        stats = {}

        for col in df.columns:
            mean_val = means[col]
            std_val = stds[col]
            stats[col] = (mean_val, std_val)

            # Z-score normalization (avoid division by zero)
            if std_val > 0:
                df[col] = (df[col] - mean_val) / std_val
            else:
                df[col] = 0

        logger.info(f"Normalized {len(features_list)} feature vectors")
        return df, stats


def parse_pcap_to_flows(pcap_path: str) -> List[Dict]:
    """
    Parse a PCAP file and extract flows without aggregating.

    Useful for detailed analysis or export.

    Args:
        pcap_path: Path to PCAP file.

    Returns:
        List of flow dicts with packet-level details.
    """
    try:
        import pyshark

        flows = {}
        pcap = pyshark.FileCapture(
            pcap_path, only_summaries=True, include_raw=False, display_filter="ip"
        )

        for pkt in pcap:
            try:
                if not hasattr(pkt, "ip"):
                    continue

                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                flow_key = f"{src_ip}:{dst_ip}"

                if flow_key not in flows:
                    flows[flow_key] = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "packets": 0,
                        "bytes": 0,
                        "protocols": [],
                    }

                flows[flow_key]["packets"] += 1
                flows[flow_key]["bytes"] += int(pkt.frame_info.frame_len)

                if hasattr(pkt, "tcp"):
                    flows[flow_key]["protocols"].append("TCP")
                elif hasattr(pkt, "udp"):
                    flows[flow_key]["protocols"].append("UDP")
                elif hasattr(pkt, "icmp"):
                    flows[flow_key]["protocols"].append("ICMP")

            except Exception:
                continue

        return list(flows.values())

    except Exception as exc:
        logger.error(f"Error parsing PCAP: {exc}")
        return []
