# local/sanitization/sanitizer.py
"""
AeroGuard IDS - PCAP Sanitization Engine

Converts raw PCAP files to privacy-safe JSON metadata.
Strips all application-layer payloads, masks IP addresses, and validates
that no sensitive data is leaked.
"""

import logging
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

# Regex patterns for sensitive data detection
SENSITIVE_PATTERNS = {
    "credit_card": r"[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}",
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "password": r"password\s*=|passwd\s*=|pwd\s*=|secret\s*=",
    "api_key": r"api[_-]?key\s*=|apikey\s*=",
    "ssn": r"\d{3}-\d{2}-\d{4}",
}


class PCAPSanitizer:
    """
    Convert PCAP captures to privacy-safe JSON metadata.

    Implements defense-in-depth:
    1. Parse PCAP (L3/L4 headers only, no payloads)
    2. Mask IP addresses (last octet → XXX)
    3. Aggregate flows with counts and protocols
    4. Validate output for sensitive data
    """

    def __init__(self):
        """Initialize the sanitizer."""
        self.flows: Dict[str, Dict] = {}
        self.statistics: Dict = {}

    def sanitize_to_json(
        self, pcap_path: str, output_path: Optional[str] = None
    ) -> Dict:
        """
        Convert a PCAP file to sanitized JSON metadata.

        Args:
            pcap_path: Path to input PCAP file.
            output_path: Optional path to save JSON output.

        Returns:
            Dict with sanitized metadata and validation results.
        """
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        try:
            from scapy.all import rdpcap, IP

            output = {
                "metadata": {
                    "source_pcap": str(pcap_path),
                    "total_packets": 0,
                    "total_bytes": 0,
                    "flow_count": 0,
                },
                "flows": [],
                "statistics": {},
                "validation": {},
            }

            self.flows = {}
            packet_count = 0
            byte_count = 0

            packets = rdpcap(pcap_path)

            for pkt in packets:
                try:
                    if IP not in pkt:
                        continue

                    packet_count += 1
                    pkt_len = len(pkt)
                    byte_count += pkt_len

                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst

                    # Extract L4 info
                    src_port = 0
                    dst_port = 0
                    proto_name = f"IP({protocol})"

                    if pkt.haslayer("TCP"):
                        src_port = pkt["TCP"].sport
                        dst_port = pkt["TCP"].dport
                        proto_name = "TCP"
                    elif pkt.haslayer("UDP"):
                        src_port = pkt["UDP"].sport
                        dst_port = pkt["UDP"].dport
                        proto_name = "UDP"
                    elif pkt.haslayer("ICMP"):
                        proto_name = "ICMP"
                    else:
                        proto_name = "IP"

                    # Mask IP addresses
                    masked_src = self.mask_ip_address(src_ip)
                    masked_dst = self.mask_ip_address(dst_ip)
                    flow_key = f"{masked_src}:{masked_dst}"

                    if flow_key not in self.flows:
                        self.flows[flow_key] = {
                            "src_ip_masked": masked_src,
                            "dst_ip_masked": masked_dst,
                            "packet_count": 0,
                            "byte_count": 0,
                            "protocols": defaultdict(int),
                            "src_ports": set(),
                            "dst_ports": set(),
                        }

                    self.flows[flow_key]["packet_count"] += 1
                    self.flows[flow_key]["byte_count"] += pkt_len
                    self.flows[flow_key]["protocols"][proto_name] += 1

                    if src_port > 0:
                        self.flows[flow_key]["src_ports"].add(src_port)
                    if dst_port > 0:
                        self.flows[flow_key]["dst_ports"].add(dst_port)

                except Exception as exc:
                    logger.debug(f"Error parsing packet: {exc}")
                    continue

            # Convert flows to JSON-serializable format
            for flow_key, flow_data in self.flows.items():
                flow_json = {
                    "src_ip_masked": flow_data["src_ip_masked"],
                    "dst_ip_masked": flow_data["dst_ip_masked"],
                    "packet_count": flow_data["packet_count"],
                    "byte_count": flow_data["byte_count"],
                    "protocols": dict(flow_data["protocols"]),
                    "src_ports": sorted(list(flow_data["src_ports"])),
                    "dst_ports": sorted(list(flow_data["dst_ports"])),
                }
                output["flows"].append(flow_json)

            # Compute statistics
            output["metadata"]["total_packets"] = packet_count
            output["metadata"]["total_bytes"] = byte_count
            output["metadata"]["flow_count"] = len(self.flows)

            output["statistics"] = self._compute_statistics(output["flows"])

            # Validate sanitization
            validation = validate_sanitization(json.dumps(output))
            output["validation"] = validation

            if not validation["is_sanitized"]:
                logger.warning(f"Sanitization validation failed: {validation}")
                output["validation"]["sensitive_patterns_found"] = (
                    validation.get("issues", [])
                )

            # Save to file if path provided
            if output_path:
                output_path = Path(output_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w") as f:
                    json.dump(output, f, indent=2)
                logger.info(f"Saved sanitized PCAP to {output_path}")

            return output

        except Exception as exc:
            logger.error(f"Error sanitizing PCAP: {exc}")
            return {
                "error": str(exc),
                "flows": [],
                "validation": {"is_sanitized": False},
            }

    @staticmethod
    def mask_ip_address(ip: str) -> str:
        """
        Mask the last octet of an IP address.

        Example: 192.168.1.100 → 192.168.1.XXX

        Args:
            ip: IPv4 address string.

        Returns:
            Masked IP address.
        """
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.XXX"
        except Exception:
            pass
        return "X.X.X.XXX"

    @staticmethod
    def _compute_statistics(flows: List[Dict]) -> Dict:
        """
        Compute aggregate statistics from flows.

        Args:
            flows: List of flow dicts.

        Returns:
            Statistics dict.
        """
        if not flows:
            return {}

        total_packets = sum(f["packet_count"] for f in flows)
        total_bytes = sum(f["byte_count"] for f in flows)

        protocol_counts = defaultdict(int)
        for flow in flows:
            for proto, count in flow["protocols"].items():
                protocol_counts[proto] += count

        unique_src_ips = len(set(f["src_ip_masked"] for f in flows))
        unique_dst_ips = len(set(f["dst_ip_masked"] for f in flows))

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_flows": len(flows),
            "avg_packet_size": (
                total_bytes / total_packets if total_packets > 0 else 0
            ),
            "protocol_distribution": dict(protocol_counts),
            "unique_src_ips_masked": unique_src_ips,
            "unique_dst_ips_masked": unique_dst_ips,
        }

    @staticmethod
    def extract_flow_headers_only(pcap_path: str) -> List[Dict]:
        """
        Extract only L3/L4 headers from PCAP, no payload data.

        Args:
            pcap_path: Path to PCAP file.

        Returns:
            List of header-only flow dicts.
        """
        flows = []
        try:
            from scapy.all import rdpcap, IP

            packets = rdpcap(pcap_path)

            for pkt in packets:
                try:
                    if IP not in pkt:
                        continue

                    flow_dict = {
                        "src_ip": pkt[IP].src,
                        "dst_ip": pkt[IP].dst,
                        "protocol": pkt[IP].proto,
                        "length": len(pkt),
                    }

                    if pkt.haslayer("TCP"):
                        flow_dict["src_port"] = int(pkt["TCP"].sport)
                        flow_dict["dst_port"] = int(pkt.tcp.dstport)
                    elif pkt.haslayer("UDP"):
                        flow_dict["src_port"] = int(pkt["UDP"].sport)
                        flow_dict["dst_port"] = int(pkt["UDP"].dport)

                    flows.append(flow_dict)
                except Exception:
                    continue

            return flows

        except Exception as exc:
            logger.error(f"Error extracting headers: {exc}")
            return []


def validate_sanitization(json_data: str) -> Dict:
    """
    Validate that sanitized JSON contains no sensitive data.

    Checks for credit cards, emails, passwords, API keys, etc.

    Args:
        json_data: JSON string to validate.

    Returns:
        Dict with validation results:
        {
            'is_sanitized': bool,
            'issues': [list of issues found],
            'patterns_checked': int
        }
    """
    issues = []

    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, json_data, re.IGNORECASE)
        if matches:
            issues.append({
                "pattern": pattern_name,
                "matches_found": len(matches),
                "examples": matches[:3],  # Show first 3 examples
            })

    return {
        "is_sanitized": len(issues) == 0,
        "patterns_checked": len(SENSITIVE_PATTERNS),
        "issues": issues,
    }


def estimate_data_leakage(pcap_path: str, json_output: Dict) -> Dict:
    """
    Estimate what percentage of data has been removed during sanitization.

    Args:
        pcap_path: Original PCAP file path.
        json_output: Sanitized JSON output.

    Returns:
        Dict with leakage estimates.
    """
    try:
        pcap_size = Path(pcap_path).stat().st_size
        json_size = len(json.dumps(json_output))

        reduction_pct = (1 - json_size / pcap_size) * 100 if pcap_size > 0 else 100

        return {
            "original_pcap_bytes": pcap_size,
            "sanitized_json_bytes": json_size,
            "data_reduction_percent": round(reduction_pct, 2),
            "compression_ratio": round(pcap_size / json_size, 2) if json_size > 0 else 0,
        }

    except Exception as exc:
        logger.error(f"Error estimating data leakage: {exc}")
        return {}
