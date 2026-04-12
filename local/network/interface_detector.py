# local/network/interface_detector.py
"""
AeroGuard IDS - Network Interface Detector

Auto-detect capture-capable network interfaces using psutil and scapy.
Provides validation and interactive selection for packet capture.
"""

import logging
import platform
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Module-level imports with graceful fallback (enables test mocking)
try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    psutil = None  # type: ignore
    _HAS_PSUTIL = False

try:
    from scapy.all import sniff as scapy_sniff
except ImportError:
    scapy_sniff = None  # type: ignore


def get_active_interfaces() -> List[Dict]:
    """
    List all active network interfaces capable of packet capture.

    Combines psutil (for status/address info) and scapy (for capture
    capability) to produce a unified interface list. Loopback and
    down interfaces are excluded.

    Returns:
        List of dicts, each describing an interface:
        [
            {
                'name': 'eth0',
                'ip': '192.168.1.100',
                'mac': '00:11:22:33:44:55',
                'status': 'up',
                'mtu': 1500,
                'is_loopback': False,
                'is_wireless': False
            },
            ...
        ]
    """
    if not _HAS_PSUTIL:
        logger.warning("psutil not installed, using scapy-only detection.")
        return _get_interfaces_scapy_only()

    interfaces: List[Dict] = []

    try:
        # Get interface stats (up/down)
        net_stats = psutil.net_if_stats()
        # Get interface addresses (IP, MAC)
        net_addrs = psutil.net_if_addrs()

        for iface_name, stats in net_stats.items():
            # Skip interfaces that are down
            if not stats.isup:
                continue

            # Detect loopback
            is_loopback = _is_loopback_interface(iface_name, net_addrs.get(iface_name, []))
            if is_loopback:
                continue

            # Extract addresses
            ipv4_addr = None
            mac_addr = None
            for addr in net_addrs.get(iface_name, []):
                if addr.family.name == "AF_INET":
                    ipv4_addr = addr.address
                elif addr.family.name == "AF_LINK" or addr.family.name == "AF_PACKET":
                    mac_addr = addr.address

            interfaces.append({
                "name": iface_name,
                "ip": ipv4_addr or "N/A",
                "mac": mac_addr or "N/A",
                "status": "up",
                "mtu": stats.mtu if hasattr(stats, "mtu") else 1500,
                "is_loopback": False,
                "is_wireless": _is_wireless_interface(iface_name),
            })

    except Exception as exc:
        logger.error("Error detecting interfaces via psutil: %s", exc)

    return interfaces


def _get_interfaces_scapy_only() -> List[Dict]:
    """Fallback interface detection using only scapy."""
    try:
        from scapy.all import get_if_list, get_if_hwaddr, conf

        interfaces = []
        for iface_name in get_if_list():
            if _is_loopback_name(iface_name):
                continue
            try:
                mac = get_if_hwaddr(iface_name)
            except Exception:
                mac = "N/A"

            interfaces.append({
                "name": iface_name,
                "ip": "N/A",
                "mac": mac,
                "status": "up",
                "mtu": 1500,
                "is_loopback": False,
                "is_wireless": _is_wireless_interface(iface_name),
            })
        return interfaces
    except ImportError:
        logger.error("scapy not installed. Cannot detect interfaces.")
        return []


def _is_loopback_interface(name: str, addrs: list) -> bool:
    """Check if an interface is a loopback device."""
    if _is_loopback_name(name):
        return True

    # Check addresses for 127.x.x.x
    for addr in addrs:
        if hasattr(addr, "address") and addr.address and addr.address.startswith("127."):
            return True

    return False


def _is_loopback_name(name: str) -> bool:
    """Check if the interface name is a known loopback name."""
    loopback_names = {"lo", "lo0", "loopback", "loopback pseudo-interface 1"}
    return name.lower() in loopback_names


def _is_wireless_interface(name: str) -> bool:
    """
    Heuristic check if interface is wireless.
    Not definitive, but useful for UI hints.
    """
    wireless_indicators = {"wlan", "wifi", "wi-fi", "wlp", "ath", "ra0"}
    name_lower = name.lower()
    return any(indicator in name_lower for indicator in wireless_indicators)


def select_interface_interactive() -> Optional[str]:
    """
    Prompt the user to select a capture interface from CLI.

    Lists all active interfaces with index numbers and waits
    for user input.

    Returns:
        Selected interface name, or None if cancelled.
    """
    interfaces = get_active_interfaces()

    if not interfaces:
        print("No active network interfaces found.")
        return None

    print("\nAvailable Network Interfaces:")
    print("-" * 50)
    for idx, iface in enumerate(interfaces, start=1):
        wireless_tag = " [wireless]" if iface["is_wireless"] else ""
        print(f"  {idx}. {iface['name']:<20} IP: {iface['ip']:<16} MTU: {iface['mtu']}{wireless_tag}")
    print("-" * 50)

    while True:
        try:
            choice = input(f"Select interface (1-{len(interfaces)}, or 'q' to cancel): ").strip()
            if choice.lower() == "q":
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                selected = interfaces[idx]["name"]
                logger.info("User selected interface: %s", selected)
                return selected
            else:
                print(f"Invalid choice. Enter a number between 1 and {len(interfaces)}.")
        except (ValueError, EOFError):
            print("Invalid input.")
            return None


def validate_capture_capability(interface: str) -> bool:
    """
    Verify that an interface can be used for packet capture.

    Attempts a 1-second scapy sniff on the given interface.
    Returns False if sniffing fails (e.g., permission denied,
    interface not found, or no libpcap).

    Args:
        interface: Interface name to test.

    Returns:
        True if a capture can be started on this interface.
    """
    try:
        if scapy_sniff is None:
            logger.warning("scapy not installed. Cannot validate capture.")
            return False

        # Attempt a very short sniff (1 second, max 1 packet)
        packets = scapy_sniff(iface=interface, timeout=1, count=1, store=True)
        logger.info("Capture validation passed for %s (%d packets)", interface, len(packets))
        return True

    except PermissionError:
        logger.warning("Permission denied for capture on %s. Run as root/admin.", interface)
        return False
    except OSError as exc:
        logger.warning("OS error on interface %s: %s", interface, exc)
        return False
    except Exception as exc:
        logger.warning("Capture validation failed for %s: %s", interface, exc)
        return False


def get_interface_mtu(interface: str) -> int:
    """
    Retrieve the Maximum Transmission Unit for an interface.

    Used to estimate buffer sizes for PCAP spooling.

    Args:
        interface: Interface name.

    Returns:
        MTU in bytes (defaults to 1500 if unavailable).
    """
    try:
        if psutil is None:
            return 1500

        stats = psutil.net_if_stats()
        if interface in stats:
            mtu = stats[interface].mtu
            if mtu and mtu > 0:
                return mtu
    except Exception as exc:
        logger.debug("Could not get MTU for %s: %s", interface, exc)

    return 1500  # Standard Ethernet MTU
