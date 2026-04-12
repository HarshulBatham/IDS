# local/network/pyshark_spooler.py
"""
AeroGuard IDS - PyShark PCAP Spooler

On-demand deep packet capture using tshark subprocess.
Writes PCAP files directly to OS temp directory to prevent RAM exhaustion.
Validates captures with PCAP magic-byte integrity checks.
"""

import logging
import os
import platform
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# PCAP magic bytes for file validation
PCAP_MAGIC_LE = 0xA1B2C3D4  # Little-endian standard pcap
PCAP_MAGIC_BE = 0xD4C3B2A1  # Big-endian standard pcap
PCAPNG_MAGIC = 0x0A0D0D0A  # pcapng Section Header Block

AEROSGUARD_DIR_NAME = "aerosguard"


def _get_secure_temp_dir() -> Path:
    """
    Return the most secure temp directory available.

    - Linux: /dev/shm (RAM-backed, never touches disk)
    - Others: Standard OS temp dir (protected by FDE)
    """
    if platform.system() == "Linux":
        shm = Path("/dev/shm")
        if shm.exists():
            aero_shm = shm / AEROSGUARD_DIR_NAME
            aero_shm.mkdir(mode=0o700, exist_ok=True)
            return aero_shm

    temp_dir = Path(tempfile.gettempdir()) / AEROSGUARD_DIR_NAME
    temp_dir.mkdir(mode=0o700, exist_ok=True)
    return temp_dir


class PySharkSpooler:
    """
    High-level PCAP capture using tshark subprocess.

    Writes capture data directly to a temp file on disk,
    preventing RAM exhaustion during long captures. Provides
    progress monitoring via file-size polling (no packet parsing).
    """

    def __init__(self, interface: str, output_dir: Optional[str] = None):
        """
        Initialize the spooler.

        Args:
            interface: Network interface to capture on.
            output_dir: Directory to write PCAP files to.
                        Defaults to the platform-specific secure temp dir.
        """
        self.interface = interface
        self.output_dir = Path(output_dir) if output_dir else _get_secure_temp_dir()
        self.capture_process: Optional[subprocess.Popen] = None
        self.pcap_file_path: Optional[str] = None
        self._start_time: Optional[float] = None
        self._capture_duration: int = 0

    def start_capture(self, duration_seconds: int) -> str:
        """
        Start a tshark capture with the specified duration.

        Spawns tshark in batch mode (non-interactive) and spools
        captured packets directly to a temporary PCAP file.

        Args:
            duration_seconds: Duration of the capture (e.g. 60, 300, 600).

        Returns:
            Absolute path to the PCAP output file.

        Raises:
            RuntimeError: If a capture is already in progress.
            FileNotFoundError: If tshark is not installed.
            ValueError: If duration is out of range.
        """
        if self.capture_process and self.capture_process.poll() is None:
            raise RuntimeError("A capture is already in progress.")

        if duration_seconds < 1 or duration_seconds > 3600:
            raise ValueError("Duration must be between 1 and 3600 seconds.")

        # Ensure output directory exists
        self.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Create temp file for PCAP output
        temp_file = tempfile.NamedTemporaryFile(
            dir=self.output_dir,
            prefix="aerog_",
            suffix=".pcap",
            delete=False,
        )
        temp_file.close()
        self.pcap_file_path = temp_file.name
        self._capture_duration = duration_seconds

        # Restrict file permissions
        try:
            os.chmod(self.pcap_file_path, 0o600)
        except OSError:
            pass  # Windows may not support chmod

        # Build tshark command (list-based, no shell injection)
        cmd = [
            "tshark",
            "-i", self.interface,
            "-a", f"duration:{duration_seconds}",
            "-w", self.pcap_file_path,
            "-q",  # Quiet mode
        ]

        try:
            self.capture_process = subprocess.Popen(
                cmd,
                shell=False,  # CRITICAL: Prevents shell injection
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self._start_time = time.time()
            logger.info(
                "Started tshark capture on %s for %ds → %s",
                self.interface,
                duration_seconds,
                self.pcap_file_path,
            )
            return self.pcap_file_path

        except FileNotFoundError:
            logger.error("tshark not found. Install Wireshark/tshark.")
            raise FileNotFoundError(
                "tshark not found. Install Wireshark (https://www.wireshark.org)."
            )

    def get_capture_progress(self) -> Dict:
        """
        Return capture progress by polling file size (non-blocking).

        Does NOT parse packets—only checks file size on disk for
        efficiency. Suitable for calling from a UI progress bar.

        Returns:
            {
                'is_running': bool,
                'file_size_mb': float,
                'elapsed_seconds': int,
                'estimated_pkts': int,
                'duration_seconds': int
            }
        """
        is_running = (
            self.capture_process is not None
            and self.capture_process.poll() is None
        )

        file_size = 0
        if self.pcap_file_path and Path(self.pcap_file_path).exists():
            file_size = Path(self.pcap_file_path).stat().st_size

        elapsed = int(time.time() - self._start_time) if self._start_time else 0

        # Rough estimate: average packet ~500 bytes in PCAP
        estimated_pkts = file_size // 500 if file_size > 0 else 0

        return {
            "is_running": is_running,
            "file_size_mb": round(file_size / (1024 * 1024), 2),
            "elapsed_seconds": elapsed,
            "estimated_pkts": estimated_pkts,
            "duration_seconds": self._capture_duration,
        }

    def stop_capture_gracefully(self) -> Optional[str]:
        """
        Terminate the capture process gracefully.

        Sends SIGTERM (Unix) or TerminateProcess (Windows) to tshark
        and waits up to 5 seconds for the process to finish writing
        the PCAP file.

        Returns:
            Path to the finalized PCAP file, or None if no capture.
        """
        if self.capture_process is None:
            return self.pcap_file_path

        if self.capture_process.poll() is None:
            # Process is still running
            try:
                self.capture_process.terminate()
                self.capture_process.wait(timeout=5)
                logger.info("tshark terminated gracefully.")
            except subprocess.TimeoutExpired:
                self.capture_process.kill()
                self.capture_process.wait(timeout=3)
                logger.warning("tshark killed after timeout.")
            except Exception as exc:
                logger.error("Error stopping tshark: %s", exc)

        self.capture_process = None
        return self.pcap_file_path

    def wait_for_capture_completion(self, timeout_sec: int = 700) -> str:
        """
        Block until the capture finishes or timeout is reached.

        Suitable for CLI and batch workflows where the caller
        wants to wait synchronously.

        Args:
            timeout_sec: Maximum time to wait (safety limit).

        Returns:
            Path to the completed PCAP file.

        Raises:
            TimeoutError: If capture exceeds the timeout.
            RuntimeError: If no capture is in progress.
        """
        if self.capture_process is None:
            raise RuntimeError("No capture in progress.")

        try:
            self.capture_process.wait(timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            self.stop_capture_gracefully()
            raise TimeoutError(
                f"Capture exceeded {timeout_sec}s timeout. Partial data saved."
            )

        # Validate result
        if self.pcap_file_path and Path(self.pcap_file_path).exists():
            if validate_pcap_file(self.pcap_file_path):
                logger.info("Capture complete: %s", self.pcap_file_path)
                return self.pcap_file_path
            else:
                logger.warning("Capture file failed validation: %s", self.pcap_file_path)

        return self.pcap_file_path


def validate_pcap_file(pcap_path: str) -> bool:
    """
    Verify PCAP file integrity by checking magic bytes.

    Supports standard pcap (libpcap) and pcapng formats.

    Args:
        pcap_path: Path to the PCAP file.

    Returns:
        True if the file has valid PCAP/PCAPNG magic bytes.
    """
    path = Path(pcap_path)

    if not path.exists():
        logger.warning("PCAP file does not exist: %s", pcap_path)
        return False

    if path.stat().st_size < 4:
        logger.warning("PCAP file too small: %s (%d bytes)", pcap_path, path.stat().st_size)
        return False

    try:
        with open(pcap_path, "rb") as f:
            header = f.read(4)

        if len(header) < 4:
            return False

        magic = struct.unpack("<I", header)[0]

        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE):
            return True

        # Check pcapng (Section Header Block)
        if magic == PCAPNG_MAGIC:
            return True

        # Also check big-endian interpretation
        magic_be = struct.unpack(">I", header)[0]
        if magic_be in (PCAP_MAGIC_LE, PCAP_MAGIC_BE):
            return True

        logger.warning("Invalid PCAP magic bytes: 0x%08X in %s", magic, pcap_path)
        return False

    except Exception as exc:
        logger.error("Error validating PCAP %s: %s", pcap_path, exc)
        return False


def estimate_packet_count(pcap_path: str) -> int:
    """
    Quick estimate of packet count without full parse.

    Uses file size heuristics (average ~500 bytes per packet
    in typical PCAP captures including headers).

    Args:
        pcap_path: Path to the PCAP file.

    Returns:
        Estimated packet count (0 if file doesn't exist).
    """
    path = Path(pcap_path)
    if not path.exists():
        return 0

    file_size = path.stat().st_size

    # Subtract PCAP global header (~24 bytes)
    payload_size = max(0, file_size - 24)

    # Average packet = ~500 bytes (header 16 bytes + ~484 bytes payload)
    avg_packet_size = 500
    return payload_size // avg_packet_size
