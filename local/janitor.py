# local/janitor.py
"""
AeroGuard IDS - Startup Janitor

Securely cleans up residual PCAP and temporary files on system boot.
Uses SSD-aware deletion strategy (single zero-pass + OS FDE reliance).
"""

import logging
import os
import platform
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# File extensions that the janitor targets for cleanup
TARGET_EXTENSIONS = {".pcap", ".pcapng", ".json", ".lock", ".tmp"}
AEROSGUARD_PREFIX = "aerog_"
AEROSGUARD_DIR_NAME = "aerosguard"


def get_aerosguard_temp_dir() -> Path:
    """
    Return the AeroGuard temp directory path for the current platform.

    Returns:
        Path to the AeroGuard temp directory.
    """
    if platform.system() == "Linux":
        shm_dir = Path("/dev/shm") / AEROSGUARD_DIR_NAME
        if Path("/dev/shm").exists():
            return shm_dir

    return Path(tempfile.gettempdir()) / AEROSGUARD_DIR_NAME


def enumerate_residual_files(temp_dir: str) -> List[Path]:
    """
    Scan a directory for stale AeroGuard files (.pcap, .json, .lock, .tmp).

    Only returns files that match AeroGuard naming conventions or
    have known capture-related extensions within the AeroGuard temp dir.

    Args:
        temp_dir: Path to the directory to scan.

    Returns:
        List of Path objects for files eligible for cleanup.
    """
    target_path = Path(temp_dir)
    residual_files: List[Path] = []

    if not target_path.exists() or not target_path.is_dir():
        logger.debug("Temp directory does not exist: %s", temp_dir)
        return residual_files

    try:
        for entry in target_path.iterdir():
            if entry.is_file() and entry.suffix.lower() in TARGET_EXTENSIONS:
                residual_files.append(entry)
    except PermissionError:
        logger.warning("Permission denied scanning: %s", temp_dir)
    except OSError as exc:
        logger.error("Error scanning temp directory %s: %s", temp_dir, exc)

    return residual_files


def secure_delete_file(file_path: Path) -> bool:
    """
    Securely delete a file using an SSD-aware strategy.

    Performs a single zero-pass overwrite as defense-in-depth,
    then unlinks the file. Primary data-at-rest protection is
    expected to come from OS-level Full Disk Encryption
    (BitLocker, FileVault, LUKS).

    On RAM-backed filesystems (/dev/shm), the zero-pass is
    still performed for consistency but is technically redundant.

    Args:
        file_path: Path to the file to delete.

    Returns:
        True if the file was successfully deleted, False otherwise.
    """
    try:
        path = Path(file_path)
        if not path.exists():
            return True

        # Single zero-pass overwrite (defense-in-depth)
        file_size = path.stat().st_size
        if file_size > 0:
            with open(path, "r+b") as f:
                f.seek(0)
                # Write in chunks to avoid large memory allocation
                chunk_size = min(file_size, 1024 * 1024)  # 1MB chunks
                bytes_written = 0
                while bytes_written < file_size:
                    to_write = min(chunk_size, file_size - bytes_written)
                    f.write(b"\x00" * to_write)
                    bytes_written += to_write
                f.flush()
                os.fsync(f.fileno())

        # Delete the file
        path.unlink()
        logger.info("Deleted file: %s", file_path)
        return True

    except PermissionError:
        logger.warning("Permission denied deleting: %s", file_path)
        return False
    except OSError as exc:
        logger.error("Failed to delete %s: %s", file_path, exc)
        return False


def run_startup_janitor(temp_dir: Optional[str] = None) -> dict:
    """
    Execute the startup janitor to clean all residual AeroGuard files.

    Scans the AeroGuard temp directory (or a specified directory) for
    stale capture, lock, and metadata files, then securely deletes them.

    Args:
        temp_dir: Optional override for the temp directory to scan.
                  Defaults to the platform-specific AeroGuard temp dir.

    Returns:
        Dictionary with cleanup results:
        {
            'deleted_count': int,
            'failed_count': int,
            'files_found': int,
            'log': str,
            'timestamp': str
        }
    """
    if temp_dir is None:
        scan_dir = str(get_aerosguard_temp_dir())
    else:
        scan_dir = temp_dir

    timestamp = datetime.now(timezone.utc).isoformat()
    log_lines = [f"[{timestamp}] Janitor started. Scanning: {scan_dir}"]

    residual_files = enumerate_residual_files(scan_dir)
    files_found = len(residual_files)
    log_lines.append(f"Found {files_found} residual file(s).")

    deleted_count = 0
    failed_count = 0

    for file_path in residual_files:
        success = secure_delete_file(file_path)
        if success:
            deleted_count += 1
            log_lines.append(f"  Deleted: {file_path.name}")
        else:
            failed_count += 1
            log_lines.append(f"  FAILED: {file_path.name}")

    log_lines.append(
        f"Janitor complete. Deleted: {deleted_count}, Failed: {failed_count}"
    )
    log_text = "\n".join(log_lines)
    logger.info(log_text)

    return {
        "deleted_count": deleted_count,
        "failed_count": failed_count,
        "files_found": files_found,
        "log": log_text,
        "timestamp": timestamp,
    }


def register_startup_hook() -> bool:
    """
    Register the janitor to run on system startup (platform-specific).

    - Windows: Creates a scheduled task via schtasks.
    - macOS: Installs a launchd plist.
    - Linux: Creates a systemd user service.

    Returns:
        True if the hook was successfully registered.
    """
    import subprocess
    import sys

    system = platform.system()
    python_exe = sys.executable
    janitor_cmd = f'"{python_exe}" -c "from local.janitor import run_startup_janitor; run_startup_janitor()"'

    try:
        if system == "Windows":
            # Create Windows Scheduled Task
            result = subprocess.run(
                [
                    "schtasks",
                    "/create",
                    "/tn",
                    "AeroGuard_Janitor",
                    "/tr",
                    janitor_cmd,
                    "/sc",
                    "onlogon",
                    "/rl",
                    "limited",
                    "/f",
                ],
                capture_output=True,
                text=True,
                shell=False,
            )
            if result.returncode == 0:
                logger.info("Registered Windows startup task.")
                return True
            else:
                logger.error("schtasks failed: %s", result.stderr)
                return False

        elif system == "Darwin":
            # macOS launchd plist
            plist_path = Path.home() / "Library" / "LaunchAgents" / "com.aerosguard.janitor.plist"
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aerosguard.janitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_exe}</string>
        <string>-c</string>
        <string>from local.janitor import run_startup_janitor; run_startup_janitor()</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"""
            plist_path.parent.mkdir(parents=True, exist_ok=True)
            plist_path.write_text(plist_content)
            logger.info("Registered macOS launchd plist: %s", plist_path)
            return True

        elif system == "Linux":
            # systemd user service
            service_dir = Path.home() / ".config" / "systemd" / "user"
            service_dir.mkdir(parents=True, exist_ok=True)
            service_path = service_dir / "aerosguard-janitor.service"
            service_content = f"""[Unit]
Description=AeroGuard IDS Startup Janitor
After=default.target

[Service]
Type=oneshot
ExecStart={python_exe} -c "from local.janitor import run_startup_janitor; run_startup_janitor()"

[Install]
WantedBy=default.target
"""
            service_path.write_text(service_content)
            subprocess.run(
                ["systemctl", "--user", "enable", "aerosguard-janitor.service"],
                capture_output=True,
                shell=False,
            )
            logger.info("Registered systemd user service: %s", service_path)
            return True

        else:
            logger.warning("Unsupported platform for startup hook: %s", system)
            return False

    except Exception as exc:
        logger.error("Failed to register startup hook: %s", exc)
        return False
