"""
Phase 4: Active Agent Containment Module
Provides functions to isolate malicious processes and block IPs at the firewall level.
"""

import psutil
import subprocess
import logging
import platform
import os
import pandas as pd
from typing import Dict, Tuple, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ContainmentAgent:
    """Handles process suspension and firewall-based containment."""
    
    def __init__(self):
        self.os_type = platform.system()  # "Windows", "Linux", "Darwin"
        self.is_admin = self._check_admin_privileges()
    
    def _check_admin_privileges(self) -> bool:
        """Check if the application is running with admin/root privileges."""
        try:
            if self.os_type == "Windows":
                import ctypes
                return ctypes.windll.shell.IsUserAnAdmin()
            else:  # Linux/macOS
                return os.getuid() == 0
        except Exception as e:
            logger.warning(f"Cannot determine admin status: {e}")
            return False
    
    def isolate_process(self, pid: int, action: str = "suspend") -> Tuple[bool, str]:
        """
        Isolate a malicious process by suspending or terminating it.
        
        Args:
            pid: Process ID to isolate
            action: "suspend" or "terminate"
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if pid is None or pd.isna(pid):
                return False, "Invalid PID"
            
            process = psutil.Process(int(pid))
            
            if action == "suspend":
                process.suspend()
                logger.info(f"Process {pid} ({process.name()}) suspended.")
                return True, f"✅ Process {process.name()} (PID {pid}) suspended successfully."
            
            elif action == "terminate":
                process.terminate()
                logger.info(f"Process {pid} ({process.name()}) terminated.")
                return True, f"✅ Process {process.name()} (PID {pid}) terminated successfully."
            
            else:
                return False, f"Unknown action: {action}"
                
        except psutil.NoSuchProcess:
            return False, f"❌ Process {pid} not found (may have already exited)."
        except psutil.AccessDenied:
            return False, f"❌ Access denied. Run as Administrator/root to suspend PID {pid}."
        except Exception as e:
            logger.error(f"Error isolating process {pid}: {e}")
            return False, f"❌ Error: {str(e)}"
    
    def block_ip_windows(self, ip_address: str, direction: str = "both") -> Tuple[bool, str]:
        """
        Block an IP address using Windows Firewall (netsh).
        
        Args:
            ip_address: IP to block
            direction: "in", "out", or "both"
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.is_admin:
            return False, "❌ Windows Firewall requires Administrator privileges. Please run as Admin."
        
        try:
            rule_name = f"AeroGuard_Block_{ip_address.replace('.', '_')}"
            
            if direction in ["in", "both"]:
                cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip_address}'
                subprocess.run(cmd_in, shell=True, check=True, capture_output=True)
            
            if direction in ["out", "both"]:
                cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip_address}'
                subprocess.run(cmd_out, shell=True, check=True, capture_output=True)
            
            logger.info(f"Firewall rule added to block {ip_address}")
            return True, f"✅ IP {ip_address} blocked via Windows Firewall."
            
        except subprocess.CalledProcessError as e:
            if "already exists" in str(e):
                return True, f"⚠️ IP {ip_address} was already blocked."
            logger.error(f"Firewall command error: {e}")
            return False, f"❌ Failed to block IP: {str(e)}"
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False, f"❌ Error: {str(e)}"
    
    def block_ip_linux(self, ip_address: str, direction: str = "both") -> Tuple[bool, str]:
        """
        Block an IP address using Linux iptables.
        
        Args:
            ip_address: IP to block
            direction: "in", "out", or "both"
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.is_admin:
            return False, "❌ iptables requires root privileges. Please run with sudo."
        
        try:
            if direction in ["in", "both"]:
                cmd_in = f"iptables -I INPUT -s {ip_address} -j DROP"
                subprocess.run(cmd_in, shell=True, check=True, capture_output=True)
            
            if direction in ["out", "both"]:
                cmd_out = f"iptables -I OUTPUT -d {ip_address} -j DROP"
                subprocess.run(cmd_out, shell=True, check=True, capture_output=True)
            
            # Persist rules
            subprocess.run("iptables-save > /etc/iptables/rules.v4", shell=True, capture_output=True)
            
            logger.info(f"iptables rule added to block {ip_address}")
            return True, f"✅ IP {ip_address} blocked via iptables."
            
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables command error: {e}")
            return False, f"❌ Failed to block IP: {str(e)}"
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False, f"❌ Error: {str(e)}"
    
    def block_ip(self, ip_address: str, direction: str = "both") -> Tuple[bool, str]:
        """
        Platform-agnostic IP blocking.
        
        Args:
            ip_address: IP to block
            direction: "in", "out", or "both"
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        if self.os_type == "Windows":
            return self.block_ip_windows(ip_address, direction)
        elif self.os_type == "Linux":
            return self.block_ip_linux(ip_address, direction)
        else:
            return False, f"❌ IP blocking not supported on {self.os_type}"
    
    def unblock_ip_windows(self, ip_address: str) -> Tuple[bool, str]:
        """Remove Windows Firewall blocking rule."""
        if not self.is_admin:
            return False, "❌ Requires Administrator privileges."
        
        try:
            rule_name = f"AeroGuard_Block_{ip_address.replace('.', '_')}"
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}_IN"'
            subprocess.run(cmd, shell=True, check=False, capture_output=True)
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"'
            subprocess.run(cmd, shell=True, check=False, capture_output=True)
            return True, f"✅ Unblocked {ip_address}"
        except Exception as e:
            return False, f"❌ Error: {str(e)}"
    
    def unblock_ip_linux(self, ip_address: str) -> Tuple[bool, str]:
        """Remove Linux iptables blocking rule."""
        if not self.is_admin:
            return False, "❌ Requires root privileges."
        
        try:
            cmd_in = f"iptables -D INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd_in, shell=True, check=False, capture_output=True)
            cmd_out = f"iptables -D OUTPUT -d {ip_address} -j DROP"
            subprocess.run(cmd_out, shell=True, check=False, capture_output=True)
            subprocess.run("iptables-save > /etc/iptables/rules.v4", shell=True, capture_output=True)
            return True, f"✅ Unblocked {ip_address}"
        except Exception as e:
            return False, f"❌ Error: {str(e)}"
    
    def unblock_ip(self, ip_address: str) -> Tuple[bool, str]:
        """Platform-agnostic IP unblocking."""
        if self.os_type == "Windows":
            return self.unblock_ip_windows(ip_address)
        elif self.os_type == "Linux":
            return self.unblock_ip_linux(ip_address)
        else:
            return False, f"❌ Not supported on {self.os_type}"
    
    def get_containment_status(self) -> Dict[str, str]:
        """Get current containment system status."""
        return {
            "os": self.os_type,
            "admin_privileged": self.is_admin,
            "firewall_available": self.is_admin,
            "process_control_available": True
        }
