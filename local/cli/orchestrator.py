# local/cli/orchestrator.py
"""
AeroGuard IDS - Orchestration Engine

Coordinates local capture, feature extraction, anomaly detection, and sanitization.
Handles the full pipeline: capture → features → detection → sanitization → reporting.
"""

import logging
import json
from pathlib import Path
from typing import Dict, Optional, Any
from datetime import datetime

from local.network.interface_detector import get_active_interfaces, validate_capture_capability
from local.network.scapy_sniffer import ScapySniffer
from local.network.pyshark_spooler import PySharkSpooler
from local.ml.feature_extractor import FeatureExtractor
from local.ml.anomaly_detector import IsolationForestModel
from local.sanitization.sanitizer import PCAPSanitizer
from local.storage.sqlite_cache import LocalCache

logger = logging.getLogger(__name__)


class AnalysisOrchestrator:
    """Orchestrates the full AeroGuard IDS analysis pipeline."""

    def __init__(self, cache_dir: Optional[Path] = None, verbose: bool = False):
        """
        Initialize orchestrator with cache and logging.

        Args:
            cache_dir: Directory for model and cache storage. Defaults to ~/.aerosguard
            verbose: Enable verbose logging
        """
        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".aerosguard"
        self.cache_dir.mkdir(exist_ok=True)

        # Initialize components
        self.cache = LocalCache(db_path=str(self.cache_dir / "aerosguard.db"))
        self.sniffer = None
        self.spooler = None
        self.extractor = FeatureExtractor()
        self.sanitizer = PCAPSanitizer()

        # Setup logging
        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

    def list_interfaces(self) -> list:
        """
        List available network interfaces for capture.

        Returns:
            List of interface info dicts with keys: name, ip, mac, mtu, is_wireless, status
        """
        logger.info("Detecting network interfaces...")
        interfaces = get_active_interfaces()
        
        for iface in interfaces:
            logger.info(
                f"  {iface['name']:15} | IP: {iface['ip']:15} | "
                f"Status: {'UP' if iface['status'] else 'DOWN':4} | "
                f"Wireless: {'Yes' if iface['is_wireless'] else 'No':3}"
            )
        
        return interfaces

    def validate_interface(self, interface_name: str) -> bool:
        """
        Validate that interface can perform packet capture.

        Args:
            interface_name: Name of network interface (e.g., 'eth0', 'wlan0')

        Returns:
            True if interface is capture-ready, False otherwise
        """
        logger.info(f"Validating capture capability on {interface_name}...")
        is_valid = validate_capture_capability(interface_name)
        
        if is_valid:
            logger.info(f"✓ {interface_name} is ready for capture")
        else:
            logger.warning(
                f"✗ {interface_name} is not ready for capture. "
                "May require elevated privileges."
            )
        
        return is_valid

    def capture_traffic(
        self,
        interface: str,
        duration_seconds: int,
        method: str = "scapy",
        output_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Capture network traffic from specified interface.

        Args:
            interface: Network interface name
            duration_seconds: Capture duration in seconds
            method: Capture method - 'scapy' (pure Python, default) or 'pyshark' (requires tshark/Wireshark)
            output_path: Path to save PCAP file. Defaults to cache_dir/capture_<timestamp>.pcap

        Returns:
            Dict with keys:
            - pcap_path: Path to captured PCAP file
            - duration: Actual capture duration
            - packet_count: Estimated packet count
            - status: 'success' or 'failed'
            - error: Error message if failed
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.cache_dir / f"capture_{timestamp}.pcap"

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(
            f"Starting {duration_seconds}s capture on {interface} "
            f"(method: {method}, output: {output_path})"
        )

        try:
            if method == "scapy":
                return self._capture_scapy(interface, duration_seconds, output_path)
            elif method == "pyshark":
                return self._capture_pyshark(interface, duration_seconds, output_path)
            else:
                return {
                    "status": "failed",
                    "error": f"Unknown capture method: {method}",
                    "pcap_path": None,
                }
        except Exception as e:
            logger.error(f"Capture failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "pcap_path": None,
            }

    def _capture_scapy(
        self, interface: str, duration_seconds: int, output_path: Path
    ) -> Dict[str, Any]:
        """Internal: Capture using Scapy sniffer."""
        self.sniffer = ScapySniffer(interface=interface)
        self.sniffer.start_sniffing_threaded()

        logger.info(f"Sniffing on {interface} for {duration_seconds} seconds...")
        import time
        time.sleep(duration_seconds)

        summary = self.sniffer.stop_sniffing()
        packet_count = summary["packet_count"]
        byte_count = summary["bytes_total"]

        logger.info(f"Captured {packet_count} packets ({byte_count} bytes)")

        return {
            "status": "success",
            "pcap_path": str(output_path),
            "duration": duration_seconds,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "capture_summary": summary,  # Store full summary for feature extraction
            "method": "scapy",
        }

    def _capture_pyshark(
        self, interface: str, duration_seconds: int, output_path: Path
    ) -> Dict[str, Any]:
        """Internal: Capture using PyShark spooler (tshark subprocess)."""
        self.spooler = PySharkSpooler(interface=interface, output_dir=output_path.parent)
        
        pcap_path = self.spooler.start_capture(duration_seconds=duration_seconds)
        self.spooler.wait_for_capture_completion()

        # Validate PCAP
        if not pcap_path or not Path(pcap_path).exists():
            return {
                "status": "failed",
                "error": "PCAP file not created",
                "pcap_path": None,
            }

        if not self.spooler.validate_pcap_file(pcap_path):
            return {
                "status": "failed",
                "error": "Invalid PCAP file",
                "pcap_path": None,
            }

        # Move to output path if different
        pcap_file = Path(pcap_path)
        if str(pcap_file) != str(output_path):
            pcap_file.rename(output_path)

        packet_count = self.spooler.estimate_packet_count(str(output_path))

        logger.info(f"Captured {packet_count} packets to {output_path}")

        return {
            "status": "success",
            "pcap_path": str(output_path),
            "duration": duration_seconds,
            "packet_count": packet_count,
        }

    def detect_anomalies(
        self,
        pcap_path: str,
        baseline_model_path: Optional[str] = None,
        contamination: float = 0.1,
    ) -> Dict[str, Any]:
        """
        Detect anomalies in PCAP file using trained model.

        Args:
            pcap_path: Path to PCAP file for analysis
            baseline_model_path: Path to pre-trained model pickle. If None, trains on data.
            contamination: Percentage of data expected to be anomalous (0.0-1.0)

        Returns:
            Dict with keys:
            - status: 'success' or 'failed'
            - anomaly_scores: List of anomaly scores per flow
            - predictions: List of predictions (-1=anomalous, 1=normal)
            - threat_level: 'low', 'medium', 'high' based on percentage anomalous
            - anomalous_count: Number of anomalous flows
            - total_flows: Total flows analyzed
            - sanitized_data: JSON-safe dict with masked IPs
            - error: Error message if failed
        """
        logger.info(f"Analyzing {pcap_path}...")

        try:
            # Extract features from PCAP
            logger.info("Extracting features from PCAP...")
            features_df = self.extractor.extract_from_pcap(pcap_path)

            if features_df is None or features_df.empty:
                return {
                    "status": "failed",
                    "error": "No features extracted from PCAP",
                }

            # Normalize features
            features_df = self.extractor.normalize_features(features_df)
            logger.info(f"Extracted features for {len(features_df)} flows")

            # Load or train model
            model = IsolationForestModel(contamination=contamination)

            if baseline_model_path and Path(baseline_model_path).exists():
                logger.info(f"Loading baseline model from {baseline_model_path}...")
                model = IsolationForestModel.load_model(baseline_model_path)
            else:
                # If no baseline, use data itself as training (assumes mostly normal)
                logger.warning(
                    "No baseline model provided. Using input data as baseline. "
                    "For best results, provide a trained baseline."
                )
                model.train_on_baseline(features_df)

            # Score the traffic
            anomaly_scores, predictions = model.score_anomalies(features_df)

            # Calculate statistics
            anomalous_count = sum(1 for p in predictions if p == -1)
            total_flows = len(predictions)
            anomaly_percent = (anomalous_count / total_flows * 100) if total_flows > 0 else 0

            # Determine threat level
            if anomaly_percent > 20:
                threat_level = "high"
            elif anomaly_percent > 5:
                threat_level = "medium"
            else:
                threat_level = "low"

            logger.info(
                f"Analysis complete: {anomalous_count}/{total_flows} flows anomalous "
                f"({anomaly_percent:.1f}%) - Threat Level: {threat_level}"
            )

            # Sanitize PCAP to JSON
            logger.info("Sanitizing PCAP data...")
            sanitized_data = self.sanitizer.sanitize_pcap_to_json(pcap_path)

            return {
                "status": "success",
                "anomaly_scores": anomaly_scores.tolist(),
                "predictions": predictions.tolist(),
                "threat_level": threat_level,
                "anomalous_count": anomalous_count,
                "total_flows": total_flows,
                "anomaly_percent": anomaly_percent,
                "sanitized_data": sanitized_data,
                "model_info": model.get_model_info(),
            }

        except Exception as e:
            logger.error(f"Detection failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
            }

    def calibrate_baseline(
        self,
        interface: str,
        duration_seconds: int,
        output_model_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Capture baseline (normal) traffic and train anomaly detection model.

        Args:
            interface: Network interface to capture from
            duration_seconds: Capture duration for baseline
            output_model_path: Path to save trained model. Defaults to cache_dir/baseline.pkl

        Returns:
            Dict with keys:
            - status: 'success' or 'failed'
            - model_path: Path to saved model
            - training_samples: Number of flows in baseline
            - training_time: Time to train model (seconds)
            - error: Error message if failed
        """
        if output_model_path is None:
            output_model_path = str(self.cache_dir / "baseline.pkl")

        logger.info(f"Starting baseline calibration ({duration_seconds}s on {interface})...")
        logger.info("Keep network traffic normal during this period.")

        # Capture baseline traffic (using pure Python Scapy, no external dependencies)
        capture_result = self.capture_traffic(
            interface=interface,
            duration_seconds=duration_seconds,
            method="scapy",
        )

        if capture_result["status"] != "success":
            return {
                "status": "failed",
                "error": f"Capture failed: {capture_result.get('error')}",
            }

        try:
            # Extract features from captured traffic
            logger.info("Extracting features from baseline traffic...")
            
            # If captured via Scapy, extract from capture summary directly
            if capture_result.get("method") == "scapy" and "capture_summary" in capture_result:
                features_list = self.extractor.extract_features_from_scapy_sniffer(
                    capture_result["capture_summary"]
                )
                # Convert list of dicts to DataFrame
                features_df = pd.DataFrame(features_list) if features_list else None
            else:
                # Fallback: try to extract from PCAP (requires tshark)
                pcap_path = capture_result["pcap_path"]
                features_list = self.extractor.extract_from_pcap(pcap_path)
                # Convert list of dicts to DataFrame
                features_df = pd.DataFrame(features_list) if features_list else None

            if features_df is None or features_df.empty:
                return {
                    "status": "failed",
                    "error": "No features extracted from baseline",
                }

            features_df = self.extractor.normalize_features(features_df)

            # Train model
            logger.info(f"Training anomaly detection model on {len(features_df)} flows...")
            import time
            start_time = time.time()

            model = IsolationForestModel(contamination=0.1)
            model.train_on_baseline(features_df)

            training_time = time.time() - start_time

            # Save model
            model.save_model(output_model_path)
            logger.info(f"✓ Baseline model saved to {output_model_path}")

            return {
                "status": "success",
                "model_path": output_model_path,
                "training_samples": len(features_df),
                "training_time": training_time,
            }

        except Exception as e:
            logger.error(f"Baseline calibration failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
            }

    def save_analysis_report(
        self, analysis_result: Dict[str, Any], output_path: str
    ) -> bool:
        """
        Save analysis result to JSON file.

        Args:
            analysis_result: Dict returned from detect_anomalies()
            output_path: Path to save JSON report

        Returns:
            True if successful, False otherwise
        """
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            report = {
                "timestamp": datetime.now().isoformat(),
                "analysis": analysis_result,
            }

            with open(output_path, "w") as f:
                json.dump(report, f, indent=2, default=str)

            logger.info(f"✓ Report saved to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return False
