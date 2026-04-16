# local/storage/sqlite_cache.py
"""
AeroGuard IDS - SQLite Local Cache

Persists ML models, baseline profiles, user settings, and analysis results
in a local SQLite database for offline functionality.
"""

import logging
import sqlite3
import json
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
import pickle

logger = logging.getLogger(__name__)

# Default cache location
DEFAULT_CACHE_DIR = Path.home() / ".config" / "aerosguard"
DEFAULT_CACHE_DB = DEFAULT_CACHE_DIR / "local.db"


class LocalCache:
    """
    SQLite-backed cache for local model and result persistence.

    Schema:
    - users: User profiles and auth
    - baseline_profiles: Trained models and baseline statistics
    - settings: User preferences and configuration
    - analysis_cache: Cached analysis results with TTL
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the cache database.

        Args:
            db_path: Path to SQLite database. Defaults to ~/.config/aerosguard/local.db
        """
        self.db_path = Path(db_path) if db_path else DEFAULT_CACHE_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.connection: Optional[sqlite3.Connection] = None
        self._init_database()

    def _init_database(self) -> None:
        """Initialize database schema if not already present."""
        try:
            self.connection = sqlite3.connect(
                self.db_path, isolation_level=None, check_same_thread=False
            )
            self.connection.row_factory = sqlite3.Row
            cursor = self.connection.cursor()

            # Create tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_auth TIMESTAMP,
                    firebase_uid TEXT UNIQUE
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baseline_profiles (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    profile_name TEXT NOT NULL,
                    iso_forest_model BLOB NOT NULL,
                    normalization_stats TEXT NOT NULL,
                    feature_count INTEGER,
                    training_samples INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id),
                    UNIQUE(user_id, profile_name)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_cache (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    pcap_hash TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    anomaly_score REAL,
                    threat_label TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ttl_seconds INTEGER DEFAULT 86400,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)

            # Create indexes for faster lookup
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_analysis_pcap_hash
                ON analysis_cache(pcap_hash)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_baseline_user
                ON baseline_profiles(user_id)
            """)

            self.connection.commit()
            logger.info(f"Initialized SQLite cache at {self.db_path}")

        except Exception as exc:
            logger.error(f"Error initializing database: {exc}")
            raise

    def get_or_create_user(
        self, username: str, email: str, firebase_uid: Optional[str] = None
    ) -> Optional[int]:
        """
        Get or create a user in the database.

        Args:
            username: Username.
            email: Email address.
            firebase_uid: Optional Firebase UID for cloud sync.

        Returns:
            User ID, or None if error.
        """
        try:
            cursor = self.connection.cursor()

            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                return row["id"]

            # Create new user
            cursor.execute(
                """
                INSERT INTO users (username, email, firebase_uid)
                VALUES (?, ?, ?)
                """,
                (username, email, firebase_uid),
            )
            self.connection.commit()

            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            logger.info(f"Created user: {username} (ID: {row['id']})")
            return row["id"] if row else None

        except Exception as exc:
            logger.error(f"Error getting/creating user: {exc}")
            return None

    def save_baseline_profile(
        self,
        user_id: int,
        profile_name: str,
        model: Any,
        feature_count: int,
        training_samples: int,
        normalization_stats: Dict,
    ) -> bool:
        """
        Save a trained baseline profile to the database.

        Args:
            user_id: User ID.
            profile_name: Name for the profile (e.g., "office_baseline").
            model: Trained Isolation Forest model.
            feature_count: Number of features.
            training_samples: Number of samples trained on.
            normalization_stats: Dict of Z-score normalization parameters.

        Returns:
            True if successful.
        """
        try:
            # Serialize model to blob
            model_blob = pickle.dumps(model)
            stats_json = json.dumps(normalization_stats)

            cursor = self.connection.cursor()

            # Delete existing profile with same name
            cursor.execute(
                """
                DELETE FROM baseline_profiles
                WHERE user_id = ? AND profile_name = ?
                """,
                (user_id, profile_name),
            )

            # Insert new profile
            cursor.execute(
                """
                INSERT INTO baseline_profiles
                (user_id, profile_name, iso_forest_model, normalization_stats,
                 feature_count, training_samples)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, profile_name, model_blob, stats_json, feature_count, training_samples),
            )
            self.connection.commit()

            logger.info(f"Saved baseline profile: {profile_name} for user {user_id}")
            return True

        except Exception as exc:
            logger.error(f"Error saving baseline profile: {exc}")
            return False

    def load_baseline_profile(
        self, user_id: int, profile_name: str = "default"
    ) -> Optional[Any]:
        """
        Load a trained baseline profile from the database.

        Args:
            user_id: User ID.
            profile_name: Profile name to load.

        Returns:
            Tuple of (model, stats_dict) or None if not found.
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                """
                SELECT iso_forest_model, normalization_stats
                FROM baseline_profiles
                WHERE user_id = ? AND profile_name = ?
                """,
                (user_id, profile_name),
            )
            row = cursor.fetchone()

            if not row:
                logger.warning(
                    f"Baseline profile not found: {profile_name} for user {user_id}"
                )
                return None

            model = pickle.loads(row["iso_forest_model"])
            stats = json.loads(row["normalization_stats"])

            # Update last_used
            cursor.execute(
                """
                UPDATE baseline_profiles
                SET last_used = CURRENT_TIMESTAMP
                WHERE user_id = ? AND profile_name = ?
                """,
                (user_id, profile_name),
            )
            self.connection.commit()

            return model, stats

        except Exception as exc:
            logger.error(f"Error loading baseline profile: {exc}")
            return None

    def save_analysis_result(
        self,
        user_id: int,
        pcap_hash: str,
        metadata: Dict,
        anomaly_score: float,
        threat_label: Optional[str] = None,
        ttl_hours: int = 24,
    ) -> bool:
        """
        Cache an analysis result with automatic expiration.

        Args:
            user_id: User ID.
            pcap_hash: SHA256 hash of PCAP file (for deduplication).
            metadata: Sanitized metadata from analysis.
            anomaly_score: Computed anomaly score (0-1).
            threat_label: Optional threat classification.
            ttl_hours: Time-to-live in hours (default 24).

        Returns:
            True if successful.
        """
        try:
            ttl_seconds = ttl_hours * 3600
            metadata_json = json.dumps(metadata)

            cursor = self.connection.cursor()
            cursor.execute(
                """
                INSERT INTO analysis_cache
                (user_id, pcap_hash, metadata, anomaly_score, threat_label, ttl_seconds)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, pcap_hash, metadata_json, anomaly_score, threat_label, ttl_seconds),
            )
            self.connection.commit()

            logger.info(f"Cached analysis result for PCAP hash: {pcap_hash[:16]}")
            return True

        except Exception as exc:
            logger.error(f"Error saving analysis result: {exc}")
            return False

    def get_cached_analysis(self, pcap_hash: str) -> Optional[Dict]:
        """
        Retrieve a cached analysis result if it exists and hasn't expired.

        Args:
            pcap_hash: SHA256 hash of PCAP file.

        Returns:
            Dict with cached analysis, or None if not found/expired.
        """
        try:
            cursor = self.connection.cursor()

            # Get cached result and check TTL
            cursor.execute(
                """
                SELECT metadata, anomaly_score, threat_label, timestamp, ttl_seconds
                FROM analysis_cache
                WHERE pcap_hash = ?
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (pcap_hash,),
            )
            row = cursor.fetchone()

            if not row:
                return None

            # Check if expired
            timestamp = datetime.fromisoformat(row["timestamp"])
            ttl = timedelta(seconds=row["ttl_seconds"])
            if datetime.now() - timestamp > ttl:
                logger.info(f"Cached analysis expired for: {pcap_hash[:16]}")
                return None

            return {
                "metadata": json.loads(row["metadata"]),
                "anomaly_score": row["anomaly_score"],
                "threat_label": row["threat_label"],
                "cached_at": row["timestamp"],
            }

        except Exception as exc:
            logger.error(f"Error retrieving cached analysis: {exc}")
            return None

    def set_user_setting(self, key: str, value: str) -> bool:
        """
        Save a user setting (e.g., preferred interface, capture duration).

        Args:
            key: Setting key.
            value: Setting value (JSON-encoded if complex).

        Returns:
            True if successful.
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO settings (key, value)
                VALUES (?, ?)
                """,
                (key, value),
            )
            self.connection.commit()
            return True

        except Exception as exc:
            logger.error(f"Error setting user setting: {exc}")
            return False

    def get_user_setting(self, key: str) -> Optional[str]:
        """
        Retrieve a user setting by key.

        Args:
            key: Setting key.

        Returns:
            Setting value, or None if not found.
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row["value"] if row else None

        except Exception as exc:
            logger.error(f"Error getting user setting: {exc}")
            return None

    def cleanup_expired_cache(self) -> int:
        """
        Delete expired analysis cache entries.

        Returns:
            Number of entries deleted.
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                DELETE FROM analysis_cache
                WHERE datetime(timestamp, '+' || ttl_seconds || ' seconds') < CURRENT_TIMESTAMP
            """)
            self.connection.commit()
            deleted = cursor.rowcount
            logger.info(f"Cleaned up {deleted} expired cache entries")
            return deleted

        except Exception as exc:
            logger.error(f"Error cleaning up cache: {exc}")
            return 0

    def close(self) -> None:
        """Close the database connection."""
        if self.connection:
            self.connection.close()
            logger.info("Closed SQLite cache connection")

    def __del__(self):
        """Ensure database connection is closed."""
        self.close()


def get_default_cache_path() -> Path:
    """
    Return the default cache database path.

    Returns:
        Path to default cache database.
    """
    return DEFAULT_CACHE_DB


def calculate_pcap_hash(pcap_path: str) -> str:
    """
    Calculate SHA256 hash of a PCAP file.

    Used for deduplication and cache lookup.

    Args:
        pcap_path: Path to PCAP file.

    Returns:
        Hex digest of SHA256 hash.
    """
    try:
        sha256_hash = hashlib.sha256()
        with open(pcap_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    except Exception as exc:
        logger.error(f"Error calculating PCAP hash: {exc}")
        return ""
