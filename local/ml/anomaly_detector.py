# local/ml/anomaly_detector.py
"""
AeroGuard IDS - Isolation Forest Anomaly Detector

Trains an unsupervised anomaly detection model using scikit-learn's
Isolation Forest on baseline network traffic features.
"""

import logging
import pickle
from typing import List, Dict, Tuple, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from pathlib import Path

logger = logging.getLogger(__name__)

# Default contamination rate (expected % of anomalies in baseline)
DEFAULT_CONTAMINATION = 0.05

# Default number of isolation trees
DEFAULT_N_ESTIMATORS = 100


class IsolationForestModel:
    """
    Unsupervised anomaly detection using Isolation Forest.

    Trains on baseline network traffic features and scores new traffic
    for anomalies. Provides anomaly scores (0-1) and feature importance.
    """

    def __init__(
        self,
        contamination: float = DEFAULT_CONTAMINATION,
        n_estimators: int = DEFAULT_N_ESTIMATORS,
        random_state: int = 42,
    ):
        """
        Initialize the Isolation Forest model.

        Args:
            contamination: Expected fraction of anomalies in baseline (0.01-0.5).
            n_estimators: Number of isolation trees.
            random_state: Random seed for reproducibility.
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.feature_names: List[str] = []
        self.normalization_stats: Dict[str, Tuple[float, float]] = {}
        self.is_trained = False

    def train_on_baseline(
        self, features_df: pd.DataFrame
    ) -> Tuple[bool, Dict]:
        """
        Train the Isolation Forest model on baseline features.

        Args:
            features_df: DataFrame of normalized features (from FeatureExtractor).

        Returns:
            Tuple of (success, stats_dict).
        """
        if features_df.empty:
            logger.error("Cannot train on empty features dataframe")
            return False, {}

        try:
            self.feature_names = features_df.columns.tolist()

            self.model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=self.random_state,
                n_jobs=-1,  # Use all available cores
            )

            self.model.fit(features_df)
            self.is_trained = True

            # Compute training statistics
            predictions = self.model.predict(features_df)
            anomaly_count = sum(1 for p in predictions if p == -1)

            stats = {
                "samples_trained": len(features_df),
                "anomalies_detected": anomaly_count,
                "training_contamination": anomaly_count / len(features_df),
                "features_count": len(self.feature_names),
                "feature_names": self.feature_names,
            }

            logger.info(
                f"Trained Isolation Forest: {len(features_df)} samples, "
                f"{anomaly_count} anomalies detected"
            )

            return True, stats

        except Exception as exc:
            logger.error(f"Error training Isolation Forest: {exc}")
            return False, {}

    def score_anomalies(
        self, features_df: pd.DataFrame
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Score a batch of feature vectors for anomalies.

        Args:
            features_df: DataFrame of normalized features to score.

        Returns:
            Tuple of (anomaly_scores, predictions).
            - anomaly_scores: 0-1 values (higher = more anomalous)
            - predictions: -1 for anomaly, 1 for normal
        """
        if not self.is_trained or self.model is None:
            logger.warning("Model not trained. Cannot score.")
            return np.array([]), np.array([])

        try:
            # Ensure features match training
            if set(features_df.columns) != set(self.feature_names):
                logger.warning("Feature mismatch. Reordering to match training.")
                features_df = features_df[self.feature_names]

            # Get anomaly scores (negative of isolation depth)
            # Range: ~0 (normal, deep in trees) to ~1 (anomalous, shallow)
            scores = self.model.score_samples(features_df)

            # Normalize scores to 0-1 range
            # Lower (more negative) scores = more anomalous
            anomaly_scores = 1 / (1 + np.exp(-scores))  # Sigmoid for 0-1

            # Get predictions (-1 = anomaly, 1 = normal)
            predictions = self.model.predict(features_df)

            return anomaly_scores, predictions

        except Exception as exc:
            logger.error(f"Error scoring anomalies: {exc}")
            return np.array([]), np.array([])

    def explain_anomalies(
        self, features_df: pd.DataFrame, anomaly_scores: np.ndarray, k: int = 5
    ) -> List[Dict]:
        """
        Identify top contributing features for each anomaly.

        Args:
            features_df: Original feature vectors.
            anomaly_scores: Scores from score_anomalies().
            k: Number of top features to identify.

        Returns:
            List of dicts with top contributing features per sample.
        """
        explanations = []

        try:
            for idx, score in enumerate(anomaly_scores):
                if idx >= len(features_df):
                    break

                features = features_df.iloc[idx]

                # Find most extreme feature values (high deviation)
                top_features = {}
                for feat_name in self.feature_names:
                    if feat_name in features.index:
                        val = abs(features[feat_name])
                        top_features[feat_name] = val

                # Sort and get top-k
                sorted_features = sorted(
                    top_features.items(), key=lambda x: x[1], reverse=True
                )[:k]

                explanation = {
                    "sample_idx": idx,
                    "anomaly_score": float(score),
                    "top_features": {
                        name: float(val) for name, val in sorted_features
                    },
                }
                explanations.append(explanation)

            return explanations

        except Exception as exc:
            logger.error(f"Error explaining anomalies: {exc}")
            return []

    def save_model(self, model_path: str) -> bool:
        """
        Persist the trained model to disk using pickle.

        Args:
            model_path: Path to save the model.

        Returns:
            True if successful.
        """
        if not self.is_trained:
            logger.error("Cannot save untrained model")
            return False

        try:
            path = Path(model_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            model_data = {
                "model": self.model,
                "feature_names": self.feature_names,
                "contamination": self.contamination,
                "n_estimators": self.n_estimators,
                "normalization_stats": self.normalization_stats,
            }

            with open(path, "wb") as f:
                pickle.dump(model_data, f)

            logger.info(f"Saved Isolation Forest model to {model_path}")
            return True

        except Exception as exc:
            logger.error(f"Error saving model: {exc}")
            return False

    @classmethod
    def load_model(cls, model_path: str) -> Optional["IsolationForestModel"]:
        """
        Load a previously trained model from disk.

        Args:
            model_path: Path to the saved model.

        Returns:
            IsolationForestModel instance, or None if load failed.
        """
        try:
            with open(model_path, "rb") as f:
                model_data = pickle.load(f)

            instance = cls(
                contamination=model_data.get("contamination", DEFAULT_CONTAMINATION),
                n_estimators=model_data.get("n_estimators", DEFAULT_N_ESTIMATORS),
            )
            instance.model = model_data.get("model")
            instance.feature_names = model_data.get("feature_names", [])
            instance.normalization_stats = model_data.get("normalization_stats", {})
            instance.is_trained = instance.model is not None

            logger.info(f"Loaded Isolation Forest model from {model_path}")
            return instance

        except Exception as exc:
            logger.error(f"Error loading model: {exc}")
            return None

    def get_model_info(self) -> Dict:
        """
        Return metadata about the trained model.

        Returns:
            Dict with model configuration and training info.
        """
        return {
            "is_trained": self.is_trained,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "feature_count": len(self.feature_names),
            "feature_names": self.feature_names,
            "normalization_stats": self.normalization_stats,
        }
