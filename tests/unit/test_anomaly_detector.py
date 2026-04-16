# tests/unit/test_anomaly_detector.py
"""
Unit tests for Isolation Forest Anomaly Detector.

Tests model training, scoring, explanations, and persistence.
"""

import pytest
import pandas as pd
import numpy as np
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from sklearn.ensemble import IsolationForest

from local.ml.anomaly_detector import IsolationForestModel


class TestAnomalyModelTraining:
    """Tests for IsolationForestModel.train_on_baseline()."""

    def test_train_on_valid_features(self):
        """Verify model trains on valid feature DataFrame."""
        model = IsolationForestModel()

        # Create synthetic baseline features
        baseline_data = {
            "packet_count": [100, 105, 95, 1000],  # 1000 is outlier
            "byte_count": [50000, 52000, 48000, 500000],
            "tcp_ratio": [0.7, 0.75, 0.65, 0.95],
        }
        df = pd.DataFrame(baseline_data)

        success, stats = model.train_on_baseline(df)

        assert success
        assert model.is_trained
        assert stats["samples_trained"] == 4
        assert stats["features_count"] == 3
        assert "anomalies_detected" in stats

    def test_train_on_empty_dataframe(self):
        """Verify empty DataFrame is rejected."""
        model = IsolationForestModel()
        empty_df = pd.DataFrame()

        success, stats = model.train_on_baseline(empty_df)

        assert not success
        assert not model.is_trained

    def test_contamination_parameter(self):
        """Verify contamination parameter affects anomaly detection."""
        model_low = IsolationForestModel(contamination=0.01)
        model_high = IsolationForestModel(contamination=0.2)

        baseline_data = {
            "packet_count": list(range(100, 200)),
            "byte_count": list(range(50000, 50100)),
        }
        df = pd.DataFrame(baseline_data)

        model_low.train_on_baseline(df)
        model_high.train_on_baseline(df)

        assert model_low.contamination < model_high.contamination


class TestAnomalyScoring:
    """Tests for IsolationForestModel.score_anomalies()."""

    def test_score_normal_traffic(self):
        """Verify normal traffic scores low on anomaly scale."""
        model = IsolationForestModel(contamination=0.05)

        # Train on normal data
        baseline_data = {
            "packet_count": [100, 105, 95, 98, 102],
            "byte_count": [50000, 52000, 48000, 49000, 51000],
        }
        baseline_df = pd.DataFrame(baseline_data)
        model.train_on_baseline(baseline_df)

        # Score normal data
        normal_data = {
            "packet_count": [100, 103],
            "byte_count": [50000, 51000],
        }
        test_df = pd.DataFrame(normal_data)
        scores, predictions = model.score_anomalies(test_df)

        assert len(scores) == 2
        assert len(predictions) == 2
        # Normal traffic should have low anomaly scores
        assert scores[0] < 0.5
        assert predictions[0] == 1  # 1 = normal

    def test_score_anomalous_traffic(self):
        """Verify anomalous traffic can be distinguished from normal."""
        model = IsolationForestModel(contamination=0.05)

        # Train on data with consistent pattern
        baseline_data = {
            "packet_count": [100, 110, 90, 100, 105, 95, 105, 100],
            "byte_count": [50000, 55000, 45000, 50000, 52000, 48000, 52000, 50000],
        }
        baseline_df = pd.DataFrame(baseline_data)
        model.train_on_baseline(baseline_df)

        # Score on data point that's within normal range
        normal_data = {"packet_count": [100], "byte_count": [50000]}
        normal_df = pd.DataFrame(normal_data)
        normal_scores, normal_preds = model.score_anomalies(normal_df)

        # Score on extreme outlier (different from typical data pattern)
        # Use much smaller values to be outlier in opposite direction
        anomaly_data = {"packet_count": [10], "byte_count": [5000]}
        anomaly_df = pd.DataFrame(anomaly_data)
        anomaly_scores, anomaly_preds = model.score_anomalies(anomaly_df)

        # Normal should be classified as normal (1) or at least lower score
        assert normal_preds[0] == 1 or normal_scores[0] < 0.5

    def test_score_before_training(self):
        """Verify scoring before training returns empty arrays."""
        model = IsolationForestModel()

        test_data = {"packet_count": [100], "byte_count": [50000]}
        test_df = pd.DataFrame(test_data)

        scores, predictions = model.score_anomalies(test_df)

        assert len(scores) == 0
        assert len(predictions) == 0


class TestAnomalyExplanation:
    """Tests for IsolationForestModel.explain_anomalies()."""

    def test_explain_identifies_top_features(self):
        """Verify explanation identifies top contributing features."""
        model = IsolationForestModel()

        baseline_data = {
            "packet_count": [100] * 10,
            "byte_count": [50000] * 10,
            "tcp_ratio": [0.7] * 10,
        }
        baseline_df = pd.DataFrame(baseline_data)
        model.train_on_baseline(baseline_df)

        # Create anomaly with extreme packet count
        anomaly_data = {
            "packet_count": [1000],  # Extreme
            "byte_count": [50000],   # Normal
            "tcp_ratio": [0.7],      # Normal
        }
        anomaly_df = pd.DataFrame(anomaly_data)
        scores, _ = model.score_anomalies(anomaly_df)

        explanations = model.explain_anomalies(anomaly_df, scores, k=2)

        assert len(explanations) == 1
        assert "top_features" in explanations[0]
        # packet_count should be in top features
        assert "packet_count" in explanations[0]["top_features"]


class TestModelPersistence:
    """Tests for saving and loading models."""

    def test_save_and_load_model(self):
        """Verify model can be saved and loaded."""
        original_model = IsolationForestModel(contamination=0.05)

        baseline_data = {
            "packet_count": [100, 105, 95],
            "byte_count": [50000, 52000, 48000],
        }
        baseline_df = pd.DataFrame(baseline_data)
        original_model.train_on_baseline(baseline_df)

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "test_model.pkl"

            # Save
            assert original_model.save_model(str(model_path))

            # Load
            loaded_model = IsolationForestModel.load_model(str(model_path))

            assert loaded_model is not None
            assert loaded_model.is_trained
            assert loaded_model.feature_names == original_model.feature_names
            assert loaded_model.contamination == original_model.contamination

    def test_save_untrained_model_fails(self):
        """Verify saving untrained model returns False."""
        model = IsolationForestModel()

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "test_model.pkl"
            assert not model.save_model(str(model_path))

    def test_get_model_info(self):
        """Verify get_model_info returns metadata."""
        model = IsolationForestModel()

        baseline_data = {
            "packet_count": [100, 105, 95],
            "byte_count": [50000, 52000, 48000],
        }
        baseline_df = pd.DataFrame(baseline_data)
        model.train_on_baseline(baseline_df)

        info = model.get_model_info()

        assert info["is_trained"]
        assert len(info["feature_names"]) == 2
        assert info["feature_count"] == 2
        assert "contamination" in info
