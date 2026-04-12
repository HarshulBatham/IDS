# tests/unit/test_janitor.py
"""
Unit tests for the AeroGuard IDS Startup Janitor.

Tests file enumeration, SSD-aware secure deletion,
and the full janitor run lifecycle.
"""

import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from local.janitor import (
    enumerate_residual_files,
    secure_delete_file,
    run_startup_janitor,
    get_aerosguard_temp_dir,
)


class TestEnumerateResidualFiles:
    """Tests for enumerate_residual_files()."""

    def test_finds_pcap_files(self):
        """Verify .pcap files are detected as residual."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "capture_123.pcap").touch()
            (Path(tmpdir) / "capture_456.pcap").touch()
            (Path(tmpdir) / "readme.txt").touch()  # Should be ignored

            result = enumerate_residual_files(tmpdir)

            assert len(result) == 2
            assert all(str(f).endswith(".pcap") for f in result)

    def test_finds_json_and_lock_files(self):
        """Verify .json, .lock, and .tmp files are detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "metadata.json").touch()
            (Path(tmpdir) / "capture.lock").touch()
            (Path(tmpdir) / "session.tmp").touch()

            result = enumerate_residual_files(tmpdir)

            assert len(result) == 3

    def test_ignores_non_target_extensions(self):
        """Verify files with non-target extensions are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "readme.txt").touch()
            (Path(tmpdir) / "notes.md").touch()
            (Path(tmpdir) / "image.png").touch()

            result = enumerate_residual_files(tmpdir)

            assert len(result) == 0

    def test_handles_nonexistent_directory(self):
        """Verify clean return for a path that doesn't exist."""
        result = enumerate_residual_files("/nonexistent/path/xyz")

        assert result == []

    def test_handles_empty_directory(self):
        """Verify clean return for an empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = enumerate_residual_files(tmpdir)

            assert result == []

    def test_skips_subdirectories(self):
        """Verify subdirectories are not included in results."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir) / "subdir.pcap"  # Directory with .pcap name
            subdir.mkdir()

            result = enumerate_residual_files(tmpdir)

            assert len(result) == 0


class TestSecureDeleteFile:
    """Tests for secure_delete_file()."""

    def test_deletes_file_successfully(self):
        """Verify file is deleted after secure_delete_file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pcap") as f:
            f.write("SENSITIVE_CAPTURE_DATA_12345")
            path = Path(f.name)

        success = secure_delete_file(path)

        assert success is True
        assert not path.exists()

    def test_returns_true_for_nonexistent_file(self):
        """Verify already-deleted files return True (idempotent)."""
        path = Path("/tmp/nonexistent_aerog_file.pcap")
        assert not path.exists()

        success = secure_delete_file(path)

        assert success is True

    def test_overwrites_content_before_deletion(self):
        """
        Verify the file content is zero-filled before unlinking.
        We test this by intercepting the write before the unlink.
        """
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".pcap") as f:
            original_data = b"SECRET_PACKET_DATA_XYZ"
            f.write(original_data)
            path = Path(f.name)

        # Patch unlink to check content before actual deletion
        original_unlink = Path.unlink
        content_at_unlink = None

        def spy_unlink(self_path, *args, **kwargs):
            nonlocal content_at_unlink
            with open(self_path, "rb") as check:
                content_at_unlink = check.read()
            original_unlink(self_path, *args, **kwargs)

        with patch.object(Path, "unlink", spy_unlink):
            secure_delete_file(path)

        # Content should be all zeros at the time of deletion
        assert content_at_unlink is not None
        assert original_data not in content_at_unlink
        assert content_at_unlink == b"\x00" * len(original_data)

    def test_handles_empty_file(self):
        """Verify zero-byte files are deleted without error."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
            path = Path(f.name)

        assert path.stat().st_size == 0

        success = secure_delete_file(path)

        assert success is True
        assert not path.exists()


class TestRunStartupJanitor:
    """Tests for run_startup_janitor()."""

    def test_cleans_residual_files(self):
        """Verify janitor deletes all target files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "old_capture.pcap").write_text("data1")
            (Path(tmpdir) / "old_meta.json").write_text("data2")

            result = run_startup_janitor(temp_dir=tmpdir)

            assert result["deleted_count"] == 2
            assert result["failed_count"] == 0
            assert result["files_found"] == 2

    def test_empty_directory_no_errors(self):
        """Verify janitor handles empty directories gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_startup_janitor(temp_dir=tmpdir)

            assert result["deleted_count"] == 0
            assert result["failed_count"] == 0
            assert result["files_found"] == 0
            assert isinstance(result["log"], str)
            assert isinstance(result["timestamp"], str)

    def test_result_contains_required_keys(self):
        """Verify the result dict has all expected keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_startup_janitor(temp_dir=tmpdir)

            assert "deleted_count" in result
            assert "failed_count" in result
            assert "files_found" in result
            assert "log" in result
            assert "timestamp" in result

    def test_uses_default_temp_dir_when_none(self):
        """Verify janitor uses the platform default when no dir specified."""
        # Should not crash even if the default dir doesn't exist yet
        result = run_startup_janitor()

        assert isinstance(result, dict)
        assert "deleted_count" in result


class TestGetAerosguardTempDir:
    """Tests for get_aerosguard_temp_dir()."""

    def test_returns_path_object(self):
        """Verify the return type is a Path."""
        result = get_aerosguard_temp_dir()
        assert isinstance(result, Path)

    def test_path_contains_aerosguard(self):
        """Verify the returned path includes the aerosguard directory name."""
        result = get_aerosguard_temp_dir()
        assert "aerosguard" in str(result).lower() or "aerog" in str(result).lower()
