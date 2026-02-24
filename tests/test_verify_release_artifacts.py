import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.verify_release_artifacts import (
    parse_checksum_manifest,
    verify_checksums,
    verify_cosign,
)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class TestVerifyReleaseArtifacts(unittest.TestCase):
    def test_parse_checksum_manifest_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            digest = "a" * 64
            manifest = root / "SHA256SUMS"
            manifest.write_text(f"{digest}  dpuin-linux.zip\n", encoding="utf-8")
            rows = parse_checksum_manifest(manifest)
            self.assertEqual(rows, [(digest, "dpuin-linux.zip")])

    def test_parse_checksum_manifest_invalid_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            manifest = root / "SHA256SUMS"
            manifest.write_text("xyz  dpuin-linux.zip\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                parse_checksum_manifest(manifest)

    def test_verify_checksums_reports_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            artifact = root / "dpuin-linux.zip"
            artifact.write_text("demo", encoding="utf-8")
            manifest = root / "SHA256SUMS"
            manifest.write_text(f"{'b' * 64}  dpuin-linux.zip\n", encoding="utf-8")
            report = verify_checksums(root, "SHA256SUMS")
            self.assertFalse(report["ok"])
            self.assertEqual(report["entry_count"], 1)
            self.assertEqual(len(report["mismatched_files"]), 1)

    def test_verify_checksums_reports_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            artifact = root / "dpuin-linux.zip"
            artifact.write_text("demo", encoding="utf-8")
            digest = _sha256_text("demo")
            manifest = root / "SHA256SUMS"
            manifest.write_text(f"{digest}  dpuin-linux.zip\n", encoding="utf-8")
            report = verify_checksums(root, "SHA256SUMS")
            self.assertTrue(report["ok"])
            self.assertEqual(report["verified_files"], ["dpuin-linux.zip"])

    @patch("scripts.verify_release_artifacts._cosign_available", return_value=False)
    def test_verify_cosign_skips_when_not_required(self, _mock_available) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            report = verify_cosign(
                assets_dir=root,
                files=["dpuin-linux.zip"],
                manifest_name="SHA256SUMS",
                repo="herb318/autonomous-ai-reward-network",
                workflow_path=".github/workflows/cross-platform-release.yml",
                tag_regexp="refs/tags/v.*",
                require_cosign=False,
            )
            self.assertTrue(report["skipped"])
            self.assertFalse(report["cosign_available"])

    @patch("scripts.verify_release_artifacts._cosign_available", return_value=False)
    def test_verify_cosign_fails_when_required(self, _mock_available) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            report = verify_cosign(
                assets_dir=root,
                files=["dpuin-linux.zip"],
                manifest_name="SHA256SUMS",
                repo="herb318/autonomous-ai-reward-network",
                workflow_path=".github/workflows/cross-platform-release.yml",
                tag_regexp="refs/tags/v.*",
                require_cosign=True,
            )
            self.assertFalse(report["skipped"])
            self.assertFalse(report["cosign_available"])
            self.assertIn("dpuin-linux.zip", report["missing_signature_files"])


if __name__ == "__main__":
    unittest.main()
