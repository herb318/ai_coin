import json
import tempfile
import unittest
from pathlib import Path

from scripts.auto_verify_publish import load_status_payload, should_block_publish


class TestAutoVerifyPublish(unittest.TestCase):
    def test_should_not_block_when_production_checks_disabled(self) -> None:
        blocked, reason = should_block_publish(
            status_payload={"status_ok": False, "health_level": "DEGRADED", "status_reasons": ["qa_failed"]},
            production_checks=False,
            allow_failing_status=False,
        )
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_should_block_when_status_is_degraded(self) -> None:
        blocked, reason = should_block_publish(
            status_payload={
                "status_ok": False,
                "health_level": "DEGRADED",
                "status_reasons": ["preflight:key_management_passed"],
            },
            production_checks=True,
            allow_failing_status=False,
        )
        self.assertTrue(blocked)
        self.assertIn("degraded", reason)
        self.assertIn("preflight:key_management_passed", reason)

    def test_should_not_block_when_allow_failing_status_enabled(self) -> None:
        blocked, reason = should_block_publish(
            status_payload={"status_ok": False, "health_level": "DEGRADED", "status_reasons": ["qa_failed"]},
            production_checks=True,
            allow_failing_status=True,
        )
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_should_not_block_when_status_ok(self) -> None:
        blocked, reason = should_block_publish(
            status_payload={"status_ok": True, "health_level": "OK", "status_reasons": []},
            production_checks=True,
            allow_failing_status=False,
        )
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_should_not_block_warn_by_default(self) -> None:
        blocked, reason = should_block_publish(
            status_payload={"status_ok": True, "health_level": "WARN", "advisories": ["production_readiness_false"]},
            production_checks=True,
            allow_failing_status=False,
            fail_on_warn=False,
        )
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_should_block_warn_when_fail_on_warn_enabled(self) -> None:
        blocked, reason = should_block_publish(
            status_payload={"status_ok": True, "health_level": "WARN", "advisories": ["production_readiness_false"]},
            production_checks=True,
            allow_failing_status=False,
            fail_on_warn=True,
        )
        self.assertTrue(blocked)
        self.assertIn("WARN", reason)
        self.assertIn("production_readiness_false", reason)

    def test_load_status_payload_reads_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "NETWORK_STATUS.json"
            path.write_text(json.dumps({"status_ok": True}), encoding="utf-8")
            payload = load_status_payload(path)
        self.assertEqual(payload["status_ok"], True)

    def test_load_status_payload_raises_on_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "missing.json"
            with self.assertRaises(RuntimeError):
                load_status_payload(path)

    def test_load_status_payload_raises_on_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "NETWORK_STATUS.json"
            path.write_text("{invalid-json", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                load_status_payload(path)


if __name__ == "__main__":
    unittest.main()
