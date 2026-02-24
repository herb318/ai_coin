import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.auto_verify_publish import (
    load_status_payload,
    parse_generated_at_utc,
    should_block_publish,
    validate_status_payload_schema,
)


def _base_status_payload() -> dict:
    return {
        "generated_at_utc": datetime(2026, 2, 24, 15, 0, 0, tzinfo=timezone.utc).isoformat(),
        "mode": "network-status-agent",
        "protocol_id": "dpuin-protocol",
        "status_ok": True,
        "health_level": "OK",
        "status_reasons": [],
        "network_size_nodes": 5,
        "avg_winner_latency_ms": 45.6,
        "requests_executed": 5,
        "qa_overall_passed": True,
        "qa_agent_count": 5,
        "status_fingerprint": "a" * 64,
        "history_chain": {"tracked_entries": 1, "valid": True},
    }


class TestAutoVerifyPublish(unittest.TestCase):
    def test_validate_status_payload_schema_ok(self) -> None:
        ok, reason = validate_status_payload_schema(_base_status_payload())
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_validate_status_payload_schema_invalid_health(self) -> None:
        payload = _base_status_payload()
        payload["health_level"] = "UNKNOWN"
        ok, reason = validate_status_payload_schema(payload)
        self.assertFalse(ok)
        self.assertIn("health_level", reason)

    def test_parse_generated_at_utc_accepts_zulu(self) -> None:
        parsed = parse_generated_at_utc("2026-02-24T15:00:00Z")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed, datetime(2026, 2, 24, 15, 0, 0, tzinfo=timezone.utc))

    def test_should_block_when_generated_timestamp_missing(self) -> None:
        payload = _base_status_payload()
        payload.pop("generated_at_utc", None)
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=False,
        )
        self.assertTrue(blocked)
        self.assertIn("generated_at_utc", reason)

    def test_should_block_when_status_is_stale(self) -> None:
        payload = _base_status_payload()
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=False,
            max_status_age_seconds=60,
            now_utc=datetime(2026, 2, 24, 15, 5, 0, tzinfo=timezone.utc),
        )
        self.assertTrue(blocked)
        self.assertIn("stale", reason)

    def test_should_not_block_when_status_is_fresh(self) -> None:
        payload = _base_status_payload()
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=False,
            max_status_age_seconds=600,
            now_utc=datetime(2026, 2, 24, 15, 5, 0, tzinfo=timezone.utc),
        )
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_should_block_when_history_chain_invalid(self) -> None:
        payload = _base_status_payload()
        payload["history_chain"] = {
            "tracked_entries": 3,
            "valid": False,
            "broken_index": 2,
            "broken_reason": "history_hash verification failed",
            "latest_hash": "abc",
        }
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=False,
            now_utc=datetime(2026, 2, 24, 15, 0, 30, tzinfo=timezone.utc),
        )
        self.assertTrue(blocked)
        self.assertIn("history chain integrity", reason)
        self.assertIn("broken index", reason.lower())

    def test_should_block_when_schema_invalid(self) -> None:
        payload = _base_status_payload()
        payload["protocol_id"] = "invalid-protocol"
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=False,
            now_utc=datetime(2026, 2, 24, 15, 0, 30, tzinfo=timezone.utc),
        )
        self.assertTrue(blocked)
        self.assertIn("schema validation failed", reason.lower())

    def test_should_block_when_negative_requests(self) -> None:
        payload = _base_status_payload()
        payload["requests_executed"] = -1
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=False,
            now_utc=datetime(2026, 2, 24, 15, 0, 30, tzinfo=timezone.utc),
        )
        self.assertTrue(blocked)
        self.assertIn("requests_executed", reason)

    def test_should_not_block_when_production_checks_disabled(self) -> None:
        blocked, reason = should_block_publish(
            status_payload={"status_ok": False, "health_level": "DEGRADED", "status_reasons": ["qa_failed"]},
            production_checks=False,
            allow_failing_status=False,
        )
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_should_not_block_invalid_history_when_allow_failing(self) -> None:
        payload = _base_status_payload()
        payload["history_chain"] = {"tracked_entries": 2, "valid": False}
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=True,
        )
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_should_block_when_status_is_degraded(self) -> None:
        payload = _base_status_payload()
        payload.update(
            {
                "status_ok": False,
                "health_level": "DEGRADED",
                "status_reasons": ["preflight:key_management_passed"],
                "recommended_actions": ["Set NETWORK_SHARED_SECRET and retry."],
            }
        )
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=False,
            now_utc=datetime(2026, 2, 24, 15, 0, 30, tzinfo=timezone.utc),
        )
        self.assertTrue(blocked)
        self.assertIn("degraded", reason)
        self.assertIn("preflight:key_management_passed", reason)
        self.assertIn("NETWORK_SHARED_SECRET", reason)

    def test_should_not_block_when_allow_failing_status_enabled(self) -> None:
        payload = _base_status_payload()
        payload.update({"status_ok": False, "health_level": "DEGRADED", "status_reasons": ["qa_failed"]})
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=True,
        )
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_should_not_block_when_status_ok(self) -> None:
        payload = _base_status_payload()
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=False,
            now_utc=datetime(2026, 2, 24, 15, 0, 30, tzinfo=timezone.utc),
        )
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_should_not_block_warn_by_default(self) -> None:
        payload = _base_status_payload()
        payload.update({"health_level": "WARN", "advisories": ["production_readiness_false"]})
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=False,
            fail_on_warn=False,
            now_utc=datetime(2026, 2, 24, 15, 0, 30, tzinfo=timezone.utc),
        )
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_should_block_warn_when_fail_on_warn_enabled(self) -> None:
        payload = _base_status_payload()
        payload.update(
            {
                "health_level": "WARN",
                "advisories": ["production_readiness_false"],
                "recommended_actions": ["Run status agent with --production-checks."],
            }
        )
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=False,
            fail_on_warn=True,
            now_utc=datetime(2026, 2, 24, 15, 0, 30, tzinfo=timezone.utc),
        )
        self.assertTrue(blocked)
        self.assertIn("WARN", reason)
        self.assertIn("production_readiness_false", reason)
        self.assertIn("--production-checks", reason)

    def test_load_status_payload_reads_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "NETWORK_STATUS.json"
            path.write_text(json.dumps({"status_ok": True, "health_level": "OK"}), encoding="utf-8")
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
