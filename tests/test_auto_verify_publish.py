import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.auto_verify_publish import (
    load_status_payload,
    parse_generated_at_utc,
    should_block_publish,
    validate_status_payload_consistency,
    validate_status_payload_schema,
)
from scripts.network_status_agent import _status_fingerprint


def _base_status_payload() -> dict:
    payload = {
        "generated_at_utc": datetime(2026, 2, 24, 15, 0, 0, tzinfo=timezone.utc).isoformat(),
        "mode": "network-status-agent",
        "protocol_name": "Distributed Proof-of-Useful-Inference Network",
        "protocol_id": "dpuin-protocol",
        "status_ok": True,
        "health_level": "OK",
        "status_reasons": [],
        "launch_error": "",
        "qa_error": "",
        "advisories": [],
        "recommended_actions": [],
        "production_checks": False,
        "network_size_nodes": 5,
        "avg_winner_latency_ms": 45.6,
        "requests_executed": 5,
        "preflight_checks": {
            "security_scan_passed": True,
            "economic_invariant_passed": True,
            "consensus_quorum_passed": True,
            "key_management_passed": True,
            "stress_test_passed": True,
            "account_registry_passed": True,
        },
        "production_readiness": {
            "ready": False,
            "checks": {
                "security_scan_passed": True,
                "economic_invariant_passed": True,
                "consensus_quorum_passed": True,
                "key_management_passed": False,
                "stress_test_passed": True,
                "account_registry_passed": False,
            },
        },
        "qa_overall_passed": True,
        "qa_agent_count": 5,
        "launch_state": {
            "owner_id": "owner-dev-local",
            "armed": False,
            "unstoppable_started": False,
            "successful_open": False,
            "started_by_runner": "",
            "started_at_utc": "",
            "last_runner_id": "",
            "last_run_at_utc": "",
            "total_runs": 0,
            "start_attempts": 0,
        },
        "snapshot": {
            "epoch": 5,
            "model_version": "llm-shard-v1.0",
            "minted_supply": "4807425.3741",
            "max_supply": "10000000.0000",
            "balances": {},
            "launch_gate": {},
            "mainnet_open": True,
            "slash_points": {},
            "ledger_entries": 5,
            "owner_id": "owner-dev-local",
            "wallets_redacted": {},
            "account_registry_ready": False,
            "connection_configured": False,
        },
        "top_node_balances": [],
        "history_chain": {"tracked_entries": 1, "legacy_entries": 0, "valid": True},
    }
    payload["status_fingerprint"] = _status_fingerprint(payload)
    payload["history_chain"]["latest_hash"] = payload["status_fingerprint"]
    return payload


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

    def test_validate_status_payload_schema_invalid_history_latest_hash(self) -> None:
        payload = _base_status_payload()
        payload["history_chain"]["latest_hash"] = "not-a-hash"
        ok, reason = validate_status_payload_schema(payload)
        self.assertFalse(ok)
        self.assertIn("latest_hash", reason)

    def test_validate_status_payload_consistency_ok(self) -> None:
        ok, reason = validate_status_payload_consistency(_base_status_payload())
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_validate_status_payload_consistency_fingerprint_mismatch(self) -> None:
        payload = _base_status_payload()
        payload["status_fingerprint"] = "f" * 64
        ok, reason = validate_status_payload_consistency(payload)
        self.assertFalse(ok)
        self.assertIn("status_fingerprint mismatch", reason)

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
            "legacy_entries": 0,
            "valid": False,
            "broken_index": 2,
            "broken_reason": "history_hash verification failed",
            "latest_hash": "a" * 64,
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

    def test_should_block_when_history_chain_has_legacy_entries(self) -> None:
        payload = _base_status_payload()
        payload["history_chain"]["tracked_entries"] = 4
        payload["history_chain"]["legacy_entries"] = 2
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=False,
            now_utc=datetime(2026, 2, 24, 15, 0, 30, tzinfo=timezone.utc),
        )
        self.assertTrue(blocked)
        self.assertIn("legacy history entries", reason)

    def test_should_block_when_history_latest_hash_invalid(self) -> None:
        payload = _base_status_payload()
        payload["history_chain"]["tracked_entries"] = 3
        payload["history_chain"]["latest_hash"] = "123"
        blocked, reason = should_block_publish(
            status_payload=payload,
            production_checks=True,
            allow_failing_status=False,
            now_utc=datetime(2026, 2, 24, 15, 0, 30, tzinfo=timezone.utc),
        )
        self.assertTrue(blocked)
        self.assertIn("latest_hash", reason)

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
        payload["history_chain"] = {"tracked_entries": 2, "legacy_entries": 0, "valid": False, "latest_hash": "a" * 64}
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
        payload["status_fingerprint"] = _status_fingerprint(payload)
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
        payload["status_fingerprint"] = _status_fingerprint(payload)
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
        payload["status_fingerprint"] = _status_fingerprint(payload)
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
