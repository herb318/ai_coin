import json
import os
import tempfile
import unittest
from unittest.mock import patch

from decentralized_ai_network_demo import (
    IdentityRegistry,
    RequestSecurity,
    TranslationNetwork,
    UnstoppableLaunchSentinel,
    now_ts,
    run_qa_team_suite,
)


class TestIdentityRegistry(unittest.TestCase):
    def test_duplicate_wallet_rejected(self) -> None:
        with self.assertRaises(ValueError):
            IdentityRegistry.from_mapping(
                owner_id="owner-1",
                wallets={
                    "node-sea-1": "dup-wallet",
                    "node-tyo-2": "dup-wallet",
                },
            )


class TestRequestSecurityConfig(unittest.TestCase):
    def test_rejects_non_positive_skew(self) -> None:
        with self.assertRaises(ValueError):
            RequestSecurity(b"x" * 32, max_skew_seconds=0)

    def test_rejects_excessive_skew(self) -> None:
        with self.assertRaises(ValueError):
            RequestSecurity(b"x" * 32, max_skew_seconds=3601)

    def test_rejects_non_positive_rate_limit(self) -> None:
        with self.assertRaises(ValueError):
            RequestSecurity(b"x" * 32, max_requests_per_minute=0)

    def test_rejects_excessive_rate_limit(self) -> None:
        with self.assertRaises(ValueError):
            RequestSecurity(b"x" * 32, max_requests_per_minute=10001)

    def test_rejects_non_positive_seen_entries(self) -> None:
        with self.assertRaises(ValueError):
            RequestSecurity(b"x" * 32, max_seen_entries=0)


class TestLaunchGate(unittest.TestCase):
    def test_open_is_blocked_when_security_scan_fails(self) -> None:
        net = TranslationNetwork()
        checks = net.run_preflight_checks(security_scan_passed=False, production_mode=False)
        self.assertFalse(checks["security_scan_passed"])
        with self.assertRaises(RuntimeError):
            net.open_mainnet()

    def test_production_checks_pass_with_manual_env(self) -> None:
        env = {
            "OWNER_ID": "owner-prod-1",
            "NETWORK_SHARED_SECRET": "A9x#4mB2qL7zT1vK8nR3pW6yH0dC5fJ!",
            "PRIVATE_RPC_URL": "https://private.rpc.local",
            "PRIVATE_API_TOKEN": "Priv_token_local_value_123",
            "WALLET_NODE_SEA_1": "wallet_node_sea_1_unique",
            "WALLET_NODE_TYO_2": "wallet_node_tyo_2_unique",
            "WALLET_NODE_SGP_3": "wallet_node_sgp_3_unique",
            "WALLET_NODE_FRA_4": "wallet_node_fra_4_unique",
            "WALLET_NODE_IAD_5": "wallet_node_iad_5_unique",
            "WALLET_FOUNDER_TREASURY": "wallet_founder_treasury_unique",
            "WALLET_ECOSYSTEM_TREASURY": "wallet_ecosystem_treasury_unique",
            "WALLET_SECURITY_TREASURY": "wallet_security_treasury_unique",
            "WALLET_COMMUNITY_TREASURY": "wallet_community_treasury_unique",
        }
        with patch.dict(os.environ, env, clear=False):
            net = TranslationNetwork()
            checks = net.run_preflight_checks(security_scan_passed=True, production_mode=True)
            self.assertTrue(all(checks.values()))
            net.open_mainnet()
            self.assertTrue(net.launch_gate.opened)

    def test_production_checks_fail_with_placeholder_values(self) -> None:
        env = {
            "OWNER_ID": "CHANGE_ME_OWNER_ID",
            "NETWORK_SHARED_SECRET": "CHANGE_ME_WITH_MINIMUM_32_CHAR_SECRET_VALUE",
            "PRIVATE_RPC_URL": "https://change-me-private-rpc.example",
            "PRIVATE_API_TOKEN": "CHANGE_ME_PRIVATE_API_TOKEN",
            "WALLET_NODE_SEA_1": "change_me_wallet_node_sea_1_unique",
            "WALLET_NODE_TYO_2": "change_me_wallet_node_tyo_2_unique",
            "WALLET_NODE_SGP_3": "change_me_wallet_node_sgp_3_unique",
            "WALLET_NODE_FRA_4": "change_me_wallet_node_fra_4_unique",
            "WALLET_NODE_IAD_5": "change_me_wallet_node_iad_5_unique",
            "WALLET_FOUNDER_TREASURY": "change_me_wallet_founder_treasury_unique",
            "WALLET_ECOSYSTEM_TREASURY": "change_me_wallet_ecosystem_treasury_unique",
            "WALLET_SECURITY_TREASURY": "change_me_wallet_security_treasury_unique",
            "WALLET_COMMUNITY_TREASURY": "change_me_wallet_community_treasury_unique",
        }
        with patch.dict(os.environ, env, clear=False):
            net = TranslationNetwork()
            checks = net.run_preflight_checks(security_scan_passed=True, production_mode=True)
            self.assertFalse(checks["account_registry_passed"])
            with self.assertRaises(RuntimeError):
                net.open_mainnet()

    def test_production_checks_fail_with_weak_shared_secret(self) -> None:
        env = {
            "OWNER_ID": "owner-prod-1",
            "NETWORK_SHARED_SECRET": "secretsecretsecretsecretsecretsecret12",
            "PRIVATE_RPC_URL": "https://private.rpc.local",
            "PRIVATE_API_TOKEN": "Priv_token_local_value_123",
            "WALLET_NODE_SEA_1": "wallet_node_sea_1_unique",
            "WALLET_NODE_TYO_2": "wallet_node_tyo_2_unique",
            "WALLET_NODE_SGP_3": "wallet_node_sgp_3_unique",
            "WALLET_NODE_FRA_4": "wallet_node_fra_4_unique",
            "WALLET_NODE_IAD_5": "wallet_node_iad_5_unique",
            "WALLET_FOUNDER_TREASURY": "wallet_founder_treasury_unique",
            "WALLET_ECOSYSTEM_TREASURY": "wallet_ecosystem_treasury_unique",
            "WALLET_SECURITY_TREASURY": "wallet_security_treasury_unique",
            "WALLET_COMMUNITY_TREASURY": "wallet_community_treasury_unique",
        }
        with patch.dict(os.environ, env, clear=False):
            net = TranslationNetwork()
            checks = net.run_preflight_checks(security_scan_passed=True, production_mode=True)
            self.assertFalse(checks["key_management_passed"])
            with self.assertRaises(RuntimeError):
                net.open_mainnet()

    def test_production_checks_fail_with_insecure_rpc_url(self) -> None:
        env = {
            "OWNER_ID": "owner-prod-1",
            "NETWORK_SHARED_SECRET": "A9x#4mB2qL7zT1vK8nR3pW6yH0dC5fJ!",
            "PRIVATE_RPC_URL": "http://private.rpc.local",
            "PRIVATE_API_TOKEN": "Priv_token_local_value_123",
            "WALLET_NODE_SEA_1": "wallet_node_sea_1_unique",
            "WALLET_NODE_TYO_2": "wallet_node_tyo_2_unique",
            "WALLET_NODE_SGP_3": "wallet_node_sgp_3_unique",
            "WALLET_NODE_FRA_4": "wallet_node_fra_4_unique",
            "WALLET_NODE_IAD_5": "wallet_node_iad_5_unique",
            "WALLET_FOUNDER_TREASURY": "wallet_founder_treasury_unique",
            "WALLET_ECOSYSTEM_TREASURY": "wallet_ecosystem_treasury_unique",
            "WALLET_SECURITY_TREASURY": "wallet_security_treasury_unique",
            "WALLET_COMMUNITY_TREASURY": "wallet_community_treasury_unique",
        }
        with patch.dict(os.environ, env, clear=False):
            net = TranslationNetwork()
            checks = net.run_preflight_checks(security_scan_passed=True, production_mode=True)
            self.assertFalse(checks["account_registry_passed"])
            with self.assertRaises(RuntimeError):
                net.open_mainnet()


class TestSecurity(unittest.TestCase):
    def test_replay_attack_is_blocked(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        env = net.security.build_envelope("replay-test", "node-sea-1", "안녕하세요, 회의에 참석해 주셔서 감사합니다.")
        net.process_request(env)

        with self.assertRaises(ValueError):
            net.process_request(env)

    def test_unknown_node_is_blocked(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        env = net.security.build_envelope("unknown-node-test", "node-evil-9", "안녕하세요, 회의에 참석해 주셔서 감사합니다.")
        with self.assertRaisesRegex(ValueError, "unknown node_id"):
            net.process_request(env)
        self.assertEqual(net.slash_points[TranslationNetwork.INVALID_SENDER_SLASH_KEY], 1)
        self.assertNotIn("node-evil-9", net.slash_points)

    def test_invalid_node_type_is_bucketed_under_invalid_sender_slash(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        env = net.security.build_envelope("invalid-node-type", "node-sea-1", "안녕하세요, 회의에 참석해 주셔서 감사합니다.")
        env["node_id"] = {"unexpected": "object"}
        with self.assertRaisesRegex(ValueError, "invalid node_id type"):
            net.process_request(env)
        self.assertEqual(net.slash_points[TranslationNetwork.INVALID_SENDER_SLASH_KEY], 1)

    def test_invalid_nonce_format_is_blocked(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        env = net.security.build_envelope("nonce-format-test", "node-sea-1", "질문이 있으면 언제든지 말씀해 주세요.")
        env["nonce"] = "nonce-not-hex"
        env["signature"] = net.security.sign(
            {
                "request_id": env["request_id"],
                "node_id": env["node_id"],
                "source_text": env["source_text"],
                "nonce": env["nonce"],
                "timestamp": env["timestamp"],
            }
        )
        with self.assertRaisesRegex(ValueError, "invalid nonce"):
            net.process_request(env)

    def test_unexpected_envelope_field_is_blocked(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        env = net.security.build_envelope("unexpected-field", "node-sea-1", "안녕하세요, 회의에 참석해 주셔서 감사합니다.")
        env["debug"] = "not-allowed"
        with self.assertRaisesRegex(ValueError, "unexpected field"):
            net.process_request(env)

    def test_boolean_timestamp_is_blocked(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        env = net.security.build_envelope("bool-ts", "node-sea-1", "질문이 있으면 언제든지 말씀해 주세요.")
        env["timestamp"] = True
        env["signature"] = net.security.sign(
            {
                "request_id": env["request_id"],
                "node_id": env["node_id"],
                "source_text": env["source_text"],
                "nonce": env["nonce"],
                "timestamp": env["timestamp"],
            }
        )
        with self.assertRaisesRegex(ValueError, "invalid timestamp type"):
            net.process_request(env)

    def test_oversized_payload_is_blocked(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        env = net.security.build_envelope("oversized-source", "node-sea-1", "a" * 5000)
        env["signature"] = net.security.sign(
            {
                "request_id": env["request_id"],
                "node_id": env["node_id"],
                "source_text": env["source_text"],
                "nonce": env["nonce"],
                "timestamp": env["timestamp"],
            }
        )
        with self.assertRaisesRegex(ValueError, "source_text too large"):
            net.process_request(env)

    def test_source_text_with_control_chars_is_blocked(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        env = net.security.build_envelope("control-char-source", "node-sea-1", "hello\x00world")
        with self.assertRaisesRegex(ValueError, "invalid source_text control chars"):
            net.process_request(env)

    def test_duplicate_request_id_is_blocked(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        first = net.security.build_envelope("dup-request-id", "node-sea-1", "안녕하세요, 회의에 참석해 주셔서 감사합니다.")
        second = net.security.build_envelope("dup-request-id", "node-sea-1", "안녕하세요, 회의에 참석해 주셔서 감사합니다.")
        net.process_request(first)
        with self.assertRaisesRegex(ValueError, "duplicate request_id"):
            net.process_request(second)

    def test_duplicate_request_id_across_nodes_is_blocked(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        first = net.security.build_envelope("dup-request-id-global", "node-sea-1", "안녕하세요, 회의에 참석해 주셔서 감사합니다.")
        second = net.security.build_envelope("dup-request-id-global", "node-tyo-2", "질문이 있으면 언제든지 말씀해 주세요.")
        net.process_request(first)
        with self.assertRaisesRegex(ValueError, "duplicate request_id"):
            net.process_request(second)

    def test_invalid_request_id_format_is_blocked(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        env = net.security.build_envelope("bad request id", "node-sea-1", "질문이 있으면 언제든지 말씀해 주세요.")
        with self.assertRaisesRegex(ValueError, "invalid request_id format"):
            net.process_request(env)

    def test_duplicate_request_id_is_blocked_after_security_cache_eviction(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()
        net.security.max_seen_entries = 1

        first = net.security.build_envelope(
            "dup-request-id-persistent",
            "node-sea-1",
            "안녕하세요, 회의에 참석해 주셔서 감사합니다.",
        )
        filler = net.security.build_envelope(
            "dup-request-id-filler",
            "node-tyo-2",
            "질문이 있으면 언제든지 말씀해 주세요.",
        )
        net.process_request(first)
        net.process_request(filler)

        replay = net.security.build_envelope(
            "dup-request-id-persistent",
            "node-sgp-3",
            "오늘 일정은 실시간 번역 네트워크 데모입니다.",
        )
        with self.assertRaisesRegex(ValueError, "duplicate request_id"):
            net.process_request(replay)

    def test_duplicate_request_id_with_whitespace_is_blocked_after_cache_eviction(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()
        net.security.max_seen_entries = 1

        first = net.security.build_envelope(
            "dup-request-id-space",
            "node-sea-1",
            "안녕하세요, 회의에 참석해 주셔서 감사합니다.",
        )
        filler = net.security.build_envelope(
            "dup-request-id-space-filler",
            "node-tyo-2",
            "질문이 있으면 언제든지 말씀해 주세요.",
        )
        net.process_request(first)
        net.process_request(filler)

        replay = net.security.build_envelope(
            "  dup-request-id-space  ",
            "node-sgp-3",
            "오늘 일정은 실시간 번역 네트워크 데모입니다.",
        )
        with self.assertRaisesRegex(ValueError, "duplicate request_id"):
            net.process_request(replay)

    def test_source_text_is_trimmed_after_verification(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        env = net.security.build_envelope(
            "source-text-trim-test",
            "node-sea-1",
            "  안녕하세요, 회의에 참석해 주셔서 감사합니다.  ",
        )
        out = net.process_request(env)
        self.assertEqual(out["final_output"], "Hello, thank you for joining the meeting.")

    def test_stale_timestamp_is_blocked(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        env = net.security.build_envelope("stale-timestamp", "node-sea-1", "질문이 있으면 언제든지 말씀해 주세요.")
        env["timestamp"] = now_ts() - (net.security.max_skew_seconds + 5)
        env["signature"] = net.security.sign(
            {
                "request_id": env["request_id"],
                "node_id": env["node_id"],
                "source_text": env["source_text"],
                "nonce": env["nonce"],
                "timestamp": env["timestamp"],
            }
        )
        with self.assertRaisesRegex(ValueError, "timestamp outside allowed clock skew"):
            net.process_request(env)

    def test_rate_limit_is_enforced(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        for idx in range(net.security.max_requests_per_minute):
            env = net.security.build_envelope(
                f"rate-ok-{idx}",
                "node-sea-1",
                "안녕하세요, 회의에 참석해 주셔서 감사합니다.",
            )
            net.process_request(env)

        overflow = net.security.build_envelope(
            "rate-overflow",
            "node-sea-1",
            "안녕하세요, 회의에 참석해 주셔서 감사합니다.",
        )
        with self.assertRaisesRegex(ValueError, "rate limit exceeded"):
            net.process_request(overflow)


class TestQATeam(unittest.TestCase):
    def test_qa_team_suite_passes(self) -> None:
        report = run_qa_team_suite(production_mode=False)
        self.assertTrue(report["overall_passed"])
        self.assertEqual(len(report["agents"]), 5)


class TestUnstoppableLaunchSentinel(unittest.TestCase):
    def test_non_owner_execution_triggers_unstoppable_start_once_armed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = os.path.join(tmp_dir, "launch_state.json")
            sentinel = UnstoppableLaunchSentinel(state_path=state_path, owner_id="owner-main")
            sentinel.arm("owner-main")

            before = sentinel.record_execution("owner-main")
            self.assertFalse(before["unstoppable_started"])
            self.assertTrue(before["armed"])

            after = sentinel.record_execution("runner-other")
            self.assertTrue(after["unstoppable_started"])
            self.assertEqual(after["started_by_runner"], "runner-other")

            reload_sentinel = UnstoppableLaunchSentinel(state_path=state_path, owner_id="owner-main")
            persisted = reload_sentinel.snapshot()
            self.assertTrue(persisted["unstoppable_started"])
            self.assertEqual(persisted["started_by_runner"], "runner-other")

    def test_only_owner_can_arm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = os.path.join(tmp_dir, "launch_state.json")
            sentinel = UnstoppableLaunchSentinel(state_path=state_path, owner_id="owner-main")
            with self.assertRaises(PermissionError):
                sentinel.arm("intruder")

    def test_owner_mismatch_resets_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = os.path.join(tmp_dir, "launch_state.json")
            original = UnstoppableLaunchSentinel(state_path=state_path, owner_id="owner-main")
            original.arm("owner-main")
            original.record_execution("runner-other")

            replaced = UnstoppableLaunchSentinel(state_path=state_path, owner_id="owner-new")
            snapshot = replaced.snapshot()
            self.assertEqual(snapshot["owner_id"], "owner-new")
            self.assertFalse(snapshot["armed"])
            self.assertFalse(snapshot["unstoppable_started"])
            self.assertEqual(snapshot["total_runs"], 0)
            self.assertEqual(snapshot["start_attempts"], 0)

    def test_malformed_state_values_reset_to_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = os.path.join(tmp_dir, "launch_state.json")
            malformed = {
                "owner_id": "owner-main",
                "armed": True,
                "unstoppable_started": True,
                "successful_open": True,
                "started_by_runner": "runner-x",
                "started_at_utc": "2026-02-24T00:00:00+00:00",
                "last_runner_id": "runner-x",
                "last_run_at_utc": "2026-02-24T00:00:00+00:00",
                "total_runs": "not-an-int",
                "start_attempts": "not-an-int",
            }
            with open(state_path, "w", encoding="utf-8") as handle:
                json.dump(malformed, handle)

            sentinel = UnstoppableLaunchSentinel(state_path=state_path, owner_id="owner-main")
            snapshot = sentinel.snapshot()
            self.assertEqual(snapshot["owner_id"], "owner-main")
            self.assertFalse(snapshot["armed"])
            self.assertFalse(snapshot["unstoppable_started"])
            self.assertFalse(snapshot["successful_open"])
            self.assertEqual(snapshot["total_runs"], 0)
            self.assertEqual(snapshot["start_attempts"], 0)


if __name__ == "__main__":
    unittest.main()
