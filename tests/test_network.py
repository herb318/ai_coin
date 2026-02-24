import os
import tempfile
import unittest
from unittest.mock import patch

from decentralized_ai_network_demo import (
    IdentityRegistry,
    TranslationNetwork,
    UnstoppableLaunchSentinel,
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
            "NETWORK_SHARED_SECRET": "this_is_a_minimum_32_bytes_secret_value_123456",
            "PRIVATE_RPC_URL": "https://private.rpc.local",
            "PRIVATE_API_TOKEN": "private_token_local_value",
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


class TestSecurity(unittest.TestCase):
    def test_replay_attack_is_blocked(self) -> None:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=False)
        net.open_mainnet()

        env = net.security.build_envelope("replay-test", "node-sea-1", "안녕하세요, 회의에 참석해 주셔서 감사합니다.")
        net.process_request(env)

        with self.assertRaises(ValueError):
            net.process_request(env)


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

    def test_owner_can_pause_and_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = os.path.join(tmp_dir, "launch_state.json")
            sentinel = UnstoppableLaunchSentinel(state_path=state_path, owner_id="owner-main")
            paused = sentinel.pause("owner-main", "maintenance")
            self.assertTrue(paused["paused"])
            self.assertEqual(paused["pause_reason"], "maintenance")

            resumed = sentinel.resume("owner-main")
            self.assertFalse(resumed["paused"])
            self.assertEqual(resumed["pause_reason"], "")

    def test_non_owner_cannot_pause_or_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = os.path.join(tmp_dir, "launch_state.json")
            sentinel = UnstoppableLaunchSentinel(state_path=state_path, owner_id="owner-main")
            with self.assertRaises(PermissionError):
                sentinel.pause("intruder", "bad")
            with self.assertRaises(PermissionError):
                sentinel.resume("intruder")


if __name__ == "__main__":
    unittest.main()
