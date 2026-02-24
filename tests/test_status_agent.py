import os
import tempfile
import unittest
from unittest.mock import patch

from scripts.network_status_agent import build_status_payload


def _production_env() -> dict[str, str]:
    return {
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


class TestStatusAgent(unittest.TestCase):
    def test_non_production_payload_is_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = os.path.join(tmp_dir, "launch_state.json")
            with patch.dict(os.environ, {}, clear=True):
                payload = build_status_payload(production_checks=False, launch_state_path=state_path)

        self.assertTrue(payload["status_ok"])
        self.assertEqual(payload["status_reasons"], [])
        self.assertIn("production_readiness", payload)
        self.assertFalse(payload["production_readiness"]["ready"])
        self.assertIn("production_readiness_false", payload["advisories"])
        self.assertTrue(payload["qa_overall_passed"])
        self.assertGreater(payload["requests_executed"], 0)
        self.assertEqual(payload["launch_error"], "")
        self.assertEqual(payload["qa_error"], "")

    def test_production_payload_is_degraded_without_required_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = os.path.join(tmp_dir, "launch_state.json")
            with patch.dict(os.environ, {}, clear=True):
                payload = build_status_payload(production_checks=True, launch_state_path=state_path)

        self.assertFalse(payload["status_ok"])
        self.assertIn("preflight:key_management_passed", payload["status_reasons"])
        self.assertIn("preflight:account_registry_passed", payload["status_reasons"])
        self.assertFalse(payload["production_readiness"]["ready"])
        self.assertEqual(payload["advisories"], [])
        self.assertTrue(str(payload["launch_error"]).startswith("Launch blocked"))
        self.assertFalse(payload["qa_overall_passed"])
        self.assertTrue(payload["qa_error"])
        self.assertEqual(payload["requests_executed"], 0)

    def test_production_payload_is_healthy_with_valid_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = os.path.join(tmp_dir, "launch_state.json")
            with patch.dict(os.environ, _production_env(), clear=True):
                payload = build_status_payload(production_checks=True, launch_state_path=state_path)

        self.assertTrue(payload["status_ok"])
        self.assertTrue(all(payload["preflight_checks"].values()))
        self.assertTrue(payload["production_readiness"]["ready"])
        self.assertEqual(payload["advisories"], [])
        self.assertEqual(payload["launch_error"], "")
        self.assertTrue(payload["qa_overall_passed"])
        self.assertEqual(payload["qa_error"], "")
        self.assertEqual(payload["requests_executed"], 5)


if __name__ == "__main__":
    unittest.main()
