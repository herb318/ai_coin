import unittest

from scripts.run_operator_loop import _check_demo, _check_qa, parse_json_payload


class TestOperatorLoop(unittest.TestCase):
    def test_parse_json_payload_returns_dict(self) -> None:
        payload = parse_json_payload('{"mode":"qa","overall_passed":true}')
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload.get("mode"), "qa")

    def test_parse_json_payload_rejects_invalid(self) -> None:
        self.assertIsNone(parse_json_payload("not-json"))
        self.assertIsNone(parse_json_payload('["array"]'))

    def test_check_qa_passes_on_valid_payload(self) -> None:
        stdout = '{"mode":"qa","overall_passed":true}'
        passed, reason = _check_qa(0, stdout, "")
        self.assertTrue(passed)
        self.assertIn("passed", reason)

    def test_check_qa_fails_when_overall_failed(self) -> None:
        stdout = '{"mode":"qa","overall_passed":false}'
        passed, reason = _check_qa(0, stdout, "")
        self.assertFalse(passed)
        self.assertIn("overall_passed", reason)

    def test_check_demo_passes_on_valid_payload(self) -> None:
        stdout = '{"mode":"demo","snapshot":{"mainnet_open":true}}'
        passed, reason = _check_demo(0, stdout, "")
        self.assertTrue(passed)
        self.assertIn("passed", reason)

    def test_check_demo_fails_on_closed_mainnet(self) -> None:
        stdout = '{"mode":"demo","snapshot":{"mainnet_open":false}}'
        passed, reason = _check_demo(0, stdout, "")
        self.assertFalse(passed)
        self.assertIn("mainnet_open", reason)


if __name__ == "__main__":
    unittest.main()
