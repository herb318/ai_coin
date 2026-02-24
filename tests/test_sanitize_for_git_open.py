import tempfile
import unittest
from pathlib import Path

from scripts.sanitize_for_git_open import check_gitignore, scan_file


class TestSanitizeForGitOpen(unittest.TestCase):
    def test_detects_env_secret_and_redacts_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "sample.env"
            sample_value = "".join(["Priv", "_", "token", "_", "local", "_", "value", "_", "123"])
            target.write_text(f"PRIVATE_API_TOKEN={sample_value}\n", encoding="utf-8")

            findings = scan_file(str(target))

        self.assertEqual(len(findings), 1)
        self.assertIn("Non-placeholder value for PRIVATE_API_TOKEN", findings[0].reason)
        self.assertIn("PRIVATE_API_TOKEN=", findings[0].snippet)
        self.assertNotIn(sample_value, findings[0].snippet)
        self.assertIn("...", findings[0].snippet)

    def test_ignores_placeholder_env_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "sample.env"
            target.write_text("PRIVATE_API_TOKEN=CHANGE_ME_PRIVATE_API_TOKEN\n", encoding="utf-8")

            findings = scan_file(str(target))

        self.assertEqual(findings, [])

    def test_detects_telegram_token_and_redacts_snippet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "config.txt"
            sample_credential = "".join(["123456789", ":", "A" * 35])
            target.write_text(f"telegram_token={sample_credential}\n", encoding="utf-8")

            findings = scan_file(str(target))

        reasons = [item.reason for item in findings]
        self.assertIn("Potential Telegram bot token pattern", reasons)
        joined = "\n".join(item.snippet for item in findings)
        self.assertNotIn(sample_credential, joined)
        self.assertIn("...", joined)

    def test_detects_credential_url_and_masks_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "rpc.txt"
            sample_url = "".join(["https://", "admin", ":", "su", "per", "pw", "@", "rpc.example.com/v1"])
            target.write_text(sample_url + "\n", encoding="utf-8")

            findings = scan_file(str(target))

        reasons = [item.reason for item in findings]
        self.assertIn("Potential credential-in-URL pattern", reasons)
        snippets = "\n".join(item.snippet for item in findings)
        self.assertNotIn("SuperSecretPassword", snippets)

    def test_check_gitignore_reports_required_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            gitignore_path = Path(tmp_dir) / ".gitignore"
            gitignore_path.write_text("runtime/\n", encoding="utf-8")

            issues = check_gitignore(tmp_dir)

        self.assertIn("Missing .gitignore rule: .env", issues)
        self.assertIn("Missing .gitignore rule: .env.*", issues)
        self.assertIn("Missing .gitignore rule: !.env.example", issues)


if __name__ == "__main__":
    unittest.main()
