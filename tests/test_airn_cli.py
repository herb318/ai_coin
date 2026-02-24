import unittest
from unittest.mock import patch

from scripts.airn import main


class TestAIRNCli(unittest.TestCase):
    @patch("scripts.airn.print_summary")
    @patch("scripts.airn.run_check_pipeline")
    def test_check_command_runs_pipeline(self, mock_pipeline, _mock_print_summary) -> None:
        mock_pipeline.return_value = ({"overall_passed": True}, 0)
        with patch("sys.argv", ["airn.py", "check"]):
            with self.assertRaises(SystemExit) as exc:
                main()
        self.assertEqual(exc.exception.code, 0)
        self.assertTrue(mock_pipeline.called)

    @patch("scripts.airn.run_command")
    def test_demo_command_runs_subprocess(self, mock_run_command) -> None:
        mock_run_command.return_value = 0
        with patch("sys.argv", ["airn.py", "demo"]):
            with self.assertRaises(SystemExit) as exc:
                main()
        self.assertEqual(exc.exception.code, 0)
        self.assertTrue(mock_run_command.called)

    @patch("scripts.airn.run_command")
    @patch("scripts.airn.build_operator_loop_command")
    def test_loop_command_builds_and_runs(self, mock_build, mock_run_command) -> None:
        mock_build.return_value = ["python3", "scripts/run_operator_loop.py", "--once"]
        mock_run_command.return_value = 0
        with patch("sys.argv", ["airn.py", "loop", "--once"]):
            with self.assertRaises(SystemExit) as exc:
                main()
        self.assertEqual(exc.exception.code, 0)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_run_command.called)


if __name__ == "__main__":
    unittest.main()
