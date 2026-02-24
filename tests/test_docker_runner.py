import unittest
from unittest.mock import patch

from scripts.airn_ops import build_check_steps, build_operator_loop_command
from scripts.docker_runner import main


class TestDockerRunner(unittest.TestCase):
    def test_build_check_steps_default(self) -> None:
        steps = build_check_steps(production_checks=False, include_status_agent=True)
        self.assertEqual(len(steps), 6)
        self.assertEqual(steps[0].name, "unit-tests")
        self.assertNotIn("--production-checks", steps[3].command)
        self.assertNotIn("--production-checks", steps[4].command)
        self.assertNotIn("--production-checks", steps[5].command)

    def test_build_check_steps_production(self) -> None:
        steps = build_check_steps(production_checks=True, include_status_agent=True)
        self.assertEqual(len(steps), 6)
        self.assertIn("--production-checks", steps[3].command)
        self.assertIn("--production-checks", steps[4].command)
        self.assertIn("--production-checks", steps[5].command)

    def test_build_check_steps_without_status(self) -> None:
        steps = build_check_steps(production_checks=False, include_status_agent=False)
        self.assertEqual(len(steps), 5)
        self.assertEqual(steps[-1].name, "demo")

    def test_build_operator_loop_command(self) -> None:
        cmd = build_operator_loop_command(
            production_checks=True,
            include_status_agent=True,
            interval_seconds=30,
            max_consecutive_failures=2,
            once=True,
            launch_state_path="runtime/custom_launch_state.json",
        )
        self.assertIn("scripts/run_operator_loop.py", cmd)
        self.assertIn("--production-checks", cmd)
        self.assertIn("--include-status-agent", cmd)
        self.assertIn("--once", cmd)
        self.assertIn("30", cmd)
        self.assertIn("2", cmd)

    @patch("scripts.docker_runner.print_summary")
    @patch("scripts.docker_runner.run_check_pipeline")
    def test_main_oneshot_calls_pipeline(self, mock_pipeline, _mock_print_summary) -> None:
        mock_pipeline.return_value = ({"overall_passed": True}, 0)
        with patch(
            "sys.argv",
            ["docker_runner.py", "--mode", "oneshot", "--production-checks"],
        ):
            with self.assertRaises(SystemExit) as exc:
                main()
        self.assertEqual(exc.exception.code, 0)
        self.assertTrue(mock_pipeline.called)

    @patch("scripts.docker_runner.run_command")
    @patch("scripts.docker_runner.build_operator_loop_command")
    def test_main_operator_loop_calls_run_command(self, mock_build_cmd, mock_run_command) -> None:
        mock_build_cmd.return_value = ["python3", "scripts/run_operator_loop.py", "--once"]
        mock_run_command.return_value = 0
        with patch(
            "sys.argv",
            ["docker_runner.py", "--mode", "operator-loop", "--once"],
        ):
            with self.assertRaises(SystemExit) as exc:
                main()
        self.assertEqual(exc.exception.code, 0)
        self.assertTrue(mock_build_cmd.called)
        self.assertTrue(mock_run_command.called)


if __name__ == "__main__":
    unittest.main()
