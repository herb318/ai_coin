import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.docker_runner import (
    build_oneshot_steps,
    build_operator_loop_command,
    run_oneshot,
)


class TestDockerRunner(unittest.TestCase):
    def test_build_oneshot_steps_default(self) -> None:
        steps = build_oneshot_steps(production_checks=False)
        self.assertEqual(len(steps), 6)
        self.assertEqual(steps[0].name, "unit-tests")
        self.assertIn("decentralized_ai_network_demo.py", steps[3].command)
        self.assertNotIn("--production-checks", steps[3].command)
        self.assertNotIn("--production-checks", steps[4].command)
        self.assertNotIn("--production-checks", steps[5].command)

    def test_build_oneshot_steps_production(self) -> None:
        steps = build_oneshot_steps(production_checks=True)
        self.assertEqual(len(steps), 6)
        self.assertIn("--production-checks", steps[3].command)
        self.assertIn("--production-checks", steps[4].command)
        self.assertIn("--production-checks", steps[5].command)

    def test_build_operator_loop_command(self) -> None:
        cmd = build_operator_loop_command(
            production_checks=True,
            include_status_agent=True,
            interval_seconds=30,
            max_consecutive_failures=2,
            once=True,
        )
        self.assertIn("scripts/run_operator_loop.py", cmd)
        self.assertIn("--production-checks", cmd)
        self.assertIn("--include-status-agent", cmd)
        self.assertIn("--once", cmd)
        self.assertIn("30", cmd)
        self.assertIn("2", cmd)

    @patch("builtins.print")
    @patch("scripts.docker_runner.run_step")
    def test_run_oneshot_stops_on_first_failure(self, mock_run_step, _mock_print) -> None:
        mock_run_step.side_effect = [
            {
                "step": "unit-tests",
                "command": [],
                "returncode": 0,
                "passed": True,
                "started_at_utc": "2026-01-01T00:00:00+00:00",
                "ended_at_utc": "2026-01-01T00:00:01+00:00",
                "duration_ms": 1.0,
            },
            {
                "step": "security-bandit",
                "command": [],
                "returncode": 3,
                "passed": False,
                "started_at_utc": "2026-01-01T00:00:02+00:00",
                "ended_at_utc": "2026-01-01T00:00:03+00:00",
                "duration_ms": 1.0,
            },
        ]
        code = run_oneshot(production_checks=False, project_root=Path("."))
        self.assertEqual(code, 3)
        self.assertEqual(mock_run_step.call_count, 2)


if __name__ == "__main__":
    unittest.main()
