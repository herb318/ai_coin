#!/usr/bin/env python3
"""Backward-compatible Docker runner wrapper for AIRN."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scripts.airn_ops import (
    PROJECT_ROOT,
    build_operator_loop_command,
    print_summary,
    run_check_pipeline,
    run_command,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run AIRN Docker automation modes.")
    parser.add_argument("--mode", choices=["oneshot", "operator-loop"], default="oneshot")
    parser.add_argument("--production-checks", action="store_true")
    parser.add_argument("--project-root", default=str(PROJECT_ROOT))
    parser.add_argument("--launch-state-path", default="runtime/launch_state.json")
    parser.add_argument("--include-status-agent", action="store_true")
    parser.add_argument("--interval-seconds", type=int, default=120)
    parser.add_argument("--max-consecutive-failures", type=int, default=5)
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(args.project_root).resolve()

    if args.mode == "operator-loop":
        command = build_operator_loop_command(
            production_checks=bool(args.production_checks),
            include_status_agent=bool(args.include_status_agent),
            interval_seconds=int(args.interval_seconds),
            max_consecutive_failures=int(args.max_consecutive_failures),
            once=bool(args.once),
            launch_state_path=args.launch_state_path,
        )
        raise SystemExit(run_command(command, cwd=root))

    summary, exit_code = run_check_pipeline(
        production_checks=bool(args.production_checks),
        include_status_agent=True,
        launch_state_path=args.launch_state_path,
        project_root=root,
        stream_output=True,
    )
    print_summary(summary)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
