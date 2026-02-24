#!/usr/bin/env python3
"""Single simple CLI for AIRN operations."""

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
    python_cmd,
    run_check_pipeline,
    run_command,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AIRN simple CLI (check, demo, qa, status, loop, launch controls)."
    )
    parser.add_argument("--project-root", default=str(PROJECT_ROOT), help="Project root for command execution.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="Run simple full check pipeline.")
    check.add_argument("--production-checks", action="store_true", help="Enable strict production checks.")
    check.add_argument("--no-status-agent", action="store_true", help="Skip status-agent generation.")
    check.add_argument(
        "--launch-state-path",
        default="runtime/launch_state.json",
        help="Launch sentinel state path shared by demo/qa/status.",
    )

    qa = subparsers.add_parser("qa", help="Run QA suite.")
    qa.add_argument("--production-checks", action="store_true")
    qa.add_argument("--launch-state-path", default="runtime/launch_state.json")

    demo = subparsers.add_parser("demo", help="Run demo flow.")
    demo.add_argument("--production-checks", action="store_true")
    demo.add_argument("--launch-state-path", default="runtime/launch_state.json")

    status = subparsers.add_parser("status", help="Generate user-facing network status docs.")
    status.add_argument("--production-checks", action="store_true")
    status.add_argument("--launch-state-path", default="runtime/launch_state.json")

    loop = subparsers.add_parser("loop", help="Run continuous operator loop.")
    loop.add_argument("--production-checks", action="store_true")
    loop.add_argument("--include-status-agent", action="store_true")
    loop.add_argument("--interval-seconds", type=int, default=120)
    loop.add_argument("--max-consecutive-failures", type=int, default=5)
    loop.add_argument("--once", action="store_true")

    arm = subparsers.add_parser("launch-arm", help="Arm final launch sentinel (owner only).")
    arm.add_argument("--launch-state-path", default="runtime/launch_state.json")
    arm.add_argument("--runner-id", default="")

    show = subparsers.add_parser("launch-state", help="Show launch sentinel state.")
    show.add_argument("--launch-state-path", default="runtime/launch_state.json")

    return parser.parse_args()


def _run_mode(mode: str, production_checks: bool, launch_state_path: str, root: Path) -> int:
    command = python_cmd(
        "decentralized_ai_network_demo.py",
        "--mode",
        mode,
        "--launch-state-path",
        launch_state_path,
    )
    if production_checks:
        command.append("--production-checks")
    return run_command(command, cwd=root)


def _run_status(production_checks: bool, launch_state_path: str, root: Path) -> int:
    command = python_cmd(
        "scripts/network_status_agent.py",
        "--launch-state-path",
        launch_state_path,
    )
    if production_checks:
        command.append("--production-checks")
    return run_command(command, cwd=root)


def _run_launch_action(
    action: str,
    launch_state_path: str,
    runner_id: str,
    root: Path,
) -> int:
    command = python_cmd(
        "decentralized_ai_network_demo.py",
        "--launch-state-path",
        launch_state_path,
    )
    if action == "arm":
        command.append("--arm-final-launch")
        if runner_id:
            command.extend(["--runner-id", runner_id])
    elif action == "show":
        command.append("--show-launch-state")
    else:
        raise ValueError(f"Unsupported launch action: {action}")
    return run_command(command, cwd=root)


def main() -> None:
    args = parse_args()
    root = Path(args.project_root).resolve()

    if args.command == "check":
        summary, exit_code = run_check_pipeline(
            production_checks=bool(args.production_checks),
            include_status_agent=not bool(args.no_status_agent),
            launch_state_path=args.launch_state_path,
            project_root=root,
            stream_output=True,
        )
        print_summary(summary)
        raise SystemExit(exit_code)

    if args.command == "qa":
        raise SystemExit(_run_mode("qa", bool(args.production_checks), args.launch_state_path, root))

    if args.command == "demo":
        raise SystemExit(_run_mode("demo", bool(args.production_checks), args.launch_state_path, root))

    if args.command == "status":
        raise SystemExit(_run_status(bool(args.production_checks), args.launch_state_path, root))

    if args.command == "loop":
        command = build_operator_loop_command(
            production_checks=bool(args.production_checks),
            include_status_agent=bool(args.include_status_agent),
            interval_seconds=int(args.interval_seconds),
            max_consecutive_failures=int(args.max_consecutive_failures),
            once=bool(args.once),
        )
        raise SystemExit(run_command(command, cwd=root))

    if args.command == "launch-arm":
        raise SystemExit(_run_launch_action("arm", args.launch_state_path, args.runner_id, root))

    if args.command == "launch-state":
        raise SystemExit(_run_launch_action("show", args.launch_state_path, "", root))

    raise SystemExit(2)


if __name__ == "__main__":
    main()
