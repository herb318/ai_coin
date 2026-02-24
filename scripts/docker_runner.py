#!/usr/bin/env python3
"""Docker-oriented one-shot verifier and operator launcher for AIRN."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class StepSpec:
    name: str
    command: List[str]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _python_cmd(*args: str) -> List[str]:
    return [sys.executable, *args]


def build_oneshot_steps(production_checks: bool) -> List[StepSpec]:
    qa_cmd = _python_cmd("decentralized_ai_network_demo.py", "--mode", "qa")
    demo_cmd = _python_cmd("decentralized_ai_network_demo.py", "--mode", "demo")
    status_cmd = _python_cmd("scripts/network_status_agent.py")
    if production_checks:
        qa_cmd.append("--production-checks")
        demo_cmd.append("--production-checks")
        status_cmd.append("--production-checks")
    return [
        StepSpec(
            name="unit-tests",
            command=_python_cmd("-m", "unittest", "discover", "-s", "tests", "-v"),
        ),
        StepSpec(
            name="security-bandit",
            command=_python_cmd("-m", "bandit", "-r", ".", "-q"),
        ),
        StepSpec(
            name="security-sanitize",
            command=_python_cmd("scripts/sanitize_for_git_open.py", "--root", "."),
        ),
        StepSpec(name="qa", command=qa_cmd),
        StepSpec(name="demo", command=demo_cmd),
        StepSpec(name="status-agent", command=status_cmd),
    ]


def build_operator_loop_command(
    production_checks: bool,
    include_status_agent: bool,
    interval_seconds: int,
    max_consecutive_failures: int,
    once: bool,
) -> List[str]:
    cmd = _python_cmd(
        "scripts/run_operator_loop.py",
        "--interval-seconds",
        str(interval_seconds),
        "--max-consecutive-failures",
        str(max_consecutive_failures),
    )
    if production_checks:
        cmd.append("--production-checks")
    if include_status_agent:
        cmd.append("--include-status-agent")
    if once:
        cmd.append("--once")
    return cmd


def run_step(spec: StepSpec, cwd: Path) -> Dict[str, Any]:
    started = time.monotonic()
    started_at = _utc_now()
    print(f">> [{spec.name}] {shlex.join(spec.command)}")
    completed = subprocess.run(  # nosec B603
        spec.command,
        cwd=str(cwd),
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.stdout.strip():
        print(completed.stdout.strip())
    if completed.stderr.strip():
        print(completed.stderr.strip(), file=sys.stderr)
    ended_at = _utc_now()
    duration_ms = round((time.monotonic() - started) * 1000.0, 2)
    return {
        "step": spec.name,
        "command": spec.command,
        "returncode": completed.returncode,
        "passed": completed.returncode == 0,
        "started_at_utc": started_at,
        "ended_at_utc": ended_at,
        "duration_ms": duration_ms,
    }


def run_oneshot(production_checks: bool, project_root: Path) -> int:
    summary: Dict[str, Any] = {
        "mode": "oneshot",
        "production_checks": bool(production_checks),
        "project_root": str(project_root),
        "started_at_utc": _utc_now(),
        "steps": [],
    }
    exit_code = 0
    for step in build_oneshot_steps(production_checks=production_checks):
        result = run_step(step, cwd=project_root)
        summary["steps"].append(result)
        if not result["passed"]:
            exit_code = int(result["returncode"]) or 1
            break
    summary["ended_at_utc"] = _utc_now()
    summary["overall_passed"] = exit_code == 0 and all(item.get("passed") for item in summary["steps"])
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return exit_code


def run_operator_loop_mode(
    production_checks: bool,
    include_status_agent: bool,
    interval_seconds: int,
    max_consecutive_failures: int,
    once: bool,
    project_root: Path,
) -> int:
    command = build_operator_loop_command(
        production_checks=production_checks,
        include_status_agent=include_status_agent,
        interval_seconds=interval_seconds,
        max_consecutive_failures=max_consecutive_failures,
        once=once,
    )
    print(f">> [operator-loop] {shlex.join(command)}")
    completed = subprocess.run(  # nosec B603
        command,
        cwd=str(project_root),
        check=False,
    )
    return int(completed.returncode)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run AIRN one-shot Docker automation or operator loop.")
    parser.add_argument(
        "--mode",
        choices=["oneshot", "operator-loop"],
        default="oneshot",
        help="oneshot: full verification pipeline. operator-loop: long-running operator.",
    )
    parser.add_argument(
        "--production-checks",
        action="store_true",
        help="Enable strict production checks for demo/qa/status or operator loop.",
    )
    parser.add_argument(
        "--project-root",
        default=str(PROJECT_ROOT),
        help="Project root for command execution.",
    )
    parser.add_argument(
        "--include-status-agent",
        action="store_true",
        help="When mode=operator-loop, include status agent each cycle.",
    )
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=120,
        help="When mode=operator-loop, sleep duration between cycles.",
    )
    parser.add_argument(
        "--max-consecutive-failures",
        type=int,
        default=5,
        help="When mode=operator-loop, stop after N consecutive failures.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="When mode=operator-loop, run one cycle and exit.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(args.project_root).resolve()
    if args.mode == "operator-loop":
        if args.interval_seconds < 1:
            raise ValueError("--interval-seconds must be >= 1")
        if args.max_consecutive_failures < 1:
            raise ValueError("--max-consecutive-failures must be >= 1")
        code = run_operator_loop_mode(
            production_checks=args.production_checks,
            include_status_agent=args.include_status_agent,
            interval_seconds=args.interval_seconds,
            max_consecutive_failures=args.max_consecutive_failures,
            once=args.once,
            project_root=root,
        )
        raise SystemExit(code)

    code = run_oneshot(production_checks=args.production_checks, project_root=root)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
