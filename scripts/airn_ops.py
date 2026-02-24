#!/usr/bin/env python3
"""Shared simple orchestration utilities for AIRN commands."""

from __future__ import annotations

import json
import shlex
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple


PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class StepSpec:
    name: str
    command: List[str]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def python_cmd(*args: str) -> List[str]:
    return [sys.executable, *args]


def build_check_steps(
    production_checks: bool,
    include_status_agent: bool = True,
    launch_state_path: str = "runtime/launch_state.json",
) -> List[StepSpec]:
    qa_cmd = python_cmd(
        "decentralized_ai_network_demo.py",
        "--mode",
        "qa",
        "--launch-state-path",
        launch_state_path,
    )
    demo_cmd = python_cmd(
        "decentralized_ai_network_demo.py",
        "--mode",
        "demo",
        "--launch-state-path",
        launch_state_path,
    )
    status_cmd = python_cmd(
        "scripts/network_status_agent.py",
        "--launch-state-path",
        launch_state_path,
    )
    if production_checks:
        qa_cmd.append("--production-checks")
        demo_cmd.append("--production-checks")
        status_cmd.append("--production-checks")

    steps = [
        StepSpec(name="unit-tests", command=python_cmd("-m", "unittest", "discover", "-s", "tests", "-v")),
        StepSpec(name="security-bandit", command=python_cmd("-m", "bandit", "-r", ".", "-q")),
        StepSpec(name="security-sanitize", command=python_cmd("scripts/sanitize_for_git_open.py", "--root", ".")),
        StepSpec(name="qa", command=qa_cmd),
        StepSpec(name="demo", command=demo_cmd),
    ]
    if include_status_agent:
        steps.append(StepSpec(name="status-agent", command=status_cmd))
    return steps


def build_operator_loop_command(
    production_checks: bool,
    include_status_agent: bool,
    interval_seconds: int,
    max_consecutive_failures: int,
    once: bool,
    launch_state_path: str = "runtime/launch_state.json",
) -> List[str]:
    _ = launch_state_path
    cmd = python_cmd(
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


def run_step(spec: StepSpec, cwd: Path, stream_output: bool = True) -> Dict[str, Any]:
    started = time.monotonic()
    started_at = utc_now()
    if stream_output:
        print(f">> [{spec.name}] {shlex.join(spec.command)}")
    completed = subprocess.run(  # nosec B603
        spec.command,
        cwd=str(cwd),
        check=False,
        text=True,
        capture_output=True,
    )
    if stream_output:
        if completed.stdout.strip():
            print(completed.stdout.strip())
        if completed.stderr.strip():
            print(completed.stderr.strip(), file=sys.stderr)
    ended_at = utc_now()
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


def run_check_pipeline(
    production_checks: bool,
    include_status_agent: bool = True,
    launch_state_path: str = "runtime/launch_state.json",
    project_root: Path = PROJECT_ROOT,
    stream_output: bool = True,
) -> Tuple[Dict[str, Any], int]:
    summary: Dict[str, Any] = {
        "mode": "check",
        "production_checks": bool(production_checks),
        "include_status_agent": bool(include_status_agent),
        "project_root": str(project_root),
        "launch_state_path": launch_state_path,
        "started_at_utc": utc_now(),
        "steps": [],
    }
    exit_code = 0
    for step in build_check_steps(
        production_checks=production_checks,
        include_status_agent=include_status_agent,
        launch_state_path=launch_state_path,
    ):
        result = run_step(step, cwd=project_root, stream_output=stream_output)
        summary["steps"].append(result)
        if not result["passed"]:
            exit_code = int(result["returncode"]) or 1
            summary["failed_step"] = result["step"]
            break
    summary["ended_at_utc"] = utc_now()
    summary["overall_passed"] = exit_code == 0 and all(item.get("passed") for item in summary["steps"])
    return summary, exit_code


def run_command(command: List[str], cwd: Path = PROJECT_ROOT, stream_output: bool = True) -> int:
    if stream_output:
        print(f">> {shlex.join(command)}")
    completed = subprocess.run(  # nosec B603
        command,
        cwd=str(cwd),
        check=False,
    )
    return int(completed.returncode)


def print_summary(summary: Dict[str, Any]) -> None:
    print(json.dumps(summary, ensure_ascii=False, indent=2))
