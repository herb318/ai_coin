#!/usr/bin/env python3
"""Continuous local operator loop for AIRN."""

from __future__ import annotations

import argparse
import json
import os
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_STOP_FILE = PROJECT_ROOT / "runtime" / "STOP_OPERATOR_LOOP"
DEFAULT_LOG_FILE = PROJECT_ROOT / "runtime" / "operator_loop.log"
DEFAULT_STATE_FILE = PROJECT_ROOT / "runtime" / "operator_loop_state.json"
DEFAULT_PID_FILE = PROJECT_ROOT / "runtime" / "operator_loop.pid"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_json_payload(stdout_text: str) -> Optional[Dict[str, Any]]:
    text = stdout_text.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _check_qa(returncode: int, stdout_text: str, stderr_text: str) -> Tuple[bool, str]:
    if returncode != 0:
        detail = stderr_text.strip() or "non-zero exit"
        return False, f"qa command failed: {detail}"
    payload = parse_json_payload(stdout_text)
    if not payload:
        return False, "qa output is not valid json object"
    if payload.get("mode") != "qa":
        return False, "qa output mode mismatch"
    if payload.get("overall_passed") is not True:
        return False, "qa overall_passed is false"
    return True, "qa passed"


def _check_demo(returncode: int, stdout_text: str, stderr_text: str) -> Tuple[bool, str]:
    if returncode != 0:
        detail = stderr_text.strip() or "non-zero exit"
        return False, f"demo command failed: {detail}"
    payload = parse_json_payload(stdout_text)
    if not payload:
        return False, "demo output is not valid json object"
    if payload.get("mode") != "demo":
        return False, "demo output mode mismatch"
    snapshot = payload.get("snapshot", {})
    if not isinstance(snapshot, dict) or snapshot.get("mainnet_open") is not True:
        return False, "demo mainnet_open is false"
    return True, "demo passed"


def _check_status(returncode: int, _stdout_text: str, stderr_text: str) -> Tuple[bool, str]:
    if returncode != 0:
        detail = stderr_text.strip() or "non-zero exit"
        return False, f"status command failed: {detail}"
    return True, "status passed"


@dataclass
class StepSpec:
    name: str
    command: List[str]
    checker: Callable[[int, str, str], Tuple[bool, str]]


@dataclass
class StepResult:
    name: str
    passed: bool
    reason: str
    returncode: int
    started_at_utc: str
    ended_at_utc: str


def append_log(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def write_state(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    os.replace(tmp_path, path)


def run_step(spec: StepSpec) -> StepResult:
    started = utc_now()
    completed = subprocess.run(  # nosec B603
        spec.command,
        cwd=str(PROJECT_ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    ended = utc_now()
    passed, reason = spec.checker(completed.returncode, completed.stdout, completed.stderr)
    return StepResult(
        name=spec.name,
        passed=passed,
        reason=reason,
        returncode=completed.returncode,
        started_at_utc=started,
        ended_at_utc=ended,
    )


def build_steps(production_checks: bool, include_status: bool) -> List[StepSpec]:
    qa_cmd = [sys.executable, "decentralized_ai_network_demo.py", "--mode", "qa"]
    if production_checks:
        qa_cmd.append("--production-checks")
    steps = [
        StepSpec(name="qa", command=qa_cmd, checker=_check_qa),
        StepSpec(
            name="demo",
            command=[sys.executable, "decentralized_ai_network_demo.py", "--mode", "demo"],
            checker=_check_demo,
        ),
    ]
    if include_status:
        status_cmd = [sys.executable, "scripts/network_status_agent.py"]
        if production_checks:
            status_cmd.append("--production-checks")
        steps.append(StepSpec(name="status", command=status_cmd, checker=_check_status))
    return steps


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Continuously run QA+demo operator loop.")
    parser.add_argument("--interval-seconds", type=int, default=120, help="Sleep between successful cycles.")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit.")
    parser.add_argument(
        "--production-checks",
        action="store_true",
        help="Enable production checks in QA/status steps.",
    )
    parser.add_argument(
        "--include-status-agent",
        action="store_true",
        help="Run network_status_agent.py in every cycle.",
    )
    parser.add_argument("--max-consecutive-failures", type=int, default=5, help="Stop after N consecutive failures.")
    parser.add_argument("--stop-file", default=str(DEFAULT_STOP_FILE), help="If this file exists, loop stops.")
    parser.add_argument("--log-file", default=str(DEFAULT_LOG_FILE), help="JSONL log output path.")
    parser.add_argument("--state-file", default=str(DEFAULT_STATE_FILE), help="Current loop state path.")
    parser.add_argument("--pid-file", default=str(DEFAULT_PID_FILE), help="PID file path.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.interval_seconds < 1:
        raise ValueError("--interval-seconds must be >= 1")
    if args.max_consecutive_failures < 1:
        raise ValueError("--max-consecutive-failures must be >= 1")

    stop_file = Path(args.stop_file)
    log_file = Path(args.log_file)
    state_file = Path(args.state_file)
    pid_file = Path(args.pid_file)

    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(str(os.getpid()), encoding="utf-8")

    steps = build_steps(production_checks=args.production_checks, include_status=args.include_status_agent)
    consecutive_failures = 0
    cycle = 0
    stopped_by_marker = False

    try:
        while True:
            cycle += 1
            cycle_started = utc_now()
            cycle_results: List[StepResult] = []

            for spec in steps:
                result = run_step(spec)
                cycle_results.append(result)
                append_log(
                    log_file,
                    {
                        "timestamp_utc": result.ended_at_utc,
                        "cycle": cycle,
                        "step": result.name,
                        "passed": result.passed,
                        "reason": result.reason,
                        "returncode": result.returncode,
                    },
                )
                if not result.passed:
                    break

            cycle_passed = all(item.passed for item in cycle_results) and len(cycle_results) == len(steps)
            if cycle_passed:
                consecutive_failures = 0
            else:
                consecutive_failures += 1

            cycle_state = {
                "timestamp_utc": utc_now(),
                "cycle": cycle,
                "cycle_started_at_utc": cycle_started,
                "cycle_passed": cycle_passed,
                "consecutive_failures": consecutive_failures,
                "max_consecutive_failures": args.max_consecutive_failures,
                "production_checks": bool(args.production_checks),
                "include_status_agent": bool(args.include_status_agent),
                "steps": [
                    {
                        "name": item.name,
                        "passed": item.passed,
                        "reason": item.reason,
                        "returncode": item.returncode,
                        "started_at_utc": item.started_at_utc,
                        "ended_at_utc": item.ended_at_utc,
                    }
                    for item in cycle_results
                ],
            }
            write_state(state_file, cycle_state)

            if args.once:
                if not cycle_passed:
                    raise SystemExit(1)
                return

            if stop_file.exists():
                stopped_by_marker = True
                return

            if consecutive_failures >= args.max_consecutive_failures:
                raise SystemExit(1)

            time.sleep(args.interval_seconds)
    finally:
        if stopped_by_marker:
            append_log(
                log_file,
                {
                    "timestamp_utc": utc_now(),
                    "cycle": cycle,
                    "step": "loop",
                    "passed": True,
                    "reason": "stopped_by_marker_file",
                    "returncode": 0,
                },
            )
        if pid_file.exists():
            pid_file.unlink()


if __name__ == "__main__":
    main()
