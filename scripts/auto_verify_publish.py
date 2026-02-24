#!/usr/bin/env python3
"""Run full verification, regenerate network status, and auto-publish if changed."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess  # nosec B404
from datetime import datetime, timezone
from pathlib import Path
from typing import List


def run(cmd: List[str], cwd: Path) -> str:
    print(f">> {shlex.join(cmd)}")
    # Command list is explicit and executed without shell interpolation.
    completed = subprocess.run(  # nosec B603
        cmd,
        cwd=str(cwd),
        check=True,
        text=True,
        capture_output=True,
    )
    if completed.stdout.strip():
        print(completed.stdout.strip())
    if completed.stderr.strip():
        print(completed.stderr.strip())
    return completed.stdout


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify project and publish updated network status docs automatically."
    )
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parent.parent),
        help="Repository root path.",
    )
    parser.add_argument(
        "--production-checks",
        action="store_true",
        help="Pass --production-checks to network status agent.",
    )
    parser.add_argument(
        "--launch-state-path",
        default="runtime/launch_state.json",
        help="Launch state path forwarded to network status agent.",
    )
    parser.add_argument(
        "--skip-push",
        action="store_true",
        help="Commit changes but skip git push.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    repo = Path(args.repo_root).resolve()

    run(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo)

    run(["python3", "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=repo)
    run(["python3", "-m", "bandit", "-r", ".", "-q"], cwd=repo)
    run(["python3", "scripts/sanitize_for_git_open.py", "--root", "."], cwd=repo)

    status_cmd = ["python3", "scripts/network_status_agent.py", "--launch-state-path", args.launch_state_path]
    if args.production_checks:
        status_cmd.append("--production-checks")
    run(status_cmd, cwd=repo)

    changed = run(
        ["git", "status", "--porcelain", "--", "docs/NETWORK_STATUS.md", "docs/NETWORK_STATUS.json"],
        cwd=repo,
    ).strip()
    if not changed:
        result = {
            "published": False,
            "reason": "No status doc changes detected.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    run(["git", "add", "docs/NETWORK_STATUS.md", "docs/NETWORK_STATUS.json"], cwd=repo)
    commit_msg = f"chore: auto-update network status ({datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')})"
    run(["git", "commit", "-m", commit_msg], cwd=repo)
    if not args.skip_push:
        run(["git", "push"], cwd=repo)

    result = {
        "published": True,
        "commit_message": commit_msg,
        "pushed": not args.skip_push,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
