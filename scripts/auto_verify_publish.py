#!/usr/bin/env python3
"""Run full verification, regenerate DPUIN status view, and auto-publish if changed."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess  # nosec B404
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple


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


def load_status_payload(path: Path) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Missing status JSON: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid status JSON: {path}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected status JSON type at {path}")
    return data


def parse_generated_at_utc(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def should_block_publish(
    status_payload: Dict[str, Any],
    production_checks: bool,
    allow_failing_status: bool,
    fail_on_warn: bool = False,
    max_status_age_seconds: int = 900,
    now_utc: datetime | None = None,
) -> Tuple[bool, str]:
    if not production_checks or allow_failing_status:
        return False, ""
    now = now_utc or datetime.now(timezone.utc)
    max_age = max(0, int(max_status_age_seconds))
    generated_at = parse_generated_at_utc(status_payload.get("generated_at_utc"))
    if generated_at is None:
        return (
            True,
            "Generated status is missing/invalid generated_at_utc under --production-checks. "
            "Regenerate status report before publish.",
        )
    age_seconds = (now - generated_at).total_seconds()
    if age_seconds > max_age:
        return (
            True,
            "Generated status is stale under --production-checks. "
            f"Age={int(age_seconds)}s exceeds max={max_age}s. "
            "Regenerate status before publish.",
        )
    if age_seconds < -60:
        return (
            True,
            "Generated status timestamp is too far in the future under --production-checks. "
            f"Clock skew={int(-age_seconds)}s. Fix clocks and regenerate status before publish.",
        )
    history_chain = status_payload.get("history_chain", {})
    if isinstance(history_chain, dict):
        tracked_entries = int(history_chain.get("tracked_entries", 0) or 0)
        chain_valid = bool(history_chain.get("valid", True))
        if tracked_entries > 0 and not chain_valid:
            broken_index = history_chain.get("broken_index", -1)
            broken_reason = str(history_chain.get("broken_reason", "") or "unknown")
            latest_hash = str(history_chain.get("latest_hash", "") or "-")
            return (
                True,
                "Generated status reports invalid history chain integrity under --production-checks. "
                f"Broken index: {broken_index}. "
                f"Reason: {broken_reason}. "
                f"Latest valid hash: {latest_hash}. "
                "Repair or rotate history file before publish.",
            )
    health_level = str(status_payload.get("health_level", "")).upper().strip()
    if not health_level:
        has_reasons = bool(status_payload.get("status_reasons"))
        has_advisories = bool(status_payload.get("advisories"))
        if has_reasons:
            health_level = "DEGRADED"
        elif has_advisories:
            health_level = "WARN"
        elif status_payload.get("status_ok", False):
            health_level = "OK"
        else:
            health_level = "DEGRADED"

    if health_level == "OK":
        return False, ""
    if health_level == "WARN" and not fail_on_warn:
        return False, ""

    if health_level == "WARN":
        advisories = status_payload.get("advisories", [])
        advisory_text = ", ".join(str(item) for item in advisories) if advisories else "unknown advisory"
        actions = status_payload.get("recommended_actions", [])
        action_text = " | ".join(str(action) for action in actions[:3]) if actions else "No action suggestions available."
        return (
            True,
            "Generated status is WARN under --production-checks with --fail-on-warn. "
            f"Advisories: {advisory_text}. "
            f"Actions: {action_text}. "
            "Resolve advisories or remove --fail-on-warn.",
        )

    reasons = status_payload.get("status_reasons", [])
    reason_text = ", ".join(str(reason) for reason in reasons) if reasons else "unknown reason"
    actions = status_payload.get("recommended_actions", [])
    action_text = " | ".join(str(action) for action in actions[:3]) if actions else "No action suggestions available."
    return (
        True,
        "Generated status is degraded under --production-checks. "
        f"Reasons: {reason_text}. "
        f"Actions: {action_text}. "
        "Fix environment/security checks or pass --allow-failing-status.",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify project and publish updated DPUIN status view docs automatically."
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
    parser.add_argument(
        "--allow-failing-status",
        action="store_true",
        help="Allow commit/push even if generated status is degraded.",
    )
    parser.add_argument(
        "--fail-on-warn",
        action="store_true",
        help="Treat WARN health status as blocking during --production-checks.",
    )
    parser.add_argument(
        "--max-status-age-seconds",
        type=int,
        default=900,
        help="Maximum allowed status age in seconds during --production-checks (default: 900).",
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
    status_json_path = repo / "docs" / "NETWORK_STATUS.json"
    status_payload = load_status_payload(status_json_path)
    should_block, reason = should_block_publish(
        status_payload=status_payload,
        production_checks=args.production_checks,
        allow_failing_status=args.allow_failing_status,
        fail_on_warn=args.fail_on_warn,
        max_status_age_seconds=args.max_status_age_seconds,
    )
    if should_block:
        raise RuntimeError(reason)

    changed = run(
        [
            "git",
            "status",
            "--porcelain",
            "--",
            "docs/NETWORK_STATUS.md",
            "docs/NETWORK_STATUS.json",
            "docs/NETWORK_HISTORY.jsonl",
        ],
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

    run(
        ["git", "add", "docs/NETWORK_STATUS.md", "docs/NETWORK_STATUS.json", "docs/NETWORK_HISTORY.jsonl"],
        cwd=repo,
    )
    commit_msg = (
        f"chore: auto-update DPUIN status view ({datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')})"
    )
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
