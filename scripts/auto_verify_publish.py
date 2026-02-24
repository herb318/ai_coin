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

from scripts.network_status_agent import _status_fingerprint

EXPECTED_MODE = "network-status-agent"
EXPECTED_PROTOCOL_ID = "dpuin-protocol"
ALLOWED_HEALTH_LEVELS = {"OK", "WARN", "DEGRADED"}


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


def _is_sha256_hex(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(ch in "0123456789abcdef" for ch in value.lower())


def _is_non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and value >= 0


def _is_non_negative_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and float(value) >= 0


def validate_status_payload_schema(status_payload: Dict[str, Any]) -> Tuple[bool, str]:
    mode = status_payload.get("mode")
    if mode != EXPECTED_MODE:
        return False, f"Invalid mode: expected {EXPECTED_MODE}, got {mode!r}"

    protocol_id = status_payload.get("protocol_id")
    if protocol_id != EXPECTED_PROTOCOL_ID:
        return False, f"Invalid protocol_id: expected {EXPECTED_PROTOCOL_ID}, got {protocol_id!r}"

    if not isinstance(status_payload.get("status_ok"), bool):
        return False, "Invalid status_ok type: expected bool"

    health_level = str(status_payload.get("health_level", "")).upper().strip()
    if health_level not in ALLOWED_HEALTH_LEVELS:
        return False, f"Invalid health_level: {health_level!r}"

    status_reasons = status_payload.get("status_reasons")
    advisories = status_payload.get("advisories")
    recommended_actions = status_payload.get("recommended_actions")
    if not isinstance(status_reasons, list):
        return False, "Invalid status_reasons type: expected list"
    if not isinstance(advisories, list):
        return False, "Invalid advisories type: expected list"
    if not isinstance(recommended_actions, list):
        return False, "Invalid recommended_actions type: expected list"

    if not _is_non_negative_int(status_payload.get("network_size_nodes")):
        return False, "Invalid network_size_nodes: expected non-negative int"
    if int(status_payload.get("network_size_nodes", 0)) < 3:
        return False, "Invalid network_size_nodes: value must be >= 3"

    if not _is_non_negative_int(status_payload.get("requests_executed")):
        return False, "Invalid requests_executed: expected non-negative int"

    if not _is_non_negative_number(status_payload.get("avg_winner_latency_ms")):
        return False, "Invalid avg_winner_latency_ms: expected non-negative number"

    if not isinstance(status_payload.get("qa_overall_passed"), bool):
        return False, "Invalid qa_overall_passed type: expected bool"

    if not _is_non_negative_int(status_payload.get("qa_agent_count")):
        return False, "Invalid qa_agent_count: expected non-negative int"
    if int(status_payload.get("qa_agent_count", 0)) < 1:
        return False, "Invalid qa_agent_count: value must be >= 1"

    status_fingerprint = status_payload.get("status_fingerprint")
    if not _is_sha256_hex(status_fingerprint):
        return False, "Invalid status_fingerprint: expected 64-char sha256 hex"

    history_chain = status_payload.get("history_chain")
    if history_chain is not None:
        if not isinstance(history_chain, dict):
            return False, "Invalid history_chain type: expected object"
        tracked_entries = history_chain.get("tracked_entries", 0)
        if not _is_non_negative_int(tracked_entries):
            return False, "Invalid history_chain.tracked_entries: expected non-negative int"
        if "valid" in history_chain and not isinstance(history_chain.get("valid"), bool):
            return False, "Invalid history_chain.valid type: expected bool"

    return True, ""


def validate_status_payload_consistency(status_payload: Dict[str, Any]) -> Tuple[bool, str]:
    health_level = str(status_payload.get("health_level", "")).upper().strip()
    status_ok = bool(status_payload.get("status_ok"))
    status_reasons = status_payload.get("status_reasons", [])
    advisories = status_payload.get("advisories", [])

    if health_level == "OK" and status_reasons:
        return False, "Health is OK but status_reasons is non-empty"
    if health_level == "DEGRADED" and not status_reasons:
        return False, "Health is DEGRADED but status_reasons is empty"
    if status_ok and health_level == "DEGRADED":
        return False, "status_ok is true while health_level is DEGRADED"
    if (not status_ok) and health_level == "OK" and not advisories:
        return False, "status_ok is false while health_level is OK with no advisories"

    actual_fingerprint = str(status_payload.get("status_fingerprint", ""))
    expected_fingerprint = _status_fingerprint(status_payload)
    if actual_fingerprint != expected_fingerprint:
        return False, "status_fingerprint mismatch against recomputed semantic fingerprint"

    return True, ""


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
    schema_ok, schema_reason = validate_status_payload_schema(status_payload)
    if not schema_ok:
        return (
            True,
            "Generated status payload schema validation failed under --production-checks. "
            f"{schema_reason}. "
            "Regenerate status report before publish.",
        )
    consistency_ok, consistency_reason = validate_status_payload_consistency(status_payload)
    if not consistency_ok:
        return (
            True,
            "Generated status payload consistency validation failed under --production-checks. "
            f"{consistency_reason}. "
            "Regenerate status report before publish.",
        )
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
