#!/usr/bin/env python3
"""Generate an easy-to-read current network status report."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from decentralized_ai_network_demo import (
    DEFAULT_LAUNCH_STATE_PATH,
    IdentityRegistry,
    TranslationNetwork,
    UnstoppableLaunchSentinel,
    load_env_file,
    run_qa_team_suite,
    to_jsonable,
)

PROTOCOL_NAME = "Autonomous AI Reward Network"
PROTOCOL_ID = "dpuin-protocol"


def _failed_preflight_reasons(checks: Dict[str, bool]) -> List[str]:
    return [name for name, passed in checks.items() if not passed]


def _top_node_balances(snapshot: Dict[str, Any], limit: int = 5) -> List[tuple[str, Any]]:
    balances = snapshot.get("balances", {})
    node_items = [(k, v) for k, v in balances.items() if k.startswith("node-")]
    node_items.sort(key=lambda kv: float(kv[1]), reverse=True)
    return node_items[:limit]


def _node_details(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    balances = snapshot.get("balances", {})
    wallet_preview = snapshot.get("wallets_redacted", {})
    slash_points = snapshot.get("slash_points", {})
    node_items = [(k, v) for k, v in balances.items() if k.startswith("node-")]
    node_items.sort(key=lambda kv: float(kv[1]), reverse=True)
    total_node_balance = sum(float(balance) for _, balance in node_items)
    details: List[Dict[str, Any]] = []
    for rank, (node_id, balance) in enumerate(node_items, start=1):
        share = 0.0
        if total_node_balance > 0:
            share = round((float(balance) / total_node_balance) * 100.0, 4)
        details.append(
            {
                "rank": rank,
                "node_id": node_id,
                "balance": balance,
                "share_of_node_balance_pct": share,
                "wallet_preview": wallet_preview.get(node_id, ""),
                "slash_points": int(slash_points.get(node_id, 0)),
            }
        )
    return details


def _request_details(outputs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    details: List[Dict[str, Any]] = []
    for item in outputs:
        details.append(
            {
                "request_id": item.get("request_id"),
                "requester_node": item.get("requester_node"),
                "winner_node": item.get("winner_node"),
                "winner_latency_ms": item.get("winner_latency_ms"),
                "final_output": item.get("final_output"),
                "emission": item.get("emission"),
                "node_rewards": item.get("node_rewards", {}),
                "applied_upgrades": item.get("applied_upgrades", []),
            }
        )
    return details


def _safe_run_qa_suite(production_checks: bool) -> Dict[str, Any]:
    try:
        qa = run_qa_team_suite(production_mode=production_checks)
        return {
            "overall_passed": bool(qa.get("overall_passed", False)),
            "agent_count": len(qa.get("agents", [])),
            "error": "",
        }
    except Exception as exc:
        return {
            "overall_passed": False,
            "agent_count": 0,
            "error": str(exc),
        }


def _production_readiness_snapshot() -> Dict[str, Any]:
    network = TranslationNetwork()
    checks = network.run_preflight_checks(security_scan_passed=True, production_mode=True)
    return {
        "ready": all(checks.values()),
        "checks": checks,
    }


def _health_level(status_reasons: List[str], advisories: List[str]) -> str:
    if status_reasons:
        return "DEGRADED"
    if advisories:
        return "WARN"
    return "OK"


def _recommended_actions(
    status_reasons: List[str],
    advisories: List[str],
    production_checks: bool,
) -> List[str]:
    actions: List[str] = []
    if any(reason == "preflight:key_management_passed" for reason in status_reasons):
        actions.append(
            "Set a strong NETWORK_SHARED_SECRET (>=32 chars, mixed classes) and rerun with --production-checks."
        )
    if any(reason == "preflight:account_registry_passed" for reason in status_reasons):
        actions.append(
            "Set OWNER_ID, PRIVATE_RPC_URL, PRIVATE_API_TOKEN, and unique WALLET_* values in .env for production."
        )
    if any(reason in {"qa_failed", "qa_execution_error"} for reason in status_reasons):
        actions.append(
            "Run `python3 scripts/airn.py check --production-checks` and fix failing checks."
        )
    if "open_mainnet_failed" in status_reasons:
        actions.append("Inspect launch gate checks and resolve unmet preflight conditions before opening mainnet.")
    if "production_readiness_false" in advisories and not production_checks:
        actions.append(
            "Generate strict readiness view with `python3 scripts/airn.py status --production-checks`."
        )
    if not actions and status_reasons:
        actions.append("Investigate status_reasons and rerun QA plus production-checks before publish.")
    return actions


def _status_fingerprint(payload: Dict[str, Any]) -> str:
    basis = {
        "mode": payload.get("mode"),
        "protocol_name": payload.get("protocol_name"),
        "protocol_id": payload.get("protocol_id"),
        "status_ok": payload.get("status_ok"),
        "health_level": payload.get("health_level"),
        "status_reasons": payload.get("status_reasons"),
        "launch_error": payload.get("launch_error"),
        "qa_error": payload.get("qa_error"),
        "advisories": payload.get("advisories"),
        "recommended_actions": payload.get("recommended_actions"),
        "production_checks": payload.get("production_checks"),
        "network_size_nodes": payload.get("network_size_nodes"),
        "avg_winner_latency_ms": payload.get("avg_winner_latency_ms"),
        "requests_executed": payload.get("requests_executed"),
        "preflight_checks": payload.get("preflight_checks"),
        "production_readiness": payload.get("production_readiness"),
        "qa_overall_passed": payload.get("qa_overall_passed"),
        "qa_agent_count": payload.get("qa_agent_count"),
        "launch_state": payload.get("launch_state"),
        "snapshot": payload.get("snapshot"),
        "top_node_balances": payload.get("top_node_balances"),
        "node_details": payload.get("node_details"),
        "recent_requests": payload.get("recent_requests"),
    }
    encoded = json.dumps(to_jsonable(basis), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _history_entry(payload: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = payload.get("snapshot", {})
    return {
        "generated_at_utc": payload.get("generated_at_utc"),
        "status_fingerprint": payload.get("status_fingerprint") or _status_fingerprint(payload),
        "health_level": payload.get("health_level"),
        "status_ok": bool(payload.get("status_ok")),
        "production_checks": bool(payload.get("production_checks")),
        "qa_overall_passed": bool(payload.get("qa_overall_passed")),
        "network_size_nodes": int(payload.get("network_size_nodes", 0)),
        "avg_winner_latency_ms": payload.get("avg_winner_latency_ms"),
        "requests_executed": int(payload.get("requests_executed", 0)),
        "epoch": snapshot.get("epoch"),
        "minted_supply": snapshot.get("minted_supply"),
        "status_reasons": list(payload.get("status_reasons", [])),
        "advisories": list(payload.get("advisories", [])),
        "recommended_actions": list(payload.get("recommended_actions", [])),
    }


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _history_hash_basis(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "generated_at_utc": entry.get("generated_at_utc"),
        "status_fingerprint": entry.get("status_fingerprint"),
        "health_level": entry.get("health_level"),
        "status_ok": bool(entry.get("status_ok")),
        "production_checks": bool(entry.get("production_checks")),
        "qa_overall_passed": bool(entry.get("qa_overall_passed")),
        "network_size_nodes": int(entry.get("network_size_nodes", 0)),
        "avg_winner_latency_ms": entry.get("avg_winner_latency_ms"),
        "requests_executed": int(entry.get("requests_executed", 0)),
        "epoch": entry.get("epoch"),
        "minted_supply": entry.get("minted_supply"),
        "status_reasons": list(entry.get("status_reasons", [])),
        "advisories": list(entry.get("advisories", [])),
        "recommended_actions": list(entry.get("recommended_actions", [])),
        "previous_history_hash": str(entry.get("previous_history_hash", "")),
    }


def _compute_history_hash(entry: Dict[str, Any]) -> str:
    encoded = json.dumps(
        to_jsonable(_history_hash_basis(entry)),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _latest_history_hash(entries: List[Dict[str, Any]]) -> str:
    for item in reversed(entries):
        candidate = str(item.get("history_hash", ""))
        if _is_sha256_hex(candidate):
            return candidate
    return ""


def _rebuild_history_chain(entries: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], bool]:
    rebuilt: List[Dict[str, Any]] = []
    previous_hash = ""
    repaired = False
    for raw_item in entries:
        item = dict(raw_item)
        old_prev = str(item.get("previous_history_hash", ""))
        old_hash = str(item.get("history_hash", ""))
        item["previous_history_hash"] = previous_hash
        item["history_hash"] = _compute_history_hash(item)
        if old_prev != item["previous_history_hash"] or old_hash != item["history_hash"]:
            repaired = True
        previous_hash = item["history_hash"]
        rebuilt.append(item)
    return rebuilt, repaired


def _history_chain_summary(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    tracked_entries = 0
    valid = True
    broken_index = -1
    broken_reason = ""
    previous_hash = ""
    latest_hash = ""

    for idx, item in enumerate(entries):
        entry_hash = str(item.get("history_hash", ""))
        if not entry_hash:
            continue

        tracked_entries += 1
        if not _is_sha256_hex(entry_hash):
            valid = False
            broken_index = idx
            broken_reason = "history_hash format invalid"
            break

        stated_prev = str(item.get("previous_history_hash", ""))
        if stated_prev != previous_hash:
            valid = False
            broken_index = idx
            broken_reason = "previous_history_hash mismatch"
            break

        expected = _compute_history_hash(item)
        if not _is_sha256_hex(expected) or expected != entry_hash:
            valid = False
            broken_index = idx
            broken_reason = "history_hash verification failed"
            break

        latest_hash = entry_hash
        previous_hash = entry_hash

    return {
        "enabled": tracked_entries > 0,
        "valid": valid,
        "tracked_entries": tracked_entries,
        "legacy_entries": max(0, len(entries) - tracked_entries),
        "broken_index": broken_index,
        "broken_reason": broken_reason,
        "latest_hash": latest_hash,
    }


def _parse_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _history_trend(entries: List[Dict[str, Any]], recent_window: int = 20) -> Dict[str, Any]:
    if not entries:
        return {
            "recent_window": recent_window,
            "sample_size": 0,
            "health_counts": {"OK": 0, "WARN": 0, "DEGRADED": 0},
            "latest_health": "",
            "previous_health": "",
            "health_changed": False,
            "avg_latency_delta_ms": 0.0,
            "epoch_delta": 0,
        }

    recent = entries[-recent_window:] if recent_window > 0 else entries
    health_counts = {"OK": 0, "WARN": 0, "DEGRADED": 0}
    for item in recent:
        health = str(item.get("health_level", "")).upper()
        if health in health_counts:
            health_counts[health] += 1

    latest = recent[-1]
    previous = recent[-2] if len(recent) >= 2 else {}
    latest_latency = _parse_float(latest.get("avg_winner_latency_ms"))
    previous_latency = _parse_float(previous.get("avg_winner_latency_ms"))
    latency_delta = 0.0
    if latest_latency is not None and previous_latency is not None:
        latency_delta = round(latest_latency - previous_latency, 4)

    epoch_delta = 0
    latest_epoch = latest.get("epoch")
    previous_epoch = previous.get("epoch")
    if isinstance(latest_epoch, int) and isinstance(previous_epoch, int):
        epoch_delta = latest_epoch - previous_epoch

    latest_health = str(latest.get("health_level", ""))
    previous_health = str(previous.get("health_level", ""))

    return {
        "recent_window": recent_window,
        "sample_size": len(recent),
        "health_counts": health_counts,
        "latest_health": latest_health,
        "previous_health": previous_health,
        "health_changed": bool(previous and latest_health != previous_health),
        "avg_latency_delta_ms": latency_delta,
        "epoch_delta": epoch_delta,
    }


def _read_history(history_path: Path) -> List[Dict[str, Any]]:
    if not history_path.exists():
        return []
    entries: List[Dict[str, Any]] = []
    with open(history_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                entries.append(item)
    return entries


def append_history(
    history_path: Path,
    payload: Dict[str, Any],
    max_entries: int = 500,
    recent_limit: int = 5,
    trend_window: int = 20,
    skip_if_unchanged: bool = True,
) -> Dict[str, Any]:
    entries = _read_history(history_path)
    chain_before = _history_chain_summary(entries)
    new_entry = _history_entry(payload)
    history_appended = True
    trimmed = False
    history_chain_repaired = False
    history_append_blocked = False

    if chain_before["enabled"] and not chain_before["valid"]:
        history_appended = False
        history_append_blocked = True
    else:
        entries, repaired = _rebuild_history_chain(entries)
        history_chain_repaired = history_chain_repaired or repaired

        if skip_if_unchanged and entries:
            last_fingerprint = str(entries[-1].get("status_fingerprint", ""))
            new_fingerprint = str(new_entry.get("status_fingerprint", ""))
            if last_fingerprint and new_fingerprint and last_fingerprint == new_fingerprint:
                history_appended = False

        if history_appended:
            previous_hash = _latest_history_hash(entries)
            new_entry["previous_history_hash"] = previous_hash
            new_entry["history_hash"] = _compute_history_hash(new_entry)
            entries.append(new_entry)

        if max_entries > 0 and len(entries) > max_entries:
            trimmed = True
            entries = entries[-max_entries:]
            entries, repaired = _rebuild_history_chain(entries)
            history_chain_repaired = history_chain_repaired or repaired

    chain_summary = _history_chain_summary(entries)

    if history_appended or trimmed or history_chain_repaired or not history_path.exists():
        history_path.parent.mkdir(parents=True, exist_ok=True)
        with open(history_path, "w", encoding="utf-8") as handle:
            for item in entries:
                handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    return {
        "history_total_entries": len(entries),
        "recent_history": entries[-recent_limit:] if recent_limit > 0 else [],
        "history_trend": _history_trend(entries, recent_window=trend_window),
        "history_appended": history_appended,
        "history_append_blocked": history_append_blocked,
        "history_chain_repaired": history_chain_repaired,
        "history_chain": chain_summary,
    }


def build_status_payload(production_checks: bool, launch_state_path: str) -> Dict[str, Any]:
    identities = IdentityRegistry.from_env()
    network = TranslationNetwork()
    checks = network.run_preflight_checks(security_scan_passed=True, production_mode=production_checks)
    production_readiness = _production_readiness_snapshot()
    status_reasons: List[str] = []
    advisories: List[str] = []
    launch_error = ""
    outputs: List[Dict[str, Any]] = []

    if all(checks.values()):
        try:
            network.open_mainnet()
            for envelope in network.build_demo_requests():
                outputs.append(network.process_request(envelope))
        except Exception as exc:
            launch_error = str(exc)
            status_reasons.append("open_mainnet_failed")
    else:
        blocked = _failed_preflight_reasons(checks)
        status_reasons.extend([f"preflight:{name}" for name in blocked])
        launch_error = f"Launch blocked. Unmet checks: {', '.join(blocked)}"

    snapshot = to_jsonable(network.state_snapshot())

    sentinel = UnstoppableLaunchSentinel(
        state_path=launch_state_path,
        owner_id=identities.owner_id,
    )
    launch_state = sentinel.snapshot()

    qa = _safe_run_qa_suite(production_checks=production_checks)
    avg_latency = 0.0
    if outputs:
        avg_latency = sum(float(item["winner_latency_ms"]) for item in outputs) / len(outputs)
    if not qa["overall_passed"]:
        status_reasons.append("qa_failed")
        if qa["error"]:
            status_reasons.append("qa_execution_error")

    if not production_checks and not production_readiness["ready"]:
        advisories.append("production_readiness_false")

    status_ok = not status_reasons
    health_level = _health_level(status_reasons=status_reasons, advisories=advisories)
    recommended_actions = _recommended_actions(
        status_reasons=status_reasons,
        advisories=advisories,
        production_checks=production_checks,
    )

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "network-status-agent",
        "protocol_name": PROTOCOL_NAME,
        "protocol_id": PROTOCOL_ID,
        "status_ok": status_ok,
        "health_level": health_level,
        "status_reasons": status_reasons,
        "launch_error": launch_error,
        "qa_error": qa["error"],
        "advisories": advisories,
        "recommended_actions": recommended_actions,
        "production_checks": production_checks,
        "network_size_nodes": len(network.nodes),
        "avg_winner_latency_ms": round(avg_latency, 2),
        "requests_executed": len(outputs),
        "preflight_checks": checks,
        "production_readiness": production_readiness,
        "qa_overall_passed": qa["overall_passed"],
        "qa_agent_count": qa["agent_count"],
        "launch_state": launch_state,
        "snapshot": snapshot,
        "top_node_balances": _top_node_balances(snapshot, limit=5),
        "node_details": _node_details(snapshot),
        "recent_requests": _request_details(outputs),
    }
    return payload


def render_markdown(payload: Dict[str, Any]) -> str:
    snapshot = payload["snapshot"]
    launch_state = payload["launch_state"]
    top_nodes = payload["top_node_balances"]
    node_details = payload.get("node_details", [])
    recent_requests = payload.get("recent_requests", [])
    checks = payload["preflight_checks"]
    prod_readiness = payload.get("production_readiness", {"ready": False, "checks": {}})
    prod_checks = prod_readiness.get("checks", {})
    status_reasons = payload.get("status_reasons", [])
    advisories = payload.get("advisories", [])
    recommended_actions = payload.get("recommended_actions", [])
    recent_history = payload.get("recent_history", [])
    history_trend = payload.get("history_trend", {})
    history_total_entries = payload.get("history_total_entries", 0)
    history_chain = payload.get("history_chain", {})
    status_fingerprint = payload.get("status_fingerprint", "")
    history_appended = payload.get("history_appended", True)
    history_append_blocked = payload.get("history_append_blocked", False)
    history_chain_repaired = payload.get("history_chain_repaired", False)
    history_path = payload.get("history_path", "docs/NETWORK_HISTORY.jsonl")
    launch_error = payload.get("launch_error", "")
    qa_error = payload.get("qa_error", "")
    checks_lines = "\n".join(
        f"- `{k}`: `{v}`" for k, v in checks.items()
    )
    top_node_lines = "\n".join(
        f"- `{node}`: `{balance}`" for node, balance in top_nodes
    ) or "- none"
    node_table_lines = "\n".join(
        f"| {item.get('rank')} | `{item.get('node_id')}` | `{item.get('balance')}` | "
        f"`{item.get('share_of_node_balance_pct')}%` | `{item.get('slash_points')}` | `{item.get('wallet_preview')}` |"
        for item in node_details
    ) or "| - | - | - | - | - | - |"
    request_lines = "\n".join(
        f"- `{item.get('request_id')}` | requester=`{item.get('requester_node')}` | "
        f"winner=`{item.get('winner_node')}` | latency=`{item.get('winner_latency_ms')} ms` | "
        f"emission=`{item.get('emission')}` | output=`{item.get('final_output')}`"
        for item in recent_requests
    ) or "- none"
    status_reason_lines = "\n".join(f"- `{reason}`" for reason in status_reasons) or "- none"
    advisory_lines = "\n".join(f"- `{advisory}`" for advisory in advisories) or "- none"
    recommended_action_lines = "\n".join(f"- {action}" for action in recommended_actions) or "- none"
    prod_checks_lines = "\n".join(f"- `{name}`: `{passed}`" for name, passed in prod_checks.items()) or "- none"
    recent_history_lines = "\n".join(
        f"- `{item.get('generated_at_utc')}` | health=`{item.get('health_level')}` | "
        f"epoch=`{item.get('epoch')}` | minted=`{item.get('minted_supply')}` | "
        f"latency=`{item.get('avg_winner_latency_ms')}`"
        for item in recent_history
    ) or "- none"
    trend_health_counts = history_trend.get("health_counts", {"OK": 0, "WARN": 0, "DEGRADED": 0})
    health = payload.get("health_level", "DEGRADED")
    balances = snapshot.get("balances", {})

    return f"""# Autonomous AI Reward Network Status (DPUIN)

Generated at: `{payload['generated_at_utc']}`

## Summary

- Protocol: `{payload['protocol_name']}` (`{payload['protocol_id']}`)
- Health: `{health}`
- Network nodes: `{payload['network_size_nodes']}`
- QA overall: `{payload['qa_overall_passed']}` (`{payload['qa_agent_count']}` agents)
- Avg winner latency: `{payload['avg_winner_latency_ms']} ms`
- Production checks mode: `{payload['production_checks']}`
- Requests executed: `{payload.get('requests_executed')}`

## Friendly Overview

- Current operator view: health=`{health}`, status_ok=`{payload.get('status_ok')}`
- Mainnet state: `open={snapshot.get('mainnet_open')}`, `epoch={snapshot.get('epoch')}`, `model={snapshot.get('model_version')}`
- Performance: average winner latency `{payload['avg_winner_latency_ms']} ms`
- Participation: `{payload['network_size_nodes']}` nodes, `{payload.get('requests_executed')}` processed requests in this snapshot

## Status Reasons

{status_reason_lines}

## Advisories

{advisory_lines}

## Recommended Actions

{recommended_action_lines}

## Production Readiness

- Ready: `{prod_readiness.get('ready')}`

### Production Checks

{prod_checks_lines}

## Errors

- Launch error: `{launch_error or '-'}`
- QA error: `{qa_error or '-'}`

## Recent History

- History file: `{history_path}`
- Total history entries: `{history_total_entries}`
- History appended this run: `{history_appended}`
- History append blocked: `{history_append_blocked}`
- History chain repaired: `{history_chain_repaired}`
- Status fingerprint: `{status_fingerprint}`

{recent_history_lines}

## History Integrity

- Chain enabled: `{history_chain.get('enabled')}`
- Chain valid: `{history_chain.get('valid')}`
- Tracked entries: `{history_chain.get('tracked_entries')}`
- Legacy entries: `{history_chain.get('legacy_entries')}`
- Latest chain hash: `{history_chain.get('latest_hash') or '-'}`
- Broken index: `{history_chain.get('broken_index')}`
- Broken reason: `{history_chain.get('broken_reason') or '-'}`

## History Trend

- Window size: `{history_trend.get('recent_window')}`
- Sample size: `{history_trend.get('sample_size')}`
- Health counts: `OK={trend_health_counts.get('OK')}, WARN={trend_health_counts.get('WARN')}, DEGRADED={trend_health_counts.get('DEGRADED')}`
- Latest health: `{history_trend.get('latest_health')}`
- Previous health: `{history_trend.get('previous_health')}`
- Health changed: `{history_trend.get('health_changed')}`
- Avg latency delta (latest-prev): `{history_trend.get('avg_latency_delta_ms')} ms`
- Epoch delta (latest-prev): `{history_trend.get('epoch_delta')}`

## Launch State

- Armed: `{launch_state.get('armed')}`
- Unstoppable started: `{launch_state.get('unstoppable_started')}`
- Successful open: `{launch_state.get('successful_open')}`
- Started by: `{launch_state.get('started_by_runner')}`
- Last runner: `{launch_state.get('last_runner_id')}`
- Total runs: `{launch_state.get('total_runs')}`
- Start attempts: `{launch_state.get('start_attempts')}`

## Preflight Checks

{checks_lines}

## Token Snapshot

- Epoch: `{snapshot.get('epoch')}`
- Model version: `{snapshot.get('model_version')}`
- Minted supply: `{snapshot.get('minted_supply')}`
- Max supply: `{snapshot.get('max_supply')}`
- Mainnet open: `{snapshot.get('mainnet_open')}`
- Account registry ready: `{snapshot.get('account_registry_ready')}`
- Connection configured: `{snapshot.get('connection_configured')}`

## Treasury Balances

- Founder treasury: `{balances.get('founder_treasury')}`
- Ecosystem treasury: `{balances.get('ecosystem_treasury')}`
- Security treasury: `{balances.get('security_treasury')}`
- Community treasury: `{balances.get('community_treasury')}`

## Top Node Balances

{top_node_lines}

## Node Details (All)

| Rank | Node | Balance | Share of Node Pool | Slash Points | Wallet Preview |
| --- | --- | --- | --- | --- | --- |
{node_table_lines}

## Request Details (Latest Run)

{request_lines}

---

This report is generated by `scripts/network_status_agent.py`.
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Network status agent")
    parser.add_argument("--dotenv-path", default=".env")
    parser.add_argument("--production-checks", action="store_true")
    parser.add_argument("--launch-state-path", default=DEFAULT_LAUNCH_STATE_PATH)
    parser.add_argument("--output-md", default="docs/NETWORK_STATUS.md")
    parser.add_argument("--output-json", default="docs/NETWORK_STATUS.json")
    parser.add_argument("--history-path", default="docs/NETWORK_HISTORY.jsonl")
    parser.add_argument("--history-max-entries", type=int, default=500)
    parser.add_argument("--history-trend-window", type=int, default=20)
    parser.add_argument("--no-history-dedupe", action="store_true")
    parser.add_argument("--stable-output", dest="stable_output", action="store_true", default=True)
    parser.add_argument("--no-stable-output", dest="stable_output", action="store_false")
    return parser.parse_args()


def _load_existing_payload(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def main() -> None:
    args = parse_args()
    load_env_file(args.dotenv_path)

    payload = build_status_payload(
        production_checks=args.production_checks,
        launch_state_path=args.launch_state_path,
    )

    out_md = Path(args.output_md)
    out_json = Path(args.output_json)
    history_path = Path(args.history_path)
    existing_payload = _load_existing_payload(out_json)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    payload["status_fingerprint"] = _status_fingerprint(payload)
    if args.stable_output and existing_payload:
        if existing_payload.get("status_fingerprint") == payload["status_fingerprint"]:
            existing_generated_at = existing_payload.get("generated_at_utc")
            if isinstance(existing_generated_at, str) and existing_generated_at:
                payload["generated_at_utc"] = existing_generated_at

    history_meta = append_history(
        history_path=history_path,
        payload=payload,
        max_entries=max(0, args.history_max_entries),
        trend_window=max(1, args.history_trend_window),
        skip_if_unchanged=not args.no_history_dedupe,
    )
    payload["history_path"] = str(history_path)
    payload["history_total_entries"] = history_meta["history_total_entries"]
    payload["recent_history"] = history_meta["recent_history"]
    payload["history_trend"] = history_meta["history_trend"]
    payload["history_appended"] = history_meta["history_appended"]
    payload["history_append_blocked"] = history_meta["history_append_blocked"]
    payload["history_chain_repaired"] = history_meta["history_chain_repaired"]
    payload["history_chain"] = history_meta["history_chain"]

    markdown = render_markdown(payload)
    out_md.write_text(markdown, encoding="utf-8")
    out_json.write_text(json.dumps(to_jsonable(payload), ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(to_jsonable(payload), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
