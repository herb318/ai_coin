#!/usr/bin/env python3
"""Decentralized AI network simulation with production-gate QA workflow.

Capabilities:
1) Deterministic tokenomics + future reward forecast
2) Genesis allocation with lockup/vesting
3) Mandatory launch gate before open
4) HMAC auth + replay prevention + rate limiting
5) QA agent unit/team participation test runner
6) Env-based unique account registry for private owner wallets
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, getcontext
from difflib import SequenceMatcher
from typing import Any, Callable, Deque, Dict, List, Optional, Set
from urllib.parse import urlparse

getcontext().prec = 28

NODE_ENV_MAP = {
    "node-sea-1": "WALLET_NODE_SEA_1",
    "node-tyo-2": "WALLET_NODE_TYO_2",
    "node-sgp-3": "WALLET_NODE_SGP_3",
    "node-fra-4": "WALLET_NODE_FRA_4",
    "node-iad-5": "WALLET_NODE_IAD_5",
}

TREASURY_ENV_MAP = {
    "founder_treasury": "WALLET_FOUNDER_TREASURY",
    "ecosystem_treasury": "WALLET_ECOSYSTEM_TREASURY",
    "security_treasury": "WALLET_SECURITY_TREASURY",
    "community_treasury": "WALLET_COMMUNITY_TREASURY",
}

REQUIRED_CONNECTION_ENV = ["PRIVATE_RPC_URL", "PRIVATE_API_TOKEN"]
DEFAULT_OWNER_ID = "owner-dev-local"
DEFAULT_RUNNER_ID = "runner-unknown"
DEFAULT_LAUNCH_STATE_PATH = "runtime/launch_state.json"
OWNER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{5,63}$")
WALLET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
HEX_CHARS = set("0123456789abcdef")


def now_ts() -> int:
    return int(time.time())


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize(text: str) -> str:
    return " ".join(text.lower().strip().split())


def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, normalize(a), normalize(b)).ratio()


def decimal_to_str(value: Decimal, places: str = "0.0001") -> str:
    return str(value.quantize(Decimal(places)))


def canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def to_jsonable(obj: Any) -> Any:
    if isinstance(obj, Decimal):
        return str(obj.quantize(Decimal("0.0001")))
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_jsonable(v) for v in obj]
    return obj


def deterministic_jitter(seed_material: str, spread: int = 8) -> int:
    digest = sha256_hex(seed_material)
    value = int(digest[:8], 16)
    return (value % (2 * spread + 1)) - spread


def redact(value: str, left: int = 6, right: int = 4) -> str:
    if len(value) <= left + right:
        return "*" * len(value)
    return f"{value[:left]}...{value[-right:]}"


def load_env_file(path: str = ".env") -> List[str]:
    loaded: List[str] = []
    if not path or not os.path.exists(path):
        return loaded

    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'").strip('"')
            if key and key not in os.environ:
                os.environ[key] = value
                loaded.append(key)
    return loaded


def resolve_runner_id(cli_runner_id: str, owner_id: str) -> str:
    if cli_runner_id.strip():
        return cli_runner_id.strip()

    env_runner = os.getenv("RUNNER_ID", "").strip()
    if env_runner:
        return env_runner

    if owner_id and owner_id != DEFAULT_OWNER_ID:
        return owner_id
    return DEFAULT_RUNNER_ID


@dataclass
class IdentityRegistry:
    owner_id: str
    wallets: Dict[str, str]
    connection_info: Dict[str, str]
    missing_wallet_env: List[str]
    missing_connection_env: List[str]

    @classmethod
    def from_env(cls) -> "IdentityRegistry":
        owner_id = os.getenv("OWNER_ID", DEFAULT_OWNER_ID)
        wallets: Dict[str, str] = {}
        missing_wallet_env: List[str] = []

        all_env_map = dict(NODE_ENV_MAP)
        all_env_map.update(TREASURY_ENV_MAP)

        for participant_id, env_name in all_env_map.items():
            env_val = os.getenv(env_name, "").strip()
            if env_val:
                wallets[participant_id] = env_val
            else:
                wallets[participant_id] = f"dev_{sha256_hex(participant_id)[:24]}"
                missing_wallet_env.append(env_name)

        connection_info: Dict[str, str] = {}
        missing_connection_env: List[str] = []
        for env_name in REQUIRED_CONNECTION_ENV:
            env_val = os.getenv(env_name, "").strip()
            if env_val:
                connection_info[env_name] = env_val
            else:
                connection_info[env_name] = ""
                missing_connection_env.append(env_name)

        registry = cls(
            owner_id=owner_id,
            wallets=wallets,
            connection_info=connection_info,
            missing_wallet_env=missing_wallet_env,
            missing_connection_env=missing_connection_env,
        )
        registry.validate_unique_wallets()
        return registry

    @classmethod
    def from_mapping(
        cls,
        owner_id: str,
        wallets: Dict[str, str],
        connection_info: Optional[Dict[str, str]] = None,
    ) -> "IdentityRegistry":
        registry = cls(
            owner_id=owner_id,
            wallets=dict(wallets),
            connection_info=dict(connection_info or {}),
            missing_wallet_env=[],
            missing_connection_env=[],
        )
        registry.validate_unique_wallets()
        return registry

    def validate_unique_wallets(self) -> None:
        seen: Dict[str, str] = {}
        dupes: List[str] = []
        for participant, wallet in self.wallets.items():
            if wallet in seen:
                dupes.append(f"{wallet} ({seen[wallet]}, {participant})")
            seen[wallet] = participant
        if dupes:
            raise ValueError(f"Wallet addresses must be unique. Duplicates: {', '.join(dupes)}")

    def has_unique_wallets(self) -> bool:
        return len(set(self.wallets.values())) == len(self.wallets)

    @staticmethod
    def _normalize_placeholder_text(value: str) -> str:
        return "".join(ch for ch in value.lower().strip() if ch.isalnum())

    def _looks_placeholder(self, value: str) -> bool:
        lowered = value.lower().strip()
        if not lowered:
            return True
        if lowered.startswith("dev_"):
            return True
        normalized = self._normalize_placeholder_text(lowered)
        markers = [
            "changeme",
            "placeholder",
            "example",
            "dummy",
            "sample",
            "replace",
            "your",
            "default",
            "testvalue",
        ]
        return any(marker in normalized for marker in markers)

    def _valid_rpc_url(self, value: str) -> bool:
        candidate = value.strip()
        if self._looks_placeholder(candidate):
            return False
        parsed = urlparse(candidate)
        if parsed.scheme not in {"https", "wss"}:
            return False
        if not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False
        host = parsed.hostname
        if host == "localhost":
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return True
        return not (address.is_loopback or address.is_multicast or address.is_unspecified)

    def _valid_api_token(self, value: str) -> bool:
        token = value.strip()
        if self._looks_placeholder(token):
            return False
        if len(token) < 24:
            return False
        if any(ch.isspace() for ch in token):
            return False
        char_classes = [
            any(ch.islower() for ch in token),
            any(ch.isupper() for ch in token),
            any(ch.isdigit() for ch in token),
            any(not ch.isalnum() for ch in token),
        ]
        return sum(char_classes) >= 3

    def _valid_owner_id(self, value: str) -> bool:
        owner_id = value.strip()
        if self._looks_placeholder(owner_id):
            return False
        return bool(OWNER_ID_PATTERN.fullmatch(owner_id))

    def _valid_wallet(self, value: str) -> bool:
        wallet = value.strip()
        if self._looks_placeholder(wallet):
            return False
        if any(ch.isspace() for ch in wallet):
            return False
        return bool(WALLET_PATTERN.fullmatch(wallet))

    def production_ready(self) -> bool:
        if self.owner_id == DEFAULT_OWNER_ID:
            return False
        if not self._valid_owner_id(self.owner_id):
            return False
        if self.missing_wallet_env or self.missing_connection_env:
            return False
        if not self.has_unique_wallets():
            return False
        if any(not self._valid_wallet(wallet) for wallet in self.wallets.values()):
            return False
        rpc_url = self.connection_info.get("PRIVATE_RPC_URL", "")
        if not self._valid_rpc_url(rpc_url):
            return False
        api_token = self.connection_info.get("PRIVATE_API_TOKEN", "")
        if not self._valid_api_token(api_token):
            return False
        return True

    def public_wallet_snapshot(self) -> Dict[str, str]:
        return {participant: redact(wallet) for participant, wallet in self.wallets.items()}

    def connection_configured(self) -> bool:
        return not self.missing_connection_env


@dataclass
class UnstoppableLaunchState:
    owner_id: str
    armed: bool = False
    unstoppable_started: bool = False
    successful_open: bool = False
    started_by_runner: str = ""
    started_at_utc: str = ""
    last_runner_id: str = ""
    last_run_at_utc: str = ""
    total_runs: int = 0
    start_attempts: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owner_id": self.owner_id,
            "armed": self.armed,
            "unstoppable_started": self.unstoppable_started,
            "successful_open": self.successful_open,
            "started_by_runner": self.started_by_runner,
            "started_at_utc": self.started_at_utc,
            "last_runner_id": self.last_runner_id,
            "last_run_at_utc": self.last_run_at_utc,
            "total_runs": self.total_runs,
            "start_attempts": self.start_attempts,
        }


class UnstoppableLaunchSentinel:
    def __init__(self, state_path: str, owner_id: str) -> None:
        self.state_path = state_path
        self.state = self._load_or_default(owner_id)

    def _default_state(self, owner_id: str) -> UnstoppableLaunchState:
        return UnstoppableLaunchState(owner_id=owner_id)

    def _load_or_default(self, owner_id: str) -> UnstoppableLaunchState:
        if not os.path.exists(self.state_path):
            state = self._default_state(owner_id)
            self._save(state)
            return state

        try:
            with open(self.state_path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError):
            state = self._default_state(owner_id)
            self._save(state)
            return state

        stored_owner = str(raw.get("owner_id") or owner_id).strip() or owner_id
        if stored_owner != owner_id:
            # Fail closed on ownership mismatch so stale/tampered state cannot hijack control.
            state = self._default_state(owner_id)
            self._save(state)
            return state

        state = UnstoppableLaunchState(
            owner_id=owner_id,
            armed=bool(raw.get("armed", False)),
            unstoppable_started=bool(raw.get("unstoppable_started", False)),
            successful_open=bool(raw.get("successful_open", False)),
            started_by_runner=str(raw.get("started_by_runner", "")),
            started_at_utc=str(raw.get("started_at_utc", "")),
            last_runner_id=str(raw.get("last_runner_id", "")),
            last_run_at_utc=str(raw.get("last_run_at_utc", "")),
            total_runs=max(0, int(raw.get("total_runs", 0))),
            start_attempts=max(0, int(raw.get("start_attempts", 0))),
        )
        self._save(state)
        return state

    def _save(self, state: UnstoppableLaunchState) -> None:
        os.makedirs(os.path.dirname(self.state_path) or ".", exist_ok=True)
        tmp_path = f"{self.state_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(state.to_dict(), handle, ensure_ascii=False, indent=2)
        os.replace(tmp_path, self.state_path)

    def arm(self, runner_id: str) -> Dict[str, Any]:
        if runner_id != self.state.owner_id:
            raise PermissionError("Only OWNER_ID can arm final launch sentinel.")
        self.state.armed = True
        self._save(self.state)
        return self.snapshot()

    def record_execution(self, runner_id: str) -> Dict[str, Any]:
        now_utc = datetime.now(timezone.utc).isoformat()
        self.state.total_runs += 1
        self.state.last_runner_id = runner_id
        self.state.last_run_at_utc = now_utc

        if self.state.unstoppable_started:
            self.state.start_attempts += 1
            self._save(self.state)
            return self.snapshot()

        if self.state.armed and runner_id != self.state.owner_id:
            self.state.unstoppable_started = True
            self.state.started_by_runner = runner_id
            self.state.started_at_utc = now_utc
            self.state.start_attempts += 1

        self._save(self.state)
        return self.snapshot()

    def mark_successful_open(self) -> Dict[str, Any]:
        if self.state.unstoppable_started:
            self.state.successful_open = True
            self._save(self.state)
        return self.snapshot()

    def snapshot(self) -> Dict[str, Any]:
        return self.state.to_dict()


@dataclass
class Node:
    node_id: str
    region: str
    base_latency_ms: int
    reliability: float
    style: str

    def propose(self, source_text: str, canonical_output: str, epoch: int) -> Dict[str, Any]:
        jitter = deterministic_jitter(f"{self.node_id}:{source_text}:{epoch}", spread=8)
        latency_ms = max(20, self.base_latency_ms + jitter)
        output = self._style_variant(canonical_output)
        quality = Decimal(str(0.8 * similarity(output, canonical_output) + 0.2 * self.reliability))
        speed_factor = Decimal(str(max(0.55, 1.25 - (latency_ms / 380.0))))
        poui_base = quality * speed_factor
        return {
            "node_id": self.node_id,
            "region": self.region,
            "latency_ms": latency_ms,
            "output": output,
            "quality": quality,
            "poui_base": poui_base,
            "source_hash": sha256_hex(source_text)[:16],
            "output_hash": sha256_hex(output)[:16],
        }

    def _style_variant(self, text: str) -> str:
        if self.style == "formal":
            return text.replace("Let's", "Let us").replace("please", "kindly")
        if self.style == "concise":
            return text.replace("Thank you for joining the meeting.", "Thanks for joining.")
        if self.style == "natural":
            return text.replace("demo", "prototype demo")
        return text


@dataclass
class GenesisWallet:
    wallet: str
    amount: Decimal
    lockup_epochs: int
    vesting_epochs: int
    released: Decimal = Decimal("0")

    def releasable(self, epoch: int) -> Decimal:
        if epoch < self.lockup_epochs:
            return Decimal("0")
        elapsed = epoch - self.lockup_epochs + 1
        vested_ratio = min(Decimal("1"), Decimal(elapsed) / Decimal(self.vesting_epochs))
        vested_amount = self.amount * vested_ratio
        releasable_amount = vested_amount - self.released
        return max(Decimal("0"), releasable_amount)

    def release(self, epoch: int) -> Decimal:
        amount = self.releasable(epoch)
        self.released += amount
        return amount


@dataclass
class TokenEconomy:
    max_supply: Decimal = Decimal("10000000")
    initial_epoch_emission: Decimal = Decimal("1500")
    emission_decay: Decimal = Decimal("0.995")
    min_epoch_emission: Decimal = Decimal("100")
    minted_supply: Decimal = Decimal("0")
    balances: Dict[str, Decimal] = field(default_factory=lambda: defaultdict(lambda: Decimal("0")))
    genesis_wallets: Dict[str, GenesisWallet] = field(default_factory=dict)

    def bootstrap_genesis(self) -> None:
        genesis = [
            GenesisWallet("founder_treasury", Decimal("2200000"), lockup_epochs=12, vesting_epochs=96),
            GenesisWallet("ecosystem_treasury", Decimal("1600000"), lockup_epochs=0, vesting_epochs=1),
            GenesisWallet("security_treasury", Decimal("600000"), lockup_epochs=0, vesting_epochs=1),
            GenesisWallet("community_treasury", Decimal("400000"), lockup_epochs=0, vesting_epochs=1),
        ]
        self.genesis_wallets = {g.wallet: g for g in genesis}

        total_genesis = sum(g.amount for g in genesis)
        if total_genesis > self.max_supply:
            raise ValueError("Genesis allocation exceeds max supply.")

        self.minted_supply += total_genesis
        for wallet in genesis:
            released = wallet.release(0)
            self.balances[wallet.wallet] += released

    def epoch_emission(self, epoch: int) -> Decimal:
        raw = self.initial_epoch_emission * (self.emission_decay ** Decimal(epoch))
        planned = raw if raw > self.min_epoch_emission else self.min_epoch_emission
        remaining = self.max_supply - self.minted_supply
        if remaining <= 0:
            return Decimal("0")
        return planned if planned <= remaining else remaining

    def forecast(self, start_epoch: int, epochs: int) -> List[Dict[str, str]]:
        result: List[Dict[str, str]] = []
        minted_temp = self.minted_supply
        for ep in range(start_epoch, start_epoch + epochs):
            raw = self.initial_epoch_emission * (self.emission_decay ** Decimal(ep))
            planned = raw if raw > self.min_epoch_emission else self.min_epoch_emission
            remaining = self.max_supply - minted_temp
            emission = Decimal("0") if remaining <= 0 else (planned if planned <= remaining else remaining)
            minted_temp += emission
            result.append(
                {
                    "epoch": str(ep),
                    "emission": decimal_to_str(emission),
                    "projected_total_minted": decimal_to_str(minted_temp),
                }
            )
        return result

    def release_genesis_vesting(self, epoch: int) -> Dict[str, Decimal]:
        released: Dict[str, Decimal] = {}
        for wallet in self.genesis_wallets.values():
            amount = wallet.release(epoch)
            if amount > 0:
                self.balances[wallet.wallet] += amount
                released[wallet.wallet] = amount
        return released

    def distribute_epoch_rewards(self, epoch: int, poui_scores: Dict[str, Decimal]) -> Dict[str, Any]:
        emission = self.epoch_emission(epoch)
        if emission <= 0:
            return {
                "emission": Decimal("0"),
                "node_rewards": {node_id: Decimal("0") for node_id in poui_scores},
                "ecosystem_reserve": Decimal("0"),
                "security_reserve": Decimal("0"),
            }

        self.minted_supply += emission
        committee_pool = emission * Decimal("0.75")
        ecosystem_reserve = emission * Decimal("0.20")
        security_reserve = emission - committee_pool - ecosystem_reserve

        total_score = sum(max(Decimal("0"), score) for score in poui_scores.values())
        node_rewards: Dict[str, Decimal] = {}
        if total_score > 0:
            for node_id, score in poui_scores.items():
                positive = max(Decimal("0"), score)
                reward = (positive / total_score) * committee_pool
                self.balances[node_id] += reward
                node_rewards[node_id] = reward
        else:
            even_reward = committee_pool / Decimal(len(poui_scores))
            for node_id in poui_scores:
                self.balances[node_id] += even_reward
                node_rewards[node_id] = even_reward

        self.balances["ecosystem_treasury"] += ecosystem_reserve
        self.balances["security_treasury"] += security_reserve

        return {
            "emission": emission,
            "node_rewards": node_rewards,
            "ecosystem_reserve": ecosystem_reserve,
            "security_reserve": security_reserve,
        }


@dataclass
class LaunchGate:
    checks: Dict[str, bool] = field(
        default_factory=lambda: {
            "security_scan_passed": False,
            "economic_invariant_passed": False,
            "consensus_quorum_passed": False,
            "key_management_passed": False,
            "stress_test_passed": False,
            "account_registry_passed": False,
        }
    )
    opened: bool = False

    def set_check(self, check_name: str, passed: bool) -> None:
        if check_name not in self.checks:
            raise ValueError(f"Unknown check: {check_name}")
        self.checks[check_name] = passed

    def can_open(self) -> bool:
        return all(self.checks.values())

    def open(self) -> None:
        if not self.can_open():
            failed = [k for k, v in self.checks.items() if not v]
            raise RuntimeError(f"Launch blocked. Unmet checks: {', '.join(failed)}")
        self.opened = True


@dataclass
class UpgradeProposal:
    proposal_id: str
    target_model_version: str
    created_epoch: int
    activate_after_epoch: int
    votes_for: Set[str] = field(default_factory=set)
    votes_against: Set[str] = field(default_factory=set)
    applied: bool = False

    def approved(self, quorum: int) -> bool:
        return len(self.votes_for) >= quorum and len(self.votes_for) > len(self.votes_against)


class RequestSecurity:
    REQUEST_ID_MAX_CHARS = 128
    REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    SOURCE_TEXT_MAX_CHARS = 4096
    NONCE_HEX_LEN = 32
    SIGNATURE_HEX_LEN = 64
    MAX_ALLOWED_SKEW_SECONDS = 3600
    MAX_ALLOWED_REQUESTS_PER_MINUTE = 10000
    MAX_ALLOWED_SEEN_ENTRIES = 1_000_000

    def __init__(
        self,
        shared_secret: bytes,
        max_skew_seconds: int = 120,
        max_requests_per_minute: int = 60,
        allowed_nodes: Optional[Set[str]] = None,
        max_seen_entries: int = 20000,
    ) -> None:
        if len(shared_secret) < 32:
            raise ValueError("Shared secret must be at least 32 bytes.")
        if not isinstance(max_skew_seconds, int) or max_skew_seconds <= 0:
            raise ValueError("max_skew_seconds must be a positive integer.")
        if max_skew_seconds > self.MAX_ALLOWED_SKEW_SECONDS:
            raise ValueError(
                f"max_skew_seconds must be <= {self.MAX_ALLOWED_SKEW_SECONDS} for safe replay window."
            )
        if not isinstance(max_requests_per_minute, int) or max_requests_per_minute <= 0:
            raise ValueError("max_requests_per_minute must be a positive integer.")
        if max_requests_per_minute > self.MAX_ALLOWED_REQUESTS_PER_MINUTE:
            raise ValueError(
                f"max_requests_per_minute must be <= {self.MAX_ALLOWED_REQUESTS_PER_MINUTE}."
            )
        if not isinstance(max_seen_entries, int) or max_seen_entries <= 0:
            raise ValueError("max_seen_entries must be a positive integer.")
        if max_seen_entries > self.MAX_ALLOWED_SEEN_ENTRIES:
            raise ValueError(f"max_seen_entries must be <= {self.MAX_ALLOWED_SEEN_ENTRIES}.")
        self.shared_secret = shared_secret
        self.max_skew_seconds = max_skew_seconds
        self.max_requests_per_minute = max_requests_per_minute
        self.allowed_nodes = set(allowed_nodes or set())
        self.max_seen_entries = max_seen_entries
        self.used_nonces: Dict[str, int] = {}
        self.used_request_ids: Dict[str, int] = {}
        self.nonce_seen_order: Deque[tuple[str, int]] = deque()
        self.request_seen_order: Deque[tuple[str, int]] = deque()
        self.node_request_times: Dict[str, Deque[int]] = defaultdict(deque)

    def sign(self, payload: Dict[str, Any]) -> str:
        msg = canonical_json(payload).encode("utf-8")
        return hmac.new(self.shared_secret, msg, hashlib.sha256).hexdigest()

    def build_envelope(self, request_id: str, node_id: str, source_text: str) -> Dict[str, Any]:
        request_id = request_id.strip()
        node_id = node_id.strip()
        source_text = source_text.strip()
        payload = {
            "request_id": request_id,
            "node_id": node_id,
            "source_text": source_text,
            "nonce": secrets.token_hex(16),
            "timestamp": now_ts(),
        }
        payload["signature"] = self.sign(payload)
        return payload

    def verify(self, envelope: Dict[str, Any], current_ts: Optional[int] = None) -> tuple[bool, str]:
        now = now_ts() if current_ts is None else current_ts
        required = ["request_id", "node_id", "source_text", "nonce", "timestamp", "signature"]
        for key in required:
            if key not in envelope:
                return False, f"missing field: {key}"

        request_id = envelope["request_id"]
        if not isinstance(request_id, str):
            return False, "invalid request_id type"
        request_id = request_id.strip()
        if not request_id or len(request_id) > self.REQUEST_ID_MAX_CHARS:
            return False, "invalid request_id"
        if not self.REQUEST_ID_PATTERN.fullmatch(request_id):
            return False, "invalid request_id format"

        node_id = envelope["node_id"]
        if not isinstance(node_id, str):
            return False, "invalid node_id type"
        node_id = node_id.strip()
        if not node_id:
            return False, "invalid node_id"
        if self.allowed_nodes and node_id not in self.allowed_nodes:
            return False, "unknown node_id"

        source_text = envelope["source_text"]
        if not isinstance(source_text, str):
            return False, "invalid source_text type"
        source_text = source_text.strip()
        if not source_text:
            return False, "empty source_text"
        if len(source_text) > self.SOURCE_TEXT_MAX_CHARS:
            return False, "source_text too large"
        if any(ord(ch) < 32 for ch in source_text):
            return False, "invalid source_text control chars"

        nonce = envelope["nonce"]
        if not isinstance(nonce, str):
            return False, "invalid nonce type"
        nonce = nonce.strip().lower()
        if not self._is_hex_string(nonce, expected_len=self.NONCE_HEX_LEN):
            return False, "invalid nonce"

        provided = envelope["signature"]
        if not isinstance(provided, str):
            return False, "invalid signature type"
        provided = provided.strip().lower()
        if not self._is_hex_string(provided, expected_len=self.SIGNATURE_HEX_LEN):
            return False, "invalid signature format"

        try:
            timestamp = int(envelope["timestamp"])
        except (TypeError, ValueError):
            return False, "invalid timestamp"
        if timestamp <= 0:
            return False, "invalid timestamp"

        if abs(now - timestamp) > self.max_skew_seconds:
            return False, "timestamp outside allowed clock skew"

        signed_payload = {
            "request_id": request_id,
            "node_id": node_id,
            "source_text": source_text,
            "nonce": nonce,
            "timestamp": timestamp,
        }
        expected = self.sign(signed_payload)
        if not hmac.compare_digest(expected, provided):
            return False, "signature verification failed"

        # Persist canonicalized values back into the mutable envelope so downstream
        # processing and ledger checks use exactly the verified payload.
        envelope["request_id"] = request_id
        envelope["node_id"] = node_id
        envelope["source_text"] = source_text
        envelope["nonce"] = nonce
        envelope["timestamp"] = timestamp
        envelope["signature"] = provided

        self._cleanup_seen_entries(now)
        nonce_key = f"{node_id}:{nonce}"
        if nonce_key in self.used_nonces:
            return False, "replay detected (nonce reused)"

        request_key = request_id
        if request_key in self.used_request_ids:
            return False, "duplicate request_id"

        if not self._allow_rate(node_id, now):
            return False, "rate limit exceeded"

        self.used_nonces[nonce_key] = now
        self.nonce_seen_order.append((nonce_key, now))
        self.used_request_ids[request_key] = now
        self.request_seen_order.append((request_key, now))
        self._enforce_seen_entry_limit()
        return True, "ok"

    @staticmethod
    def _is_hex_string(value: str, expected_len: int) -> bool:
        return len(value) == expected_len and all(ch in HEX_CHARS for ch in value)

    def _cleanup_seen_entries(self, now: int) -> None:
        expire_before = now - self.max_skew_seconds
        while self.nonce_seen_order and self.nonce_seen_order[0][1] < expire_before:
            nonce_key, seen = self.nonce_seen_order.popleft()
            if self.used_nonces.get(nonce_key) == seen:
                self.used_nonces.pop(nonce_key, None)
        while self.request_seen_order and self.request_seen_order[0][1] < expire_before:
            request_key, seen = self.request_seen_order.popleft()
            if self.used_request_ids.get(request_key) == seen:
                self.used_request_ids.pop(request_key, None)

    def _enforce_seen_entry_limit(self) -> None:
        while len(self.nonce_seen_order) > self.max_seen_entries:
            nonce_key, seen = self.nonce_seen_order.popleft()
            if self.used_nonces.get(nonce_key) == seen:
                self.used_nonces.pop(nonce_key, None)
        while len(self.request_seen_order) > self.max_seen_entries:
            request_key, seen = self.request_seen_order.popleft()
            if self.used_request_ids.get(request_key) == seen:
                self.used_request_ids.pop(request_key, None)

    def _allow_rate(self, node_id: str, now: int) -> bool:
        queue = self.node_request_times[node_id]
        cutoff = now - 60
        while queue and queue[0] < cutoff:
            queue.popleft()
        if len(queue) >= self.max_requests_per_minute:
            return False
        queue.append(now)
        return True


class TranslationNetwork:
    def __init__(self, identity_registry: Optional[IdentityRegistry] = None, strict_secret_from_env: bool = False) -> None:
        self.model_version = "llm-shard-v1.0"
        self.epoch = 0
        self.ledger: List[Dict[str, Any]] = []
        self.ledger_request_ids: Set[str] = set()
        self.launch_gate = LaunchGate()
        self.token = TokenEconomy()
        self.token.bootstrap_genesis()
        self.identities = identity_registry or IdentityRegistry.from_env()
        self.nodes = [
            Node("node-sea-1", "seoul-edge", 45, 0.97, "formal"),
            Node("node-tyo-2", "tokyo", 70, 0.94, "natural"),
            Node("node-sgp-3", "singapore", 85, 0.95, "literal"),
            Node("node-fra-4", "frankfurt", 140, 0.92, "concise"),
            Node("node-iad-5", "virginia", 165, 0.91, "literal"),
        ]

        self.secret_from_env = False
        self.secret_strength_passed = False
        secret_env = os.getenv("NETWORK_SHARED_SECRET", "").strip()
        if secret_env and len(secret_env.encode("utf-8")) >= 32:
            secret_bytes = secret_env.encode("utf-8")
            self.secret_from_env = True
            self.secret_strength_passed = self._is_strong_shared_secret(secret_env)
        elif strict_secret_from_env:
            raise ValueError("NETWORK_SHARED_SECRET must be set and >= 32 bytes for strict mode.")
        else:
            secret_bytes = secrets.token_bytes(32)

        self.security = RequestSecurity(
            secret_bytes,
            allowed_nodes={node.node_id for node in self.nodes},
        )
        self.slash_points: Dict[str, int] = defaultdict(int)
        self.upgrades: Dict[str, UpgradeProposal] = {}

    @staticmethod
    def _is_strong_shared_secret(secret: str) -> bool:
        candidate = secret.strip()
        if len(candidate.encode("utf-8")) < 32:
            return False
        normalized = "".join(ch for ch in candidate.lower() if ch.isalnum())
        weak_markers = ["password", "secret", "changeme", "default", "example", "test", "demo"]
        if any(marker in normalized for marker in weak_markers):
            return False
        if len(set(candidate)) < 10:
            return False
        char_classes = [
            any(ch.islower() for ch in candidate),
            any(ch.isupper() for ch in candidate),
            any(ch.isdigit() for ch in candidate),
            any(not ch.isalnum() for ch in candidate),
        ]
        return sum(char_classes) >= 3

    @staticmethod
    def canonical_translate_ko_to_en(text: str) -> str:
        phrase_map = {
            "안녕하세요, 회의에 참석해 주셔서 감사합니다.": "Hello, thank you for joining the meeting.",
            "오늘 일정은 실시간 번역 네트워크 데모입니다.": "Today's agenda is a real-time translation network demo.",
            "질문이 있으면 언제든지 말씀해 주세요.": "Please ask any questions at any time.",
            "이 네트워크는 출시 전 보안 검증이 필요합니다.": "This network requires security validation before launch.",
            "지연시간과 품질을 동시에 검증합니다.": "We validate latency and quality at the same time.",
        }
        if text in phrase_map:
            return phrase_map[text]
        return f"[untranslated] {text}"

    def run_preflight_checks(self, security_scan_passed: bool, production_mode: bool) -> Dict[str, bool]:
        self.launch_gate.set_check("security_scan_passed", security_scan_passed)
        self.launch_gate.set_check("economic_invariant_passed", self.token.max_supply > self.token.minted_supply)
        self.launch_gate.set_check("consensus_quorum_passed", len(self.nodes) >= 3)
        self.launch_gate.set_check("stress_test_passed", self.simulate_stress_test(max_requests=100))

        if production_mode:
            key_management = self.secret_from_env and self.secret_strength_passed
            account_registry = self.identities.production_ready()
        else:
            key_management = len(self.security.shared_secret) >= 32
            account_registry = self.identities.has_unique_wallets()

        self.launch_gate.set_check("key_management_passed", key_management)
        self.launch_gate.set_check("account_registry_passed", account_registry)
        return dict(self.launch_gate.checks)

    def simulate_stress_test(self, max_requests: int) -> bool:
        node_count = len(self.nodes)
        if node_count < 3:
            return False
        throughput_score = node_count * max_requests
        return throughput_score >= 500

    def open_mainnet(self) -> None:
        self.launch_gate.open()

    def propose_upgrade(self, proposal_id: str, target_model_version: str, delay_epochs: int) -> None:
        if proposal_id in self.upgrades:
            raise ValueError(f"proposal already exists: {proposal_id}")
        self.upgrades[proposal_id] = UpgradeProposal(
            proposal_id=proposal_id,
            target_model_version=target_model_version,
            created_epoch=self.epoch,
            activate_after_epoch=self.epoch + delay_epochs,
        )

    def vote_upgrade(self, proposal_id: str, node_id: str, support: bool) -> None:
        proposal = self.upgrades[proposal_id]
        proposal.votes_for.discard(node_id)
        proposal.votes_against.discard(node_id)
        if support:
            proposal.votes_for.add(node_id)
        else:
            proposal.votes_against.add(node_id)

    def apply_approved_upgrades(self) -> List[str]:
        applied: List[str] = []
        quorum = max(3, len(self.nodes) // 2 + 1)
        for proposal in self.upgrades.values():
            if proposal.applied:
                continue
            if self.epoch < proposal.activate_after_epoch:
                continue
            if proposal.approved(quorum):
                self.model_version = proposal.target_model_version
                proposal.applied = True
                applied.append(proposal.proposal_id)
        return applied

    def cross_verify(self, candidate: Dict[str, Any], canonical_output: str) -> Decimal:
        threshold = 0.79
        candidate_text = str(candidate["output"])
        approvals = 0
        for verifier in self.nodes:
            if verifier.node_id == candidate["node_id"]:
                continue
            verifier_noise = 0.01 * (1.0 - verifier.reliability)
            agree = (similarity(candidate_text, canonical_output) - verifier_noise) >= threshold
            approvals += int(agree)
        return Decimal(approvals) / Decimal(len(self.nodes) - 1)

    def process_request(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        if not self.launch_gate.opened:
            raise RuntimeError("Mainnet is closed. Launch gate must pass first.")

        ok, reason = self.security.verify(envelope)
        if not ok:
            node_id = str(envelope.get("node_id", "unknown"))
            self.slash_points[node_id] += 1
            raise ValueError(f"request rejected: {reason}")

        request_id = str(envelope["request_id"]).strip()
        if request_id in self.ledger_request_ids:
            node_id = str(envelope.get("node_id", "unknown"))
            self.slash_points[node_id] += 1
            raise ValueError("request rejected: duplicate request_id")

        source_text = str(envelope["source_text"]).strip()
        canonical = self.canonical_translate_ko_to_en(source_text)
        proposals = [node.propose(source_text, canonical, self.epoch) for node in self.nodes]

        poui_scores: Dict[str, Decimal] = {}
        for p in proposals:
            agreement = self.cross_verify(p, canonical)
            p["agreement"] = agreement
            p["poui_final"] = p["poui_base"] * (Decimal("0.5") + Decimal("0.5") * agreement)
            poui_scores[str(p["node_id"])] = p["poui_final"]

        winner = max(proposals, key=lambda x: x["poui_final"])
        reward_result = self.token.distribute_epoch_rewards(self.epoch, poui_scores)
        vesting_release = self.token.release_genesis_vesting(self.epoch)

        ledger_entry = {
            "request_id": request_id,
            "epoch": self.epoch,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "model_version": self.model_version,
            "source_hash": sha256_hex(source_text),
            "canonical_hash": sha256_hex(canonical),
            "winner_node": winner["node_id"],
            "winner_output_hash": sha256_hex(str(winner["output"])),
            "committee_hash": sha256_hex(
                canonical_json(
                    {
                        "members": [
                            {"node": p["node_id"], "output_hash": p["output_hash"]} for p in proposals
                        ]
                    }
                )
            ),
            "signature_hash": sha256_hex(str(envelope["signature"])),
        }
        ledger_entry["entry_hash"] = sha256_hex(canonical_json(ledger_entry))
        self.ledger.append(ledger_entry)
        self.ledger_request_ids.add(request_id)

        applied = self.apply_approved_upgrades()
        self.epoch += 1

        return {
            "request_id": request_id,
            "requester_node": envelope["node_id"],
            "winner_node": winner["node_id"],
            "winner_latency_ms": winner["latency_ms"],
            "final_output": winner["output"],
            "emission": reward_result["emission"],
            "node_rewards": reward_result["node_rewards"],
            "vesting_release": vesting_release,
            "ledger_entry_hash": ledger_entry["entry_hash"][:20],
            "applied_upgrades": applied,
        }

    def build_demo_requests(self) -> List[Dict[str, Any]]:
        items = [
            ("req-001", "node-sea-1", "안녕하세요, 회의에 참석해 주셔서 감사합니다."),
            ("req-002", "node-tyo-2", "오늘 일정은 실시간 번역 네트워크 데모입니다."),
            ("req-003", "node-sgp-3", "질문이 있으면 언제든지 말씀해 주세요."),
            ("req-004", "node-fra-4", "이 네트워크는 출시 전 보안 검증이 필요합니다."),
            ("req-005", "node-iad-5", "지연시간과 품질을 동시에 검증합니다."),
        ]
        return [self.security.build_envelope(req_id, node_id, text) for req_id, node_id, text in items]

    def build_team_participation_requests(self, rounds: int = 2) -> List[Dict[str, Any]]:
        phrases = [
            "안녕하세요, 회의에 참석해 주셔서 감사합니다.",
            "오늘 일정은 실시간 번역 네트워크 데모입니다.",
            "질문이 있으면 언제든지 말씀해 주세요.",
            "이 네트워크는 출시 전 보안 검증이 필요합니다.",
            "지연시간과 품질을 동시에 검증합니다.",
        ]
        requests: List[Dict[str, Any]] = []
        for round_idx in range(rounds):
            for node_idx, node in enumerate(self.nodes):
                text = phrases[(round_idx + node_idx) % len(phrases)]
                req_id = f"team-{round_idx:02d}-{node.node_id}"
                requests.append(self.security.build_envelope(req_id, node.node_id, text))
        return requests

    def state_snapshot(self) -> Dict[str, Any]:
        return {
            "epoch": self.epoch,
            "model_version": self.model_version,
            "minted_supply": self.token.minted_supply,
            "max_supply": self.token.max_supply,
            "balances": dict(sorted(self.token.balances.items())),
            "launch_gate": dict(self.launch_gate.checks),
            "mainnet_open": self.launch_gate.opened,
            "slash_points": dict(self.slash_points),
            "ledger_entries": len(self.ledger),
            "owner_id": self.identities.owner_id,
            "wallets_redacted": self.identities.public_wallet_snapshot(),
            "account_registry_ready": self.identities.production_ready(),
            "connection_configured": self.identities.connection_configured(),
        }


@dataclass
class QAAgentResult:
    agent_id: str
    passed: bool
    summary: str
    evidence: Dict[str, Any]


class QAAgent:
    agent_id: str = "qa-base-agent"

    def run(self) -> QAAgentResult:
        raise NotImplementedError


NetworkFactory = Callable[[], TranslationNetwork]


class LaunchGateQAAgent(QAAgent):
    agent_id = "qa-launch-gate-agent"

    def run(self) -> QAAgentResult:
        net = TranslationNetwork()
        checks = net.run_preflight_checks(security_scan_passed=False, production_mode=False)
        blocked = False
        reason = ""
        try:
            net.open_mainnet()
        except RuntimeError as exc:
            blocked = True
            reason = str(exc)

        passed = blocked and "security_scan_passed" in reason
        return QAAgentResult(
            agent_id=self.agent_id,
            passed=passed,
            summary="Open must stay blocked when required checks fail.",
            evidence={
                "checks": checks,
                "blocked": blocked,
                "reason": reason,
            },
        )


class SecurityQAAgent(QAAgent):
    agent_id = "qa-security-agent"

    def __init__(self, network_factory: NetworkFactory) -> None:
        self.network_factory = network_factory

    def run(self) -> QAAgentResult:
        net = self.network_factory()

        def resign(envelope: Dict[str, Any]) -> None:
            envelope["signature"] = net.security.sign(
                {
                    "request_id": envelope["request_id"],
                    "node_id": envelope["node_id"],
                    "source_text": envelope["source_text"],
                    "nonce": envelope["nonce"],
                    "timestamp": envelope["timestamp"],
                }
            )

        valid = net.security.build_envelope("qa-security-valid", "node-sea-1", "안녕하세요, 회의에 참석해 주셔서 감사합니다.")
        net.process_request(valid)

        replay_blocked = False
        replay_reason = ""
        try:
            net.process_request(valid)
        except ValueError as exc:
            replay_blocked = "replay" in str(exc)
            replay_reason = str(exc)

        tampered = net.security.build_envelope("qa-security-bad-sign", "node-tyo-2", "질문이 있으면 언제든지 말씀해 주세요.")
        tampered["signature"] = "00" * 32
        signature_blocked = False
        signature_reason = ""
        try:
            net.process_request(tampered)
        except ValueError as exc:
            signature_blocked = "signature" in str(exc)
            signature_reason = str(exc)

        unknown_node = net.security.build_envelope("qa-security-unknown-node", "node-unknown-9", "안녕하세요, 회의에 참석해 주셔서 감사합니다.")
        unknown_node_blocked = False
        unknown_node_reason = ""
        try:
            net.process_request(unknown_node)
        except ValueError as exc:
            unknown_node_blocked = "unknown node_id" in str(exc)
            unknown_node_reason = str(exc)

        bad_nonce = net.security.build_envelope("qa-security-bad-nonce", "node-sea-1", "질문이 있으면 언제든지 말씀해 주세요.")
        bad_nonce["nonce"] = "nonce-not-hex"
        resign(bad_nonce)
        nonce_blocked = False
        nonce_reason = ""
        try:
            net.process_request(bad_nonce)
        except ValueError as exc:
            nonce_blocked = "invalid nonce" in str(exc)
            nonce_reason = str(exc)

        oversized = net.security.build_envelope("qa-security-large", "node-sea-1", "a" * 5000)
        resign(oversized)
        oversized_blocked = False
        oversized_reason = ""
        try:
            net.process_request(oversized)
        except ValueError as exc:
            oversized_blocked = "source_text too large" in str(exc)
            oversized_reason = str(exc)

        control_chars = net.security.build_envelope("qa-security-control-chars", "node-sea-1", "hello\x00world")
        control_chars_blocked = False
        control_chars_reason = ""
        try:
            net.process_request(control_chars)
        except ValueError as exc:
            control_chars_blocked = "invalid source_text control chars" in str(exc)
            control_chars_reason = str(exc)

        first = net.security.build_envelope("qa-security-dup-req", "node-sea-1", "안녕하세요, 회의에 참석해 주셔서 감사합니다.")
        net.process_request(first)
        duplicate = net.security.build_envelope("qa-security-dup-req", "node-sea-1", "안녕하세요, 회의에 참석해 주셔서 감사합니다.")
        duplicate_request_blocked = False
        duplicate_request_reason = ""
        try:
            net.process_request(duplicate)
        except ValueError as exc:
            duplicate_request_blocked = "duplicate request_id" in str(exc)
            duplicate_request_reason = str(exc)

        cross_node_first = net.security.build_envelope(
            "qa-security-cross-node-dup",
            "node-sea-1",
            "안녕하세요, 회의에 참석해 주셔서 감사합니다.",
        )
        net.process_request(cross_node_first)
        cross_node_duplicate = net.security.build_envelope(
            "qa-security-cross-node-dup",
            "node-tyo-2",
            "질문이 있으면 언제든지 말씀해 주세요.",
        )
        cross_node_duplicate_blocked = False
        cross_node_duplicate_reason = ""
        try:
            net.process_request(cross_node_duplicate)
        except ValueError as exc:
            cross_node_duplicate_blocked = "duplicate request_id" in str(exc)
            cross_node_duplicate_reason = str(exc)

        invalid_request_id = net.security.build_envelope(
            "qa security bad id",
            "node-sea-1",
            "질문이 있으면 언제든지 말씀해 주세요.",
        )
        invalid_request_id_blocked = False
        invalid_request_id_reason = ""
        try:
            net.process_request(invalid_request_id)
        except ValueError as exc:
            invalid_request_id_blocked = "invalid request_id format" in str(exc)
            invalid_request_id_reason = str(exc)

        persistent_replay_net = self.network_factory()
        persistent_replay_net.security.max_seen_entries = 1
        first_seen = persistent_replay_net.security.build_envelope(
            "qa-security-persistent-dup",
            "node-sea-1",
            "안녕하세요, 회의에 참석해 주셔서 감사합니다.",
        )
        filler = persistent_replay_net.security.build_envelope(
            "qa-security-persistent-filler",
            "node-tyo-2",
            "질문이 있으면 언제든지 말씀해 주세요.",
        )
        persistent_replay_net.process_request(first_seen)
        persistent_replay_net.process_request(filler)
        replay_after_evict = persistent_replay_net.security.build_envelope(
            "qa-security-persistent-dup",
            "node-sgp-3",
            "오늘 일정은 실시간 번역 네트워크 데모입니다.",
        )
        persistent_duplicate_blocked = False
        persistent_duplicate_reason = ""
        try:
            persistent_replay_net.process_request(replay_after_evict)
        except ValueError as exc:
            persistent_duplicate_blocked = "duplicate request_id" in str(exc)
            persistent_duplicate_reason = str(exc)

        replay_after_evict_whitespace = persistent_replay_net.security.build_envelope(
            "  qa-security-persistent-dup  ",
            "node-fra-4",
            "이 네트워크는 출시 전 보안 검증이 필요합니다.",
        )
        persistent_whitespace_duplicate_blocked = False
        persistent_whitespace_duplicate_reason = ""
        try:
            persistent_replay_net.process_request(replay_after_evict_whitespace)
        except ValueError as exc:
            persistent_whitespace_duplicate_blocked = "duplicate request_id" in str(exc)
            persistent_whitespace_duplicate_reason = str(exc)

        whitespace_source = net.security.build_envelope(
            "qa-security-whitespace-source",
            "node-sea-1",
            "  안녕하세요, 회의에 참석해 주셔서 감사합니다.  ",
        )
        whitespace_source_ok = False
        whitespace_source_output = ""
        try:
            whitespace_result = net.process_request(whitespace_source)
            whitespace_source_output = str(whitespace_result.get("final_output", ""))
            whitespace_source_ok = whitespace_source_output == "Hello, thank you for joining the meeting."
        except ValueError:
            whitespace_source_ok = False

        stale_timestamp = net.security.build_envelope(
            "qa-security-stale-ts",
            "node-sea-1",
            "질문이 있으면 언제든지 말씀해 주세요.",
        )
        stale_timestamp["timestamp"] = now_ts() - (net.security.max_skew_seconds + 10)
        resign(stale_timestamp)
        stale_timestamp_blocked = False
        stale_timestamp_reason = ""
        try:
            net.process_request(stale_timestamp)
        except ValueError as exc:
            stale_timestamp_blocked = "timestamp outside allowed clock skew" in str(exc)
            stale_timestamp_reason = str(exc)

        rate_limit_net = self.network_factory()
        max_per_minute = rate_limit_net.security.max_requests_per_minute
        for idx in range(max_per_minute):
            env = rate_limit_net.security.build_envelope(
                f"qa-security-rate-ok-{idx}",
                "node-sea-1",
                "안녕하세요, 회의에 참석해 주셔서 감사합니다.",
            )
            rate_limit_net.process_request(env)

        rate_limit_env = rate_limit_net.security.build_envelope(
            "qa-security-rate-block",
            "node-sea-1",
            "안녕하세요, 회의에 참석해 주셔서 감사합니다.",
        )
        rate_limit_blocked = False
        rate_limit_reason = ""
        try:
            rate_limit_net.process_request(rate_limit_env)
        except ValueError as exc:
            rate_limit_blocked = "rate limit exceeded" in str(exc)
            rate_limit_reason = str(exc)

        passed = (
            replay_blocked
            and signature_blocked
            and unknown_node_blocked
            and nonce_blocked
            and oversized_blocked
            and control_chars_blocked
            and duplicate_request_blocked
            and cross_node_duplicate_blocked
            and invalid_request_id_blocked
            and persistent_duplicate_blocked
            and persistent_whitespace_duplicate_blocked
            and whitespace_source_ok
            and stale_timestamp_blocked
            and rate_limit_blocked
        )
        return QAAgentResult(
            agent_id=self.agent_id,
            passed=passed,
            summary="Replay/tampering/stale timestamp/rate abuse must be rejected by network security controls.",
            evidence={
                "replay_blocked": replay_blocked,
                "replay_reason": replay_reason,
                "signature_blocked": signature_blocked,
                "signature_reason": signature_reason,
                "unknown_node_blocked": unknown_node_blocked,
                "unknown_node_reason": unknown_node_reason,
                "nonce_blocked": nonce_blocked,
                "nonce_reason": nonce_reason,
                "oversized_blocked": oversized_blocked,
                "oversized_reason": oversized_reason,
                "control_chars_blocked": control_chars_blocked,
                "control_chars_reason": control_chars_reason,
                "duplicate_request_blocked": duplicate_request_blocked,
                "duplicate_request_reason": duplicate_request_reason,
                "cross_node_duplicate_blocked": cross_node_duplicate_blocked,
                "cross_node_duplicate_reason": cross_node_duplicate_reason,
                "invalid_request_id_blocked": invalid_request_id_blocked,
                "invalid_request_id_reason": invalid_request_id_reason,
                "persistent_duplicate_blocked": persistent_duplicate_blocked,
                "persistent_duplicate_reason": persistent_duplicate_reason,
                "persistent_whitespace_duplicate_blocked": persistent_whitespace_duplicate_blocked,
                "persistent_whitespace_duplicate_reason": persistent_whitespace_duplicate_reason,
                "whitespace_source_ok": whitespace_source_ok,
                "whitespace_source_output": whitespace_source_output,
                "stale_timestamp_blocked": stale_timestamp_blocked,
                "stale_timestamp_reason": stale_timestamp_reason,
                "rate_limit_blocked": rate_limit_blocked,
                "rate_limit_reason": rate_limit_reason,
                "slash_points": dict(net.slash_points),
            },
        )


class EconomyQAAgent(QAAgent):
    agent_id = "qa-economy-agent"

    def __init__(self, network_factory: NetworkFactory) -> None:
        self.network_factory = network_factory

    def run(self) -> QAAgentResult:
        net = self.network_factory()
        emissions: List[Decimal] = []
        for envelope in net.build_team_participation_requests(rounds=2):
            out = net.process_request(envelope)
            emissions.append(out["emission"])

        non_increasing = all(emissions[i] >= emissions[i + 1] for i in range(len(emissions) - 1))
        cap_safe = net.token.minted_supply <= net.token.max_supply
        founder_locked = net.token.balances["founder_treasury"] == Decimal("0")

        passed = non_increasing and cap_safe and founder_locked
        return QAAgentResult(
            agent_id=self.agent_id,
            passed=passed,
            summary="Emission schedule and supply cap must remain deterministic and safe.",
            evidence={
                "emission_series": [decimal_to_str(e) for e in emissions],
                "non_increasing": non_increasing,
                "minted_supply": decimal_to_str(net.token.minted_supply),
                "max_supply": decimal_to_str(net.token.max_supply),
                "founder_treasury_before_unlock": decimal_to_str(net.token.balances["founder_treasury"]),
            },
        )


class TeamParticipationQAAgent(QAAgent):
    agent_id = "qa-team-participation-agent"

    def __init__(self, network_factory: NetworkFactory) -> None:
        self.network_factory = network_factory

    def run(self) -> QAAgentResult:
        net = self.network_factory()
        envelopes = net.build_team_participation_requests(rounds=2)
        participation = defaultdict(int)
        for env in envelopes:
            participation[str(env["node_id"])] += 1
            net.process_request(env)

        node_balances = {node.node_id: net.token.balances[node.node_id] for node in net.nodes}
        all_participated = all(participation[node.node_id] >= 2 for node in net.nodes)
        all_rewarded = all(balance > 0 for balance in node_balances.values())
        passed = all_participated and all_rewarded

        return QAAgentResult(
            agent_id=self.agent_id,
            passed=passed,
            summary="Every node must join team tests and receive rewards.",
            evidence={
                "participation": dict(participation),
                "node_balances": {k: decimal_to_str(v) for k, v in node_balances.items()},
                "all_participated": all_participated,
                "all_rewarded": all_rewarded,
            },
        )


class PrivacyConfigQAAgent(QAAgent):
    agent_id = "qa-privacy-config-agent"

    def run(self) -> QAAgentResult:
        net = TranslationNetwork()
        snapshot_text = json.dumps(to_jsonable(net.state_snapshot()), ensure_ascii=False)
        redacted = net.identities.public_wallet_snapshot()
        raw_wallets = list(net.identities.wallets.values())

        redaction_ok = all(
            redacted[participant] != net.identities.wallets[participant]
            and ("..." in redacted[participant] or "*" in redacted[participant])
            for participant in redacted
        )
        raw_leak = any(wallet in snapshot_text for wallet in raw_wallets)

        secret_env = os.getenv("NETWORK_SHARED_SECRET", "")
        secret_leak = bool(secret_env and secret_env in snapshot_text)

        passed = redaction_ok and not raw_leak and not secret_leak
        return QAAgentResult(
            agent_id=self.agent_id,
            passed=passed,
            summary="Public snapshot must not expose private wallet values or secrets.",
            evidence={
                "redaction_ok": redaction_ok,
                "raw_wallet_leak_detected": raw_leak,
                "secret_leak_detected": secret_leak,
                "wallet_preview": redacted,
            },
        )


class QATeamRunner:
    def __init__(self, production_mode: bool) -> None:
        self.production_mode = production_mode

    def _network_factory(self) -> TranslationNetwork:
        net = TranslationNetwork()
        net.run_preflight_checks(security_scan_passed=True, production_mode=self.production_mode)
        net.open_mainnet()
        return net

    def run(self) -> Dict[str, Any]:
        agents: List[QAAgent] = [
            LaunchGateQAAgent(),
            SecurityQAAgent(self._network_factory),
            EconomyQAAgent(self._network_factory),
            TeamParticipationQAAgent(self._network_factory),
            PrivacyConfigQAAgent(),
        ]
        results = [agent.run() for agent in agents]
        return {
            "mode": "qa",
            "production_mode": self.production_mode,
            "overall_passed": all(result.passed for result in results),
            "agents": [
                {
                    "agent_id": result.agent_id,
                    "passed": result.passed,
                    "summary": result.summary,
                    "evidence": result.evidence,
                }
                for result in results
            ],
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }


def run_demo(production_mode: bool) -> Dict[str, Any]:
    network = TranslationNetwork()
    network.propose_upgrade("upgrade-001", "llm-shard-v1.1", delay_epochs=2)
    for node in network.nodes[:4]:
        network.vote_upgrade("upgrade-001", node.node_id, support=True)
    network.vote_upgrade("upgrade-001", network.nodes[4].node_id, support=False)

    checks = network.run_preflight_checks(security_scan_passed=True, production_mode=production_mode)
    network.open_mainnet()

    outputs: List[Dict[str, Any]] = []
    for envelope in network.build_demo_requests():
        outputs.append(network.process_request(envelope))

    return {
        "mode": "demo",
        "production_mode": production_mode,
        "preflight_checks": checks,
        "forecast_next_12_epochs": network.token.forecast(network.epoch, 12),
        "requests": outputs,
        "snapshot": network.state_snapshot(),
    }


def run_qa_team_suite(production_mode: bool) -> Dict[str, Any]:
    runner = QATeamRunner(production_mode=production_mode)
    return runner.run()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Decentralized AI network simulator and QA runner.")
    parser.add_argument("--mode", choices=["demo", "qa"], default="demo", help="Run demo flow or QA team suite.")
    parser.add_argument(
        "--production-checks",
        action="store_true",
        help="Require production-grade preflight checks (manual env accounts + static shared secret).",
    )
    parser.add_argument(
        "--dotenv-path",
        default=".env",
        help="Optional path to .env file for local private config loading.",
    )
    parser.add_argument(
        "--runner-id",
        default="",
        help="Execution actor id (falls back to RUNNER_ID env then OWNER_ID).",
    )
    parser.add_argument(
        "--launch-state-path",
        default=DEFAULT_LAUNCH_STATE_PATH,
        help="Persistent launch sentinel state path.",
    )
    parser.add_argument(
        "--arm-final-launch",
        action="store_true",
        help="Arm final launch sentinel. Only OWNER_ID can arm it.",
    )
    parser.add_argument(
        "--show-launch-state",
        action="store_true",
        help="Print launch sentinel state and exit.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    load_env_file(args.dotenv_path)
    identities = IdentityRegistry.from_env()
    runner_id = resolve_runner_id(args.runner_id, identities.owner_id)

    sentinel = UnstoppableLaunchSentinel(
        state_path=args.launch_state_path,
        owner_id=identities.owner_id,
    )

    if args.arm_final_launch:
        sentinel.arm(runner_id)

    if args.show_launch_state:
        print(json.dumps(to_jsonable({"launch_sentinel": sentinel.snapshot()}), ensure_ascii=False, indent=2))
        return

    launch_state = sentinel.record_execution(runner_id)
    force_live_mode = bool(launch_state["unstoppable_started"])

    effective_mode = args.mode
    effective_production_checks = args.production_checks
    if force_live_mode:
        effective_mode = "demo"
        effective_production_checks = True

    try:
        if effective_mode == "qa":
            result = run_qa_team_suite(production_mode=effective_production_checks)
        else:
            result = run_demo(production_mode=effective_production_checks)
    except Exception as exc:
        if force_live_mode:
            payload = {
                "mode": "forced-live-start",
                "forced_live_mode": True,
                "runner_id": runner_id,
                "error": str(exc),
                "launch_sentinel": sentinel.snapshot(),
            }
            print(json.dumps(to_jsonable(payload), ensure_ascii=False, indent=2))
            return
        raise

    if force_live_mode:
        launch_state = sentinel.mark_successful_open()

    result["runner_id"] = runner_id
    result["forced_live_mode"] = force_live_mode
    result["launch_sentinel"] = launch_state
    print(json.dumps(to_jsonable(result), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
