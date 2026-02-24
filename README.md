# Autonomous AI Reward Network (DPUIN)

A decentralized AI network prototype where participants contribute useful inference and receive deterministic rewards.

Technical project identifier:
- `dpuin-protocol`
Repository:
- `herb318/autonomous-ai-reward-network`

## Automation Provenance

This repository was completed through **ChatGPT Codex automation** with user-directed requirements and local execution verification.
  
Verification details:
- [Codex Automation Verification](docs/CODEX_AUTOMATION_VERIFICATION.md)
- [Network Status](docs/NETWORK_STATUS.md)
- [Cross-Platform Release](docs/CROSS_PLATFORM_RELEASE.md)
- [AI Usage Guide](docs/AI_USAGE_GUIDE.md)
- [Docker Automation](docs/DOCKER_AUTOMATION.md)
- [Supply Chain Verification](docs/SUPPLY_CHAIN_VERIFICATION.md)
- [Security Policy](SECURITY.md)

## What This Project Is

- Open, evolving network AI simulation
- Deterministic reward mechanism (no hidden minting/backdoor)
- Launch gate + security controls before opening
- QA agent/team validation workflow
- Public-safe release workflow (secret/PII scan)
- Cross-platform prebuilt binary pipeline (Windows/Linux/macOS)

## Core Principles

1. Open evolution:
- Model upgrades are proposal/vote based.
- Approved upgrades activate after a delay epoch.

2. Useful-work rewards:
- Rewards are tied to **quality + latency + committee agreement**.
- Emission schedule is deterministic and forecastable.

3. Safety first:
- Mainnet cannot open until mandatory preflight checks pass.
- HMAC auth, replay protection, timestamp skew validation, and rate limit are enforced.
- `request_id` format is validated and enforced as ledger-level network-wide unique (cache eviction cannot bypass).
- Verified envelope fields are canonicalized (trimmed) before inference/ledger processing.
- Security runtime config is fail-closed validated (`max_skew_seconds`, `max_requests_per_minute`, `max_seen_entries`).
- `source_text` control characters are rejected to reduce payload abuse/log injection risk.
- Invalid/unknown sender penalties are bucketed to a fixed key to avoid slash-map pollution.
- Malformed launch sentinel state values are fail-closed reset to defaults.
- Launch sentinel persisted booleans/invariants are strictly validated (no truthy-string coercion).
- Launch sentinel persisted schema is strict (non-object/unknown fields trigger fail-closed reset).
- Production RPC URL validation rejects private/link-local/reserved IP endpoints.
- `request_id` is canonicalized to lowercase to prevent case-variant duplicate bypass.
- Request envelope schema is strict: unexpected fields and boolean timestamps are rejected.

4. Public transparency:
- Reward equations and treasury splits are documented.
- Private runtime state and secrets are excluded from git.

## Exact Reward Mechanism

See full details in:
- [Reward Mechanism](docs/REWARD_MECHANISM.md)

Summary:
- Epoch emission:
  - `E(epoch) = min(remaining_supply, max(min_epoch_emission, initial_emission * decay^epoch))`
- Emission split:
  - Committee pool: `75%`
  - Ecosystem treasury: `20%`
  - Security treasury: `5%`
- Per-node final score:
  - `PoUI_i = PoUI_base_i * (0.5 + 0.5 * agreement_i)`
- Per-node reward:
  - `Reward_i = committee_pool * max(PoUI_i, 0) / Σ max(PoUI_j, 0)`

## Launch and Unstoppable Start

Final pre-launch behavior supports:
- Owner arms the final launch sentinel
- If a non-owner executes once after arming, unstoppable start is triggered and persisted

See:
- [Launch & Governance](docs/LAUNCH_AND_GOVERNANCE.md)

## Quick Start

```bash
cd <repo-root>
cp .env.example .env
# Fill .env manually with your private values
```

Simple full check (recommended):
```bash
python3 scripts/airn.py check
```

Strict production check:
```bash
python3 scripts/airn.py check --production-checks
```

Run only demo:
```bash
python3 scripts/airn.py demo
```

Run only QA:
```bash
python3 scripts/airn.py qa
```

Continuous loop operator (runs QA+demo repeatedly):

```bash
nohup python3 scripts/airn.py loop --include-status-agent --interval-seconds 120 > runtime/operator_loop.out 2>&1 &
```

Practical post-boot usage and network-AI example scenarios:
- [AI Usage Guide](docs/AI_USAGE_GUIDE.md)

## Docker One-Shot Automation

Run full validation in one command:

```bash
docker compose run --rm --build oneshot
```

Strict production checks (requires `.env` with valid private values):

```bash
docker compose --profile production run --rm --build oneshot-prod
```

Containerized operator loop:

```bash
docker compose --profile operator up --build operator-loop
```

## Final Launch Sequence

1. Arm sentinel (owner only):
```bash
python3 scripts/airn.py launch-arm --launch-state-path runtime/launch_state.json
```

2. Check state:
```bash
python3 scripts/airn.py launch-state --launch-state-path runtime/launch_state.json
```

3. After arm, any non-owner one-time execution triggers unstoppable live start.

## Security and Open-Source Hygiene

Run local scans before publishing:
```bash
python3 -m bandit -r .
python3 scripts/sanitize_for_git_open.py --root .
```

Sanitize scanner coverage now includes:
- env secret keys (`NETWORK_SHARED_SECRET`, `PRIVATE_API_TOKEN`, `PRIVATE_RPC_URL`, `WALLET_*`)
- common token formats (OpenAI, GitHub, Google, Telegram, Slack, JWT)
- private key headers and credential-in-URL patterns
- redacted output snippets (no raw token echo in scan logs)

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Cross-Platform Prebuilt Binaries

GitHub Actions now builds precompiled binaries for:

- Windows
- Linux
- macOS

Workflow:
- `.github/workflows/cross-platform-release.yml`

Outputs:
- `dpuin-windows.zip`
- `dpuin-linux.zip`
- `dpuin-macos.zip`
- `SHA256SUMS` (+ `.sig`, `.pem`)
- `<artifact>.sig` + `<artifact>.pem` for each zip (Sigstore keyless)

Trigger release asset upload by pushing a version tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Verify downloaded release artifacts:

```bash
python3 scripts/verify_release_artifacts.py --assets-dir <download-dir> --require-cosign
```

## Status View (Git-Friendly)

Check current network status view files:

```bash
ls docs/NETWORK_STATUS.md docs/NETWORK_STATUS.json
```

If missing or outdated, regenerate:

```bash
python3 scripts/airn.py status
```

Strict production readiness view:

```bash
python3 scripts/airn.py status --production-checks
```

Outputs:
- `docs/NETWORK_STATUS.md`
- `docs/NETWORK_STATUS.json`
- `docs/NETWORK_HISTORY.jsonl` (append-only status history)

GitHub view entrypoint:
- `docs/NETWORK_STATUS.md`

Health fields in JSON:
- `status_ok`: overall health flag
- `health_level`: `OK` / `WARN` / `DEGRADED`
- `status_reasons`: machine-readable degraded reasons
- `advisories`: non-fatal warnings (for example local run while production readiness is false)
- `recommended_actions`: immediate operator actions generated from reasons/advisories
- `production_readiness.ready`: strict production readiness result
- `production_readiness.checks`: strict production check breakdown
- `recent_history`: latest history entries
- `history_trend`: trend summary from recent history window
- `history_chain`: append-only history integrity summary (`valid`, `broken_index`, `latest_hash`)
- `status_fingerprint`: semantic status digest (timestamp-independent)
- `history_appended`: whether a new history record was appended this run
- `history_append_blocked`: true when chain corruption blocks new append
- `history_chain_repaired`: true when legacy history gets auto-migrated/repaired into a valid chain
- `node_details`: per-node rank/balance/share/slash points/wallet preview
- `recent_requests`: request-by-request winner/latency/emission/output summary from latest run

Advanced status-agent options:
- `--no-history-dedupe`: append history even when fingerprint is unchanged
- `--no-stable-output`: always refresh `generated_at_utc` even if semantic status is unchanged
- `launch_error` / `qa_error`: failure details when degraded

## Full Auto Verification + Publish

Run all checks and automatically commit/push status docs if changed:

```bash
python3 scripts/auto_verify_publish.py --production-checks
```

Behavior:
- With `--production-checks`, auto publish validates status payload schema (mode/protocol/health/metrics/fingerprint/history metadata).
- With `--production-checks`, auto publish verifies payload consistency (health/status relation + recomputed `status_fingerprint` match).
- With `--production-checks`, auto publish aborts if `status_ok=false`.
- With `--production-checks`, auto publish also aborts if `history_chain.valid=false`, `history_chain.latest_hash` is invalid, or `history_chain.legacy_entries>0`.
- With `--production-checks`, auto publish aborts if `generated_at_utc` is invalid/missing or older than `--max-status-age-seconds` (default `900`).
- Optional strict mode: add `--fail-on-warn` to block when `health_level=WARN`.
- Use `--allow-failing-status` only when you explicitly want to publish degraded status.

## License

MIT. See [LICENSE](LICENSE).
