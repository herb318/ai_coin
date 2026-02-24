# Distributed Proof-of-Useful-Inference Network (DPUIN)

A decentralized AI network prototype where participants contribute useful inference and receive deterministic rewards.

Technical project identifier:
- `dpuin-protocol`

## Automation Provenance

This repository was completed through **ChatGPT Codex automation** with user-directed requirements and local execution verification.
  
Verification details:
- [Codex Automation Verification](docs/CODEX_AUTOMATION_VERIFICATION.md)
- [Network Status](docs/NETWORK_STATUS.md)

## What This Project Is

- Open, evolving network AI simulation
- Deterministic reward mechanism (no hidden minting/backdoor)
- Launch gate + security controls before opening
- QA agent/team validation workflow
- Public-safe release workflow (secret/PII scan)

## Core Principles

1. Open evolution:
- Model upgrades are proposal/vote based.
- Approved upgrades activate after a delay epoch.

2. Useful-work rewards:
- Rewards are tied to **quality + latency + committee agreement**.
- Emission schedule is deterministic and forecastable.

3. Safety first:
- Mainnet cannot open until mandatory preflight checks pass.
- HMAC auth, replay protection, and rate limit are enforced.

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

Run demo:
```bash
python3 decentralized_ai_network_demo.py --mode demo
```

Run QA team suite:
```bash
python3 decentralized_ai_network_demo.py --mode qa
```

Run production checks:
```bash
python3 decentralized_ai_network_demo.py --mode qa --production-checks
```

## Final Launch Sequence

1. Arm sentinel (owner only):
```bash
python3 decentralized_ai_network_demo.py --arm-final-launch --launch-state-path runtime/launch_state.json
```

2. Check state:
```bash
python3 decentralized_ai_network_demo.py --show-launch-state --launch-state-path runtime/launch_state.json
```

3. After arm, any non-owner one-time execution triggers unstoppable live start.

## Security and Open-Source Hygiene

Run local scans before publishing:
```bash
python3 -m bandit -r .
python3 scripts/sanitize_for_git_open.py --root .
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Status View (Git-Friendly)

Check current network status view files:

```bash
ls docs/NETWORK_STATUS.md docs/NETWORK_STATUS.json
```

If missing or outdated, regenerate:

```bash
python3 scripts/network_status_agent.py
```

Strict production readiness view:

```bash
python3 scripts/network_status_agent.py --production-checks
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
- `status_fingerprint`: semantic status digest (timestamp-independent)
- `history_appended`: whether a new history record was appended this run

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
- With `--production-checks`, auto publish aborts if `status_ok=false`.
- Optional strict mode: add `--fail-on-warn` to block when `health_level=WARN`.
- Use `--allow-failing-status` only when you explicitly want to publish degraded status.

## License

MIT. See [LICENSE](LICENSE).
