# Open Evolving Network AI (`ai_coin`)

A decentralized AI network prototype where participants contribute useful inference and receive deterministic rewards.

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
cd /Users/j/Desktop/작업/ai_coin
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

## License

MIT. See [LICENSE](LICENSE).
