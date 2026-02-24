# AI Usage Guide (After Boot)

This guide summarizes practical usage after startup, including examples that use network-AI strengths.

## 1) Start Fast (Any OS)

Use prebuilt binaries from release assets:

- Windows: `dpuin-windows.zip` -> `dpuin.exe`
- Linux: `dpuin-linux.zip` -> `dpuin`
- macOS: `dpuin-macos.zip` -> `dpuin`

Basic run:

- Windows demo: `.\dpuin.exe --mode demo`
- Linux/macOS demo: `./dpuin --mode demo`

Or run from source:

- `python3 decentralized_ai_network_demo.py --mode demo`

## 2) Main Run Modes

- Demo mode:
  - `python3 decentralized_ai_network_demo.py --mode demo`
  - Runs representative inference requests through distributed nodes.
- QA mode:
  - `python3 decentralized_ai_network_demo.py --mode qa`
  - Runs launch/security/economy/team/privacy QA agents.
- Production checks:
  - `python3 decentralized_ai_network_demo.py --mode qa --production-checks`
  - Requires real env values (`OWNER_ID`, `NETWORK_SHARED_SECRET`, `PRIVATE_RPC_URL`, `PRIVATE_API_TOKEN`, `WALLET_*`).

## 3) How to Read Output Quickly

Key fields in JSON output:

- `preflight_checks`: launch gate pass/fail by control.
- `requests[]`: per-request winner node, latency, final output, rewards.
- `snapshot.balances`: node/treasury balances after processing.
- `snapshot.launch_gate`: current launch-gate state.
- `launch_sentinel`: final-launch sentinel state.

Observed local run behavior:

- `--mode demo`: succeeds with `mainnet_open=true`.
- `--mode qa`: succeeds with `overall_passed=true`.
- `--mode qa --production-checks`: fails without production env (expected).

## 4) Network-AI Strength Examples

### A. Real-time multilingual event translation

- Why network AI helps:
  - Multiple geographic nodes compete/cooperate on latency + quality.
  - Consensus-style cross verification raises reliability.
- What to watch:
  - `winner_latency_ms`, `final_output`, per-node `node_rewards`.

### B. Security-first public inference

- Why network AI helps:
  - Signed requests + replay prevention + strict envelope schema.
  - Independent QA agents continuously validate attack paths.
- What to watch:
  - QA security evidence (`replay_blocked`, `signature_blocked`, `rate_limit_blocked`).

### C. Always-on incentive alignment

- Why network AI helps:
  - Useful inference is rewarded; not meaningless work.
  - Emission is deterministic and capped, with treasury split visibility.
- What to watch:
  - `emission`, `node_rewards`, `minted_supply`, `max_supply`.

### D. Live protocol evolution without central lock-in

- Why network AI helps:
  - Upgrade proposals activate by vote + epoch delay.
  - Model version changes are observable in ledger/snapshot.
- What to watch:
  - `applied_upgrades`, `snapshot.model_version`.

## 5) Recommended Operator Flow

1. Run `--mode qa` after every change.
2. Run `--mode demo` to validate end-to-end behavior and reward distribution.
3. Run status agent for shared visibility:
   - `python3 scripts/network_status_agent.py`
4. Before public push, run:
   - `python3 scripts/sanitize_for_git_open.py --root .`

## 6) Continuous Operator Loop (Recommended)

Run continuously in background:

```bash
cd /Users/j/Desktop/작업/ai_coin
nohup python3 scripts/run_operator_loop.py --interval-seconds 120 --include-status-agent > runtime/operator_loop.out 2>&1 &
```

Check loop status:

```bash
cat runtime/operator_loop_state.json
tail -n 20 runtime/operator_loop.log
```

Stop loop cleanly:

```bash
touch runtime/STOP_OPERATOR_LOOP
```

Immediate single-cycle check:

```bash
python3 scripts/run_operator_loop.py --once
```

## 7) Common Failure Cause

If production checks fail with:

- `Launch blocked. Unmet checks: key_management_passed, account_registry_passed`

Then your `.env` is missing/placeholder/weak values. Fill all required production values and retry.
