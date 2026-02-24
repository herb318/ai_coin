# Launch and Governance

## Mandatory Preflight (Open Blocking)

Mainnet open is blocked unless all checks are true:
- `security_scan_passed`
- `economic_invariant_passed`
- `consensus_quorum_passed`
- `key_management_passed`
- `stress_test_passed`
- `account_registry_passed`

## Final Launch Sentinel

Purpose:
- Prevent accidental early open
- Allow deliberate irreversible start condition

Behavior:
1. Owner arms sentinel (`--arm-final-launch`)
2. If armed and a non-owner executes once, `unstoppable_started=true`
3. After this, runs are forced into live start path

State is persisted in:
- `runtime/launch_state.json` (git-ignored)

## Emergency Pause/Resume

Owner-only commands:
- `--pause-network --pause-reason "<reason>"`
- `--resume-network`

Rules:
- Only `OWNER_ID` can pause/resume.
- Pause blocks normal execution paths and returns paused state.
- Pause/release metadata is persisted (`paused_by_runner`, `paused_at_utc`, `resumed_by_runner`, `resumed_at_utc`).

## Runner Identity Rules

Runner identity resolution order:
1. `--runner-id`
2. `RUNNER_ID` env
3. `OWNER_ID` env
4. fallback `runner-unknown`

## Upgrade Governance

Model upgrades are governed by:
- Proposal creation
- Node voting (`for/against`)
- Quorum and delayed activation epoch

Only approved and matured proposals are applied.

## Open Source Safety

Before public push:
1. Keep secrets only in local `.env`
2. Run sanitizer script
3. Verify no secret in tracked files
4. Push only template `.env.example`
