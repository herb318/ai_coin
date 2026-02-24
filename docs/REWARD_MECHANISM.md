# Reward Mechanism (Exact)

This document defines the deterministic reward model for participating nodes.

## 1) Token Emission

Variables:
- `max_supply = 10,000,000`
- `initial_epoch_emission = 1,500`
- `emission_decay = 0.995`
- `min_epoch_emission = 100`

For epoch `t`:

`raw_t = initial_epoch_emission * (emission_decay ^ t)`

`planned_t = max(min_epoch_emission, raw_t)`

`E_t = min(planned_t, max_supply - minted_supply)`

If supply is exhausted, `E_t = 0`.

## 2) Emission Split

For each epoch emission `E_t`:
- Committee reward pool: `C_t = 0.75 * E_t`
- Ecosystem reserve: `Eco_t = 0.20 * E_t`
- Security reserve: `Sec_t = E_t - C_t - Eco_t` (5%)

## 3) Node Quality Score

For node `i`:

`quality_i = 0.8 * text_similarity(output_i, canonical_output) + 0.2 * reliability_i`

`speed_factor_i = max(0.55, 1.25 - (latency_ms_i / 380))`

`PoUI_base_i = quality_i * speed_factor_i`

`agreement_i = approvals_i / (committee_size - 1)`

`PoUI_i = PoUI_base_i * (0.5 + 0.5 * agreement_i)`

## 4) Per-Node Reward Allocation

Let:

`S = Σ_j max(PoUI_j, 0)`

If `S > 0`:

`Reward_i = C_t * max(PoUI_i, 0) / S`

If `S = 0`, committee pool is split evenly.

## 5) Genesis Allocation and Lockup

Genesis wallets:
- `founder_treasury`: `2,200,000` with `12` epoch lockup + `96` epoch vesting
- `ecosystem_treasury`: `1,600,000`
- `security_treasury`: `600,000`
- `community_treasury`: `400,000`

Founder treasury does not release before lockup end.

## 6) Anti-Manipulation Conditions

- HMAC signature required on request envelope
- Replay blocked by nonce reuse detection
- Timestamp skew check
- Per-node rate limiting
- Slash points for invalid/tampered attempts

## 7) Why this is deterministic

- Emission uses fixed parameters and epoch index
- Distribution uses formula-based proportional allocation
- No hidden mint path outside epoch emission and declared genesis

## 8) Practical Interpretation

Participants are rewarded for:
1. Better output quality
2. Lower latency
3. Higher committee agreement

Poor quality or rejected behavior lowers reward share naturally.
