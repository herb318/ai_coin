# Security Policy

## Supported Scope

The `main` branch and tagged release artifacts are actively maintained.

## Reporting a Vulnerability

If you find a security issue:

1. Do not open a public issue with exploit details.
2. Contact the maintainer directly through GitHub private channels.
3. Include reproduction steps, impact, and affected commit/tag if possible.

We will acknowledge valid reports and coordinate remediation + disclosure timing.

## Supply-Chain Integrity

Release artifacts are protected with:

- `SHA256SUMS` checksum manifest
- Sigstore keyless signatures (`.sig`) and certificates (`.pem`) for each artifact
- Signed checksum manifest (`SHA256SUMS.sig`, `SHA256SUMS.pem`)

Verification guide:

- [Supply Chain Verification](docs/SUPPLY_CHAIN_VERIFICATION.md)

## Secure Usage Baseline

- Never commit `.env` or secrets.
- Rotate `NETWORK_SHARED_SECRET`, `PRIVATE_API_TOKEN`, and wallet credentials on compromise suspicion.
- Use `python3 scripts/airn.py check --production-checks` before production release.
- Keep branch protection enabled on `main`:
  - required PR review
  - required CI pass
  - force-push disabled
