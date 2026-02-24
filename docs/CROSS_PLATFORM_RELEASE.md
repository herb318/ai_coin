# Cross-Platform Prebuilt Release

This project now ships automated prebuilt binaries for:

- Windows
- Linux
- macOS

Pipeline file:
- `.github/workflows/cross-platform-release.yml`

## What gets uploaded

For each platform, the workflow creates:

- `dpuin-<platform>.zip`

For signed release tags (`v*`), the workflow also creates:

- `SHA256SUMS`
- `SHA256SUMS.sig`, `SHA256SUMS.pem`
- `dpuin-<platform>.zip.sig`, `dpuin-<platform>.zip.pem`

Each zip includes:

- platform binary (`dpuin` or `dpuin.exe`)
- `RUN_ME_FIRST.txt`
- `.env.example`
- `README.md`
- governance/reward docs

## When builds run

- `pull_request`
- `push` to `main`
- manual `workflow_dispatch`

On tag push (`v*`), the workflow uploads zip bundles plus checksum/signature files to GitHub Release assets.

Verification:

- [Supply Chain Verification](docs/SUPPLY_CHAIN_VERIFICATION.md)

## Local manual bundle (optional)

1. Build binary (example):
   - `python -m PyInstaller --clean --onefile --name dpuin decentralized_ai_network_demo.py`
2. Build release zip:
   - `python scripts/create_release_bundle.py --binary-path dist/dpuin --target linux --output-dir release`
