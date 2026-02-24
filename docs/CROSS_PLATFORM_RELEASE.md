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

On tag push (`v*`), the workflow also uploads all zip bundles to GitHub Release assets.

## Local manual bundle (optional)

1. Build binary (example):
   - `python -m PyInstaller --clean --onefile --name dpuin decentralized_ai_network_demo.py`
2. Build release zip:
   - `python scripts/create_release_bundle.py --binary-path dist/dpuin --target linux --output-dir release`
