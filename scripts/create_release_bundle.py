#!/usr/bin/env python3
"""Create a zipped, cross-platform release bundle around a prebuilt binary."""

from __future__ import annotations

import argparse
import json
import shutil
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INCLUDED_DOCS = [
    "README.md",
    "SECURITY.md",
    "LICENSE",
    ".env.example",
    "docs/LAUNCH_AND_GOVERNANCE.md",
    "docs/REWARD_MECHANISM.md",
    "docs/SUPPLY_CHAIN_VERIFICATION.md",
]


def _quick_start_text(binary_name: str) -> str:
    if binary_name.lower().endswith(".exe"):
        run_demo = f".\\{binary_name} --mode demo"
        run_qa = f".\\{binary_name} --mode qa"
    else:
        run_demo = f"./{binary_name} --mode demo"
        run_qa = f"./{binary_name} --mode qa"
    return "\n".join(
        [
            "Autonomous AI Reward Network quick start",
            "",
            "1) Copy .env.example to .env and fill private values.",
            f"2) Run demo: {run_demo}",
            f"3) Run QA: {run_qa}",
            "",
            "Production checks:",
            f"{run_qa} --production-checks",
        ]
    )


def build_bundle(binary_path: Path, target: str, output_dir: Path) -> Path:
    if not binary_path.exists() or not binary_path.is_file():
        raise FileNotFoundError(f"Binary not found: {binary_path}")
    if not target.strip():
        raise ValueError("target must not be empty")

    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_name = f"dpuin-{target.strip()}"
    staging_dir = output_dir / f"{bundle_name}_staging"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    bundle_root = staging_dir / bundle_name
    bundle_root.mkdir(parents=True, exist_ok=True)

    binary_name = binary_path.name
    shutil.copy2(binary_path, bundle_root / binary_name)
    (bundle_root / "RUN_ME_FIRST.txt").write_text(_quick_start_text(binary_name), encoding="utf-8")

    for relative_path in INCLUDED_DOCS:
        src = PROJECT_ROOT / relative_path
        if not src.exists():
            continue
        dst = bundle_root / relative_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    zip_path = output_dir / f"{bundle_name}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(bundle_root.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=path.relative_to(staging_dir))

    shutil.rmtree(staging_dir)
    return zip_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a release bundle zip for a single prebuilt binary.")
    parser.add_argument("--binary-path", required=True, help="Path to compiled binary (dpuin or dpuin.exe).")
    parser.add_argument("--target", required=True, help="Target label (for example: windows-x64, linux-x64).")
    parser.add_argument("--output-dir", default="release", help="Output directory for zip bundles.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    zip_path = build_bundle(Path(args.binary_path), args.target, Path(args.output_dir))
    payload = {
        "target": args.target,
        "binary_path": str(Path(args.binary_path)),
        "bundle_path": str(zip_path),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
