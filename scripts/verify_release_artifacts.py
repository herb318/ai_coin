#!/usr/bin/env python3
"""Verify release artifact integrity with checksums and optional Sigstore signatures."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess  # nosec B404
from pathlib import Path
from typing import Dict, List, Tuple


def _is_sha256_hex(value: str) -> bool:
    if len(value) != 64:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def parse_checksum_manifest(manifest_path: Path) -> List[Tuple[str, str]]:
    if not manifest_path.exists() or not manifest_path.is_file():
        raise FileNotFoundError(f"Checksum manifest not found: {manifest_path}")
    rows: List[Tuple[str, str]] = []
    with open(manifest_path, "r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                raise ValueError(f"Invalid checksum line at {line_no}: {line!r}")
            digest, file_name = parts
            if not _is_sha256_hex(digest):
                raise ValueError(f"Invalid checksum digest at {line_no}: {digest!r}")
            file_name = file_name.strip()
            if file_name.startswith("*"):
                file_name = file_name[1:]
            if not file_name:
                raise ValueError(f"Invalid checksum filename at {line_no}")
            rows.append((digest.lower(), file_name))
    if not rows:
        raise ValueError(f"Checksum manifest is empty: {manifest_path}")
    return rows


def file_sha256(path: Path) -> str:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Artifact not found: {path}")
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_checksums(assets_dir: Path, manifest_name: str = "SHA256SUMS") -> Dict[str, object]:
    manifest_path = assets_dir / manifest_name
    entries = parse_checksum_manifest(manifest_path)
    verified: List[str] = []
    missing: List[str] = []
    mismatched: List[Dict[str, str]] = []
    for expected, file_name in entries:
        artifact = assets_dir / file_name
        if not artifact.exists():
            missing.append(file_name)
            continue
        actual = file_sha256(artifact)
        if actual != expected:
            mismatched.append({"file": file_name, "expected": expected, "actual": actual})
            continue
        verified.append(file_name)
    ok = not missing and not mismatched
    return {
        "ok": ok,
        "manifest": manifest_name,
        "entry_count": len(entries),
        "verified_files": verified,
        "missing_files": missing,
        "mismatched_files": mismatched,
    }


def _cosign_available() -> bool:
    return shutil.which("cosign") is not None


def _cosign_identity_regexp(repo: str, workflow_path: str, tag_regexp: str) -> str:
    workflow = workflow_path.strip()
    if workflow.startswith("./"):
        workflow = workflow[2:]
    return f"https://github.com/{repo}/{workflow}@{tag_regexp}"


def _verify_blob_signature(
    target_path: Path,
    cert_path: Path,
    sig_path: Path,
    identity_regexp: str,
) -> Tuple[bool, str]:
    command = [
        "cosign",
        "verify-blob",
        "--certificate",
        str(cert_path),
        "--signature",
        str(sig_path),
        "--certificate-identity-regexp",
        identity_regexp,
        "--certificate-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        str(target_path),
    ]
    completed = subprocess.run(  # nosec B603
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return True, ""
    reason = completed.stderr.strip() or completed.stdout.strip() or "cosign verification failed"
    return False, reason


def verify_cosign(
    assets_dir: Path,
    files: List[str],
    manifest_name: str,
    repo: str,
    workflow_path: str,
    tag_regexp: str,
    require_cosign: bool,
) -> Dict[str, object]:
    available = _cosign_available()
    if not available and not require_cosign:
        return {
            "enabled": True,
            "cosign_available": False,
            "skipped": True,
            "reason": "cosign not installed; run with --require-cosign to make this blocking",
            "verified_files": [],
            "failed_files": [],
            "missing_signature_files": [],
        }
    if not available and require_cosign:
        return {
            "enabled": True,
            "cosign_available": False,
            "skipped": False,
            "reason": "cosign is required but not installed",
            "verified_files": [],
            "failed_files": [],
            "missing_signature_files": [manifest_name, *files],
        }

    identity_regexp = _cosign_identity_regexp(repo=repo, workflow_path=workflow_path, tag_regexp=tag_regexp)
    targets = [manifest_name, *files]
    verified: List[str] = []
    failed: List[Dict[str, str]] = []
    missing: List[str] = []
    for name in targets:
        target_path = assets_dir / name
        cert_path = assets_dir / f"{name}.pem"
        sig_path = assets_dir / f"{name}.sig"
        if not target_path.exists() or not cert_path.exists() or not sig_path.exists():
            missing.append(name)
            continue
        ok, reason = _verify_blob_signature(
            target_path=target_path,
            cert_path=cert_path,
            sig_path=sig_path,
            identity_regexp=identity_regexp,
        )
        if ok:
            verified.append(name)
        else:
            failed.append({"file": name, "reason": reason})

    ok = not missing and not failed
    return {
        "enabled": True,
        "cosign_available": True,
        "skipped": False,
        "identity_regexp": identity_regexp,
        "verified_files": verified,
        "failed_files": failed,
        "missing_signature_files": missing,
        "ok": ok,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify release artifacts with checksums and Sigstore signatures.")
    parser.add_argument("--assets-dir", default="release-assets", help="Directory containing release artifacts.")
    parser.add_argument("--manifest", default="SHA256SUMS", help="Checksum manifest file name.")
    parser.add_argument("--repo", default="herb318/autonomous-ai-reward-network", help="GitHub owner/repo.")
    parser.add_argument(
        "--workflow-path",
        default=".github/workflows/cross-platform-release.yml",
        help="Workflow path used for keyless signatures.",
    )
    parser.add_argument(
        "--tag-regexp",
        default="refs/tags/v.*",
        help="Tag ref regexp expected in signing identity certificate.",
    )
    parser.add_argument(
        "--skip-cosign",
        action="store_true",
        help="Skip signature verification and only validate checksums.",
    )
    parser.add_argument(
        "--require-cosign",
        action="store_true",
        help="Fail if cosign is not installed.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    assets_dir = Path(args.assets_dir).resolve()

    checksum_report = verify_checksums(assets_dir=assets_dir, manifest_name=args.manifest)
    files = list(checksum_report.get("verified_files", []))

    if args.skip_cosign:
        cosign_report: Dict[str, object] = {
            "enabled": False,
            "skipped": True,
            "reason": "--skip-cosign set",
        }
        overall_ok = bool(checksum_report.get("ok"))
    else:
        cosign_report = verify_cosign(
            assets_dir=assets_dir,
            files=files,
            manifest_name=args.manifest,
            repo=args.repo,
            workflow_path=args.workflow_path,
            tag_regexp=args.tag_regexp,
            require_cosign=bool(args.require_cosign),
        )
        checksum_ok = bool(checksum_report.get("ok"))
        cosign_ok = bool(cosign_report.get("ok", False))
        skipped = bool(cosign_report.get("skipped", False))
        overall_ok = checksum_ok and (cosign_ok or skipped)

    payload = {
        "assets_dir": str(assets_dir),
        "overall_ok": overall_ok,
        "checksum": checksum_report,
        "cosign": cosign_report,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    raise SystemExit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
