#!/usr/bin/env python3
"""Scan workspace for likely secrets/PII before opening repository publicly."""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from typing import List, Tuple

IGNORE_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "runtime"}
PLACEHOLDER_TOKENS = {"change_me", "example", "placeholder", "your_", "dev_", "xxxx", "redacted"}

GITIGNORE_REQUIRED = [".env", ".env.*", "!.env.example"]

GENERIC_SECRET_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("Potential OpenAI API key pattern", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("Potential GitHub classic token pattern", re.compile(r"ghp_[A-Za-z0-9]{30,}")),
    ("Potential GitHub fine-grained token pattern", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("Potential Google API key pattern", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Potential Telegram bot token pattern", re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("Potential Slack token pattern", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "Potential JWT token pattern",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    ("Potential private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Potential credential-in-URL pattern", re.compile(r"https?://[^/\s:@]+:[^@\s]+@[^/\s]+")),
]

ENV_SECRET_PATTERN = re.compile(
    r"^\s*(NETWORK_SHARED_SECRET|PRIVATE_API_TOKEN|PRIVATE_RPC_URL|WALLET_[A-Z0-9_]+)\s*=\s*(.+?)\s*$"
)

HEX_WALLET_PATTERN = re.compile(r"0x[a-fA-F0-9]{40}")


@dataclass
class Finding:
    file_path: str
    line_no: int
    reason: str
    snippet: str


def likely_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in PLACEHOLDER_TOKENS)


def redact_secret(value: str, left: int = 4, right: int = 4) -> str:
    token = value.strip()
    if not token:
        return ""
    if len(token) <= left + right:
        return "*" * len(token)
    return f"{token[:left]}...{token[-right:]}"


def sanitize_snippet(snippet: str) -> str:
    redacted = snippet
    for _, pattern in GENERIC_SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: redact_secret(match.group(0)), redacted)
    redacted = HEX_WALLET_PATTERN.sub(lambda match: redact_secret(match.group(0)), redacted)
    return redacted


def scan_file(file_path: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except (UnicodeDecodeError, OSError):
        return findings

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()

        env_match = ENV_SECRET_PATTERN.match(stripped)
        if env_match:
            key = env_match.group(1)
            if key.endswith("_PATTERN"):
                continue
            value = env_match.group(2).strip().strip('"').strip("'")
            if value and not likely_placeholder(value):
                findings.append(
                    Finding(
                        file_path=file_path,
                        line_no=idx,
                        reason=f"Non-placeholder value for {key}",
                        snippet=f"{key}={redact_secret(value)}",
                    )
                )

        for reason, pattern in GENERIC_SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        file_path=file_path,
                        line_no=idx,
                        reason=reason,
                        snippet=sanitize_snippet(stripped[:220]),
                    )
                )

        if HEX_WALLET_PATTERN.search(line) and ".env.example" not in file_path:
            findings.append(
                Finding(
                    file_path=file_path,
                    line_no=idx,
                    reason="Potential wallet address found outside template",
                    snippet=sanitize_snippet(stripped[:220]),
                )
            )

    return findings


def scan_workspace(root: str) -> List[Finding]:
    findings: List[Finding] = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for name in files:
            if name.endswith((".pyc", ".png", ".jpg", ".jpeg", ".gif", ".pdf")):
                continue
            file_path = os.path.join(base, name)
            if os.path.abspath(file_path) == os.path.abspath(__file__):
                continue
            findings.extend(scan_file(file_path))
    return findings


def check_gitignore(root: str) -> List[str]:
    issues: List[str] = []
    path = os.path.join(root, ".gitignore")
    if not os.path.exists(path):
        return ["Missing .gitignore"]
    try:
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except OSError:
        return ["Unable to read .gitignore"]

    for rule in GITIGNORE_REQUIRED:
        if rule not in content:
            issues.append(f"Missing .gitignore rule: {rule}")
    return issues


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PII/secret scanner before public git open.")
    parser.add_argument("--root", default=".", help="Workspace root path.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = os.path.abspath(args.root)
    findings = scan_workspace(root)
    gitignore_issues = check_gitignore(root)

    if not findings and not gitignore_issues:
        print("Sanitize check passed: no obvious secrets/PII detected.")
        return

    if gitignore_issues:
        print("Gitignore issues:")
        for issue in gitignore_issues:
            print(f"- {issue}")

    if findings:
        print("Potential secret/PII findings:")
        for finding in findings:
            print(f"- {finding.file_path}:{finding.line_no} | {finding.reason} | {finding.snippet}")

    sys.exit(1)


if __name__ == "__main__":
    main()
