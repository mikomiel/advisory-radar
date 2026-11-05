#!/usr/bin/env python3
"""CI guard: fail if any tracked file contains internal/estate identifiers.

Public repository rule: no secrets, no internal hostnames, IPs, webhook URLs,
container numbers or runbook fragments. This script scans every git-tracked
file for those patterns. It is also run in CI (.github/workflows/ci.yml).

Patterns are deliberately specific to one private estate; generic words like
"homelab" or vendor names are fine.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# (label, pattern) — compiled once. Each must be specific enough that a
# legitimate public occurrence is implausible.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private domain", re.compile(r"kiciateam\.eu|kicia\.team|mielczarek\.com\.pl")),
    ("private IPv4 range", re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b|\b10\.0\.\d{1,3}\.\d{1,3}\b")),
    ("internal container id", re.compile(r"\bCT1\d\d\b")),
    ("live webhook URL", re.compile(r"(discord|discordapp)\.com/api/webhooks/\S+|hooks\.slack\.com/services/\S+")),
    ("credential store name", re.compile(r"\binfisical\b", re.IGNORECASE)),
    ("internal secret path", re.compile(r"/etc/ops-notify/|ops-notify")),
    ("internal proxy host", re.compile(r"agent-vault|agent_vault")),
]

SKIP_FILES = {"scripts/check_no_estate_identifiers.py", ".gitleaks.toml", "uv.lock"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2"}


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True, check=True)
    return [line for line in out.stdout.splitlines() if line]


def main() -> int:
    failures: list[str] = []
    for rel in tracked_files():
        if rel in SKIP_FILES or Path(rel).suffix.lower() in SKIP_SUFFIXES:
            continue
        path = REPO / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for label, pattern in PATTERNS:
                if pattern.search(line):
                    failures.append(f"{rel}:{lineno}: {label}: {line.strip()[:120]}")
    if failures:
        print("estate/internal identifiers found in tracked files:", file=sys.stderr)
        for failure in failures[:50]:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(f"OK: no internal identifiers in {len(tracked_files())} tracked files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
