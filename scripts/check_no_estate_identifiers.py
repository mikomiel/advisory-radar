#!/usr/bin/env python3
"""CI guard: fail if any tracked file contains internal/estate identifiers.

Public repository rule: no secrets, no internal hostnames, IPs, webhook URLs,
container numbers or runbook fragments. This script matches those patterns
against every path in the git index and against the content of every blob the
index names. It is also run in CI (.github/workflows/ci.yml).

Patterns are deliberately specific to one private estate; generic words like
"homelab" or vendor names are fine.

The guard fails closed: what it cannot read or classify is a failure, never a
pass.

* Content comes from the blobs (``git cat-file --batch``), not from the work
  tree. A symlink is stored as its target text, so the target is scanned, and
  a file that is unreadable on this machine is scanned like any other.
* Every blob is decoded as UTF-8 with ``errors="replace"``, so a file that is
  not UTF-8 is still matched, and so are ASCII text next to a stray NUL byte
  and the raw ASCII inside image data: a NUL byte does not make a blob binary.
  A blob that holds a NUL byte is read as text in UTF-16 and UTF-32 as well,
  because every ASCII character of such text is written with NUL bytes (a
  Windows tool saves a file that way, with or without a byte order mark): once
  per encoding and byte order, from the first byte. A blob without a NUL byte
  cannot hold an ASCII identifier in a wide encoding, so no wide text slips
  between the readings. Two inputs are reported clean and are known limits: an
  identifier that a NUL byte splits, which no reading joins again, and UTF-32
  text that follows a prefix of one to three bytes, which only some of the
  readings realign. The suffix decides nothing: an ``.svg`` is text, and a
  text file named ``.png`` is read.
* Path names are matched too.
* The content of one file is not read: this script, which lists what it looks
  for. The lock file and the secret-scan configuration are read like any other
  file.
* A git error, an object that cannot be read, output that does not parse, or
  an index with no entry ends in status 2 with the reason, never in ``OK``.

Exit status: 0 nothing found, 1 identifiers found, 2 the scan could not
complete.

The scan reads the index, so it covers what a commit carries. Stage a change
before a local run: an edit that is not staged, and a file that is not added,
are not scanned.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
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

#: Content that is deliberately not scanned: only this script, whose text lists what it looks for and so matches two
#: of its own patterns. Its path name is still matched. Every other file is read, the lock and the secret-scan
#: configuration included: a lock generated against a private index names that index in every package entry it
#: resolved there, and a comment in the configuration can name a host as easily as any other file can.
SKIP_FILES = {"scripts/check_no_estate_identifiers.py"}

#: The encodings in which every ASCII character is written with NUL bytes, so that a text file in one of them is a
#: blob that holds NUL bytes. Each is applied from the first byte whether or not a byte order mark is there, and
#: only to a blob that holds a NUL byte, beside its UTF-8 reading.
WIDE_CODECS = ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")

#: A submodule entry is a commit of another repository: it has no blob here, so only its path name is matched.
GITLINK = "160000"
MAX_REPORTED = 50

# ``git ls-files -s``: "<mode> <object> <stage>", a TAB, then the path. ``cat-file --batch``: "<object> <type> <size>".
INDEX_META = re.compile(rb"([0-7]{6}) ([0-9a-f]{40,64}) [0-3]")
OBJECT_HEADER = re.compile(rb"([0-9a-f]{40,64}) ([a-z]+) ([0-9]+)")


class ScanError(Exception):
    """The scan could not look at everything, so it cannot vouch for anything."""


@dataclass(frozen=True)
class Entry:
    mode: str
    oid: str
    path: str  # decoded with errors="replace": it is matched and shown, never opened


def show(text: str, limit: int = 120) -> str:
    """One printable line. A control character in a path or in a file must not start a line of its own: CI reads
    a line that begins with ``::`` as a workflow command."""
    return "".join(ch if ch.isprintable() else ascii(ch)[1:-1] for ch in text.strip()[:limit])


def git(*args: str, data: bytes | None = None) -> bytes:
    try:
        done = subprocess.run(["git", "-C", str(REPO), *args], input=data, capture_output=True, check=True)
    except OSError as exc:
        raise ScanError(f"cannot run git: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        detail = show(exc.stderr.decode("utf-8", errors="replace"), 300)
        raise ScanError(f"git {args[0]} exited with status {exc.returncode}: {detail}") from exc
    return done.stdout


def index_entries() -> list[Entry]:
    """Every index entry, every stage of an unmerged path included (``-z``: no quoting, a name may hold anything)."""
    entries: list[Entry] = []
    for record in git("ls-files", "-s", "-z").split(b"\0"):
        if not record:
            continue
        meta, tab, name = record.partition(b"\t")
        found = INDEX_META.fullmatch(meta)
        if not tab or found is None:
            raise ScanError(f"unexpected output from git ls-files: {show(record.decode('utf-8', errors='replace'))}")
        entries.append(Entry(found[1].decode(), found[2].decode(), name.decode("utf-8", errors="replace")))
    if not entries:
        raise ScanError("the index lists no file, so there is nothing to scan")
    return entries


def split_batch(output: bytes, oids: list[str]) -> list[bytes]:
    """Cut ``git cat-file --batch`` output into one blob per requested object, checking every frame."""
    blobs: list[bytes] = []
    offset = 0
    for oid in oids:
        end = output.find(b"\n", offset)
        header = output[offset:end] if end >= 0 else b""
        found = OBJECT_HEADER.fullmatch(header)
        if found is None or found[1].decode() != oid:
            raise ScanError(f"git cannot read object {oid}: {show(header.decode('utf-8', errors='replace'))}")
        if found[2] != b"blob":
            raise ScanError(f"object {oid} is a {found[2].decode()}, not a blob")
        start = end + 1
        stop = start + int(found[3])
        if output[stop : stop + 1] != b"\n":
            raise ScanError(f"the content of object {oid} is shorter than git declared")
        blobs.append(output[start:stop])
        offset = stop + 1
    if offset != len(output):
        raise ScanError("git returned more output than objects were requested")
    return blobs


def read_blobs(entries: list[Entry]) -> list[tuple[Entry, bytes | None]]:
    """Each entry with the content of its blob, or ``None`` for a submodule."""
    wanted = [entry for entry in entries if entry.mode != GITLINK]
    request = "".join(f"{entry.oid}\n" for entry in wanted).encode()
    contents = iter(split_batch(git("cat-file", "--batch", data=request), [entry.oid for entry in wanted]))
    return [(entry, None if entry.mode == GITLINK else next(contents)) for entry in entries]


def readings(content: bytes) -> list[str]:
    """The texts that a blob may hold: UTF-8 always, and one text per wide encoding when it holds a NUL byte.

    No encoding is chosen: a reading that is wrong for the blob is noise and matches none of the patterns (they
    need ASCII characters in a row), so no heuristic can pick the wrong one. The UTF-8 reading is never dropped,
    because a NUL byte turns no ASCII text into anything else: a stray one, or the zeros inside binary data, must
    not hide an identifier that stands next to it. Binary data is read the same way and yields a match only when
    its bytes spell an identifier.
    """
    texts = [content.decode("utf-8", errors="replace")]
    if b"\0" in content:
        texts += [content.decode(codec, errors="replace") for codec in WIDE_CODECS]
    return texts


def scan(blobs: list[tuple[Entry, bytes | None]]) -> list[str]:
    findings: list[str] = []
    for entry, content in blobs:
        where = show(entry.path, 200)
        for label, pattern in PATTERNS:
            if pattern.search(entry.path):
                findings.append(f"{where}: {label}: in the path name")
        if content is None or entry.path in SKIP_FILES:
            continue
        for text in readings(content):
            for lineno, line in enumerate(text.splitlines(), start=1):
                for label, pattern in PATTERNS:
                    if pattern.search(line):
                        findings.append(f"{where}:{lineno}: {label}: {show(line)}")
    return findings


def main() -> int:
    try:
        blobs = read_blobs(index_entries())
    except ScanError as exc:
        print(f"estate-identifier guard could not complete: {exc}", file=sys.stderr)
        return 2
    findings = scan(blobs)
    if findings:
        print("estate/internal identifiers found in tracked files:", file=sys.stderr)
        for finding in findings[:MAX_REPORTED]:
            print(f"  {finding}", file=sys.stderr)
        if len(findings) > MAX_REPORTED:
            print(f"  ... and {len(findings) - MAX_REPORTED} more", file=sys.stderr)
        return 1
    print(f"OK: no internal identifiers in {len({entry.path for entry, _ in blobs})} tracked files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
