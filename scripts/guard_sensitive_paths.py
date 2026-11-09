#!/usr/bin/env python3
"""The sensitive-path guard for ``.github/workflows/automerge.yml``.

The repository auto-merges an approved pull request whose ``ci`` is green, with
one exception: **a person merges anything that widens what the automation can
reach** -- the workflows, the published artifact and its packaging, the secret
scan configuration, and the test suite that decides what ``ci`` accepts.

That rule used to live as one ``grep -E`` inside the workflow, where nothing
could test it and a small regex edit would silently widen auto-merge. It lives
here instead, with ``tests/test_guard_sensitive_paths.py`` pinning the paths
that must be refused and the ones that must not be.

Usage (the workflow pipes the *immutable* two-SHA comparison into it, never the
pull request's mutable ``files`` endpoint -- a head that moved A -> B -> A could
show B's harmless files while A merges)::

    gh api "repos/$REPO/compare/$base...$head" \\
      | python3 scripts/guard_sensitive_paths.py --declared "$changedFiles"

Exit codes: ``0`` nothing sensitive, safe to auto-merge; ``2`` a human must merge
(a sensitive path, or a file list too short to prove completeness); ``1`` the
input was unusable -- also a refusal, because the guard must fail closed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence

#: Anchored at the start: ``src/tests/helpers.py`` is ordinary code, ``tests/`` is not. ``$`` after a
#: filename keeps ``docs/Dockerfile.md`` ordinary while ``Dockerfile`` is not.
SENSITIVE_PATTERNS: tuple[str, ...] = (
    r"^\.github/",
    r"^Dockerfile$",
    r"^docker-compose\.yml$",
    r"^deploy/",
    r"^pyproject\.toml$",
    # The lock decides what CI installs under ``uv sync --frozen``, so a lock-only change can change what
    # runs there. The interpreter pin chooses the runtime, and the ignore list decides what enters the image.
    r"^uv\.lock$",
    r"^\.python-version$",
    r"^\.dockerignore$",
    r"^\.gitleaks\.toml$",
    r"^tests/",
    # The workflows execute scripts/ on the default branch: this guard, and the approval rule the gate and
    # the merge both apply. Leaving them out of their own guard would let one approved pull request disable
    # the guard, and every pull request after it merge without a person.
    r"^scripts/",
)
SENSITIVE = re.compile("|".join(SENSITIVE_PATTERNS))


class Unusable(Exception):
    """The comparison cannot be evaluated, so the guard cannot clear the pull request."""


def _names(document: dict) -> list[str]:
    """Every path the comparison names, both sides of a rename (``previous_filename``)."""
    files = document.get("files")
    if not isinstance(files, list):
        raise Unusable("the comparison carries no file list")
    names: list[str] = []
    for entry in files:
        if not isinstance(entry, dict):
            raise Unusable("the comparison carries a file entry that is not an object")
        for key in ("filename", "previous_filename"):
            name = entry.get(key)
            if name is None:
                continue
            if not isinstance(name, str) or not name:
                raise Unusable(f"a file entry has an unusable {key}")
            names.append(name)
    return names


def sensitive_paths(document: dict, declared: int) -> tuple[list[str], int]:
    """The sensitive paths among the files, and how many file entries the comparison listed.

    ``declared`` is the pull request's own changed-file count. ``compare`` caps its list (300 files),
    so a shorter list than the pull request reports means the guard cannot see everything and must
    refuse rather than clear a pull request on a partial view.
    """
    names = _names(document)
    listed = len(document["files"])
    if listed < declared:
        raise Unusable(f"the comparison lists {listed} of {declared} changed files, so the guard cannot see everything")
    return [name for name in names if SENSITIVE.search(name)], listed


def main(argv: Sequence[str] | None = None, stdin=None) -> int:
    parser = argparse.ArgumentParser(description="Refuse an auto-merge that touches what the automation reaches.")
    parser.add_argument("--declared", type=int, default=0, help="the pull request's changed-file count")
    arguments = parser.parse_args(argv)
    try:
        document = json.load(sys.stdin if stdin is None else stdin)
    except ValueError as exc:
        print(f"::error::the comparison is not JSON: {exc}")
        return 1
    if not isinstance(document, dict):
        print("::error::the comparison is not an object")
        return 1
    try:
        hits, listed = sensitive_paths(document, arguments.declared)
    except Unusable as exc:
        print(f"guard: {exc}; a human must merge this pull request")
        return 2
    if hits:
        print(f"guard: needs a human merge, it touches: {' '.join(hits)}")
        return 2
    print(f"guard: {listed} changed file(s), none sensitive")
    return 0


if __name__ == "__main__":
    sys.exit(main())
