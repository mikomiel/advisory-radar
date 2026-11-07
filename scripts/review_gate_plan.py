#!/usr/bin/env python3
"""Turn a snapshot of open pull requests into one status decision per head commit.

The gate publishes a *commit status*, and a status is keyed by (sha, context) -- not by pull request. Two
open pull requests can share a head commit (a branch and a copy of it), and then a single status must speak
for both. Publishing whichever pull request was processed last would let an approved one turn a
changes-requested one green, so this script aggregates conservatively: the worst verdict among the pull
requests sharing a head wins, and the description names them all.

Input: a JSON array of ``{number, head, draft, author, changed, reviews, files}`` on stdin -- one entry per
open pull request, with the reviews exactly as the API returned them, ``changed`` the pull request's own
changed-file count, and ``files`` the entries of the immutable ``compare`` (``filename`` and
``previous_filename``). Flattening renames is this script's job, so that it is tested.

Output: one line per head, ``head<TAB>state<TAB>description``, where state is a GitHub status state. The
caller publishes these; it decides nothing.

The approval rule itself lives in :mod:`review_state` and is imported, not copied -- the gate and the merge
workflow must not be able to disagree about what an approval is.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The scripts directory is not a package: import the rule by path so the merge workflow and this gate share
# one implementation instead of two that can drift.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import review_state  # noqa: E402

#: Higher blocks more: a shared head is only green when every pull request on it is green.
SEVERITY = {"success": 1, "pending": 2, "failure": 3}
MAX_DESCRIPTION = 140
#: Authors whose pull requests do not need an App review, and only while every changed path stays inside
#: DEPENDENCY_PATHS. Dependabot's updates are mechanical and `ci` (the image build included) still has to pass.
#: The login is GitHub's, not the pull request's, so a patch cannot claim it. A pull request the exemption
#: covers is not taken by automerge.yml, which requires an APPROVED review decision an exempt pull request
#: does not have. GitHub's own auto-merge switch is separate: while `allow_auto_merge` is on, a write-access
#: user can have GitHub merge an exempt bump once its checks are green.
EXEMPT_AUTHORS = frozenset({"app/dependabot", "dependabot[bot]"})
#: Paths a dependency update may touch for the exemption to apply, checked rather than assumed. Files match
#: exactly -- ``Dockerfile/evil.py`` is somebody deleting the manifest and adding a directory of source, not a
#: dependency update -- and only the workflow tree matches as a prefix.
DEPENDENCY_FILES = frozenset({"pyproject.toml", "uv.lock", "Dockerfile", "docker-compose.yml"})
DEPENDENCY_DIRECTORIES = (".github/workflows/",)


def _changed_names(entry: dict) -> list[str]:
    """Every path the comparison names, both sides of a rename; empty when the list is unusable."""
    files = entry.get("files")
    if not isinstance(files, list) or not files:
        return []
    names: list[str] = []
    for item in files:
        if not isinstance(item, dict):
            return []
        name = item.get("filename")
        if not isinstance(name, str) or not name:
            return []
        names.append(name)
        previous = item.get("previous_filename")
        if isinstance(previous, str) and previous:
            names.append(previous)
    return names


def _dependency_only(names: list[str]) -> bool:
    """Whether every changed path is a dependency manifest the exemption may cover."""
    if not names:
        return False
    for name in names:
        if name in DEPENDENCY_FILES:
            continue
        if any(name.startswith(directory) for directory in DEPENDENCY_DIRECTORIES):
            continue
        return False
    return True


def exempt(entry: dict, author: str, exempt_authors: frozenset[str]) -> bool:
    """Whether the exemption covers this entry: an exempt author, on a complete, manifest-only path list.

    Fail-closed in three places: an unreadable list is not exempt, a list shorter than the pull request's own
    changed-file count is not exempt (``compare`` caps its list at 300, so a source file could hide past the
    cap), and an empty list is not exempt.
    """
    if author not in exempt_authors:
        return False
    files = entry.get("files")
    declared = entry.get("changed")
    if not isinstance(files, list) or not isinstance(declared, int) or declared < 1:
        return False
    if len(files) < declared:
        return False
    return _dependency_only(_changed_names(entry))


def merge(
    entries: list[object],
    reviewer: str,
    reviewer_type: str,
    associations: frozenset[str],
    exempt_authors: frozenset[str] = EXEMPT_AUTHORS,
) -> list[tuple[str, str, str]]:
    """``(head, state, description)`` for every head in the snapshot, worst verdict winning."""
    decisions: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        head = str(entry.get("head") or "")
        if not head:
            continue
        number = entry.get("number")
        author = str(entry.get("author") or "")
        if entry.get("draft"):
            # A draft is not mergeable; saying so revokes a success left over from before it was a draft.
            state, description = "pending", "pull request is a draft"
        elif exempt(entry, author, exempt_authors):
            # An exemption, not a review, and only where no eligible reviewer has said *anything*: any review at
            # all -- including a comment that holds the change -- is used as-is rather than read as approval.
            reviews = entry.get("reviews")
            ours = reviews if isinstance(reviews, list) else []
            if review_state.matching_reviews(ours, reviewer, reviewer_type, associations):
                state, description = review_state.verdict(ours, reviewer, reviewer_type, head, associations)
            else:
                state = "success"
                description = f"dependency update by {author}: App review not required"
        else:
            reviews = entry.get("reviews")
            state, description = review_state.verdict(
                reviews if isinstance(reviews, list) else [], reviewer, reviewer_type, head, associations
            )
        severity = SEVERITY.get(state, SEVERITY["pending"])
        current = decisions.get(head)
        numbers = list(current["numbers"]) if current else []
        if isinstance(number, int) and number not in numbers:
            numbers.append(number)  # every pull request on this head, not only the ones at the worst severity
        if current is None or severity > current["severity"]:
            decisions[head] = {"severity": severity, "state": state, "description": description, "numbers": numbers}
        else:
            current["numbers"] = numbers
    plan = []
    for head, decision in sorted(decisions.items()):
        # Sorted: the description must be identical whatever order the API listed the pull requests in, or an
        # unchanged verdict would be republished every sweep (and GitHub keeps only 1000 statuses per head).
        numbers = "".join(f" #{n}" for n in sorted(decision["numbers"]))
        description = f"{decision['description']}{numbers}"[:MAX_DESCRIPTION]
        plan.append((head, decision["state"], description))
    return plan


def main(argv: list[str] | None = None, stdin=None) -> int:
    parser = argparse.ArgumentParser(description="One status decision per head commit from an open-PR snapshot.")
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--type", default="Bot")
    parser.add_argument("--trusted-associations", default=",".join(sorted(review_state.TRUSTED_ASSOCIATIONS)))
    parser.add_argument(
        "--exempt-authors",
        default=",".join(sorted(EXEMPT_AUTHORS)),
        help="comma-separated authors whose pull requests need no App review; empty disables the exemption",
    )
    arguments = parser.parse_args(argv)
    associations = frozenset(
        value.strip().upper() for value in arguments.trusted_associations.split(",") if value.strip()
    )
    try:
        document = json.load(sys.stdin if stdin is None else stdin)
    except ValueError as exc:
        # No decisions at all: the caller must not publish a success from a snapshot it could not read.
        print(f"::error::the snapshot is not JSON: {exc}")
        return 1
    if not isinstance(document, list):
        print("::error::the snapshot is not an array")
        return 1
    exempt_authors = frozenset(value.strip() for value in arguments.exempt_authors.split(",") if value.strip())
    for head, state, description in merge(document, arguments.reviewer, arguments.type, associations, exempt_authors):
        print(f"{head}\t{state}\t{description}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
