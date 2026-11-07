#!/usr/bin/env python3
"""Turn a snapshot of open pull requests into one status decision per head commit.

The gate publishes a *commit status*, and a status is keyed by (sha, context) -- not by pull request. Two
open pull requests can share a head commit (a branch and a copy of it), and then a single status must speak
for both. Publishing whichever pull request was processed last would let an approved one turn a
changes-requested one green, so this script aggregates conservatively: the worst verdict among the pull
requests sharing a head wins, and the description names them all.

Input: a JSON array of ``{number, head, draft, reviews}`` on stdin -- one entry per open pull request, with
the reviews exactly as the API returned them.

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
#: Authors whose pull requests do not need an App review. Dependabot's updates are mechanical, its pull
#: requests touch `.github/workflows` or the lockfile -- which the sensitive-path guard already routes to a
#: person -- and `ci` (including the image build) still has to pass. The login is GitHub's, not the pull
#: request's, so it cannot be claimed by a patch. A real verdict always wins: this only fills the gap where
#: nobody reviewed the pull request.
EXEMPT_AUTHORS = frozenset({"app/dependabot", "dependabot[bot]"})


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
        elif author in exempt_authors:
            # An exemption, not a review: it only covers the case where no verdict exists at all.
            reviews = entry.get("reviews")
            state, description = review_state.verdict(
                reviews if isinstance(reviews, list) else [], reviewer, reviewer_type, head, associations
            )
            if state == "pending":
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
