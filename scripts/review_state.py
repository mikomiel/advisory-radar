#!/usr/bin/env python3
"""The approval rule: which review counts, at which commit, and what that means.

Two workflows need this one answer -- ``automerge.yml`` ("may I merge this head?") and ``review-gate.yml``
("what should the required ``review`` status say?"). Keeping it in one tested place stops the two from
drifting: a merge path that accepts an approval the gate rejects (or the reverse) is worse than either
rule alone.

Printing contract: one line, ``state<TAB>description``, where ``state`` is a GitHub commit-status state
(``success``, ``failure`` or ``pending``). Exit code is ``0`` only for ``success``, so a caller that only
tests the exit code cannot accidentally treat "awaiting review" as an approval.

Rules, mirroring GitHub's own semantics:

* a review counts when it comes from the configured identity (matched on both ``user.login`` and REST
  ``user.type``, so a human account with the same name cannot pass) **or** from someone with repository
  access -- ``author_association`` of ``OWNER``, ``MEMBER`` or ``COLLABORATOR``. The second route is what
  lets a maintainer approve a contributor's pull request, which the App cannot do for its own;
* a later ``COMMENTED`` review does not undo an earlier approval, but a later ``CHANGES_REQUESTED`` or
  ``DISMISSED`` does;
* an approval is about one commit: it counts only at the head being considered, because a push after the
  review is a change nobody approved.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Sequence

#: Review states that decide the outcome. ``COMMENTED`` and ``PENDING`` are opinions-in-passing, not verdicts.
DECISIVE = frozenset({"APPROVED", "CHANGES_REQUESTED", "DISMISSED"})
#: ``author_association`` values GitHub sets for someone with access to the repository. A stranger's review
#: reports ``NONE`` or ``CONTRIBUTOR``, so this is the line between "a maintainer approved" and "anyone did".
TRUSTED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
SUCCESS = "success"
FAILURE = "failure"
PENDING = "pending"


def _submitted(review: dict) -> str:
    return str(review.get("submitted_at") or "")


def eligible(
    review: dict, reviewer: str, reviewer_type: str, associations: frozenset[str] = TRUSTED_ASSOCIATIONS
) -> bool:
    """Whether this review may count: the configured identity, or somebody with repository access."""
    user = review.get("user")
    if not isinstance(user, dict):
        return False
    if user.get("login") == reviewer and user.get("type") == reviewer_type:
        return True
    return str(review.get("author_association") or "").upper() in associations


def matching_reviews(
    reviews: Iterable[object],
    reviewer: str,
    reviewer_type: str,
    associations: frozenset[str] = TRUSTED_ASSOCIATIONS,
) -> list[dict]:
    """The reviews that may count, oldest first."""
    kept = [
        review
        for review in reviews
        if isinstance(review, dict) and eligible(review, reviewer, reviewer_type, associations)
    ]
    return sorted(kept, key=_submitted)


def current_verdicts(
    reviews: Iterable[object],
    reviewer: str,
    reviewer_type: str,
    associations: frozenset[str] = TRUSTED_ASSOCIATIONS,
) -> dict[str, dict]:
    """Each eligible identity's latest decisive review, keyed by login.

    Per reviewer, not globally: one person approving must not silently withdraw another person's outstanding
    change request, and one person dismissing a review must not erase another's approval. That is also how
    GitHub treats them -- every reviewer keeps their own verdict on the pull request.
    """
    latest: dict[str, dict] = {}
    for review in matching_reviews(reviews, reviewer, reviewer_type, associations):
        if str(review.get("state") or "").upper() not in DECISIVE:
            continue  # a comment is not a verdict and never replaces one
        latest[str((review.get("user") or {}).get("login") or "")] = review
    return latest


def deciding_review(
    reviews: Iterable[object],
    reviewer: str,
    reviewer_type: str,
    associations: frozenset[str] = TRUSTED_ASSOCIATIONS,
) -> dict:
    """The review behind the verdict: an outstanding change request, else the approval, else the last one."""
    verdicts = list(current_verdicts(reviews, reviewer, reviewer_type, associations).values())
    for wanted in ("CHANGES_REQUESTED", "APPROVED"):
        matching = [review for review in verdicts if str(review.get("state") or "").upper() == wanted]
        if matching:
            return max(matching, key=_submitted)
    return max(verdicts, key=_submitted) if verdicts else {}


def _who(review: dict, fallback: str) -> str:
    return str((review.get("user") or {}).get("login") or fallback)


def verdict(
    reviews: Iterable[object],
    reviewer: str,
    reviewer_type: str,
    head: str,
    associations: frozenset[str] = TRUSTED_ASSOCIATIONS,
) -> tuple[str, str]:
    """``(state, description)`` for one head: can a merge rely on this review, and what should we say?"""
    verdicts = current_verdicts(reviews, reviewer, reviewer_type, associations)
    short_head = head[:12]
    outstanding = [
        review for review in verdicts.values() if str(review.get("state") or "").upper() == "CHANGES_REQUESTED"
    ]
    if outstanding:
        review = max(outstanding, key=_submitted)
        commit = str(review.get("commit_id") or "")
        return FAILURE, f"changes requested at {commit[:12]} by {_who(review, reviewer)}"
    approved = [review for review in verdicts.values() if str(review.get("state") or "").upper() == "APPROVED"]
    at_head = [review for review in approved if str(review.get("commit_id") or "") == head]
    if at_head:
        return SUCCESS, f"approved at {short_head} by {_who(max(at_head, key=_submitted), reviewer)}"
    if approved:
        review = max(approved, key=_submitted)
        commit = str(review.get("commit_id") or "")
        return (
            PENDING,
            f"{_who(review, reviewer)} approved {commit[:12]}, head is {short_head}: a fresh review is needed",
        )
    if verdicts:
        review = max(verdicts.values(), key=_submitted)
        return PENDING, f"{_who(review, reviewer)}'s review was dismissed; a new review is needed"
    return PENDING, f"awaiting a review from {reviewer} or a maintainer"


def main(argv: Sequence[str] | None = None, stdin=None) -> int:
    parser = argparse.ArgumentParser(description="Decide whether a head carries an acceptable approval.")
    parser.add_argument("--reviewer", required=True, help="the configured reviewing identity, e.g. app[bot]")
    parser.add_argument("--type", default="Bot", help="the REST user type that must match (default Bot)")
    parser.add_argument("--head", required=True, help="the commit under consideration")
    parser.add_argument("--reviews", help="a file holding the reviews JSON array (default: stdin)")
    parser.add_argument(
        "--trusted-associations",
        default=",".join(sorted(TRUSTED_ASSOCIATIONS)),
        help="comma-separated author_association values that may also approve; empty disables that route",
    )
    arguments = parser.parse_args(argv)
    associations = frozenset(
        value.strip().upper() for value in arguments.trusted_associations.split(",") if value.strip()
    )
    source = sys.stdin if stdin is None else stdin
    try:
        if arguments.reviews:
            with open(arguments.reviews, encoding="utf-8") as handle:
                document = json.load(handle)
        else:
            document = json.load(source)
    except (OSError, ValueError) as exc:
        # Unreadable reviews are not "approved": say so, and never exit 0.
        print(f"{PENDING}\tno usable review list: {exc}")
        return 3
    reviews = document if isinstance(document, list) else []
    state, description = verdict(reviews, arguments.reviewer, arguments.type, arguments.head, associations)
    print(f"{state}\t{description}")
    return 0 if state == SUCCESS else 3


if __name__ == "__main__":
    sys.exit(main())
