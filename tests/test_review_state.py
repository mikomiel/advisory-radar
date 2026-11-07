"""The approval rule that both the merge workflow and the review gate rely on.

The merge path and the required ``review`` status must agree: a status that says "approved" while the
merge refuses (or worse, the reverse) is a rule with two owners. So the rule is tested here, at the one
place both callers read.
"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_state.py"
REVIEWER = "review-bot[bot]"
HEAD = "195e30d8b02d5ba36e30caf889bb6bb3b1be92e2"


def load_rule():
    spec = importlib.util.spec_from_file_location("review_state", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rule = load_rule()


def review(
    state: str,
    commit: str = HEAD,
    login: str = REVIEWER,
    kind: str = "Bot",
    at: str = "2026-11-07T00:10:00Z",
    association: str = "NONE",
):
    return {
        "state": state,
        "commit_id": commit,
        "submitted_at": at,
        "author_association": association,
        "user": {"login": login, "type": kind},
    }


def maintainer(state: str, commit: str = HEAD, association: str = "OWNER") -> dict:
    return review(state, commit=commit, login="a-maintainer", kind="User", association=association)


def state_of(reviews: list[dict], head: str = HEAD) -> tuple[str, str]:
    return rule.verdict(reviews, REVIEWER, "Bot", head)


def test_an_approval_at_the_head_is_the_only_success():
    assert state_of([review("APPROVED")])[0] == "success"


def test_an_approval_at_an_earlier_commit_does_not_count():
    state, description = state_of([review("APPROVED", commit="0" * 40)])
    assert state == "pending"
    assert "fresh review is needed" in description


def test_changes_requested_blocks_at_any_commit():
    assert state_of([review("CHANGES_REQUESTED")])[0] == "failure"
    assert state_of([review("CHANGES_REQUESTED", commit="0" * 40)])[0] == "failure"


def test_no_review_awaits_one():
    state, description = state_of([])
    assert state == "pending" and "awaiting a review" in description


def test_a_comment_is_not_an_approval():
    assert state_of([review("COMMENTED")])[0] == "pending"


def test_a_later_comment_does_not_undo_an_approval():
    reviews = [review("APPROVED", at="2026-11-07T00:10:00Z"), review("COMMENTED", at="2026-11-07T00:20:00Z")]
    assert state_of(reviews)[0] == "success"


def test_a_later_change_request_does_undo_an_approval():
    reviews = [review("APPROVED", at="2026-11-07T00:10:00Z"), review("CHANGES_REQUESTED", at="2026-11-07T00:20:00Z")]
    assert state_of(reviews)[0] == "failure"


def test_a_dismissed_review_is_not_an_approval():
    reviews = [review("APPROVED", at="2026-11-07T00:10:00Z"), review("DISMISSED", at="2026-11-07T00:20:00Z")]
    assert state_of(reviews)[0] == "pending"


def test_a_human_account_with_the_same_name_is_not_the_reviewer():
    # the REST user.type is what separates an App bot from a human who took its name
    assert state_of([review("APPROVED", kind="User")])[0] == "pending"


def test_a_review_by_another_identity_is_ignored():
    assert state_of([review("APPROVED", login="someone-else")])[0] == "pending"


def test_the_latest_decisive_review_wins():
    reviews = [
        review("CHANGES_REQUESTED", commit="0" * 40, at="2026-11-07T00:10:00Z"),
        review("APPROVED", at="2026-11-07T00:20:00Z"),
    ]
    assert state_of(reviews)[0] == "success"


def test_malformed_entries_are_ignored_rather_than_crashing():
    assert state_of([{"user": None}, "noise", 7])[0] == "pending"  # type: ignore[list-item]


@pytest.mark.parametrize("document", ["{not json", "null"])
def test_an_unreadable_review_list_is_never_an_approval(document: str):
    assert rule.main(["--reviewer", REVIEWER, "--head", HEAD], stdin=io.StringIO(document)) == 3


def test_the_cli_prints_state_and_description_and_exits_nonzero_unless_approved():
    approved = io.StringIO(json.dumps([review("APPROVED")]))
    printed = io.StringIO()
    real_stdout, rule.sys.stdout = rule.sys.stdout, printed
    try:
        code = rule.main(["--reviewer", REVIEWER, "--head", HEAD], stdin=approved)
    finally:
        rule.sys.stdout = real_stdout
    assert code == 0
    state, _, description = printed.getvalue().strip().partition("\t")
    assert state == "success" and "approved at" in description

    refused = io.StringIO(json.dumps([review("CHANGES_REQUESTED")]))
    assert rule.main(["--reviewer", REVIEWER, "--head", HEAD], stdin=refused) == 3


def test_a_maintainer_may_approve_a_contributors_pull_request():
    # the App cannot approve its own author's pull request, so a contributor's needs this route
    assert state_of([maintainer("APPROVED")])[0] == "success"


def test_a_stranger_approval_does_not_count():
    assert state_of([maintainer("APPROVED", association="NONE")])[0] == "pending"
    assert state_of([maintainer("APPROVED", association="CONTRIBUTOR")])[0] == "pending"


def test_a_maintainer_change_request_blocks():
    assert state_of([maintainer("CHANGES_REQUESTED", association="MEMBER")])[0] == "failure"


def test_the_description_names_who_approved():
    state, description = state_of([maintainer("APPROVED", association="COLLABORATOR")])
    assert state == "success" and "a-maintainer" in description


def test_the_association_route_can_be_disabled():
    reviews = [maintainer("APPROVED")]
    assert rule.verdict(reviews, REVIEWER, "Bot", HEAD, frozenset())[0] == "pending"
