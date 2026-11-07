"""The gate's aggregation: one status per head commit, worst verdict winning.

A status is keyed by (sha, context), so two pull requests on the same head share one. The failure this
guards against is an approved pull request turning a changes-requested one green simply by being processed
last -- a merge button that lies about the pull request it is attached to.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

HEAD = "195e30d8b02d5ba36e30caf889bb6bb3b1be92e2"
OTHER = "5753428684342e7e0fb38a10426a342ec61ffaaa"
REVIEWER = "review-bot[bot]"


def load_plan():
    import_path = Path(__file__).resolve().parents[1] / "scripts"
    sys.path.insert(0, str(import_path))
    spec = importlib.util.spec_from_file_location("review_gate_plan", import_path / "review_gate_plan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plan = load_plan()


def review(state: str, commit: str = HEAD, login: str = REVIEWER, kind: str = "Bot", association: str = "NONE"):
    return {
        "state": state,
        "commit_id": commit,
        "submitted_at": "2026-11-07T00:10:00Z",
        "author_association": association,
        "user": {"login": login, "type": kind},
    }


def entry(number: int, head: str = HEAD, reviews=(), draft: bool = False, author: str = "mikomiel") -> dict:
    return {"number": number, "head": head, "draft": draft, "author": author, "reviews": list(reviews)}


def decisions(entries: list[dict]) -> dict[str, tuple[str, str]]:
    return {
        head: (state, description)
        for head, state, description in plan.merge(entries, REVIEWER, "Bot", frozenset({"OWNER"}))
    }


def test_an_approved_pull_request_cannot_turn_a_change_requested_one_green():
    # the reachable bug: the status is per head, so whichever PR is processed last used to decide
    entries = [
        entry(1, reviews=[review("CHANGES_REQUESTED")]),
        entry(2, reviews=[review("APPROVED")]),
    ]
    state, description = decisions(entries)[HEAD]
    assert state == "failure"
    assert "#1" in description and "#2" in description


def test_an_approval_and_a_pending_pull_request_share_a_pending_status():
    entries = [entry(1, reviews=[review("APPROVED")]), entry(2, reviews=[])]
    assert decisions(entries)[HEAD][0] == "pending"


def test_a_single_approved_pull_request_is_success():
    assert decisions([entry(1, reviews=[review("APPROVED")])])[HEAD][0] == "success"


def test_a_draft_revokes_a_success_left_from_before_it_was_a_draft():
    entries = [entry(1, reviews=[review("APPROVED")], draft=True)]
    state, description = decisions(entries)[HEAD]
    assert state == "pending" and "draft" in description


def test_each_head_is_decided_separately():
    entries = [
        entry(1, head=HEAD, reviews=[review("APPROVED")]),
        entry(2, head=OTHER, reviews=[review("CHANGES_REQUESTED", commit=OTHER)]),
    ]
    got = decisions(entries)
    assert got[HEAD][0] == "success"
    assert got[OTHER][0] == "failure"


def test_the_stricter_verdict_is_kept_whatever_the_input_order():
    forward = decisions([entry(1, reviews=[review("APPROVED")]), entry(2, reviews=[review("CHANGES_REQUESTED")])])
    backward = decisions([entry(2, reviews=[review("CHANGES_REQUESTED")]), entry(1, reviews=[review("APPROVED")])])
    assert forward == backward
    assert forward[HEAD][0] == "failure"


def test_an_entry_without_a_head_is_ignored():
    assert decisions([{"number": 1, "reviews": []}]) == {}


def test_the_cli_prints_one_line_per_head_and_refuses_a_bad_snapshot():
    payload = json.dumps([entry(1, reviews=[review("APPROVED")])])
    printed = io.StringIO()
    real, plan.sys.stdout = plan.sys.stdout, printed
    try:
        assert plan.main(["--reviewer", REVIEWER], stdin=io.StringIO(payload)) == 0
    finally:
        plan.sys.stdout = real
    head, state, description = printed.getvalue().strip().split("\t")
    assert head == HEAD and state == "success" and "approved" in description
    assert plan.main(["--reviewer", REVIEWER], stdin=io.StringIO("{not json")) == 1
    assert plan.main(["--reviewer", REVIEWER], stdin=io.StringIO("{}")) == 1


def test_a_dependabot_update_needs_no_app_review():
    state, description = decisions([entry(17, reviews=[], author="app/dependabot")])[HEAD]
    assert state == "success"
    assert "not required" in description and "dependabot" in description


def test_the_other_dependabot_login_is_recognised():
    assert decisions([entry(17, reviews=[], author="dependabot[bot]")])[HEAD][0] == "success"


def test_an_ordinary_author_is_not_exempt():
    assert decisions([entry(18, reviews=[], author="mikomiel")])[HEAD][0] == "pending"


def test_a_real_verdict_wins_over_the_exemption():
    # an exemption fills the gap where nobody reviewed; it never overrules a reviewer who did
    changed = decisions([entry(17, reviews=[review("CHANGES_REQUESTED")], author="app/dependabot")])[HEAD]
    assert changed[0] == "failure"
    approved = decisions([entry(17, reviews=[review("APPROVED")], author="app/dependabot")])[HEAD]
    assert approved[0] == "success" and "approved at" in approved[1]


def test_a_draft_dependabot_update_is_still_a_draft():
    assert decisions([entry(17, reviews=[], author="app/dependabot", draft=True)])[HEAD][0] == "pending"


def test_the_exemption_can_be_disabled():
    got = plan.merge(
        [entry(17, reviews=[], author="app/dependabot")], REVIEWER, "Bot", frozenset({"OWNER"}), frozenset()
    )
    assert got[0][1] == "pending"
