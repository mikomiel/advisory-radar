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
BASE = "2c673bb56bf216ad60928dd9703143ac41f052ec"
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


FILES = [{"filename": ".github/workflows/ci.yml", "previous_filename": None}]


def entry(
    number: int,
    head: str = HEAD,
    reviews=(),
    draft: bool = False,
    author: str = "mikomiel",
    files: list[dict] | None = None,
    changed: int | None = None,
    base: str = BASE,
    count_head: str | None = None,
    count_base: str | None = None,
    branch: str = "feat/example",
    head_repo: str = "mikomiel/advisory-radar",
) -> dict:
    chosen = FILES if files is None else files
    return {
        "number": number,
        "head": head,
        "base": base,
        "draft": draft,
        "author": author,
        "branch": branch,
        "head_repo": head_repo,
        "reviews": list(reviews),
        "files": chosen,
        "changed": len(chosen) if changed is None else changed,
        # A coherent snapshot: the count describes the same two commits as the comparison.
        "count_head": head if count_head is None else count_head,
        "count_base": base if count_base is None else count_base,
    }


#: The files release-please manages in its release pull request: the version in two places, the changelog and the
#: manifest it bumps from. A test that adds one here without adding it to ``RELEASE_PATHS`` fails, on purpose.
RELEASE_FILES = [
    {"filename": ".release-please-manifest.json", "previous_filename": None},
    {"filename": "CHANGELOG.md", "previous_filename": None},
    {"filename": "pyproject.toml", "previous_filename": None},
    {"filename": "src/advisory_radar/__init__.py", "previous_filename": None},
]


def release_entry(number: int = 40, **changes) -> dict:
    """The generated release pull request: release-please's branch, the token owner, release-managed files only."""
    options = {
        "reviews": [],
        "author": plan.RELEASE_AUTHOR,
        "files": RELEASE_FILES,
        "branch": plan.RELEASE_BRANCH,
        "head_repo": plan.RELEASE_REPOSITORY,
    }
    options.update(changes)
    return entry(number, **options)


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
    state, description = decisions(
        [
            entry(
                17,
                reviews=[],
                author="app/dependabot",
                files=[{"filename": ".github/workflows/ci.yml", "previous_filename": None}],
            )
        ]
    )[HEAD]
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


def test_the_exemption_needs_a_dependency_only_path_set():
    # author alone would exempt a bump that reached into src/, which automerge would then take unreviewed
    reached = decisions(
        [
            entry(
                17,
                reviews=[],
                author="app/dependabot",
                files=[
                    {"filename": ".github/workflows/ci.yml", "previous_filename": None},
                    {"filename": "src/x.py", "previous_filename": None},
                ],
            )
        ]
    )
    assert reached[HEAD][0] == "pending"
    missing = decisions([entry(17, reviews=[], author="app/dependabot", files=[])])
    assert missing[HEAD][0] == "pending"
    manifest = decisions(
        [
            entry(
                17,
                reviews=[],
                author="app/dependabot",
                files=[
                    {"filename": "pyproject.toml", "previous_filename": None},
                    {"filename": "uv.lock", "previous_filename": None},
                ],
            )
        ]
    )
    assert manifest[HEAD][0] == "success"


def test_a_shared_head_with_a_blocked_pull_request_stays_blocked():
    entries = [
        entry(
            17, reviews=[], author="app/dependabot", files=[{"filename": "pyproject.toml", "previous_filename": None}]
        ),
        entry(18, reviews=[], author="mikomiel", files=[{"filename": "src/x.py", "previous_filename": None}]),
    ]
    state, description = decisions(entries)[HEAD]
    assert state == "pending"
    assert "#17" in description and "#18" in description


def test_the_exemption_does_not_cover_a_stale_or_dismissed_verdict():
    """Only an absence of verdict is exempt: "approved at another commit" and "dismissed" are not reviews."""
    stale = decisions([entry(17, reviews=[review("APPROVED", commit="0" * 40)], author="app/dependabot")])[HEAD]
    assert stale[0] == "pending"
    assert "not required" not in stale[1]
    dismissed = decisions([entry(17, reviews=[review("DISMISSED")], author="app/dependabot")])[HEAD]
    assert dismissed[0] == "pending"


def test_a_renamed_source_counts_against_the_exemption():
    # the comparison names both sides of a rename; only ``filename`` would let src/x.py become pyproject.toml
    renamed = decisions(
        [
            entry(
                17,
                reviews=[],
                author="app/dependabot",
                files=[{"filename": "pyproject.toml", "previous_filename": "src/x.py"}],
            )
        ]
    )
    assert renamed[HEAD][0] == "pending"


def test_a_nested_path_under_a_manifest_name_is_not_a_dependency_update():
    # deleting Dockerfile and adding Dockerfile/evil.py must not read as a manifest-only change
    nested = decisions(
        [
            entry(
                17,
                reviews=[],
                author="app/dependabot",
                files=[{"filename": "Dockerfile/evil.py", "previous_filename": None}],
            )
        ]
    )
    assert nested[HEAD][0] == "pending"
    for name in ("pyproject.toml/evil.py", "uv.lock/evil.py", "docker-compose.yml/evil.py"):
        got = decisions(
            [entry(17, reviews=[], author="app/dependabot", files=[{"filename": name, "previous_filename": None}])]
        )
        assert got[HEAD][0] == "pending", name


def test_a_truncated_comparison_is_not_exempt():
    # compare caps its list at 300: a source file can hide past the cap, so a short list proves nothing
    entry_with_short_list = entry(
        17,
        reviews=[],
        author="app/dependabot",
        files=[{"filename": "pyproject.toml", "previous_filename": None}],
        changed=5,
    )
    assert decisions([entry_with_short_list])[HEAD][0] == "pending"


def test_a_count_from_another_commit_pair_is_not_exempt():
    """The count and the comparison are two reads: a branch that moved between them proves nothing.

    Pairing the pinned comparison of head A (truncated at the comparison cap) with the smaller count of a
    newer head B would let an omitted source path pass the short-list check that exists to catch it.
    """
    files = [{"filename": "pyproject.toml", "previous_filename": None}]
    coherent = entry(17, reviews=[], author="app/dependabot", files=files, changed=1)
    assert decisions([coherent])[HEAD][0] == "success"
    moved_head = entry(17, reviews=[], author="app/dependabot", files=files, changed=1, count_head=OTHER)
    assert decisions([moved_head])[HEAD][0] == "pending"
    moved_base = entry(17, reviews=[], author="app/dependabot", files=files, changed=1, count_base="0" * 40)
    assert decisions([moved_base])[HEAD][0] == "pending"


def test_a_comment_holds_a_dependency_update():
    # any review at all is used as-is; a comment is not an approval
    commented = decisions([entry(17, reviews=[review("COMMENTED")], author="app/dependabot")])[HEAD]
    assert commented[0] == "pending"


#: The repository root: the release configuration beside the scripts is what the exemption must keep matching.
ROOT = Path(__file__).resolve().parents[1]


def test_the_generated_release_pull_request_needs_no_app_review():
    state, description = decisions([release_entry()])[HEAD]
    assert state == "success"
    assert "release" in description and "not required" in description


def test_a_change_request_still_blocks_the_generated_release_pull_request():
    # the exemption removes the approval requirement, not a veto
    assert decisions([release_entry(reviews=[review("CHANGES_REQUESTED")])])[HEAD][0] == "failure"


def test_an_approval_at_the_head_is_reported_as_that_approval():
    # the exemption fills the gap; it does not rewrite a verdict that is already there
    state, description = decisions([release_entry(reviews=[review("APPROVED")])])[HEAD]
    assert state == "success" and "approved at" in description


def test_a_stale_approval_or_a_dismissal_does_not_block_the_generated_release():
    # release-please rewrites its branch on every run, so a review left on the previous head must not park it
    for reviews in ([review("APPROVED", commit="0" * 40)], [review("DISMISSED")], [review("COMMENTED")]):
        got = decisions([release_entry(reviews=reviews)])[HEAD]
        assert got[0] == "success" and "not required" in got[1]


OTHER_RELEASE_FILE = {"filename": "src/advisory_radar/web.py", "previous_filename": None}


def test_every_other_release_like_shape_keeps_the_review_requirement():
    cases = {
        "another branch": {"branch": "release-please--branches--main--components--other"},
        "a fork's head": {"head_repo": "someone/advisory-radar"},
        "another author": {"author": "contributor"},
        "a draft": {"draft": True},
        "no file list": {"files": []},
        "an unexpected path": {"files": RELEASE_FILES + [OTHER_RELEASE_FILE]},
        "a truncated list": {"files": RELEASE_FILES[:1], "changed": len(RELEASE_FILES)},
        "a count from another commit pair": {"count_head": OTHER},
    }
    for label, change in cases.items():
        assert decisions([release_entry(**change)])[HEAD][0] == "pending", label


def test_a_rename_out_of_a_release_managed_file_is_not_a_release():
    renamed = [
        {"filename": "CHANGELOG.md", "previous_filename": "src/advisory_radar/web.py"},
        {"filename": "pyproject.toml", "previous_filename": None},
    ]
    assert decisions([release_entry(files=renamed, changed=2)])[HEAD][0] == "pending"


def test_the_release_shape_follows_the_release_configuration():
    """The exemption's literals mirror two files; a drift in either must fail here, not silently stop matching."""
    config = json.loads((ROOT / "release-please-config.json").read_text(encoding="utf-8"))
    package = config["packages"]["."]["package-name"]
    assert f"release-please--branches--main--components--{package}" == plan.RELEASE_BRANCH
    # The tag is `vX.Y.Z` because release.yml triggers on that and ignores a component prefix.
    assert config["include-v-in-tag"] is True
    assert config["include-component-in-tag"] is False
    # One root package, so the release pull request changes the root files the exemption names.
    assert list(json.loads((ROOT / ".release-please-manifest.json").read_text(encoding="utf-8"))) == ["."]
    assert {"pyproject.toml", "src/advisory_radar/__init__.py", "CHANGELOG.md"} <= plan.RELEASE_PATHS


def test_the_release_exemption_names_the_token_owner():
    # The pull request's author is the account behind RELEASE_PLEASE_TOKEN; if that account changes, this and
    # RELEASE_AUTHOR change together or the release pull request falls back to needing the normal review.
    assert plan.RELEASE_AUTHOR == "mikomiel"
    assert plan.RELEASE_REPOSITORY == "mikomiel/advisory-radar"
