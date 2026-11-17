"""Execute the review gate's shell: the branches that decide whether a status is written live there.

The planner has its own tests; this file runs the workflow's run block against a stub `gh` and asserts the
writes. It pins the defect that an empty or incomplete snapshot must not overwrite a head's verdict, while a
stale lifecycle event must not block the snapshot that superseded it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "review-gate.yml"
HEAD = "a" * 40
BASE = "b" * 40
OTHER = "c" * 40
MOVED = "d" * 40
REPOSITORY = "mikomiel/advisory-radar"
RELEASE_BRANCH = "release-please--branches--main--components--advisory-radar"


def pull_line(
    number: int,
    head: str,
    base: str,
    *,
    draft: bool = False,
    author: str = "mikomiel",
    branch: str = "feat/example",
    repository: str = REPOSITORY,
) -> str:
    """One `pulls?state=open` row as the gate's jq emits it: seven tab-separated fields."""
    return f"{number}\t{head}\t{base}\t{str(draft).lower()}\t{author}\t{branch}\t{repository}\n"


STUB = """#!/usr/bin/env bash
set -u
url=""
post=""
jqfilter=""
previous=""
for arg in "$@"; do
  [ "$previous" = "--jq" ] && jqfilter=$arg
  previous=$arg
  case "$arg" in repos/*) url=$arg ;; esac
  [ "$arg" = "POST" ] && post=1
done
if [ -n "$post" ]; then
  printf '%s %s\\n' "$url" "$*" >> "$FAKE_POSTS"
  exit 0
fi
case "$url" in
  *"pulls?state=open"*) cat "$FAKE_PULLS" ;;
  *"/reviews"*) cat "$FAKE_REVIEWS" ;;
  *"/compare/"*)
    if [ -f "${FAKE_COMPARE_FAIL:-}" ]; then echo "stub: compare failed" >&2; exit 1; fi
    # A raw comparison body is projected with the workflow's own --jq, so a test can cover the transport itself.
    if [ -n "${FAKE_COMPARE_RAW:-}" ] && [ -n "$jqfilter" ]; then jq -c "$jqfilter" "$FAKE_COMPARE"
    else cat "$FAKE_COMPARE"; fi ;;
  *"/statuses"*) cat "$FAKE_PREVIOUS" ;;
  *"/pulls/"*)
    # Only the named pull request's read fails: the changed-file count for a snapshot pull request is a
    # different read, and a test for the corroborating lookup must not be able to pass because that one broke.
    if [ -f "${FAKE_LIVE_FAIL:-}" ] && [ "${url##*/pulls/}" = "${FAKE_LIVE_FAIL_PR:-}" ]; then exit 1; fi
    cat "$FAKE_LIVE" ;;
  *) printf 'stub: unexpected %s\\n' "$url" >&2; exit 1 ;;
esac
"""


def _run_block() -> str:
    document = yaml.safe_load(WORKFLOW.read_text())
    for job in document["jobs"].values():
        for step in job.get("steps", []):
            if isinstance(step, dict) and "review_gate_plan" in step.get("run", ""):
                assert "EVENT_ACTION" in step["env"]
                return step["run"]
    raise AssertionError("the gate's run block is not in the workflow")


def _gate(
    tmp_path: Path,
    *,
    pulls: str = "",
    live: str = f"open\t{HEAD}",
    live_fails_for: str = "",
    reviews: str = "[]",
    compare: str = "[]",
    commits: list[dict] | None = None,
    raw_compare: dict | None = None,
    compare_fails: bool = False,
    event_head: str = "",
    event_action: str = "",
    event_pr: str = "",
    capture: list[str] | None = None,
) -> tuple[int, list[tuple[str, str]]]:
    (tmp_path / "gate.sh").write_text(re.sub(r"\$\{\{[^}]*\}\}", "1", _run_block()))
    # `compare` is the file list and `commits` the commit list, as the workflow's projection hands them on.
    projected = {"files": json.loads(compare), "commits": commits or [], "total_commits": len(commits or [])}
    files = {
        "FAKE_PULLS": pulls,
        "FAKE_REVIEWS": reviews,
        "FAKE_COMPARE": json.dumps(raw_compare) if raw_compare is not None else json.dumps(projected),
        "FAKE_PREVIOUS": "",
        "FAKE_LIVE": live,
    }
    for name, value in files.items():
        (tmp_path / name.lower()).write_text(value)
    if live_fails_for:
        (tmp_path / "fake_live_fail").write_text("")
    if compare_fails:
        (tmp_path / "fake_compare_fail").write_text("")
    (tmp_path / "posts").write_text("")
    stub = tmp_path / "gh"
    stub.write_text(STUB)
    stub.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        # The gate is the base repository of every pull request it lists, and the planner holds a Dependabot update's
        # head to it, so the pull request rows below (their head repository is REPOSITORY) must name the same one.
        "REPO": REPOSITORY,
        "GATE_CONTEXT": "review",
        "REVIEWER_LOGIN": "review-bot[bot]",
        "REVIEWER_TYPE": "Bot",
        "TRUSTED_ASSOCIATIONS": "OWNER,MEMBER,COLLABORATOR",
        "EVENT_HEAD": event_head,
        "EVENT_ACTION": event_action,
        "EVENT_PR": event_pr,
        "FAKE_POSTS": str(tmp_path / "posts"),
        "FAKE_LIVE_FAIL": str(tmp_path / "fake_live_fail"),
        "FAKE_LIVE_FAIL_PR": live_fails_for,
        "FAKE_COMPARE_FAIL": str(tmp_path / "fake_compare_fail"),
        "FAKE_COMPARE_RAW": "1" if raw_compare is not None else "",
        **{name: str(tmp_path / name.lower()) for name in files},
    }
    proc = subprocess.run(["bash", str(tmp_path / "gate.sh")], cwd=ROOT, env=env, capture_output=True, text=True)
    if capture is not None:
        capture.append(proc.stdout + proc.stderr)
    if proc.returncode != 0:
        print(proc.stdout, proc.stderr)
    posted = []
    for line in (tmp_path / "posts").read_text().splitlines():
        head = line.split("statuses/")[-1].split()[0]
        state = re.search(r"-f state=(\w+)", line)
        posted.append((head, state.group(1) if state else "?"))
    return proc.returncode, posted


def test_an_empty_snapshot_for_a_lifecycle_event_fails_without_writing(tmp_path):
    """The event names a head carried by an open pull request, so an empty read is not evidence of absence."""
    code, posted = _gate(tmp_path, event_head=HEAD, event_action="synchronize", event_pr="27")
    assert code != 0
    assert posted == []


def test_a_close_still_revokes_the_head_it_names(tmp_path):
    code, posted = _gate(tmp_path, event_head=HEAD, event_action="closed", event_pr="27")
    assert code == 0
    assert posted == [(HEAD, "pending")]


def test_a_nonempty_snapshot_missing_the_event_head_fails_before_publishing(tmp_path):
    """Publishing the other heads would leave this one's old verdict standing with no signal."""
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(17, OTHER, BASE),
        event_head=HEAD,
        event_action="synchronize",
        event_pr="27",
        live=f"open\t{HEAD}",
    )
    assert code != 0
    assert posted == []


def test_a_stale_event_does_not_block_the_snapshot(tmp_path):
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(17, OTHER, BASE),
        event_head=HEAD,
        event_action="synchronize",
        event_pr="27",
        live=f"closed\t{HEAD}",
    )
    assert code == 0
    assert posted == [(OTHER, "pending")]  # no review at all is pending, not a failure


def test_a_schedule_writes_one_verdict_per_head(tmp_path):
    code, posted = _gate(tmp_path, pulls=pull_line(17, OTHER, BASE))
    assert code == 0
    assert posted == [(OTHER, "pending")]


def _approval() -> str:
    return (
        f'[{{"state": "APPROVED", "commit_id": "{HEAD}", "submitted_at": "2026-11-08T00:00:00Z",'
        ' "author_association": "OWNER", "user": {"login": "review-bot[bot]", "type": "Bot"}}]'
    )


def test_a_lookup_failure_refuses_to_publish(tmp_path):
    """The corroborating read is what makes publishing safe; without it, write nothing."""
    output: list[str] = []
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(17, OTHER, BASE),
        event_head=HEAD,
        event_action="synchronize",
        event_pr="27",
        live_fails_for="27",
        capture=output,
    )
    assert code != 0
    assert posted == []
    # Only the event pull request's own read fails here, so this refusal can only have come from that read.
    assert "to explain a snapshot that omits" in output[0]


def test_a_stale_event_head_moved_to_a_planned_head_does_not_block_the_snapshot(tmp_path):
    """The pull request moved to another head the snapshot carries: stale event, snapshot decides."""
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(17, OTHER, BASE),
        event_head=HEAD,
        event_action="synchronize",
        event_pr="27",
        live=f"open\t{OTHER}",
    )
    assert code == 0
    assert posted == [(OTHER, "pending")]


def test_a_head_that_moved_out_of_the_snapshot_fails_before_publishing(tmp_path):
    """A moved head the snapshot also omits is an incomplete read, not an explanation, so nothing may be written."""
    output: list[str] = []
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(17, OTHER, BASE),
        event_head=HEAD,
        event_action="synchronize",
        event_pr="27",
        live=f"open\t{MOVED}",
        capture=output,
    )
    assert code != 0
    assert posted == []
    assert MOVED in output[0]


def test_an_unreadable_live_state_refuses_to_publish(tmp_path):
    """An answer that names neither a state nor a head cannot be told from an incomplete snapshot."""
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(17, OTHER, BASE),
        event_head=HEAD,
        event_action="synchronize",
        event_pr="27",
        live="",
    )
    assert code != 0
    assert posted == []


def test_a_closed_head_absent_from_a_nonempty_plan_is_revoked(tmp_path):
    """The positive path: a close names a head the plan omits, so that head's old verdict must go."""
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(17, OTHER, BASE),
        event_head=HEAD,
        event_action="closed",
        event_pr="27",
    )
    assert code == 0
    assert posted == [(OTHER, "pending"), (HEAD, "pending")]


def test_a_closed_head_carried_by_another_open_pull_request_is_not_revoked(tmp_path):
    """The reused-head exception: the plan's verdict stands and nothing revokes it."""
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(19, HEAD, BASE),
        reviews=_approval(),
        event_head=HEAD,
        event_action="closed",
        event_pr="18",
    )
    assert code == 0
    assert posted == [(HEAD, "success")]


def test_an_approval_on_the_event_head_is_published(tmp_path):
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(18, HEAD, BASE),
        reviews=_approval(),
        event_head=HEAD,
        event_action="synchronize",
        event_pr="18",
    )
    assert code == 0
    assert posted == [(HEAD, "success")]


def test_a_generated_release_pull_request_is_published_as_success(tmp_path):
    """The seven-field row and the release exemption together: this proves the wiring, not the rule."""
    comparison = json.dumps(
        [
            {
                "filename": ".release-please-manifest.json",
                "previous_filename": None,
                "additions": 1,
                "deletions": 1,
                "patch": '@@ -1,3 +1,3 @@\n {\n-  ".": "0.1.0"\n+  ".": "0.2.0"\n }',
            },
            {
                "filename": "CHANGELOG.md",
                "previous_filename": None,
                "additions": 1,
                "deletions": 0,
                "patch": "@@ -9,3 +9,4 @@\n \n+## [0.2.0](https://example)\n",
            },
            {
                "filename": "pyproject.toml",
                "previous_filename": None,
                "additions": 1,
                "deletions": 1,
                "patch": '@@ -4,7 +4,7 @@\n [project]\n-version = "0.1.0"\n+version = "0.2.0"\n',
            },
            {
                "filename": "src/advisory_radar/__init__.py",
                "previous_filename": None,
                "additions": 1,
                "deletions": 1,
                "patch": '@@ -1,3 +1,3 @@\n """advisory-radar."""\n-__version__ = "0.1.0"\n+__version__ = "0.2.0"\n',
            },
            {
                "filename": "uv.lock",
                "previous_filename": None,
                "additions": 1,
                "deletions": 1,
                "patch": (
                    '@@ -5,7 +5,7 @@\n [[package]]\n name = "advisory-radar"\n'
                    '-version = "0.1.0"\n+version = "0.2.0"\n source = { editable = "." }\n'
                ),
            },
        ]
    )
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(40, HEAD, BASE, branch=RELEASE_BRANCH),
        live=f"{HEAD}\t{BASE}\t5",
        compare=comparison,
    )
    assert code == 0
    assert posted == [(HEAD, "success")]


def test_the_same_row_on_an_ordinary_branch_still_needs_a_review(tmp_path):
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(40, HEAD, BASE),
        live=f"{HEAD}\t{BASE}\t4",
        compare=json.dumps([{"filename": "pyproject.toml", "previous_filename": None}]),
    )
    assert code == 0
    assert posted == [(HEAD, "pending")]


def raw_comparison() -> dict:
    """A `compare` response body, before the workflow's --jq projection.

    The changelog is deliberately large: the projection drops a patch above forty changed lines, so a successful
    release proof from this body also shows the proof does not depend on a patch it does not need.
    """
    return {
        "files": [
            {
                "filename": ".release-please-manifest.json",
                "previous_filename": None,
                "status": "modified",
                "additions": 1,
                "deletions": 1,
                "patch": '@@ -1,3 +1,3 @@\n {\n-  ".": "0.1.0"\n+  ".": "0.2.0"\n }',
            },
            {
                "filename": "CHANGELOG.md",
                "previous_filename": None,
                "status": "modified",
                "additions": 61,
                "deletions": 0,
                "patch": "@@ -9,3 +9,64 @@\n \n+## [0.2.0](https://example) (2026-11-13)\n",
            },
            {
                "filename": "pyproject.toml",
                "previous_filename": None,
                "status": "modified",
                "additions": 1,
                "deletions": 1,
                "patch": '@@ -4,7 +4,7 @@\n [project]\n-version = "0.1.0"\n+version = "0.2.0"\n',
            },
            {
                "filename": "src/advisory_radar/__init__.py",
                "previous_filename": None,
                "status": "modified",
                "additions": 1,
                "deletions": 1,
                "patch": '@@ -1,3 +1,3 @@\n """advisory-radar."""\n-__version__ = "0.1.0"\n+__version__ = "0.2.0"\n',
            },
            {
                "filename": "uv.lock",
                "previous_filename": None,
                "status": "modified",
                "additions": 1,
                "deletions": 1,
                "patch": (
                    '@@ -5,7 +5,7 @@\n [[package]]\n name = "advisory-radar"\n'
                    '-version = "0.1.0"\n+version = "0.2.0"\n source = { editable = "." }\n'
                ),
            },
        ]
    }


def test_the_real_comparison_projection_feeds_the_release_proof(tmp_path):
    """The stub applies the workflow's own --jq here, so the counts and the patch cut-off are exercised too."""
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(40, HEAD, BASE, branch=RELEASE_BRANCH),
        live=f"{HEAD}\t{BASE}\t5",
        raw_compare=raw_comparison(),
    )
    assert code == 0
    assert posted == [(HEAD, "success")]


DEPENDABOT_BRANCH = "dependabot/github_actions/actions-all-7e0f"
DEPENDABOT = "dependabot[bot]"


def raw_commit(
    sha: str = HEAD, author: str = DEPENDABOT, committer: str = "web-flow", verification: dict | None = None
) -> dict:
    """One commit of a raw `compare` body: the user objects and the signature verdict nest as the API nests them."""
    return {
        "sha": sha,
        "author": {"login": author, "type": "Bot"},
        "committer": {"login": committer, "type": "User"},
        "commit": {
            "message": "build(deps): bump actions/checkout",
            "verification": verification
            or {"verified": True, "reason": "valid", "signature": "-----BEGIN PGP SIGNATURE-----", "payload": "tree"},
        },
    }


def raw_pin_file(pairs: int, name: str = ".github/workflows/ci.yml") -> dict:
    """A workflow edit that moves ``pairs`` pins: two changed lines each, as Dependabot writes them."""
    removed = f"      - uses: actions/checkout@{'a1' * 20}  # v7.0.1"
    added = f"      - uses: actions/checkout@{'b2' * 20}  # v7.0.2"
    patch = "@@ -20,5 +20,5 @@\n steps:\n" + f"-{removed}\n" * pairs + f"+{added}\n" * pairs
    return {
        "filename": name,
        "previous_filename": None,
        "status": "modified",
        "additions": pairs,
        "deletions": pairs,
        "patch": patch,
    }


def _dependabot(
    tmp_path: Path,
    body: dict,
    count: int = 1,
    author: str = DEPENDABOT,
    branch: str = DEPENDABOT_BRANCH,
    repository: str = REPOSITORY,
) -> list[tuple[str, str]]:
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(41, HEAD, BASE, author=author, branch=branch, repository=repository),
        live=f"{HEAD}\t{BASE}\t{count}",
        raw_compare=body,
    )
    assert code == 0
    return posted


def test_a_dependabot_pin_update_is_published_as_success_through_the_real_projection(tmp_path):
    """Six pins are twelve changed lines: past the old four-line bound, so the patch must now travel."""
    body = {"files": [raw_pin_file(6)], "commits": [raw_commit()], "total_commits": 1}
    assert _dependabot(tmp_path, body) == [(HEAD, "success")]


def test_a_dependabot_update_from_a_fork_or_another_branch_keeps_the_review_requirement(tmp_path):
    """The row carries the head ref and the head repository, and the planner holds both to Dependabot's shape.

    The same body, commits and author succeed from the bot's own branch of this repository; only the row changes.
    """
    body = {"files": [raw_pin_file(2)], "commits": [raw_commit()], "total_commits": 1}
    assert _dependabot(tmp_path, body) == [(HEAD, "success")]
    assert _dependabot(tmp_path, body, branch="feat/example") == [(HEAD, "pending")]
    assert _dependabot(tmp_path, body, repository="someone/advisory-radar") == [(HEAD, "pending")]
    # A deleted fork has no head repository, so the row ends in an empty field: that must not read as a match.
    assert _dependabot(tmp_path, body, repository="") == [(HEAD, "pending")]


def test_a_commit_that_is_not_dependabots_own_keeps_the_review_requirement_through_the_projection(tmp_path):
    maintainer = raw_commit(OTHER, author="mikomiel", committer="web-flow")
    body = {"files": [raw_pin_file(2)], "commits": [maintainer, raw_commit()], "total_commits": 2}
    assert _dependabot(tmp_path, body) == [(HEAD, "pending")]
    # the bot's name on a commit a person signed: only the committer shows who that was
    borrowed = raw_commit(committer="mikomiel")
    body = {"files": [raw_pin_file(2)], "commits": [borrowed], "total_commits": 1}
    assert _dependabot(tmp_path, body) == [(HEAD, "pending")]


def test_an_unsigned_or_unreported_signature_keeps_the_review_requirement_through_the_projection(tmp_path):
    for verification in ({"verified": False, "reason": "unsigned"}, {"reason": "valid"}):
        body = {
            "files": [raw_pin_file(2)],
            "commits": [raw_commit(verification=verification)],
            "total_commits": 1,
        }
        assert _dependabot(tmp_path, body) == [(HEAD, "pending")], verification
    # a commit GitHub could not tie to an account has no author or committer object at all
    anonymous = {**raw_commit(), "author": None, "committer": None}
    body = {"files": [raw_pin_file(2)], "commits": [anonymous], "total_commits": 1}
    assert _dependabot(tmp_path, body) == [(HEAD, "pending")]


def test_a_comparison_that_lists_fewer_commits_than_it_counts_is_not_exempt(tmp_path):
    body = {"files": [raw_pin_file(2)], "commits": [raw_commit()], "total_commits": 3}
    assert _dependabot(tmp_path, body) == [(HEAD, "pending")]


def test_a_patch_beyond_the_transport_bound_is_dropped_and_the_workflow_edit_stays_unproven(tmp_path):
    """Twenty-five pins are fifty changed lines: above the bound, so no patch travels and the rule fails closed."""
    body = {"files": [raw_pin_file(25)], "commits": [raw_commit()], "total_commits": 1}
    assert _dependabot(tmp_path, body) == [(HEAD, "pending")]


def test_a_comparison_larger_than_one_argument_still_reaches_the_planner(tmp_path):
    """The comparison goes to jq through a file: 120 files of forty changed lines carry far more than the
    128 KB one command-line argument can hold, and the snapshot of every other pull request depends on this run."""
    files = [raw_pin_file(20, name=f".github/workflows/w{number}.yml") for number in range(120)]
    body = {"files": files, "commits": [raw_commit()], "total_commits": 1}
    assert sum(len(item["patch"]) for item in files) > 200_000
    assert _dependabot(tmp_path, body, count=120, author="mikomiel") == [(HEAD, "pending")]


def test_a_patch_beyond_the_size_bound_is_dropped_whatever_its_line_count(tmp_path):
    """One changed pair, but a context line of twenty thousand characters: the bound is on size as well as lines."""
    body = {"files": [raw_pin_file(1)], "commits": [raw_commit()], "total_commits": 1}
    assert _dependabot(tmp_path, body) == [(HEAD, "success")]  # the same edit with a short context line
    item = raw_pin_file(1)
    item["patch"] = item["patch"].replace(" steps:\n", f" {'x' * 20_000}\n")
    body = {"files": [item], "commits": [raw_commit()], "total_commits": 1}
    assert _dependabot(tmp_path, body) == [(HEAD, "pending")]


def test_an_unreadable_comparison_leaves_the_pull_request_without_an_exemption(tmp_path):
    """The read fails for one pull request: it is not exempt, and the run still publishes every verdict."""
    output: list[str] = []
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(41, HEAD, BASE, author=DEPENDABOT, branch=DEPENDABOT_BRANCH),
        live=f"{HEAD}\t{BASE}\t1",
        compare_fails=True,
        capture=output,
    )
    assert code == 0
    assert posted == [(HEAD, "pending")]
    assert "cannot read the comparison; not exempt from review" in output[0]
