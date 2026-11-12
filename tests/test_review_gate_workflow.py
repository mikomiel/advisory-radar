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
for arg in "$@"; do
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
  *"/compare/"*) cat "$FAKE_COMPARE" ;;
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
    event_head: str = "",
    event_action: str = "",
    event_pr: str = "",
    capture: list[str] | None = None,
) -> tuple[int, list[tuple[str, str]]]:
    (tmp_path / "gate.sh").write_text(re.sub(r"\$\{\{[^}]*\}\}", "1", _run_block()))
    files = {
        "FAKE_PULLS": pulls,
        "FAKE_REVIEWS": reviews,
        "FAKE_COMPARE": compare,
        "FAKE_PREVIOUS": "",
        "FAKE_LIVE": live,
    }
    for name, value in files.items():
        (tmp_path / name.lower()).write_text(value)
    if live_fails_for:
        (tmp_path / "fake_live_fail").write_text("")
    (tmp_path / "posts").write_text("")
    stub = tmp_path / "gh"
    stub.write_text(STUB)
    stub.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "REPO": "owner/name",
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
            {"filename": ".release-please-manifest.json", "previous_filename": None},
            {"filename": "CHANGELOG.md", "previous_filename": None},
            {"filename": "pyproject.toml", "previous_filename": None},
            {"filename": "src/advisory_radar/__init__.py", "previous_filename": None},
        ]
    )
    code, posted = _gate(
        tmp_path,
        pulls=pull_line(40, HEAD, BASE, branch=RELEASE_BRANCH),
        live=f"{HEAD}\t{BASE}\t4",
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
