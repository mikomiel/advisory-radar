"""The merge loop of ``automerge.yml`` runs for real here, against a stubbed ``gh``.

The loop decides which approved pull request a workflow with a write token merges, and it reports one fact to the
``release`` job: the ``merged`` output. The order of its writes is the contract. ``merged=false`` is written before the
queue is read, and ``merged=true`` the moment ``gh pr merge`` succeeds, before the branch cleanup and the comment, so
that a later failure can neither lose a merge that landed nor invent one. A test of the workflow text cannot see the
order in which a program acts, so these tests run ``scripts/automerge_loop.py`` the way the workflow does.

* The script runs as a subprocess with a temporary ``GITHUB_OUTPUT`` file, and the real ``review_state.py``,
  ``guard_sensitive_paths.py`` and ``delete_merged_branch.py`` beside it.
* ``PATH`` holds one directory: a stub ``gh``, and a stub ``git`` for the cleanup's ``git push``. The real programs
  cannot start, so no test can reach GitHub, and the repository is ``owner/name``.
* A stub answers from a scenario. It logs each call with what ``GITHUB_OUTPUT`` held at that moment, which is how a
  test sees the order of the writes from outside. A call that the scenario does not hold fails the test in
  ``Harness.run``: the script tolerates a failed cleanup and a failed comment on purpose, so the stub's exit status
  alone would pass as a warning.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "automerge_loop.py"
REPO = "owner/name"
REVIEWER = "review-bot[bot]"
HEAD = "a" * 40
BASE = "b" * 40
SECOND = "c" * 40  # the head of a second pull request in the same queue
STALE = "d" * 40  # a commit that an earlier approval was about
MOVED = "e" * 40  # where a head or a base went while the checks ran
#: What the file holds after a run that merged nothing, and after one that merged.
NOT_MERGED = "merged=false\n"
MERGED = "merged=false\nmerged=true\n"

#: One program behind both ``gh`` and ``git``. It answers from the scenario and logs each call with the content of
#: ``GITHUB_OUTPUT`` at that moment. Several answers for one key are given in turn, the last one repeating.
STUB = r"""
import json
import os
import sys

tool, args = sys.argv[1], sys.argv[2:]
if tool == "git":
    key = "git " + args[0]
elif args[0] == "api":
    key = "api " + args[-1].split("/", 3)[3]  # without "repos/<owner>/<name>/"
elif args[:2] == ["pr", "list"]:
    key = "pr list"
else:
    key = " ".join(args[:3])  # "pr view 12", "pr merge 12", "pr comment 12"

try:
    with open(os.environ["GITHUB_OUTPUT"], encoding="utf-8") as handle:
        output = handle.read()
except FileNotFoundError:
    output = None
try:
    with open(os.environ["STUB_LOG"], encoding="utf-8") as handle:
        earlier = [json.loads(line)["key"] for line in handle]
except FileNotFoundError:
    earlier = []
with open(os.environ["STUB_SCENARIO"], encoding="utf-8") as handle:
    answers = json.load(handle).get(key)
with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as handle:
    entry = {"key": key, "args": args, "output": output, "scripted": answers is not None}
    handle.write(json.dumps(entry) + "\n")
if answers is None:
    sys.stderr.write("stub " + tool + ": no answer for " + repr(key) + "\n")
    sys.exit(97)
answer = answers[min(earlier.count(key), len(answers) - 1)]
sys.stdout.write(answer["stdout"])
sys.stderr.write(answer["stderr"])
sys.exit(answer["code"])
"""


def answer(stdout: str = "", *, stderr: str = "", code: int = 0) -> dict:
    return {"stdout": stdout, "stderr": stderr, "code": code}


def check_run(name: str, conclusion: str = "SUCCESS") -> dict:
    """A check run as ``gh pr view --json statusCheckRollup`` shows it: an unfinished one has an empty conclusion."""
    return {"__typename": "CheckRun", "name": name, "status": "COMPLETED", "conclusion": conclusion}


def status_context(context: str, state: str = "SUCCESS") -> dict:
    """A legacy commit status: it has a ``state`` and no ``conclusion``."""
    return {"__typename": "StatusContext", "context": context, "state": state}


def review(
    state: str = "APPROVED",
    commit: str = HEAD,
    login: str = REVIEWER,
    kind: str = "Bot",
    association: str = "NONE",
    at: str = "2026-11-17T10:00:00Z",
) -> dict:
    return {
        "state": state,
        "commit_id": commit,
        "submitted_at": at,
        "author_association": association,
        "user": {"login": login, "type": kind},
    }


GREEN = (check_run("ci"), status_context("gate"), status_context("review"), check_run("dependency-review"))


@dataclass(frozen=True)
class Pull:
    """A pull request that passes every rule, and the one field to change to make it fail one."""

    number: int = 12
    head: str = HEAD
    base: str = BASE
    mergeable: str = "MERGEABLE"
    checks: tuple[dict, ...] = field(default=GREEN)
    reviews: tuple[dict, ...] | None = None  # None: an approval by the reviewer at this head
    files: tuple[str, ...] = ("src/advisory_radar/feature.py",)
    declared: int | None = None  # None: as many files as the comparison lists
    branch: str = "feature/x"
    cross: bool = False
    reread: dict | None = None  # None: the head and the base the first read showed

    def meta(self) -> dict:
        return {
            "headRefOid": self.head,
            "baseRefOid": self.base,
            "mergeable": self.mergeable,
            "reviews": [],
            "statusCheckRollup": list(self.checks),
            "changedFiles": len(self.files) if self.declared is None else self.declared,
            "headRefName": self.branch,
            "isCrossRepository": self.cross,
        }

    def install(self, harness: Harness) -> None:
        reviews = [review(commit=self.head)] if self.reviews is None else list(self.reviews)
        again = {"headRefOid": self.head, "baseRefOid": self.base} if self.reread is None else self.reread
        harness.script(f"pr view {self.number}", answer(json.dumps(self.meta())), answer(json.dumps(again)))
        harness.script(f"api pulls/{self.number}/reviews?per_page=100", answer(json.dumps(reviews)))
        comparison = {"files": [{"filename": name} for name in self.files]}
        harness.script(f"api compare/{self.base}...{self.head}", answer(json.dumps(comparison)))
        harness.script(f"pr merge {self.number}", answer(stderr=f"merged {self.number}\n"))
        harness.script("git push", answer())  # the cleanup of the merged head branch
        harness.script(f"pr comment {self.number}", answer())


class Harness:
    """One scenario: the answers the stubs give, the environment the script runs in, and what the stubs saw."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.scenario: dict[str, list[dict]] = {}
        self.output = root / "github_output"
        self.output.touch()  # the runner creates the file before the step starts
        self.log = root / "calls.jsonl"
        self.scenario_file = root / "scenario.json"
        stub = root / "stub.py"
        stub.write_text(STUB, encoding="utf-8")
        self.bin = root / "bin"
        self.bin.mkdir()
        for tool in ("gh", "git"):
            wrapper = self.bin / tool
            wrapper.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(stub))} {tool} "$@"\n')
            wrapper.chmod(0o755)

    def script(self, key: str, *answers: dict) -> None:
        self.scenario[key] = list(answers)

    def queue(self, *pulls: Pull, drafts: tuple[int, ...] = ()) -> None:
        listing = [{"number": pull.number, "mergeable": "MERGEABLE", "isDraft": False} for pull in pulls]
        listing += [{"number": number, "mergeable": "UNKNOWN", "isDraft": True} for number in drafts]
        self.script("pr list", answer(json.dumps(listing)))
        for pull in pulls:
            pull.install(self)

    def run(
        self, *, without: tuple[str, ...] = (), env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.scenario_file.write_text(json.dumps(self.scenario), encoding="utf-8")
        environment = {
            "PATH": str(self.bin),
            "GITHUB_OUTPUT": str(self.output),
            "REPO": REPO,
            "REVIEWER_LOGIN": REVIEWER,
            "REVIEWER_TYPE": "Bot",
            "REQUIRED_CHECK": "ci",
            "STUB_SCENARIO": str(self.scenario_file),
            "STUB_LOG": str(self.log),
            **(env or {}),
        }
        for name in without:
            del environment[name]
        # The workflow starts the script in the checkout; a temporary directory proves it needs no particular one.
        done = subprocess.run(
            [sys.executable, str(SCRIPT)],
            env=environment,
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        unscripted = [call["key"] for call in self.calls() if not call["scripted"]]
        assert not unscripted, f"the script made calls that the scenario does not hold: {unscripted}"
        return done

    def output_text(self) -> str:
        return self.output.read_text(encoding="utf-8")

    def calls(self, prefix: str = "") -> list[dict]:
        if not self.log.exists():
            return []
        entries = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        return [entry for entry in entries if entry["key"].startswith(prefix)]

    def keys(self) -> list[str]:
        return [call["key"] for call in self.calls()]


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def succeeded(done: subprocess.CompletedProcess[str]) -> None:
    assert done.returncode == 0, f"exit {done.returncode}\nstdout:\n{done.stdout}\nstderr:\n{done.stderr}"


# --- the three runs the output contract has to survive ------------------------------------------------------------


def test_an_empty_queue_writes_merged_false_and_exits_zero(harness):
    harness.script("pr list", answer("[]"))
    done = harness.run()
    succeeded(done)
    assert harness.output_text() == NOT_MERGED
    assert "no approved pull requests to consider" in done.stdout
    assert harness.keys() == ["pr list"]


def test_a_merge_that_github_refuses_leaves_merged_false_and_exits_zero(harness):
    harness.queue(Pull())
    harness.script("pr merge 12", answer(stderr="Pull request is not mergeable\n", code=1))
    done = harness.run()
    succeeded(done)
    assert harness.output_text() == NOT_MERGED
    assert "skip #12: GitHub refused the merge (protection, or a check changed)" in done.stdout.splitlines()
    # Without these the run could have skipped the candidate earlier and passed for the wrong reason.
    assert len(harness.calls("pr merge 12")) == 1
    assert harness.calls("git") == []
    assert harness.calls("pr comment") == []


def test_a_merge_then_a_failed_fetch_keeps_merged_true_and_exits_nonzero(harness):
    """The release job reads the output of a job that ended red, because it is gated on ``!cancelled()``."""
    harness.queue(Pull(number=12), Pull(number=13, head=SECOND))
    harness.script("pr view 13", answer(stderr="HTTP 502: Bad Gateway\n", code=1))
    done = harness.run()
    assert done.returncode == 1
    assert harness.output_text() == MERGED
    assert f"merged #12 at {HEAD} (approval by {REVIEWER})" in done.stdout.splitlines()
    assert "::error::" in done.stdout
    # What follows the merge happened before the next candidate was read.
    assert harness.keys()[-4:] == ["pr merge 12", "git push", "pr comment 12", "pr view 13"]
    # And the read that failed already found the merge in the file: the write came before it, not after the run.
    (failed,) = harness.calls("pr view 13")
    assert failed["output"] == MERGED


# --- the order of the writes --------------------------------------------------------------------------------------


def test_merged_false_is_already_written_when_the_queue_is_read(harness):
    harness.script("pr list", answer("[]"))
    harness.run()
    (listing,) = harness.calls("pr list")
    assert listing["output"] == NOT_MERGED


def test_an_enumeration_failure_fails_the_run_and_never_looks_like_an_empty_queue(harness):
    harness.script("pr list", answer(stderr="HTTP 502: Bad Gateway\n", code=1))
    done = harness.run()
    assert done.returncode == 1
    assert "::error::cannot enumerate open pull requests" in done.stdout.splitlines()
    assert "no approved pull requests" not in done.stdout
    assert harness.output_text() == NOT_MERGED


def test_merged_true_is_written_at_the_merge_before_the_cleanup_and_the_comment(harness):
    harness.queue(Pull())
    succeeded(harness.run())
    assert harness.output_text() == MERGED
    (merge,) = harness.calls("pr merge")
    assert merge["output"] == NOT_MERGED, "merged=true must not be written before the merge has happened"
    for later in ("git push", "pr comment"):
        (call,) = harness.calls(later)
        assert call["output"] == MERGED, f"{later} ran before merged=true was written"


def test_a_failed_cleanup_and_a_failed_comment_cannot_fail_the_run_after_the_merge(harness):
    harness.queue(Pull())
    harness.script("git push", answer(stderr=" ! [rejected] (stale info)\n", code=1))
    harness.script("pr comment 12", answer(stderr="HTTP 403: Forbidden\n", code=1))
    done = harness.run()
    succeeded(done)
    assert harness.output_text() == MERGED
    lines = done.stdout.splitlines()
    assert "::warning::merged #12; its head branch was left in place (the reason is above)" in lines
    assert not any(line.startswith("deleted head branch") for line in lines)
    assert len(harness.calls("pr comment 12")) == 1


# --- what the merge itself is ---------------------------------------------------------------------------------------


def test_a_merge_reads_the_pull_request_decides_and_only_then_merges(harness):
    harness.queue(Pull())
    succeeded(harness.run())
    assert harness.keys() == [
        "pr list",
        "pr view 12",
        "api pulls/12/reviews?per_page=100",
        f"api compare/{BASE}...{HEAD}",
        "pr view 12",
        "pr merge 12",
        "git push",
        "pr comment 12",
    ]


def test_the_merge_asks_for_the_head_the_reviewer_approved(harness):
    """``--match-head-commit`` makes GitHub refuse a head that moved. ``--delete-branch`` stays out: gh deletes the
    local branch with it and fails after the merge when that branch is not checked out on the runner."""
    harness.queue(Pull())
    succeeded(harness.run())
    (merge,) = harness.calls("pr merge")
    assert merge["args"] == ["pr", "merge", "12", "--repo", REPO, "--squash", "--match-head-commit", HEAD]


def test_the_merged_head_branch_is_deleted_by_a_lease_on_the_merged_head(harness):
    harness.queue(Pull())
    done = harness.run()
    succeeded(done)
    (push,) = harness.calls("git push")
    assert push["args"] == [
        "push",
        f"--force-with-lease=refs/heads/feature/x:{HEAD}",
        f"https://github.com/{REPO}.git",
        ":refs/heads/feature/x",
    ]
    assert "deleted head branch feature/x" in done.stdout.splitlines()


def test_the_comment_names_the_check_and_the_approved_head(harness):
    harness.queue(Pull())
    succeeded(harness.run())
    (comment,) = harness.calls("pr comment")
    body = f"Merged by automerge: ci green and approved at `{HEAD}` by {REVIEWER}."
    assert comment["args"] == ["pr", "comment", "12", "--repo", REPO, "--body", body]


def test_a_pull_request_from_a_fork_is_merged_and_its_branch_is_left_alone(harness):
    harness.queue(Pull(cross=True))
    done = harness.run()
    succeeded(done)
    assert harness.output_text() == MERGED
    assert harness.calls("git") == [], "a fork's branch name can match an unrelated branch of this repository"
    assert "::warning::merged #12; its head branch was left in place (the reason is above)" in done.stdout.splitlines()
    assert len(harness.calls("pr comment 12")) == 1


def test_the_required_check_and_the_reviewer_come_from_the_environment(harness):
    other = "build"
    harness.queue(Pull(checks=(check_run(other), status_context("review")), reviews=(review(login="other[bot]"),)))
    done = harness.run(env={"REQUIRED_CHECK": other, "REVIEWER_LOGIN": "other[bot]"})
    succeeded(done)
    (comment,) = harness.calls("pr comment")
    assert comment["args"][-1] == f"Merged by automerge: {other} green and approved at `{HEAD}` by other[bot]."


# --- the queue --------------------------------------------------------------------------------------------------------


def test_the_queue_is_the_open_pull_requests_against_main(harness):
    harness.queue(Pull())
    succeeded(harness.run())
    (listing,) = harness.calls("pr list")
    assert listing["args"] == [
        *("pr", "list", "--repo", REPO, "--state", "open", "--base", "main", "--limit", "1000"),
        *("--json", "number,mergeable,isDraft"),
    ]


def test_the_queue_is_worked_in_the_order_gh_lists_it(harness):
    harness.queue(Pull(number=13, head=SECOND), Pull(number=12))
    succeeded(harness.run())
    assert [call["key"] for call in harness.calls("pr merge")] == ["pr merge 13", "pr merge 12"]


def test_a_draft_is_not_a_candidate(harness):
    harness.queue(Pull(number=12), drafts=(11,))
    succeeded(harness.run())
    assert [call["key"] for call in harness.calls("pr view")] == ["pr view 12", "pr view 12"]


def test_a_queue_of_drafts_is_an_empty_queue(harness):
    harness.queue(drafts=(11, 14))
    done = harness.run()
    succeeded(done)
    assert "no approved pull requests to consider" in done.stdout
    assert harness.keys() == ["pr list"]
    assert harness.output_text() == NOT_MERGED


def test_a_skipped_pull_request_does_not_stop_the_queue(harness):
    harness.queue(Pull(number=12, mergeable="UNKNOWN"), Pull(number=13, head=SECOND))
    done = harness.run()
    succeeded(done)
    lines = done.stdout.splitlines()
    assert "skip #12: mergeable=UNKNOWN (retry on the next trigger)" in lines
    assert f"merged #13 at {SECOND} (approval by {REVIEWER})" in lines
    assert harness.output_text() == MERGED


def test_a_pull_request_skipped_after_a_merge_does_not_take_the_merge_back(harness):
    harness.queue(Pull(number=12), Pull(number=13, head=SECOND, mergeable="CONFLICTING"))
    done = harness.run()
    succeeded(done)
    assert "skip #13: mergeable=CONFLICTING (retry on the next trigger)" in done.stdout.splitlines()
    assert harness.output_text() == MERGED


def test_a_refused_merge_does_not_stop_the_queue(harness):
    harness.queue(Pull(number=12), Pull(number=13, head=SECOND))
    harness.script("pr merge 12", answer(code=1))
    done = harness.run()
    succeeded(done)
    assert f"merged #13 at {SECOND} (approval by {REVIEWER})" in done.stdout.splitlines()
    assert harness.output_text() == MERGED
    assert harness.calls("pr comment 12") == []
    assert len(harness.calls("pr comment 13")) == 1


# --- a pull request that fails a rule is skipped, and the run stays green -------------------------------------------

GUARD = "skip #12: a person merges this one (the guard's reason is on the line above)"
NOT_GREEN = "skip #12: 1 check(s) not green (pending, failing or errored)"
SKIPS = [
    pytest.param(
        Pull(mergeable="UNKNOWN"), "skip #12: mergeable=UNKNOWN (retry on the next trigger)", id="not-settled"
    ),
    pytest.param(
        Pull(mergeable="CONFLICTING"), "skip #12: mergeable=CONFLICTING (retry on the next trigger)", id="conflict"
    ),
    pytest.param(Pull(reviews=()), f"skip #12: awaiting a review from {REVIEWER} or a maintainer", id="no-review"),
    pytest.param(
        Pull(reviews=(review(commit=STALE),)),
        f"skip #12: {REVIEWER} approved {STALE[:12]}, head is {HEAD[:12]}: a fresh review is needed",
        id="approval-of-an-older-head",
    ),
    pytest.param(
        Pull(reviews=(review("CHANGES_REQUESTED"),)),
        f"skip #12: changes requested at {HEAD[:12]} by {REVIEWER}",
        id="changes-requested",
    ),
    pytest.param(
        Pull(reviews=(review(kind="User"),)),
        f"skip #12: awaiting a review from {REVIEWER} or a maintainer",
        id="a-human-with-the-reviewers-name",
    ),
    pytest.param(
        Pull(checks=(check_run("ci", "FAILURE"), status_context("review"))),
        f"skip #12: ci is not SUCCESS on {HEAD}",
        id="ci-failed",
    ),
    pytest.param(Pull(checks=()), f"skip #12: ci is not SUCCESS on {HEAD}", id="ci-absent"),
    pytest.param(
        # Only a check run has a name and a conclusion; a commit status that is called ci is not the ci check.
        Pull(checks=(status_context("ci"), status_context("gate"))),
        f"skip #12: ci is not SUCCESS on {HEAD}",
        id="a-status-named-like-the-check",
    ),
    pytest.param(Pull(checks=(check_run("ci"), check_run("lint", ""))), NOT_GREEN, id="another-check-unfinished"),
    pytest.param(Pull(checks=(check_run("ci"), status_context("review", "PENDING"))), NOT_GREEN, id="a-status-pending"),
    pytest.param(Pull(checks=(check_run("ci"), status_context("gate", "FAILURE"))), NOT_GREEN, id="a-status-failing"),
    pytest.param(
        # jq's `a // b` keeps an empty string, so an unfinished run is not rescued by a `state` it does not have.
        Pull(checks=(check_run("ci"), {"name": "lint", "conclusion": "", "state": "SUCCESS"})),
        NOT_GREEN,
        id="an-empty-conclusion-is-not-green",
    ),
    pytest.param(
        Pull(checks=(check_run("ci"), *(check_run(f"job-{n}") for n in range(99)))),
        "skip #12: 100 check contexts - the rollup may be truncated, cannot verify completeness",
        id="rollup-at-its-bound",
    ),
    pytest.param(Pull(files=(".github/workflows/ci.yml",)), GUARD, id="sensitive-path"),
    pytest.param(Pull(files=("src/advisory_radar/feature.py",), declared=3), GUARD, id="comparison-too-short"),
    pytest.param(
        Pull(reread={"headRefOid": MOVED, "baseRefOid": BASE}),
        "skip #12: base or head moved during the check; a fresh run decides",
        id="head-moved",
    ),
    pytest.param(
        Pull(reread={"headRefOid": HEAD, "baseRefOid": MOVED}),
        "skip #12: base or head moved during the check; a fresh run decides",
        id="base-moved",
    ),
]


@pytest.mark.parametrize(("pull", "message"), SKIPS)
def test_a_pull_request_that_fails_a_rule_is_skipped_and_the_run_stays_green(harness, pull, message):
    harness.queue(pull)
    done = harness.run()
    succeeded(done)
    assert message in done.stdout.splitlines()
    assert harness.output_text() == NOT_MERGED
    assert harness.calls("pr merge") == []
    assert harness.calls("git") == [] and harness.calls("pr comment") == []


def test_a_pull_request_that_is_not_mergeable_is_skipped_before_anything_else_is_read(harness):
    harness.queue(Pull(mergeable="CONFLICTING"))
    succeeded(harness.run())
    assert harness.keys() == ["pr list", "pr view 12"]


def test_the_guards_reason_is_on_the_line_above_the_skip(harness):
    harness.queue(Pull(files=("src/advisory_radar/feature.py", ".github/workflows/ci.yml")))
    lines = harness.run().stdout.splitlines()
    assert lines[lines.index(GUARD) - 1] == "guard: needs a human merge, it touches: .github/workflows/ci.yml"


def test_a_comparison_that_cannot_be_fetched_is_a_skip_not_a_crash(harness):
    harness.queue(Pull())
    harness.script(f"api compare/{BASE}...{HEAD}", answer(stderr="HTTP 404: Not Found\n", code=1))
    done = harness.run()
    succeeded(done)
    assert GUARD in done.stdout.splitlines()
    assert harness.calls("pr merge") == []


def test_neutral_and_skipped_checks_and_green_statuses_do_not_hold_a_merge_back(harness):
    checks = (check_run("ci"), check_run("docs", "NEUTRAL"), check_run("optional", "SKIPPED"), status_context("gate"))
    harness.queue(Pull(checks=checks))
    succeeded(harness.run())
    assert harness.output_text() == MERGED


def test_a_rollup_one_short_of_its_bound_is_still_read(harness):
    harness.queue(Pull(checks=(check_run("ci"), *(check_run(f"job-{n}") for n in range(98)))))
    succeeded(harness.run())
    assert harness.output_text() == MERGED


@pytest.mark.parametrize(
    ("pages", "merges"),
    [
        pytest.param(
            [[review(commit=STALE, at="2026-11-17T09:00:00Z")], [review(at="2026-11-17T10:00:00Z")]],
            True,
            id="the-current-approval-is-on-the-second-page",
        ),
        pytest.param(
            [
                [
                    review(
                        "CHANGES_REQUESTED",
                        login="maintainer",
                        kind="User",
                        association="OWNER",
                        at="2026-11-17T09:00:00Z",
                    )
                ],
                [review(at="2026-11-17T10:00:00Z")],
            ],
            False,
            id="a-change-request-on-the-first-page-still-counts",
        ),
    ],
)
def test_reviews_on_every_page_are_read_as_one_list(harness, pages, merges):
    """``gh api --paginate`` prints one JSON array per page, with nothing between them."""
    harness.queue(Pull())
    harness.script("api pulls/12/reviews?per_page=100", answer("".join(json.dumps(page) for page in pages)))
    succeeded(harness.run())
    assert (harness.output_text() == MERGED) is merges


# --- a failed read ends the run, as ``set -e`` ended it -------------------------------------------------------------


@pytest.mark.parametrize("key", ["pr view 12", "api pulls/12/reviews?per_page=100"])
def test_a_read_that_fails_ends_the_run_and_nothing_is_merged(harness, key):
    harness.queue(Pull())
    harness.script(key, answer(stderr="HTTP 502: Bad Gateway\n", code=1))
    done = harness.run()
    assert done.returncode == 1
    assert "::error::" in done.stdout
    assert harness.output_text() == NOT_MERGED
    assert harness.calls("pr merge") == []


def test_a_failed_reread_ends_the_run_and_nothing_is_merged(harness):
    pull = Pull()
    harness.queue(pull)
    harness.script("pr view 12", answer(json.dumps(pull.meta())), answer(stderr="HTTP 502\n", code=1))
    done = harness.run()
    assert done.returncode == 1
    assert harness.output_text() == NOT_MERGED
    assert harness.calls("pr merge") == []


def test_pull_request_data_that_is_not_json_ends_the_run(harness):
    harness.queue(Pull())
    harness.script("pr view 12", answer("this is not json"))
    done = harness.run()
    assert done.returncode == 1
    assert "::error::" in done.stdout
    assert harness.calls("pr merge") == []


@pytest.mark.parametrize("name", ["REPO", "REVIEWER_LOGIN", "REVIEWER_TYPE", "REQUIRED_CHECK"])
def test_a_missing_setting_ends_the_run_after_the_default_and_before_any_call(harness, name):
    """Every setting is read before the first call, so a queue that happens to be empty cannot hide a missing one."""
    harness.script("pr list", answer("[]"))
    done = harness.run(without=(name,))
    assert done.returncode == 1
    assert f"::error::{name} is not set" in done.stdout.splitlines()
    assert harness.output_text() == NOT_MERGED
    assert harness.calls() == []


@pytest.mark.parametrize("name", ["REPO", "REVIEWER_LOGIN", "REVIEWER_TYPE", "REQUIRED_CHECK"])
def test_a_setting_that_is_set_but_empty_is_missing(harness, name):
    """A setting that is set but empty counts as missing.

    An expression that resolves to nothing arrives as an empty string, and an empty reviewer or check would skip every
    pull request quietly. The run goes red instead.
    """
    harness.script("pr list", answer("[]"))
    done = harness.run(env={name: ""})
    assert done.returncode == 1
    assert f"::error::{name} is not set" in done.stdout.splitlines()
    assert harness.output_text() == NOT_MERGED
    assert harness.calls() == []


def test_a_missing_output_file_ends_the_run_before_anything_is_called(harness):
    harness.script("pr list", answer("[]"))
    done = harness.run(without=("GITHUB_OUTPUT",))
    assert done.returncode == 1
    assert "::error::GITHUB_OUTPUT is not set" in done.stdout.splitlines()
    assert harness.output_text() == ""
    assert harness.calls() == []
