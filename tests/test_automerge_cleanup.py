"""The automerge deletes the branch it merged, and only that branch.

``delete_branch_on_merge`` is a repository setting, and a merge made through the API does not honour it: the
branch of an automerged pull request survived with the setting on. The workflow therefore deletes the head ref
itself. That step is a shell script which only runs on the default branch, so this test is structural: it pins
the properties a reviewer cannot observe in a diff of a live run -- the merge still requires the exact head,
the delete targets the ref that was merged, and a fork's head is never touched.
"""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "automerge.yml"


def merge_step() -> str:
    loaded = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = loaded["jobs"]["merge"]["steps"]
    return next(step["run"] for step in steps if "gh pr merge" in step.get("run", ""))


def test_the_merge_still_pins_the_head_the_reviewer_approved():
    run = merge_step()
    # The head the approval was checked against is the head GitHub merges. --delete-branch is deliberately not
    # used: gh deletes the local branch too, and fails after the merge when that branch is not checked out here.
    assert 'gh pr merge "$pr" --repo "$REPO" --squash --match-head-commit "$head"' in run
    assert "--delete-branch" not in run


def test_the_delete_targets_the_merged_ref_of_this_repository_only():
    run = merge_step()
    delete = run.index("git/refs/heads/$branch")
    assert run.index("headRefName") < delete, "the delete must use the branch name the merge just used"
    assert run.index("isCrossRepository") < delete, "a fork's head may name an unrelated branch of this repository"
    assert "^[A-Za-z0-9][A-Za-z0-9._/-]*$" in run, "the ref name is checked before it reaches the API"
    # An elif condition can fail without aborting the `set -e` loop, so a 404 or a permissions failure reports
    # itself instead of failing the run that already merged.
    assert "elif gh api -X DELETE" in run
    assert "::warning::" in run
