"""The automerge calls the tested cleanup, and its failure cannot fail the merge.

The deletion itself is tested in ``tests/test_delete_merged_branch.py``, against a real local git remote. This
file pins the two declarations the workflow must hold: the merge still refuses a head that moved, and the
cleanup is a guarded call whose non-zero exit is a warning -- the merge it follows has already happened.
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


def test_the_cleanup_is_the_tested_script_and_its_failure_is_a_warning():
    run = merge_step()
    call = next(line for line in run.splitlines() if "scripts/delete_merged_branch.py" in line)
    assert call.strip().startswith("if python3 scripts/delete_merged_branch.py"), (
        "the call is a condition, so a refusal or a failed delete cannot abort the run after the merge"
    )
    assert '--branch "$branch"' in call and '--head "$head"' in call
    assert run.index("headRefName") < run.index("scripts/delete_merged_branch.py")
    assert run.index("isCrossRepository") < run.index("scripts/delete_merged_branch.py")
    assert "::warning::" in run
