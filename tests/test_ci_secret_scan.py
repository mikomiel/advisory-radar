"""The CI secret scan covers the complete intended range, and the job proves it before reporting.

The guarantee is easy to edit away: a checkout back to a one-commit clone, a range that silently
shrinks to the working tree, or a self-test that no longer fails the job would each leave a green
``ci`` claiming more than it checked. These assertions pin the properties rather than the exact
shell text, so the range and the fail-closed paths cannot be removed by accident.
"""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"


def ci_job() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["ci"]


def secret_scan_step() -> dict:
    steps = [step for step in ci_job()["steps"] if step.get("name") == "Secret scan"]
    assert len(steps) == 1, "the ci job must have exactly one secret-scan step"
    return steps[0]


def test_the_ci_checkout_fetches_every_commit():
    checkouts = [step for step in ci_job()["steps"] if str(step.get("uses", "")).startswith("actions/checkout@")]
    assert len(checkouts) == 1, "the secret scan depends on the ci job's single checkout"
    assert checkouts[0].get("with", {}).get("fetch-depth") == 0, (
        "a one-commit checkout would hide a secret added and removed earlier in the same branch"
    )


def test_the_secret_scan_proves_the_event_range_before_scanning_it():
    step = secret_scan_step()
    # The range comes from the event, not from a fixed ref or the working tree.
    assert step["env"]["EVENT_NAME"] == "${{ github.event_name }}"
    assert step["env"]["PR_BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert step["env"]["PUSH_BEFORE_SHA"] == "${{ github.event.before }}"

    run = step["run"]
    for marker in ("git cat-file -e", "git merge-base --is-ancestor", "git rev-list --count"):
        assert marker in run, f"the range is not proved: {marker!r} is missing"
    assert 'range="$base..$head"' in run, "the scan must use the event range, not a default git log"
    assert '--log-opts="$range"' in run, "the scanner must be given the proved range"
    assert 'range="--all"' in run, "a new branch or another event must scan every ref instead of shrinking"
    assert run.count("::error::") >= 4, "a missing base, a non-ancestor or an empty range must fail closed"


def test_the_secret_scan_self_tests_history_before_the_real_scan():
    run = secret_scan_step()["run"]
    assert "mktemp -d" in run, "the self-test must not write its fixture into the repository"
    assert "ghp_" in run, "the self-test fixture must be a shape the scanner detects"
    assert "--log-opts=--all" in run, "the self-test must scan history, not the working tree"
    assert '"$self_code" -ne 1' in run, "the self-test must fail the job unless the removed secret is detected"
    assert run.index("self-test: remove") < run.index("--report-path"), (
        "the self-test must run before the real scan: a scanner that cannot see history invalidates it"
    )
