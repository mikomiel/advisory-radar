"""Every action reference is a commit, and the release attests the digest it pushed.

A mutable tag is a supply-chain hole: the tag can be repointed without any commit here. The repository
setting that rejects mutable references enforces the same rule on the server, and this test fails first --
in review, before the merge. Dependabot keeps the pins current because each one carries its version in a
trailing comment, which is also what a person reads when the diff arrives.

The release assertions are structural rather than textual on purpose, and they keep the job boundary,
because ``steps`` is job-local: an attestation in another job, or one that runs before the build, names an
empty digest while every string still looks right. That is the regression worth catching.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
# Anchored at the line: "statuses:" also contains "uses:", and a permission key is not an action reference.
USES = re.compile(r"^[ \t]*(?:-[ \t]*)?uses:[ \t]*(\S+)", re.M)
PINNED = re.compile(r"[^@\s]+@[0-9a-f]{40}")
RUNNER = re.compile(r"runs-on:[ \t]*([^\s#]+)")
BUILD = "docker/build-push-action@"
ATTEST = "actions/attest-build-provenance@"


def workflow_paths() -> list[Path]:
    # GitHub accepts both extensions, so a new workflow must not be able to slip past these checks.
    return sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))


def workflow_texts() -> list[tuple[str, str]]:
    return [(path.name, path.read_text()) for path in workflow_paths()]


def release() -> dict:
    return yaml.safe_load((WORKFLOWS / "release.yml").read_text())


def test_every_action_reference_is_a_pinned_commit():
    for name, text in workflow_texts():
        for match in USES.finditer(text):
            reference = match.group(1)
            if reference.startswith("./"):
                # A reusable workflow in this repository runs the default-branch file the caller
                # already trusts, so it has no release to pin; name the only one allowed.
                assert reference == "./.github/workflows/release-please.yml", f"{name}: {reference}"
                continue
            assert PINNED.fullmatch(reference), f"{name}: {reference} is a mutable reference"
            line = text[match.start() : text.index("\n", match.start())]
            assert re.search(r"#\s*v\d", line), f"{name}: {reference} is pinned without its version comment"


def test_the_release_workflow_is_called_only_when_the_merge_landed():
    """`workflow_run` fires on every completion of the sweep, merged or not.

    The sweep completes on a schedule and after every gate or CI pass, so observing its completion
    cost one release run per completion rather than per merge. The merge step now reports whether
    it landed a pull request and the release workflow is called from that result.
    """
    merge = yaml.safe_load((WORKFLOWS / "automerge.yml").read_text())
    job = merge["jobs"]["merge"]
    assert job["outputs"] == {"merged": "${{ steps.merge.outputs.merged }}"}
    step = next(item for item in job["steps"] if item.get("id") == "merge")
    # The shell owns the outcome, and the order matters: a default written before the loop, the
    # true written at the merge itself. A later candidate's failure must not lose a landed merge,
    # which is why the true is written before the branch cleanup and the comment can fail.
    run = step["run"]
    default_at = run.index('echo "merged=false" >> "$GITHUB_OUTPUT"')
    loop_at = run.index("mapfile -t candidates")
    merge_at = run.index('if gh pr merge "$pr"')
    true_at = run.index('echo "merged=true" >> "$GITHUB_OUTPUT"')
    cleanup_at = run.index("delete_merged_branch.py")
    comment_at = run.index("gh pr comment")
    assert default_at < loop_at, "the default must precede the loop"
    assert merge_at < true_at < cleanup_at < comment_at, "write true at the merge, before cleanup"
    assert run.count('echo "merged=true" >> "$GITHUB_OUTPUT"') == 1
    assert run.count('echo "merged=false" >> "$GITHUB_OUTPUT"') == 1

    release_job = merge["jobs"]["release"]
    assert release_job["needs"] == "merge"
    # The output alone decides; !cancelled() keeps a landed merge releasable after a later failure.
    assert release_job["if"] == "${{ !cancelled() && needs.merge.outputs.merged == 'true' }}"
    assert release_job["uses"] == "./.github/workflows/release-please.yml"
    assert release_job["secrets"] == "inherit"
    assert release_job["permissions"] == {"contents": "write", "pull-requests": "write"}

    release_please = yaml.safe_load((WORKFLOWS / "release-please.yml").read_text())
    declared = release_please.get("on", release_please.get(True))
    assert declared["push"] == {"branches": ["main"]}
    assert "workflow_call" in declared
    assert "workflow_dispatch" in declared
    assert "workflow_run" not in declared


def test_every_job_runs_on_a_pinned_os_release():
    # A label, not an immutable image: GitHub still updates the image behind ubuntu-24.04. It just cannot
    # move to another release without a commit here, which is what ubuntu-latest allows.
    for name, text in workflow_texts():
        for label in RUNNER.findall(text):
            assert label == "ubuntu-24.04", f"{name}: {label} can move to another release without a commit"


def test_the_release_attests_the_digest_it_pushed():
    jobs = release()["jobs"]
    holders = {
        name: job
        for name, job in jobs.items()
        if any(str(step.get("uses", "")).startswith((BUILD, ATTEST)) for step in job["steps"])
    }
    assert list(holders) == ["image"], (
        f"the build and its attestation must live in one job, because steps.* is job-local; found {sorted(holders)}"
    )

    steps = holders["image"]["steps"]
    builds = [index for index, step in enumerate(steps) if str(step.get("uses", "")).startswith(BUILD)]
    attests = [index for index, step in enumerate(steps) if str(step.get("uses", "")).startswith(ATTEST)]
    assert len(builds) == 1, "exactly one build step must be the attestation's subject"
    assert len(attests) == 1, "the release must publish the attestation, not merely mention it"
    assert attests[0] > builds[0], "the attestation reads steps.build.outputs.digest, so it runs after the build"

    build, attest = steps[builds[0]], steps[attests[0]]
    assert build.get("id") == "build", "the attestation reads steps.build.outputs.digest; this step must own it"
    assert build["with"].get("push") is True, "an unpushed image has no digest to attest"
    assert build["with"].get("provenance") is True
    assert build["with"].get("sbom") is True

    subject = attest["with"]
    assert subject["subject-digest"] == "${{ steps.build.outputs.digest }}", "the subject must be the pushed digest"
    assert subject["subject-name"].startswith("ghcr.io/")
    assert subject.get("push-to-registry") is True, "an attestation nobody can fetch verifies nothing"


def test_the_release_may_sign_and_publish_the_attestation():
    document = release()
    workflow_permissions = document.get("permissions") or {}
    signing = [
        job
        for job in document["jobs"].values()
        if any(str(step.get("uses", "")).startswith(ATTEST) for step in job["steps"])
    ]
    assert len(signing) == 1
    # A job-level mapping replaces the workflow-level one rather than merging with it, so it is the
    # effective grant and the only thing that decides whether signing can work.
    effective = signing[0].get("permissions", workflow_permissions)
    assert effective.get("id-token") == "write", "sigstore signing needs the OIDC token"
    assert effective.get("attestations") == "write"


def test_the_merge_workflow_may_close_the_issues_its_body_names():
    """GitHub closes a linked issue only for the identity that merges with `issues: write`.

    Without the scope the auto-close is skipped silently and the tracking issue stays open until
    someone notices -- measured on merge-guard, where human merges closed their issue one second
    after the merge and bot merges did not (mikomiel/merge-guard#62).
    """
    merge = yaml.safe_load((WORKFLOWS / "automerge.yml").read_text())
    # A job-level mapping replaces the workflow-level one rather than merging with it, so it is the
    # effective grant; asserting only the workflow mapping would miss an override on the merge job.
    effective = merge["jobs"]["merge"].get("permissions", merge["permissions"])
    assert effective.get("issues") == "write"
