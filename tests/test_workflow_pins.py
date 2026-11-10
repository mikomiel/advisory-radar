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
            assert PINNED.fullmatch(reference), f"{name}: {reference} is a mutable reference"
            line = text[match.start() : text.index("\n", match.start())]
            assert re.search(r"#\s*v\d", line), f"{name}: {reference} is pinned without its version comment"


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
