"""Every action reference is a commit, and the release attests the digest it pushed.

A mutable tag is a supply-chain hole: the tag can be repointed without any commit here. The repository
setting that rejects mutable references enforces the same rule on the server, and this test fails first --
in review, before the merge. Dependabot keeps the pins current because each one carries its version in a
trailing comment, which is also what a person reads when the diff arrives.

The release assertions are structural rather than textual on purpose. Searching the file for a string would
still pass if `id: build` moved to another step, or if the attestation step were removed and its strings
left in a comment -- and an attestation that names an empty digest is exactly the regression worth catching.
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


def workflow_paths() -> list[Path]:
    # GitHub accepts both extensions, so a new workflow must not be able to slip past these checks.
    return sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))


def workflow_texts() -> list[tuple[str, str]]:
    return [(path.name, path.read_text()) for path in workflow_paths()]


def release_steps() -> list[dict]:
    document = yaml.safe_load((WORKFLOWS / "release.yml").read_text())
    return [step for job in document["jobs"].values() for step in job["steps"]]


def steps_using(prefix: str) -> list[dict]:
    return [step for step in release_steps() if str(step.get("uses", "")).startswith(prefix)]


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
    build = steps_using("docker/build-push-action@")
    assert len(build) == 1, "exactly one build step must be the attestation's subject"
    build = build[0]
    assert build.get("id") == "build", "the attestation reads steps.build.outputs.digest; this step must own it"
    assert build["with"].get("push") is True, "an unpushed image has no digest to attest"
    assert build["with"].get("provenance") is True
    assert build["with"].get("sbom") is True

    attest = steps_using("actions/attest-build-provenance@")
    assert len(attest) == 1, "the release must publish the attestation, not merely mention it"
    subject = attest[0]["with"]
    assert subject["subject-digest"] == "${{ steps.build.outputs.digest }}", "the subject must be the pushed digest"
    assert subject["subject-name"].startswith("ghcr.io/")
    assert subject.get("push-to-registry") is True, "an attestation nobody can fetch verifies nothing"


def test_the_release_may_sign_and_publish_the_attestation():
    permissions = yaml.safe_load((WORKFLOWS / "release.yml").read_text())["permissions"]
    assert permissions["id-token"] == "write", "sigstore signing needs the OIDC token"
    assert permissions["attestations"] == "write"
