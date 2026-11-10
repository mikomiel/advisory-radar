"""Every action reference is a commit, and every runner is a fixed image.

A mutable tag is a supply-chain hole: the tag can be repointed without any commit here. The repository
setting that rejects mutable references enforces the same rule on the server, and this test fails first --
in review, before the merge. Dependabot keeps the pins current because each one carries its version in a
trailing comment, which is also what a person reads when the diff arrives.
"""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
# Anchored at the line: "statuses:" also contains "uses:", and a permission key is not an action reference.
USES = re.compile(r"^[ \t]*(?:-[ \t]*)?uses:[ \t]*(\S+)", re.M)
PINNED = re.compile(r"[^@\s]+@[0-9a-f]{40}")
RUNNER = re.compile(r"runs-on:[ \t]*([^\s#]+)")


def workflow_texts() -> list[tuple[str, str]]:
    return [(path.name, path.read_text()) for path in sorted(WORKFLOWS.glob("*.yml"))]


def test_every_action_reference_is_a_pinned_commit():
    for name, text in workflow_texts():
        for match in USES.finditer(text):
            reference = match.group(1)
            assert PINNED.fullmatch(reference), f"{name}: {reference} is a mutable reference"
            line = text[match.start() : text.index("\n", match.start())]
            assert re.search(r"#\s*v\d", line), f"{name}: {reference} is pinned without its version comment"


def test_every_job_runs_on_a_fixed_runner():
    for name, text in workflow_texts():
        for label in RUNNER.findall(text):
            assert label == "ubuntu-24.04", f"{name}: {label} moves under us"


def test_the_release_attests_the_image_it_publishes():
    release = (WORKFLOWS / "release.yml").read_text()
    # The attestation names the digest the build actually pushed, so the build step must export it.
    assert "id: build" in release
    assert "subject-digest: ${{ steps.build.outputs.digest }}" in release
    assert "actions/attest-build-provenance@" in release
    assert "provenance: true" in release and "sbom: true" in release
    assert "id-token: write" in release and "attestations: write" in release
