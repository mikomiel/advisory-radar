"""A pushed tag releases the image only when it is a release of ``main``, and only the newest one moves ``latest``.

Anyone who can push a tag can start the ``release`` workflow, and the job holds the credentials that publish the
image and sign its provenance. So before it builds or pushes anything the job must prove that the tag's commit
landed on ``main`` and that the version the tag names is the version in ``pyproject.toml``, and it may move
``latest`` only for the highest stable version. A workflow that merely contains those commands proves nothing,
so these tests run the job's own shell steps in the order the runner does, in throwaway repositories laid out
the way ``actions/checkout`` with ``fetch-depth: 0`` leaves a tag build, and read what the job would publish.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml"
BUILD = "docker/build-push-action@"
REPOSITORY = "octo/radar"
IMAGE = f"ghcr.io/{REPOSITORY}"


def release_steps() -> list[dict]:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["image"]["steps"]


def shell_before_the_build() -> list[dict]:
    """The ``run`` steps that come before the build step: whatever they refuse, the release never reaches it."""
    ahead: list[dict] = []
    for step in release_steps():
        if str(step.get("uses", "")).startswith(BUILD):
            return ahead
        if "run" in step:
            ahead.append(step)
    raise AssertionError("the release job has no build step")


@dataclass(frozen=True)
class Outcome:
    refused: bool
    log: str
    tags: list[str]


class Checkout:
    """A repository in the state a tag build finds it: every tag fetched, ``origin/main`` present, detached head."""

    def __init__(self, root: Path) -> None:
        self.root = root
        base = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
        self.env = {
            **base,
            "HOME": str(root.parent),
            "XDG_CONFIG_HOME": str(root.parent / "xdg"),
            # The job's own interpreter parses pyproject.toml, so the one that runs this suite is on the path.
            "PATH": os.pathsep.join([str(Path(sys.executable).parent), base.get("PATH", "")]),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
        root.mkdir(parents=True)
        self.git("init", "-q", "--initial-branch=main")
        self.counter = 0

    def git(self, *args: str) -> str:
        done = subprocess.run(["git", "-C", str(self.root), *args], env=self.env, capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        return done.stdout.strip()

    def commit(self, version: str | None, *, on_main: bool = True, project: str | None = None) -> str:
        """A commit whose ``pyproject.toml`` carries ``version``; ``main`` (and ``origin/main``) move to it.

        ``version=None`` leaves the commit without a ``pyproject.toml``, and ``project`` is the text of that file when
        it should be something else than a well-formed ``[project]`` table.
        """
        self.counter += 1
        pyproject = self.root / "pyproject.toml"
        if project is not None:
            pyproject.write_text(project)
        elif version is None:
            pyproject.unlink(missing_ok=True)
        else:
            pyproject.write_text(f'[project]\nname = "radar"\nversion = "{version}"\n')
        (self.root / "change.txt").write_text(f"{self.counter}\n")
        self.git("add", "--all")
        self.git("commit", "-q", "-m", f"change {self.counter}")
        sha = self.git("rev-parse", "HEAD")
        if on_main:
            self.git("update-ref", "refs/remotes/origin/main", sha)
        return sha

    def side_commit(self, version: str) -> str:
        """A commit that is not an ancestor of ``origin/main``, as on a branch that never merged.

        The head goes back to ``main`` afterwards, so that the next commit continues ``main`` and does not adopt
        this one.
        """
        main = self.git("rev-parse", "refs/remotes/origin/main")
        self.git("checkout", "-q", "--detach", main)
        sha = self.commit(version, on_main=False)
        self.git("checkout", "-q", "--detach", main)
        return sha

    def tag(self, name: str, sha: str, *, annotated: bool = False) -> None:
        self.git("tag", *(["--annotate", "--message", "release"] if annotated else []), name, sha)

    def release(self, tag: str) -> Outcome:
        """Run the job's shell for a push of ``tag``, as the runner would, and report what it would publish."""
        sha = self.git("rev-parse", f"{tag}^{{commit}}")
        self.git("checkout", "-q", "--detach", sha)
        output = self.root.parent / "github-output"
        output.write_text("")
        env = {
            **self.env,
            "GITHUB_SHA": sha,
            "GITHUB_REF_NAME": tag,
            "GITHUB_REF": f"refs/tags/{tag}",
            "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_OUTPUT": str(output),
        }
        log = ""
        for step in shell_before_the_build():
            done = subprocess.run(
                ["bash", "--noprofile", "--norc", "-e", "-c", step["run"]],
                cwd=self.root,
                env=env,
                capture_output=True,
                text=True,
            )
            log += done.stdout + done.stderr
            if done.returncode != 0:
                return Outcome(refused=True, log=log, tags=[])
        return Outcome(refused=False, log=log, tags=published_tags(output.read_text()))


def published_tags(github_output: str) -> list[str]:
    found = re.search(r"^list<<(\w+)\n(.*?)\n\1$", github_output, re.M | re.S)
    assert found, f"the job wrote no tag list: {github_output!r}"
    return found.group(2).split("\n")


@pytest.fixture
def checkout(tmp_path: Path) -> Checkout:
    return Checkout(tmp_path / "work")


def test_a_tag_on_main_with_its_version_is_released_and_moves_latest(checkout: Checkout):
    checkout.tag("v1.0.0", checkout.commit("1.0.0"))
    outcome = checkout.release("v1.0.0")
    assert not outcome.refused, outcome.log
    assert outcome.tags == [f"{IMAGE}:v1.0.0", f"{IMAGE}:latest"]


def test_a_tag_whose_commit_is_not_on_main_is_refused_before_the_build(checkout: Checkout):
    checkout.tag("v1.0.0", checkout.commit("1.0.0"))
    checkout.tag("v1.1.0", checkout.side_commit("1.1.0"))
    outcome = checkout.release("v1.1.0")
    assert outcome.refused, "a tag on a commit that never reached main must not publish an image"
    assert "main" in outcome.log


def test_a_tag_that_names_another_version_than_pyproject_is_refused(checkout: Checkout):
    checkout.tag("v1.1.0", checkout.commit("1.0.0"))
    outcome = checkout.release("v1.1.0")
    assert outcome.refused, "the tag says 1.1.0 while the code at that commit says 1.0.0"
    assert "1.0.0" in outcome.log and "1.1.0" in outcome.log


def test_a_checkout_without_origin_main_cannot_clear_a_tag(checkout: Checkout):
    checkout.tag("v1.0.0", checkout.commit("1.0.0"))
    checkout.git("update-ref", "-d", "refs/remotes/origin/main")
    outcome = checkout.release("v1.0.0")
    assert outcome.refused, "without origin/main the job cannot tell whether the tag is on main"
    assert "origin/main" in outcome.log


def test_an_older_stable_tag_never_moves_latest(checkout: Checkout):
    checkout.tag("v1.0.0", checkout.commit("1.0.0"))
    checkout.tag("v1.1.0", checkout.commit("1.1.0"))
    outcome = checkout.release("v1.0.0")
    assert not outcome.refused, outcome.log
    assert outcome.tags == [f"{IMAGE}:v1.0.0"], "latest would move back to a version that is not the newest"
    assert checkout.release("v1.1.0").tags == [f"{IMAGE}:v1.1.0", f"{IMAGE}:latest"]


def test_the_newest_tag_is_chosen_by_version_number_not_by_text(checkout: Checkout):
    checkout.tag("v0.9.0", checkout.commit("0.9.0"))
    checkout.tag("v0.10.0", checkout.commit("0.10.0"))
    assert checkout.release("v0.9.0").tags == [f"{IMAGE}:v0.9.0"]
    assert checkout.release("v0.10.0").tags == [f"{IMAGE}:v0.10.0", f"{IMAGE}:latest"]


@pytest.mark.parametrize("tag", ["v1.2.0-rc1", "v1.2.0+build5", "v1.2.0.1"])
def test_a_tag_that_is_not_a_stable_version_never_moves_latest(checkout: Checkout, tag: str):
    # No stable tag exists at all here: the listing of stable tags is empty and must not abort the job.
    checkout.tag(tag, checkout.commit(tag.removeprefix("v")))
    outcome = checkout.release(tag)
    assert not outcome.refused, outcome.log
    assert outcome.tags == [f"{IMAGE}:{tag}"]


def test_a_pre_release_does_not_hide_the_newest_stable_tag(checkout: Checkout):
    checkout.tag("v1.0.0", checkout.commit("1.0.0"))
    checkout.tag("v1.1.0-rc1", checkout.commit("1.1.0-rc1"))
    assert checkout.release("v1.0.0").tags == [f"{IMAGE}:v1.0.0", f"{IMAGE}:latest"]


#: Above every release these tests cut: a rule that lets this tag rank holds ``latest`` back for good.
STRAY = "v999.0.0"

#: A commit for the stray tag, each with one thing wrong that the first step of the job refuses to release.
STRAY_COMMITS = {
    "a commit that never reached main": lambda checkout: checkout.side_commit("999.0.0"),
    "a version that is not the tag's": lambda checkout: checkout.commit("1.0.1"),
    "no pyproject.toml": lambda checkout: checkout.commit(None),
    "a pyproject.toml that is not TOML": lambda checkout: checkout.commit(None, project="[project\n"),
}


@pytest.mark.parametrize("make_stray", STRAY_COMMITS.values(), ids=STRAY_COMMITS.keys())
def test_a_higher_tag_that_the_job_would_refuse_does_not_hold_latest_back(checkout: Checkout, make_stray):
    # `latest` goes to the highest stable tag that is a release of main. A tag that fails the checks of the first step
    # is not one, whoever pushed it: letting it rank would keep `latest` on the old image until someone deletes it.
    checkout.tag("v1.0.0", checkout.commit("1.0.0"))
    checkout.tag(STRAY, make_stray(checkout))
    assert checkout.release(STRAY).refused, "the stray tag has to be one that the job refuses to release itself"
    outcome = checkout.release("v1.0.0")
    assert not outcome.refused, outcome.log
    assert outcome.tags == [f"{IMAGE}:v1.0.0", f"{IMAGE}:latest"]


def test_a_higher_tag_that_names_no_commit_does_not_hold_latest_back(checkout: Checkout):
    # A tag may point at a tree or a blob. It has no commit to check, so it cannot be a release, and it must not
    # abort the job either.
    checkout.tag("v1.0.0", checkout.commit("1.0.0"))
    checkout.tag(STRAY, checkout.git("rev-parse", "HEAD^{tree}"))
    outcome = checkout.release("v1.0.0")
    assert not outcome.refused, outcome.log
    assert outcome.tags == [f"{IMAGE}:v1.0.0", f"{IMAGE}:latest"]


def test_a_stray_tag_does_not_keep_a_later_release_from_taking_latest(checkout: Checkout):
    checkout.tag("v1.0.0", checkout.commit("1.0.0"))
    checkout.tag(STRAY, checkout.side_commit("999.0.0"))
    checkout.tag("v1.1.0", checkout.commit("1.1.0"))
    assert checkout.release("v1.1.0").tags == [f"{IMAGE}:v1.1.0", f"{IMAGE}:latest"]
    # and the stray tag is no reason to hand `latest` back to the older release
    assert checkout.release("v1.0.0").tags == [f"{IMAGE}:v1.0.0"]


@pytest.mark.parametrize("annotated", [False, True], ids=["lightweight", "annotated"])
def test_a_higher_tag_that_is_a_release_still_holds_latest_back(checkout: Checkout, annotated: bool):
    # The other half of the rule, next to a stray tag that ranks above both: a higher tag that passes the checks is
    # what the older release has to yield to, whether the tag is an object of its own or a bare reference.
    checkout.tag("v1.0.0", checkout.commit("1.0.0"))
    checkout.tag(STRAY, checkout.side_commit("999.0.0"))
    checkout.tag("v1.1.0", checkout.commit("1.1.0"), annotated=annotated)
    outcome = checkout.release("v1.0.0")
    assert not outcome.refused, outcome.log
    assert outcome.tags == [f"{IMAGE}:v1.0.0"], "v1.1.0 is a release of main and is above this tag"


def test_the_tag_is_checked_before_anything_is_built_or_pushed():
    steps = release_steps()
    assert str(steps[0]["uses"]).startswith("actions/checkout@")
    assert steps[0].get("with", {}).get("fetch-depth") == 0, "origin/main and every tag must be present"
    first_shell = steps[1]
    assert "run" in first_shell, "the check must be the step right after the checkout"
    assert "merge-base --is-ancestor" in first_shell["run"]
    # nothing that holds a credential or builds may run first
    credentialed = [i for i, step in enumerate(steps) if str(step.get("uses", "")).startswith("docker/")]
    assert credentialed and min(credentialed) > 1


def test_the_image_is_built_from_the_checkout_that_was_verified():
    steps = release_steps()
    build = next(step for step in steps if str(step.get("uses", "")).startswith(BUILD))
    # Without a `context` the build action reads the repository again through its own default Git context, and what it
    # builds is no longer the working tree that the first step verified.
    assert build["with"].get("context") == ".", "the build must name the verified checkout as its context"
    # `.` is that working tree only while the checkout leaves the event's commit at the workspace root
    assert not {"ref", "path", "repository"} & set(steps[0].get("with", {}))


def test_no_expression_is_interpolated_into_a_script():
    # A tag name is attacker-chosen text. The runner exposes it as GITHUB_REF_NAME, so a script reads the
    # environment instead of having the value pasted into its source.
    for step in release_steps():
        assert "${{" not in step.get("run", ""), f"{step.get('name')}: an expression is pasted into the script"
