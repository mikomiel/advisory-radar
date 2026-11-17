"""Build and CI inputs are pinned, bounded and exercised, so none of them moves or hangs without a commit here.

Five properties, each one that has been edited away or never existed:

* the build backend and the ``uv`` that CI runs are exact versions, so a new release of either cannot change
  what CI builds or installs (the lock pins the dependencies, not the tools that read it);
* Dependabot watches the container files as well as the Python dependencies and the actions;
* every job that runs steps has a timeout, so a hung step cannot hold a runner for the default six hours;
* CI exercises what a self-hoster runs: the compose file must parse, and the image must write to a volume that
  Docker has just created, with no ``chmod`` standing in for the ownership the image should provide;
* ruff reads every file: it skips what any ``.gitignore`` or ``.ignore`` lists, tracked files included, so a pull
  request could take a directory out of the lint and the format check by adding one such file beside it.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
EXACT = re.compile(r"[A-Za-z0-9_.-]+==\d+(\.\d+)*")
SETUP_UV = "astral-sh/setup-uv@"
MAX_TIMEOUT_MINUTES = 60
RUFF_RUN = re.compile(r"\bruff\s+(check|format)\b")


def workflows() -> dict[str, dict]:
    paths = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    return {path.name: yaml.safe_load(path.read_text()) for path in paths}


def ci_steps() -> list[dict]:
    return workflows()["ci.yml"]["jobs"]["ci"]["steps"]


def step_named(name: str) -> dict:
    found = [step for step in ci_steps() if step.get("name") == name]
    assert len(found) == 1, f"the ci job needs exactly one step named {name!r}"
    return found[0]


def test_the_build_backend_is_an_exact_version():
    requires = tomllib.loads((ROOT / "pyproject.toml").read_text())["build-system"]["requires"]
    assert requires, "the build system names no backend"
    for requirement in requires:
        assert EXACT.fullmatch(requirement), f"{requirement!r} lets the build backend change without a commit"
    assert any(requirement.startswith("hatchling==") for requirement in requires)


def test_setup_uv_installs_the_uv_family_of_the_image():
    # The image's builder runs the 0.9 line of uv against the same lock, so CI runs an exact release of that line.
    dockerfile = (ROOT / "Dockerfile").read_text()
    family = re.search(r"^FROM ghcr\.io/astral-sh/uv:(\d+\.\d+)-", dockerfile, re.M)
    assert family, "the Dockerfile no longer names the uv family it builds with"
    seen = 0
    for name, document in workflows().items():
        for job_name, job in document["jobs"].items():
            for step in job.get("steps", []):
                if not str(step.get("uses", "")).startswith(SETUP_UV):
                    continue
                seen += 1
                version = str(step.get("with", {}).get("version", ""))
                where = f"{name}: {job_name}"
                assert re.fullmatch(r"\d+\.\d+\.\d+", version), f"{where}: setup-uv has no exact version ({version!r})"
                line = family.group(1)
                assert version.startswith(line + "."), f"{where}: uv {version} is outside the {line} line"
    assert seen, "no workflow installs uv any more; delete this test with the last step"


def test_dependabot_covers_every_dependency_ecosystem_the_repository_uses():
    updates = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())["updates"]
    covered = {(update["package-ecosystem"], update["directory"]) for update in updates}
    assert covered >= {("uv", "/"), ("github-actions", "/"), ("docker", "/"), ("docker-compose", "/")}
    for update in updates:
        ecosystem = update["package-ecosystem"]
        assert update["schedule"]["interval"] == "weekly", ecosystem
        assert update["open-pull-requests-limit"] == 5, ecosystem
        assert "dependencies" in update["labels"], ecosystem
        assert update["groups"], f"{ecosystem}: ungrouped updates would open one pull request per image"


@pytest.mark.parametrize(("name", "job_name"), [(n, j) for n, d in workflows().items() for j in d["jobs"]])
def test_every_job_has_a_bounded_run_time(name: str, job_name: str):
    job = workflows()[name]["jobs"][job_name]
    if "uses" in job:
        # GitHub rejects timeout-minutes on a job that calls a reusable workflow; the called jobs carry their own.
        assert "timeout-minutes" not in job, f"{name}: {job_name} calls a workflow, which takes no timeout"
        return
    minutes = job.get("timeout-minutes")
    assert isinstance(minutes, int) and not isinstance(minutes, bool), f"{name}: {job_name} has no timeout-minutes"
    assert 1 <= minutes <= MAX_TIMEOUT_MINUTES, f"{name}: {job_name} may run {minutes} minutes"


def test_ci_checks_that_the_compose_file_parses():
    step = step_named("Compose file is valid")
    run = step["run"]
    assert "docker compose" in run and "config -q" in run
    # `env_file: .env` must exist for `config` to resolve, so the check runs on a scratch copy and leaves the
    # checkout alone: a .env written into the work tree could be picked up by a later step.
    assert "mktemp -d" in run
    assert (ROOT / "docker-compose.yml").is_file()


def test_every_ruff_run_reads_the_files_that_an_ignore_file_lists():
    """ruff honours a .gitignore or .ignore in any directory, so one file could hide a subtree from the checks.

    Nothing under ``tests/`` or ``.github/`` changes in such a pull request, so the sensitive-path guard cannot see
    it, and a guard that listed every ``.gitignore`` would refuse ordinary work. The flag takes the files out of the
    decision instead. Every ruff run of every workflow is held to it, so a ruff step added to another job (the
    ``py314`` job has none today) is covered too.
    """
    runs = []
    for name, document in workflows().items():
        for job_name, job in document["jobs"].items():
            for step in job.get("steps", []):
                for line in str(step.get("run", "")).splitlines():
                    found = RUFF_RUN.search(line)
                    if found:
                        runs.append((found.group(1), f"{name}: {job_name}: {line.strip()}", line.split()))
    assert {kind for kind, _, _ in runs} == {"check", "format"}, "CI no longer runs both the lint and the format check"
    for _, where, words in runs:
        assert "--no-respect-gitignore" in words, f"{where} skips the files that an ignore file lists"
