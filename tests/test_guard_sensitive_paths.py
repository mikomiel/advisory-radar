"""The sensitive-path guard: the paths a person must merge, pinned by a test.

The rule decides whether the merge automation may act without a person, and it used to live as one
``grep -E`` inside a workflow, where nothing could test it. The failure that matters is a false
negative -- a pull request that widens what the automation can reach, auto-merged because the regex
stopped matching. So every guarded path is asserted here, and so are the paths that merely look like
one (``docs/Dockerfile.md``, ``docs/tests/notes.md``).
"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "guard_sensitive_paths.py"


def load_guard():
    spec = importlib.util.spec_from_file_location("guard_sensitive_paths", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load_guard()


def comparison(*paths: str) -> dict:
    return {"files": [{"filename": path} for path in paths]}


def run(*paths: str, declared: int | None = None, payload: str | None = None) -> int:
    body = payload if payload is not None else json.dumps(comparison(*paths))
    return guard.main(["--declared", str(len(paths) if declared is None else declared)], stdin=io.StringIO(body))


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/ci.yml",
        ".github/dependabot.yml",
        "Dockerfile",
        "docker-compose.yml",
        "deploy/podman/advisory-radar.container",
        "pyproject.toml",
        ".gitleaks.toml",
        "tests/test_core.py",
    ],
)
def test_these_paths_need_a_human_merge(path: str):
    assert run(path) == 2


@pytest.mark.parametrize(
    "path",
    [
        "src/advisory_radar/web.py",
        "docs/deployment.md",
        "README.md",
        "uv.lock",  # reach follows pyproject.toml, which is guarded; the lock alone widens nothing
        "docs/Dockerfile.md",  # the anchor is the whole filename, not a substring
        "src/advisory_radar/tests_helper.py",
        "docs/tests/notes.md",  # only a top-level tests/ tree is the suite that decides what ci accepts
        "scripts/check_no_estate_identifiers.py",
    ],
)
def test_these_paths_may_merge_without_a_person(path: str):
    assert run(path) == 0


def test_a_rename_out_of_a_guarded_tree_is_refused():
    document = {"files": [{"filename": "src/moved.py", "previous_filename": "tests/test_moved.py"}]}
    hits, _ = guard.sensitive_paths(document, 1)
    assert hits == ["tests/test_moved.py"]  # the old path is where the guarded content came from


def test_a_rename_into_a_guarded_tree_is_refused():
    document = {"files": [{"filename": "tests/test_moved.py", "previous_filename": "src/moved.py"}]}
    assert run(payload=json.dumps(document)) == 2


def test_a_file_list_shorter_than_the_pull_request_reports_is_refused():
    # compare caps its list (300 files); a shorter list means the guard cannot see everything
    assert run("src/a.py", declared=5) == 2


def test_an_empty_comparison_is_safe():
    assert run() == 0


def test_unusable_input_fails_closed():
    # not a comparison at all: the job must fail, not clear the pull request
    assert run(payload="{not json") == 1
    assert run(payload="[]") == 1
    # a comparison we cannot read is "cannot verify", the same refusal as an incomplete file list
    assert run(payload=json.dumps({"files": [{"filename": 7}]})) == 2
    assert run(payload=json.dumps({"files": "nope"})) == 2


def test_the_policy_is_the_documented_one():
    """A new sensitive path is a policy change: it belongs in the list *and* in the README paragraph."""
    assert guard.SENSITIVE_PATTERNS == (
        r"^\.github/",
        r"^Dockerfile$",
        r"^docker-compose\.yml$",
        r"^deploy/",
        r"^pyproject\.toml$",
        r"^\.gitleaks\.toml$",
        r"^tests/",
    )
