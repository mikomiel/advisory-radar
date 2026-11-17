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

#: The files that override what the checks run. The first is root-only on purpose (pytest, tox, uv, coverage and the
#: build backend read one file at the root; pytest 9 reads four names of its own besides pyproject.toml, and any of
#: them wins over it); a conftest.py counts at any depth; ruff applies the closest configuration file to each file,
#: so a ruff.toml or a pyproject.toml below the root silences the subtree it sits in.
CHECK_CONFIGURATION = (
    r"^(\.?ruff\.toml|\.?pytest\.(ini|toml)|tox\.ini|setup\.cfg|uv\.toml|\.coveragerc|noxfile\.py"
    r"|hatch\.toml|hatch_build\.py|sitecustomize\.py)$"
)
CONFTEST = r"(^|/)conftest\.py$"
NESTED_RUFF_CONFIGURATION = r"/(\.?ruff\.toml|pyproject\.toml)$"
#: gitleaks drops every finding that a .gitleaksignore lists, so adding one hides a secret from the scan.
GITLEAKS_IGNORE = r"(^|/)\.gitleaksignore$"


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
        # the lock decides what `uv sync --frozen` installs; the pin and the ignore list change the runtime
        "uv.lock",
        ".python-version",
        ".dockerignore",
        ".gitleaks.toml",
        # the ignore list hides findings from the secret scan, at the scan root and, to stay on the safe side, anywhere
        ".gitleaksignore",
        "src/.gitleaksignore",
        # the release files decide the tag a release carries and the version it starts from
        "release-please-config.json",
        ".release-please-manifest.json",
        # the agent instruction files at the root are the rules a coding agent follows in this repository
        "AGENTS.md",
        "CLAUDE.md",
        "tests/test_core.py",
        # the workflows execute scripts/ on the default branch: the guard and the approval rule are policy
        "scripts/guard_sensitive_paths.py",
        "scripts/review_state.py",
        "scripts/review_gate_plan.py",
        "scripts/check_no_estate_identifiers.py",
        # files that decide what the checks run: a root conftest.py can skip every test, a ruff.toml can select no
        # rule, and none of them lives under tests/
        "conftest.py",
        "ruff.toml",
        ".ruff.toml",
        "pytest.ini",
        # pytest 9 reads these three as well, and each one takes precedence over the [tool.pytest.ini_options] table
        # of pyproject.toml: `addopts = "--co"` in one of them makes `pytest` pass without running a test
        ".pytest.ini",
        "pytest.toml",
        ".pytest.toml",
        "tox.ini",
        "setup.cfg",
        "uv.toml",
        ".coveragerc",
        "noxfile.py",
        # the build backend merges hatch.toml over [tool.hatch], and runs hatch_build.py as a build hook: both run
        # (or change what ships) during `uv sync` in CI and during the image build
        "hatch.toml",
        "hatch_build.py",
        "sitecustomize.py",
        # a conftest.py counts at any depth; ruff applies the closest config file to each file, so a ruff
        # configuration below the root silences the whole subtree it sits in
        "src/conftest.py",
        "src/advisory_radar/conftest.py",
        "src/advisory_radar/ruff.toml",
        "src/advisory_radar/.ruff.toml",
        "src/advisory_radar/pyproject.toml",
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
        "docs/Dockerfile.md",  # the anchor is the whole filename, not a substring
        # the new anchors are exact files too: neither a parent directory, an extension nor a suffix qualifies
        "docs/uv.lock",
        "uv.lock.bak",
        "docs/.python-version",
        ".dockerignore.example",
        "docs/release-please-config.json",  # release policy lives at the root, not under docs/
        "release-please-config.json.bak",
        # the agent instruction files are exact root files too: a copy in a subdirectory or a suffixed name is ordinary
        "docs/AGENTS.md",
        "src/CLAUDE.md",
        "AGENTS.md.bak",
        "CLAUDE.md.bak",
        "src/advisory_radar/tests_helper.py",
        "docs/tests/notes.md",  # only a top-level tests/ tree is the suite that decides what ci accepts
        # the check-configuration names are whole filenames, not substrings or suffixes
        "docs/ruff.toml.md",
        "ruff.toml.bak",
        "docs/pytest.ini.example",
        ".pytest.ini.bak",
        "docs/pytest.toml.md",
        "noxfile.py.bak",
        "hatch.toml.bak",
        "hatch_build.py.bak",
        "docs/hatch.toml.md",
        ".gitleaksignore.bak",  # the ignore list is a whole filename, not a prefix or a suffix
        "docs/not.gitleaksignore",
        "docs/gitleaksignore.md",
        "src/advisory_radar/conftest_helpers.py",
        "src/advisory_radar/my_conftest.py",
        "src/advisory_radar/pyproject.toml.md",
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
    """A new sensitive path is a policy change: it belongs in the list *and* in the docs paragraph."""
    assert guard.SENSITIVE_PATTERNS == (
        r"^\.github/",
        r"^Dockerfile$",
        r"^docker-compose\.yml$",
        r"^deploy/",
        r"^pyproject\.toml$",
        r"^uv\.lock$",
        r"^\.python-version$",
        r"^\.dockerignore$",
        r"^\.gitleaks\.toml$",
        GITLEAKS_IGNORE,
        r"^release-please-config\.json$",
        r"^\.release-please-manifest\.json$",
        r"^AGENTS\.md$",
        r"^CLAUDE\.md$",
        r"^tests/",
        r"^scripts/",
        CHECK_CONFIGURATION,
        CONFTEST,
        NESTED_RUFF_CONFIGURATION,
    )
    # The docstring promises the docs page too, so check it. A pattern that reads as one literal path once its anchors
    # and regex escapes are gone is checked as that name. The four that name several files, or depend on where a file
    # sits, are listed with what the paragraph must carry: every name as a code span of its own (a bare substring
    # would let `.pytest.ini` stand in for `pytest.ini`) and, for the rules about place, a phrase that appears once in
    # the paragraph. Without the phrase, deleting the sentence of a nested rule would still pass on names that the
    # rest of the paragraph carries.
    grouped = {
        CHECK_CONFIGURATION: (
            [
                "ruff.toml",
                ".ruff.toml",
                "pytest.ini",
                ".pytest.ini",
                "pytest.toml",
                ".pytest.toml",
                "tox.ini",
                "setup.cfg",
                "uv.toml",
                ".coveragerc",
                "noxfile.py",
                "hatch.toml",
                "hatch_build.py",
                "sitecustomize.py",
            ],
            ["the root files"],
        ),
        CONFTEST: (["conftest.py"], ["at any depth"]),
        NESTED_RUFF_CONFIGURATION: (["ruff.toml", ".ruff.toml", "pyproject.toml"], ["below the root"]),
        GITLEAKS_IGNORE: ([".gitleaksignore"], ["in any directory"]),
    }
    docs = (Path(__file__).resolve().parents[1] / "docs" / "review-and-merge.md").read_text()
    paragraph = docs.split("**A person merges anything that widens", 1)[1].split("\n\n", 1)[0]
    for pattern in guard.SENSITIVE_PATTERNS:
        names, phrases = grouped.get(pattern) or ([pattern.strip("^$").replace("\\", "")], [])
        for name in names:
            assert f"`{name}`" in paragraph, f"{pattern} is guarded but `{name}` is not documented"
        for phrase in phrases:
            assert paragraph.count(phrase) == 1, f"{pattern} is guarded but the paragraph does not say {phrase!r} once"
