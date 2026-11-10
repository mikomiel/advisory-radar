"""The cleanup that removes a merged head branch, and the ways it must refuse.

The automerge deletes the branch it merged, because the repository setting did not cover an API merge. Two
properties are safety, not convenience: a fork's head is never touched (its name can match an unrelated branch
of this repository), and a branch that no longer points at the merged head is not deleted (that would remove a
commit nobody merged). The lease is git's own, so the delete is exercised against a real local bare repository.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "delete_merged_branch.py"
HEAD = "a" * 40


def load_rule():
    spec = importlib.util.spec_from_file_location("delete_merged_branch", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rule = load_rule()


def test_a_normal_branch_of_this_repository_is_deletable():
    assert rule.refusal("feature/readme", HEAD, "false") is None
    assert rule.refusal("release/1.2", HEAD, "false") is None


@pytest.mark.parametrize(
    "branch",
    # "refs/heads/other" is deliberately not here: it is a well-formed branch name, and the refspec would
    # address refs/heads/refs/heads/other, not the default branch.
    ["", "-x", "a b", "a..b", "a//b", "x.lock", "x.", "caf\u00e9", "feature/\u001b[2J"],
)
def test_a_name_this_repository_would_not_create_is_refused(branch):
    assert rule.refusal(branch, HEAD, "false") is not None


def test_a_fork_head_is_never_deleted():
    assert rule.refusal("feature/x", HEAD, "true") is not None


def test_a_head_that_is_not_a_full_commit_sha_is_refused():
    assert rule.refusal("feature/x", "abc", "false") is not None
    assert rule.refusal("feature/x", "A" * 40, "false") is not None  # the API reports lowercase


def test_a_refused_branch_never_reaches_git(capsys):
    calls: list[list[str]] = []

    def run(*args, **kwargs):
        calls.append(list(args[0]))
        raise AssertionError("a refused branch must not reach git")

    code = rule.main(
        ["--repo", "owner/name", "--branch", "feature/x", "--head", HEAD, "--cross-repository", "true"], run=run
    )
    assert code == 2
    assert calls == []
    assert "another repository" in capsys.readouterr().err


def test_a_failed_delete_returns_one_and_reports_the_reason(capsys):
    class Result:
        returncode = 1
        stderr = " ! [rejected]        (delete) -> feature/x (stale info)\n"
        stdout = ""

    code = rule.main(
        ["--repo", "owner/name", "--branch", "feature/x", "--head", HEAD, "--cross-repository", "false"],
        run=lambda *args, **kwargs: Result(),
    )
    assert code == 1
    assert "stale info" in capsys.readouterr().err


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _commit(work: Path, message: str) -> str:
    _git(
        "-c", "user.email=test@example.net", "-c", "user.name=test", "commit", "--allow-empty", "-m", message, cwd=work
    )
    return _git("rev-parse", "HEAD", cwd=work).stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    remote = tmp_path / "remote.git"
    work = tmp_path / "work"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    subprocess.run(["git", "init", "-q", str(work)], check=True)
    return remote, work


def _heads(remote: Path, work: Path) -> str:
    return _git("ls-remote", "--heads", str(remote), "refs/heads/feature/x", cwd=work).stdout


def test_the_merged_branch_is_deleted(tmp_path):
    remote, work = _repository(tmp_path)
    merged = _commit(work, "one")
    _git("push", "-q", str(remote), f"{merged}:refs/heads/feature/x", cwd=work)
    assert rule.delete("feature/x", merged, repo="owner/name", url=str(remote), cwd=work) == 0
    assert _heads(remote, work) == ""


def test_a_branch_that_moved_after_the_merge_is_not_deleted(tmp_path):
    remote, work = _repository(tmp_path)
    merged = _commit(work, "one")
    _git("push", "-q", str(remote), f"{merged}:refs/heads/feature/x", cwd=work)
    moved = _commit(work, "two")  # a push lands on the branch after the merge
    _git("push", "-q", str(remote), f"{moved}:refs/heads/feature/x", cwd=work)
    assert rule.delete("feature/x", merged, repo="owner/name", url=str(remote), cwd=work) == 1
    heads = _heads(remote, work)
    assert heads.split("\t")[0].strip() == moved, "the branch that received an unmerged commit must still be there"
