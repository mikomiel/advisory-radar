#!/usr/bin/env python3
"""Delete the head branch of a pull request the automerge just merged.

``delete_branch_on_merge`` is a repository setting, and a merge made through the API did not honour it -- the
branches of automerged pull requests #36 and #43 survived with the setting on -- so the workflow deletes the
head ref itself.

The branch is a mutable ref: a push between the merge and this cleanup would be lost by a plain delete. The
delete is therefore a ``git push --force-with-lease=refs/heads/<branch>:<merged head>``, which the remote checks
before removing the ref, so a branch that no longer points at the commit that was merged is left alone.

A pull request from a fork keeps its head in another repository, and its ``headRefName`` can name an unrelated
branch of this repository, so a cross-repository pull request is never deleted.

Exit codes: 0 the branch is gone; 2 refused (a fork, or a name this repository would not create); 1 the delete
failed (the branch moved, or the transport failed). The workflow treats every non-zero exit as "left in place"
and warns: the merge it followed has already happened.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

#: A normal branch name. This repository creates these; anything else is not the ref the merge used, and a
#: delete is not reversible.
_WELL_FORMED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def refusal(branch: str, head: str, cross_repository: str) -> str | None:
    """Why this branch must not be deleted, or None when it is the ref the merge just used."""
    if cross_repository != "false":
        return "the pull request's head branch is in another repository"
    if not _SHA.fullmatch(head):
        return "the merged head is not a full commit sha"
    if not _WELL_FORMED.fullmatch(branch) or ".." in branch or "//" in branch:
        return "the head branch name is not one this repository would create"
    if branch.endswith(("/", ".", ".lock")):
        return "the head branch name is not one this repository would create"
    return None


def _auth_environment(environment: dict[str, str]) -> dict[str, str]:
    """The GitHub token as a per-host header in the environment, never in a command line.

    A command line is visible to every process on the runner, and the token has no business there.
    """
    token = environment.get("GH_TOKEN", "")
    if not token:
        return dict(environment)
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return {
        **environment,
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
    }


def delete(
    branch: str,
    head: str,
    *,
    repo: str,
    url: str | None = None,
    cwd: str | Path = ".",
    environment: dict[str, str] | None = None,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> int:
    """Delete ``branch`` only while it still points at ``head``; 0 when it is gone."""
    environment = dict(os.environ if environment is None else environment)
    target = url or f"https://github.com/{repo}.git"
    completed = run(
        ["git", "push", f"--force-with-lease=refs/heads/{branch}:{head}", target, f":refs/heads/{branch}"],
        cwd=str(cwd),
        env=_auth_environment(environment),
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return 0
    detail = (completed.stderr or completed.stdout or "").strip().splitlines()
    reason = detail[-1] if detail else f"git exited {completed.returncode}"
    print(f"could not delete {branch}: {reason}", file=sys.stderr)
    return 1


def main(argv: Sequence[str] | None = None, *, run=subprocess.run, url: str | None = None) -> int:
    parser = argparse.ArgumentParser(prog="delete-merged-branch")
    parser.add_argument("--repo", required=True, help="owner/name the merged pull request belongs to")
    parser.add_argument("--branch", required=True, help="the head branch the pull request reports")
    parser.add_argument("--head", required=True, help="the commit that was merged")
    parser.add_argument("--cross-repository", required=True, help="the pull request's isCrossRepository flag")
    args = parser.parse_args(argv)
    reason = refusal(args.branch, args.head, args.cross_repository)
    if reason is not None:
        print(f"not deleting {args.branch!r}: {reason}", file=sys.stderr)
        return 2
    code = delete(args.branch, args.head, repo=args.repo, url=url, run=run)
    if code == 0:
        print(f"deleted {args.branch}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
