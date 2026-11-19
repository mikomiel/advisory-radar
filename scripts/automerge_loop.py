#!/usr/bin/env python3
"""The merge loop of ``.github/workflows/automerge.yml``: merge each approved pull request whose checks are green.

The workflow runs this script, and nothing else, as the merge step. It lists the open pull requests against ``main``
and takes them in the order ``gh`` lists them. A pull request that fails a rule is skipped with its reason and the loop
goes on, so one pull request that is not ready never holds back the next. The rules are applied in this order, and a
rule that an earlier one settled is not reached:

1. GitHub reports the pull request mergeable.
2. ``review_state.py`` finds an approval at the exact head, from the configured reviewer or a maintainer. That rule
   has one owner, which ``review-gate.yml`` shares: two copies are how a status says "approved" while the merge
   refuses, or the reverse. The reviews are read over REST, because ``user.type`` tells an App bot from a human
   account of the same name and ``user.login`` keeps the ``[bot]`` suffix that GraphQL drops.
3. The required check is ``SUCCESS`` on that head, and every check is finished and acceptable, a pending one
   included, so that no check can start failing after the merge. GitHub bounds the rollup at 100 contexts, and at
   that size an omitted check could be the failing one, so a rollup that long is refused.
4. ``guard_sensitive_paths.py`` finds no path that a person must merge. Its input is the comparison of the two
   commits, never the pull request's own file list: that one follows the branch, and a head that moved A -> B -> A
   could show B's harmless files while A merges.
5. A second read shows the base and the head of the first. The guard compared ``base...head``, and a base that has
   advanced since no longer fits that comparison. Branch protection, which is strict, is the server-side half.

``gh pr merge`` then merges, with ``--match-head-commit`` so that GitHub refuses a head that moved instead of merging
a commit that the reviewer never saw. A standing auto-merge order is not used, because a later push would move the
head past the review that was just checked.

The ``merged`` step output is the one fact the ``release`` job needs, and the order of its writes is the contract:

* ``merged=false`` is written before the queue is read, so that a run that merges nothing, or fails early, reports it.
* ``merged=true`` is written the moment ``gh pr merge`` succeeds, before the branch cleanup and the comment. A later
  candidate's failed read, a failed cleanup and a failed comment can therefore neither lose a merge that landed nor
  invent one. The ``release`` job runs on ``!cancelled()`` and that output alone, so a run that ends red after a merge
  still releases.

``tests/test_automerge_loop.py`` runs this script against a stub ``gh`` and pins that order.

Exit codes: 0 when the queue was worked through, whatever was skipped, refused or left in place; 1 when a setting is
missing or empty, or a read failed or returned what cannot be used. The reads that end the run are the queue, a pull
request's data, its reviews and the second read of its head and base. A failed read never looks like an empty queue,
and a merge that landed before it stays reported. The comparison that the guard reads is the exception: one that
cannot be read is a skip, because the guard refuses what it cannot parse and the pull request waits for a person.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

#: The scripts that this one calls sit beside it, whatever the working directory is.
SCRIPTS = Path(__file__).resolve().parent
#: The environment variable behind each setting. ``GH_TOKEN`` is read by ``gh`` and by the branch cleanup. The workflow
#: provides all of them, and ``tests/test_workflow_pins.py`` pins that.
SETTINGS = {
    "repo": "REPO",
    "reviewer": "REVIEWER_LOGIN",
    "reviewer_type": "REVIEWER_TYPE",
    "required_check": "REQUIRED_CHECK",
}
#: GitHub bounds ``statusCheckRollup`` at this many contexts.
ROLLUP_LIMIT = 100
#: What a finished check may say and still not stand in the way of a merge.
ACCEPTABLE = ("SUCCESS", "NEUTRAL", "SKIPPED")
#: What ``gh pr view`` is asked for, as the shell asked for it. Its ``reviews`` are not used: the approval rule reads
#: them over REST.
PULL_REQUEST_FIELDS = (
    "headRefOid,baseRefOid,mergeable,reviews,statusCheckRollup,changedFiles,headRefName,isCrossRepository"
)


class Skip(Exception):
    """A pull request that is left for a later run; the message says why."""


class Failure(Exception):
    """The run cannot go on: a setting is missing, or a read failed or returned what cannot be used."""


class Settings(NamedTuple):
    output: Path
    repo: str
    reviewer: str
    reviewer_type: str
    required_check: str


def say(message: str) -> None:
    """Write one log line at once. The programs that this one runs write to the same log, so the order matters."""
    print(message, flush=True)


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise Failure(f"{name} is not set")
    return value


def write_output(path: Path, line: str) -> None:
    """Append one line to the step's output file and close it, so that the line is in the file when this returns."""
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{line}\n")


def run(command: Sequence[str], *, stdin: str = "", capture: bool = False) -> subprocess.CompletedProcess[str]:
    """Run a program with this step's environment, and without a shell.

    Its stderr goes to the log, and so does its stdout unless ``capture`` is set.
    """
    sys.stdout.flush()
    return subprocess.run(
        command, input=stdin, stdout=subprocess.PIPE if capture else None, encoding="utf-8", check=False
    )


def read(command: Sequence[str], what: str) -> str:
    """The stdout of a read that has to succeed. A failed read ends the run and is never taken for an empty answer."""
    done = run(command, capture=True)
    if done.returncode != 0:
        raise Failure(f"cannot {what}")
    return done.stdout


def decode(text: str, what: str) -> object:
    try:
        return json.loads(text)
    except ValueError as exc:
        raise Failure(f"cannot {what}: the answer is not JSON ({exc})") from exc


def pull_request(settings: Settings, number: int, fields: str, what: str) -> dict:
    document = decode(read(["gh", "pr", "view", str(number), "--repo", settings.repo, "--json", fields], what), what)
    if not isinstance(document, dict):
        raise Failure(f"cannot {what}: the answer is not an object")
    return document


def commit(meta: dict, key: str, number: int) -> str:
    value = meta.get(key)
    if not isinstance(value, str) or not value:
        raise Failure(f"cannot read pull request #{number}: it has no {key}")
    return value


def open_pull_requests(settings: Settings) -> list[int]:
    """The open pull requests against ``main`` that are not drafts, in the order ``gh`` lists them.

    ``gh`` follows its pages up to the limit, which is far above any realistic queue. The selection is deliberately
    narrow: it leaves out drafts and decides nothing else. The approval rule has one owner, ``review_state.py``, so a
    filter on GitHub's ``reviewDecision`` would be a second copy of it, and a wrong one: branch protection requires
    no approving review, GitHub then reports no ``reviewDecision`` at all, and such a filter would match nothing.
    """
    what = "enumerate open pull requests"
    command = ["gh", "pr", "list", "--repo", settings.repo, "--state", "open", "--base", "main", "--limit", "1000"]
    listing = decode(read([*command, "--json", "number,mergeable,isDraft"], what), what)
    if not isinstance(listing, list) or not all(isinstance(entry, dict) for entry in listing):
        raise Failure(f"cannot {what}: the answer is not a list of pull requests")
    numbers = [entry.get("number") for entry in listing if entry.get("isDraft") is False]
    if not all(isinstance(number, int) and not isinstance(number, bool) for number in numbers):
        raise Failure(f"cannot {what}: a pull request has no number")
    return numbers


def reviews(settings: Settings, number: int) -> list:
    """Every review of the pull request, as one list.

    ``gh api --paginate`` prints one JSON array per page with nothing between them. Judging each page alone would
    give several answers, and an eligible approval on a later page would look like a mismatch.
    """
    what = f"read the reviews of pull request #{number}"
    endpoint = f"repos/{settings.repo}/pulls/{number}/reviews?per_page=100"
    rest = read(["gh", "api", "--paginate", endpoint], what).lstrip()
    found: list = []
    while rest:
        try:
            page, end = json.JSONDecoder().raw_decode(rest)
        except ValueError as exc:
            raise Failure(f"cannot {what}: the answer is not JSON ({exc})") from exc
        if not isinstance(page, list):
            raise Failure(f"cannot {what}: a page is not a list")
        found.extend(page)
        rest = rest[end:].lstrip()
    return found


def require_mergeable(meta: dict) -> None:
    mergeable = meta.get("mergeable")
    if mergeable != "MERGEABLE":
        raise Skip(f"mergeable={mergeable} (retry on the next trigger)")


def require_approval(settings: Settings, number: int, head: str) -> None:
    command = [sys.executable, str(SCRIPTS / "review_state.py")]
    command += ["--reviewer", settings.reviewer, "--type", settings.reviewer_type, "--head", head]
    done = run(command, stdin=json.dumps(reviews(settings, number)), capture=True)
    if done.returncode != 0:
        # The script prints "state<TAB>description"; the skip line carries the description.
        line = done.stdout.rstrip("\n")
        before, tab, after = line.partition("\t")
        raise Skip(after if tab else before)


def verdict(context: dict) -> object:
    """What one entry of the rollup says: a check run reports ``conclusion``, a legacy commit status ``state``.

    Only a missing value, ``null`` and ``false`` fall through to the next, as in the shell's ``a // b // c``. An
    unfinished check run has an empty conclusion, which a ``state`` that it does not have could not rescue.
    """
    for key in ("conclusion", "state"):
        value = context.get(key)
        if value is not None and value is not False:
            return value
    return "PENDING"


def require_green(settings: Settings, meta: dict, head: str) -> None:
    rollup = meta.get("statusCheckRollup")
    if not isinstance(rollup, list) or not all(isinstance(context, dict) for context in rollup):
        raise Failure("cannot read the checks of a pull request: the rollup is not a list of checks")
    # A positive assertion: the required check answered SUCCESS for this head. Only a check run has a name.
    required_check = settings.required_check
    if not any(context.get("name") == required_check and context.get("conclusion") == "SUCCESS" for context in rollup):
        raise Skip(f"{required_check} is not SUCCESS on {head}")
    if len(rollup) >= ROLLUP_LIMIT:
        raise Skip(f"{len(rollup)} check contexts - the rollup may be truncated, cannot verify completeness")
    not_green = [context for context in rollup if verdict(context) not in ACCEPTABLE]
    if not_green:
        raise Skip(f"{len(not_green)} check(s) not green (pending, failing or errored)")


def require_no_sensitive_path(settings: Settings, meta: dict, base: str, head: str) -> None:
    """Leave a change to what the automation can reach to a person: the workflows, this script, the artifact.

    The comparison carries its file list on its first page only, so it is one request, and the guard refuses a list
    that it cannot trust. A comparison that cannot be read goes to the guard as it is, and the guard refuses what it
    cannot parse, so the pull request waits for a person.
    """
    comparison = run(["gh", "api", f"repos/{settings.repo}/compare/{base}...{head}"], capture=True)
    command = [sys.executable, str(SCRIPTS / "guard_sensitive_paths.py"), "--declared"]
    guard = run([*command, str(meta.get("changedFiles") or 0)], stdin=comparison.stdout)
    if comparison.returncode != 0 or guard.returncode != 0:
        raise Skip("a person merges this one (the guard's reason is on the line above)")


def require_unmoved(settings: Settings, number: int, base: str, head: str) -> None:
    current = pull_request(settings, number, "headRefOid,baseRefOid", f"read pull request #{number} again")
    if current.get("baseRefOid") != base or current.get("headRefOid") != head:
        raise Skip("base or head moved during the check; a fresh run decides")


def admit(settings: Settings, number: int) -> tuple[dict, str]:
    """Apply the rules in order: the pull request's data and its head, or ``Skip`` with the reason it waits."""
    meta = pull_request(settings, number, PULL_REQUEST_FIELDS, f"read pull request #{number}")
    head = commit(meta, "headRefOid", number)
    require_mergeable(meta)
    require_approval(settings, number, head)
    require_green(settings, meta, head)
    base = commit(meta, "baseRefOid", number)
    require_no_sensitive_path(settings, meta, base, head)
    require_unmoved(settings, number, base, head)
    return meta, head


def delete_head_branch(settings: Settings, number: int, meta: dict, head: str) -> None:
    """Delete the merged head branch with the tested script, and warn when it stays.

    The repository setting did not cover a merge made through the API. The script's delete is a lease on this exact
    head, so a push that landed after the merge is never removed, and it refuses a fork's branch. The merge has
    already happened, so a refusal or a failed delete is a warning and nothing more.
    """
    branch = meta.get("headRefName")
    branch = branch if isinstance(branch, str) else ""
    cross_repository = "false" if meta.get("isCrossRepository") is False else "true"
    command = [sys.executable, str(SCRIPTS / "delete_merged_branch.py"), "--repo", settings.repo]
    command += ["--branch", branch, "--head", head, "--cross-repository", cross_repository]
    if run(command).returncode == 0:
        say(f"deleted head branch {branch}")
    else:
        say(f"::warning::merged #{number}; its head branch was left in place (the reason is above)")


def merge(settings: Settings, number: int, meta: dict, head: str) -> None:
    """Merge one admitted pull request, and write ``merged=true`` before anything that follows it can fail."""
    # ``--delete-branch`` stays out: gh deletes the local branch with it, and fails after the merge when that branch
    # is not checked out on the runner. The branch is deleted below.
    command = ["gh", "pr", "merge", str(number), "--repo", settings.repo, "--squash", "--match-head-commit", head]
    if run(command).returncode != 0:
        say(f"skip #{number}: GitHub refused the merge (protection, or a check changed)")
        return
    write_output(settings.output, "merged=true")
    say(f"merged #{number} at {head} (approval by {settings.reviewer})")
    delete_head_branch(settings, number, meta, head)
    # The comment is a courtesy: when it fails, nothing else does.
    body = f"Merged by automerge: {settings.required_check} green and approved at `{head}` by {settings.reviewer}."
    run(["gh", "pr", "comment", str(number), "--repo", settings.repo, "--body", body])


def main() -> int:
    try:
        output = Path(required("GITHUB_OUTPUT"))
        # The default comes before anything that can fail, and a merge overwrites it at once.
        write_output(output, "merged=false")
        settings = Settings(output, **{field: required(name) for field, name in SETTINGS.items()})
        queue = open_pull_requests(settings)
        if not queue:
            say("no approved pull requests to consider")
            return 0
        for number in queue:
            try:
                meta, head = admit(settings, number)
            except Skip as skip:
                say(f"skip #{number}: {skip}")
                continue
            merge(settings, number, meta, head)
    except Failure as failure:
        say(f"::error::{failure}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
