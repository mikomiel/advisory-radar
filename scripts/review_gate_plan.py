#!/usr/bin/env python3
"""Turn a snapshot of open pull requests into one status decision per head commit.

The gate publishes a *commit status*, and a status is keyed by (sha, context) -- not by pull request. Two
open pull requests can share a head commit (a branch and a copy of it), and then a single status must speak
for both. Publishing whichever pull request was processed last would let an approved one turn a
changes-requested one green, so this script aggregates conservatively: the worst verdict among the pull
requests sharing a head wins, and the description names them all.

Input: a JSON array of ``{number, head, base, draft, author, changed, count_head, count_base, branch,
head_repo, reviews, files}`` on stdin -- one entry per open pull request, with the reviews exactly as the API
returned them, ``changed`` the pull request's own changed-file count, ``files`` the entries of the immutable
``compare`` (``filename`` and ``previous_filename``), and ``branch``/``head_repo`` the head ref and its
repository as the list endpoint reported them. Flattening renames is this script's job, so that it is tested.

Two entries may be published as ``success`` without an independent approval, and only by their exact shape: a
Dependabot update that touches nothing but dependency manifests, and the release pull request release-please
generates from merged commits -- recognised by its branch, author, the four files it manages *and* a patch that is
only the version bump those files carry. Neither can be auto-merged: the merge workflow still asks
:mod:`review_state` for an eligible approval at the exact head, and both always change a path
``guard_sensitive_paths.py`` reserves for a person.

Output: one line per head, ``head<TAB>state<TAB>description``, where state is a GitHub status state. The
caller publishes these; it decides nothing.

The approval rule itself lives in :mod:`review_state` and is imported, not copied -- the gate and the merge
workflow must not be able to disagree about what an approval is.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# The scripts directory is not a package: import the rule by path so the merge workflow and this gate share
# one implementation instead of two that can drift.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import review_state  # noqa: E402

#: Higher blocks more: a shared head is only green when every pull request on it is green.
SEVERITY = {"success": 1, "pending": 2, "failure": 3}
MAX_DESCRIPTION = 140
#: Authors whose pull requests do not need an App review, and only while every changed path stays inside
#: DEPENDENCY_PATHS. Dependabot's updates are mechanical and `ci` (the image build included) still has to pass.
#: The login is GitHub's, not the pull request's, so a patch cannot claim it. A pull request the exemption
#: covers is still not taken by automerge.yml: the merge asks ``review_state.py`` for an eligible approval at
#: the exact head, and an exempt pull request has none. GitHub's own auto-merge switch is separate: while
#: `allow_auto_merge` is on, a write-access user can have GitHub merge an exempt bump once its checks are green.
EXEMPT_AUTHORS = frozenset({"app/dependabot", "dependabot[bot]"})
#: Paths a dependency update may touch for the exemption to apply, checked rather than assumed. Files match
#: exactly -- ``Dockerfile/evil.py`` is somebody deleting the manifest and adding a directory of source, not a
#: dependency update -- and only the workflow tree matches as a prefix.
DEPENDENCY_FILES = frozenset({"pyproject.toml", "uv.lock", "Dockerfile", "docker-compose.yml"})
DEPENDENCY_DIRECTORIES = (".github/workflows/",)
#: The generated release pull request, recognised by its exact shape: release-please names the branch after the
#: package, opens it with the token owner's account, and only ever changes the release-managed files. Every fact
#: together, because any one alone is too broad -- a fixed branch name would let a maintainer reuse it, an author
#: would exempt anything that account opens, and those paths alone are an ordinary changelog edit. No authoring
#: session exists to request the App review, and the human merge of this pull request is the release decision.
#: Update them together if the token owner, package name or release-managed files change; a drift fails closed,
#: because the pull request then needs the normal review. The branch name is the one release-please produced for
#: mikomiel/ci-burst at the same pinned action version and the same configuration shape.
RELEASE_BRANCH = "release-please--branches--main--components--advisory-radar"
RELEASE_AUTHOR = "mikomiel"
RELEASE_REPOSITORY = "mikomiel/advisory-radar"
#: The one line a generated release writes in each file that carries the version, matched against the patch's
#: added *and* removed line. The identity facts say who opened the pull request; only the patch says what it
#: changed inside a path the release manages. A dependency added beside the version, an import on the same line,
#: two changed lines or no patch at all is not the generator's output and keeps the review requirement, and the
#: captured version must agree across all three files.
RELEASE_VERSION_FILES = {
    ".release-please-manifest.json": r'\s*"\.": "(\d+\.\d+\.\d+)"',
    "pyproject.toml": r'version = "(\d+\.\d+\.\d+)"',
    "src/advisory_radar/__init__.py": r'__version__ = "(\d+\.\d+\.\d+)"',
}
#: The changelog must gain its generated section. Its prose is documentation, not something this automation can
#: reach, so "present, with additions" is all that is asked. Every one of these four files must appear, and no
#: other path may.
RELEASE_CHANGELOG = "CHANGELOG.md"
RELEASE_PATHS = frozenset(RELEASE_VERSION_FILES) | {RELEASE_CHANGELOG}


def _changed_names(entry: dict) -> list[str]:
    """Every path the comparison names, both sides of a rename; empty when the list is unusable."""
    files = entry.get("files")
    if not isinstance(files, list) or not files:
        return []
    names: list[str] = []
    for item in files:
        if not isinstance(item, dict):
            return []
        name = item.get("filename")
        if not isinstance(name, str) or not name:
            return []
        names.append(name)
        previous = item.get("previous_filename")
        if isinstance(previous, str) and previous:
            names.append(previous)
    return names


def _dependency_only(names: list[str]) -> bool:
    """Whether every changed path is a dependency manifest the exemption may cover."""
    if not names:
        return False
    for name in names:
        if name in DEPENDENCY_FILES:
            continue
        if any(name.startswith(directory) for directory in DEPENDENCY_DIRECTORIES):
            continue
        return False
    return True


def _complete(entry: dict) -> bool:
    """Whether the file list provably covers the whole change: no shorter than the declared count.

    ``compare`` caps its list at 300 files and the count arrives in a different response, so the count proves the
    list complete only for the commits it describes. A head that moved in between would pair a pinned, possibly
    truncated list with the newer, smaller count -- and the truncated list would then pass the short-list check
    that exists to fail it. An unreadable list, a count naming another commit pair, or a short list is not
    complete, and both exemptions fail closed on it.
    """
    head = entry.get("head")
    base = entry.get("base")
    if not isinstance(head, str) or not isinstance(base, str) or not base:
        return False
    if entry.get("count_head") != head or entry.get("count_base") != base:
        return False
    files = entry.get("files")
    declared = entry.get("changed")
    if not isinstance(files, list) or not isinstance(declared, int) or declared < 1:
        return False
    return len(files) >= declared


def exempt(entry: dict, author: str, exempt_authors: frozenset[str]) -> bool:
    """Whether the dependency exemption covers this entry: an exempt author, a complete, manifest-only path list.

    Fail-closed in four places: an unreadable list is not exempt, a list shorter than the pull request's own
    changed-file count is not exempt (``compare`` caps its list at 300, so a source file could hide past the
    cap), a count that does not describe the same commit pair as the comparison is not exempt, and an empty
    list is not exempt.
    """
    return author in exempt_authors and _complete(entry) and _dependency_only(_changed_names(entry))


def release_candidate(entry: dict) -> bool:
    """The generated release pull request's identity, before its changed paths are checked."""
    if entry.get("draft") is not False:
        return False
    return (
        entry.get("branch") == RELEASE_BRANCH
        and entry.get("head_repo") == RELEASE_REPOSITORY
        and entry.get("author") == RELEASE_AUTHOR
    )


def _changed_file(entry: dict, path: str) -> dict | None:
    """The comparison's entry for one path, or None when the list does not carry it."""
    files = entry.get("files")
    for item in files if isinstance(files, list) else []:
        if isinstance(item, dict) and item.get("filename") == path:
            return item
    return None


def _bumped_version(entry: dict, path: str, pattern: str) -> str | None:
    """The version one version-carrying file writes, or None when its diff is not exactly that one line replaced.

    The identity facts only say who opened the pull request; the patch is what proves the change inside an allowed
    path is the generator's. A generated release replaces one line per file -- ``-version = "0.1.0"`` becomes
    ``+version = "0.2.0"`` -- so an added dependency (two added lines), an import appended to the version line (the
    added line no longer matches the pattern), a file left untouched, or a patch the compare omitted all fail here.
    """
    item = _changed_file(entry, path)
    if item is None or item.get("additions") != 1 or item.get("deletions") != 1:
        return None
    patch = item.get("patch")
    if not isinstance(patch, str):
        return None
    added: list[str] = []
    removed: list[str] = []
    # Split on LF alone. ``str.splitlines`` also breaks on a bare carriage return, and a Python parser reads that
    # as a newline: ``+__version__ = "0.2.0"\rprint(...)`` would then look like the version line plus a fragment
    # this loop ignores, while the file really gained a statement. The whole content line must be validated, so
    # the separator is the one git writes.
    for line in patch.split("\n"):
        if line.startswith("--- ") or line.startswith("+++ "):
            continue  # the file headers, which carry a path after the marker
        if line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("-"):
            removed.append(line[1:])
    if len(added) != 1 or len(removed) != 1:
        return None
    new = re.fullmatch(pattern, added[0])
    old = re.fullmatch(pattern, removed[0])
    if new is None or old is None or new.group(1) == old.group(1):
        return None
    return new.group(1)


def release_scope(entry: dict) -> bool:
    """Whether this entry is the generator's output: its identity, all four release files, and one version bump.

    Fails closed everywhere: an unreadable or incomplete file list, a path outside the release-managed set, a
    missing release file, a changelog that gained nothing, a version file whose diff is not the one line, versions
    that disagree, or a patch the compare did not carry.
    """
    if not release_candidate(entry) or not _complete(entry):
        return False
    if set(_changed_names(entry)) != RELEASE_PATHS:
        return False
    changelog = _changed_file(entry, RELEASE_CHANGELOG)
    if changelog is None or not isinstance(changelog.get("additions"), int) or changelog["additions"] < 1:
        return False
    versions = {_bumped_version(entry, path, pattern) for path, pattern in RELEASE_VERSION_FILES.items()}
    return None not in versions and len(versions) == 1


def merge(
    entries: list[object],
    reviewer: str,
    reviewer_type: str,
    associations: frozenset[str],
    exempt_authors: frozenset[str] = EXEMPT_AUTHORS,
) -> list[tuple[str, str, str]]:
    """``(head, state, description)`` for every head in the snapshot, worst verdict winning.

    Two shapes reach ``success`` without an approval, both deterministic artifacts of work that already merged: a
    Dependabot manifest bump and the generated release pull request. A change request from an eligible reviewer
    still makes either a failure -- an exemption removes the approval requirement, not a veto.
    """
    decisions: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        head = str(entry.get("head") or "")
        if not head:
            continue
        number = entry.get("number")
        author = str(entry.get("author") or "")
        if entry.get("draft"):
            # A draft is not mergeable; saying so revokes a success left over from before it was a draft.
            state, description = "pending", "pull request is a draft"
        else:
            reviews = entry.get("reviews")
            ours = reviews if isinstance(reviews, list) else []
            state, description = review_state.verdict(ours, reviewer, reviewer_type, head, associations)
            if state == "pending" and release_scope(entry):
                state, description = "success", f"generated release by {author}: App review not required"
            elif (
                state != "failure"
                and exempt(entry, author, exempt_authors)
                and not review_state.matching_reviews(ours, reviewer, reviewer_type, associations)
            ):
                # Only where no eligible reviewer has said *anything*: any review at all -- including a comment
                # that holds the change -- is used as-is rather than read as approval.
                state, description = "success", f"dependency update by {author}: App review not required"
        severity = SEVERITY.get(state, SEVERITY["pending"])
        current = decisions.get(head)
        numbers = list(current["numbers"]) if current else []
        if isinstance(number, int) and number not in numbers:
            numbers.append(number)  # every pull request on this head, not only the ones at the worst severity
        if current is None or severity > current["severity"]:
            decisions[head] = {"severity": severity, "state": state, "description": description, "numbers": numbers}
        else:
            current["numbers"] = numbers
    plan = []
    for head, decision in sorted(decisions.items()):
        # Sorted: the description must be identical whatever order the API listed the pull requests in, or an
        # unchanged verdict would be republished every sweep (and GitHub keeps only 1000 statuses per head).
        numbers = "".join(f" #{n}" for n in sorted(decision["numbers"]))
        description = f"{decision['description']}{numbers}"[:MAX_DESCRIPTION]
        plan.append((head, decision["state"], description))
    return plan


def main(argv: list[str] | None = None, stdin=None) -> int:
    parser = argparse.ArgumentParser(description="One status decision per head commit from an open-PR snapshot.")
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--type", default="Bot")
    parser.add_argument("--trusted-associations", default=",".join(sorted(review_state.TRUSTED_ASSOCIATIONS)))
    parser.add_argument(
        "--exempt-authors",
        default=",".join(sorted(EXEMPT_AUTHORS)),
        help="comma-separated authors whose pull requests need no App review; empty disables the exemption",
    )
    arguments = parser.parse_args(argv)
    associations = frozenset(
        value.strip().upper() for value in arguments.trusted_associations.split(",") if value.strip()
    )
    try:
        document = json.load(sys.stdin if stdin is None else stdin)
    except ValueError as exc:
        # No decisions at all: the caller must not publish a success from a snapshot it could not read.
        print(f"::error::the snapshot is not JSON: {exc}")
        return 1
    if not isinstance(document, list):
        print("::error::the snapshot is not an array")
        return 1
    exempt_authors = frozenset(value.strip() for value in arguments.exempt_authors.split(",") if value.strip())
    for head, state, description in merge(document, arguments.reviewer, arguments.type, associations, exempt_authors):
        print(f"{head}\t{state}\t{description}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
