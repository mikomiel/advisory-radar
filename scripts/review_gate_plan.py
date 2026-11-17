#!/usr/bin/env python3
"""Turn a snapshot of open pull requests into one status decision per head commit.

The gate publishes a *commit status*, and a status is keyed by (sha, context) -- not by pull request. Two
open pull requests can share a head commit (a branch and a copy of it), and then a single status must speak
for both. Publishing whichever pull request was processed last would let an approved one turn a
changes-requested one green, so this script aggregates conservatively: the worst verdict among the pull
requests sharing a head wins, and the description names them all.

Input: a JSON array of ``{number, head, base, draft, author, changed, count_head, count_base, branch,
head_repo, base_repo, reviews, files, commits, total_commits}`` on stdin -- one entry per open pull request, with the
reviews exactly as the API returned them, ``changed`` the pull request's own changed-file count, ``files`` the
entries of the immutable ``compare`` (``filename``, ``previous_filename``, ``status``, ``additions``,
``deletions`` and, for a small change, ``patch``), ``commits`` its commits (``sha``, the ``author`` and
``committer`` logins and the signature's ``verified`` verdict) with ``total_commits`` the count the comparison
reports, ``branch``/``head_repo`` the head ref and its repository as the list endpoint reported them, and
``base_repo`` the repository the gate runs in, which is the base of every pull request it lists.
Flattening renames is this script's job, so that it is tested.

Two entries may be published as ``success`` without an independent approval, and only by their exact shape: a
Dependabot update -- on a ``dependabot/`` branch of this repository, not a fork's, every commit the bot's own and
signed by GitHub, touching nothing but dependency manifests and, in a workflow, nothing but the pin of an action it
already uses -- and the release pull request release-please generates from merged commits, recognised by its
branch, author, the five files it manages *and* a patch that is only the version bump those files carry. Neither
can be auto-merged: the merge workflow still asks :mod:`review_state` for an eligible approval at the exact head,
and both always change a path ``guard_sensitive_paths.py`` reserves for a person.

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
#: Authors whose pull requests do not need an App review, and only while the head is a Dependabot branch of this
#: repository, every commit is their own and every changed path stays inside DEPENDENCY_FILES and
#: DEPENDENCY_DIRECTORIES. Dependabot's updates are mechanical and `ci` (the image build included) still has to
#: pass. The login is GitHub's, not the pull request's, so a patch cannot claim it -- but it is only whoever
#: *opened* the pull request, which is why the branch and the commits are read too.
#: A pull request the exemption covers is still not taken by automerge.yml: the merge asks ``review_state.py``
#: for an eligible approval at the exact head, and an exempt pull request has none. GitHub's own auto-merge
#: switch is separate: while `allow_auto_merge` is on, a write-access user can have GitHub merge an exempt bump
#: once its checks are green.
EXEMPT_AUTHORS = frozenset({"app/dependabot", "dependabot[bot]"})
#: Dependabot pushes the branch of an update to the repository it updates, and names it under this prefix.
DEPENDABOT_BRANCH_PREFIX = "dependabot/"
#: Who may be recorded as the committer of an exempt author's commit besides that author: GitHub itself, whose
#: key signs what Dependabot writes through the API. This narrows the exemption; it does not authenticate the bot.
#: An author is only an email address, so a commit carries the bot's name without the bot having written it. A
#: squash merge of a Dependabot pull request is recorded by GitHub as authored by that bot, committed by
#: ``web-flow`` and verified, whatever content the merged branch held: such a commit satisfies every identity
#: condition here, and a person with write access can bring one about. The exemption therefore trusts the people
#: with write access, and what it refuses is a commit by somebody else, an unsigned one, and a head that is not
#: a Dependabot branch of this repository.
SIGNING_COMMITTERS = frozenset({"web-flow"})
#: Paths a dependency update may touch for the exemption to apply, checked rather than assumed. Files match
#: exactly -- ``Dockerfile/evil.py`` is somebody deleting the manifest and adding a directory of source, not a
#: dependency update -- and only the workflow tree matches as a prefix. A manifest is accepted by its path; a
#: workflow can run code, so its patch must also be nothing but pins moved (see ``_only_pin_changes``).
DEPENDENCY_FILES = frozenset({"pyproject.toml", "uv.lock", "Dockerfile", "docker-compose.yml"})
DEPENDENCY_DIRECTORIES = (".github/workflows/",)
#: The one workflow line a Dependabot update writes: ``uses:`` an action at a full commit id, an optional
#: ``# vX.Y.Z`` comment of printable ASCII, and nothing else -- no tab, no carriage return, no second key. The
#: captured ``lead`` is the indentation and list marker, which must not move.
PINNED_USES = re.compile(
    r"(?P<lead>[ ]*(?:-[ ]+)?)uses:[ ]+(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@(?P<sha>[0-9a-f]{40})"
    r"(?:[ ]+#[ -~]*)?"
)
#: The only lines of a patch that are not content: a hunk header and git's missing-newline marker.
HUNK_HEADER = re.compile(r"@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@.*")
NO_NEWLINE_MARKER = "\\ No newline at end of file"
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
#: The package whose own ``version`` line the release writes in ``uv.lock``. A dependency version that happened to
#: match is not the generator's output, so the lockfile rule also checks the package name the patch carries.
RELEASE_PACKAGE = "advisory-radar"
RELEASE_LOCKFILE = "uv.lock"
#: The changelog must gain its generated section. Its prose is documentation, not something this automation can
#: reach, so "present, with additions" is all that is asked. Every one of these five files must appear, and no
#: other path may.
RELEASE_CHANGELOG = "CHANGELOG.md"
RELEASE_PATHS = frozenset(RELEASE_VERSION_FILES) | {RELEASE_CHANGELOG, RELEASE_LOCKFILE}


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


def _count(value: object) -> bool:
    """Whether a count is an integer; a boolean is not one, although Python says so."""
    return isinstance(value, int) and not isinstance(value, bool)


def _commits_are_the_authors_own(entry: dict, exempt_authors: frozenset[str]) -> bool:
    """Whether every commit of the comparison is an exempt author's own, signed by GitHub, and none is missing.

    The pull request's author is whoever opened it, and a branch takes more commits afterwards: a maintainer who
    pushes to a Dependabot branch leaves that author unchanged. So each commit is read: authored by an exempt
    author, committed by GitHub or by that author, and carrying a signature GitHub reports as verified. The
    verdict must be the boolean ``true`` -- a missing or unreadable one is not a pass. ``compare`` lists at most
    250 commits and reports the full count beside them, so a list shorter than that count could hide a later
    commit by somebody else and proves nothing; the head must be among them, or the list describes another commit.
    These facts narrow the exemption; they do not authenticate the bot (see ``SIGNING_COMMITTERS``).
    """
    head = entry.get("head")
    commits = entry.get("commits")
    total = entry.get("total_commits")
    if not isinstance(head, str) or not head or not isinstance(commits, list):
        return False
    if not _count(total) or len(commits) < total:
        return False
    signers = SIGNING_COMMITTERS | exempt_authors
    shas: set[str] = set()
    for item in commits:
        if not isinstance(item, dict):
            return False
        sha, author, committer = item.get("sha"), item.get("author"), item.get("committer")
        if not isinstance(sha, str) or not sha:
            return False
        # Type first: a value that is not a name must be refused, not looked up (a list is not hashable).
        if not isinstance(author, str) or author not in exempt_authors:
            return False
        if not isinstance(committer, str) or committer not in signers:
            return False
        if item.get("verified") is not True:
            return False
        shas.add(sha)
    return head in shas


def _change_blocks(patch: str) -> list[tuple[list[str], list[str]]] | None:
    """A patch as its blocks of changed lines, each ``(removed, added)``, or None when a line is not one git writes.

    Split on LF alone, as ``_bumped_version`` does: ``str.splitlines`` also breaks on a carriage return or U+2028,
    and a YAML parser may read those as a newline, so a changed line could then look like the pin plus a fragment
    this loop never saw. A block is what lies between context lines, removals first, as git writes it. Any other
    line -- text outside a hunk, a removal after an addition -- is not understood and fails the whole patch.
    """
    blocks: list[tuple[list[str], list[str]]] = []
    removed: list[str] = []
    added: list[str] = []
    for line in patch.split("\n"):
        if line.startswith("-") and not added:
            removed.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
        elif line == "" or line.startswith(" ") or line == NO_NEWLINE_MARKER or HUNK_HEADER.fullmatch(line):
            # Context, a header or the end of the patch: the block that was open is complete.
            if removed or added:
                blocks.append((removed, added))
                removed, added = [], []
        else:
            return None
    if removed or added:
        blocks.append((removed, added))
    return blocks


def _pins_moved(removed: list[str], added: list[str]) -> bool:
    """Whether each removed line is replaced, in place, by a pin of the same action at the same indentation."""
    if not removed or len(removed) != len(added):
        return False
    for old, new in zip(removed, added, strict=True):
        before, after = PINNED_USES.fullmatch(old), PINNED_USES.fullmatch(new)
        if before is None or after is None:
            return False
        if before["lead"] != after["lead"] or before["action"] != after["action"]:
            return False
    return True


def _only_pin_changes(item: dict) -> bool:
    """Whether a workflow file's diff only moves the pin of an action the workflow already uses.

    The path says a workflow changed; the patch says what it can do now. A Dependabot update replaces ``uses:``
    lines one for one and writes nothing else, so every changed line must be such a line, paired with the line it
    replaces, and the counts the comparison reports must agree with the patch: a patch the compare cut short, an
    addition it hid, a file that was added, removed or renamed, or no patch at all is not proof and fails closed.
    """
    if item.get("status") != "modified" or item.get("previous_filename"):
        return False
    patch, additions, deletions = item.get("patch"), item.get("additions"), item.get("deletions")
    if not isinstance(patch, str) or not _count(additions) or not _count(deletions):
        return False
    blocks = _change_blocks(patch)
    if not blocks:
        return False
    if sum(len(removed) for removed, _ in blocks) != deletions or sum(len(added) for _, added in blocks) != additions:
        return False
    return all(_pins_moved(removed, added) for removed, added in blocks)


def _workflow_edits_are_pins(entry: dict) -> bool:
    """Whether every file that touches the workflow tree, under either name, only moves pins."""
    files = entry.get("files")
    for item in files if isinstance(files, list) else []:
        if not isinstance(item, dict):
            return False
        names = (item.get("filename"), item.get("previous_filename"))
        in_tree = any(isinstance(name, str) and name.startswith(d) for name in names for d in DEPENDENCY_DIRECTORIES)
        if in_tree and not _only_pin_changes(item):
            return False
    return True


def _from_dependabots_branch(entry: dict) -> bool:
    """Whether the head is a ``dependabot/`` branch of this repository, not a fork's.

    Dependabot pushes the branch of an update to the repository it updates, so a pull request from a fork, or from a
    branch of another name, is not the bot's even when its author reads as the bot. ``base_repo`` is the repository
    the gate runs in. A missing or unreadable fact is not a match, and neither are two empty names: a deleted fork
    reports no head repository, and an unknown base must not equal it.
    """
    branch, head_repo, base_repo = entry.get("branch"), entry.get("head_repo"), entry.get("base_repo")
    if not isinstance(branch, str) or not branch.startswith(DEPENDABOT_BRANCH_PREFIX):
        return False
    return isinstance(head_repo, str) and bool(head_repo) and head_repo == base_repo


def exempt(entry: dict, author: str, exempt_authors: frozenset[str]) -> bool:
    """Whether the dependency exemption covers this entry: the author's own signed commits, manifests and pins only.

    Fail-closed in every place a fact is unproven: a head that is not a ``dependabot/`` branch of this repository
    is not exempt, an unreadable list is not exempt, a list shorter than the pull request's own changed-file count
    is not exempt (``compare`` caps its list at 300, so a source file could hide past the cap), a count that does
    not describe the same commit pair as the comparison is not exempt, an empty list is not exempt, a commit that
    is not the exempt author's own and signed by GitHub is not exempt (nor is a commit list that may be
    incomplete), and a workflow edit that is more than a moved pin is not exempt.
    """
    return (
        author in exempt_authors
        and _from_dependabots_branch(entry)
        and _complete(entry)
        and _dependency_only(_changed_names(entry))
        and _commits_are_the_authors_own(entry, exempt_authors)
        and _workflow_edits_are_pins(entry)
    )


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


def _lock_bumped_version(entry: dict) -> str | None:
    """The ``advisory-radar`` package version the release writes in ``uv.lock``, or None for any other edit.

    The one-line rule alone would also accept a dependency's version line, so the patch must place the replaced
    line under this package's ``name``. The name is a context line of the hunk (git shows three either side); a
    patch without it fails closed rather than guessing.
    """
    version = _bumped_version(entry, RELEASE_LOCKFILE, r'version = "(\d+\.\d+\.\d+)"')
    if version is None:
        return None
    patch = _changed_file(entry, RELEASE_LOCKFILE).get("patch")
    if not isinstance(patch, str):
        return None
    package: str | None = None
    for line in patch.split("\n"):
        if line.startswith(" ") or line.startswith("+"):
            match = re.fullmatch(r'\s*name = "([^"]+)"', line[1:])
            if match is not None:
                package = match.group(1)
        elif line.startswith("-") and re.fullmatch(r'version = "(\d+\.\d+\.\d+)"', line[1:]):
            # The version line being replaced belongs to the last package named above it in the hunk.
            return version if package == RELEASE_PACKAGE else None
    return None


def release_scope(entry: dict) -> bool:
    """Whether this entry is the generator's output: its identity, all five release files, and one version bump.

    Fails closed everywhere: an unreadable or incomplete file list, a path outside the release-managed set, a
    missing release file, a changelog that gained nothing, a version file whose diff is not the one line, versions
    that disagree, a lockfile line under another package, or a patch the compare did not carry.
    """
    if not release_candidate(entry) or not _complete(entry):
        return False
    if set(_changed_names(entry)) != RELEASE_PATHS:
        return False
    changelog = _changed_file(entry, RELEASE_CHANGELOG)
    if changelog is None or not isinstance(changelog.get("additions"), int) or changelog["additions"] < 1:
        return False
    versions = {_bumped_version(entry, path, pattern) for path, pattern in RELEASE_VERSION_FILES.items()}
    if None in versions or len(versions) != 1:
        return False
    return _lock_bumped_version(entry) == next(iter(versions))


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
        help=(
            "comma-separated authors whose pull requests need no App review, when the head is also a dependabot/ "
            "branch of this repository; empty disables the exemption"
        ),
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
