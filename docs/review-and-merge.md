# Review and merge automation

This page owns the detailed merge policy. [CONTRIBUTING.md](../CONTRIBUTING.md)
is the contributor-facing summary; the README links here instead of repeating
the policy.

`main` is protected by **four required status checks** — `ci`, `gate`, `review`
and `dependency-review` — all strict (require the branch to be up to date).
`review` is not a workflow that runs tests — it is the review itself, published
as a status:

- `.github/workflows/review-gate.yml` reads every open pull request's reviews on each
  `ci` completion, on pull-request lifecycle events (opened, reopened, ready for review,
  converted to draft, closed, pushed) and every five minutes, then publishes `review` on
  the head commit: `success` when there is an **approving review at that exact commit** or
  the pull request is one of the two exempt shapes described below (a dependency update, or
  the release pull request release-please generates), `failure` when a reviewer's
  verdict is "changes requested", and `pending` otherwise. The logic lives in
  [`scripts/review_gate_plan.py`](../scripts/review_gate_plan.py), which also aggregates
  several pull requests sharing one head — a status is keyed by commit, so the worst
  verdict must win.
- The rule has one owner: [`scripts/review_state.py`](../scripts/review_state.py), tested by
  [`tests/test_review_state.py`](../tests/test_review_state.py) and used by both the gate and
  the merge workflow, so the two cannot disagree. A review counts when it comes from the
  configured reviewer App, or from someone with repository access
  (`OWNER`/`MEMBER`/`COLLABORATOR`) — the second route is how a maintainer approves a
  contributor's pull request.
- `dependency-review` runs on every pull request and fails when the changed
  dependency graph introduces a known-vulnerable package. It is a separate
  context from `ci`, so a dependency failure stays visible without hiding the
  test result.
- A review is *about one commit*. A push after the review leaves the new head with no
  `review` status, so the merge button goes back to blocked. That is the intended
  behaviour, not an outage.
- **A review is acted on at once, not at the next sweep.** `pull_request_review` cannot run the
  gate itself: like `pull_request`, it would execute the head's copy of the workflow that declares
  it. So a no-op workflow, `review-signal`, listens for `submitted` and `dismissed` — no checkout,
  no secret, `permissions: {}` as committed, one line of output — and its completion is the signal
  the default branch acts on. `review-signal` starts `review-gate`, which republishes the status, and
  `review-gate`'s completion starts `automerge`, which asks for a fresh merge attempt. For an
  otherwise eligible pull request — approval at the exact head, checks green, no sensitive path — the
  expected merge latency is minutes, not a guarantee: anything under `scripts/`, `tests/` or
  `.github/` is for a person either way. The `*/5` and `*/30` schedules remain only as a backstop: GitHub
  runs fixed crons late, and an approval that arrives after `ci` has finished would otherwise wait
  hours for one.
- **Dependency updates are exempt from the App review.** A pull
  request opened by Dependabot (`dependabot[bot]`) gets `review: success` with the reason
  in the description, and only while four things hold. First, the head is a `dependabot/`
  branch of this repository, not a fork's: Dependabot pushes the branch of an update to the
  repository it updates, under that prefix, so a pull request from a fork or from a branch of
  any other name keeps the review requirement even when its author reads as the bot. Second,
  *every* path the immutable
  `base...head` comparison names - both sides of a rename - is a dependency manifest
  (`.github/workflows`, `pyproject.toml`, `uv.lock`, `Dockerfile`, `docker-compose.yml`), and
  the changed-file count that proves that list complete describes the *same* two commits as
  the comparison: the count is read separately, so a branch that moved in between is not
  exempt. Third, *every commit* of that comparison is Dependabot's own: authored by the bot,
  committed by GitHub (`web-flow`) or by the bot, and carrying a signature GitHub reports as
  verified. The pull request's author is only whoever opened it, and a branch takes more
  commits afterwards, so a push by a maintainer to a Dependabot branch, or GitHub's *Update
  branch* button (a merge commit in that person's name), ends the exemption for that head. The
  comparison lists at most 250 commits and reports their full count beside them, and a list
  shorter than that count is not exempt. To get a clean head again, comment `@dependabot
  rebase`: Dependabot rewrites the branch from its own commits. Fourth, a workflow edit is
  nothing but pins moved: its patch changes only `uses:` lines, each replaced one for one by a
  `uses:` line for the same action at a full 40-character commit id (with an optional
  `# vX.Y.Z` comment) and at the same indentation. A changed `run:`, `with:` or `permissions:`
  line, an extra line, another action, a tag instead of a commit id, an added, removed or
  renamed workflow file, or a patch the gate did not carry keeps the review requirement. The
  gate carries a patch for at most 40 changed lines and 16 KiB per file; that bound is
  transport, not policy. The other manifests are still accepted by path alone, and `ci` is
  what reads their content. The exemption is keyed on an
  author login GitHub assigns, which a patch cannot claim, and it applies **only where no
  eligible reviewer has said anything decisive**: a stale approval, a dismissed review or a
  comment still leaves it pending, and an approval or a change request is used as-is.
  **These conditions narrow the exemption; they do not authenticate the bot.** GitHub records
  a squash merge of a Dependabot pull request as authored by the bot, committed by `web-flow`
  and verified, whatever content the merged branch held, so a commit like that passes the
  identity conditions above, and people with write access are trusted for this exemption.
  What it refuses is a head that is not a `dependabot/` branch of this repository, a commit
  by anyone else, and an unsigned one.
  `.github/workflows/automerge.yml` still never takes an exempt pull request: it holds
  every candidate to `scripts/review_state.py`'s eligible approval at the exact head, and
  an exempt one has none. **GitHub's own auto-merge is a separate switch**, and while
  repository setting `allow_auto_merge` is on, anyone
  with write access can enable it on an exempt bump and GitHub will merge once `ci`,
  `gate`, `review` and `dependency-review` are green — no approval involved. If "a person merges every bump" is meant
  literally, turn that setting off: there is no other use for it here, because the merge
  is this repository's own workflow.
- A green `review` means "not required" rather than "approved" in two cases: an exempt
  dependency update and the generated release pull request. The description says which, and
  each exemption applies only while every changed path is one it covers — a bump that
  changed `src/advisory_radar/web.py` would not be exempt, and neither would a release
  branch that carried one.
- **The generated release pull request is the second exemption.** Merging that pull request
  is the release decision, and no authoring session exists to request the App review, so the
  gate publishes `review: success` for it — but only for the generator's output, which is
  more than a branch name. The identity: the head branch
  `release-please--branches--main--components--advisory-radar` in this repository, the
  `RELEASE_PLEASE_TOKEN` owner as author, not a draft. The changes: every path the immutable
  `base...head` comparison names is one of the five files the release manages
  (`.release-please-manifest.json`, `CHANGELOG.md`, `pyproject.toml`,
  `src/advisory_radar/__init__.py`, `uv.lock`) and all five are present; the changelog gains
  its section; each version-carrying file's patch is *exactly* its one `version` line
  replaced, and the lockfile's line must sit under the `advisory-radar` package (a dependency
  version that happened to match is not the generator's output); the four versions agree and
  the version actually changes. The changed-file count must
  also prove the list complete for the same two commits. A dependency added beside the
  version, an import appended to the version line, a second changed line, a path outside the
  set, a missing patch (the gate carries one only for a change of at most 40 lines and 16 KiB
  per file) or an unreadable list keeps the normal requirement and fails closed. An approval
  at the exact head is still reported as that approval, a change request still makes the
  status a `failure`, and `.github/workflows/automerge.yml` still never takes the pull
  request: it changes
  `pyproject.toml`, a sensitive path, so a person merges it. The shape is recognised in
  [`scripts/review_gate_plan.py`](../scripts/review_gate_plan.py), pinned by
  [`tests/test_review_gate_plan.py`](../tests/test_review_gate_plan.py), and it mirrors
  `release-please-config.json` and the token owner: a drift fails closed, and the release
  pull request then needs the normal review.
- What a green `review` proves, exactly: that this commit was approved **when last
  evaluated** (or, for an exempt dependency update or the generated release pull request,
  that none was required). It is a stored assertion, not a live query, so it is not a proof at the
  instant you click merge. Automerges re-read the reviews with the same rule immediately
  before merging, so a withdrawal before that read stops them. A withdrawal *after* the
  read, or a manual merge before the next evaluation, can still land — the window is
  bounded by event delivery and by the five-minute sweep, not eliminated. The event that
  would close it, `pull_request_review`, runs the pull request's own copy of the workflow,
  so a pull request could rewrite it to publish its own success; the window is the price of
  never running head-controlled code.

Why a status instead of GitHub's own "require a pull request review": when that rule was
enabled here on 2026-11-06, the reviewer App approved pull request #9 at its exact head
and GitHub still reported `reviewDecision: REVIEW_REQUIRED` and
`mergeStateStatus: BLOCKED` — an App approval does not satisfy it, and with one human
account (which cannot approve its own pull requests) the rule blocked all maintenance.
The status-based gate expresses the same requirement in a way this repository can satisfy.
Two-person review still needs a second human account or a team with another member, plus
`.github/CODEOWNERS`; that is a separate step, and the gate does not pretend to replace it.

**A person merges anything that widens what the automation can reach.** The list lives in
[`scripts/guard_sensitive_paths.py`](../scripts/guard_sensitive_paths.py) — `.github/`
(including the workflows and this automation), `Dockerfile`, `docker-compose.yml`,
`deploy/`, `pyproject.toml`, `uv.lock` (the lock decides what CI installs under
`uv sync --frozen`), `.python-version`, `.dockerignore`, `.gitleaks.toml`, a `.gitleaksignore`
in any directory (gitleaks drops every finding that one lists, so adding it hides a secret from
the scan),
`release-please-config.json` and `.release-please-manifest.json` (the tag format, what a
release contains, and the version it starts from), `AGENTS.md` and `CLAUDE.md` at the
repository root (the rules a coding agent follows in this repository), `tests/` and
`scripts/` (the guard, the approval rule and the merge loop are policy too: the workflows execute them from
the default branch, so they need the same human merge as the workflows themselves), and the
files that configure how the checks run, which would otherwise let a pull request switch the
checks off without touching `tests/`: `conftest.py` at any depth, the root files `ruff.toml`,
`.ruff.toml`, `pytest.ini`, `.pytest.ini`, `pytest.toml`, `.pytest.toml` (pytest reads all four
names, and each one wins over the `[tool.pytest.ini_options]` table of `pyproject.toml`),
`tox.ini`, `setup.cfg`, `uv.toml`, `.coveragerc`, `noxfile.py`, `hatch.toml`, `hatch_build.py`
(the build backend merges the first over `[tool.hatch]` and runs the second as a build hook, in
CI and in the image build) and
`sitecustomize.py`, and a `ruff.toml`, `.ruff.toml` or `pyproject.toml` below the root (ruff
applies the closest configuration file to each file, so a nested one silences its own
subtree) — and
[`tests/test_guard_sensitive_paths.py`](../tests/test_guard_sensitive_paths.py) pins it. A
pull request touching one of those paths is never auto-merged: the workflow skips it and a
human merges it. The guard therefore means "a person merges these", not "a second person
approved them".

`.github/workflows/automerge.yml` does the merging itself, and its one step runs
[`scripts/automerge_loop.py`](../scripts/automerge_loop.py): an approved pull request whose
checks are green is squash-merged (with `--match-head-commit`, so a head that moved is
refused) when `ci` finishes, when `review-gate` finishes, or on a 30-minute sweep. The loop is a
standard-library Python script that calls `gh`, the approval rule, the guard and the branch cleanup,
so a test can run it against a stub `gh`; the workflow holds no merge logic of its own. It also
deletes the head branch: the *automatically delete head branches* setting did not delete the
branch an automerge left behind (#36, #43), so
[`scripts/delete_merged_branch.py`](../scripts/delete_merged_branch.py) removes the merged ref — only for a
same-repository head, and only while the branch still points at the commit that was merged; a branch that
moved, or a fork's branch, is left in place and the run warns.

The loop reports whether it merged anything through the step output `merged`, and the order of its
writes is the contract. It writes `merged=false` before it reads the queue, and `merged=true` the
moment `gh pr merge` succeeds, before the branch cleanup and the comment. The `release` job runs when
the run is not cancelled and `merged` is `'true'`, so a merge that landed is released even when a later
candidate fails and turns the run red. A failed read of the queue, of a pull request, of its reviews or of its
head and base before the merge ends the run with an `::error::` line and a non-zero exit; it never
passes for an empty queue. The comparison that the guard reads fails closed the other way: a comparison
that cannot be read leaves the pull request for a person, and the loop goes on. A merge that GitHub
refuses is likewise only a skip: the loop goes on to the next candidate and the output stays as it was.
[`tests/test_automerge_loop.py`](../tests/test_automerge_loop.py) runs the real script against a
stub `gh` and pins that order, and
[`tests/test_workflow_pins.py`](../tests/test_workflow_pins.py) pins the release gate and that the
workflow step is only the call to the script.

The workflow only runs from the default branch — `workflow_run` and `schedule`,
never `pull_request*` and not `workflow_dispatch` (a dispatcher can pick another
ref, and that ref's copy of the file is what runs). Expected latency for an otherwise
eligible pull request is therefore minutes, because a review starts the relay above; the
schedules are the backstop, not the mechanism, and GitHub runs fixed crons late. Nothing
merges without an approval from the configured reviewer at the exact head — or, for an
exempt dependency update or the generated release pull request, without one being required —
and any check that is not terminal-success stops it.

To enable the required checks on a copy of this repository
(`contexts` replaces the whole list, so name all four):

```
echo '{"strict": true, "contexts": ["ci", "gate", "review", "dependency-review"]}' \
  | gh api -X PATCH repos/<owner>/<repo>/branches/main/protection/required_status_checks --input -
```

Merge a change to `.github/` *before* adding `review`, or the gate cannot run and every
pull request is blocked by a check that does not exist yet.

The reviewer is the Gandalf GitHub App, which posts its review through the
`external_github_review` route; a review is requested, not spawned — the gate enforces a
review, it does not write one. Contributors can of course review each other, and a
maintainer's approval satisfies the gate on a contributor's pull request; the point is
that no human has to click merge.

## Secret scan

The `ci` job scans with a pinned gitleaks binary. It checks out with `fetch-depth: 0` and proves
the event's complete commit range before the scanner runs: `base..head` for a pull request,
`before..HEAD` for a push, and `--all` for a new branch or any other event. A missing base
commit, a base that is not an ancestor of the head, or an empty range fails the job — it never
falls back to a smaller scan, and it prints the range and its commit count. Before the real
scan, a self-test in a throwaway repository adds a synthetic token in one commit and removes it
in the next; the job fails unless the scanner finds it, so a scanner that cannot see history
cannot report a clean range.

What a green scan means, exactly: **post-push detection**. The commits are already on the remote
when `ci` runs, so the result says the proven range contained no secret the scanner detects. It
is not prevention: once a secret is pushed it is exposed, and a later commit that deletes it
does not undo the exposure — the credential must be revoked. Prevention is pre-push and belongs
to the contributor: never commit a secret, and scan locally before pushing. This policy alleges
no historical leak; it closes the gap between what the job claimed to cover and what a
one-commit checkout could see.

## Estate identifier guard

`scripts/check_no_estate_identifiers.py` (the `ci` step "No internal identifiers") fails closed. It
matches every path in the git index and the content of every blob the index names, read with
`git cat-file --batch`, so a symlink's target and a file that cannot be read on the runner are scanned
like any other. Every blob is decoded leniently as UTF-8, so a file that is not UTF-8 is still matched,
and so are ASCII text next to a stray NUL byte and the raw ASCII inside image data: a NUL byte does not
make a blob binary. A blob that holds a NUL byte is also read as text in UTF-16 and UTF-32: every ASCII
character of such text is written with NUL bytes, and a Windows tool saves a file that way, with or
without a byte order mark. Those are four more readings, one per encoding and byte order, each from the
first byte, and a reading that is wrong for the blob matches nothing. A blob without a NUL byte cannot
hold an ASCII identifier in a wide encoding. Two inputs are reported clean and are known limits: an
identifier that a NUL byte splits, which no reading joins again, and UTF-32 text that follows a prefix
of one to three bytes, which only some of the readings realign. The suffix decides nothing: an `.svg`
is text, and image data is read like text, so a binary file fails only when its bytes spell an
identifier. One file is skipped for its content only, `scripts/check_no_estate_identifiers.py`, because
its text lists the patterns; its path name is still matched. The lock file and `.gitleaks.toml` are read
like any other file: a lock generated against a private index names that index in every package entry it
resolved there. A git error, an object that cannot be read, output that does not parse, or an empty index
ends the run with status 2 and the reason, never with `OK`; status 1 means identifiers were found.

The scan reads the index, not the work tree. An edit that is not staged and a file that is not added are
not scanned, so stage a change before a local run. CI checks out a tree in which everything is tracked,
so the limit does not apply there.

## Release tags

`release-please` opens the release pull request, merging it creates the `vX.Y.Z` tag, and the tag
starts `.github/workflows/release.yml`, which builds, pushes and signs the image. Anyone who can push
a tag starts that job, so it checks the tag before it builds or pushes anything:

- The tag's commit must be an ancestor of `origin/main`. The checkout fetches the whole history for
  this, and a checkout without `origin/main` fails the job instead of skipping the check.
- The version in the tag name must equal `[project] version` in `pyproject.toml`, which only the
  release pull request changes. A pre-release tag such as `v1.2.0-rc1` therefore builds only when
  `pyproject.toml` carries exactly that version.
- `latest` moves only when the tag is the highest stable `vX.Y.Z` tag that is a release of `main`,
  compared as versions (`v0.10.0` is above `v0.9.0`). A stable tag is a release of `main` when it passes
  the two checks above, read at its own commit: that commit is an ancestor of `origin/main`, and the tag
  name equals `[project] version` in `pyproject.toml` there. A stray higher tag that fails one of them (a
  `v999.0.0` on a side commit, on a commit that carries another version, or on no commit at all) does not
  hold `latest` back from the real releases below it. Any other tag publishes its own version tag and
  leaves `latest` where it was. Two tags pushed within one build window can still leave `latest` on the
  lower one; the next release moves it.

These checks make a wrong tag fail instead of publish. They run inside the job, so they do not stop a
person with write access from starting it with a tag on a commit of `main`. The build step sets
`context: .`, so it builds the checkout that the checks read, not what the build action's own default Git
context would read again at build time; a tag moved after the checkout cannot change what is built. Which
commit the checkout holds is up to `actions/checkout`, and nothing in the job compares it with
`GITHUB_SHA`, which the ancestry check names. Neither this point nor the build action's handling of a
path context was checked against the pinned actions here. Two repository settings finish
the control. Neither is visible in the source, and this change neither verifies nor applies either
one; both are owner actions:

1. **A tag ruleset for `v*`.** In Settings, Rules, Rulesets, create a tag ruleset on `v*` that restricts
   creation, update and deletion, so that only the identity that owns `RELEASE_PLEASE_TOKEN` can still
   create such a tag. A ruleset's bypass list takes roles, teams, apps and deploy keys rather than a
   named user, so pick the entry that covers that identity and nothing wider; these mechanics were not
   checked here. release-please creates the tag with that token when the release pull request merges,
   so a ruleset that also blocks that identity stops the release at the tag.
2. **`RELEASE_PLEASE_TOKEN` in an environment restricted to `main`.** The `release-please` job reads it
   as `secrets.RELEASE_PLEASE_TOKEN`, a plain secret, so a workflow file on any branch that a writer can
   push can ask for it. Create a deployment environment whose deployment branches are limited to `main`,
   move the secret there, and only then add `environment:` to that job in
   `.github/workflows/release-please.yml`. Adding `environment:` first is wrong: GitHub creates a
   missing environment on first reference, with no protection, so the job would keep working while
   protecting nothing. The job carries no `environment:` today, on purpose.

## CI container checks

The `ci` job checks more than the Python code. `docker compose config -q` runs against a scratch copy
of `docker-compose.yml` with an empty `.env`, so a broken compose file fails the job without starting
anything. The image is then built and started, and asked for `/healthz`. This job does not start the
shipped compose file or the Podman quadlet under `deploy/podman/`.

Both ruff steps run with `--no-respect-gitignore`. By default ruff skips what a `.gitignore` or an
`.ignore` file lists, in any directory and for a tracked file as well, so a new `.gitignore` under
`src/` that names a module would hide it from the lint and from the format check without touching a
path that the guard reserves. The flag makes ruff read every file under the root; its default
excludes still keep `.venv` and `.git` out. A local run without the flag skips those files too, so
it can pass where CI fails.

Every job carries a `timeout-minutes`, so a hung step cannot hold a runner for the default six hours.
[`tests/test_ci_hardening.py`](../tests/test_ci_hardening.py) pins that, the ruff flag, the exact
`hatchling` pin, the `setup-uv` version in the same line as the Dockerfile's builder, and Dependabot's
coverage of `uv`, `github-actions`, `docker` and `docker-compose`.
