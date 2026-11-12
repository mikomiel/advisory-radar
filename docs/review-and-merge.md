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
  in the description, and only while *every* path the immutable `base...head` comparison
  names — both sides of a rename — is a dependency manifest (`.github/workflows`,
  `pyproject.toml`, `uv.lock`, `Dockerfile`, `docker-compose.yml`), and only while the
  changed-file count that proves that list complete describes the *same* two commits as
  the comparison: the count is read separately, so a branch that moved in between is not
  exempt. It is keyed on an
  author login GitHub assigns, which a patch cannot claim, and it applies **only where no
  eligible reviewer has said anything decisive**: a stale approval, a dismissed review or a
  comment still leaves it pending, and an approval or a change request is used as-is.
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
  `base...head` comparison names is one of the four files the release manages
  (`.release-please-manifest.json`, `CHANGELOG.md`, `pyproject.toml`,
  `src/advisory_radar/__init__.py`) and all four are present; the changelog gains its section;
  and each version-carrying file's patch is *exactly* its one `version` line replaced, with
  the three versions agreeing and the version actually changing. The changed-file count must
  also prove the list complete for the same two commits. A dependency added beside the
  version, an import appended to the version line, a second changed line, a path outside the
  set, a missing patch (the gate carries one only for a change of at most four lines) or an
  unreadable list keeps the normal requirement and fails closed. An approval at the exact head
  is still reported as that approval, a change request still makes the status a `failure`,
  and `.github/workflows/automerge.yml` still never takes the pull request: it changes
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
`uv sync --frozen`), `.python-version`, `.dockerignore`, `.gitleaks.toml`,
`release-please-config.json` and `.release-please-manifest.json` (the tag format, what a
release contains, and the version it starts from), `tests/` and
`scripts/` (the guard and the approval rule are policy too: the workflows execute them from
the default branch, so they need the same human merge as the workflows themselves) — and
[`tests/test_guard_sensitive_paths.py`](../tests/test_guard_sensitive_paths.py) pins it. A
pull request touching one of those paths is never auto-merged: the workflow skips it and a
human merges it. The guard therefore means "a person merges these", not "a second person
approved them".

`.github/workflows/automerge.yml` does the merging itself: an approved pull request whose
checks are green is squash-merged (with `--match-head-commit`, so a head that moved is
refused) when `ci` finishes, when `review-gate` finishes, or on a 30-minute sweep. It also
deletes the head branch: the *automatically delete head branches* setting did not delete the
branch an automerge left behind (#36, #43), so
[`scripts/delete_merged_branch.py`](../scripts/delete_merged_branch.py) removes the merged ref — only for a
same-repository head, and only while the branch still points at the commit that was merged; a branch that
moved, or a fork's branch, is left in place and the run warns.

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
