# advisory-radar

Self-hostable security advisory watcher. Point it at the sources you care about
(vendor RSS/Atom feeds, FreshRSS, changedetection.io, generic webhooks), let it
enrich every finding with CVE.org / NVD CVSS, EPSS, CISA KEV and OSV, decide a
severity per CVE, and deliver one deduplicated alert per new advisory to the
channels you configure (Discord, Matrix, ntfy, Gotify, Apprise, generic webhook,
SMTP). A built-in web UI shows alerts, sources, notifiers, the parked queue and
run history. One container, one process, JSON state on a volume, YAML + environment
configuration.

## Quickstart

```bash
# Until the first tagged release is on GHCR, build locally:
docker build -t ghcr.io/mikomiel/advisory-radar:latest .
docker compose up -d
# or with Podman: install deploy/podman/advisory-radar.container as a quadlet
# (see docs/deployment.md)
```

Then open http://localhost:8080 (sign in with `ADVISORY_RADAR_AUTH_TOKEN`) for the
dashboard, alert history, parked queue, run log and config overview. `/healthz`
and `/metrics` (Prometheus text) are unauthenticated for probes and scrapers.
Configuration lives in `config/` on the mounted volume (see `examples/config.yml`);
secrets come from environment variables or `<NAME>_FILE` files, never from
committed files.

```yaml
# examples/config.yml (abridged)
sources:
  - id: nodejs
    type: rss
    url: https://nodejs.org/en/feed/vulnerability.xml
notifiers:
  - id: discord
    type: discord_webhook
    url: ${DISCORD_WEBHOOK_URL}
# optional: scope alerts to what you run (see below)
watchlist: ./config/watchlist.json
```

`watchlist.json` is optional. Without it every advisory that arrives is judged;
with it, only items that match one of your products (a name alias in the text or
a link on one of its domains) are considered, and `excluded_products` drops the
ones you do not run. Package patterns filter Debian DSA titles.

```json
{
  "schema": "security-watchlist.v1",
  "debian_source_packages": ["curl", "openssl"],
  "excluded_products": ["legacy-app"],
  "products": [{"id": "nodejs", "aliases": ["node.js"], "domains": ["nodejs.org"]}]
}
```

### Settings without a restart

The `/config` page changes four things without editing the YAML or restarting the
container: `notifiers` (the whole list, which is how a channel is added, edited or
disabled), each source's `enabled` flag and `tag`, `poll_interval`, and
`hidden_source_hosts`. A save writes `settings.json` next to the state file (on the
`/data` volume) and applies it as soon as the state lock is free; the page shows which
saved revision is live. `SIGHUP` reloads the same overlay for a configuration edited by
hand. Every other setting stays in `config/config.yml` and still needs a restart.

Secrets stay in the environment. The overlay stores a notifier's `url`, `key`,
`password` or `token` only as a `${NAME}` or `${NAME}_FILE` reference, refuses a literal
value, and does not accept `headers` at all. Changing an environment variable still
needs a restart, because the process reads the environment when it starts.

A reload builds the new configuration and its plugins before it swaps them in under the
state lock. An invalid overlay is refused with the same error the YAML would give, and
the running configuration stays; a pass that already started finishes with the
configuration it started with, and the next pass uses the reloaded one.

### Gap detection

A source that knows its own page size (a FreshRSS export) reports a truncated
window, and the pass fails loudly when a full window shares nothing with the
previous one — that is how silently missed advisories surface. An RSS/Atom feed
is bounded by its publisher, and the changedetection.io source reports no
truncation at all, so a skipped item there cannot be detected; poll those sources
often enough that rotation is unlikely.

## Why

Vendor security feeds are noisy; the interesting question is "does this affect
what I run, and how badly". advisory-radar answers it per CVE (CVSS, EPSS,
KEV, SSVC), suppresses the noise below the floor, escalates when a watched CVE
turns critical, and never re-sends what you already received.

## Features

- Configurable source plugins: RSS/Atom, FreshRSS (GReader API), changedetection.io (API poll + inbound webhook), generic inbound webhook; vendor enrichment for Debian DSA, php.net ChangeLog, Node.js security blog, Adobe APSB bulletins
- Enrichment plugins: CVE.org, NVD, FIRST EPSS, CISA KEV, OSV, Debian security tracker
- Notifier plugins: Discord webhook, Matrix (Hookshot), ntfy, Gotify, Apprise, generic webhook, SMTP
- Severity decision per CVE with re-evaluation window and one escalation per level
- Web UI + REST API, in-process scheduler (default every 15 min), atomic JSON state on a volume
- Docker and Podman deployment (compose file + quadlet/kube YAML), `/healthz` and `/metrics`
- Secrets via environment / `_FILE` only; redaction filter on logs; fail-closed source errors

## Screenshots

The UI is server-rendered: there is no JavaScript build step. These are from a
local run with demo data, so the advisories in them are not real findings.

![Dashboard: pending, parked and recently seen counts with the last pass result](docs/screenshots/dashboard.png)

| Alerts | Configuration |
|---|---|
| ![Alert history: advisory id, outcome and UTC first-seen time](docs/screenshots/alerts.png) | ![Configuration: sources, notifiers and the poll interval](docs/screenshots/config.png) |

| Parked messages | Runs |
|---|---|
| ![Parked queue: severity, title and advisory ids, with bulk release and drop actions](docs/screenshots/parked.png) | ![Run history: sent, parked, pending and exit code per pass](docs/screenshots/runs.png) |

## Sources

Four source types are built in, and the table below is the whole catalogue: a
**required** key has no default, an **optional** one may be left out. The same
catalogue is on the `/sources` page of the web UI and in
`advisory-radar sources list`, which needs no config file.

`advisory-radar sources test <id>` fetches one *configured* source, prints its
items and whether its window was truncated, and exits non-zero when it was or
when the fetch failed. It sends no notification and writes no state, so it is
safe to run while the service is polling. A `webhook` source is read from an
empty inbox, so it prints no items: the command checks configuration, not intake.

| Kind | Summary | Required keys | Optional keys |
|---|---|---|---|
| `rss` | Any RSS 2.0 or Atom feed URL, read in one conditional GET. | `url` | `tag`, `enabled` |
| `freshrss` | A FreshRSS shared query, read through its GReader JSON export. | `url`, `token` | `user`, `enabled` |
| `changedetection` | Poll a changedetection.io instance; every watch whose page changed becomes one item. | `url`, `api_key` | `tag`, `enabled` |
| `webhook` | Items pushed to this instance's `/webhooks/<id>` endpoint, read from the state inbox. | — | `tag`, `enabled` |

An accepted key is not always read by every kind: `tag` scopes a
changedetection.io poll to one watch tag, `user` names the FreshRSS account, and
`enabled: false` keeps an entry in the file without building it. An RSS/Atom feed
and a changedetection.io poll return the whole response, so the FreshRSS GReader
export is the only built-in that reports a truncated window.

## Review and merge automation

`main` is protected by **three required status checks** — `ci`, `gate` and `review` — all
strict (require the branch to be up to date). `review` is not a workflow that runs tests — it is
the review itself, published as a status:

- `.github/workflows/review-gate.yml` reads every open pull request's reviews on each
  `ci` completion, on pull-request lifecycle events (opened, reopened, ready for review,
  converted to draft, closed, pushed) and every five minutes, then publishes `review` on
  the head commit: `success` when there is an **approving review at that exact commit** or
  the pull request is an exempt dependency update (below), `failure` when a reviewer's
  verdict is "changes requested", and `pending` otherwise. The logic lives in `scripts/review_gate_plan.py`, which also aggregates
  several pull requests sharing one head — a status is keyed by commit, so the worst
  verdict must win.
- The rule has one owner: [`scripts/review_state.py`](scripts/review_state.py), tested by
  [`tests/test_review_state.py`](tests/test_review_state.py) and used by both the gate and
  the merge workflow, so the two cannot disagree. A review counts when it comes from the
  configured reviewer App, or from someone with repository access
  (`OWNER`/`MEMBER`/`COLLABORATOR`) — the second route is how a maintainer approves a
  contributor's pull request.
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
- **Dependency updates are exempt from the App review, and nothing else is.** A pull
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
  `gate` and `review` are green — no approval involved. If "a person merges every bump" is meant
  literally, turn that setting off: there is no other use for it here, because the merge
  is this repository's own workflow.
- An exempt dependency update is the one case where a green `review` means "not required"
  rather than "approved": the description says which, and the exemption applies only while
  every changed path is a dependency manifest the gate checks — a bump that reached into
  `src/` would not be exempt.
- What a green `review` proves, exactly: that this commit was approved **when last
  evaluated** (or, for an exempt dependency update, that it was never required). It is a stored assertion, not a live query, so it is not a proof at the
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
[`scripts/guard_sensitive_paths.py`](scripts/guard_sensitive_paths.py) — `.github/`
(including the workflows and this automation), `Dockerfile`, `docker-compose.yml`,
`deploy/`, `pyproject.toml`, `uv.lock` (the lock decides what CI installs under
`uv sync --frozen`), `.python-version`, `.dockerignore`, `.gitleaks.toml`, `tests/` and
`scripts/` (the guard and the approval rule are policy too: the workflows execute them from
the default branch, so they need the same human merge as the workflows themselves) — and
[`tests/test_guard_sensitive_paths.py`](tests/test_guard_sensitive_paths.py) pins it. A
pull request touching one of those paths is never auto-merged: the workflow skips it and a
human merges it. The guard therefore means "a person merges these", not "a second person
approved them".

`.github/workflows/automerge.yml` does the merging itself: an approved pull request whose
checks are green is squash-merged (with `--match-head-commit`, so a head that moved is
refused) when `ci` finishes, when `review-gate` finishes, or on a 30-minute sweep. It also
deletes the head branch: the *automatically delete head branches* setting did not delete the
branch an automerge left behind (#36, #43), so
[`scripts/delete_merged_branch.py`](scripts/delete_merged_branch.py) removes the merged ref — only for a
same-repository head, and only while the branch still points at the commit that was merged; a branch that
moved, or a fork's branch, is left in place and the run warns.

The workflow only runs from the default branch — `workflow_run` and `schedule`,
never `pull_request*` and not `workflow_dispatch` (a dispatcher can pick another
ref, and that ref's copy of the file is what runs). Expected latency for an otherwise
eligible pull request is therefore minutes, because a review starts the relay above; the
schedules are the backstop, not the mechanism, and GitHub runs fixed crons late. Nothing
merges without an approval from the configured reviewer at the exact head — or, for an
exempt dependency update, without one being required — and any check that is not
terminal-success stops it.

To enable the required checks on a copy of this repository
(`contexts` replaces the whole list, so name all three):

```
echo '{"strict": true, "contexts": ["ci", "gate", "review"]}' \
  | gh api -X PATCH repos/<owner>/<repo>/branches/main/protection/required_status_checks --input -
```

Merge a change to `.github/` *before* adding `review`, or the gate cannot run and every
pull request is blocked by a check that does not exist yet.

The reviewer is the Gandalf GitHub App, which posts its review through the
`external_github_review` route; a review is requested, not spawned — the gate enforces a
review, it does not write one. Contributors can of course review each other, and a
maintainer's approval satisfies the gate on a contributor's pull request; the point is
that no human has to click merge.

## Development

```bash
uv sync --group dev
uv run ruff check .
uv run pytest -q
uv run python -m advisory_radar --help
```

Conventional Commits; every PR runs lint, tests, a secret scan and a
no-internal-identifiers scan on free GitHub-hosted runners; `main` is protected
(requires green CI and a review).

## Security

Report vulnerabilities privately via GitHub's private vulnerability reporting
(see [SECURITY.md](SECURITY.md)). Do not open public issues for undisclosed
vulnerabilities.

## License

[MIT](LICENSE)

## Status

`0.1.0` — the first public release. The pipeline, plugin seams, web UI, container
and integrations are complete and covered by the test suite that CI runs on every pull
request on free GitHub-hosted runners. Version numbers follow SemVer; every `vX.Y.Z` tag
on `main` publishes a multi-arch image to `ghcr.io/mikomiel/advisory-radar`, with build
provenance and an SBOM attestation bound to the pushed digest:

```
gh attestation verify oci://ghcr.io/mikomiel/advisory-radar:<tag> --repo mikomiel/advisory-radar
```

What is deliberately not here yet: a per-host agent, alert deduplication across
sources beyond the watch window, and any hosted service. Issues and pull requests
are welcome.
