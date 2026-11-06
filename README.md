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

### Gap detection

A source that knows its own page size (a FreshRSS export, a changedetection
watch) reports a truncated window, and the pass fails loudly when a full window
shares nothing with the previous one — that is how silently missed advisories
surface. An RSS/Atom feed is bounded by its publisher instead, so a skipped item
there cannot be detected; poll those feeds often enough that rotation is
unlikely.

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

## Review and merge automation

`main` is protected: a pull request needs **an approving review from the review App**
and a green `ci` run. The workflow below then performs the merge itself.

**A person merges anything that widens what the automation can reach.** A pull request
touching `.github/` (including the workflows and this automation), `Dockerfile`,
`docker-compose.yml`, `deploy/`, `pyproject.toml`, `.gitleaks.toml` or `tests/` is
never auto-merged — the workflow skips it and a human merges it. The repository has
one human account, which cannot approve its own pull requests, so a "require code
owner approval" rule would deadlock maintenance instead of adding a check. The path
guard therefore means "a person merges these", not "a second person approved them".

**The day this repository is shared, turn on one branch-protection rule.**

```
gh api -X PATCH repos/mikomiel/advisory-radar/branches/main/protection/required_pull_request_reviews \
  -F required_approving_review_count=1 -F dismiss_stale_reviews=true
```

What we know about that rule here, rather than what it is supposed to do: when it was
enabled on 2026-11-06, the review App approved pull request #9 at its exact head and
GitHub still reported `reviewDecision: REVIEW_REQUIRED` and `mergeStateStatus: BLOCKED`
— the App's approval did not satisfy it, and only a person's approval would have. That
is why the rule is off today: this repository has one human account, it authors every
pull request, and GitHub does not let an author approve their own pull request, so the
rule blocked all maintenance. The day other people can open pull requests that deadlock
disappears and the rule is the right one.

If a future GitHub change lets an App approval satisfy the rule, the stricter
configuration is *Require review from Code Owners* with a `.github/CODEOWNERS` entry for
a second human account or a team with another member — which is also what genuine
two-person review needs, and what this repository cannot express with one account.

`.github/workflows/automerge.yml` then does the merging itself: an approved
pull request whose checks are green is squash-merged (with `--match-head-commit`,
so a head that moved is refused) when `ci` finishes or on a 30-minute sweep. Branch deletion follows the repository's *automatically delete head
branches* setting.

The workflow only runs from the default branch — `workflow_run` and `schedule`,
never `pull_request*` and not `workflow_dispatch` (a dispatcher can pick another
ref, and that ref's copy of the file is what runs). The trade-off is latency: a merge lands
within ~30 minutes of the approval, not at the instant of the review. Nothing
merges without an approval from the configured reviewer at the exact head, and
any check that is not terminal-success stops it.

The reviewer is the Gandalf GitHub App, which posts its review through the
`external_github_review` route. Contributors can of course review each other;
the point is that no human has to click merge.

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
and integrations are complete and tested (178 tests), and CI runs them on free
GitHub-hosted runners. Version numbers follow SemVer; every `vX.Y.Z` tag on `main`
publishes a multi-arch image to `ghcr.io/mikomiel/advisory-radar`.

What is deliberately not here yet: a per-host agent, alert deduplication across
sources beyond the watch window, and any hosted service. Issues and pull requests
are welcome.
