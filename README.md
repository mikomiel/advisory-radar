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
docker compose up -d
# or with Podman:
podman play kube deploy/podman/advisory-radar.yaml
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

- Configurable source plugins: RSS/Atom, FreshRSS (GReader API), changedetection.io (API poll + inbound webhook), generic inbound webhook, Adobe APSB, Debian DSA, PHP ChangeLog, Node.js security blog
- Enrichment plugins: CVE.org, NVD, FIRST EPSS, CISA KEV, OSV, Debian security tracker
- Notifier plugins: Discord, Matrix, ntfy, Gotify, Apprise, generic webhook, SMTP
- Severity decision per CVE with re-evaluation window and one escalation per level
- Web UI + REST API, in-process scheduler (default every 15 min), atomic JSON state on a volume
- Docker and Podman deployment (compose file + quadlet/kube YAML), `/healthz` and `/metrics`
- Secrets via environment / `_FILE` only; redaction filter on logs; fail-closed source errors

## Review and merge automation

`main` is protected: a pull request needs **one approving review** and a green `ci`
run. `.github/workflows/automerge.yml` then does the merging itself: an approved
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

Bootstrap complete; CI and review app smoke-tested on this PR.
