# advisory-radar

Self-hostable security advisory watcher: it reads the vendor feeds, webhooks
and changedetection.io watches you configure, enriches every finding with
CVE.org / NVD, EPSS, CISA KEV and OSV, decides a severity per CVE, and sends one
deduplicated alert per new advisory to the channels you choose.

![Dashboard: pending, parked, seen-today and total counts above the last pass's sent, parked and exit result](docs/screenshots/dashboard.png)

## What it does

- Watches RSS/Atom/JSON Feed, FreshRSS, changedetection.io and inbound webhooks,
  with vendor parsing for Debian DSA, php.net, Node.js and Adobe bulletins.
- Enriches each advisory with CVE.org, NVD, EPSS, CISA KEV, OSV and the Debian
  tracker, re-evaluates it inside the window and escalates once per level.
- Judges a level per CVE — critical, warning or suppressed — from global and
  per-source thresholds; an unmeasured severity is never suppressed.
- Delivers to Discord, Matrix, ntfy, Gotify, Apprise, signed generic webhooks
  and SMTP, with routing groups, digests and quiet hours for non-critical mail.
- Serves a server-rendered UI and REST API: alert history with URL filters, a
  page per advisory, the parked queue, sources, notifiers and run history.
- Keeps state in one JSON document, SQLite or PostgreSQL; `/healthz` and
  `/metrics` are unauthenticated for probes and scrapers.

## Quickstart

```bash
# Until the first tagged release is on GHCR, build locally:
docker build -t ghcr.io/mikomiel/advisory-radar:latest .
docker compose up -d
# or with Podman: install deploy/podman/advisory-radar.container as a quadlet
# (see docs/deployment.md)
```

Open http://localhost:8080 and sign in with `ADVISORY_RADAR_AUTH_TOKEN`.
Configuration lives in `config/` on the mounted volume; start from
[examples/config.yml](examples/config.yml) and read
[docs/configuration.md](docs/configuration.md). Secrets come from environment
variables or a `${NAME_FILE}` reference to a file, never from committed files.

## Documentation

- [Configuration](docs/configuration.md) — watchlist, thresholds, routing,
  delivery, settings, storage and gap detection.
- [Sources](docs/sources.md) — the source catalogue, probe behaviour, intervals
  and OPML import.
- [Deployment](docs/deployment.md) — compose, Podman, health and metrics.
- [Features](docs/features.md) — the full capability list and the problem it
  solves.
- [Screenshots](docs/screenshots.md) — the UI gallery.
- [Review and merge](docs/review-and-merge.md) — the automation and its limits.

## Contributing

Bug reports and pull requests are welcome. `main` requires exact-head CI and
review; the contributor workflow, the sensitive paths and the merge rules are in
[CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/review-and-merge.md](docs/review-and-merge.md).

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

`0.1.0` is the first public release. Version numbers follow SemVer; every
`vX.Y.Z` tag on `main` publishes a multi-arch image to
`ghcr.io/mikomiel/advisory-radar`, with build provenance and an SBOM attestation
bound to the pushed digest:

```bash
gh attestation verify oci://ghcr.io/mikomiel/advisory-radar:<tag> --repo mikomiel/advisory-radar
```

Deliberately not here yet: a per-host agent, cross-source deduplication beyond
the watch window, and a hosted service.
