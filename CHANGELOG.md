# Changelog

All notable changes to advisory-radar. Format: Keep a Changelog; versions are
SemVer.

The version, this file and the release tag are maintained by
[release-please](https://github.com/googleapis/release-please) from the
conventional commits merged to `main`. Merging its release pull request is the
release decision: the `vX.Y.Z` tag it creates is what builds and publishes
`ghcr.io/mikomiel/advisory-radar` (tag + `latest`). Do not edit a released
section by hand -- [CONTRIBUTING.md](CONTRIBUTING.md#releases) owns the release
boundary.

## [0.1.0] - 2026-11-06

The first public release: the extracted security-advisory notifier, packaged as a
single container with plugin seams for sources and notifiers.

### Added
- Core pipeline: configurable source plugins (RSS/Atom, FreshRSS GReader,
  changedetection.io API polling, generic inbound webhook) with per-source
  window-gap detection; enrichment via CVE.org, NVD, FIRST EPSS, CISA KEV,
  OSV, Debian security tracker, php.net ChangeLog, nodejs.org posts, Adobe
  APSB bulletins.
- Per-CVE severity verdicts (KEV / SSVC active / remote-unauthenticated CVSS
  >= 9.0 / EPSS threshold; suppression below CVSS 4.0 only on complete data),
  daily re-evaluation with at most one escalation per level, Markdown-neutralised
  vendor text, bounded fetch budgets, fail-closed source faults.
- Notifier plugins: Apprise, Discord webhook, Matrix webhook, ntfy, Gotify,
  generic webhook, SMTP.
- Web UI (dashboard, alerts, parked queue with release/drop, runs, config
  view, run-a-pass, token login), `/healthz` and Prometheus `/metrics`,
  in-process scheduler.
- Atomic JSON state with parking of undeliverable messages (never silently
  discarded), backlog cutoff, export window gap detection, log redaction.
- Deployment: rootless multi-stage Dockerfile with healthcheck,
  `docker-compose.yml`, Podman quadlet, `docs/deployment.md` (incl. Beszel
  monitoring), GHCR release workflow on `v*` tags.
- CI on free GitHub-hosted runners: ruff, pytest, pinned gitleaks secret
  scan, internal-identifier guard, docker build smoke. Dependabot weekly.
- Community files: CONTRIBUTING, SECURITY (private vulnerability reporting),
  CODE_OF_CONDUCT, issue/PR templates, branch protection on `main`.
