# Changelog

All notable changes to advisory-radar. Format: Keep a Changelog; versions are
SemVer. A release is a `vX.Y.Z` tag on `main` — tagging is a deliberate
operator action, and the release workflow then builds and pushes the image to
`ghcr.io/mikomiel/advisory-radar` (tag + `latest`).

## [Unreleased]

### Fixed
- The web UI printed stored timestamps as raw epoch seconds (`1792600000`). The dashboard,
  `/alerts` and `/runs` render a UTC `YYYY-MM-DD HH:MM` instead. A state value that is not a
  usable timestamp is blank in the tables (the dashboard's last pass says `never`) rather than
  failing the page: its "seen in the last 24h" count compared a stored string against an epoch and
  raised, `/alerts` sorted mixed types, and a run record that was not an object broke `/` and
  `/runs`. Such a value is also not counted as recent.
- `automerge.yml` selected no pull request at all. It pre-filtered candidates on
  GitHub's `reviewDecision`, which is empty because branch protection requires
  zero approving reviews. Selection now skips only drafts and leaves the approval
  decision to `scripts/review_state.py`, its single owner, inside the loop.
- An approval that arrived after `ci` had already completed was not seen until the
  next scheduled run, and GitHub runs those schedules hours apart. A review now
  relays through a no-op `review-signal` workflow, `review-gate` re-evaluates when
  it completes, and `automerge` merges when `review-gate` completes instead of
  waiting for a sweep. The schedules stay as the backstop.

### Changed
- The sensitive-path guard also covers `uv.lock`, `.python-version` and
  `.dockerignore`: the lock decides what `uv sync --frozen` installs in CI, and
  the pin and the ignore list change the runtime and the image.
- The README states the three required checks (`ci`, `gate`, `review`) in the
  policy paragraph and in the setup example, and the guard test now checks that
  every guarded pattern is documented in that paragraph.

### Security
- Every workflow action is pinned to a full commit SHA, with its version in a
  trailing comment so Dependabot keeps it current, and every job runs on
  `ubuntu-24.04` instead of the moving `ubuntu-latest`.
- The release publishes build provenance and an SBOM: BuildKit attestations in
  the image manifest, plus a GitHub attestation bound to the pushed digest and
  verifiable with `gh attestation verify oci://ghcr.io/mikomiel/advisory-radar:<tag>`.

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
