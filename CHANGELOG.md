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

## [0.6.0](https://github.com/mikomiel/advisory-radar/compare/v0.5.0...v0.6.0) (2026-11-19)


### Added

* **inventory:** import SBOM and OSV-Scanner results as evidence ([#163](https://github.com/mikomiel/advisory-radar/issues/163)) ([e379483](https://github.com/mikomiel/advisory-radar/commit/e379483a04e5a884006ea544806d18082341f74d))
* **pipeline:** add a pass time budget and durable CVE enrichment ([#160](https://github.com/mikomiel/advisory-radar/issues/160)) ([56c0229](https://github.com/mikomiel/advisory-radar/commit/56c0229cb2ebaf343171413d871f9d7eefdb5e63))
* **sources:** add a CSAF source for the Red Hat provider ([#162](https://github.com/mikomiel/advisory-radar/issues/162)) ([a45dc51](https://github.com/mikomiel/advisory-radar/commit/a45dc51a505d033f669496efaa7142d36f9a48d4))
* **state:** archive delivery history after two years, add benchmark ([#161](https://github.com/mikomiel/advisory-radar/issues/161)) ([bdf747d](https://github.com/mikomiel/advisory-radar/commit/bdf747d50ff571d8199e34782e07dc2062e7dfc5))
* **web:** catalogue-driven source and notifier forms with test send ([#159](https://github.com/mikomiel/advisory-radar/issues/159)) ([4eaa333](https://github.com/mikomiel/advisory-radar/commit/4eaa33386e10c4c2d30d1c908fe9e98263c901c7))

## [0.5.0](https://github.com/mikomiel/advisory-radar/compare/v0.4.0...v0.5.0) (2026-11-17)


### ⚠ BREAKING CHANGES

* **web:** POST /parked/drop now renders a confirmation page; the drop happens on POST /parked/drop/confirm with the same snapshot digest.

### Added

* **web:** confirm bulk parked drops and show attempts per row ([#151](https://github.com/mikomiel/advisory-radar/issues/151)) ([a8911ef](https://github.com/mikomiel/advisory-radar/commit/a8911ef0b48bd8f758991acc0b2724ba64dff50d))
* **web:** preview where an escalation is routed ([#152](https://github.com/mikomiel/advisory-radar/issues/152)) ([97bf83b](https://github.com/mikomiel/advisory-radar/commit/97bf83b4d1c40faffcf372b5f5e69f139169dadb)), closes [#89](https://github.com/mikomiel/advisory-radar/issues/89)


### Fixed

* **pipeline:** keep the higher watch level on a late new message ([#148](https://github.com/mikomiel/advisory-radar/issues/148)) ([99bef9c](https://github.com/mikomiel/advisory-radar/commit/99bef9cf8d9fc60bd723969ef2b0314a710200a4))

## [0.4.0](https://github.com/mikomiel/advisory-radar/compare/v0.3.1...v0.4.0) (2026-11-17)


### ⚠ BREAKING CHANGES

* **deploy:** compose keeps state in the named volume `advisory-radar-data` instead of ./data (move the data, or switch the volume line back to ./data as docs/deployment.md describes); the web UI is published on 127.0.0.1 only in compose and the quadlet; the example notifier is disabled. The new compose file and quadlet need an image that contains this change.
* **web:** an auth token or webhook secret shorter than 24 characters now stops startup; settings overlay references to environment variables must be listed in `overlay_references` in config.yml; OPML imports with ${...} references are refused.

### Added

* **messages:** render notifications in English or Polish ([#135](https://github.com/mikomiel/advisory-radar/issues/135)) ([34b9f85](https://github.com/mikomiel/advisory-radar/commit/34b9f85d8d933964e33eeccfb688470620eaecce))
* **notifiers:** add a log notifier for shadow runs ([#134](https://github.com/mikomiel/advisory-radar/issues/134)) ([5c3b29d](https://github.com/mikomiel/advisory-radar/commit/5c3b29d89b4c8cb27c98cf13cfaa5820a9e21b17))


### Fixed

* **deploy:** make the container deployment paths start and stay healthy ([#142](https://github.com/mikomiel/advisory-radar/issues/142)) ([77186ac](https://github.com/mikomiel/advisory-radar/commit/77186acd446ac04d152ec835fdb23ce064369393))
* **pipeline:** harden outage backlog, store faults, delivery order and fetch limits ([#140](https://github.com/mikomiel/advisory-radar/issues/140)) ([a86fefa](https://github.com/mikomiel/advisory-radar/commit/a86fefa5f492c95e1d98aa3cc023e49083971b64))
* **web:** harden overlay references, proxy trust, probes and secret loading ([#141](https://github.com/mikomiel/advisory-radar/issues/141)) ([3d068a8](https://github.com/mikomiel/advisory-radar/commit/3d068a8dcb594d1d51e0133382be8246cb1b244e))

## [0.3.1](https://github.com/mikomiel/advisory-radar/compare/v0.3.0...v0.3.1) (2026-11-15)


### Fixed

* **web:** keep store errors out of /readyz and escape revision banners ([#129](https://github.com/mikomiel/advisory-radar/issues/129)) ([55a24bc](https://github.com/mikomiel/advisory-radar/commit/55a24bc438b1fa49ec5fa62d2017b6880f5fdf27))

## [0.3.0](https://github.com/mikomiel/advisory-radar/compare/v0.2.2...v0.3.0) (2026-11-13)


### Added

* **web:** add an actionable dashboard and a unified advisory inbox ([#125](https://github.com/mikomiel/advisory-radar/issues/125)) ([eb45b7c](https://github.com/mikomiel/advisory-radar/commit/eb45b7c475fca943a3a7d39c253d4c53564dfda9))

## [0.2.2](https://github.com/mikomiel/advisory-radar/compare/v0.2.1...v0.2.2) (2026-11-13)


### Fixed

* **settings:** serialise overlay writes across processes ([#120](https://github.com/mikomiel/advisory-radar/issues/120)) ([977b09d](https://github.com/mikomiel/advisory-radar/commit/977b09d7c2c102ed53723789a65c4725b04f1e7d))

## [0.2.1](https://github.com/mikomiel/advisory-radar/compare/v0.2.0...v0.2.1) (2026-11-13)


### Fixed

* **alerts:** keep source provenance and retain later notification events ([#118](https://github.com/mikomiel/advisory-radar/issues/118)) ([1f8a205](https://github.com/mikomiel/advisory-radar/commit/1f8a20576778f4a812b34e9920d1541120a1b064))
* **state:** refuse unreadable documents and test 3.13-3.14 ([#116](https://github.com/mikomiel/advisory-radar/issues/116)) ([25ef072](https://github.com/mikomiel/advisory-radar/commit/25ef0727caaeda97b3a0fccaa1bec62903ffeec6))
* **web:** report the result of Run a pass now ([#115](https://github.com/mikomiel/advisory-radar/issues/115)) ([0a0a6f4](https://github.com/mikomiel/advisory-radar/commit/0a0a6f4111d2bf24af4274baa3654c69db0cebf3))

## [0.2.0](https://github.com/mikomiel/advisory-radar/compare/v0.1.0...v0.2.0) (2026-11-13)


### Added

* add a source catalogue with sources list and sources test ([#44](https://github.com/mikomiel/advisory-radar/issues/44)) ([0a7a78f](https://github.com/mikomiel/advisory-radar/commit/0a7a78f306176f4d97af988c90cd793065bb245f))
* **ci:** a required `review` status, and one owner for both automation rules ([#25](https://github.com/mikomiel/advisory-radar/issues/25)) ([2f9d72e](https://github.com/mikomiel/advisory-radar/commit/2f9d72e3b325169c4a66b7eaee4a6e32db992eb9))
* **ci:** exempt dependency updates from the App review ([#26](https://github.com/mikomiel/advisory-radar/issues/26)) ([5fa50c9](https://github.com/mikomiel/advisory-radar/commit/5fa50c982e389f4295139b877ae15afadaa1dbba))
* **config:** per-source thresholds, and route predicates on measured facts ([#53](https://github.com/mikomiel/advisory-radar/issues/53)) ([0c09257](https://github.com/mikomiel/advisory-radar/commit/0c092571c7118a1278b802c17dd2d32e5fe9cdea))
* **config:** set the risk thresholds, and preview a decision before relying on it ([#52](https://github.com/mikomiel/advisory-radar/issues/52)) ([0d908a2](https://github.com/mikomiel/advisory-radar/commit/0d908a2606dd7723d629033780cec5cb24916392))
* **delivery:** one digest per routing group, quiet hours, and a signed webhook ([#56](https://github.com/mikomiel/advisory-radar/issues/56)) ([58b0f7e](https://github.com/mikomiel/advisory-radar/commit/58b0f7e88124f0ef14b0cfc85fe3ed8650c59bfe))
* **enrich:** optional NVD key and conditional GET for feeds ([#24](https://github.com/mikomiel/advisory-radar/issues/24)) ([c69e4a7](https://github.com/mikomiel/advisory-radar/commit/c69e4a7561302281772ec7563624330a2a5b686f))
* **observability:** readiness endpoint and honest metrics ([#23](https://github.com/mikomiel/advisory-radar/issues/23)) ([2948517](https://github.com/mikomiel/advisory-radar/commit/2948517cbed64221ea8d0d8051a301fda1d840e5))
* route notifications by rule instead of to every notifier ([#47](https://github.com/mikomiel/advisory-radar/issues/47)) ([042f90b](https://github.com/mikomiel/advisory-radar/commit/042f90b303e19bb254f64ac7440219144ec097f9))
* settings you can change without a restart ([#46](https://github.com/mikomiel/advisory-radar/issues/46)) ([2cf771b](https://github.com/mikomiel/advisory-radar/commit/2cf771bc605ee2ba3e519cedbc17390792866a10))
* **sources:** add, test and watch sources from the browser ([#51](https://github.com/mikomiel/advisory-radar/issues/51)) ([75cf224](https://github.com/mikomiel/advisory-radar/commit/75cf22464328c8948db917c65e4c11ed53562433))
* **sources:** read any feed format, poll each source at its own pace, import OPML ([#54](https://github.com/mikomiel/advisory-radar/issues/54)) ([f063735](https://github.com/mikomiel/advisory-radar/commit/f06373559ea85f5662f8045d52c7c053d2c1fec3))
* **storage:** a store seam, SQLite and PostgreSQL for the state document ([#55](https://github.com/mikomiel/advisory-radar/issues/55)) ([4577553](https://github.com/mikomiel/advisory-radar/commit/45775533c125edfeec21860e1e56b76c497a1461))
* **ui:** filterable lists, an advisory page and per-entry queue actions ([#48](https://github.com/mikomiel/advisory-radar/issues/48)) ([ca045b9](https://github.com/mikomiel/advisory-radar/commit/ca045b907947ed930977d4c27ae63f01d4228db0))
* **ui:** one designed shell for every page ([#50](https://github.com/mikomiel/advisory-radar/issues/50)) ([65ab95e](https://github.com/mikomiel/advisory-radar/commit/65ab95ea4f48080e752dcc75fa83ea30458c2de4))
* **watchlist:** edit the product scope in the browser ([#57](https://github.com/mikomiel/advisory-radar/issues/57)) ([11dd8a0](https://github.com/mikomiel/advisory-radar/commit/11dd8a0b198e8d31f0fd66b7b872d3f0e51fb9ae))
* **web:** security headers, form tokens, sign-out and login throttling ([#22](https://github.com/mikomiel/advisory-radar/issues/22)) ([a96a225](https://github.com/mikomiel/advisory-radar/commit/a96a2255c950702c3a6a7b88647981205794a2aa))


### Fixed

* **changedetection:** urlencode tag query parameters ([#107](https://github.com/mikomiel/advisory-radar/issues/107)) ([b7701f1](https://github.com/mikomiel/advisory-radar/commit/b7701f1c4943fd2fb99404d2cc3a10ab2f007ca2))
* **ci:** a lifecycle event cannot revoke its own head ([#27](https://github.com/mikomiel/advisory-radar/issues/27)) ([81b78c5](https://github.com/mikomiel/advisory-radar/commit/81b78c5b646225f92075991c927f510735dda65f))
* **ci:** a review wakes the gate, and the gate wakes the merge ([#39](https://github.com/mikomiel/advisory-radar/issues/39)) ([230e7f9](https://github.com/mikomiel/advisory-radar/commit/230e7f9b21cced71a46c1ccee742e7722f7b744e))
* **ci:** automerge selects candidates by the one approval rule ([#35](https://github.com/mikomiel/advisory-radar/issues/35)) ([71ce36e](https://github.com/mikomiel/advisory-radar/commit/71ce36e600165a61f87604fc922002617a1ca206))
* **ci:** delete the merged head branch after an automerge ([#45](https://github.com/mikomiel/advisory-radar/issues/45)) ([55d3d87](https://github.com/mikomiel/advisory-radar/commit/55d3d87a9491156cdbbdcfd7ba511af3a5c8d8a1))
* **core:** bound classification independently of quiet-held messages, and stop discarding a disabled source's cursors ([#108](https://github.com/mikomiel/advisory-radar/issues/108)) ([e694351](https://github.com/mikomiel/advisory-radar/commit/e69435141621e695483813080fca5f065301c739))
* **core:** keep a withdrawn OSV record out of current severity evidence ([#112](https://github.com/mikomiel/advisory-radar/issues/112)) ([59ada19](https://github.com/mikomiel/advisory-radar/commit/59ada19a470e660bec3088a8d6857eb7ea41eac3))
* **core:** record bootstrap history as backlog without rewriting seen records ([#111](https://github.com/mikomiel/advisory-radar/issues/111)) ([ddeabf1](https://github.com/mikomiel/advisory-radar/commit/ddeabf17027a107e659467c88309e2aaf5df3475))
* **feeds:** honour declared plain text in JSON Feed and Atom ([#109](https://github.com/mikomiel/advisory-radar/issues/109)) ([22264dd](https://github.com/mikomiel/advisory-radar/commit/22264dd12ccbf6661fc25aeaf09cc7f860ae3b22)), closes [#71](https://github.com/mikomiel/advisory-radar/issues/71)
* **webhook:** merge validated structured ids with prose ids, and answer 4xx for undecodable payloads ([#110](https://github.com/mikomiel/advisory-radar/issues/110)) ([e420c4c](https://github.com/mikomiel/advisory-radar/commit/e420c4cc77579cd065d4e456029ac75c7acab05d))
* **web:** render stored timestamps as UTC dates, not epochs ([#42](https://github.com/mikomiel/advisory-radar/issues/42)) ([ad603b3](https://github.com/mikomiel/advisory-radar/commit/ad603b3171e4a3bc017fbaf24ddcbbb2f1cbde89))

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
