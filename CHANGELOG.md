# Changelog

All notable changes to advisory-radar. Format: Keep a Changelog; versions are
SemVer. A release is a `vX.Y.Z` tag on `main` — tagging is a deliberate
operator action, and the release workflow then builds and pushes the image to
`ghcr.io/mikomiel/advisory-radar` (tag + `latest`).

## [Unreleased]

### Added
- Sources can be added, edited and removed on `/config` without touching the read-only
  config mount. The settings overlay gained `sources_added`: a source the YAML does not
  define is stored whole in the overlay, while the YAML keeps owning the entries the file
  defines. The two may not share an id (a collision fails the load instead of letting the
  merge order decide which URL is polled), and a secret key (`token`, `api_key`) may only be
  stored as a `${NAME}`/`${NAME_FILE}` reference. `SourceSpec.secret_keys` in the catalogue
  is the one owner of which keys those are, so the config key allowlist, the form and the
  overlay's rule are derived rather than repeated.
- A source probe in the browser: **Test the new source** on `/config` and a **Test** button
  on every row of `/config` and `/sources` perform the same fetch a pass performs, show the
  entry count, the first entries or the error, and write nothing. A probe of an unsaved
  source resolves its `${NAME}` references (reporting a missing variable by name, never its
  value) and offers a form that saves exactly what it fetched. `create_app` takes an
  injectable transport for it, so the tests answer without a network.
- Per-source health: each pass records `source_health` (last attempt, last success, entries,
  redacted error) in the same write as that source's validators, pruned to the configured
  ids. `/sources` is now the operational page — one line per enabled source with its state,
  timestamps, entries and error beside the probe button — and `/metrics` exports
  `advisory_radar_source_up`, `_source_last_success_timestamp_seconds` and `_source_items`,
  labelled by source id, so a failing feed is named rather than only failing the pass.
- A source catalogue (`advisory_radar/catalogue.py`): one `SourceSpec` per
  built-in kind with its summary, required and optional keys, a tested example
  and a docs anchor. The config key allowlist is derived from it instead of
  being repeated by hand.
- `advisory-radar sources list` (every built-in kind and its keys, no config
  file or secret needed) and `advisory-radar sources test <id> --limit N`
  (fetch one configured source, print its items and truncation flag, deliver
  nothing, write no state).
- A `/sources` page rendered from the catalogue, and a README source table kept
  equal to it by `tests/test_catalogue.py`.
- A settings overlay (`settings.json` beside the state file) merged over the YAML before
  validation: `notifiers` (the overlay replaces the list's membership and ordinary fields,
  so a channel can be added, edited or disabled; a notifier's `headers` stay in the YAML
  and are carried over by id), per-source `enabled`/`tag`, `poll_interval` and
  `hidden_source_hosts`. A shared configuration value fails with the `ConfigError` the YAML
  gives, and the overlay adds its own restrictions — a secret-bearing key must be a
  `${NAME}`/`${NAME_FILE}` reference, a source edit is `enabled`/`tag` only, and `headers`
  may not be written. A credential is therefore only ever a reference, with one limit worth knowing: a
  source `url` is ordinary configuration to the validator, so a URL that carries a token has to be
  written as a reference and nothing here can tell whether it was.
- Hot reload: a saved overlay, `POST /reload` and `SIGHUP` rebuild the plugins off to the
  side and swap them under the state lock; the scheduler reads the configuration per pass,
  and the wait between passes restarts on a reload so a shorter `poll_interval` takes
  effect without sleeping out the old one. A refused overlay keeps the running
  configuration, and pending and parked messages are untouched.
- `/config` edits those settings with plain forms (poll interval, hidden hosts, sources,
  notifiers) and shows which saved overlay revision is live. Each form carries a fingerprint
  of the configuration it was rendered from, so a stale tab — after another save, a YAML
  edit, or an overlay deleted and recreated — is refused instead of overwriting it, and a
  notifier's `headers` stay in the YAML while the overlay edits its enablement.
- Notification routing: an ordered `routes` list in `config.yml` matches a message on `source`,
  `tag`, watched `product` or an `ids` pattern (first match wins) and sends it to only the
  notifiers named by that rule, with an optional `default` and no change at all when no rules
  are configured. A selection that names no enabled notifier fails the pass rather than
  silencing the message, and a delivery retry re-sends only to the channels that have not
  accepted it yet.
- `/alerts` filters by severity tag, recorded source, outcome, a text search over the
  identifier and title, and an inclusive UTC day range (`since`/`until`). Every filter is in
  the URL, so a reload or a shared link keeps it, and the list pages with a keyset cursor
  (50 rows, newest first by time then identifier) instead of the fixed 200-row cap. `/runs`
  filters by exit code and the same day range; it has no pager because the state keeps only
  the last 200 passes, and the page says so.
- A delivery record on a seen advisory: a delivered `new` message also stores its tag,
  source heading, title, link, kind, per-CVE levels and CVSS scores, and the notifier ids
  that accepted it, the identifiers and CVEs, KEV-only CVEs and the matched watchlist
  products (never the message body). The first record for an identifier is kept.
  The snapshot is stored once per message under `deliveries` and each identifier's
  record points at it, so a message naming thousands of identifiers does not store
  thousands of copies of its own lists. The first record for an identifier is kept.
- `/advisories/<identifier>` shows what the state holds for one advisory, looked up in the
  seen record, then a pending message, then a parked one: tag, source, title, per-CVE levels
  and scores, KEV-only CVEs, accepted or already-sent notifiers, attempt count and timestamps.
  Records written by an older version say their details were not recorded; unknown
  identifiers are a 404 page. The page never renders the message body: a delivered record
  does not retain it, while a pending or parked entry still carries its body in the queue
  until it leaves.
- Per-entry release and drop on `/parked` (`POST /parked/<index>/release` and
  `/parked/<index>/drop`), CSRF-protected, with each form carrying a row token: a stale row
  is refused with `404`, a missing or malformed token with `400`, and a pass holding the
  state lock with `409`. The bulk actions stay, and dropping a partially delivered message
  keeps the channel that had already accepted it.
- The routing `routes`/`default` block is editable on `/config`, with three fixed rule rows
  plus a default selection, the same fingerprint/stale-form refusal and validate-and-build
  path as the other forms. An empty form keeps the YAML's rules; a partly filled row is saved
  as written and the merged validator reports what is wrong.
- `scripts/capture_screenshots.py`: an opt-in script that builds demo config and state in a
  temporary directory, serves the app on loopback, signs in through the real login form with
  Playwright and writes the five README screenshots at 1024 px wide, cropped to the page.
  Playwright is not a project dependency, and no CI job runs it.
- A `thresholds` block in `config.yml` (or in the settings overlay, merged key by key) for
  the three numbers the severity decision reads: `critical_cvss`, `critical_epss` and
  `suppress_below_cvss`, with their previous hardcoded values as defaults. The numbers are
  validated (a number in range, and a floor no higher than the critical bar) and reach the
  decision as a `config.Thresholds` value instead of a module constant, so a saved change
  applies to the next pass. `/config` edits them with the same fingerprint/stale-form
  refusal as the other sections, and an empty field falls back to the YAML value.
- `GET /thresholds`, linked from `/config`: a preview of what one advisory would be judged
  as and where its message would go. It renders the live thresholds and calls the same
  `core.level_of` and `routing.select` the pass calls, showing the level, the reason, the
  metrics line and note the message would carry, and the matching route and notifiers. The
  advisory's identifiers are an input, because a rule may match on them: a preview that
  invented one would predict a destination the real message never reaches, so without one
  and with such a rule configured the page says so instead. It is a read-only GET -- nothing
  is written, so a link to it can be shared.
- Per-source thresholds: a `sources:` entry may carry its own `thresholds` block, partial or
  complete, merged key by key over the global block and validated by the same rules and
  ranges with the source's id in the message. `Config.thresholds_for(source_id)` resolves it
  at load time; `core.classify_new` judges an item with its source's block and
  `core.reevaluate` re-judges each watch entry with the block of the source that queued it
  (recorded on the watch entry at delivery and at suppression, with the global block as the
  fallback for state written before this change or damaged by hand). Both the YAML list and
  the overlay's `sources`/`sources_added` entries accept the block, and `/config` edits each
  source's three numbers under the global ones, leaving a field empty when it follows the
  global block.
- Three routing predicates in a rule's `match`: `min_cvss` (the highest CVSS the message
  reports is at least this), `epss_gte` (the highest EPSS it reports is at least this) and
  `kev` (true when a CVE it names is in the KEV catalog, false when none is). They read only
  what the classification measured, carried on the queue entry as `scores`, `epss` and `kev`;
  a message with no measured score satisfies no numeric predicate, and an unmeasured KEV
  membership (an unreadable catalog) satisfies neither boolean. The validator judges each
  match value by its key instead of requiring a non-empty string, so a predicate outside its
  range or a non-boolean `kev` is refused when the configuration loads. `/config` exposes the
  three on every route row, and `/thresholds` predicts them from the values it was given.

### Changed
- `/thresholds` judges the previewed advisory with the previewed source's own threshold
  block when it has one and says so, instead of always using the global block.
- `settings.validate_settings` accepts a source's `thresholds` block in an overlay edit and
  in an added source, checking only its shape; the numbers are merged and judged by the
  configuration validator with the YAML's messages.
- A watch entry records the source that queued it, so a per-source threshold change is a
  change of rules for that source only: it re-baselines that source's CVEs without sending
  them, while a new KEV hit or CISA active flag still escalates against what the reader was
  actually told.
- `_SOURCE_KEYS` treats `thresholds` as a structural source key, like `enabled`; the source
  catalogue keeps owning only the keys a kind's builder reads.

### Fixed
- A first pass whose every source failed wrote no state at all, so `/sources` reported
  "not polled yet" for each source and no per-source metric appeared while the pass log said
  otherwise. It now persists the health records in a seeded-empty document: no validator
  moves and no source is marked seeded, so the first pass that does read a feed still
  bootstraps its history.
- The probe judged a source's URL before expanding it, so a valid `url: ${FEED_URL}`
  reference was refused as a bad scheme and a missing URL reference was reported as one
  instead of naming the variable.
- A source URL nobody can parse (`http://[oops/…`) raised while an id was derived from it or
  while a probe checked its scheme, which answered 500. Both paths now refuse it in words.
- A routing rule matching a `tag` outside `critical` and `warning` was accepted and could
  never fire: `routing.SEVERITY_TAGS` is now the closed set the validator uses, and a rule
  naming an unconfigured source id is reported on `/config` as inert (staging a rule before
  its source is legitimate, so that one warns rather than fails).
- `http.urllib_http` accepted any URL scheme, so a `file://` source would have been read as a
  local file. A source or notifier URL is HTTP(S); every other scheme is now a refused
  request, and the probe says so in words.
- An automerge left its head branch behind: the repository's *automatically delete head branches*
  setting did not delete the branch of a merge made through the API (the branches of #36 and #43
  survived with the setting on). The workflow now deletes the merged head ref through
  `scripts/delete_merged_branch.py`: only for a same-repository head, and only with a
  `git push --force-with-lease` on the merged commit, so a branch that received a later push is left
  alone. A branch that stays is a warning, never a failed run after the merge.
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

- The note a message carries names the threshold that decided it (`CVSS >= 7.5, remote
  attack, ...`) instead of a literal 9.0, so the text cannot claim a bar the configuration no
  longer has; the escalation note does the same for EPSS.
- A saved threshold re-baselines what is already watched instead of escalating it: each
  watch entry records the numbers it was judged under (`state["watch"][*]["thresholds"]`),
  and the first evaluation after a change records the new verdict without sending anything.
  The entry keeps the level the reader was told (`level`) apart from the level the numbers in
  force make of it (`judged`), so a KEV hit, or CISA's active flag, that arrives later still
  escalates against what was actually sent. State written before this change carries no
  record and is judged by the defaults, which is what judged it.
- `/sources` leads with what this instance monitors: each enabled source's state, last
  attempt, last success, entries and error, with a probe per row. The built-in catalogue
  stays on the page, below the configured sources it documents. The `/config` source table
  gained the added-keys, remove and test columns, and the watch-tag column now says what it
  is: a changedetection.io watch tag the other kinds ignore.
- The web UI has one design: a shared shell with a brand, a marked current section and a footer
  (version and the probe links), design tokens measured for WCAG AA contrast in light and dark,
  hairline tables, severity and outcome badges, stat tiles on the dashboard, numbered
  configuration sections, a notifier laid out as a block instead of a table row, and an empty
  state instead of a bare table. It is still one inline stylesheet with no script, no web font
  and no external origin, and it follows `prefers-color-scheme` without a toggle. Every page now
  carries a language, a viewport, a per-page title, one `h1`, a `main` landmark and a skip link.
- The sensitive-path guard also covers `uv.lock`, `.python-version` and
  `.dockerignore`: the lock decides what `uv sync --frozen` installs in CI, and
  the pin and the ignore list change the runtime and the image.
- The README states the three required checks (`ci`, `gate`, `review`) in the
  policy paragraph and in the setup example, and the guard test now checks that
  every guarded pattern is documented in that paragraph.

### Security
- A plugin id is a name: the validator refuses a whole `${NAME}`/`${NAME_FILE}` reference in
  one, and refuses an id composed from a variable that supplies a credential anywhere in the
  same configuration (`id: feed-${CD_TOKEN}` beside `api_key: ${CD_TOKEN}`), because an id
  appears in routes, logs, the state and -- for a source -- a metric label on the
  unauthenticated `/metrics` endpoint. The inventory is deliberately blind to the entry's kind
  and to its `enabled` flag -- `type` may itself be a reference, and a disabled entry can
  supply the value an enabled id borrows -- and it includes a notifier's `headers` and the
  top-level `nvd_api_key`. A source `url` counts wherever it can hold a credential — its
  userinfo, path or query, including a query with no path at all
  (`https://feeds.example.net?token=${FEED_TOKEN}`) — while a reference in a host label
  (`https://${TENANT}.example.net/…`) stays a name an id may reuse. Reference identity follows
  `_expand`'s own lookup: `${X}`, `${X_FILE}` and `${X_FILE_FILE}` are one variable family, and
  a credential position holds its reference at any depth, because `_expand` resolves the
  strings inside a list or mapping too. A name composed
  from a naming variable (`tenant-${X}`, `a${Y}`) stays allowed, and the value it composes is
  what those places show.
- A source added from `/config` may not point into a private network unless the YAML sets
  `allow_private_sources: true`. It is a guard rail against pointing this instance at a
  router page by mistake, not a privilege the YAML keeps and the overlay does not.
  The check reads the destination the way the transport does -- the authority is unquoted
  before the host is separated from the port, so `%3A8080` is a port and not part of a name --
  and refuses loopback, private, shared, link-local, site-local and multicast addresses and
  the IPv6 ranges that wrap an IPv4 one (`::/96`, `64:ff9b::/96`, `2002::/16`). A disabled
  source is not checked, so one whose host later resolves internally can still be switched
  off; probing is judged by ownership instead, so a probe of a source the overlay added is
  checked even while that source is disabled. This is a guard rail against a mistake, not an
  isolation boundary: the pass resolves the name again when it fetches, and the operator
  token can already reach whatever the host can reach. A configured YAML source is unaffected, so a LAN FreshRSS or
  changedetection.io target behaves as before.
- An id the settings overlay adds must be literal text: it is rendered on `/sources`, kept in
  the state's health map and used as a metric label on the unauthenticated `/metrics`
  endpoint, so a `${NAME}` reference there would publish the value it expands to.
- A probe's answer is redacted against every secret the entry resolved, not only its error:
  a source can echo a request token back in a feed title or in a link's host, and the probe
  page must not become a way to read a `${NAME}` out. The origin is redacted before it is
  extracted -- extraction lowercases a hostname, which would transform the value being matched
  -- and `/sources` redacts the origin it shows for the same reason, because it reads the
  expanded configuration rather than the references.
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
