# Features
## Why

Vendor security feeds are noisy; the interesting question is "does this affect
what I run, and how badly". advisory-radar answers it per CVE (CVSS, EPSS,
KEV, SSVC), suppresses the noise below the floor, escalates when a watched CVE
turns critical, and never re-sends what you already received.

## Capabilities

- Configurable source plugins: RSS/Atom/JSON Feed, FreshRSS (GReader API), changedetection.io (API poll + inbound webhook), generic inbound webhook; vendor enrichment for Debian DSA, php.net ChangeLog, Node.js security blog, Adobe APSB bulletins
- Enrichment plugins: CVE.org, NVD, FIRST EPSS, CISA KEV, OSV, Debian security tracker
- Notifier plugins: Discord webhook, Matrix (Hookshot), ntfy, Gotify, Apprise, generic webhook
  (optionally signed), SMTP, and `log` (writes each message to the application log and delivers
  nothing, for a shadow run); digests per routing group and local quiet hours for non-critical
  messages
- Severity decision per CVE with re-evaluation window and one escalation per level; the
  thresholds are configurable on `/config` globally or per source, and `/thresholds` previews
  what one advisory would be judged as and where its message would go
- A dashboard of what needs attention — undelivered criticals, quiet-window holds, parked
  advisories, awaiting classification, oldest recorded queue age, failing or stale sources and
  deferred enrichment — counting with the same reader and predicate as the inbox, so every
  count equals the rows its link renders; the last attempted, completed and successful pass are
  kept apart, and a pass that exited 0 with work outstanding is marked deferred work
- One `/inbox` work list over the queue, quiet-window holds, carried work, the parked queue and
  the delivery history, with URL filters and keyset pagination; each identifier keeps its own
  facts, a co-named message is context rather than a replacement, related identifiers are shown
  rather than merged, and transport state is kept apart from remediation, which this version
  does not track
- Filterable `/alerts` and `/runs` lists with their state in the URL, keyset pagination for
  the alert history, and a per-advisory page (`/advisories/<id>`) showing the stored
  classification, delivery record and later notification events. The source filter matches the
  configured source id,
  never the advisory heading
- A wall-clock budget per pass (`pass_budget`, 10 minutes by default): the sources, candidates and Adobe Commerce read a
  pass has no time for are deferred and handled first by the next pass, never dropped; such a pass exits 0, is marked
  `incomplete` in `/runs` and `/metrics`, and delivery of queued messages is outside the budget
- The CVEs a message named beyond the lookup cap are durable work, not forgotten ones: each pass measures a few, one
  source in turn, inside the same budget; KEV evidence escalates at once; the dashboard and `/metrics` count the
  CVEs by state and show the oldest wait, and a CVE with enrichment outstanding stays watched for up to 30 days
- Web UI + REST API, in-process scheduler (default every 15 min), atomic state on a volume:
  a JSON file by default, SQLite or PostgreSQL when `storage` says so
- Per-entry release/drop on the parked queue, next to the bulk actions: each row shows its
  delivery attempts and the channels that already accepted it and links to its advisory page,
  and dropping the whole queue asks for confirmation first; `routes`/`default` editable on
  `/config` with the other settings
- Docker and Podman deployment (compose file + quadlet/kube YAML), `/healthz` and `/metrics`
- Secrets via environment / `${NAME_FILE}` references only; redaction filter on logs; fail-closed source errors
