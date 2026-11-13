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
  (optionally signed), SMTP; digests per routing group and local quiet hours for non-critical
  messages
- Severity decision per CVE with re-evaluation window and one escalation per level; the
  thresholds are configurable on `/config` globally or per source, and `/thresholds` previews
  what one advisory would be judged as and where its message would go
- A dashboard of what needs attention — undelivered criticals, quiet-window holds, parked
  messages, awaiting classification, oldest queued age, failing or stale sources and deferred
  enrichment — with every count linked to the filtered view it describes and the last
  attempted, completed and successful pass kept apart; a pass that exited 0 with work
  outstanding is marked deferred work
- One `/inbox` work list over the queue, quiet-window holds, carried work, the parked queue and
  the delivery history, with URL filters and keyset pagination; each identifier keeps its own
  evidence, related identifiers are shown rather than merged, and transport state is kept apart
  from remediation, which this version does not track
- Filterable `/alerts` and `/runs` lists with their state in the URL, keyset pagination for
  the alert history, and a per-advisory page (`/advisories/<id>`) showing the stored
  classification, delivery record and later notification events. The source filter matches the
  configured source id,
  never the advisory heading
- Web UI + REST API, in-process scheduler (default every 15 min), atomic state on a volume:
  a JSON file by default, SQLite or PostgreSQL when `storage` says so
- Per-entry release/drop on the parked queue, next to the bulk actions; `routes`/`default`
  editable on `/config` with the other settings
- Docker and Podman deployment (compose file + quadlet/kube YAML), `/healthz` and `/metrics`
- Secrets via environment / `${NAME_FILE}` references only; redaction filter on logs; fail-closed source errors
