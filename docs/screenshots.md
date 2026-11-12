# Screenshots
The UI is server-rendered: there is no JavaScript build step. Its pages share one
hand-written stylesheet with no script, no web font and no external origin, and it follows
the reader's light or dark preference. These are from a local run with demo data, so the
advisories in them are not real findings. The set is
reproducible: `uv run --with playwright python scripts/capture_screenshots.py` builds the
demo config and state in a temporary directory, serves the app on loopback and writes the
six PNGs (Playwright is opt-in and not a project dependency; see
`deployment.md`).

![Dashboard: pending, parked, seen-today and total counts above the last pass's sent, parked and exit result](screenshots/dashboard.png)

| Alerts | Configuration |
|---|---|
| ![Alert history: URL filters for tag, source, outcome, text and date, with severity badges and the advisory rows linked to their detail page](screenshots/alerts.png) | ![Configuration: numbered sections for settings, sources, notifiers and routes, with the poll interval and the settings overlay status](screenshots/config.png) |

| Watchlist | Parked messages |
|---|---|
| ![The product scope: one row per watched product with its aliases and domains, the Debian package patterns and exclusions, and the form that checks one advisory against the document](screenshots/watchlist.png) | ![Parked queue: severity, title and advisory ids, with per-entry release and drop plus the bulk actions](screenshots/parked.png) |

| Runs |
|---|
| ![Run history: sent, parked, pending and exit code per pass, filtered by exit code and day](screenshots/runs.png) |

