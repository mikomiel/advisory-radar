# Deployment

advisory-radar ships as one rootless-friendly container. Pick one:

## Docker Compose

```bash
mkdir -p config data
cp examples/config.yml config/config.yml   # edit sources/notifiers
printf 'ADVISORY_RADAR_AUTH_TOKEN=%s\n' "$(openssl rand -hex 24)" > .env   # plus your notifier secrets
docker compose up -d
```

The image runs as UID 10001 by default; the compose file overrides it to your own
UID/GID so `./data` stays writable (`ADVISORY_RADAR_UID` / `ADVISORY_RADAR_GID` if
your ids are not 1000). If you would rather keep the image's user, make the
directory writable for it: `sudo install -d -m 0750 -o 10001 -g 10001 data`.

## Podman (quadlet, rootless)

```bash
mkdir -p ~/.config/advisory-radar ~/.local/share/advisory-radar ~/.config/containers/systemd
cp examples/config.yml ~/.config/advisory-radar/config.yml
printf 'ADVISORY_RADAR_AUTH_TOKEN=%s\n' "$(openssl rand -hex 24)" > ~/.config/advisory-radar.env
chmod 600 ~/.config/advisory-radar.env
cp deploy/podman/advisory-radar.container ~/.config/containers/systemd/
systemctl --user daemon-reload && systemctl --user start advisory-radar
```

The quadlet runs with `UserNS=keep-id:uid=10001,gid=10001`, which maps the
image's user to yours so both `~/.config/advisory-radar` (read-only config) and
`~/.local/share/advisory-radar` (state) are usable without a chown. It mounts
`~/.config/advisory-radar`, the same directory the commands above create.

## Kubernetes

The container is a plain single-process app: one Deployment with a
`config` ConfigMap (read-only) and a `data` PersistentVolumeClaim, plus a
Service on 8080. `/healthz` is the liveness probe, `/readyz` the readiness
probe, `/metrics` the Prometheus scrape endpoint.

## Monitoring (Beszel and friends)

Run the usual `beszel-agent` on the same host — the container's own CPU/RAM/
disk are covered by host metrics. For app-level signal there are two probes:

| Endpoint | Means | Use it for |
|---|---|---|
| `/healthz` | the process answers HTTP | liveness, the image's `HEALTHCHECK` |
| `/readyz` | a pass finished recently and the state is readable; otherwise `503` with the reason | orchestrator readiness, uptime monitors |

Readiness goes stale when the last pass is older than three poll intervals
(never fewer than five minutes), so a stopped scheduler surfaces instead of
answering `ok` forever.

`/metrics` is Prometheus text for any compatible scraper:

| Metric | Meaning |
|---|---|
| `advisory_radar_pending` / `_parked` | queue depth; parked messages wait for an operator decision in the UI |
| `advisory_radar_seen_total` / `_watch_total` / `_runs_retained` | identities seen, CVEs under re-evaluation, passes retained (run history is trimmed to 200) |
| `advisory_radar_last_pass_timestamp_seconds` | when the last pass finished (`0` = never) |
| `advisory_radar_last_pass_exit` / `_sent` / `_parked` / `_pending` | what the last pass did |
| `advisory_radar_ready` | `1` when `/readyz` would answer `200` |
| `advisory_radar_state_readable` | `1` when the state document could be read; `0` means the scrape answered with only these two gauges (every other number is unknown, not zero) |
| `advisory_radar_source_up{source}` | `1` when that source's last fetch succeeded, `0` when it failed; absent until the source has been polled once |
| `advisory_radar_source_last_success_timestamp_seconds{source}` | when that source last answered (`0` = never) |
| `advisory_radar_source_items{source}` | entries in that source's last window |

Alert on `advisory_radar_ready == 0`, `advisory_radar_parked > 0`, and — for the
earliest signal — on `time() - advisory_radar_last_pass_timestamp_seconds`
exceeding a few poll intervals. A single broken feed is `advisory_radar_source_up == 0`
while every pass-level number stays green: that is the alert the run history cannot
give you, and `/sources` shows the same state with the error text beside it.

## Configuration

One YAML file (`/config/config.yml`, see `examples/config.yml`). Secrets are
`${VAR}` placeholders resolved from the environment at startup; `${VAR_FILE}`
reads the value from the file named by the `VAR_FILE` environment variable (Docker
secrets / Podman secrets pattern). The
container needs:

| Env var | Purpose |
|---|---|
| `ADVISORY_RADAR_AUTH_TOKEN` | Web UI login token (required for `run`) |
| `ADVISORY_RADAR_CONFIG` | Config path (the image sets `/config/config.yml`) |
| `ADVISORY_RADAR_PUBLIC_HTTPS` | `1` when TLS terminates in front of the container: sends HSTS. Off by default, because a wrong HSTS setting pins a browser to HTTPS |
| `ADVISORY_RADAR_INSECURE_COOKIES` | `1` only for a plain-HTTP development instance: stops marking the session cookie `Secure` |
| plus one per referenced secret | e.g. `DISCORD_WEBHOOK_URL`, `APPRISE_PASSWORD`, `FRESHRSS_TOKEN` |

Volumes: `/config` (read-only) and `/data` (state + KEV cache).

`advisory-radar sources list` prints every built-in source kind with its required
and optional keys and needs no config file. `advisory-radar sources test <id>
--limit N` loads the config strictly — a `${VAR}` missing for *any* enabled
source or notifier is a configuration error, exactly as it is for a pass — then
fetches that one source and prints its items and truncation flag. It sends no
notification, commits no state and writes no state file, so it is safe to run
against a live data volume. A `webhook` source is read from an empty inbox, so
the command prints no items for it and exits 0: it checks the configuration, not
the intake.

The UI is protected by the login token, a `SameSite=Lax` + `Secure` + `HttpOnly`
session cookie, a per-session form token on every state-changing POST, and a
throttle on failed logins (five per five minutes per peer address). Put it behind
a TLS-terminating reverse proxy; the session cookie is only sent over HTTPS unless
`ADVISORY_RADAR_INSECURE_COOKIES=1`.

### The settings overlay

`/config` writes `settings.json` beside the state file on `/data` (`/data/settings.json`
in the container, `~/.local/share/advisory-radar/settings.json` for the rootless
quadlet). It is created with mode `0600`, owned by the container user, and replaced
atomically (a temporary file in the same directory, `fsync`, `os.replace`), so a
half-written file cannot brick a start. `/config` stays read-only: the overlay holds
only seven keys — `notifiers`, per-source `enabled`/`tag`, the sources it adds itself
(`sources_added`), `poll_interval`, `hidden_source_hosts`, and the routing `routes`/`default`
block — and the YAML owns everything else. A source the overlay adds is stored whole and may
not share an id with one the YAML defines, and it may not point into a private network unless
the YAML sets `allow_private_sources: true`. While the overlay holds a
`notifiers` list it replaces the YAML's membership and ordinary fields, so a notifier
added to the YAML later is not used until that section is removed from the overlay; a
notifier's `headers` are the exception, staying in the YAML and carried over by id. A
`routes` block saved by the form replaces the YAML's rules as a whole; the form's rows are
prefilled from the saved overlay, or from the merged YAML when the overlay holds none, and
a form with every row empty leaves the YAML's rules in force.

The overlay is optional; without it the YAML is the whole configuration. An invalid one
is refused: a save shows the configuration error and writes nothing, the *Reload
configuration* button shows the refusal, `kill -HUP <pid>` logs its reason, and either
way the running configuration stays. A pass holds the state lock for its whole transaction, so a reload waits
for it (`SIGHUP`) or answers `409` (the UI), and a pass that already started finishes
with the configuration it started with; the wait between passes follows the live interval,
so a shortened `poll_interval` does not sleep out the old one. Each settings form carries a
fingerprint of the
configuration it was rendered from, so a save from a page that has not seen a newer
configuration — another save, a YAML edit, or an overlay deleted and recreated — is
refused (`409`) rather than overwriting it. The notifier form rewrites the whole list, so
every existing notifier must already use `${NAME}`/`${NAME_FILE}` references for `url`,
`key`, `password` and `token`; a literal secret in the YAML is refused with an error
naming that notifier, and has to be moved to the environment first. Pending and parked messages are not touched by a
reload. A reload re-reads the YAML and the overlay, so an edit to `config.yml` is picked
up too; `web.host`, `web.port` and `state_path` are refused rather than reported as
applied, because they are bound when the process starts, and environment variables are
read at start, so changing one still needs a restart. Deleting `settings.json` and
reloading returns to the YAML (the empty overlay is applied as revision 0). The overlay itself is capped at 64 KiB: a value that would make the file larger
is refused instead of written.

Two upstreams reward configuration rather than credentials:

- **NVD key.** `nvd_api_key: ${NVD_API_KEY}` in the config raises NVD's anonymous limit from 5 requests per
  30 s to 50 (free, requested at <https://nvd.nist.gov/developers/request-an-api-key>). The per-pass budget
  (`MAX_NVD_CALLS`) is unchanged, so a key buys **time, not breadth**: the same lookups wait 0.6 s
  each instead of 6 s, so a pass finishes sooner.
- **Conditional GET.** RSS/Atom sources keep the publisher's `ETag`/`Last-Modified` in the state, so an
  unchanged feed answers `304` and costs one round trip instead of the whole document.

### Routing

Notification routing lives in `config.yml` by default: an ordered `routes` list plus an
optional `default`, each naming notifier ids. The same block can be saved to the settings
overlay from `/config`, where it then replaces the YAML's rules. Every id must name an enabled notifier in the effective merged
configuration (a notifier the overlay adds counts, one it disables does not), or the configuration is refused
when it loads; `release-parked` and `drop-parked` read the YAML alone and do not enforce that membership, so a
route to an overlay-only channel cannot block queue recovery. With no `routes` block every message still goes
to every enabled notifier. Delivery records on the message which channels already accepted it, so when one routed channel fails
a retry re-sends the message only to the channels that have not had it — the failed channel is retried, the
others are not repeated. The README's [Routing](../README.md#routing) section lists the match keys and an
example.

### Lists, the advisory page and screenshots

`/alerts` keeps its filters in the URL (`tag`, `source`, `outcome`, `q`, `since` and
`until`, the dates as inclusive UTC days) and pages by keyset cursor rather than an offset,
so a reload, a bookmark or a shared link shows the same rows and adding an advisory cannot
shift a page. Each row links to the advisory's page (the identifier is encoded in the path, so
one containing slashes still opens), which shows the stored classification
and delivery record — tag, source, title, identifiers and CVEs, KEV-only CVEs, matched
products, per-CVE level and CVSS, and the notifiers that accepted the message — and says the details were not recorded for a seen record written by
an older version, instead of inventing them. The page never renders the message body: a
delivered record does not retain it, while a pending or parked entry still carries its body
in the queue until it leaves. The record is stored once per message and each identifier
points at it, so a message naming thousands of identifiers does not multiply it. `/parked` releases or drops one message per row as well as the whole queue, and
`/runs` filters by exit code and day; the state keeps only the last 200 passes, so the page
states that cap instead of paging.

The README screenshots are written by an opt-in script, never by the application:
`uv run --with playwright python scripts/capture_screenshots.py` (add
`--output-dir` to write elsewhere) builds a demo configuration and state in a temporary
directory, serves the app on `127.0.0.1` with a throwaway token and captures the five pages
through the real login form. Playwright is not a project dependency; install the browser
once with `uv run --with playwright playwright install chromium`. No CI job runs it.

## Multi-arch images

Releases publish `linux/amd64` and `linux/arm64`, so the same tag runs on a
normal x86 server, a Raspberry Pi and Apple Silicon. Build locally with
`docker buildx build --platform linux/arm64 -t advisory-radar .` if you need a
single-arch image.
