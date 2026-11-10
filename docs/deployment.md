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

Alert on `advisory_radar_ready == 0`, `advisory_radar_parked > 0`, and — for the
earliest signal — on `time() - advisory_radar_last_pass_timestamp_seconds`
exceeding a few poll intervals.

## Configuration

One YAML file (`/config/config.yml`, see `examples/config.yml`). Secrets are
`${VAR}` placeholders resolved from the environment at startup; `${VAR}_FILE`
reads the value from a file (Docker secrets / Podman secrets pattern). The
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
only four keys — `notifiers`, per-source `enabled`/`tag`, `poll_interval` and
`hidden_source_hosts` — and the YAML owns everything else.

The overlay is optional; without it the YAML is the whole configuration. An invalid one
is refused: a save shows the configuration error and writes nothing, and a reload — the
*Reload configuration* button or `kill -HUP <pid>` — logs the error and keeps the running
configuration. A pass holds the state lock for its whole transaction, so a reload waits
for it (`SIGHUP`) or answers `409` (the UI), and a pass that already started finishes
with the configuration it started with. Pending and parked messages are not touched by a
reload. Changing an environment variable that a `${NAME}` reference reads still needs a
restart.

Two upstreams reward configuration rather than credentials:

- **NVD key.** `nvd_api_key: ${NVD_API_KEY}` in the config raises NVD's anonymous limit from 5 requests per
  30 s to 50 (free, requested at <https://nvd.nist.gov/developers/request-an-api-key>). The per-pass budget
  (`MAX_NVD_CALLS`) is unchanged, so a key buys **time, not breadth**: the same lookups wait 0.6 s
  each instead of 6 s, so a pass finishes sooner.
- **Conditional GET.** RSS/Atom sources keep the publisher's `ETag`/`Last-Modified` in the state, so an
  unchanged feed answers `304` and costs one round trip instead of the whole document.

## Multi-arch images

Releases publish `linux/amd64` and `linux/arm64`, so the same tag runs on a
normal x86 server, a Raspberry Pi and Apple Silicon. Build locally with
`docker buildx build --platform linux/arm64 -t advisory-radar .` if you need a
single-arch image.
