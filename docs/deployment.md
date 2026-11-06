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
Service on 8080. `/healthz` is the probe, `/metrics` the Prometheus scrape
endpoint.

## Monitoring (Beszel and friends)

Run the usual `beszel-agent` on the same host — the container's own CPU/RAM/
disk are covered by host metrics. For app-level signal, scrape
`http://<host>:8080/metrics` with any Prometheus-compatible scraper
(`advisory_radar_pending`, `advisory_radar_parked`, `advisory_radar_seen_total`,
`advisory_radar_last_pass_exit`), and alert on `/healthz` failing or
`advisory_radar_parked > 0` (parked messages wait for an operator decision in
the UI).

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

The UI is protected by the login token, a `SameSite=Lax` + `Secure` + `HttpOnly`
session cookie, a per-session form token on every state-changing POST, and a
throttle on failed logins (five per five minutes per peer address). Put it behind
a TLS-terminating reverse proxy; the session cookie is only sent over HTTPS unless
`ADVISORY_RADAR_INSECURE_COOKIES=1`.

## Multi-arch images

Releases publish `linux/amd64` and `linux/arm64`, so the same tag runs on a
normal x86 server, a Raspberry Pi and Apple Silicon. Build locally with
`docker buildx build --platform linux/arm64 -t advisory-radar .` if you need a
single-arch image.
