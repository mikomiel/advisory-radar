# Deployment

advisory-radar ships as one rootless-friendly container that runs as UID 10001.
Docker Compose and rootless Podman are both supported.

CI starts both paths end to end with [`e2e.yml`](../.github/workflows/e2e.yml): one job follows
the Compose commands below, the other installs the unmodified Podman unit for a rootless user on
the Podman that the runner provides (its log prints the version). Each job builds the image from
the change under test, then checks that the container runs that image as UID 10001, answers
`/healthz`, can write `/data` and keeps its state across a restart. Each also waits for the
container's own scheduled health check to report `healthy`, before and after the restart, and
never runs the probe by hand to get there ([Health checks](#health-checks)).

Pick one:

## Docker Compose

```bash
mkdir -p config
cp examples/config.yml config/config.yml   # edit the sources; the example's one notifier ships disabled
printf 'ADVISORY_RADAR_AUTH_TOKEN=%s\n' "$(openssl rand -hex 24)" > .env
chmod 600 .env
docker compose up -d --wait
```

The login token is the only variable a fresh copy needs. The example configuration ships
its notifier (`discord`) disabled, so the first start does not need a webhook: nothing is
sent, advisories stay queued, and each pass logs `no enabled notifiers` while any wait. To
deliver, add the notifier's variable to `.env` (`DISCORD_WEBHOOK_URL=...`), delete
`enabled: false` from that entry in `config/config.yml` and run `docker compose up -d` again.

`--wait` returns once the container reports healthy. If it does not, `docker compose ps`
shows its state and `docker compose logs advisory-radar` says why (a configuration error is
logged there). Open the UI at <http://localhost:8080>. The session cookie is `Secure`, so a
plain-HTTP trial needs `ADVISORY_RADAR_INSECURE_COOKIES=1` in `.env` (see
[Exposing the web UI](#exposing-the-web-ui)).

What the compose file sets, and why:

| Setting | Effect |
|---|---|
| `image: ghcr.io/mikomiel/advisory-radar:${ADVISORY_RADAR_TAG:-latest}` | the newest stable release, unless `.env` pins a tag ([Image tags, updates and rollback](#image-tags-updates-and-rollback)) |
| `advisory-radar-data:/data` | a named volume for the state. The image creates `/data` owned by UID 10001 and a new volume copies that owner, so it is writable with no chown and no `user:` override |
| `./config:/config:ro` | your `config.yml`, read-only |
| `127.0.0.1:8080:8080` | the UI answers on this host only ([Exposing the web UI](#exposing-the-web-ui)) |
| `cap_drop: [ALL]` and `no-new-privileges` | the process is unprivileged and needs no capability |
| `healthcheck` | the image's own probe, `advisory-radar healthcheck` ([Health checks](#health-checks)) |

`web.port` in `config.yml` (8080 in the example) is the container port the mapping targets.
The health check follows it, so change the mapping when you change the port.

### State in a directory instead of a volume

Mount a directory (`./data:/data`) instead of the named volume when you want to see, copy
or back up the state with ordinary tools, or when you are upgrading from the earlier compose
file: it mounted `./data` and ran the container as 1000:1000 unless you set
`ADVISORY_RADAR_UID` and `ADVISORY_RADAR_GID`, so your state is in that directory and the new
named volume starts empty. The directory has to be writable for whoever runs the container.
Either give it to the image's user:

```bash
sudo install -d -m 0750 -o 10001 -g 10001 data
```

or run the container as your own account: put your ids in `.env`, and uncomment the `user:`
line in the compose file.

```bash
mkdir -p data
printf 'ADVISORY_RADAR_UID=%s\nADVISORY_RADAR_GID=%s\n' "$(id -u)" "$(id -g)" >> .env
```

## Podman (quadlet, rootless)

```bash
mkdir -p ~/.config/advisory-radar ~/.local/share/advisory-radar ~/.config/containers/systemd
cp examples/config.yml ~/.config/advisory-radar/config.yml   # edit the sources; the notifier ships disabled
printf 'ADVISORY_RADAR_AUTH_TOKEN=%s\n' "$(openssl rand -hex 24)" > ~/.config/advisory-radar.env
chmod 600 ~/.config/advisory-radar.env
cp deploy/podman/advisory-radar.container ~/.config/containers/systemd/
systemctl --user daemon-reload && systemctl --user start advisory-radar
systemctl --user status advisory-radar   # the log: journalctl --user -u advisory-radar
```

There is no `systemctl enable` step: the Quadlet generator turns the unit's `[Install]`
section into the boot wiring when it generates the service. Notifier variables go in the same
env file as the token, as in the compose `.env` above.

The quadlet runs with `UserNS=keep-id:uid=10001,gid=10001`, which maps the
image's user to yours so both `~/.config/advisory-radar` (read-only config) and
`~/.local/share/advisory-radar` (state) are usable without a chown. It mounts
`~/.config/advisory-radar`, the same directory the commands above create. The env file sits
beside that directory, not in it, so it is not mounted into the container.

The unit also drops every capability (`DropCapability=ALL`), sets `NoNewPrivileges=true`,
publishes the UI on `127.0.0.1:8080` only and runs the image's own probe
(`HealthCmd=advisory-radar healthcheck`, see [Health checks](#health-checks)). It sets
`RestartSec=10` and `TimeoutStartSec=900`: a configuration error then repeats every ten
seconds in the journal instead of stopping for good once systemd's start limit trips, and the
first start has fifteen minutes to pull the image instead of the default 90 seconds.

### Prerequisites

- **Podman 4.5 or newer.** Quadlet starts at 4.4 and gained keys release by release. This unit
  needs 4.5: that release added the health check keys (`HealthCmd=` and the other `Health*`
  keys) and the UID and GID options of `UserNS=keep-id`. The unit
  is checked against the Quadlet generator of Podman 5.4.2: use that or newer. A Podman that does
  not know a key skips the whole unit and starts nothing. `/usr/libexec/podman/quadlet -dryrun -user`
  prints the reason (`unsupported key '...'`) or the service it would generate; the path of
  that binary differs between distributions.
- **Lingering.** A user unit stops when the user's last session ends and does not start at
  boot until you run `sudo loginctl enable-linger <user>` once.
- **A shell that reaches the user manager.** `systemctl --user` and `journalctl --user` talk
  to the user's systemd instance. A login over SSH or on a console has it. After `su` or
  `sudo -iu <user>` it is usually missing (`Failed to connect to bus`): open the shell with
  `sudo machinectl shell <user>@`, or export `XDG_RUNTIME_DIR=/run/user/$(id -u)` first (that
  directory exists while the user is logged in or lingering).
- **Sub-ids.** Rootless Podman maps the container's other ids through the user's ranges in
  `/etc/subuid` and `/etc/subgid` (`grep <user> /etc/subuid /etc/subgid` shows them;
  `sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 <user>` adds an
  example range; pick one that no other user holds). In an unprivileged LXC container the
  ranges must lie inside the ids the container itself was given: a range that reaches beyond
  them makes the first `podman run` fail while it sets up the user namespace, and the error
  mentions `newuidmap`. When you cannot give the user a range that fits, use the rootful
  variant below.

### Rootful variant

Run Podman as root and let the image keep its non-root user when a user namespace is not
available: the sub-id ranges above do not fit, or nobody wants a lingering user. Copy the unit
to `/etc/containers/systemd/` and change five lines, because `%h` is root's home in a system
unit and `UserNS=keep-id` exists only for rootless Podman. Create the directories first, with
the data directory owned by the image's user and the env file beside the configuration
directory, not in it:

```bash
sudo install -d -o 10001 -g 10001 -m 0750 /var/lib/advisory-radar
sudo install -d /etc/advisory-radar
sudo cp examples/config.yml /etc/advisory-radar/config.yml
printf 'ADVISORY_RADAR_AUTH_TOKEN=%s\n' "$(openssl rand -hex 24)" | sudo install -m 600 /dev/stdin /etc/advisory-radar.env
sudo cp deploy/podman/advisory-radar.container /etc/containers/systemd/
```

| In the copied unit | Becomes |
|---|---|
| `Volume=%h/.config/advisory-radar:/config:ro` | `Volume=/etc/advisory-radar:/config:ro` |
| `Volume=%h/.local/share/advisory-radar:/data` | `Volume=/var/lib/advisory-radar:/data` |
| `UserNS=keep-id:uid=10001,gid=10001` | `User=10001` and `Group=10001` (two lines) |
| `EnvironmentFile=%h/.config/advisory-radar.env` | `EnvironmentFile=/etc/advisory-radar.env` |
| `WantedBy=default.target` | `WantedBy=multi-user.target` |

Then `sudo systemctl daemon-reload && sudo systemctl start advisory-radar`. The unit is a
system service, so the status and the log are `systemctl status advisory-radar` and
`journalctl -u advisory-radar`, and it needs neither lingering nor a user manager. Run
`/usr/libexec/podman/quadlet -dryrun` (no `-user`) to see the service it generates: the
paths are the absolute ones above and the container starts with `--user 10001:10001`.

## Image tags, updates and rollback

A release tag `vX.Y.Z` publishes `ghcr.io/mikomiel/advisory-radar:vX.Y.Z`, and a stable
release also moves `latest`; a pre-release never does. The compose file and the quadlet in
this repository rely on two things the image gained with them, the `healthcheck` command and
a `/data` owned by UID 10001. Releases up to 0.3.1 have neither, so run a later release or
build this checkout (`docker build -t ghcr.io/mikomiel/advisory-radar:latest .`).

**Pin a release.** With `latest`, any pull can change the application, so pin the tag you
have read the notes for ([CHANGELOG.md](../CHANGELOG.md)). In Compose set
`ADVISORY_RADAR_TAG=vX.Y.Z` in `.env`; in the quadlet set
`Image=ghcr.io/mikomiel/advisory-radar:vX.Y.Z`. A tag can in principle be moved; to pin the
exact bytes use the digest (`docker buildx imagetools inspect <image>:vX.Y.Z` prints it) as
`ghcr.io/mikomiel/advisory-radar@sha256:<digest>` in the compose `image:` line or in `Image=`.

**Verify a release.** Every release image carries a build provenance attestation signed by
the release workflow. Check a tag before you first run it:

```bash
gh attestation verify oci://ghcr.io/mikomiel/advisory-radar:vX.Y.Z --repo mikomiel/advisory-radar
```

**Update.** Read the release notes, then copy the data first: stop the service and copy the
data volume or directory. A release that changes the state schema writes a document an older
release refuses to read (`the state file is from another version`), so the copy is also your
way back.

- Compose: set the new tag in `.env`, then `docker compose pull && docker compose up -d --wait`.
  With `latest` the same two commands fetch whatever is newest.
- Podman, pinned tag: edit `Image=` in `~/.config/containers/systemd/advisory-radar.container`,
  then `systemctl --user daemon-reload && systemctl --user restart advisory-radar`. The
  restart pulls the new tag, which can take a while (`TimeoutStartSec=900`).
- Podman, `latest`: `podman pull ghcr.io/mikomiel/advisory-radar:latest` first. The restart
  alone does not, because the image is already present.

**Roll back.** Put the previous tag (or digest) back and run the update commands again. If
the newer release already wrote the state, restore the copy you took before the update
first.

`podman auto-update` is opt-in and the quadlet does not enable it. It re-pulls the tag a unit
names, so turning it on (`AutoUpdate=registry` and the `podman-auto-update.timer`) means
following that tag unattended: on `latest` every stable release is applied without a review,
and on a pinned `vX.Y.Z` it changes nothing. Enable it only for a tag policy you have
chosen on purpose.

## Exposing the web UI

The compose file and the quadlet publish the UI on `127.0.0.1:8080`, so only the host itself
reaches it. The UI has a login and no TLS of its own, and its session cookie is `Secure`.
Earlier versions of these files published on every interface: if you reached the UI from
another machine, that stops working after you update them, by design.

To reach it from other machines, put a TLS-terminating reverse proxy on the host and forward
to `127.0.0.1:8080`, then set `ADVISORY_RADAR_PUBLIC_HTTPS=1` so the UI sends HSTS. Keep the
published address on loopback: the proxy reaches it there and nothing else needs to. A proxy
that runs as a container in the same compose project can reach the service as
`advisory-radar:8080` over the compose network, and then the `ports:` entry can go.

Change the address to `0.0.0.0` only when something else decides who can connect. With
Docker, a host firewall such as `ufw` is not that: published ports bypass its rules. The
application throttles failed logins per connecting address, which behind a proxy is the
proxy's address, so add rate limiting at the proxy if you need a limit per client.

A plain-HTTP trial on one machine works with `ADVISORY_RADAR_INSECURE_COOKIES=1` in `.env`
(Compose) or in the env file (Podman). Do not keep that setting on an instance anyone else
can reach.

## Keeping secrets out of .env

A mode 600 `.env` is enough on a host only you use. To keep a secret out of it:

- **Notifier and source secrets** already take a file. Write `${DISCORD_WEBHOOK_URL_FILE}`
  instead of `${DISCORD_WEBHOOK_URL}` in `config.yml`, and set `DISCORD_WEBHOOK_URL_FILE` to
  the path of a file that holds the value (see [Configuration](#configuration)).
- **The login token** can come from a file through `ADVISORY_RADAR_AUTH_TOKEN_FILE`. That
  variable needs a release that reads it; releases up to 0.3.1 read only
  `ADVISORY_RADAR_AUTH_TOKEN`, so check [CHANGELOG.md](../CHANGELOG.md) before you rely on
  it. Until then keep the token in `.env`, or use a Podman secret as below.

For a file secret with Compose, create the file where only you can reach it. The container's
user is UID 10001, not you, so the file itself has to be readable by others; the directory
around it keeps that from exposing the file on the host:

```bash
mkdir -m 0700 secrets
printf '%s' "$(openssl rand -hex 24)" | install -m 0444 /dev/stdin secrets/advisory_radar_token
```

A checkout of this repository lists `secrets/` in `.gitignore` and `.dockerignore`, so the file
is neither staged by `git add .` nor uploaded to a remote builder as part of the build context.
If you keep the compose file in another repository or directory, add `secrets/` to that
project's `.gitignore`, and to its `.dockerignore` if you build an image there.

Then remove `ADVISORY_RADAR_AUTH_TOKEN` from `.env` and uncomment the three marked pieces in
`docker-compose.yml`: `ADVISORY_RADAR_AUTH_TOKEN_FILE: /run/secrets/advisory_radar_token`
under `environment:`, `secrets: [advisory_radar_token]` under the service, and the top-level
`secrets:` block that points at `./secrets/advisory_radar_token`. The same shape works for a
notifier's `..._FILE` variable.

For Podman, a secret of type `env` hands the value to the container as the environment
variable, so it leaves the env file but not the container's environment. Create it from
your terminal, without the value in a command line or the shell history, and enable the
commented `Secret=` line in the unit:

```bash
read -rsp 'Login token: ' token; echo      # bash
printf '%s' "$token" | podman secret create advisory-radar-token -
unset token
# in the unit, after removing ADVISORY_RADAR_AUTH_TOKEN from the env file:
# Secret=advisory-radar-token,type=env,target=ADVISORY_RADAR_AUTH_TOKEN
```

The rootful variant uses the same commands with `sudo`; a secret belongs to the user whose
Podman creates it.

## Health checks

The image, the compose file and the quadlet all run one probe, `advisory-radar healthcheck`.
It reads one number from the YAML file (`ADVISORY_RADAR_CONFIG`, which the image sets to
`/config/config.yml`): `web.port`, which is 8080 when the file does not set it. It asks
`http://127.0.0.1:<port>/healthz` and exits 0 on a `200`. On anything else (a refused
connection, no answer within 3 seconds, another status, a file it cannot read, a `web.port`
that is not a number from 1 to 65535) it exits 1 and prints the reason on one line, which the
container runtime keeps as the health log (`State.Health` in `docker inspect` and
`podman inspect`).

The probe sends no credential and ignores proxy variables, and it only ever talks to the
loopback address of its own container. It reads nothing but that file: it expands no
`${VARIABLE}`, opens no `${VARIABLE_FILE}` secret, does not merge the settings saved in the
web UI (they cannot change `web.port`, which is bound when the process starts) and validates
no other setting. The service checks its own configuration when it starts, so a
`${VARIABLE}` that only a notifier needs, or a value that the UI has replaced, cannot turn a
running service unhealthy.

It is a liveness check: it passes while the process answers HTTP. `/readyz` is the check for
whether passes keep finishing (see [Monitoring](#monitoring-beszel-and-friends)). Run it by
hand:

```bash
docker compose exec advisory-radar advisory-radar healthcheck
podman exec advisory-radar advisory-radar healthcheck   # or: podman healthcheck run advisory-radar
```

On Podman the scheduled check is a systemd timer that Podman creates for the container.
`podman healthcheck run` runs the probe once and records its result in the same status and
log, so a `healthy` status right after it does not show that the timer works. Without a
manual run, `podman inspect --format '{{.State.Health.Status}}' advisory-radar` turns
`healthy` by itself once the first scheduled check has passed, and the log
(`podman inspect --format '{{json .State.Health.Log}}' advisory-radar`) gains an entry every
interval (30 s) after that.

If you start the image with another configuration path, set `ADVISORY_RADAR_CONFIG` to it
instead of passing `--config` on the command line: the probe reads the variable, so a flag
would leave it looking at a different file than the service.

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
| `advisory_radar_source_up{source}` | `1` when that source's last fetch succeeded, `0` when it failed; absent until the source has been polled once. The label is the configured source id, which the validator keeps a name — a whole `${NAME}` reference in an id is refused |
| `advisory_radar_source_last_success_timestamp_seconds{source}` | when that source last answered (`0` = never) |
| `advisory_radar_source_items{source}` | entries in that source's last window |

Alert on `advisory_radar_ready == 0`, `advisory_radar_parked > 0`, and — for the
earliest signal — on `time() - advisory_radar_last_pass_timestamp_seconds`
exceeding a few poll intervals. A broken feed also fails the pass and shows up in
`advisory_radar_last_pass_exit`, but that number says a pass failed, not which feed did:
`advisory_radar_source_up{source}` is the per-source signal, and `/sources` shows the same
state with the error text beside it.

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

Volumes: `/config` (read-only) and `/data` (the state file, `settings.json`, the KEV cache and, with no
`watchlist:` key, `watchlist.json`), which the image creates owned by UID 10001 with mode `0750`. An
advisory's identity is kept exactly as the publisher sent it — only its log and display spelling
is escaped — because transforming an identity can merge two advisories into one.

`/watchlist` edits the scope document where it lives. With no `watchlist:` key that is
`watchlist.json` beside `state_path`, which is writable: a document on the `/config` mount can be
read but not saved, so a deployment that wants the browser editor keeps it on `/data`. The
document is replaced atomically with mode `0600` under a lock on `watchlist.json.lock` (the same
sidecar-lock mechanism the state file uses), and a save is refused when the file changed under the
page, so two tabs or two processes cannot silently overwrite each other. A save needs no reload:
the pass reads the policy on every run.

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
a TLS-terminating reverse proxy ([Exposing the web UI](#exposing-the-web-ui)); the session cookie is only sent over HTTPS unless
`ADVISORY_RADAR_INSECURE_COOKIES=1`.

### Storage

`storage:` in `config.yml` moves the state document without changing its model. Empty is
the default and means the JSON file at `state_path`; `sqlite:////data/state.db` keeps one
file on the volume for one host; `postgresql://user:password@host/database` shares one
document between instances and needs the optional `postgres` extra, which installs the
driver into the interpreter that runs the product:

```bash
uv sync --extra postgres
```

The container image installs the same extra, so the PostgreSQL store needs no separate image
build. This is packaging evidence, not live PostgreSQL acceptance: the driver path is
unit-tested against a fake connection.

Three slashes make a SQLite path relative to the working directory; four make it absolute.
`sqlite:////data/state.db` is `/data/state.db` in the container, while
`sqlite:///data/state.db` is `data/state.db` under the image's working directory (`/data`) —
that is, `/data/data/state.db`.

The key is YAML-only. The overlay cannot move the store, and a reload refuses a changed
`storage:` as it refuses a changed `state_path`, so moving it is a restart.
`settings.json`, the KEV cache and the default `watchlist.json` stay beside `state_path` and are
not part of the document, which is why `state_path` is still required when the document lives
elsewhere.

`advisory-radar migrate --config /config/config.yml --to sqlite:////data/state.db` copies
the document read through the configured store into another one. It refuses a target that
already holds a document and prints both stores, never the URL, which can carry a password.
The source is left in place: set `storage:` and restart once the copy looks right. Run it
against a quiesced source: the command reads one consistent snapshot, but a pass that keeps
running can record deliveries, parked messages and seen identifiers after that snapshot, and
nothing in the copy accounts for them, so stop the service (or copy the store) first.

The rest of the PostgreSQL behaviour is unit-tested against a fake connection rather than
a live server: the advisory lock, the connection that carries it and the credential
scrubbing are pinned by tests, so treat a switch to the PostgreSQL store as a change to verify
on the target database first.

### The settings overlay

`/config` writes `settings.json` beside `state_path` on `/data` (`/data/settings.json`
in the container, `~/.local/share/advisory-radar/settings.json` for the rootless
quadlet). It is created with mode `0600`, owned by the container user, and replaced
atomically (a temporary file in the same directory, `fsync`, `os.replace`), so a
half-written file cannot brick a start. It is not part of the state document, whichever
store holds that. `/config` stays read-only: the overlay holds
only ten keys — `notifiers`, per-source `enabled`/`tag`/`thresholds`/`interval`, the sources it
adds itself (`sources_added`), `poll_interval`, `hidden_source_hosts`, the routing
`routes`/`default` block, the risk `thresholds`, the delivery `digest` switch and the
`quiet_hours` window — and the YAML owns everything else. A source the overlay adds is stored whole, may not
share an id with one the YAML defines, must have a literal id, and may not point into a private
network unless the YAML sets `allow_private_sources: true`. That last check is a guard rail
against a mistake rather than an isolation boundary — the pass resolves the name again when it
fetches — and the operator token is a full-trust credential, so treat it accordingly. A feed
URL discovered from a page's `<link rel="alternate">` is held to two rules, both checked
before it is fetched and neither relaxed by `allow_private_sources`: it must share the
page's own origin — the same scheme, host and port — and it must not resolve to a loopback
or private address. The first is the containment: the page's own host is the one the
operator already chose, so discovery cannot redirect the reader to a host an attacker
picked, and a feed genuinely served from another host is configured directly. The second
keeps the existing guard rail, because that URL was chosen by a remote page, not by the
operator. While the overlay holds a
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
refused (`409`) rather than overwriting it. It also carries the overlay revision, and the
save takes `settings.json.lock` (the same sidecar lock the state file and the watchlist use)
around the read, the revision comparison, the increment and the replace, so two processes
sharing one `/data` volume serialise their writes: both cannot read revision 0 and write
revision 1, and a form rendered from an older revision is refused with `409` instead of
replacing the newer document. A shared-volume multi-instance deployment is supported at
that granularity — settings writes serialise, and each process applies a saved revision only
when it reloads. The notifier form rewrites the whole list, so
every existing notifier must already use `${NAME}`/`${NAME_FILE}` references for `url`,
`key`, `password`, `secret` and `token`; a literal secret in the YAML is refused with an error
naming that notifier, and has to be moved to the environment first. Pending and parked messages are not touched by a
reload. A reload re-reads the YAML and the overlay, so an edit to `config.yml` is picked
up too; `web.host`, `web.port`, `state_path` and `storage` are refused rather than reported as
applied, because they are bound when the process starts, and environment variables are
read at start, so changing one still needs a restart. Deleting `settings.json` and
reloading returns to the YAML (the empty overlay is applied as revision 0). The overlay itself is capped at 64 KiB: a value that would make the file larger
is refused instead of written.

Two upstreams reward configuration rather than credentials:

- **NVD key.** `nvd_api_key: ${NVD_API_KEY}` in the config raises NVD's anonymous limit from 5 requests per
  30 s to 50 (free, requested at <https://nvd.nist.gov/developers/request-an-api-key>). The per-pass budget
  (`MAX_NVD_CALLS`) is unchanged, so a key buys **time, not breadth**: the same lookups wait 0.6 s
  each instead of 6 s, so a pass finishes sooner.
- **Conditional GET.** An `rss` source keeps the publisher's `ETag`/`Last-Modified` in the state, so an
  unchanged feed answers `304` and costs one round trip instead of the whole document. A URL that answers an
  HTML page is followed once through the page's feed autodiscovery link; no validator is stored for that
  hop, because a page's `ETag` says nothing about the feed it advertises.
- **Per-source pace.** `interval: 30m` on a source entry (the same `<n><s|m|h>` spelling as
  `poll_interval`) thins only that source's fetching; an absent key follows the global interval. The pass
  still re-evaluates, escalates and delivers for every source, and a failed fetch is retried on the next
  pass rather than waiting out the interval. The key is accepted by every kind and is editable on `/config`.

### Risk thresholds

The severity decision reads three numbers, from a `thresholds` block in `config.yml` or from
the overlay (the block is merged key by key, so a saved number leaves the YAML's other two in
force; an empty field on the form stops overriding that key):

```yaml
thresholds:
  critical_cvss: 9.0        # 0 < x <= 10
  critical_epss: 0.10       # 0 < x <= 1
  suppress_below_cvss: 4.0  # 0 <= x <= critical_cvss
```

`critical_cvss` and `critical_epss` decide when a CVE is critical (with a remote,
unauthenticated, no-interaction vector, or with EPSS); `suppress_below_cvss` is the floor
below which a completely measured CVE is recorded and watched but never sent. The note a
message carries names the configured bar, not a hardcoded one, and the validation refuses a
non-number, a value outside its range, and a floor above the critical bar.

A source entry may carry its own `thresholds` block, in the YAML's `sources:` list, in the
overlay's per-source edit (`sources: {nodejs: {thresholds: {...}}}`) or in an entry the
overlay adds (`sources_added`). It may be partial: the keys it states are merged over the
global block, key by key, and the merged block is validated by the same rules and ranges,
with the source's id prefixed to a refusal (`nodejs: thresholds.critical_cvss must be a
number`). An overlay edit of a YAML source merges its block key by key too, so a saved number
never drops the file's other keys for that source; a source with every field empty on
`/config` keeps no overlay block and follows the global one. A disabled source's block is not
resolved until it is enabled, exactly as its `${NAME}` references are not.

Changing a threshold changes the rules, so it does not send the watch list out: every
watched CVE records the numbers it was judged under — its source's own block when it has one
— and the first evaluation after a change records the new verdict without telling anyone. A
source's block moving re-baselines only the CVEs that source queued, and the global block
moving reaches a source only through the numbers that source does not state itself. The entry
keeps the level the reader was told
(`level`) apart from the level the numbers in force make of it (`judged`), so a KEV hit or a
CISA active flag that arrives later still escalates against what was actually sent. State
written before the source was recorded, and a hand-edited record whose source or numbers
cannot be read, is judged by the global block and never raises.

`/thresholds`, linked from `/config`, previews one advisory against the live numbers — the
previewed source's own block when it has one, and the global block otherwise — and names
which of the two it used. It shows the level, the reason, the metrics line and note the
message would carry, and the route and notifiers it would reach, including a `min_cvss`,
`epss_gte` or `kev` predicate evaluated from the CVSS, EPSS and KEV state you typed. The
advisory's identifiers are an input, because a rule may match on them; without one and with
such a rule configured, the page says the destination cannot be predicted instead of guessing.
The same is said for a `kev` rule when the catalog state is "unknown", because membership was
then not measured. A numeric or `kev` predicate is also not predicted without the advisory's
CVE id: the classifier records a score per CVE it judged, so a typed advisory-level score is
not the measurement such a rule reads, and the page asks for the CVE id rather than inventing
one. It is a read-only GET, so a link to it can be shared.

### Routing

Notification routing lives in `config.yml` by default: an ordered `routes` list plus an
optional `default`, each naming notifier ids. The same block can be saved to the settings
overlay from `/config`, where it then replaces the YAML's rules. A rule's `match` may carry a
source id, a severity tag, a watchlist product, an ids pattern, `min_cvss`, `epss_gte` and
`kev`; every key present must match, and the three predicates read the CVSS, EPSS and KEV
membership the classification measured for the message, so a message with no measured score
satisfies no numeric predicate and an unmeasured KEV membership satisfies neither `kev: true`
nor `kev: false`. The validator refuses a numeric predicate outside its range and a `kev` that
is not a boolean, as it refuses an unknown match key. Every id must name an enabled notifier in the effective merged
configuration (a notifier the overlay adds counts, one it disables does not), or the configuration is refused
when it loads; `release-parked` and `drop-parked` read the YAML alone and do not enforce that membership, so a
route to an overlay-only channel cannot block queue recovery. With no `routes` block every message still goes
to every enabled notifier. Delivery records on the message which channels already accepted it, so when one routed channel fails
a retry re-sends the message only to the channels that have not had it — the failed channel is retried, the
others are not repeated. The [routing](configuration.md#routing) section lists the match keys and an
example.

### Delivery policy and signed webhooks

Two YAML keys, both editable on `/config`, decide how a pass sends what it queued. `digest: true`
sends one message per routing group instead of one per advisory: the title states the count, the
body lists one advisory per line (title plus up to three short identifiers), the tag is
`critical` when any covered advisory is, and the message is capped at 20 lines and at the
character budget one Discord message accepts. Anything beyond either cap is counted in a final
`(+N more not listed)` line. Entries are grouped by the notifiers `routing.select` chooses, so
a digest never mixes channels. A digest is posted once per destination, so a failed attempt
counts once against every covered advisory, and delivery records each of them separately; a
destination that already accepted an advisory is not sent it again, and a rebuilt digest carries
only the advisories that destination still needs.

`quiet_hours: "22:00-07:00"` is a local-time window, wrapping midnight and half-open (07:00 is
outside it) during which **non-critical** messages wait in `pending`; they are not failed
attempts and go out after the window. A critical message is never held, and a held message does
not take one of the pass's delivery slots, so a queue of them cannot delay a critical advisory
behind it. An empty value turns
the window off, and `00:00-00:00` is an empty window. The window is read in the process's local
timezone, which is UTC in the container unless `TZ` is set. Both keys are overlay-writable.

A generic `webhook` notifier may carry `secret: ${WEBHOOK_SIGNING_SECRET}`. With one set, each
request carries `X-ADR-Timestamp` (Unix seconds, the integer part of the clock) and
`X-ADR-Signature`: `sha256=` followed by the lowercase hex HMAC-SHA256 of
`timestamp + "." + body`, keyed with the secret and computed over the exact bytes posted. A
receiver verifies a request by refusing a timestamp more than 300 seconds from its own clock,
reading the raw body bytes, recomputing
`hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()`
and comparing the two with `hmac.compare_digest`. With no secret, neither header is sent and
the request is unchanged. The overlay stores the secret only as a reference, and a `secret`
written in the YAML is carried over by id when the notifier form rewrites the list.

### Lists, the advisory page and screenshots

`/alerts` keeps its filters in the URL (`tag`, `source` — the configured source id, never the
advisory heading — `outcome`, `q`, `since` and `until`, the dates as inclusive UTC days) and
pages by keyset cursor rather than an offset, so a reload, a bookmark or a shared link shows
the same rows and adding an advisory cannot shift a page. Each row links to the advisory's
page (the identifier is encoded in the path, so one containing slashes still opens), which
shows the stored classification and delivery record — tag, source id and heading, title,
identifiers and CVEs, KEV-only CVEs, matched products, per-CVE level and CVSS, and the
notifiers that accepted the message — and says the details were not recorded for a seen
record written by an older version, instead of inventing them. Later escalation and Adobe
delivery events are listed below it (an Adobe bulletin has no other record), and `/alerts`
shows the latest of them under **Recent notifications**. The page never renders the message body: a
delivered record does not retain it, while a pending or parked entry still carries its body
in the queue until it leaves. The record is stored once per message and each identifier
points at it, so a message naming thousands of identifiers does not multiply it.
`/inbox` is the work list over the queue, quiet-window holds, carried work, the parked queue
and the delivery history, with its own URL filters (`state`, `tag`, `source`, `q`, `since`,
`until`) and the same keyset pagination. One row per identifier keeps every fact the state holds
about it: the state and tag filters select one fact (so a co-named message cannot hide a parked
critical), the other facts are listed under **Also**, related identifiers are shown rather than
merged, and the page says remediation is not tracked.
`/parked` releases or drops one message per row as well as
the whole queue, and `/runs` filters by exit code and day; the state keeps only the last 200
passes, so the page states that cap instead of paging. The dashboard above the queue counts
undelivered criticals, quiet-window holds, parked and awaiting-classification work, each count
linking to the filtered inbox view, and marks a pass that exited 0 with work outstanding as
deferred work.

The UI screenshots are written by an opt-in script, never by the application:
`uv run --with playwright python scripts/capture_screenshots.py` (add
`--output-dir` to write elsewhere) builds a demo configuration and state in a temporary
directory, serves the app on `127.0.0.1` with a throwaway token and captures the seven pages
through the real login form (`dashboard`, `inbox`, `alerts`, `parked`, `config`,
`watchlist` and `runs`). Playwright is not a project dependency; install the browser once with
`uv run --with playwright playwright install chromium`. No CI job runs it.

## Multi-arch images

Releases publish `linux/amd64` and `linux/arm64`, so the same tag runs on a
normal x86 server, a Raspberry Pi and Apple Silicon. Build locally with
`docker buildx build --platform linux/arm64 -t advisory-radar .` if you need a
single-arch image.
