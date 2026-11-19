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
named volume starts empty. The directory and every file in it have to belong to whoever runs
the container: the service writes its state, settings and lock files with mode 0600, so a file
that another UID owns cannot be read.

For a new, empty directory, give it to the image's user:

```bash
sudo install -d -m 0750 -o 10001 -g 10001 data
```

When you upgrade and `data` already holds state, the simplest path is to keep running as the
account that wrote it: put your ids in `.env` and uncomment the `user:` line in the compose
file.

```bash
printf 'ADVISORY_RADAR_UID=%s\nADVISORY_RADAR_GID=%s\n' "$(id -u)" "$(id -g)" >> .env
```

To move existing state to the image's user instead, stop the service, back the directory up,
and change the owner of the directory and everything in it:

```bash
docker compose down
tar -czf advisory-radar-data-backup.tgz data
sudo chown -R 10001:10001 data
sudo chmod 0750 data
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
  keys) and the UID and GID options of `UserNS=keep-id`. CI starts the unit on the Podman 4.9
  series that Ubuntu 24.04 ships, and its generator was also checked with 5.4.2. A Podman that does
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

`/readyz` and `/metrics` need no login, so both answer from one read of the state document that
is reused for five seconds, a failed read included. A loop of requests, or a scrape interval
shorter than that, costs one read per window instead of one per request, and an answer can be up
to five seconds behind the state. The window is far shorter than the staleness rule above, so it
cannot change a verdict. Every page behind the login reads the state live.

`/metrics` is Prometheus text for any compatible scraper:

| Metric | Meaning |
|---|---|
| `advisory_radar_pending` / `_parked` | queue depth; parked messages wait for an operator decision in the UI |
| `advisory_radar_seen_total` / `_watch_total` / `_runs_retained` | identities seen, CVEs under re-evaluation, passes retained (run history is trimmed to 200) |
| `advisory_radar_last_pass_timestamp_seconds` | when the last pass finished (`0` = never) |
| `advisory_radar_last_pass_exit` / `_sent` / `_parked` / `_pending` | what the last pass did |
| `advisory_radar_last_pass_incomplete` / `_deferred` | `1` when the last pass ran out of its [pass budget](configuration.md#the-pass-budget), and how many units of work (sources, the Adobe Commerce pass, candidates) it left for the next pass; both `0` otherwise. An incomplete pass still has exit `0` |
| `advisory_radar_enrichment_cves{state}` | watched CVEs by how their enrichment stands ([Capped CVEs](configuration.md#capped-cves)): `measured`, `kev_only` (named by a message and never measured), `deferred` (the time budget or the NVD allowance ended the lookup, which is not counted as a try) and `failed` (a provider did not answer in full). Every state has a sample, `0` included |
| `advisory_radar_enrichment_oldest_age_seconds` | seconds the longest-waiting CVE with outstanding enrichment has waited; `0` when none is outstanding |
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

One `incomplete` pass is the pass budget doing its job: the work it left is stored and the next pass starts with it.
`advisory_radar_last_pass_incomplete` staying `1` across several passes means an upstream that is too slow, or a
`pass_budget` that is too small for the number of sources; `advisory_radar_source_up{source}` and `/sources` name the
slow source first.

## Passes, the state lock and shutdown

One pass runs at a time per state document. A pass holds the state lock from when it starts reading the state until
its last write: the fetches, the lookups, the delivery and the run record. The lock is an `flock` on a sidecar file
beside the JSON file, a write lock on a sidecar database for SQLite and a session advisory lock for PostgreSQL, so
a second instance on the same store waits behind the first in the same way. `dry-run` takes no lock and writes
nothing.

What waits behind a running pass, and how:

- the scheduler and `advisory-radar once` wait for it, however long it takes;
- *Run a pass now* answers at once that a pass is already running and does nothing;
- `POST /webhooks/<id>` answers `503` with `Retry-After: 30` and queues nothing, so the sender retries;
- releasing or dropping one parked message answers `409` and changes nothing, while the bulk actions wait for the
  lock;
- a configuration reload waits (`SIGHUP`) or answers `409` (the UI);
- the pages, `/readyz` and `/metrics` read the state without the lock, and answer while a pass runs.

The [pass budget](configuration.md#the-pass-budget) bounds how long the pass can wait on other people's servers:
10 minutes by default. Delivery runs after that part, outside the budget, with the ordinary per-request limits and
the cap on messages per pass, so the longest a pass holds the lock is its budget plus its delivery. The pass makes
its requests one after another; the budget adds no parallel requests.

Nothing cancels a running pass. The budget does not interrupt running code: it cuts each request at what is left,
whether the request is connecting to one of the addresses of a host name, in its TLS handshake or waiting for the
answer, and stops the next from starting. A pass can therefore overrun it only by work that is not a request, by
resolving a host name, which the system resolver does not let anyone cut short, and by sending a request, which keeps
its 30-second limit. `SIGTERM` and `SIGINT`
stop the web server, then ask the scheduler to stop and wait 5 seconds for it. The scheduler checks that request
between passes only, so a pass that is still running when the process exits is ended where it stands. That loses
nothing the state had already recorded:

- the lock is released with the process (the operating system drops an `flock`, SQLite rolls back and closes the
  sidecar, PostgreSQL ends the session), so an interrupted pass never leaves it held;
- the state is written after each source's candidates, once before the first notification and after each channel
  accepts a notification, and the run record last. A source's cursor or validator moves in the same write as its
  candidates, so a window that was read and not yet written is read again;
- what the budget deferred (`fetch_deferred`, the carried candidates) is part of that document, so a restart
  continues from it;
- the one thing that can repeat is a notification a channel accepted just before the process ended, as the
  acknowledgement had not been written yet: it is sent again to that channel at the next pass.

## Configuration

One YAML file (`/config/config.yml`, see `examples/config.yml`). Secrets are
`${VAR}` placeholders resolved from the environment at startup; `${VAR_FILE}`
reads the value from the file named by the `VAR_FILE` environment variable (Docker
secrets / Podman secrets pattern). The
container needs:

| Env var | Purpose |
|---|---|
| `ADVISORY_RADAR_AUTH_TOKEN` | Web UI login token (required for `run`, from this variable or the `_FILE` form). At least 24 characters: `openssl rand -hex 24` makes 48. The session cookie is signed with it |
| `ADVISORY_RADAR_AUTH_TOKEN_FILE` | Path of a file holding the login token (Docker/Podman secret). Set this or `ADVISORY_RADAR_AUTH_TOKEN`, never both: the process refuses to start. The file is read once at startup, so a rotated secret needs a restart |
| `ADVISORY_RADAR_WEBHOOK_SECRET` | Bearer secret of the inbound `/webhooks/<id>` endpoint. Ingestion is off without it. Same 24-character minimum |
| `ADVISORY_RADAR_WEBHOOK_SECRET_FILE` | Path of a file holding that secret. Same rules as `ADVISORY_RADAR_AUTH_TOKEN_FILE` |
| `ADVISORY_RADAR_FORWARDED_ALLOW_IPS` | Comma-separated addresses or networks of the reverse proxy whose `X-Forwarded-For` is believed, for the login throttle. Default: loopback only. See below |
| `ADVISORY_RADAR_CONFIG` | Config path (the image sets `/config/config.yml`) |
| `ADVISORY_RADAR_PUBLIC_HTTPS` | `1` when TLS terminates in front of the container: sends HSTS. Off by default, because a wrong HSTS setting pins a browser to HTTPS |
| `ADVISORY_RADAR_INSECURE_COOKIES` | `1` only for a plain-HTTP development instance: stops marking the session cookie `Secure` |
| plus one per referenced secret | e.g. `DISCORD_WEBHOOK_URL`, `APPRISE_PASSWORD`, `FRESHRSS_TOKEN` |

A secret file that is missing, unreadable, not UTF-8 or empty stops startup with an error that
names the variable and never the path or the content. Surrounding whitespace in the file, such as
a trailing newline, is dropped. A secret shorter than 24 characters is refused the same way,
naming the variable and never the value.

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

Behind a reverse proxy every connection arrives from the proxy's address, so a throttle keyed on
the peer would be one counter for every client: five failed logins from anywhere would lock
everyone out. The server therefore reads the client from `X-Forwarded-For`, but only on a
connection from an address listed in `ADVISORY_RADAR_FORWARDED_ALLOW_IPS`, a comma-separated list
of IP addresses and networks:

```bash
ADVISORY_RADAR_FORWARDED_ALLOW_IPS=192.0.2.10,198.51.100.0/24
```

- Unset or empty means loopback only (`127.0.0.1` and `::1`), which suits a proxy on the same
  host. A proxy in another container or on another host must be listed, or the throttle keeps
  seeing the proxy.
- `*`, `0.0.0.0/0` and `::/0` are refused at startup, and so is an entry that is not an IP
  address or a network. Trusting every peer would let any client choose its own throttle key and
  the address a request is logged under.
- The server takes the right-most address in `X-Forwarded-For` that is not itself a listed
  proxy, so the proxy must append the address it saw or replace the header, as the usual
  reverse proxies do by default. A proxy that passes a client's own `X-Forwarded-For` through
  untouched lets that client pick its throttle key.
- uvicorn's own `FORWARDED_ALLOW_IPS` variable is not read: the product always passes this
  list explicitly.

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
`settings.json`, the KEV cache, the default `watchlist.json` and the
[state-archive files](#state-size-and-retention) stay beside `state_path` and are not part of the
document, which is why `state_path` is still required when the document lives elsewhere.

Whichever store holds it, a document that cannot be locked or written (a full disk, a read-only
volume, a bad permission on the JSON file) fails the pass with `the state store at <path> is
unavailable`; the JSON file store reports it the way the SQLite store always has, not as a
traceback. The store then keeps the last document that was saved. A save can fail after the
pass's messages went out, so the next pass starts from that older document. The JSON file is
replaced atomically: the new bytes are synced, renamed over the old file, and the directory is
then synced, so a document a save returned for survives a power cut. The directory sync is best
effort, because a filesystem that cannot sync a directory keeps the guarantee it had before. It
is a second flush per save, which costs real time on a slow disk.

The JSON state file is written on one line, without indentation, because it is the one document
that grows. A file written indented by an earlier version is read as it is and rewritten compactly
by the next save, and `python -m json.tool state.json` indents it again for reading. The files
people open and edit, `settings.json` and `watchlist.json`, stay indented, and the SQLite and
PostgreSQL stores keep the indented text. The KEV cache beside the state file is written the same
compact way. It is a convenience and not part of the document: when it cannot be written the pass
logs a warning and uses the catalog it has just downloaded.

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

### State size and retention

The state is one document and every store keeps it whole: a page loads all of it and a save writes
all of it. A pass saves it once after each source, once before the first message is sent, once for
each notifier that accepts a message, once after delivery and once for the run record, which is
`sources + 3` saves plus one per acknowledgement. Most of the document is bounded: `watch` drops a
CVE after 14 days, the KEV cache lasts a day and `runs` keeps the last 200 passes. Two parts grow
with use: `seen`, one short record for every identifier ever reported, and `deliveries`, one
snapshot of about 0.5 KiB for every delivered message.

**What a pass moves.** A pass moves every delivery snapshot older than two years (730 days, counted
back from the start of the UTC day, so the first pass of a day moves everything that expired and
the others find nothing) into `state-archive-<day>-<digest>.json` beside `state_path`, before its
first save, and the document drops them with that save. The file is written the way the state is: a
temporary file, synced, renamed, then the directory synced, with mode 0600. It holds the snapshots
unchanged in a `deliveries` map, with the line it was cut at (`before`) and the time of the pass
(`archived_at`). The name carries a digest of the content, so a pass that stops after the file was
written and runs again the same day finds the same name. It does not take the name on trust: it
reads that one file, and it drops the snapshots only when the file is a regular file that declares
the archive schema and holds every one of them unchanged, so it writes nothing twice. Anything else
at that name (an empty or damaged file, an archive of other records, a directory, or a symbolic
link, which is never followed) is left as it is and never replaced: the pass logs a warning and the
snapshots stay in the state, because a copy that cannot be shown to exist is not one. Move what is
in the way aside and the next pass writes the archive. Otherwise the day in the name changes after
midnight, and the first pass of the next day, which finds nothing at its name, writes a file, so a
retry after midnight may also write a second file with the same snapshots. Apart from that check, no
pass reads an archive file and nothing in the product does: to bring snapshots back, stop the
service and merge the `deliveries` map into the state by hand. An archive that cannot be written (a
full disk, a read-only volume) is logged as a warning and the snapshots stay in the state until a
pass that can write it. A dry run moves nothing.

**What stays.** Seen records are never archived. They are the deduplication: a pass reports an
identifier only when no record claims it, and an item with no date, an item whose date was changed
and a new bulletin that names an old CVE carry nothing that says "old", so without its record each
of them would be reported again. A seen record whose snapshot moved keeps its outcome, its time and
its pointer. Its advisory page says that the details moved to the archive, and `/alerts` and
`/inbox` list the row without a tag, source id or title. Pending and parked messages, the first-seen
time of every identifier and the ownership of queued messages are not touched: the pass settles
ownership before it moves anything. The price is that `seen` keeps growing, linearly, and retention
does not bound it.

**Rollback and migration.** A release without retention reads the document as it is, and its pages
already show a seen record without a snapshot with "not recorded" in its detail cells, so going back
needs no undo and the archive files stay where they are. `advisory-radar migrate` copies only the
document, so the files do not travel with it. With PostgreSQL, each instance writes its own files on
the volume of its own `state_path`.

**Supported scale.** One instance supports 100,000 seen identifiers and 20,000 live deliveries (the
deliveries of the last two years) with `/alerts` under 1 s and a state save under 2 s, with either
store. The measurement below meets both budgets there, so this release does not change the storage:
the JSON file stays the default, and SQLite and PostgreSQL stay a choice for one-file backups or
shared state, not a remedy for size.

`scripts/benchmark_state.py` produced the numbers (standard library only, seed 1, real `fsync`,
times in seconds, medians of five runs for the first six rows and of three for the others). The
first three histories were measured in one run and each of the others in a run of its own, a few
minutes apart, on one shared Linux host with Python 3.14.10 and SQLite 3.53.1. A 4 KiB `fsync`
took between 17 and 55 ms across the five runs, and the saves move with it: a slower disk makes
every save slower, so run the script on the volume you use, and repeat a row that lands near a
budget. The histories are invented: a delivered message names one to three
identifiers (1.8 on average), and the other seen identifiers are backlog, suppressed, alias,
not-security and filtered. A real history with larger snapshots is heavier.

| history (seen / deliveries) | store | document MiB | load | save | `/alerts` | `/alerts?q=` | advisory page |
|---|---|---|---|---|---|---|---|
| 1,000 / 200 | JSON | 0.2 | 0.001 | 0.108 | 0.003 | 0.003 | 0.002 |
| | SQLite | 0.3 | 0.002 | 0.090 | 0.004 | 0.004 | 0.003 |
| **100,000 / 20,000 (the target)** | JSON | 16.9 | 0.182 | 0.418 | 0.531 | 0.332 | 0.207 |
| | SQLite | 24.8 | 0.184 | 0.549 | 0.597 | 0.363 | 0.220 |
| 100,000 / 10,018 (the target over four years, after the first pass archived 9,982) | JSON | 11.8 | 0.154 | 0.231 | 0.469 | 0.252 | 0.158 |
| | SQLite | 17.2 | 0.149 | 0.460 | 0.455 | 0.244 | 0.155 |
| 150,000 / 30,000 (1.5 times the target) | JSON | 25.5 | 0.305 | 0.510 | 0.893 | 0.640 | 0.391 |
| | SQLite | 37.4 | 0.330 | 0.743 | 0.940 | 0.582 | 0.355 |
| 200,000 / 20,000 (twice the seen) | JSON | 22.9 | 0.302 | 0.428 | 0.796 | 0.489 | 0.313 |
| | SQLite | 33.5 | 0.289 | 0.904 | 0.796 | 0.489 | 0.331 |
| 200,000 / 40,000 (twice the target) | JSON | 34.0 | 0.420 | 0.736 | 1.167 | 0.714 | 0.464 |
| | SQLite | 49.9 | 0.414 | 1.149 | 1.280 | 0.771 | 0.477 |
| 400,000 / 20,000 (four times the seen) | JSON | 34.9 | 0.529 | 0.560 | 1.221 | 0.811 | 0.579 |
| | SQLite | 50.5 | 0.509 | 0.700 | 1.299 | 0.795 | 0.622 |

At the target both stores are inside both budgets: `/alerts` takes 0.53 s with the JSON file and
0.60 s with SQLite, and a save 0.42 s and 0.55 s. Past the target the first budget to fail is
`/alerts`. It still passes at 1.5 times the target (0.89 s and 0.94 s) and at twice the seen set
alone (0.80 s with both stores), with a margin that run-to-run noise can use up, and it fails at
twice the target (1.2 s and 1.3 s) and at four times the seen set (1.2 s and 1.3 s). A save stays
under 2 s in every row, at most 1.15 s. The SQLite and PostgreSQL stores keep the indented text,
which is 1.5 times the compact JSON file (24.8 against 16.9 MiB at the target).

**What a pass writes.** The same run counted the saves of a real pass with one source and one
notifier at the target, and the bytes each save handed to the kernel (`/proc/self/io`, so Linux
only). A pass with nothing to do saves 4 times. A pass that delivers the most messages one pass
may, 5, saves 9 times, because each acknowledgement saves the document again to record that one
message:

| store | pass | saves | written MiB | each save, times the document | time in saves (s) |
|---|---|---|---|---|---|
| JSON | nothing to do | 4 | 67.5 | 1.0 1.0 1.0 1.0 | 1.43 |
| JSON | 5 messages delivered | 9 | 152.0 | 1.0 1.0 1.0 1.0 1.0 1.0 1.0 1.0 1.0 | 2.93 |
| SQLite | nothing to do | 4 | 100.0 | 2.0 2.0 0.0 0.0 | 1.63 |
| SQLite | 5 messages delivered | 9 | 399.8 | 2.0 2.0 2.0 2.0 2.0 2.0 2.0 2.0 0.0 | 7.35 |

The document is the text a store keeps, 16.9 MiB for the JSON file and 24.8 MiB for SQLite. The
JSON file is written whole by every save. SQLite writes what a save changes to its write-ahead log
and then copies it into the database file, so a save that rewrites the whole text, as each
acknowledgement does, writes it twice. A save whose text is the stored text writes nothing, as the
third save of a pass with nothing to do shows, and the last save of a pass, which adds only the run
record, wrote almost nothing.
One acknowledgement writes 16.9 MiB with the JSON file to record 950 bytes of new state, and 50.0
MiB with SQLite to record 1,400 bytes of its indented text. A pass that delivers five messages
takes 3.4 s of wall time with the JSON file and 8.0 s with SQLite. The memory peaks at the target
are Python allocations above the baseline (`tracemalloc`), not the resident size of the process: a
load takes 100 MiB with the JSON file and 108 MiB with SQLite, a save 34 and 50 MiB, and an
`/alerts` request 120 MiB.

The first pass over the four-year history moved 9,982 deliveries into a 5.1 MiB archive file in
0.39 s and cut the document from 16.9 to 11.8 MiB. PostgreSQL is not measured, because it needs a
server; it keeps the same text as SQLite.

Run it from a checkout of the same release (the image carries no `scripts/`), on the volume that
holds the state:

```bash
uv run python scripts/benchmark_state.py --workdir /path/on/the/data/volume
uv run python scripts/benchmark_state.py --seen 200000 --deliveries 40000 --repeat 3
uv run python scripts/benchmark_state.py --check    # exit 1 when a row misses a budget
```

The defaults measure the first three histories with both stores. `--json` prints every
measurement, and `--alerts-budget` and `--save-budget` change the limits `--check` applies. A
history with no delivery (`--deliveries 0`, or a `--seen` below 5, whose default fifth is none) has
no advisory page to open, so that column reads `n/a` (null with `--json`) and the rest is measured.

### The settings overlay

`/config` writes `settings.json` beside `state_path` on `/data` (`/data/settings.json`
in the container, `~/.local/share/advisory-radar/settings.json` for the rootless
quadlet). It is created with mode `0600`, owned by the container user, and replaced
atomically (a temporary file in the same directory, `fsync`, `os.replace`, then a best-effort
`fsync` of the directory), so a half-written file cannot brick a start. It is not part of the state document, whichever
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
  `poll_interval`, and the same `168h` ceiling: a longer value is refused at start and on a reload) thins
  only that source's fetching; an absent key follows the global interval. The pass
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
behind it; when more are queued than a pass may deliver, the critical ones are taken first
(see `configuration.md`). An empty value turns
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
record written by an older version, and that they moved to the state archive for a delivery
older than two years ([State size and retention](#state-size-and-retention)), instead of
inventing them. Later escalation and Adobe
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
the whole queue (dropping the whole queue shows a confirmation page first), and `/runs`
filters by exit code and day; the state keeps only the last 200
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
