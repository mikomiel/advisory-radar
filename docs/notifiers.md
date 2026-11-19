# Notifiers
Eight notifier types are built in, and the table below is the whole catalogue: a **required** key has no
default, an **optional** one may be left out. A **reference** key holds the name of an environment variable,
written `${NAME}` or `${NAME_FILE}`, and never the secret itself: the settings page accepts nothing else for it,
and it only names a variable the YAML lists under `overlay_references` (see `configuration.md`, "Which variables
the overlay may reference"). A **YAML-only** key is one the settings page never writes, so it is set in the config
file; the page says so before anything is submitted. The same catalogue is on the `/config` page of the web UI.

| Kind | Summary | Required keys | Optional keys | Reference keys | YAML-only keys |
|---|---|---|---|---|---|
| `apprise` | An Apprise API gateway: the message is posted to `/notify/<key>` as that key's login. | `url`, `password` | `key`, `enabled` | `url`, `password`, `key` | - |
| `discord_webhook` | A Discord channel webhook; the message is cut to fit one Discord message. | `url` | `enabled` | `url` | - |
| `webhook` | Any JSON webhook: the whole structured message is posted, signed when a secret is set. | `url` | `secret`, `headers`, `enabled` | `url`, `secret` | `headers` |
| `matrix_webhook` | A Matrix Hookshot or Element webhook; the bridge renders the Markdown. | `url` | `enabled` | `url` | - |
| `ntfy` | An ntfy topic, published through the server's JSON API. | `url`, `topic` | `priority`, `enabled` | `url` | - |
| `gotify` | A Gotify server, posted to `/message` with the application token. | `url`, `token` | `priority`, `enabled` | `url`, `token` | - |
| `smtp` | Email through an SMTP server, over STARTTLS (587) or implicit TLS (465). | `host`, `from`, `to` | `port`, `username`, `password`, `use_tls`, `implicit_tls`, `enabled` | `password` | - |
| `log` | Writes each message to the application log and delivers nothing, for a shadow run. | - | `enabled` | - | - |

Every type can be added from the web UI, and only `headers` has to be written in the YAML. An `id` is
unique across sources and notifiers, and a notifier is built when it is enabled. The config validator accepts
any notifier key on any type and the builder ignores the keys it does not read, so the page shows only the keys
of the type you chose.

## Adding a notifier from the web UI
Open `/config#notifiers`. The table there lists every type with what it needs; **Add** opens a form for that
type alone, with its required keys marked, one input for each reference key, and a note for each YAML-only key.
A reference input takes `${NAME}` or `${NAME_FILE}`. A literal value is refused and is never shown again, so a
failed save does not hand a secret back to the page: it keeps what you typed in the plain fields (topic, host,
port and so on) and in a reference field only when that field holds a whole reference. The new notifier is
stored in the settings overlay and is live after the reload that follows the save.

A row of a notifier that is already configured edits its enabled flag, its plain keys and, on a `webhook`, its
signing `secret`. Its `url` and its other reference keys are set when the notifier is added: to point one
somewhere else, add a new notifier and disable the old one, or edit the YAML.

An smtp notifier whose password the YAML holds keeps the host, port and TLS flags from the YAML too, so an edit
made here cannot send that password to another server (see `configuration.md`, "Settings without a restart").

## Sending a test message
Every enabled notifier row on `/config` has **Send test message**; a disabled row has none. It asks for
confirmation first and sends nothing on the first click. The confirmation page names the notifier and shows the
message; **Send the test message**
then sends one real message through the notifier that is running now, the same message `advisory-radar
test-notify` sends. Two consequences follow:

- The test uses the live configuration, never unsaved edits. A notifier that is disabled, or was saved after the
  last reload, is not in it, and the page says so instead of sending.
- A notifier takes at most three test messages a minute. The fourth is answered with `429` and a
  `Retry-After` header.

The result page shows the HTTP status the destination answered, or that it did not answer. A test sends the
message and nothing else: it writes no state and no overlay, and it is not recorded as an alert. A `log`
notifier writes the message to the application log.

## apprise
Posts `{title, body, tag, format}` to `<url>/notify/<key>` with HTTP Basic credentials `key:password`. `key`
defaults to `alerts`. Every one of the three is a reference key, so the page takes each as a reference.

```yaml
notifiers:
  - id: apprise
    type: apprise
    url: ${APPRISE_URL}
    password: ${APPRISE_PASSWORD}
    key: ${APPRISE_KEY}
```

## discord_webhook
Posts the bold title and the body to the channel webhook, cut to 1900 characters. The webhook URL is itself the
credential, so it is a reference.

```yaml
notifiers:
  - id: discord
    type: discord_webhook
    url: ${DISCORD_WEBHOOK_URL}
```

## webhook
Posts the structured message as JSON: `title`, `body`, `tag`, `kind`, `ids`, `link` and `source`. With a `secret`
every request is signed, and `configuration.md` ("Delivery: digests, quiet hours and signed webhooks") has the
verification recipe. `headers` is a mapping of extra request headers. It is YAML-only because a header can carry
an API key: the page neither shows nor writes it, and saving a notifier on the page keeps the headers the file
holds.

```yaml
notifiers:
  - id: hook
    type: webhook
    url: ${WEBHOOK_URL}
    secret: ${WEBHOOK_SECRET}
    headers:
      X-Api-Key: ${WEBHOOK_API_KEY}
```

## matrix_webhook
Posts `{msgtype: m.text, text}` with the bold title and the body, cut to 4000 characters.

```yaml
notifiers:
  - id: matrix
    type: matrix_webhook
    url: ${MATRIX_WEBHOOK_URL}
```

## ntfy
Publishes JSON to the server root with the `topic` in the document. `url` is the server, `priority` runs from 1 to
5 and defaults to 3.

```yaml
notifiers:
  - id: phone
    type: ntfy
    url: ${NTFY_URL}
    topic: advisories
    priority: 4
```

## gotify
Posts to `<url>/message` with the application `token`. `priority` defaults to 5.

```yaml
notifiers:
  - id: gotify
    type: gotify
    url: ${GOTIFY_URL}
    token: ${GOTIFY_TOKEN}
    priority: 5
```

## smtp
Sends one mail through `smtplib`. `to` takes one address or a comma-separated list. `use_tls: true`, the default,
upgrades the connection with STARTTLS (port 587 is the default); `implicit_tls: true` is TLS from the first byte,
for port 465. The server certificate is always validated. `username` and `password` are optional, and a login is
attempted only when `username` is set. Only `password` is a reference key: `host`, `port` and the TLS flags are
plain keys, which is why the overlay pins them to the YAML when the YAML owns the password.

```yaml
notifiers:
  - id: mail
    type: smtp
    host: smtp.example.net
    port: 587
    from: radar@example.net
    to: ops@example.net
    username: radar
    password: ${SMTP_PASSWORD}
    use_tls: true
```

## log
Writes each message to the application log at INFO level and delivers nothing, so a shadow run can record what
would have been sent.

```yaml
notifiers:
  - id: shadow
    type: log
```
