"""Built-in notifier plugins: Apprise gateway, Discord webhook, generic webhook.

A generic ``webhook`` notifier may carry a ``secret``. With one set, every request is signed so a receiver
can tell a message this instance sent from one an attacker composed against the same URL:

``X-ADR-Timestamp``
    The Unix time the request was signed, as decimal seconds (the integer part of the clock).
``X-ADR-Signature``
    ``sha256=`` followed by the lowercase hex HMAC-SHA256 of ``timestamp + "." + body``, keyed with the
    secret. ``body`` is the exact byte string POSTed, never a re-serialisation of it.

The body is serialised once, signed, and sent as that same byte string. JSON has more than one spelling of
the same document (spacing, escaping, key order), so signing a second serialisation would produce a signature
the receiver could not reproduce from the bytes it received.

Verification recipe for a receiver:

1. Read ``X-ADR-Timestamp`` and ``X-ADR-Signature`` and refuse the request when either is missing.
2. Parse the timestamp as decimal integer seconds and refuse it when ``abs(now - timestamp) > 300`` (five
   minutes). The signature itself stays valid forever, so the timestamp is the replay bound; a receiver may
   use a smaller window, but it must allow enough for network and queueing delay.
3. Read the raw request body as bytes, exactly as received. Do not parse and re-encode it, and do not sign a
   field parsed out of it: either would compare over different bytes.
4. Compute ``hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body,
   hashlib.sha256).hexdigest()`` and compare ``"sha256=" + digest`` with the header using
   ``hmac.compare_digest``. Never compare with ``==``: a byte-by-byte comparison leaks timing information.
5. Refuse the request when the comparison fails.

With no secret nothing above applies: no signature headers are sent, and the request is the same bytes and
headers as before signing existed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
import urllib.parse
from collections.abc import Callable

from .http import Http

LOG = logging.getLogger(__name__)

#: The request headers a configured ``headers`` mapping may not spoof: the notifier writes them after merging
#: that mapping, case-insensitively, so a receiver can rely on the one value the code computed.
_SIGNATURE_HEADERS = frozenset({"x-adr-timestamp", "x-adr-signature"})


def _post(http: Http, url: str, headers: dict[str, str], body: bytes) -> int:
    status, _, _ = http("POST", url, {"Content-Type": "application/json", **headers}, body)
    return status


def _post_json(http: Http, url: str, headers: dict[str, str], payload: dict) -> int:
    return _post(http, url, headers, json.dumps(payload).encode())


def _signature(secret: str, timestamp: str, body: bytes) -> str:
    """``sha256=`` and the lowercase hex HMAC of ``timestamp + "." + body`` over the exact bytes sent.

    The secret is UTF-8 and the timestamp ASCII, which is the encoding the module docstring's recipe names:
    a receiver written in another language must be able to reproduce this byte for byte.
    """
    material = timestamp.encode("ascii") + b"." + body
    return "sha256=" + hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()


class AppriseNotifier:
    """An Apprise API gateway: POST /notify/<key> as the key's login."""

    def __init__(self, notifier_id: str, url: str, key: str, password: str) -> None:
        self.id = notifier_id
        self.url = url.rstrip("/")
        self.key = key
        self.password = password

    def send(self, entry: dict, http: Http) -> int:
        credential = base64.b64encode(f"{self.key}:{self.password}".encode()).decode()
        url = f"{self.url}/notify/{urllib.parse.quote(self.key, safe='')}"
        return _post_json(
            http,
            url,
            {"Authorization": f"Basic {credential}"},
            {"title": entry["title"], "body": entry["body"], "tag": entry["tag"], "format": "markdown"},
        )


class DiscordWebhookNotifier:
    """A Discord channel webhook; the message fits one 2000-character message."""

    def __init__(self, notifier_id: str, url: str) -> None:
        self.id = notifier_id
        self.url = url

    def send(self, entry: dict, http: Http) -> int:
        content = f"**{entry['title']}**{entry['body']}"
        return _post_json(http, self.url, {}, {"content": content[:1900]})


class WebhookNotifier:
    """Any JSON webhook: the full structured message is POSTed, signed when a secret is configured.

    ``clock`` is injectable so a test can pin the timestamp header; a deployment keeps the system clock. The
    body is encoded once here -- not by ``_post_json`` -- because the signature and the request must cover the
    very same bytes.
    """

    def __init__(
        self,
        notifier_id: str,
        url: str,
        headers: dict[str, str] | None = None,
        secret: str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.id = notifier_id
        self.url = url
        self.headers = headers or {}
        self.secret = secret or None
        self.clock = clock

    def send(self, entry: dict, http: Http) -> int:
        payload = {
            "title": entry["title"],
            "body": entry["body"],
            "tag": entry["tag"],
            "kind": entry["kind"],
            "ids": entry["ids"],
            "link": entry.get("link", ""),
            "source": entry.get("source", ""),
        }
        body = json.dumps(payload).encode()
        headers = self.headers
        if self.secret:
            timestamp = str(int(self.clock()))
            # A configured header cannot shadow the computed pair: two spellings of one header would leave
            # which value the receiver reads to the HTTP stack.
            headers = {name: value for name, value in self.headers.items() if name.lower() not in _SIGNATURE_HEADERS}
            headers["X-ADR-Timestamp"] = timestamp
            headers["X-ADR-Signature"] = _signature(self.secret, timestamp, body)
        return _post(http, self.url, headers, body)


class MatrixWebhookNotifier:
    """A Matrix Hookshot/Element webhook: JSON ``{msgtype, text}`` (Markdown rendered by the bridge)."""

    def __init__(self, notifier_id: str, url: str) -> None:
        self.id = notifier_id
        self.url = url

    def send(self, entry: dict, http: Http) -> int:
        text = f"**{entry['title']}**\n{entry['body']}"
        payload = {"msgtype": "m.text", "text": text[:4000]}
        return _post_json(http, self.url, {}, payload)


class NtfyNotifier:
    """An ntfy topic: POST the body with Title/Priority headers."""

    def __init__(self, notifier_id: str, url: str, topic: str, priority: int = 3) -> None:
        self.id = notifier_id
        # The structured publish API posts to the server root with the topic in the document; posting the JSON
        # to /<topic> would publish it as message text.
        self.url = url.rstrip("/")
        self.topic = topic
        self.priority = priority

    def send(self, entry: dict, http: Http) -> int:
        # JSON publishing, not Title/X-Title headers: http.client encodes header values as Latin-1, so an em
        # dash or CJK title in a header fails on every retry and the message parks. The JSON body is UTF-8.
        return _post_json(
            http,
            self.url,
            {},
            {
                "topic": self.topic,
                "title": entry["title"][:250],
                "message": f"{entry['title']}\n{entry['body']}"[:3500],
                "priority": self.priority,
                "tags": [entry["tag"]],
            },
        )


class GotifyNotifier:
    """A Gotify server: POST /message?token=..."""

    def __init__(self, notifier_id: str, url: str, token: str, priority: int = 5) -> None:
        self.id = notifier_id
        self.url = f"{url.rstrip('/')}/message?token={token}"
        self.priority = priority

    def send(self, entry: dict, http: Http) -> int:
        return _post_json(
            http,
            self.url,
            {},
            {
                "title": entry["title"],
                "message": entry["body"],
                "priority": self.priority,
                "extras": {"client::display": {"contentType": "text/markdown"}},
            },
        )


class SmtpNotifier:
    """Email via SMTP (stdlib smtplib; runs in the caller's thread)."""

    def __init__(
        self,
        notifier_id: str,
        host: str,
        port: int,
        from_addr: str,
        to: list[str],
        username: str | None,
        password: str | None,
        starttls: bool,
        implicit_tls: bool,
    ) -> None:
        self.id = notifier_id
        self.host = host
        self.port = port
        self.from_addr = from_addr
        self.to = to
        self.username = username
        self.password = password
        self.starttls = starttls
        self.implicit_tls = implicit_tls

    def send(self, entry: dict, http: Http) -> int:
        import smtplib
        from email.message import EmailMessage

        message = EmailMessage()
        message["Subject"] = entry["title"]
        message["From"] = self.from_addr
        message["To"] = ", ".join(self.to)
        message.set_content(entry["body"])
        import ssl

        # A validating context: without it smtplib does not check the server's certificate, and an
        # interception would hand over the configured credentials and silently swallow the message.
        context = ssl.create_default_context()
        try:
            if self.implicit_tls:  # port 465: TLS from the first byte
                with smtplib.SMTP_SSL(self.host, self.port, timeout=30, context=context) as smtp:
                    self._login(smtp)
                    refused = smtp.send_message(message)
            else:
                with smtplib.SMTP(self.host, self.port, timeout=30) as smtp:
                    if self.starttls:  # port 587: plain greeting, then an upgrade
                        smtp.starttls(context=context)
                        smtp.ehlo()
                    self._login(smtp)
                    refused = smtp.send_message(message)
            # send_message returns {} on full success and a refusal per rejected recipient: a partial send is
            # not a delivery, and acknowledging it would drop the alert from pending.
            if refused:
                count = len(refused) if isinstance(refused, dict) else 1
                LOG.warning("smtp: %d recipient(s) refused the message", count)
                return 0
            return 200
        except (OSError, smtplib.SMTPException):
            return 0

    def _login(self, smtp) -> None:
        if self.username:
            smtp.login(self.username, self.password or "")


def _bool(value: object, name: str) -> bool:
    """A YAML boolean, accepting the documented string spellings an environment expansion produces.

    ``bool("false")`` is ``True`` and an unrecognised spelling would otherwise silently mean "off" - which for
    ``use_tls`` would authenticate over a plaintext connection, so an unknown value is rejected.
    """
    if isinstance(value, bool):
        return value
    lowered = str(value).strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off", ""}:
        return False
    raise ValueError(f"{name} must be true or false")


#: Config ``type`` -> builder(config dict, env) -> Notifier. Secret fields are
#: ``${VAR}`` placeholders resolved by config.load_config at load time.
NOTIFIER_BUILDERS = {
    "apprise": lambda cfg, env: AppriseNotifier(cfg["id"], cfg["url"], cfg.get("key", "alerts"), cfg["password"]),
    "discord_webhook": lambda cfg, env: DiscordWebhookNotifier(cfg["id"], cfg["url"]),
    "webhook": lambda cfg, env: WebhookNotifier(cfg["id"], cfg["url"], cfg.get("headers") or {}, cfg.get("secret")),
    "matrix_webhook": lambda cfg, env: MatrixWebhookNotifier(cfg["id"], cfg["url"]),
    "ntfy": lambda cfg, env: NtfyNotifier(cfg["id"], cfg["url"], cfg["topic"], int(cfg.get("priority", 3))),
    "gotify": lambda cfg, env: GotifyNotifier(cfg["id"], cfg["url"], cfg["token"], int(cfg.get("priority", 5))),
    "smtp": lambda cfg, env: SmtpNotifier(
        cfg["id"],
        cfg["host"],
        int(cfg.get("port", 587)),
        cfg["from"],
        [a.strip() for a in str(cfg["to"]).split(",") if a.strip()],
        cfg.get("username"),
        cfg.get("password"),
        # `use_tls: true` is STARTTLS on the submission port (587); implicit TLS (465) is `implicit_tls: true`.
        starttls=_bool(cfg.get("use_tls", True), "use_tls"),
        implicit_tls=_bool(cfg.get("implicit_tls", False), "implicit_tls"),
    ),
}


def build_notifier(cfg: dict, env: dict[str, str]):
    kind = cfg.get("type")
    builder = NOTIFIER_BUILDERS.get(kind or "")
    if builder is None:
        builtins = ", ".join(sorted(NOTIFIER_BUILDERS))
        # No value in the message: `type` is expanded from the environment too, and the CLI logs this error.
        raise ValueError(f"unknown notifier type (id {cfg.get('id')!r}); built-ins: {builtins}")
    return builder(cfg, env)
