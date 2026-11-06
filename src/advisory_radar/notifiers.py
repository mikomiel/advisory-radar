"""Built-in notifier plugins: Apprise gateway, Discord webhook, generic webhook."""

from __future__ import annotations

import base64
import json
import logging
import urllib.parse

from .http import Http

LOG = logging.getLogger(__name__)


def _post_json(http: Http, url: str, headers: dict[str, str], payload: dict) -> int:
    body = json.dumps(payload).encode()
    status, _, _ = http("POST", url, {"Content-Type": "application/json", **headers}, body)
    return status


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
    """Any JSON webhook: the full structured message is POSTed."""

    def __init__(self, notifier_id: str, url: str, headers: dict[str, str] | None = None) -> None:
        self.id = notifier_id
        self.url = url
        self.headers = headers or {}

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
        return _post_json(http, self.url, self.headers, payload)


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
    "webhook": lambda cfg, env: WebhookNotifier(cfg["id"], cfg["url"], cfg.get("headers") or {}),
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
