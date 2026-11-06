"""Built-in notifier plugins: Apprise gateway, Discord webhook, generic webhook."""

from __future__ import annotations

import base64
import json
import urllib.parse

from .http import Http


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
        self.url = url.rstrip("/") + "/" + topic
        self.priority = priority

    def send(self, entry: dict, http: Http) -> int:
        body = f"{entry['title']}\n{entry['body']}".encode()[:3500]
        status, _, _ = http(
            "POST",
            self.url,
            {"Title": entry["title"][:100], "Priority": str(self.priority), "Tags": entry["tag"]},
            body,
        )
        return status


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
        use_tls: bool,
    ) -> None:
        self.id = notifier_id
        self.host = host
        self.port = port
        self.from_addr = from_addr
        self.to = to
        self.username = username
        self.password = password
        self.use_tls = use_tls

    def send(self, entry: dict, http: Http) -> int:
        import smtplib
        from email.message import EmailMessage

        message = EmailMessage()
        message["Subject"] = entry["title"]
        message["From"] = self.from_addr
        message["To"] = ", ".join(self.to)
        message.set_content(entry["body"])
        try:
            if self.use_tls:
                with smtplib.SMTP_SSL(self.host, self.port, timeout=30) as smtp:
                    self._login(smtp)
                    smtp.send_message(message)
            else:
                with smtplib.SMTP(self.host, self.port, timeout=30) as smtp:
                    smtp.starttls()
                    self._login(smtp)
                    smtp.send_message(message)
            return 200
        except (OSError, smtplib.SMTPException):
            return 0

    def _login(self, smtp) -> None:
        if self.username:
            smtp.login(self.username, self.password or "")


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
        bool(cfg.get("use_tls", True)),
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
