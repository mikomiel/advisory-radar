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


def _secret(env: dict, cfg: dict, key: str) -> str:
    name = cfg.get(key)
    if not name or name not in env:
        raise ValueError(f"notifier {cfg.get('id')!r}: ${{{name}}} is not set in the environment")
    return env[name]


#: Config ``type`` -> builder(config dict, env) -> Notifier
NOTIFIER_BUILDERS = {
    "apprise": lambda cfg, env: AppriseNotifier(
        cfg["id"], cfg["url"], cfg.get("key", "alerts"), cfg.get("password", "")
    ),
    "discord_webhook": lambda cfg, env: DiscordWebhookNotifier(cfg["id"], cfg["url"]),
    "webhook": lambda cfg, env: WebhookNotifier(cfg["id"], cfg["url"], cfg.get("headers") or {}),
}


def build_notifier(cfg: dict, env: dict[str, str]):
    kind = cfg.get("type")
    builder = NOTIFIER_BUILDERS.get(kind or "")
    if builder is None:
        builtins = ", ".join(sorted(NOTIFIER_BUILDERS))
        # No value in the message: `type` is expanded from the environment too, and the CLI logs this error.
        raise ValueError(f"unknown notifier type (id {cfg.get('id')!r}); built-ins: {builtins}")
    return builder(cfg, env)
