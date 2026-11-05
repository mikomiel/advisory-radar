"""Configuration: one YAML file plus environment expansion, validated into dataclasses.

Secrets are never written to the config file: a string ``${NAME}`` is replaced
from the process environment, and ``${NAME}_FILE`` reads the secret from a
file (Docker/Podman secrets pattern). Unknown keys are refused, so a typo
fails at startup instead of silently doing nothing.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_ENV_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?:_FILE)?\}")


class ConfigError(ValueError):
    pass


def _expand(value: object, env: dict[str, str]) -> object:
    if isinstance(value, str):

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            file_mode = match.group(0).endswith("_FILE}")
            if file_mode:
                path = env.get(name + "_FILE") or env.get(name)
                if path and Path(path).is_file():
                    return Path(path).read_text(encoding="utf-8").strip()
                raise ConfigError(f"${{{name}_FILE}}: no readable file (env {name}_FILE={path!r})")
            if name not in env:
                raise ConfigError(f"${{{name}}} is not set in the environment")
            return env[name]

        return _ENV_RE.sub(replace, value)
    if isinstance(value, list):
        return [_expand(item, env) for item in value]
    if isinstance(value, dict):
        return {key: _expand(item, env) for key, item in value.items()}
    return value


@dataclass(frozen=True)
class Config:
    sources: tuple[dict, ...]
    notifiers: tuple[dict, ...]
    watchlist_path: Path | None
    poll_interval_seconds: int = 900
    state_path: Path = Path("data/state.json")
    hidden_source_hosts: frozenset[str] = frozenset()
    adobe_commerce: bool = False
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    raw: dict = field(default_factory=dict)


_SOURCE_KEYS = {"id", "type", "url", "token", "enabled"}
_NOTIFIER_KEYS = {"id", "type", "url", "key", "password", "headers", "enabled"}
_TOP_KEYS = {
    "sources",
    "notifiers",
    "watchlist",
    "poll_interval",
    "state_path",
    "hidden_source_hosts",
    "adobe_commerce",
    "web",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def load_config(path: Path, env: dict[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigError(f"{path} is not a mapping")
    unknown = set(document) - _TOP_KEYS
    _require(not unknown, f"unknown top-level keys in {path}: {sorted(unknown)}")
    document = _expand(document, env)

    sources = document.get("sources") or []
    notifiers = document.get("notifiers") or []
    _require(isinstance(sources, list) and isinstance(notifiers, list), "sources/notifiers must be lists")
    for entry in (*sources, *notifiers):
        _require(
            isinstance(entry, dict) and isinstance(entry.get("id"), str) and entry["id"],
            f"every source/notifier needs a string id: {entry!r}",
        )
        _require(isinstance(entry.get("type"), str), f"{entry['id']}: missing type")
        extra = set(entry) - (_SOURCE_KEYS if entry in sources else _NOTIFIER_KEYS)
        _require(not extra, f"{entry['id']}: unknown keys {sorted(extra)}")
        _require(isinstance(entry.get("enabled", True), bool), f"{entry['id']}: enabled must be a bool")
    ids = [entry["id"] for entry in (*sources, *notifiers)]
    _require(len(ids) == len(set(ids)), f"duplicate plugin ids: {ids}")

    poll = document.get("poll_interval", "15m")
    match = re.fullmatch(r"(\d+)([smh])", str(poll))
    _require(match is not None, f"poll_interval must look like 15m/30s/12h, got {poll!r}")
    seconds = int(match.group(1)) * {"s": 1, "m": 60, "h": 3600}[match.group(2)]

    web = document.get("web") or {}
    _require(isinstance(web, dict), "web must be a mapping")
    web_host = str(web.get("host", "0.0.0.0"))
    web_port = web.get("port", 8080)
    _require(isinstance(web_port, int) and 1 <= web_port <= 65535, f"web.port must be 1..65535, got {web_port!r}")
    watchlist = document.get("watchlist")
    watchlist_path = Path(watchlist) if isinstance(watchlist, str) else None
    hidden = frozenset(document.get("hidden_source_hosts") or [])
    return Config(
        sources=tuple(entry for entry in sources if entry.get("enabled", True)),
        notifiers=tuple(entry for entry in notifiers if entry.get("enabled", True)),
        watchlist_path=watchlist_path,
        poll_interval_seconds=seconds,
        state_path=Path(document.get("state_path", "data/state.json")),
        hidden_source_hosts=hidden,
        adobe_commerce=bool(document.get("adobe_commerce", False)),
        web_host=web_host,
        web_port=int(web_port),
        raw=document,
    )


def collect_secrets(config: Config, env: dict[str, str] | None = None) -> list[str]:
    """Every ${NAME} the config references, so the CLI can redact them from logs."""
    env = os.environ if env is None else env
    names = set(_ENV_RE.findall(yaml.safe_dump(config.raw)))
    return sorted(names)
