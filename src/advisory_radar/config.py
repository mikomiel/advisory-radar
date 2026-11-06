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


def _expand(value: object, env: dict[str, str], resolved: list[str] | None = None, *, lenient: bool = False) -> object:
    if isinstance(value, str):

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            file_mode = match.group(0).endswith("_FILE}")
            if file_mode:
                path = env.get(name + "_FILE") or env.get(name)
                if path and Path(path).is_file():
                    contents = Path(path).read_text(encoding="utf-8").strip()
                    if resolved is not None:
                        resolved.append(contents)  # the value, not the path, is what must be redacted
                    return contents
                raise ConfigError(f"${{{name}_FILE}}: no readable file (env {name}_FILE={path!r})")
            if name not in env:
                if lenient:
                    return match.group(0)  # state-only commands never build the plugin that would use it
                raise ConfigError(f"${{{name}}} is not set in the environment")
            if resolved is not None:
                resolved.append(env[name])
            return env[name]

        return _ENV_RE.sub(replace, value)
    if isinstance(value, list):
        return [_expand(item, env, resolved, lenient=lenient) for item in value]
    if isinstance(value, dict):
        return {key: _expand(item, env, resolved, lenient=lenient) for key, item in value.items()}
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
    #: ``${NAME}`` references read from the file *before* expansion, for log redaction.
    secret_names: tuple[str, ...] = ()
    #: The values those references expanded to, including the contents of a ``${NAME}_FILE``.
    secret_values: tuple[str, ...] = ()


_SOURCE_KEYS = {"id", "type", "url", "token", "user", "enabled"}
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


#: Spellings accepted for a boolean option that came from the environment (expansion yields strings).
_TRUE_WORDS = frozenset({"true", "yes", "on", "1"})
_FALSE_WORDS = frozenset({"false", "no", "off", "0", ""})


def _bool_option(value: object, name: str) -> bool:
    """A boolean option: a real bool, or one of the documented spellings.

    ``bool("false")`` is ``True``, so an environment-expanded value must never be coerced directly.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE_WORDS:
            return True
        if lowered in _FALSE_WORDS:
            return False
    # No value in the message: an environment- or file-expanded option can hold a secret, and the CLI logs
    # configuration errors before the redaction filter is installed.
    raise ConfigError(f"{name} must be true or false")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def load_config(path: Path, env: dict[str, str] | None = None, *, lenient: bool = False) -> Config:
    env = os.environ if env is None else env
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigError(f"{path} is not a mapping")
    unknown = set(document) - _TOP_KEYS
    _require(not unknown, f"unknown top-level keys in {path}: {sorted(unknown)}")
    # Structure is validated on the *unexpanded* document: an entry whose id is missing must not put an
    # expanded password into the error message, and the secret names must be read before expansion
    # replaces them with their values.
    sources = document.get("sources") or []
    notifiers = document.get("notifiers") or []
    _require(isinstance(sources, list) and isinstance(notifiers, list), "sources/notifiers must be lists")
    for entry in (*sources, *notifiers):
        _require(
            isinstance(entry, dict) and isinstance(entry.get("id"), str) and entry["id"],
            "every source/notifier needs a string id",
        )
        _require(isinstance(entry.get("type"), str), f"{entry['id']}: missing type")
        extra = set(entry) - (_SOURCE_KEYS if entry in sources else _NOTIFIER_KEYS)
        _require(not extra, f"{entry['id']}: unknown keys {sorted(extra)}")
        _require(isinstance(entry.get("enabled", True), bool), f"{entry['id']}: enabled must be a bool")
    ids = [entry["id"] for entry in (*sources, *notifiers)]
    _require(len(ids) == len(set(ids)), f"duplicate plugin ids: {ids}")
    # A disabled plugin is not built, so its ${...} references are not resolved either: turning a channel
    # off must be enough to drop its credential requirement.
    enabled = {
        key: [entry for entry in document.get(key) or [] if entry.get("enabled", True)]
        for key in ("sources", "notifiers")
    }
    document.update(enabled)
    secret_names = tuple(sorted(set(_ENV_RE.findall(yaml.safe_dump(document)))))
    resolved: list[str] = []
    document = _expand(document, env, resolved, lenient=lenient)
    document.pop("secret_names_source", None)
    secret_values = tuple(sorted({value for value in resolved if value}))
    # Built plugins read the expanded entries; the structural checks above used the raw ones.
    sources = document.get("sources") or []
    notifiers = document.get("notifiers") or []
    expanded_ids = [entry["id"] for entry in (*sources, *notifiers)]
    # State keys join the source id and the item's guid with ":", so a colon in an id could collide with
    # another source's id+guid pair. The id is validated after expansion, when it is the value in use.
    _require(
        all(re.fullmatch(r"[A-Za-z0-9._-]+", identifier) for identifier in expanded_ids),
        "plugin ids may use only letters, digits, dot, dash and underscore",
    )
    _require(
        len(expanded_ids) == len(set(expanded_ids)),
        "two plugin ids expand to the same value; ids must stay unique after ${...} expansion",
    )

    poll = document.get("poll_interval", "15m")
    match = re.fullmatch(r"(\d+)([smh])", str(poll))
    _require(match is not None, "poll_interval must look like 15m, 30s or 12h")
    seconds = int(match.group(1)) * {"s": 1, "m": 60, "h": 3600}[match.group(2)]
    _require(seconds > 0, "poll_interval must be greater than zero")

    web = document.get("web") or {}
    _require(isinstance(web, dict), "web must be a mapping")
    _require(
        not set(web) - {"host", "port"},
        f"unknown web keys {sorted(set(web) - {'host', 'port'})}",
    )
    web_host = str(web.get("host", "0.0.0.0"))
    web_port = web.get("port", 8080)
    _require(isinstance(web_port, int) and 1 <= web_port <= 65535, "web.port must be an integer in 1..65535")
    state_path = Path(document.get("state_path", "data/state.json"))
    _require(
        state_path.name != "kev.json",
        "state_path must not be named kev.json: that is the KEV cache's filename beside the state file",
    )
    watchlist = document.get("watchlist")
    _require(
        watchlist is None or isinstance(watchlist, str),
        f"watchlist must be a path to a watchlist file, got {type(watchlist).__name__}",
    )
    watchlist_path = Path(watchlist) if isinstance(watchlist, str) else None
    raw_hidden = document.get("hidden_source_hosts")
    if raw_hidden is not None:
        _require(
            isinstance(raw_hidden, list) and all(isinstance(host, str) and host for host in raw_hidden),
            "hidden_source_hosts must be a list of non-empty host names",
        )
    hidden = frozenset(host.lower() for host in (raw_hidden or []))  # compared against a lowercased URL host
    return Config(
        sources=tuple(entry for entry in sources if entry.get("enabled", True)),
        notifiers=tuple(entry for entry in notifiers if entry.get("enabled", True)),
        watchlist_path=watchlist_path,
        poll_interval_seconds=seconds,
        state_path=state_path,
        hidden_source_hosts=hidden,
        adobe_commerce=_bool_option(document.get("adobe_commerce", False), "adobe_commerce"),
        web_host=web_host,
        web_port=int(web_port),
        raw=document,
        secret_names=secret_names,
        secret_values=secret_values,
    )


def collect_secrets(config: Config, env: dict[str, str] | None = None) -> list[str]:
    """Every ${NAME} the config referenced, so the CLI can redact its value from logs.

    The names come from the file as written: ``Config.raw`` already holds expanded values, so scanning
    it would find nothing to redact.
    """
    return list(config.secret_names)


def secret_values(config: Config) -> list[str]:
    """The expanded secret values, so a log line cannot carry one even when it was read from a file."""
    return list(config.secret_values)
