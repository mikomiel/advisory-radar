"""Configuration: one YAML file plus environment expansion, validated into dataclasses.

Secrets are never written to the config file: a string ``${NAME}`` is replaced
from the process environment, and a ``${NAME_FILE}`` reference reads the secret from
the file the ``NAME_FILE`` environment variable names (Docker/Podman secrets
pattern). Unknown keys are refused, so a typo fails at startup instead of silently
doing nothing.
"""

from __future__ import annotations

import copy
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .catalogue import SOURCE_SPECS
from .routing import MATCH_KEYS, SEVERITY_TAGS

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
                if lenient:
                    return match.group(0)  # a state-only command never builds the plugin that reads it
                # The variable's value is not in the message: an operator can point a *_FILE variable at the
                # secret itself by mistake, and this error is printed before any redaction exists.
                raise ConfigError(f"${{{name}_FILE}}: no readable file")
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


def expand_entry(entry: dict, env: Mapping[str, str], resolved: list[str] | None = None) -> dict:
    """One plugin entry with its ``${NAME}``/``${NAME_FILE}`` references resolved.

    A form or a probe holds an entry as it is written -- a ``${FRESHRSS_TOKEN}`` reference rather than a token --
    while a builder needs the value. A missing variable raises the ``ConfigError`` a configuration load would,
    naming the variable and never its value: the message is rendered before any redaction exists. A caller that
    may show an error adds the values it just resolved to ``resolved`` so they can be redacted.
    """
    expanded = _expand(copy.deepcopy(entry), dict(env), resolved)
    if not isinstance(expanded, dict):  # unreachable for a mapping input; keeps the return type honest
        raise ConfigError("a plugin entry must be a mapping")
    return expanded


@dataclass(frozen=True)
class Config:
    sources: tuple[dict, ...]
    notifiers: tuple[dict, ...]
    watchlist_path: Path | None
    poll_interval_seconds: int = 900
    state_path: Path = Path("data/state.json")
    hidden_source_hosts: frozenset[str] = frozenset()
    adobe_commerce: bool = False
    #: A free NVD API key: raises the anonymous 5-per-30 s limit to 50 and shortens the pace in ``core.Intel``.
    nvd_api_key: str = ""
    #: Whether a source added from the settings overlay may point into a private network. Off by default: the
    #: check is an operator-controlled guard rail against pointing this instance at a router page by mistake,
    #: turned off for an installation whose sources live on the LAN. It is not an isolation boundary -- see
    #: :func:`advisory_radar.http.private_destination` for what it does and does not cover.
    allow_private_sources: bool = False
    #: Ordered routing rules, first match wins. Empty means every message goes to every enabled notifier,
    #: exactly as it did before routing existed.
    routes: tuple[dict, ...] = ()
    #: Notifier ids for a message no route matches; empty means every enabled notifier.
    default_notifiers: tuple[str, ...] = ()
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    raw: dict = field(default_factory=dict)
    #: ``${NAME}`` references read from the file *before* expansion, for log redaction.
    secret_names: tuple[str, ...] = ()
    #: The values those references expanded to, including the contents of a ``${NAME_FILE}``.
    secret_values: tuple[str, ...] = ()


#: The keys a source entry may carry: the structural ones plus every key the catalogue documents for a
#: built-in. A key a builder needs but this set rejects is an integration nobody can configure, so the
#: allowlist is derived rather than repeated; ``tests/test_catalogue.py`` pins it to the registry and
#: ``tests/test_integrations.py`` loads one complete YAML per built-in through ``load_config`` and
#: ``build_plugins``.
_SOURCE_KEYS = {"id", "type", "enabled"} | {
    key for spec in SOURCE_SPECS.values() for key in (*spec.required, *spec.optional)
}
#: The notifier keys whose value is a credential: the overlay accepts only a reference for them, and an id may
#: not be composed from a variable that supplies one.
NOTIFIER_SECRET_KEYS = ("url", "key", "password", "token")
_NOTIFIER_KEYS = {
    "id",
    "type",
    "url",
    "key",
    "password",
    "headers",
    "enabled",
    # gotify / smtp / ntfy fields
    "token",
    "topic",
    "priority",
    "host",
    "port",
    "from",
    "to",
    "username",
    "use_tls",
    "implicit_tls",
}
_TOP_KEYS = {
    "sources",
    "notifiers",
    "watchlist",
    "poll_interval",
    "state_path",
    "hidden_source_hosts",
    "adobe_commerce",
    "nvd_api_key",
    "routes",
    "default",
    "web",
    "allow_private_sources",
}
#: The keys a routing rule itself may carry; the match keys and the tag set are ``routing.py``'s.
_ROUTE_KEYS = frozenset({"match", "notifiers"})


#: Spellings accepted for a boolean option that came from the environment (expansion yields strings).
_TRUE_WORDS = frozenset({"true", "yes", "on", "1"})
_FALSE_WORDS = frozenset({"false", "no", "off", "0", ""})


def _reference_names(value: object) -> set[str]:
    """The environment variable names a value references, with the ``_FILE`` suffix normalised away.

    ``${TOKEN}`` and ``${TOKEN_FILE}`` are the same variable's two spellings, so an id composed from one must
    meet a credential supplied by the other.
    """
    if not isinstance(value, str):
        return set()
    return {name.removesuffix("_FILE") for name in _ENV_RE.findall(value)}


def _credential_names(document: dict) -> set[str]:
    """Every environment variable that supplies a credential somewhere in this configuration.

    An id may not be composed from one of these: ``id: feed-${CD_TOKEN}`` beside ``api_key: ${CD_TOKEN}`` would
    publish the key on every page, log line and metric label that shows the id. A variable that only names
    something -- ``id: tenant-${TENANT}`` -- stays usable in an id.
    """
    names: set[str] = set()
    for entry in document.get("sources") or []:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("type")
        spec = SOURCE_SPECS.get(kind) if isinstance(kind, str) else None
        for key in spec.secret_keys if spec is not None else ():
            names |= _reference_names(entry.get(key))
    for entry in document.get("notifiers") or []:
        if not isinstance(entry, dict):
            continue
        for key in (*NOTIFIER_SECRET_KEYS, "headers"):
            value = entry.get(key)
            if isinstance(value, dict):
                for item in value.values():
                    names |= _reference_names(item)
            else:
                names |= _reference_names(value)
    return names


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


def load_document(path: Path, *, settings: dict | None = None) -> dict:
    """The YAML document with the overlay merged in, before expansion and filtering.

    The overlay is merged here, before any structural check, and validated by the same validator
    :func:`load_config` runs: an overlay value fails with the message the YAML would give.
    ``settings`` is the overlay mapping already loaded by the caller (``settings.load_settings``);
    ``None`` means no overlay.
    """
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigError(f"{path} is not a mapping")
    if settings is not None:
        _merge_settings(document, settings)
    unknown = set(document) - _TOP_KEYS
    _require(not unknown, f"unknown top-level keys in {path}: {sorted(unknown)}")
    return document


def _merge_settings(document: dict, settings: dict) -> None:
    """Overlay the seven writable keys onto the raw YAML document, in place."""
    from .settings import validate_settings  # lazy: settings.py imports ConfigError from this module

    validate_settings(settings)
    if "notifiers" in settings:
        # A full replacement is how a notifier is added, edited or disabled from the overlay. ``headers`` is
        # the one field the overlay may not store (a mapping can carry a credential), so it stays in the YAML
        # and is carried over by id: editing enablement must not silently drop authentication headers.
        headers_by_id = {
            entry.get("id"): entry["headers"]
            for entry in (document.get("notifiers") or [])
            if isinstance(entry, dict) and "headers" in entry
        }
        merged = []
        for entry in settings["notifiers"]:
            entry = dict(entry) if isinstance(entry, dict) else entry
            if isinstance(entry, dict) and "headers" not in entry and entry.get("id") in headers_by_id:
                entry["headers"] = headers_by_id[entry["id"]]
            merged.append(entry)
        document["notifiers"] = merged
    if "sources" in settings:
        document["sources"] = _merge_sources(document.get("sources"), settings["sources"])
    if "sources_added" in settings:
        document["sources"] = _merge_added_sources(document.get("sources"), settings["sources_added"])
    if "poll_interval" in settings:
        document["poll_interval"] = settings["poll_interval"]
    if "hidden_source_hosts" in settings:
        document["hidden_source_hosts"] = settings["hidden_source_hosts"]
    if "routes" in settings:
        # A full replacement, like the notifier list: the rules are edited as one ordered block, and the
        # merged validator then judges their shape and whether every id names an enabled notifier.
        document["routes"] = settings["routes"]
    if "default" in settings:
        document["default"] = settings["default"]


def _merge_sources(raw: object, overlay: dict) -> object:
    """Apply the per-id ``enabled``/``tag`` edits to the YAML source list; an unknown id is refused."""
    if raw is None:
        raw = []  # an omitted list is the same empty list the validator treats it as
    if not isinstance(raw, list):
        return raw  # the validator refuses the YAML shape, which an overlay cannot repair
    merged = [dict(entry) if isinstance(entry, dict) else entry for entry in raw]
    by_id = {entry.get("id"): entry for entry in merged if isinstance(entry, dict)}
    for identifier, changes in overlay.items():
        entry = by_id.get(identifier)
        if entry is None:
            raise ConfigError(f"settings: no source with id {identifier!r} is defined in the YAML config")
        entry.update(changes)
    return merged


def _merge_added_sources(raw: object, added: object) -> object:
    """Append the overlay's own source entries to the YAML list; a duplicate id is refused.

    The YAML owns membership: the overlay may add a source the file does not define, never redefine one it does.
    Two owners for one id would leave which URL is polled to the merge order, so the collision fails the load.
    """
    if not isinstance(added, list):
        return raw  # ``validate_settings`` already refused a shape that is not a list
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        return raw  # the validator refuses the YAML shape, which an overlay cannot repair
    merged = [dict(entry) if isinstance(entry, dict) else entry for entry in raw]
    known = {entry.get("id") for entry in merged if isinstance(entry, dict)}
    for entry in added:
        if not isinstance(entry, dict):
            continue  # the config validator refuses a non-mapping entry with its own message
        identifier = entry.get("id")
        if identifier in known:
            # The id was checked as a string by ``validate_settings``; it carries no secret, so it may be named.
            raise ConfigError(f"settings: source id {identifier!r} is already defined in the YAML config")
        known.add(identifier)
        merged.append(dict(entry))
    return merged


def load_config(
    path: Path,
    env: dict[str, str] | None = None,
    *,
    lenient: bool = False,
    settings: dict | None = None,
) -> Config:
    """Load and validate one YAML file, with an overlay merged before validation when given."""
    return config_from_document(load_document(path, settings=settings), path, env, lenient=lenient)


def _notifier_selection(value: object, where: str, enabled_ids: list[str], *, strict: bool = True) -> tuple[str, ...]:
    """A non-empty list of ids that all name an enabled notifier in this same configuration.

    ``strict=False`` is the state-only load (``release-parked``/``drop-parked``): it reads the YAML without the
    settings overlay, and a route may name a notifier the overlay adds. Recovery needs the state path, not a
    delivery target, so the shape is still checked and the membership is not.
    """
    valid = isinstance(value, list) and all(isinstance(identifier, str) and identifier for identifier in value)
    _require(valid and bool(value), f"{where} must be a non-empty list of notifier ids")
    if not strict:
        return tuple(value)
    known = set(enabled_ids)
    # A selection value can be a ${...} reference that expanded to a credential (someone wrote
    # ``default: ["${DISCORD_WEBHOOK_URL}"]``), and this message is logged before any redaction exists. Name the
    # position, never the value.
    unknown = [position for position, identifier in enumerate(value, start=1) if identifier not in known]
    if unknown:
        # Built only when it is raised: formatting the message eagerly would index an empty list.
        raise ConfigError(f"{where}: id at position {unknown[0]} is not an enabled notifier")
    return tuple(value)


def _routing(document: dict, notifiers: list[dict], *, strict: bool = True) -> tuple[tuple[dict, ...], tuple[str, ...]]:
    """Validate ``routes``/``default`` after expansion, when a notifier id is the final value in use.

    Called by the one validator with the expanded, enabled-only notifier list: an id that is not configured
    here, or is disabled, is a configuration error rather than a message nobody receives.
    """
    enabled_ids = [entry["id"] for entry in notifiers]
    raw = document.get("routes")
    if raw is None:
        raw = []
    _require(isinstance(raw, list), "routes must be a list")
    routes = []
    for index, route in enumerate(raw, start=1):
        where = f"routes[{index}]"
        _require(isinstance(route, dict), f"{where} must be a mapping")
        unknown = set(route) - _ROUTE_KEYS
        _require(not unknown, f"{where}: unknown keys {sorted(unknown)}")
        match = route.get("match")
        _require(isinstance(match, dict) and bool(match), f"{where}: match must be a non-empty mapping")
        unknown_match = set(match) - MATCH_KEYS
        _require(not unknown_match, f"{where}: unknown match keys {sorted(unknown_match)}")
        for key, value in match.items():
            _require(isinstance(value, str) and bool(value), f"{where}: match.{key} must be a non-empty string")
            if key == "tag":
                # A message's tag is its severity word, so any other value is a rule that can never fire. Refuse
                # it here: a route that silently delivers nothing is worse than a configuration error.
                _require(value in SEVERITY_TAGS, f"{where}: match.tag must be one of {sorted(SEVERITY_TAGS)}")
        routes.append(
            {
                "match": dict(match),
                "notifiers": _notifier_selection(
                    route.get("notifiers"), f"{where}: notifiers", enabled_ids, strict=strict
                ),
            }
        )
    raw_default = document.get("default")
    # An empty list says "no default" (the fallback is every enabled notifier), which an overlay uses to clear
    # a default it inherited from the YAML; only a non-empty selection needs ids checked.
    default = (
        ()
        if raw_default is None or raw_default == []
        else _notifier_selection(raw_default, "default", enabled_ids, strict=strict)
    )
    return tuple(routes), default


def config_from_document(
    document: dict, path: Path, env: dict[str, str] | None = None, *, lenient: bool = False
) -> Config:
    """The one validator: a raw document becomes a frozen ``Config``.

    The input is copied first: a caller that keeps the merged document (the web UI renders its forms
    from it) must not receive the expanded, enabled-only version this function builds.
    """
    env = os.environ if env is None else env
    document = copy.deepcopy(document)
    # Structure is validated on the *unexpanded* document: an entry whose id is missing must not put an
    # expanded password into the error message, and the secret names must be read before expansion
    # replaces them with their values.
    sources = document.get("sources") or []
    notifiers = document.get("notifiers") or []
    credential_names = _credential_names(document)
    _require(isinstance(sources, list) and isinstance(notifiers, list), "sources/notifiers must be lists")
    for entry in (*sources, *notifiers):
        _require(
            isinstance(entry, dict) and isinstance(entry.get("id"), str) and entry["id"],
            "every source/notifier needs a string id",
        )
        _require(isinstance(entry.get("type"), str), f"{entry['id']}: missing type")
        # An id is a name: it appears in routes, logs, the state and -- for a source -- a metric label on the
        # unauthenticated ``/metrics`` endpoint. A whole ``${NAME}`` reference puts a credential in that
        # position, which no reader could tell from a name, so it is refused here while a *composed* id such as
        # ``tenant-${X}`` stays allowed. Credentials belong in a url, token or key.
        _require(
            _ENV_RE.fullmatch(entry["id"]) is None,
            f"{entry['id']}: a plugin id is a name, not a whole ${{NAME}} reference",
        )
        # A composed id is allowed, but not from a variable that supplies a credential somewhere here: the id
        # would publish that credential wherever an id is shown, including an unauthenticated metric label.
        borrowed = _reference_names(entry["id"]) & credential_names
        _require(
            not borrowed,
            f"{entry['id']}: an id may not be composed from a variable that supplies a credential",
        )
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
    # Routing is validated here, after expansion and after the disabled entries were dropped, so a route names
    # a notifier that will actually be built. An absent or empty block keeps the pre-routing behaviour.
    routes, default_notifiers = _routing(document, notifiers, strict=not lenient)

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
    _require(
        state_path.name != "settings.json",
        "state_path must not be named settings.json: that is the settings overlay's filename beside the state file",
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
    raw_nvd_key = document.get("nvd_api_key", "")
    # Never in the message: this value is a credential (${NVD_API_KEY}) and the CLI logs configuration errors
    # before the redaction filter exists.
    _require(isinstance(raw_nvd_key, str), "nvd_api_key must be a string, e.g. ${NVD_API_KEY}")
    return Config(
        sources=tuple(entry for entry in sources if entry.get("enabled", True)),
        notifiers=tuple(entry for entry in notifiers if entry.get("enabled", True)),
        watchlist_path=watchlist_path,
        poll_interval_seconds=seconds,
        state_path=state_path,
        hidden_source_hosts=hidden,
        adobe_commerce=_bool_option(document.get("adobe_commerce", False), "adobe_commerce"),
        allow_private_sources=_bool_option(document.get("allow_private_sources", False), "allow_private_sources"),
        nvd_api_key=raw_nvd_key.strip(),
        routes=routes,
        default_notifiers=default_notifiers,
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
