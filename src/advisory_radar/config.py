"""Configuration: one YAML file plus environment expansion, validated into dataclasses.

Secrets are never written to the config file: a string ``${NAME}`` is replaced
from the process environment, and a ``${NAME_FILE}`` reference reads the secret from
the file the ``NAME_FILE`` environment variable names (Docker/Podman secrets
pattern). Unknown keys are refused, so a typo fails at startup instead of silently
doing nothing.
"""

from __future__ import annotations

import copy
import ipaddress
import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .budget import DEFAULT_PASS_BUDGET_SECONDS, MAX_PASS_BUDGET_SECONDS, MIN_PASS_BUDGET_SECONDS
from .catalogue import SOURCE_SPECS
from .delivery import QuietHours, parse_quiet_hours
from .inventory import INVENTORY_NAME
from .messages import DEFAULT_LANGUAGE, LANGUAGES
from .routing import MATCH_KEYS, SEVERITY_TAGS
from .storage import Store, store_for
from .watchlist import WATCHLIST_NAME

_ENV_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?:_FILE)?\}")


class ConfigError(ValueError):
    pass


def read_secret_file(path: str | None, reference: str) -> str:
    """The text of a secret file with its surrounding whitespace removed.

    Every way the read can fail is a :class:`ConfigError` that names ``reference`` (``${NAME_FILE}`` or the
    ``NAME_FILE`` variable) and nothing else. Neither the path nor the content may reach the message: an
    operator can point a ``*_FILE`` variable at the secret itself by mistake, an ``OSError`` quotes the path,
    a ``UnicodeDecodeError`` quotes the offending byte, and this error is printed before any redaction exists.
    An empty file is refused, because it would load an empty credential and fail later, far from its cause.
    """
    if not path:
        raise ConfigError(f"{reference}: no readable file")
    try:
        # ``is_file`` keeps a FIFO or a device from blocking the read: only a regular file is a secret file. It sits
        # inside the ``try`` because Python 3.13 re-raises the ``OSError`` of a failed stat (a name that is too long,
        # a directory that cannot be searched) with the path in its message; 3.14 returns ``False``.
        if not Path(path).is_file():
            raise ConfigError(f"{reference}: no readable file")
        contents = Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        raise ConfigError(f"{reference}: no readable file") from None
    except UnicodeDecodeError:
        raise ConfigError(f"{reference}: the file is not UTF-8 text") from None
    if not contents:
        raise ConfigError(f"{reference}: the file is empty")
    return contents


#: The shortest process secret (the web auth token, the webhook intake secret) a start accepts. The session cookie
#: is signed with the token, so a short one is a guessable key; ``openssl rand -hex 24`` makes twice this.
MIN_SECRET_LENGTH = 24


def env_secret(env: Mapping[str, str], name: str, *, minimum: int = 0) -> str:
    """A process secret from ``NAME`` or from the file ``NAME_FILE`` names; ``''`` when neither is set.

    This is the one resolver for the environment-only secrets, so the ``_FILE`` form (the Docker and Podman
    secrets pattern, which keeps the value out of a process listing) behaves as it does inside a ``${NAME_FILE}``
    reference: the file's surrounding whitespace is dropped and every failed read is a :class:`ConfigError` that
    names the variable and never the path or the content. An empty variable counts as unset, which is how a
    compose file passes a variable it was not given. Setting both forms is an error rather than a precedence an
    operator must remember. ``minimum`` refuses a value shorter than that, naming the variable that supplied it
    and never echoing the value.
    """
    direct = env.get(name, "")
    path = env.get(f"{name}_FILE", "")
    if direct and path:
        raise ConfigError(f"{name} and {name}_FILE are both set; set one of them")
    source = f"{name}_FILE" if path else name
    value = read_secret_file(path, source) if path else direct
    if value and len(value) < minimum:
        raise ConfigError(
            f"{source}: the secret must be at least {minimum} characters; generate one with: openssl rand -hex 24"
        )
    return value


#: The addresses whose ``X-Forwarded-For`` the server believes when ``ADVISORY_RADAR_FORWARDED_ALLOW_IPS`` is
#: unset: a proxy on the same host. uvicorn's default is the same, but it is passed explicitly so its own
#: ``FORWARDED_ALLOW_IPS`` variable, which nothing here documents, is never consulted.
DEFAULT_FORWARDED_ALLOW_IPS = ("127.0.0.1", "::1")
FORWARDED_ALLOW_IPS_VARIABLE = "ADVISORY_RADAR_FORWARDED_ALLOW_IPS"


def forwarded_allow_ips(env: Mapping[str, str]) -> list[str]:
    """The reverse-proxy addresses the server may believe about the client, from ``ADVISORY_RADAR_FORWARDED_ALLOW_IPS``.

    Behind a reverse proxy every connection comes from the proxy, so the login throttle sees one peer for every
    client unless the server reads the client from ``X-Forwarded-For`` -- which it does only for a connection
    from an address listed here. The value is a comma-separated list of addresses and networks; unset or blank
    means loopback only. A list that would trust every client is refused (``*``, ``0.0.0.0/0``, ``::/0``): any
    peer could then pick its own throttle key and the address a request is logged under. An entry uvicorn
    cannot parse is refused as well, because uvicorn keeps it as a literal that never matches and the operator
    would be left trusting no proxy without being told.
    """
    entries = [item.strip() for item in env.get(FORWARDED_ALLOW_IPS_VARIABLE, "").split(",") if item.strip()]
    for entry in entries:
        if entry == "*":
            raise ConfigError(
                f"{FORWARDED_ALLOW_IPS_VARIABLE}: '*' would trust every client; list the proxy's addresses"
            )
        try:
            # The same parse uvicorn applies: a network when it holds a "/", an address otherwise.
            parsed = ipaddress.ip_network(entry) if "/" in entry else ipaddress.ip_address(entry)
        except ValueError:
            raise ConfigError(
                f"{FORWARDED_ALLOW_IPS_VARIABLE}: {entry!r} is not an IP address or a network such as 192.0.2.0/24"
            ) from None
        if isinstance(parsed, ipaddress.IPv4Network | ipaddress.IPv6Network) and parsed.prefixlen == 0:
            raise ConfigError(
                f"{FORWARDED_ALLOW_IPS_VARIABLE}: {entry!r} would trust every client; list the proxy's addresses"
            )
    return entries or list(DEFAULT_FORWARDED_ALLOW_IPS)


def _expand(value: object, env: dict[str, str], resolved: list[str] | None = None, *, lenient: bool = False) -> object:
    if isinstance(value, str):

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            file_mode = match.group(0).endswith("_FILE}")
            if file_mode:
                # ``name`` already ends in ``_FILE`` (the group is greedy), so the reference is named as written.
                try:
                    contents = read_secret_file(env.get(name + "_FILE") or env.get(name), match.group(0))
                except ConfigError:
                    if lenient:
                        return match.group(0)  # a state-only command never builds the plugin that reads it
                    raise
                if resolved is not None:
                    resolved.append(contents)  # the value, not the path, is what must be redacted
                return contents
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


#: The names the ``thresholds`` block may carry, in the order its documentation lists them.
THRESHOLD_KEYS = ("critical_cvss", "critical_epss", "suppress_below_cvss")


@dataclass(frozen=True)
class Thresholds:
    """The three numbers the severity decision reads.

    Owned by the configuration because they *are* configuration: ``core`` takes them as an argument instead of
    reading a module constant, so a value saved from the browser applies to the next pass instead of the next
    release. The defaults are the numbers the code hardcoded before this block existed, so an installation that
    never writes it keeps its behaviour exactly.
    """

    #: At or above this CVSS a CVE can be critical: with a remote, unauthenticated, no-interaction vector, or
    #: with an EPSS score at or above ``critical_epss``.
    critical_cvss: float = 9.0
    #: At or above this exploitation probability a CVE with a CVSS at or above ``critical_cvss`` is critical.
    critical_epss: float = 0.10
    #: Below this CVSS a completely measured CVE is recorded and watched, but never sent.
    suppress_below_cvss: float = 4.0

    def snapshot(self) -> list[float]:
        """The three numbers as a JSON list, so a watch entry can record which rules judged it."""
        return [self.critical_cvss, self.critical_epss, self.suppress_below_cvss]

    @classmethod
    def from_snapshot(cls, value: object) -> Thresholds:
        """The thresholds a watch entry recorded; a damaged or missing record means the defaults.

        The state is JSON a person can edit by hand, and entries written before thresholds were configurable
        carry no record at all: both have to judge instead of raising.
        """
        members = value if isinstance(value, (list, tuple)) else ()
        usable = len(members) == 3 and all(
            isinstance(member, (int, float)) and not isinstance(member, bool) and math.isfinite(member)
            for member in members
        )
        return cls(*(float(member) for member in members)) if usable else DEFAULT_THRESHOLDS


DEFAULT_THRESHOLDS = Thresholds()


def _threshold_number(raw: object, where: str) -> float:
    """One number from the ``thresholds`` block; the value itself never reaches the message.

    A block can be written with a ``${NAME}`` reference, which expands to a string of unknown content, and these
    messages are logged before any redaction exists.
    """
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(raw):
        raise ConfigError(f"{where} must be a number")
    return float(raw)


def _thresholds(raw: object, *, base: Thresholds = DEFAULT_THRESHOLDS, context: str = "") -> Thresholds:
    """The validated ``thresholds`` block; an absent one is ``base``, never an error.

    ``base`` is what a partial block is completed from: the defaults for the global block, and the global
    block for a source's own, so a source states only the numbers it wants to differ. ``context`` prefixes
    each message with the entry that carries the block -- while the wording stays exactly the one the
    global block gives -- because two blocks share these three keys and a refusal must say whose it is.
    """
    where = f"{context}thresholds"
    if raw is None:
        return base
    _require(isinstance(raw, dict), f"{where} must be a mapping")
    unknown = set(raw) - set(THRESHOLD_KEYS)
    _require(not unknown, f"{where}: unknown keys {sorted(unknown)}")
    values = {key: getattr(base, key) for key in THRESHOLD_KEYS}
    for key in THRESHOLD_KEYS:
        if key in raw:
            values[key] = _threshold_number(raw[key], f"{where}.{key}")
    thresholds = Thresholds(**values)
    _require(0 < thresholds.critical_cvss <= 10, f"{where}.critical_cvss must be above 0 and at most 10")
    _require(0 < thresholds.critical_epss <= 1, f"{where}.critical_epss must be above 0 and at most 1")
    _require(
        0 <= thresholds.suppress_below_cvss <= thresholds.critical_cvss,
        f"{where}.suppress_below_cvss must be between 0 and thresholds.critical_cvss",
    )
    return thresholds


@dataclass(frozen=True)
class Config:
    sources: tuple[dict, ...]
    notifiers: tuple[dict, ...]
    watchlist_path: Path | None
    #: Every source id the configuration declares, including an entry with ``enabled: false``. The pipeline
    #: keeps a disabled source's carry, validators and cursors because it was not discarded -- only a source
    #: missing from this set was removed from the configuration, and its stored work goes with it.
    declared_source_ids: frozenset[str] = frozenset()
    #: Whether every declared id could be resolved. False means at least one still spells an ``${NAME}``
    #: reference the lenient expansion could not fill, so the set cannot say whether stored work under another
    #: spelling belongs to a removed source: the pipeline then keeps every source's stored work.
    declared_source_ids_complete: bool = True
    poll_interval_seconds: int = 900
    #: Per-source poll intervals in seconds, keyed by source id. A source absent from this map is polled at
    #: ``poll_interval_seconds``. The pipeline throttles the fetch only: re-evaluation, escalation and delivery
    #: keep running for every source every pass, so a slow feed never delays an alert about something else.
    source_intervals: Mapping[str, int] = field(default_factory=dict)
    #: The seconds one pass may spend waiting on upstream servers (``budget.py``). YAML-only: it bounds how long the
    #: state lock is held, which is a deployment decision rather than something to change from the settings form.
    pass_budget_seconds: int = DEFAULT_PASS_BUDGET_SECONDS
    state_path: Path = Path("data/state.json")
    #: Where the document lives: empty is the JSON file at ``state_path``, or a ``sqlite:///`` / ``postgresql://``
    #: URL. YAML-only -- the overlay cannot move the store, exactly as it cannot move ``state_path``.
    storage: str = ""
    #: The directory a dropped SBOM or scan result is picked up from, or ``None``. YAML-only, and always inside the
    #: directory of the state file or of this configuration: a browser session never chooses a file to read.
    inventory_dir: Path | None = None
    #: How old an imported inventory may be before it can no longer confirm that an advisory does not apply.
    inventory_max_age_days: int = 30
    hidden_source_hosts: frozenset[str] = frozenset()
    adobe_commerce: bool = False
    #: A free NVD API key: raises the anonymous 5-per-30 s limit to 50 and shortens the pace in ``core.Intel``.
    nvd_api_key: str = ""
    #: The environment variables the settings overlay may reference, as family names (``X`` and ``X_FILE`` are
    #: one). YAML-only and empty by default: see :func:`unlisted_overlay_references`.
    overlay_references: frozenset[str] = frozenset()
    #: Whether a source added from the settings overlay may point into a private network. Off by default: the
    #: check is an operator-controlled guard rail against pointing this instance at a router page by mistake,
    #: turned off for an installation whose sources live on the LAN. It is not an isolation boundary -- see
    #: :func:`advisory_radar.http.private_destination` for what it does and does not cover.
    allow_private_sources: bool = False
    #: The severity thresholds in force; see :class:`Thresholds`. Never read from a module constant in ``core``,
    #: or a saved overlay could not change the next pass.
    thresholds: Thresholds = DEFAULT_THRESHOLDS
    #: Per-source blocks resolved at load time, keyed by source id. Empty for a configuration that states no
    #: override, so the global block judges every message exactly as before this key existed.
    source_thresholds: Mapping[str, Thresholds] = field(default_factory=dict)
    #: Whether the advisories a pass delivers to one routing group travel as one digest message. Off by
    #: default, so an installation that never enables it sends exactly the messages it sent before.
    digest: bool = False
    #: The local-time window in which non-critical messages wait in the queue; ``None`` is no window. Held
    #: entries stay pending and are released after the window ends, never counted as a failed attempt.
    quiet_hours: QuietHours | None = None
    #: The language of every notification's text (``messages.LANGUAGES``). The routing tag a notifier receives stays
    #: English. YAML-only: the overlay does not write it, and a reload applies it from the next pass.
    language: str = DEFAULT_LANGUAGE
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

    def thresholds_for(self, source_id: str | None = None) -> Thresholds:
        """The numbers a source's items are judged by: its own block, or the global one.

        A source with no block, a source no longer configured and a message that came from no source at all
        all resolve to the global block -- which is what judged every message before overrides existed.
        """
        return self.source_thresholds.get(source_id or "", self.thresholds)

    def store(self) -> Store:
        """Where this configuration keeps the state document: the JSON file unless ``storage`` says otherwise."""
        return store_for(self.storage, self.state_path)


#: The keys a source entry may carry: the structural ones plus every key the catalogue documents for a
#: built-in. A key a builder needs but this set rejects is an integration nobody can configure, so the
#: allowlist is derived rather than repeated; ``tests/test_catalogue.py`` pins it to the registry and
#: ``tests/test_integrations.py`` loads one complete YAML per built-in through ``load_config`` and
#: ``build_plugins``. ``thresholds`` and ``interval`` are structural rather than builder keys: neither reaches a
#: source's constructor. ``thresholds`` changes the rules the source's items are judged by, and ``interval``
#: changes how often it is polled.
_SOURCE_KEYS = {"id", "type", "enabled", "thresholds", "interval"} | {
    key for spec in SOURCE_SPECS.values() for key in (*spec.required, *spec.optional)
}
#: The notifier keys whose value is a credential: the overlay accepts only a reference for them, and an id may
#: not be composed from a variable that supplies one. ``secret`` signs a generic webhook's requests; the other
#: four authenticate the channel itself.
NOTIFIER_SECRET_KEYS = ("url", "key", "password", "token", "secret")
_NOTIFIER_KEYS = {
    "id",
    "type",
    "url",
    "key",
    "password",
    "secret",
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
    "pass_budget",
    "state_path",
    "storage",
    "inventory",
    "hidden_source_hosts",
    "adobe_commerce",
    "nvd_api_key",
    "routes",
    "default",
    "web",
    "allow_private_sources",
    "thresholds",
    "digest",
    "quiet_hours",
    "language",
    "overlay_references",
}
#: The keys a routing rule itself may carry; the match keys and the tag set are ``routing.py``'s.
_ROUTE_KEYS = frozenset({"match", "notifiers"})
#: The numeric match predicates and the highest value each can accept, which is the range the measured
#: score itself occupies: a rule outside it could never match, so it is a configuration error.
_MATCH_NUMBERS = {"min_cvss": 10.0, "epss_gte": 1.0}


#: Spellings accepted for a boolean option that came from the environment (expansion yields strings).
_TRUE_WORDS = frozenset({"true", "yes", "on", "1"})
_FALSE_WORDS = frozenset({"false", "no", "off", "0", ""})


def _base_name(name: str) -> str:
    """The variable family a reference belongs to: ``X``, ``X_FILE`` and ``X_FILE_FILE`` share an ``X`` chain.

    ``_expand`` reads ``${X_FILE}`` from ``X_FILE`` or ``X``, and ``${X_FILE_FILE}`` from ``X_FILE_FILE`` or
    ``X_FILE`` -- so a spelling with more suffixes still reaches the same secret, and stripping one suffix would
    let it slip past the id check.
    """
    while name.endswith("_FILE") and len(name) > len("_FILE"):
        name = name[: -len("_FILE")]
    return name


def _reference_names(value: object) -> set[str]:
    """Every environment reference a value carries, at any depth, as family names.

    It walks lists and mappings: a credential position can hold either, and ``_expand`` resolves the strings
    inside one, so a shape the scanner skipped would still supply the value an id borrows.
    """
    if isinstance(value, str):
        return {_base_name(name) for name in _ENV_RE.findall(value)}
    if isinstance(value, list):
        return set().union(*(_reference_names(item) for item in value)) if value else set()
    if isinstance(value, dict):
        return set().union(*(_reference_names(item) for item in value.values())) if value else set()
    return set()


_VARIABLE_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")


def _overlay_references(document: dict) -> frozenset[str]:
    """The variable names the YAML lets the settings overlay reference; none unless the file lists some.

    ``overlay_references`` is not an overlay key, so a browser session cannot widen its own reach. A name is a
    variable family like everywhere else here: ``X`` and ``X_FILE`` allow the same variable.
    """
    raw = document.get("overlay_references")
    if raw is None:
        return frozenset()
    valid = isinstance(raw, list) and all(isinstance(name, str) and _VARIABLE_NAME.fullmatch(name) for name in raw)
    _require(valid, "overlay_references must be a list of environment variable names, e.g. [FEED_TOKEN]")
    return frozenset(_base_name(name) for name in raw)


def _list_twin(item: object, position: int, twin: object) -> object:
    """The YAML value that owns one overlay list item, or ``None``.

    A plugin entry is owned by the YAML entry with the same id *and* type; a string, by being a member of the
    YAML list; anything else (a routing rule) by its position.
    """
    if not isinstance(twin, list):
        return None
    if isinstance(item, dict) and isinstance(item.get("id"), str):
        return next(
            (
                entry
                for entry in twin
                if isinstance(entry, dict) and entry.get("id") == item["id"] and entry.get("type") == item.get("type")
            ),
            None,
        )
    if isinstance(item, str):
        return item if item in twin else None
    return twin[position] if position < len(twin) else None


def _walk_references(value: object, twin: object, allowed: frozenset[str], found: set[str]) -> None:
    if isinstance(value, str):
        if value != twin:  # the YAML's own string, at the place the YAML wrote it, is not the overlay's reference
            found.update(name for name in _reference_names(value) if name not in allowed)
    elif isinstance(value, dict):
        for key, item in value.items():  # a mapping key is literal text: ``_expand`` never expands one
            _walk_references(item, twin.get(key) if isinstance(twin, dict) else None, allowed, found)
    elif isinstance(value, list):
        for position, item in enumerate(value):
            _walk_references(item, _list_twin(item, position, twin), allowed, found)


def unlisted_overlay_references(settings: dict, document: dict, allowed: frozenset[str]) -> list[str]:
    """The variables an overlay references that the YAML did not list under ``overlay_references``, sorted.

    ``${NAME}`` reads *any* variable of the process, and the overlay is written from a browser session: left
    open, an authenticated session could send the auth token, a database password or another channel's
    credential to a URL or a mail host of its choosing. So every string of the overlay is checked, not only a
    credential position -- a reference in a path, a host list or a route is still a value the next request or
    error message can carry. Only names are returned; a value never appears.

    The one exemption is the YAML's own string at the same place: the settings forms store whole entries,
    YAML-owned references included, and switching one notifier off must not need its variable listed. "The
    same place" is the same notifier (id and type) and the same key, or the same source id and key, with the
    string equal character for character; a copy anywhere else is the overlay's own use. ``sources_added`` has
    no YAML twin, because the YAML owns membership.
    """
    sources = document.get("sources")
    twins: dict[str, object] = {
        key: document.get(key)
        for key in (
            "notifiers",
            "poll_interval",
            "hidden_source_hosts",
            "routes",
            "default",
            "thresholds",
            "digest",
            "quiet_hours",
        )
    }
    twins["sources"] = (
        {entry["id"]: entry for entry in sources if isinstance(entry, dict) and isinstance(entry.get("id"), str)}
        if isinstance(sources, list)
        else {}
    )
    found: set[str] = set()
    for key, value in settings.items():
        _walk_references(value, twins.get(key), allowed, found)
    return sorted(found)


#: Every key any built-in source kind declares as a credential. The collector uses the union rather than the
#: entry's own kind: ``type`` may itself be a reference, and a key that one kind ignores is still a credential
#: position in the file.
SOURCE_SECRET_KEYS = tuple(sorted({key for spec in SOURCE_SPECS.values() for key in spec.secret_keys}))


def _url_secret_names(value: object) -> set[str]:
    """References a source URL carries outside its host labels.

    A reference in a host label names a host (``https://${TENANT}.example.net/feed``), so an id may use the same
    variable. Anywhere else in the URL -- userinfo, path, query -- is a position a credential occupies
    (``?token=${FEED_TOKEN}``), so an id may not borrow it. A URL with no scheme is scanned whole.
    """
    if not isinstance(value, str):
        return set()
    _, separator, rest = value.partition("://")
    if not separator or not rest:
        return _reference_names(value)
    # The authority ends at the first of the three separators that can follow it: a URL may carry its query
    # straight after the host, with no path at all (``https://feeds.example.net?token=…``).
    ends = [index for index in (rest.find("/"), rest.find("?"), rest.find("#")) if index >= 0]
    cut = min(ends) if ends else len(rest)
    authority, tail = rest[:cut], rest[cut:]
    names = _reference_names(tail)
    if "@" in authority:
        names |= _reference_names(authority.split("@", 1)[0])
    return names


def _credential_names(document: dict) -> set[str]:
    """Every environment variable that supplies a credential somewhere in this configuration.

    An id may not be composed from one of these: ``id: feed-${CD_TOKEN}`` beside ``api_key: ${CD_TOKEN}`` would
    publish the key on every page, log line and metric label that shows the id. A variable that only names
    something -- ``id: tenant-${TENANT}`` -- stays usable in an id. The scan is deliberately blind to whether an
    entry is enabled or which kind it is: both are configuration, and both can supply a value an enabled entry's
    id borrows. The store locator counts too: a PostgreSQL URL embeds a password.
    """
    names: set[str] = set()
    for entry in document.get("sources") or []:
        if isinstance(entry, dict):
            for key in SOURCE_SECRET_KEYS:
                names |= _reference_names(entry.get(key))
            # A token-bearing feed URL is a supported shape the documentation names, so its references count too.
            names |= _url_secret_names(entry.get("url"))
    for entry in document.get("notifiers") or []:
        if isinstance(entry, dict):
            for key in (*NOTIFIER_SECRET_KEYS, "headers"):
                names |= _reference_names(entry.get(key))
    # The store locator can embed a credential (``postgresql://radar:${DB_PASSWORD}@db.example/radar``), and an
    # id composed from that variable would publish the password wherever the id is shown.
    names |= _reference_names(document.get("storage"))
    names |= _reference_names(document.get("nvd_api_key"))
    return names


#: The default for ``inventory.max_age_days``; the largest accepted value is 3650 (ten years).
INVENTORY_MAX_AGE_DAYS = 30
_INVENTORY_KEYS = frozenset({"dir", "max_age_days"})


def _inventory_options(value: object, config_path: Path, state_path: Path) -> tuple[Path | None, int]:
    """The ``inventory`` block: the drop directory and the age after which an inventory is stale.

    ``dir`` is read from the data volume or the configuration directory and never from anywhere else, so a
    typo cannot point the importer at a system directory. A relative name is relative to the directory of the
    state file. The directory must lie strictly inside one of the two and must not contain the state file's own
    directory, so no document this program writes can ever be mistaken for a file dropped there.
    """
    if value is None:
        return None, INVENTORY_MAX_AGE_DAYS
    _require(isinstance(value, dict), "inventory must be a mapping")
    _require(not set(value) - _INVENTORY_KEYS, f"unknown inventory keys {sorted(set(value) - _INVENTORY_KEYS)}")
    age = value.get("max_age_days", INVENTORY_MAX_AGE_DAYS)
    _require(
        isinstance(age, int) and not isinstance(age, bool) and 1 <= age <= 3650,
        "inventory.max_age_days must be an integer in 1..3650",
    )
    raw = value.get("dir")
    if raw is None:
        return None, age
    _require(isinstance(raw, str) and bool(raw) and "\x00" not in raw, "inventory.dir must be a directory path")
    try:
        state_dir = state_path.resolve().parent
        config_dir = config_path.resolve().parent
        chosen = Path(raw)
        resolved = (chosen if chosen.is_absolute() else state_dir / chosen).resolve()
    except (OSError, RuntimeError) as exc:  # a link loop
        raise ConfigError("inventory.dir is not a usable path") from exc
    inside = any(root in resolved.parents for root in (state_dir, config_dir))
    _require(
        inside,
        "inventory.dir must be a directory inside the directory of state_path or of the configuration file",
    )
    _require(
        state_dir != resolved and resolved not in state_dir.parents,
        "inventory.dir must not contain the directory of state_path",
    )
    return resolved, age


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
    """Overlay the ten writable keys onto the raw YAML document, in place."""
    from .settings import validate_settings  # lazy: settings.py imports ConfigError from this module

    validate_settings(settings)
    allowed = _overlay_references(document)
    unlisted = unlisted_overlay_references(settings, document, allowed)
    if unlisted:
        # Names only: a variable's name is configuration, what it holds may be a credential, and this message is
        # shown on the settings page and logged before any redaction exists.
        raise ConfigError(
            "settings: the overlay references variables the YAML does not list under overlay_references: "
            f"{', '.join(unlisted)}"
        )
    if "notifiers" in settings:
        # A full replacement is how a notifier is added, edited or disabled from the overlay. ``headers`` is a
        # mapping the overlay may not store at all, and a signing ``secret`` is a credential the overlay may
        # store only as a reference. Either can stay in the YAML, so both are carried over by id: editing
        # enablement or an ordinary field must not silently drop authentication headers or unsign a webhook.
        carried_keys = ("headers", "secret")
        yaml_notifiers = [
            entry
            for entry in (document.get("notifiers") or [])
            if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        ]
        carried_by_id = {
            entry["id"]: {key: entry[key] for key in carried_keys if key in entry} for entry in yaml_notifiers
        }
        owners = {entry["id"]: entry for entry in yaml_notifiers}
        merged = []
        for entry in settings["notifiers"]:
            entry = dict(entry) if isinstance(entry, dict) else entry
            if isinstance(entry, dict):
                for key, value in (carried_by_id.get(entry.get("id")) or {}).items():
                    entry.setdefault(key, value)
                _pin_credential_destination(entry, owners.get(entry.get("id")))
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
    if "digest" in settings:
        # A plain replacement: the form renders the saved policy, so an unticked box must turn a YAML digest off.
        document["digest"] = settings["digest"]
    if "quiet_hours" in settings:
        # An empty string is the form's "off" and overrides a YAML window too; the parser reads it as no window.
        document["quiet_hours"] = settings["quiet_hours"]
    if "routes" in settings:
        # A full replacement, like the notifier list: the rules are edited as one ordered block, and the
        # merged validator then judges their shape and whether every id names an enabled notifier.
        document["routes"] = settings["routes"]
    if "default" in settings:
        document["default"] = settings["default"]
    if "thresholds" in settings:
        # Merged key by key, unlike ``routes``: the numbers are independent, so an overlay that carries one of
        # them leaves the YAML's other two in force, and clearing one field falls back to the YAML value.
        raw_thresholds = document.get("thresholds")
        if isinstance(raw_thresholds, dict):
            document["thresholds"] = {**raw_thresholds, **settings["thresholds"]}
        elif raw_thresholds is None:
            document["thresholds"] = dict(settings["thresholds"])
        # A block that is not a mapping is refused by the validator; an overlay cannot repair it.


#: Per notifier type, the keys that say where a credential is sent when the overlay may write them as plain
#: text. Every other type sends its credential to a ``url`` that is itself a reference-only key
#: (``NOTIFIER_SECRET_KEYS``), which the ``overlay_references`` allowlist already governs; only SMTP names its
#: server in ``host``/``port`` and its TLS mode in ``use_tls``/``implicit_tls``, none of them a reference.
#: ``tests/test_settings_overlay.py`` pins this table against every notifier builder, so a new type has to be
#: classified here before it can ship.
CREDENTIAL_DESTINATION_KEYS = {"smtp": ("host", "port", "use_tls", "implicit_tls")}


def _pin_credential_destination(entry: dict, owner: dict | None) -> None:
    """Keep a YAML-owned credential where the YAML sends it, whatever the overlay says.

    The settings form stores the whole notifier, including the ``password`` reference the YAML wrote, and that
    reference is the YAML's own. If the same entry could also change the server and drop TLS, one edit would
    send the file's password to any host in plaintext. So for an entry that is the same id and type as a YAML
    notifier owning a ``password``, the destination keys come from the YAML -- their absence included, so a
    TLS default cannot be switched off by writing a value the file never set. This overwrites, unlike the
    ``setdefault`` that carries ``headers`` and ``secret``: those are credentials the overlay may not write,
    these are values it may.

    The type is read as written, before expansion. That is sound because ``config_from_document`` refuses a
    ``${NAME}`` reference in a notifier ``type``: a document that loads has the type here that the builder gets.
    """
    if owner is None or entry.get("type") != owner.get("type") or "password" not in owner:
        return
    for key in CREDENTIAL_DESTINATION_KEYS.get(str(owner.get("type")), ()):
        if key in owner:
            entry[key] = owner[key]
        else:
            entry.pop(key, None)


def _merge_sources(raw: object, overlay: dict) -> object:
    """Apply the per-id ``enabled``/``tag``/``thresholds`` edits to the YAML source list; an unknown id is refused."""
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
        if isinstance(changes, dict):
            # ``thresholds`` merges key by key, exactly like the global block: a number saved here must not
            # silently drop the YAML's other keys for this source, and clearing one field in the form has to
            # fall back to the YAML value rather than delete the whole override.
            saved = changes.get("thresholds")
            if isinstance(saved, dict) and isinstance(entry.get("thresholds"), dict):
                changes = {**changes, "thresholds": {**entry["thresholds"], **saved}}
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
        # A match value is validated by its key: the four string keys are names and patterns, the two numeric
        # predicates are numbers in the range the score itself occupies, and ``kev`` is the boolean it reads.
        # Accepting "a non-empty string" for all of them would let ``min_cvss: "9.5"`` load and never fire.
        validated: dict = {}
        for key, value in match.items():
            position = f"{where}: match.{key}"
            if key in _MATCH_NUMBERS:
                high = _MATCH_NUMBERS[key]
                number = _threshold_number(value, position)
                _require(0 < number <= high, f"{position} must be above 0 and at most {high:g}")
                validated[key] = number
            elif key == "kev":
                _require(isinstance(value, bool), f"{position} must be true or false")
                validated[key] = value
            else:
                _require(isinstance(value, str) and bool(value), f"{position} must be a non-empty string")
                if key == "tag":
                    # A message's tag is its severity word, so any other value is a rule that can never fire.
                    # Refuse it here: a route that silently delivers nothing is worse than a configuration error.
                    _require(value in SEVERITY_TAGS, f"{position} must be one of {sorted(SEVERITY_TAGS)}")
                validated[key] = value
        routes.append(
            {
                "match": validated,
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


#: The longest pace a poll interval may name. The scheduler waits on ``Event.wait``, which raises
#: ``OverflowError`` for a timeout beyond what the platform clock holds; a week is far below that and is as
#: slow as an advisory scanner is useful, so a typo cannot park the instance for a year.
MAX_INTERVAL_SECONDS = 7 * 86400
_INTERVAL_UNIT = {"s": 1, "m": 60, "h": 3600}


def _interval_seconds(raw: object, where: str) -> int:
    """An ``<n><s|m|h>`` interval as seconds; the value itself never reaches the message.

    An interval can be written with a ``${NAME}`` reference, which expands to a string of unknown content, and
    this message is logged before any redaction exists. One parser serves the global ``poll_interval`` and the
    per-source ``interval`` so the two cannot accept different spellings or different limits (``0`` is
    refused, and so is anything over seven days).
    """
    match = re.fullmatch(r"(\d+)([smh])", str(raw))
    _require(match is not None, f"{where} must look like 15m, 30s or 12h")
    digits = match.group(1).lstrip("0") or "0"
    # The length is judged before the number is built: ``int`` refuses more than 4300 digits with a bare
    # ``ValueError``, and seven digits already exceed the cap in any unit.
    seconds = int(digits) * _INTERVAL_UNIT[match.group(2)] if len(digits) <= 6 else MAX_INTERVAL_SECONDS + 1
    _require(seconds <= MAX_INTERVAL_SECONDS, f"{where} must be at most 168h (7 days)")
    _require(seconds > 0, f"{where} must be greater than zero")
    return seconds


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
    overlay_references = _overlay_references(document)  # read before expansion: a name is never a reference
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
    for entry in notifiers:
        # A notifier type is a name, never a reference. The type picks the keys that say where a credential is
        # sent (``CREDENTIAL_DESTINATION_KEYS``) and the overlay merge looks them up before ``_expand`` runs, so
        # ``type: ${MAIL_KIND}`` is no known type there and ``smtp`` once expanded: ``host``, ``port`` and
        # ``use_tls`` stay writable from the browser beside the YAML's password. ``search`` rather than
        # ``fullmatch``, because ``_expand`` substitutes a reference anywhere in a string; every entry, because
        # the overlay can enable a disabled one. A source type may stay a reference: the overlay cannot
        # redefine a source the YAML owns, and one it adds names a built-in type literally.
        _require(
            _ENV_RE.search(entry["type"]) is None,
            f"{entry['id']}: a notifier type is a name, not a ${{NAME}} reference; write the type itself",
        )
    ids = [entry["id"] for entry in (*sources, *notifiers)]
    _require(len(ids) == len(set(ids)), f"duplicate plugin ids: {ids}")
    # Every declared source id, enabled or not: only a source missing from this set was *removed* from the
    # configuration, and a removed source's stored work is discarded. A merely disabled one keeps its carry,
    # validators and cursors. Read before the disabled entries are dropped below. A composed id is expanded as
    # an enabled one is, while an unresolvable reference on a disabled entry stays literal: its references are
    # deliberately not resolved (see below), and that must not become a configuration error.
    declared = [_expand(entry["id"], env, lenient=True) for entry in sources]
    declared_source_ids = frozenset(declared)
    # An unresolved reference leaves a declared id unknown: stored work under the id it previously expanded to
    # cannot be told apart from a removed source's, so the pipeline keeps every source's stored work instead of
    # discarding it on a guess. Health follows the enabled sources either way.
    declared_source_ids_complete = not any(_ENV_RE.search(identifier) for identifier in declared)
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
    # After expansion: a block can carry a reference, which arrives as a string and is refused as "not a number".
    thresholds = _thresholds(document.get("thresholds"))
    # A source's own block completes itself from the global one, key by key, and is judged by the same rules.
    # Resolved here so ``core`` looks the numbers up instead of re-reading the document, and only for the
    # sources that run: a disabled plugin's block is not resolved, exactly as its references are not.
    source_thresholds: dict[str, Thresholds] = {
        entry["id"]: _thresholds(entry["thresholds"], base=thresholds, context=f"{entry['id']}: ")
        for entry in sources
        if entry.get("thresholds") is not None
    }
    # Only enabled sources are below, so a disabled entry's interval is judged when it is enabled -- the same
    # rule its other references follow, since a disabled plugin is never built and never expanded.
    source_intervals = {
        entry["id"]: _interval_seconds(entry["interval"], f"{entry['id']}: interval")
        for entry in sources
        if "interval" in entry
    }

    poll = document.get("poll_interval", "15m")
    seconds = _interval_seconds(poll, "poll_interval")
    pass_budget = _interval_seconds(document.get("pass_budget", "10m"), "pass_budget")
    _require(
        MIN_PASS_BUDGET_SECONDS <= pass_budget <= MAX_PASS_BUDGET_SECONDS,
        f"pass_budget must be between {MIN_PASS_BUDGET_SECONDS // 60}m and {MAX_PASS_BUDGET_SECONDS // 3600}h",
    )

    # Delivery policy. ``digest`` accepts the documented boolean spellings after expansion, like every other
    # switch. ``quiet_hours`` is written as the window itself; an empty or absent value is no window, and the
    # parser refuses everything else with a message naming the form and never repeating the value -- it can be
    # a ${NAME} reference that expanded to a credential, and this message is logged before redaction exists.
    digest = _bool_option(document.get("digest", False), "digest")
    raw_quiet_hours = document.get("quiet_hours")
    quiet_hours: QuietHours | None = None
    if raw_quiet_hours is not None and raw_quiet_hours != "":
        try:
            quiet_hours = parse_quiet_hours(raw_quiet_hours)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    # The language of the notification text. Like every option here it can arrive as a ${NAME} reference, and this
    # message is logged before redaction exists, so it names the accepted codes and never repeats the value.
    language = document.get("language", DEFAULT_LANGUAGE)
    _require(isinstance(language, str) and language in LANGUAGES, f"language must be one of {', '.join(LANGUAGES)}")

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
    _require(
        state_path.name != WATCHLIST_NAME,
        f"state_path must not be named {WATCHLIST_NAME}: that is the default watchlist's filename beside the "
        "state file",
    )
    _require(
        state_path.name != INVENTORY_NAME,
        f"state_path must not be named {INVENTORY_NAME}: that is the imported inventory's filename beside the "
        "state file",
    )
    inventory_dir, inventory_max_age_days = _inventory_options(document.get("inventory"), path, state_path)
    # A malformed value must fail here with every other bad key, not at the first pass: ``store_for`` is the
    # one parser, and its refusal names the accepted forms without quoting the value (a URL can carry a
    # password). The store itself is built later, from an already validated value.
    storage = document.get("storage", "")
    _require(isinstance(storage, str), "storage must be a string, e.g. sqlite:////data/state.db")
    try:
        store_for(storage, state_path)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    watchlist = document.get("watchlist")
    _require(
        watchlist is None or isinstance(watchlist, str),
        f"watchlist must be a path to a watchlist file, got {type(watchlist).__name__}",
    )
    # An embedded NUL is not a path any call can take: refusing it here fails at start with a message, instead of
    # a ValueError from the first inspection.
    _require(
        not isinstance(watchlist, str) or "\x00" not in watchlist,
        "watchlist must not contain a NUL byte",
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
        declared_source_ids=declared_source_ids,
        declared_source_ids_complete=declared_source_ids_complete,
        poll_interval_seconds=seconds,
        source_intervals=source_intervals,
        pass_budget_seconds=pass_budget,
        state_path=state_path,
        storage=storage,
        inventory_dir=inventory_dir,
        inventory_max_age_days=inventory_max_age_days,
        hidden_source_hosts=hidden,
        adobe_commerce=_bool_option(document.get("adobe_commerce", False), "adobe_commerce"),
        allow_private_sources=_bool_option(document.get("allow_private_sources", False), "allow_private_sources"),
        nvd_api_key=raw_nvd_key.strip(),
        thresholds=thresholds,
        source_thresholds=source_thresholds,
        digest=digest,
        quiet_hours=quiet_hours,
        language=language,
        routes=routes,
        default_notifiers=default_notifiers,
        web_host=web_host,
        web_port=int(web_port),
        overlay_references=overlay_references,
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
