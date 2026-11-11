"""The settings overlay: a small JSON document applied over the YAML configuration.

``settings.json`` lives beside the state file (the writable volume), not beside the YAML
(``/config`` is mounted read-only), and holds only the six keys the UI may change. The
overlay is merged into the YAML *before* ``config.load_config`` validates, so a value the
YAML would refuse is refused with the same message.

Storage and the overlay-specific shape rules live here; the merge and the configuration
validator own everything else. A secret-bearing notifier key may only be a ``${NAME}`` or
``${NAME_FILE}`` reference, and ``headers`` cannot be written at all: no credential ever
reaches this file.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from pathlib import Path

from .catalogue import SOURCE_SPECS
from .config import ConfigError
from .state import save_json, serialize_json

#: The schema tag the stored document declares.
#: One overlay transaction at a time in this process. Each save reads the revision, validates and replaces
#: the file; two concurrent form posts would otherwise read the same revision and one section would be lost.
#: It is deliberately independent of the state lock, so a save still lands while a pass is running.
SETTINGS_LOCK = threading.RLock()
SETTINGS_SCHEMA = "advisory-radar-settings.v1"
#: The filename beside the state file; see :func:`settings_path`.
SETTINGS_NAME = "settings.json"
#: A file larger than this is refused before it is parsed.
MAX_SETTINGS_BYTES = 64 * 1024
#: The only keys the overlay may carry. Everything else stays in the YAML.
OVERLAY_KEYS = frozenset(
    {"notifiers", "sources", "sources_added", "poll_interval", "hidden_source_hosts", "routes", "default"}
)
#: Notifier keys that carry a credential: only a whole-value environment reference is accepted.
SECRET_KEYS = ("url", "key", "password", "token")
#: Exactly one ``${NAME}`` (optionally ``${NAME_FILE}``), with no surrounding text: a value with
#: ``https://host/${TOKEN}`` in it would still put the rest of a credential-bearing URL in the file.
SECRET_REFERENCE = re.compile(r"\$\{[A-Z_][A-Z0-9_]*(?:_FILE)?\}")


def is_reference(value: object) -> bool:
    """Whether a value is exactly one environment reference, e.g. ``${DISCORD_WEBHOOK_URL}``."""
    return isinstance(value, str) and SECRET_REFERENCE.fullmatch(value) is not None


def validate_settings(settings: object) -> dict:
    """Refuse an overlay the runtime could not apply, without repeating the config validator.

    Only rules specific to the overlay live here: the seven-key allowlist, the reference-only secret
    rule, the two-key edit of a YAML source, and the shape of a complete source the overlay adds. Values
    the YAML validator checks -- a poll interval, a hidden-host list, a notifier's keys and its ``enabled``
    boolean, a source's remaining keys, a route's match keys and whether a selected notifier is enabled --
    are merged and left to it, so both sources of truth fail with one message.
    """
    if not isinstance(settings, dict):
        raise ConfigError("settings: the overlay must be a mapping")
    unknown = set(settings) - OVERLAY_KEYS
    if unknown:
        raise ConfigError(f"settings: unknown overlay keys {sorted(unknown)}")
    # ``routes`` and ``default`` are only type-checked here: their shape and the notifier membership are
    # judged by ``config._routing`` after the merge, where an overlay-added notifier is finally known.
    if "routes" in settings and not isinstance(settings["routes"], list):
        raise ConfigError("settings: routes must be a list of {match, notifiers} rules")
    if "default" in settings and not isinstance(settings["default"], list):
        raise ConfigError("settings: default must be a list of notifier ids")
    if "notifiers" in settings:
        entries = settings["notifiers"]
        if not isinstance(entries, list):
            raise ConfigError("sources/notifiers must be lists")
        for entry in entries:
            if not isinstance(entry, dict):
                continue  # not a mapping: the config validator refuses it with its own message
            if "headers" in entry:
                raise ConfigError(
                    f"settings: notifier {entry.get('id')!r}: headers cannot be written by the overlay; "
                    "a mapping can carry a credential"
                )
            for key in SECRET_KEYS:
                if key in entry and not is_reference(entry[key]):
                    raise ConfigError(
                        f"settings: notifier {entry.get('id')!r}: {key} must be a ${{NAME}} or ${{NAME_FILE}} "
                        "reference; a literal secret is never stored"
                    )
    if "sources" in settings:
        sources = settings["sources"]
        if not isinstance(sources, dict):
            raise ConfigError("settings: sources must be a mapping of source id to enabled/tag")
        for identifier, changes in sources.items():
            if not isinstance(changes, dict):
                raise ConfigError(f"settings: source {identifier!r} must map to enabled/tag")
            extra = set(changes) - {"enabled", "tag"}
            if extra:
                raise ConfigError(f"settings: source {identifier!r}: unknown keys {sorted(extra)}")
            if "tag" in changes and not isinstance(changes["tag"], str):
                raise ConfigError(f"settings: source {identifier!r}: tag must be a string")
    if "sources_added" in settings:
        _validate_added_sources(settings["sources_added"])
    return settings


def _validate_added_sources(added: object) -> None:
    """A complete source the overlay adds: a mapping with an id and a built-in type, no literal secret.

    A non-mapping is refused rather than skipped: ``config._merge_added_sources`` skips one it cannot read, so
    the entry would vanish between the two owners and the operator would see a saved source that never ran.
    """
    if not isinstance(added, list):
        raise ConfigError("settings: sources_added must be a list of complete source entries")
    seen: set[str] = set()
    for entry in added:
        if not isinstance(entry, dict):
            raise ConfigError("settings: every added source must be a mapping")
        identifier = entry.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise ConfigError("settings: every added source needs a string id")
        if identifier in seen:
            raise ConfigError(f"settings: added source {identifier!r} is defined twice")
        seen.add(identifier)
        kind = entry.get("type")
        if not isinstance(kind, str) or kind not in SOURCE_SPECS:
            raise ConfigError(
                f"settings: added source {identifier!r} has no built-in type (want one of {sorted(SOURCE_SPECS)})"
            )
        missing = [
            key
            for key in SOURCE_SPECS[kind].required
            if not isinstance(entry.get(key), str) or not str(entry.get(key)).strip()
        ]
        if missing:
            # A complete entry, not a shape that only looks like one: a source missing a required key would be
            # stored and then fail the very build that saves it, with a bare KeyError from the builder.
            raise ConfigError(f"settings: added source {identifier!r} ({kind}) needs {', '.join(missing)}")
        for key in SOURCE_SPECS[kind].secret_keys:
            if key in entry and not is_reference(entry[key]):
                raise ConfigError(
                    f"settings: added source {identifier!r}: {key} must be a ${{NAME}} or ${{NAME_FILE}} "
                    "reference; a literal secret is never stored"
                )


def fingerprint(settings: dict) -> str:
    """A stable hash of an overlay's settings, so an applied marker can name what it applied."""
    canonical = json.dumps(settings, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_settings_document(path: Path) -> dict:
    """The stored document, or an empty revision 0 when there is no file yet.

    An unreadable, oversized, non-JSON or wrong-schema file raises ``ConfigError`` naming it: a
    hand-edited overlay is never treated as absent and silently ignored.
    """
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return {"schema": SETTINGS_SCHEMA, "revision": 0, "updated_at": 0, "settings": {}}
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if size > MAX_SETTINGS_BYTES:
        raise ConfigError(f"{path} is larger than {MAX_SETTINGS_BYTES} bytes; refusing to parse it")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise ConfigError(f"{path} is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigError(f"{path} is not a settings document")
    schema = document.get("schema")
    if schema != SETTINGS_SCHEMA:
        raise ConfigError(f"{path} declares schema {schema!r}, not {SETTINGS_SCHEMA!r}")
    revision = document.get("revision")
    settings = document.get("settings")
    if not isinstance(revision, int) or isinstance(revision, bool) or not isinstance(settings, dict):
        raise ConfigError(f"{path} is not a settings document: revision and settings are missing")
    updated_at = document.get("updated_at", 0)
    return {
        "schema": SETTINGS_SCHEMA,
        "revision": revision,
        "updated_at": updated_at if isinstance(updated_at, int) and not isinstance(updated_at, bool) else 0,
        "settings": settings,
    }


def load_settings(path: Path) -> dict:
    """The overlay settings themselves; a missing file is an empty overlay."""
    return load_settings_document(path)["settings"]


def save_settings(path: Path, settings: dict, *, now: int) -> dict:
    """Validate, then atomically write the overlay; returns the stored document.

    The shape is checked first, so a literal secret cannot be written even by a caller that skipped
    the full merge. The revision always moves forward from the document already on disk, and an
    unreadable previous document refuses the write instead of silently resetting the counter.
    """
    validate_settings(settings)
    with SETTINGS_LOCK:
        previous = load_settings_document(path)
        document = {
            "schema": SETTINGS_SCHEMA,
            "revision": previous["revision"] + 1,
            "updated_at": int(now),
            "settings": settings,
        }
        # The reader refuses a file over the limit, so writing one would brick the next start. Check the
        # exact text that is about to be written, not the form body: JSON escaping can double a value.
        payload = serialize_json(document)
        if len(payload.encode("utf-8")) > MAX_SETTINGS_BYTES:
            raise ConfigError(
                f"the overlay would be {len(payload.encode('utf-8'))} bytes, more than the {MAX_SETTINGS_BYTES} "
                "the reader accepts; shorten a value"
            )
        save_json(path, document)
        return document


def settings_path(state_path: Path) -> Path:
    """The overlay sits beside the state file: ``/data`` is writable, ``/config`` is read-only."""
    return state_path.with_name(SETTINGS_NAME)
