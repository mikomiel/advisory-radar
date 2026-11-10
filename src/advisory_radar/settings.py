"""The settings overlay: a small JSON document applied over the YAML configuration.

``settings.json`` lives beside the state file (the writable volume), not beside the YAML
(``/config`` is mounted read-only), and holds only the four keys the UI may change. The
overlay is merged into the YAML *before* ``config.load_config`` validates, so a value the
YAML would refuse is refused with the same message.

Storage and the overlay-specific shape rules live here; the merge and the configuration
validator own everything else. A secret-bearing notifier key may only be a ``${NAME}`` or
``${NAME}_FILE`` reference, and ``headers`` cannot be written at all: no credential ever
reaches this file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .config import ConfigError
from .state import save_json

#: The schema tag the stored document declares.
SETTINGS_SCHEMA = "advisory-radar-settings.v1"
#: The filename beside the state file; see :func:`settings_path`.
SETTINGS_NAME = "settings.json"
#: A file larger than this is refused before it is parsed.
MAX_SETTINGS_BYTES = 64 * 1024
#: The only keys the overlay may carry. Everything else stays in the YAML.
OVERLAY_KEYS = frozenset({"notifiers", "sources", "poll_interval", "hidden_source_hosts"})
#: Notifier keys that carry a credential: only a whole-value environment reference is accepted.
SECRET_KEYS = ("url", "key", "password", "token")
#: Exactly one ``${NAME}`` (optionally ``${NAME}_FILE``), with no surrounding text: a value with
#: ``https://host/${TOKEN}`` in it would still put the rest of a credential-bearing URL in the file.
SECRET_REFERENCE = re.compile(r"\$\{[A-Z_][A-Z0-9_]*(?:_FILE)?\}")


def is_reference(value: object) -> bool:
    """Whether a value is exactly one environment reference, e.g. ``${DISCORD_WEBHOOK_URL}``."""
    return isinstance(value, str) and SECRET_REFERENCE.fullmatch(value) is not None


def validate_settings(settings: object) -> dict:
    """Refuse an overlay the runtime could not apply, without repeating the config validator.

    Only rules specific to the overlay live here: the four-key allowlist, the reference-only secret
    rule, and the two-key source edit. Values the YAML validator checks -- a poll interval, a
    hidden-host list, a notifier's keys and its ``enabled`` boolean -- are merged and left to it, so
    both sources of truth fail with one message.
    """
    if not isinstance(settings, dict):
        raise ConfigError("settings: the overlay must be a mapping")
    unknown = set(settings) - OVERLAY_KEYS
    if unknown:
        raise ConfigError(f"settings: unknown overlay keys {sorted(unknown)}")
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
                        f"settings: notifier {entry.get('id')!r}: {key} must be a ${{NAME}} or ${{NAME}}_FILE "
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
    return settings


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
    previous = load_settings_document(path)
    document = {
        "schema": SETTINGS_SCHEMA,
        "revision": previous["revision"] + 1,
        "updated_at": int(now),
        "settings": settings,
    }
    save_json(path, document)
    return document


def settings_path(state_path: Path) -> Path:
    """The overlay sits beside the state file: ``/data`` is writable, ``/config`` is read-only."""
    return state_path.with_name(SETTINGS_NAME)
