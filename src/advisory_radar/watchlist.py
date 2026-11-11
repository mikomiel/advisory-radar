"""Typed reader and writer for the single packaged Security Advisor scope owner.

The scope is one JSON document (``security-watchlist.v1``): the products to watch, the Debian package
patterns a DSA title must match, and the products to drop even when nothing else is scoped. ``/watchlist``
edits it and this module owns every rule about it -- the shape it must have, where it lives, and what a save
is allowed to replace. A pass reads it again every run, so a saved edit applies to the next one.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path

from .state import SourceError, save_json, serialize_json, state_lock

#: The filename an installation gets when the YAML names no document; one owner, used for the default and
#: for the path beside the state file.
WATCHLIST_NAME = "watchlist.json"
WATCHLIST = Path(WATCHLIST_NAME)  # default; config.py passes the real path
#: The packaged document: what an installation with neither a configured path nor a saved one runs on.
DEFAULT_DOCUMENT = Path(__file__).with_name("watchlist.default.json")
#: A save larger than this is refused (the page form also has to hold it); reading is not capped, so an
#: existing hand-written document keeps working however long it is.
MAX_WATCHLIST_BYTES = 16 * 1024
#: One read-validate-write at a time in this process. Two concurrent saves would otherwise read the same
#: document and one edit would silently replace the other; a save is independent of the state lock, so it
#: still lands while a pass is running.
WATCHLIST_LOCK = threading.RLock()
#: The top-level keys a document must carry, and nothing else: the packaged default, a hand-written file and
#: a browser save all produce exactly these.
DOCUMENT_KEYS = frozenset({"schema", "debian_source_packages", "excluded_products", "products"})
#: The schema tag every document declares.
SCHEMA = "security-watchlist.v1"


@dataclass(frozen=True)
class Product:
    id: str
    aliases: tuple[str, ...]
    domains: tuple[str, ...]
    metadata_only: bool


@dataclass(frozen=True)
class Policy:
    debian_source_packages: tuple[str, ...]
    excluded_products: tuple[str, ...]
    products: tuple[Product, ...]


class StaleDocument(RuntimeError):
    """The document changed between the page that was rendered and the save that would replace it."""


def _strings(value: object, *, empty: bool = False) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or (not value and not empty)
        or any(not isinstance(item, str) or not item.strip() or item != item.strip() for item in value)
    ):
        raise SourceError("watchlist requires nonempty string arrays")
    if len(value) != len(set(value)):
        raise SourceError("watchlist contains duplicate values")
    return tuple(value)


def parse_policy(document: object) -> Policy:
    """Validate one document and read it as a policy; every rule about the shape lives here.

    A caller with a document in hand -- the editor, before it writes anything -- gets the same answer a pass
    gets from the file, so nothing can be saved that the next pass would refuse.
    """
    if not isinstance(document, dict) or set(document) != DOCUMENT_KEYS or document["schema"] != SCHEMA:
        raise SourceError("watchlist schema is invalid")
    rows = document["products"]
    if not isinstance(rows, list):
        raise SourceError("watchlist products are invalid")
    products = []
    ids = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or not {"id", "aliases", "domains"} <= row.keys()
            or set(row) - {"id", "aliases", "domains", "metadata_only"}
        ):
            raise SourceError("watchlist product fields are invalid")
        identifier = row["id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z][a-z0-9-]+", identifier) or identifier in ids:
            raise SourceError("watchlist product identity is invalid")
        metadata_only = row.get("metadata_only", False)
        if type(metadata_only) is not bool:
            raise SourceError("watchlist metadata policy is invalid")
        domains = _strings(row["domains"], empty=True)
        if any(not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)+", domain) for domain in domains):
            raise SourceError("watchlist domain is invalid")
        products.append(Product(identifier, _strings(row["aliases"]), domains, metadata_only))
        ids.add(identifier)
    packages = _strings(document["debian_source_packages"])
    excluded = _strings(document["excluded_products"], empty=True)
    if any(not re.fullmatch(r"\*|[a-z0-9][a-z0-9.+-]*\*?", package) for package in packages):
        raise SourceError("watchlist package pattern is invalid")
    return Policy(packages, excluded, tuple(products))


def read_watchlist(path: Path = WATCHLIST) -> dict:
    """The document as written, once it is known to be a valid watchlist."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SourceError("watchlist cannot be read") from exc
    parse_policy(document)
    return document


def load_policy(path: Path = WATCHLIST) -> Policy:
    return parse_policy(read_watchlist(path))


def editable_path(configured: Path | None, state_path: Path) -> Path:
    """Where a save goes: the configured document, else the one beside the state file.

    ``/config`` is mounted read-only in the container and the packaged default lives inside the installation,
    so an installation that names no document is edited on the writable volume, beside the state file.
    """
    return configured if configured is not None else state_path.with_name(WATCHLIST_NAME)


def present(path: Path) -> bool:
    """Whether the directory entry exists, including a symlink that points at nothing.

    Only a missing entry is ``False``. A path that cannot be inspected -- a parent directory without the search
    bit, a link loop, an I/O error -- raises instead of answering "absent", because that answer falls back to the
    packaged default, which judges every advisory. A present-but-unreadable document must fail the pass, both
    when it is the configured path and when it is the one beside the state file.
    """
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False  # no entry, or a component that is not a directory: nothing can be there
    except OSError as exc:
        raise SourceError(f"watchlist {path} cannot be inspected: {exc}") from exc
    return True


def active_path(configured: Path | None, state_path: Path) -> Path:
    """The document a pass reads: the configured one, the saved one beside the state, else the packaged default.

    A configured path is never replaced by a fallback: a document the operator named but has not created yet
    must fail the pass, because reading the packaged default instead would silently judge every advisory.
    """
    if configured is not None:
        return configured
    beside = state_path.with_name(WATCHLIST_NAME)
    return beside if present(beside) else DEFAULT_DOCUMENT


def digest(document: object) -> str:
    """A stable hash of a document's values, so a page knows which document it was rendered from.

    The hash covers the parsed values, not the bytes: a hand edit that only reorders keys or changes
    indentation leaves it alone, while any value a save would replace moves it. The empty string is never a
    digest -- it is what "there is no document yet" is compared against.
    """
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def save_watchlist(path: Path, document: dict, *, expected: str) -> str:
    """Validate, then atomically replace the document; returns the digest of what was written.

    ``expected`` is the digest the form was rendered from, or ``""`` when there was no file: a page that would
    replace an edit it never saw is refused instead of overwriting it. The target is read before it is
    replaced, so a path that points at another document -- the state file, the settings overlay -- is refused
    rather than overwritten with a watchlist.

    The read, the check and the replacement happen under one lock on ``<document>.lock``, which is what makes the
    check mean anything: two processes that both read the same digest would otherwise both pass it and the later
    replacement would silently lose the earlier edit.

    A symlinked document is replaced at the file it names, never at the link: replacing the link would leave the
    operator's own document untouched and every later edit of it silently ignored. The lock is taken on the same
    resolved path, so two names for one document cannot save past each other.
    """
    parse_policy(document)
    target = path.resolve()
    if path.is_symlink() and not present(target):
        # The link names a file that is not there. Creating it would leave the operator editing a document they
        # did not name, with whatever the link pointed at before gone from their point of view.
        raise SourceError(f"{path} is a link to {target}, which does not exist; refusing to create it")
    with WATCHLIST_LOCK, state_lock(target):
        current = ""
        if present(target):
            # Reading first is what stops a misconfigured path from being overwritten: only a document this
            # module can read as a watchlist is a document it may replace.
            current = digest(read_watchlist(target))
        if current != expected:
            raise StaleDocument(f"{path} changed since this page was loaded")
        payload = serialize_json(document)
        if len(payload.encode("utf-8")) > MAX_WATCHLIST_BYTES:
            raise SourceError(
                f"the watchlist would be {len(payload.encode('utf-8'))} bytes, more than the "
                f"{MAX_WATCHLIST_BYTES} a save accepts; shorten a product's aliases or domains"
            )
        save_json(target, document)
        return digest(document)
