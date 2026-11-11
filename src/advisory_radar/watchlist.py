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
from collections.abc import Callable
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
    """The document as written, once it is known to be a valid watchlist.

    A file that cannot be read or decoded is never treated as absent or empty: the answer here is the same one the
    pass and the page report, whatever the fault -- including a nesting deep enough that the decoder gives up
    before it has a value, which a hand edit can leave behind and a form payload cannot (that is ``_json_list``).
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
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
    bit, a link loop, an I/O error, an embedded NUL -- raises instead of answering "absent", because that answer
    falls back to the packaged default, which judges every advisory. A present-but-unreadable document must fail
    the pass, both when it is the configured path and when it is the one beside the state file.
    """
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False  # no entry, or a component that is not a directory: nothing can be there
    except OSError as exc:
        raise SourceError(f"watchlist {path} cannot be inspected: {exc}") from exc
    except ValueError as exc:  # an embedded NUL: the path cannot be inspected at all
        raise SourceError(f"watchlist {path} is not a usable path: {exc}") from exc
    return True


def document_path(path: Path) -> Path:
    """The file a name points at: one identity, whatever ``..`` or a link in the name says.

    A save creates the resolved file, so a read that kept the configured spelling could keep failing after a
    successful save -- ``/data/missing/../scope.json`` is the shape that exposes it, because the filesystem cannot
    traverse ``missing`` even though the target it normalises to is fine. Resolving both is what makes the page
    and the pass agree on which file is the document.
    """
    try:
        return path.resolve()
    except (OSError, ValueError) as exc:  # a link loop, an embedded NUL
        raise SourceError(f"watchlist {path} is not a usable path: {exc}") from exc


def resolve_document(path: Path) -> tuple[Path, bool]:
    """The file a name points at, and whether that is a document rather than an entry with nothing behind it.

    A link that points at nothing counts as present: it is the operator's name for a file, and creating its target
    would make the link point at a new document instead of reporting that the one it named is gone.
    """
    resolved = document_path(path)
    if present(resolved):
        return resolved, True
    return resolved, path.is_symlink()


def active_path(configured: Path | None, state_path: Path) -> Path:
    """The document a pass reads: the configured one, the saved one beside the state, else the packaged default.

    A configured path is never replaced by a fallback: a document the operator named but has not created yet
    must fail the pass, because reading the packaged default instead would silently judge every advisory.
    """
    if configured is not None:
        return document_path(configured)
    beside = state_path.with_name(WATCHLIST_NAME)
    return document_path(beside) if present(beside) else document_path(DEFAULT_DOCUMENT)


def display_path(configured: Path | None, state_path: Path) -> Path:
    """The name to show a reader: what the operator wrote, once it is known to resolve to a file at all.

    A page shows the name, not the file behind it: ``watchlist: /data/scope.json`` is the useful sentence, and the
    resolved path is an implementation detail of how a save finds the same file. A name that cannot be used is an
    error here, and the page that shows it says so instead.
    """
    active_path(configured, state_path)
    return editable_path(configured, state_path)


def digest(document: object) -> str:
    """A stable hash of a document's values, so a page knows which document it was rendered from.

    The hash covers the parsed values, not the bytes: a hand edit that only reorders keys or changes
    indentation leaves it alone, while any value a save would replace moves it. The empty string is never a
    digest -- it is what "there is no document yet" is compared against.
    """
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def save_watchlist(path: Path, build: Callable[[dict | None], dict], *, expected: str) -> str:
    """Validate, then atomically replace the document; returns the digest of what was written.

    ``build`` turns the document this save replaces (``None`` when there is none) into the one to write. It runs
    under the lock and after the digest check, which is what lets an editor keep the values a page does not offer
    for editing -- the rows it rendered, a control it showed read-only -- from the document it started from,
    instead of trusting the submission for them. It may raise to refuse the save.

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
    try:
        target = path.resolve()
    except (OSError, ValueError) as exc:  # an embedded NUL, a link loop: no path to read or replace
        raise SourceError(f"watchlist {path} is not a usable path: {exc}") from exc
    if not target.name:
        # A directory root (``watchlist: /``) is a path, not a document, and it has no name for the sidecar lock:
        # refusing it here is the difference between a refusal and a crash.
        raise SourceError(f"watchlist {path} does not name a document; point watchlist: at a file")
    if path.is_symlink() and not present(target):
        # The link names a file that is not there. Creating it would leave the operator editing a document they
        # did not name, with whatever the link pointed at before gone from their point of view.
        raise SourceError(f"{path} is a link to {target}, which does not exist; refusing to create it")
    with WATCHLIST_LOCK, state_lock(target):
        if path.resolve() != target:
            # The link moved while this save waited for the lock. Replacing the old target would report success
            # for a document a pass no longer reads, so the retargeted save is the one that has to retry.
            raise StaleDocument(f"{path} now names another document; reload and make the change again")
        current: dict | None = None
        if present(target):
            # Reading first is what stops a misconfigured path from being overwritten: only a document this
            # module can read as a watchlist is a document it may replace.
            current = read_watchlist(target)
        if (digest(current) if current is not None else "") != expected:
            raise StaleDocument(f"{path} changed since this page was loaded")
        document = build(current)
        parse_policy(document)
        payload = serialize_json(document)
        if len(payload.encode("utf-8")) > MAX_WATCHLIST_BYTES:
            raise SourceError(
                f"the watchlist would be {len(payload.encode('utf-8'))} bytes, more than the "
                f"{MAX_WATCHLIST_BYTES} a save accepts; shorten a product's aliases or domains"
            )
        save_json(target, document)
        return digest(document)
