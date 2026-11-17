"""Atomic JSON state file with a schema tag and an exclusive sidecar lock."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
from collections.abc import Generator
from pathlib import Path


class SourceError(RuntimeError):
    """A state document could not be read. Carries what to show a human."""


def describe_schema(schema: object) -> str:
    """Name a declared schema without representing it.

    ``repr`` on a decoded container recurses, and a hand-edited document can nest deeply enough that it raises
    even though the decoder accepted the value. Only a string -- whose repr is its own text -- is represented;
    anything else is named by its type.
    """
    return f"schema {schema!r}" if isinstance(schema, str) else f"a {type(schema).__name__} schema"


def expect_schema(document: dict, expected: str, owner: str) -> dict:
    """Refuse a document unless it declares exactly the schema this reader speaks."""
    if not isinstance(document, dict):
        raise SourceError(f"{owner} emitted a {type(document).__name__}, not an object")
    schema = document.get("schema")
    if schema != expected:
        raise SourceError(
            f"{owner} reports {describe_schema(schema)}, not {expected!r} -- the state file is from another version"
        )
    return document


def load_state_document(path: Path, schema: str, owner: str) -> dict | None:
    """None when there is no file yet -- the caller seeds instead of publishing.

    A file that exists but is not JSON, or declares another schema, raises
    SourceError: it is never treated as absent, because re-seeding would replay history.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as exc:
        # A directory, a permission error or invalid UTF-8 is an unreadable owner, not an absent one. The
        # probes have to be able to report that; letting it escape turns a scrape into a 500 with no sample.
        raise SourceError(f"{owner} {path} cannot be read: {exc}") from exc
    try:
        document = json.loads(text)
    except (ValueError, RecursionError) as exc:
        # RecursionError: a hand edit can nest arrays past the decoder's limit. It is the same unreadable
        # document as invalid JSON -- the probes, the pass and the CLI answer it by name, never with a traceback.
        raise SourceError(f"{owner} {path} is not JSON: {exc}") from exc
    return expect_schema(document, schema, f"{owner} {path}")


def serialize_json(document: dict, *, compact: bool = False) -> str:
    """The exact text ``save_json`` writes, so a caller can size-check a document before replacing a file.

    Indented by default, because most documents here are ones a person opens to read or fix. ``compact`` is one
    line without padding, which ``save_state`` asks for: the state document is the one that grows, and every
    pass writes all of it again.
    """
    if compact:
        return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _sync_directory(directory: Path) -> None:
    """Flush a directory's entries, so that a rename inside it survives a power cut. Best effort.

    ``os.replace`` is atomic but not durable on its own: the new name lives in the directory until the directory
    is flushed, and a power cut right after a save could bring the previous document back although the new
    file's bytes were synced. A platform or filesystem that cannot open or sync a directory keeps the guarantee it
    had before; a save whose document is already in place must not fail because of it.
    """
    with contextlib.suppress(OSError):
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def save_json(path: Path, document: dict, *, compact: bool = False) -> None:
    """Atomic replace, mode 0600: a crash mid-write leaves the previous document.

    The new bytes are synced before the rename and the directory after it, so a document a save returned for is
    the one a restart finds. The one implementation behind both documents on the data volume: the state file and
    the settings overlay must not have two half-correct writers. ``compact`` is passed through to
    :func:`serialize_json`.
    """
    payload = serialize_json(document, compact=compact)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.stem}-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    _sync_directory(path.parent)


def save_state(path: Path, state: dict) -> None:
    """Atomic replace, mode 0600: a crash mid-write leaves the previous state.

    Written compactly: the state is the one document that grows, and every pass writes all of it again. The
    settings overlay and the watchlist are the files people open, so they keep the indented default.
    """
    save_json(path, state, compact=True)


class LockBusy(RuntimeError):
    """The state lock is held elsewhere (another pass or another process)."""


@contextlib.contextmanager
def state_lock(state_path: Path, *, blocking: bool = True) -> Generator[None]:
    """Exclusive lock beside a document on the data volume, held for a whole pass or operator action.

    The state file takes it around a pass; the watchlist document takes it around a save, because a check-then-write
    is only a check if no other process can write between the two. ``blocking=False`` raises :class:`LockBusy`
    instead of waiting, so an HTTP handler can answer
    409 rather than stalling until a long pass finishes.
    """
    state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(state_path.with_name(state_path.name + ".lock"), os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(handle, flags)
        except BlockingIOError as exc:
            raise LockBusy(str(state_path)) from exc
        yield
