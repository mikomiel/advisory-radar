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


def expect_schema(document: dict, expected: str, owner: str) -> dict:
    """Refuse a document unless it declares exactly the schema this reader speaks."""
    if not isinstance(document, dict):
        raise SourceError(f"{owner} emitted a {type(document).__name__}, not an object")
    schema = document.get("schema")
    if schema != expected:
        raise SourceError(
            f"{owner} reports schema {schema!r}, not {expected!r} -- the state file is from another version"
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
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise SourceError(f"{owner} {path} is not JSON: {exc}") from exc
    return expect_schema(document, schema, f"{owner} {path}")


def save_state(path: Path, state: dict) -> None:
    """Atomic replace, mode 0600: a crash mid-write leaves the previous state."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


class LockBusy(RuntimeError):
    """The state lock is held elsewhere (another pass or another process)."""


@contextlib.contextmanager
def state_lock(state_path: Path, *, blocking: bool = True) -> Generator[None]:
    """Exclusive lock beside the state file, held for a whole pass or operator action.

    ``blocking=False`` raises :class:`LockBusy` instead of waiting, so an HTTP handler can answer
    409 rather than stalling until a long pass finishes.
    """
    state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(state_path.with_suffix(".lock"), os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(handle, flags)
        except BlockingIOError as exc:
            raise LockBusy(str(state_path)) from exc
        yield
