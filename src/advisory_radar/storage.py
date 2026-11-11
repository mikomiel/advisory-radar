"""Where the state document lives: the JSON file, SQLite, or PostgreSQL.

The pipeline owns the document and ``state.py`` owns its JSON primitives and schema tag; a store owns only
where those bytes are kept and the exclusive lock around a pass. Both promises are the same for every store
because the pipeline depends on them: a save is atomic, so no reader ever sees half a document, and the lock
excludes every other writer -- a pass saves inside it after every source and every delivery.

A configured PostgreSQL URL embeds a password, so nothing here renders the value it was given. Refusals name
the supported forms, ``PostgreSqlStore.__repr__`` names host and database only, and a driver message is
scrubbed before it becomes an exception.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import urllib.parse
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol

from .state import (
    LockBusy,
    SourceError,
    expect_schema,
    load_state_document,
    save_state,
    serialize_json,
    state_lock,
)

#: Repeated from ``core`` instead of imported from it: ``core`` imports ``config``, and the configured store is
#: built where the configuration is read, so importing ``core`` from here would close that cycle.
#: ``tests/test_storage.py`` pins both constants to their owners so the repetition cannot drift.
DEFAULT_SCHEMA = "advisory-radar-state.v1"
DEFAULT_OWNER = "advisory state"

#: Three slashes before a relative path and four before an absolute one; the slashes are the only thing that
#: tells the two apart, which is why the prefix is stripped by hand rather than parsed.
_SQLITE_PREFIX = "sqlite:///"
_POSTGRES_SCHEMES = frozenset({"postgres", "postgresql"})

#: Named in every refusal, and never the value that was refused: a PostgreSQL URL embeds a password, so the
#: rejected text must not be quoted back. ``postgres://`` is libpq's older alias for the same thing.
_UNSUPPORTED_STORE = (
    "unsupported state store; use no value for the JSON file, sqlite:///path/to/state.db, or "
    "postgresql://host/database (postgres:// is the same)"
)


class StoreUnavailable(RuntimeError):
    """A store cannot be opened or used at all: no driver, an unreachable server, a refused connection.

    Deliberately not a :class:`state.SourceError`: the document was never read, so "not re-seeding" is the
    wrong answer, and the caller needs to name the missing piece -- the driver, the server -- instead.
    """


class Store(Protocol):
    """What the pipeline needs from wherever the document lives: its bytes, and the exclusive lock."""

    def load(self) -> dict | None: ...

    def save(self, document: dict) -> None: ...

    def lock(self, *, blocking: bool = True) -> contextlib.AbstractContextManager[None]: ...


class JsonStore:
    """Today's behaviour, unchanged: one JSON file, atomic replace, mode 0600, an ``flock`` sidecar.

    Every method delegates to ``state.py``. The atomic write and the lock are the two things a second
    implementation would get subtly wrong, so this store has no persistence code of its own.
    """

    def __init__(self, path: Path, *, schema: str = DEFAULT_SCHEMA, owner: str = DEFAULT_OWNER) -> None:
        self._path = path
        self._schema = schema
        self._owner = owner

    def load(self) -> dict | None:
        return load_state_document(self._path, self._schema, self._owner)

    def save(self, document: dict) -> None:
        save_state(self._path, document)

    def lock(self, *, blocking: bool = True) -> contextlib.AbstractContextManager[None]:
        return state_lock(self._path, blocking=blocking)


def _read_document(text: object, *, schema: str, owner: str, location: str) -> dict:
    """The stored text as a document, refused exactly as the JSON file store refuses a foreign file.

    Both SQL stores keep the text ``serialize_json`` produced, so the schema check stays the one in
    ``state.expect_schema`` rather than becoming a second set of rules that could disagree with it.
    """
    try:
        document = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise SourceError(f"{owner} {location} is not JSON: {exc}") from exc
    return expect_schema(document, schema, f"{owner} {location}")


_SQLITE_CREATE = """
CREATE TABLE IF NOT EXISTS state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    document TEXT NOT NULL
)
"""

_SQLITE_SELECT = "SELECT document FROM state WHERE id = 1"

_SQLITE_UPSERT = """
INSERT INTO state (id, document) VALUES (1, ?)
ON CONFLICT (id) DO UPDATE SET document = excluded.document
"""


class SqliteStore:
    """The document in a one-row SQLite table, with the lock in a sidecar database.

    The lock is not a transaction on the document database. A ``BEGIN IMMEDIATE`` held for the whole pass
    would collide with this store's own ``save()``, which the pipeline calls inside the lock after every
    source and every delivery; folding the pass into one write transaction instead would roll back the record
    of messages already sent and resend them. The sidecar gives the same cross-process exclusion without
    coupling the lock to the document's write transaction.

    ``synchronous=FULL`` matches the JSON writer's ``fsync``: a committed pass must survive a power cut, or
    the protection against resending a delivered message is lost. WAL is enabled so a reader -- the web UI --
    never waits for a writing pass.
    """

    def __init__(
        self,
        path: Path,
        *,
        schema: str = DEFAULT_SCHEMA,
        owner: str = DEFAULT_OWNER,
        timeout: float = 5.0,
    ) -> None:
        self._path = path
        #: The same suffix ``state.state_lock`` gives the JSON file, so a store and a pass over the same path
        #: still exclude each other.
        self._lock_path = path.with_name(path.name + ".lock")
        self._schema = schema
        self._owner = owner
        self._timeout = timeout
        self._ready = False

    def load(self) -> dict | None:
        connection = None
        try:
            connection = self._connect()
            self._prepare(connection)
            row = connection.execute(_SQLITE_SELECT).fetchone()
        except sqlite3.DatabaseError as exc:
            # The file store's rule, kept: unreadable is not absent, because re-seeding would replay history.
            raise SourceError(f"{self._owner} {self._path} cannot be read: {exc}") from exc
        finally:
            if connection is not None:
                connection.close()
        if row is None:
            return None
        return _read_document(row[0], schema=self._schema, owner=self._owner, location=str(self._path))

    def save(self, document: dict) -> None:
        """One statement, so the write is the row's own transaction and can never join the lock's."""
        payload = serialize_json(document)
        connection = self._connect()
        try:
            self._prepare(connection)
            connection.execute(_SQLITE_UPSERT, (payload,))
        finally:
            connection.close()

    @contextlib.contextmanager
    def lock(self, *, blocking: bool = True) -> Iterator[None]:
        """Hold the sidecar database for the pass, as ``state.state_lock`` holds the ``flock`` file."""
        self._lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # ``blocking=False`` must answer now rather than after the timeout: timeout=0 makes SQLite fail the
        # lock request immediately, and the error it raises is the LockBusy the pipeline already answers with.
        connection = sqlite3.connect(
            self._lock_path,
            timeout=self._timeout if blocking else 0,
            isolation_level=None,
        )
        try:
            os.chmod(self._lock_path, 0o600)
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise LockBusy(str(self._lock_path)) from exc
            try:
                yield
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")
        finally:
            # Closing is the backstop: SQLite rolls back on close, so a failing COMMIT cannot leave the lock
            # held by this process.
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        connection = sqlite3.connect(self._path, timeout=self._timeout, isolation_level=None)
        # SQLite applies the process umask, which would leave the document world-readable; ``state.save_json``
        # earns the same protection with an explicit chmod on the temporary file.
        os.chmod(self._path, 0o600)
        # Per connection, not per database: only journal_mode is stored in the file header.
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _prepare(self, connection: sqlite3.Connection) -> None:
        if self._ready:
            return
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(_SQLITE_CREATE)
        self._ready = True


def _postgres_target(url: str) -> tuple[str, str]:
    """The host and database a PostgreSQL URL names, refusing any other shape without echoing the value.

    Parsing here is a credential control as much as a validation: a refusal that quoted the URL would put its
    password into a log line. The password is never returned from this function or stored on its own.
    """
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
    except ValueError as exc:  # a malformed bracket or escape is a shape refusal, not a crash
        raise ValueError(_UNSUPPORTED_STORE) from exc
    if parts.scheme not in _POSTGRES_SCHEMES:
        raise ValueError(_UNSUPPORTED_STORE)
    return host, parts.path.lstrip("/")


#: Any constant would do, as long as every writer of this database uses the same one. The ASCII of "adr_stor"
#: keeps it recognisable in ``pg_locks``, and it fits a signed 64-bit integer. Advisory locks are scoped to the
#: database, so two databases on one server do not exclude each other by accident.
_POSTGRES_LOCK_KEY = 0x6164725F73746F72

_POSTGRES_CREATE = """
CREATE TABLE IF NOT EXISTS state (
    id integer PRIMARY KEY CHECK (id = 1),
    document text NOT NULL
)
"""

_POSTGRES_SELECT = "SELECT document FROM state WHERE id = 1"

_POSTGRES_UPSERT = """
INSERT INTO state (id, document) VALUES (1, %s)
ON CONFLICT (id) DO UPDATE SET document = excluded.document
"""

_POSTGRES_LOCK = "SELECT pg_advisory_lock(%s)"

_POSTGRES_TRY_LOCK = "SELECT pg_try_advisory_lock(%s)"

_POSTGRES_UNLOCK = "SELECT pg_advisory_unlock(%s)"


class PostgreSqlStore:
    """The same document row in PostgreSQL, excluded by a session advisory lock.

    The column is ``text`` rather than ``jsonb``: all three stores then hold the exact text
    ``serialize_json`` produced, so a document can be copied between them without a rewrite, and jsonb's own
    normalisation -- it preserves neither whitespace, nor object-key order, nor duplicate keys -- cannot make a
    stored document differ from the one the pass wrote. Nothing here queries inside the document, so jsonb's
    operators buy nothing.

    The lock is advisory for the same reason SQLite's is a sidecar: a pass saves inside the lock, and a table
    or row lock held for the pass would block those saves. An advisory lock touches no data, so it excludes
    other passes while leaving this session free to write.

    Every operation opens and closes its own connection. A pass saves a handful of times, and one shared
    session would be neither thread-safe for the web UI nor safe to leave idle in a transaction; closing a
    session also releases every advisory lock it holds, which is the backstop if an unlock cannot be sent.
    """

    def __init__(self, url: str, *, schema: str = DEFAULT_SCHEMA, owner: str = DEFAULT_OWNER) -> None:
        self._url = url
        self._host, self._database = _postgres_target(url)
        self._schema = schema
        self._owner = owner
        self._ready = False

    def __repr__(self) -> str:
        # Host and database identify the store; the URL's password must never appear in a traceback or a log.
        return f"PostgreSqlStore(host={self._host!r}, database={self._database!r})"

    def load(self) -> dict | None:
        connection = self._connect()
        try:
            self._prepare(connection)
            row = self._run(connection, _POSTGRES_SELECT, fetch=True)
        finally:
            connection.close()
        if row is None:
            return None
        return _read_document(row[0], schema=self._schema, owner=self._owner, location=self._target)

    def save(self, document: dict) -> None:
        """One upsert, committed on its own: the row is replaced whole or not at all."""
        payload = serialize_json(document)
        connection = self._connect()
        try:
            self._prepare(connection)
            self._run(connection, _POSTGRES_UPSERT, (payload,))
        finally:
            connection.close()

    @contextlib.contextmanager
    def lock(self, *, blocking: bool = True) -> Iterator[None]:
        """Hold the session advisory lock for the pass; ``blocking=False`` answers immediately."""
        connection = self._connect()
        try:
            row = self._run(
                connection,
                _POSTGRES_TRY_LOCK if not blocking else _POSTGRES_LOCK,
                (_POSTGRES_LOCK_KEY,),
                fetch=not blocking,
            )
            if not blocking and not (row and row[0]):
                raise LockBusy(self._target)
            try:
                yield
            finally:
                self._unlock(connection)
        finally:
            connection.close()

    @property
    def _target(self) -> str:
        """What may be shown about this store, for the same reason ``__repr__`` shows only this."""
        return f"{self._host}/{self._database}" if self._host else self._database

    def _connect(self):
        psycopg = self._driver()
        try:
            connection = psycopg.connect(self._url)
        except Exception as exc:
            raise StoreUnavailable(self._unavailable(exc)) from None
        # Autocommit: every statement is its own transaction, which is all a one-row document needs, and a
        # pass cannot leave an idle transaction holding a snapshot between saves.
        connection.autocommit = True
        return connection

    @staticmethod
    def _driver():
        """The driver, imported only when a store actually runs: PostgreSQL is an option, not a dependency."""
        try:
            import psycopg
        except ImportError:
            raise StoreUnavailable(
                "the PostgreSQL state store needs the optional psycopg driver; install it with "
                "python -m pip install 'psycopg[binary]'"
            ) from None
        return psycopg

    def _prepare(self, connection) -> None:
        if not self._ready:
            self._run(connection, _POSTGRES_CREATE)
            self._ready = True

    def _run(self, connection, sql: str, params: tuple[object, ...] = (), *, fetch: bool = False) -> tuple | None:
        """Run one statement, translating a driver fault before it can carry the credential into a traceback.

        The original exception is suppressed with ``from None``: its text is scrubbed here, but the exception
        object itself would still be printed above this one by a default traceback. ``fetch`` is explicit
        because most of these statements have no result to read.
        """
        try:
            with connection.cursor() as cursor:
                if params:
                    cursor.execute(sql, params)
                else:
                    cursor.execute(sql)
                return cursor.fetchone() if fetch else None
        except Exception as exc:
            raise StoreUnavailable(self._unavailable(exc)) from None

    def _unlock(self, connection) -> None:
        try:
            self._run(connection, _POSTGRES_UNLOCK, (_POSTGRES_LOCK_KEY,))
        except StoreUnavailable:
            # A session that cannot be told to unlock is dropped instead: PostgreSQL releases every advisory
            # lock a session holds when the session ends, so the lock cannot outlive a broken connection.
            # Swallowing this keeps a failure in the body from being replaced by a failure in the release.
            connection.close()

    def _unavailable(self, exc: BaseException) -> str:
        reason = self._scrub(f"{type(exc).__name__}: {exc}")
        return f"the state store at {self._target} is unavailable: {reason}"

    def _scrub(self, text: str) -> str:
        """Remove the credential from text that is about to become a message.

        psycopg can quote the offending connection string in a connection error, which is the leak this class
        exists to prevent. The URL and the ``password@`` fragment inside it are what a driver reproduces; a
        bare password is not, and replacing one would mangle unrelated words when it is short.
        """
        password = urllib.parse.urlsplit(self._url).password
        text = text.replace(self._url, "[redacted]")
        return text.replace(f"{password}@", "[redacted]@") if password else text


def store_for(value: str | None, state_path: Path) -> Store:
    """The store a configured value names, refusing an unknown shape without quoting the value back.

    A value is a store locator and the PostgreSQL form carries a password, so a refusal names the forms that
    are accepted and never the text it rejected: a mistyped URL must not leak through an error message.
    """
    if not value:
        return JsonStore(state_path)
    if value.startswith(_SQLITE_PREFIX):
        path = Path(value[len(_SQLITE_PREFIX) :])
        if str(path) == ".":
            raise ValueError(_UNSUPPORTED_STORE)
        return SqliteStore(path)
    if value.startswith(("postgresql://", "postgres://")):
        return PostgreSqlStore(value)
    raise ValueError(_UNSUPPORTED_STORE)
