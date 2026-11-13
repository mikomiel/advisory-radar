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
import contextvars
import json
import os
import sqlite3
import time
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

#: Refused before the driver runs: libpq decodes the userinfo and quotes the offending token -- which is the
#: password -- in its own message. Like ``_UNSUPPORTED_STORE`` this is static, so the refusal cannot leak it.
_MALFORMED_USERINFO = (
    "unsupported state store: the PostgreSQL userinfo has a malformed percent escape; percent-encode it "
    "(for example %40 for @)"
)

#: Refused before a host, database or password is derived: an authority Python cannot read back whole may be
#: read differently by libpq, and the part it hides could be the credential. Static like the other refusals,
#: so it never carries the target.
_AMBIGUOUS_TARGET = (
    "unsupported state store: the PostgreSQL URL cannot be parsed unambiguously; a password belongs in the "
    "userinfo, with a literal / or @ percent-encoded (for example %2F or %40)"
)

#: A SQLite document must not be written at the path of a file that lives beside ``state_path``: the KEV cache
#: and the settings overlay are replaced atomically by their own writers, so the first pass would destroy one.
#: The refusal names the file's role, never the path, so a log line and the message cannot disagree about it.
_RESERVED_NEIGHBOUR_REFUSAL = (
    "unsupported state store: the SQLite file is the {role} beside state_path, which this program replaces; "
    "choose another path for the state document"
)


def _refuse_reserved_neighbour(path: Path, state_path: Path) -> None:
    """Refuse a SQLite document at a file another owner keeps beside ``state_path``.

    That is the KEV cache, the settings overlay and the default watchlist: each is written by its own owner, so a
    document there destroys one of them -- and a watchlist that is really a SQLite database would be read as an
    unreadable scope, failing every pass. The comparison is on resolved absolute paths, because
    ``sqlite:///data/kev.json`` is relative to the working directory while ``sqlite:////data/kev.json`` is absolute
    and both can name the same file. The neighbour names come from the owners that write those files, so a rename
    cannot leave this check behind; they are imported here because two of them reach ``storage`` through ``config``.
    """
    from . import pipeline, settings, watchlist  # lazy: two of them import storage (through config)

    resolved = path.resolve()
    for role, neighbour in (
        ("KEV cache", state_path.with_name(pipeline.KEV_CACHE_NAME)),
        ("settings overlay", settings.settings_path(state_path)),
        ("default watchlist", state_path.with_name(watchlist.WATCHLIST_NAME)),
    ):
        if resolved == neighbour.resolve():
            raise ValueError(_RESERVED_NEIGHBOUR_REFUSAL.format(role=role))


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

    def __repr__(self) -> str:
        # A path identifies the store and carries no credential; a message can quote it.
        return f"JsonStore({str(self._path)!r})"

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


def _sqlite_unavailable(path: Path, exc: BaseException) -> StoreUnavailable:
    """A SQLite fault that is not contention: this store cannot be used.

    A full disk and a read-only database reach the caller the same way a missing driver does, because the
    pipeline and the CLI already answer ``StoreUnavailable`` with a reported failure instead of a traceback.
    """
    return StoreUnavailable(f"the state store at {path} is unavailable: {exc}")


def _sqlite_contention(exc: sqlite3.OperationalError) -> bool:
    """Whether this fault is another writer holding the database, rather than the store being unusable.

    SQLite reports both through ``OperationalError``, so only the result code settles which it is:
    ``SQLITE_BUSY`` and ``SQLITE_LOCKED`` mean the lock is held elsewhere, and everything else -- a read-only
    database, a full disk, a path that is not a database -- is a store fault. An extended code keeps the
    primary one in its low byte.
    """
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int):
        return code & 0xFF in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
    text = str(exc).lower()
    return "locked" in text or "busy" in text


#: How long a blocking acquisition waits between attempts. One attempt already waits ``SqliteStore``'s
#: ``timeout`` inside SQLite's own busy handler; this pause only keeps a waiting process from spinning.
_LOCK_RETRY_SECONDS = 0.05


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
        #: Resolved, so the document and a symlink to it share one lock: the sidecar is derived from the name,
        #: and two spellings of one file would otherwise lock different files and let two passes proceed at
        #: once. ``strict=False`` still resolves the parent of a document that does not exist yet.
        self._path = path.resolve(strict=False)
        #: The same suffix ``state.state_lock`` gives the JSON file, so a store and a pass over the same path
        #: still exclude each other.
        self._lock_path = self._path.with_name(self._path.name + ".lock")
        self._schema = schema
        self._owner = owner
        #: How long one connection waits inside SQLite before an attempt fails: the busy handler's timeout for
        #: a lock attempt, and the wait for a statement on the document database. A blocking lock retries after
        #: an attempt fails this way rather than treating it as the deadline for acquiring the lock.
        self._timeout = timeout
        self._ready = False

    def __repr__(self) -> str:
        return f"SqliteStore({str(self._path)!r})"

    def load(self) -> dict | None:
        connection = None
        try:
            if not self._path.exists():
                # A read creates nothing: the JSON store answers a missing file the same way, and a dry run
                # over a store that was never written must not leave an empty database behind. The lookup is
                # inside the translated block because it is a filesystem read too: an inaccessible ancestor
                # raises, and that is the store being unavailable rather than a raw traceback out of /readyz.
                return None
            connection = self._connect()
            self._prepare(connection)
            row = connection.execute(_SQLITE_SELECT).fetchone()
        except sqlite3.DatabaseError as exc:
            # The file store's rule, kept: unreadable is not absent, because re-seeding would replay history.
            raise SourceError(f"{self._owner} {self._path} cannot be read: {exc}") from exc
        except OSError as exc:
            # A directory that cannot be created or a database this process may open but not chmod is the
            # store being unavailable, not an escaping filesystem error: the probes and the CLI answer this.
            raise _sqlite_unavailable(self._path, exc) from exc
        finally:
            if connection is not None:
                connection.close()
        if row is None:
            return None
        return _read_document(row[0], schema=self._schema, owner=self._owner, location=str(self._path))

    def save(self, document: dict) -> None:
        """One statement, so the write is the row's own transaction and can never join the lock's.

        A fault here is the store being unusable -- a full disk, a read-only database -- not a pass-level
        error, so it is translated into the refusal the pipeline and the CLI already report.
        """
        payload = serialize_json(document)
        try:
            connection = self._connect()
            try:
                self._prepare(connection)
                connection.execute(_SQLITE_UPSERT, (payload,))
            finally:
                connection.close()
        except (sqlite3.DatabaseError, OSError) as exc:
            raise _sqlite_unavailable(self._path, exc) from exc

    @contextlib.contextmanager
    def lock(self, *, blocking: bool = True) -> Iterator[None]:
        """Hold the sidecar database for the pass, as ``state.state_lock`` holds the ``flock`` file.

        ``blocking=True`` waits until it acquires, exactly as the JSON store's ``flock`` does: the bulk queue
        callers depend on that, so a held sidecar is retried rather than turned into ``LockBusy`` once one
        attempt's timeout expires. ``blocking=False`` asks once and answers ``LockBusy`` immediately.
        """
        try:
            self._lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            connection = sqlite3.connect(
                self._lock_path,
                timeout=self._timeout if blocking else 0,
                isolation_level=None,
            )
        except (sqlite3.DatabaseError, OSError) as exc:
            # A sidecar that cannot even be opened cannot exclude anyone, so it is a store fault, not contention.
            raise _sqlite_unavailable(self._path, exc) from exc
        try:
            os.chmod(self._lock_path, 0o600)
            self._acquire(connection, blocking=blocking)
            try:
                yield
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")
        except (sqlite3.DatabaseError, OSError) as exc:
            raise _sqlite_unavailable(self._path, exc) from exc
        finally:
            # Closing is the backstop: SQLite rolls back on close, so a failing COMMIT cannot leave the lock
            # held by this process.
            connection.close()

    def _acquire(self, connection: sqlite3.Connection, *, blocking: bool) -> None:
        """Take the sidecar's write lock, waiting for it when ``blocking`` asks for that.

        One ``BEGIN IMMEDIATE`` attempt waits up to ``self._timeout`` in SQLite's busy handler, so a blocking
        acquisition sleeps briefly and tries again: treating that timeout as the deadline would make SQLite's
        lock behave unlike the JSON store's, which waits however long the holder takes. Only contention is
        retried -- a read-only or non-database sidecar raises at once and becomes ``StoreUnavailable``.
        """
        while True:
            try:
                connection.execute("BEGIN IMMEDIATE")
                return
            except sqlite3.OperationalError as exc:
                if not _sqlite_contention(exc):
                    raise
                if not blocking:
                    raise LockBusy(str(self._lock_path)) from exc
                time.sleep(_LOCK_RETRY_SECONDS)

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        connection = sqlite3.connect(self._path, timeout=self._timeout, isolation_level=None)
        try:
            # SQLite applies the process umask, which would leave the document world-readable;
            # ``state.save_json`` earns the same protection with an explicit chmod on the temporary file.
            os.chmod(self._path, 0o600)
            # Per connection, not per database: only journal_mode is stored in the file header.
            connection.execute("PRAGMA synchronous = FULL")
        except BaseException:
            # A handle opened before its setup failed must not outlive the refusal: the caller translates the
            # fault into a store that cannot be used, and a leaked handle would keep the database open.
            connection.close()
            raise
        return connection

    def _prepare(self, connection: sqlite3.Connection) -> None:
        if self._ready:
            return
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(_SQLITE_CREATE)
        self._ready = True


#: The digits of a percent escape. A ``%`` with anything else after it is a malformed token libpq refuses.
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _userinfo(url: str) -> str:
    """The ``user:password`` section of a URL, or "" when it carries none.

    The authority ends at the first ``/``, ``?`` or ``#`` (a URL may carry its query straight after the
    host), and the userinfo is what precedes the last ``@`` inside it. One splitter serves the credential
    check and the scrubber, so the two cannot disagree about where a password stops being a password.
    """
    _, separator, rest = url.partition("://")
    if not separator:
        return ""
    ends = [rest.find(marker) for marker in ("/", "?", "#") if rest.find(marker) >= 0]
    authority = rest[: min(ends)] if ends else rest
    return authority.rsplit("@", 1)[0] if "@" in authority else ""


def _malformed_percent_escape(userinfo: str) -> bool:
    """Whether the userinfo holds a ``%`` that does not begin a two-digit percent escape.

    libpq decodes the userinfo before connecting and refuses the whole URL with ``invalid percent-encoded
    token: "bad%password"`` -- quoting the password. Refusing the shape here keeps the driver, and its
    message, out of it entirely.
    """
    index = userinfo.find("%")
    while index >= 0:
        escape = userinfo[index + 1 : index + 3]
        if len(escape) != 2 or any(digit not in _HEX_DIGITS for digit in escape):
            return True
        index = userinfo.find("%", index + 3)
    return False


#: One static refusal covers every libpq option, credential or not: libpq keeps adding keywords (PostgreSQL 18's
#: ``oauth_client_secret`` was the last one), so a list of credential names would always trail it. A query
#: string is refused whole, which makes the credential inventory complete by construction -- no option can slip
#: through, whether or not this program has heard of it -- and the message names no option and no value.
_QUERY_REFUSAL = (
    "unsupported state store: a PostgreSQL connection target may not carry a query string; this program does "
    "not parse libpq options -- set them in the environment (PGSSLMODE, PGSERVICEFILE, ...) or in the "
    "server's own configuration"
)

#: A raw ``#`` is read two ways: ``urlsplit`` starts a fragment there, while libpq keeps it in the userinfo or
#: the database name and still parses what follows -- so the credential checks built on Python's view can miss
#: a password libpq then quotes. Refusing the shape removes that whole disagreement instead of mirroring libpq.
_FRAGMENT_REFUSAL = (
    "unsupported state store: the PostgreSQL URL contains a raw #; a fragment is not part of a connection "
    "target this program parses. Percent-encode a literal # (for example %23) in the userinfo or the database"
)


def _password_tokens(password: str) -> set[str]:
    """Every spelling of a password a driver message can repeat: as written, decoded, and fully encoded.

    A message can name the raw text from the URL or a decoded form of it, and neither has to be followed by
    an ``@``: libpq's own parse refusal quotes the token alone.
    """
    tokens = {password, urllib.parse.unquote(password)}
    tokens |= {urllib.parse.quote(token, safe="") for token in tokens}
    tokens.discard("")
    return tokens


def _refuse_ambiguous_target(parts: urllib.parse.SplitResult) -> None:
    """Refuse an authority or path this program cannot read the way libpq might.

    A raw ``/`` in the password moves it into the path for ``urlsplit`` -- ``radar:/secret@host/db`` is host
    ``radar`` with the secret in the path -- while libpq keeps it in the userinfo, so a host, database or
    password derived here would be wrong and could print the credential. Every such shape fails closed before
    any of those fields is computed: an ``@`` in the path, a trailing ``:``, a second ``@``, or a netloc that
    does not round-trip through the parsed pieces.
    """
    netloc = parts.netloc
    if "@" in parts.path or netloc.endswith(":") or netloc.count("@") > 1:
        raise ValueError(_AMBIGUOUS_TARGET)
    try:
        hostname, port = parts.hostname or "", parts.port
    except ValueError as exc:  # a malformed port or bracket: its text may itself be the credential
        raise ValueError(_AMBIGUOUS_TARGET) from exc
    # The host is case-insensitive and an IPv6 host is bracketed in the netloc, so the round trip undoes exactly
    # those two normalisations. Anything else differing is a shape Python did not read whole.
    userinfo, _, hostport = netloc.rpartition("@")
    rebuilt_userinfo = ""
    if "@" in netloc:
        username = parts.username or ""
        rebuilt_userinfo = username if parts.password is None else f"{username}:{parts.password}"
        if rebuilt_userinfo != userinfo:
            raise ValueError(_AMBIGUOUS_TARGET)
    rebuilt = f"{rebuilt_userinfo}@" if "@" in netloc else ""
    rebuilt += f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        rebuilt += f":{port}"
    if rebuilt.lower() != netloc.lower():
        raise ValueError(_AMBIGUOUS_TARGET)


def _postgres_target(url: str) -> tuple[str, str]:
    """The host and database a PostgreSQL URL names, refusing any other shape without echoing the value.

    Parsing here is a credential control as much as a validation: a refusal that quoted the URL would put its
    password into a log line. The password is never returned from this function or stored on its own.

    A password belongs in the userinfo or the environment. libpq also accepts connection options -- credentials
    among them -- as query parameters, and it keeps adding keywords (``oauth_client_secret`` arrived in
    PostgreSQL 18); this program does not parse that option set. A query string is therefore refused whole, so
    no option can slip past a list that would always trail libpq. A raw ``#`` is refused too, because Python's
    parser and libpq disagree about it. What remains -- a fragment-free, query-free URL whose only credential
    position is the userinfo -- is exactly what the scrubber covers.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:  # a malformed bracket or escape is a shape refusal, not a crash
        raise ValueError(_UNSUPPORTED_STORE) from exc
    if parts.scheme not in _POSTGRES_SCHEMES:
        raise ValueError(_UNSUPPORTED_STORE)
    if "#" in url:
        raise ValueError(_FRAGMENT_REFUSAL)
    _refuse_ambiguous_target(parts)
    host = parts.hostname or ""
    if _malformed_percent_escape(_userinfo(url)):
        raise ValueError(_MALFORMED_USERINFO)
    if parts.query:
        raise ValueError(_QUERY_REFUSAL)
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

    Outside a lock every operation opens and closes its own connection: a pass saves a handful of times, and
    one shared session would be neither thread-safe for the web UI nor safe to leave idle in a transaction.
    Inside ``lock()`` the operations travel on the session that holds the advisory lock itself -- see
    ``_lock_connection`` for why a save must not open its own.
    """

    def __init__(self, url: str, *, schema: str = DEFAULT_SCHEMA, owner: str = DEFAULT_OWNER) -> None:
        self._url = url
        self._host, self._database = _postgres_target(url)
        userinfo = _userinfo(url)
        #: The password as the URL spells it, for ``_scrub``; never rendered on its own.
        self._password = userinfo.split(":", 1)[1] if ":" in userinfo else ""
        self._schema = schema
        self._owner = owner
        self._ready = False
        #: The connection the current ``lock()`` context entered on, or None outside one. A pass's saves must
        #: travel on the session that holds the advisory lock: were they sent on independent connections, a
        #: terminated locking session would free the lock while this body still ran, and the class would then
        #: write a stale document over the new holder's and re-deliver. It is per context rather than per
        #: instance, so a web request cannot borrow another thread's lock.
        self._lock_connection: contextvars.ContextVar = contextvars.ContextVar(
            f"advisory-radar-postgres-lock-{id(self)}", default=None
        )

    def __repr__(self) -> str:
        # Host and database identify the store; the URL's password must never appear in a traceback or a log.
        return f"PostgreSqlStore(host={self._host!r}, database={self._database!r})"

    def load(self) -> dict | None:
        with self._connection() as connection:
            self._prepare(connection)
            row = self._run(connection, _POSTGRES_SELECT, fetch=True)
        if row is None:
            return None
        return _read_document(row[0], schema=self._schema, owner=self._owner, location=self._target)

    def save(self, document: dict) -> None:
        """One upsert, committed on its own: the row is replaced whole or not at all."""
        payload = serialize_json(document)
        with self._connection() as connection:
            self._prepare(connection)
            self._run(connection, _POSTGRES_UPSERT, (payload,))

    @contextlib.contextmanager
    def lock(self, *, blocking: bool = True) -> Iterator[None]:
        """Hold the session advisory lock for the pass; ``blocking=False`` answers immediately."""
        connection = self._connect()
        token = self._lock_connection.set(connection)
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
            self._lock_connection.reset(token)
            connection.close()

    @contextlib.contextmanager
    def _connection(self) -> Iterator[object]:
        """The locking connection inside ``lock()``, or one belonging to this operation alone.

        The lock is a *session* lock, so the writes it protects have to travel on that session. If the session
        dies mid-pass, its next statement fails and ``StoreUnavailable`` reaches the caller; opening a fresh
        connection instead would let the pass write a document the new lock holder knows nothing about.
        """
        leased = self._lock_connection.get()
        if leased is not None:
            yield leased
            return
        connection = self._connect()
        try:
            yield connection
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
                "uv sync --extra postgres (the container image already includes it)"
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
        exists to prevent. The URL is replaced whole; separately every spelling of the userinfo's password is
        replaced wherever the driver repeats it, because a message can name the token alone, with no ``@`` next
        to it -- ``invalid percent-encoded token: "bad%password"`` is exactly that shape.
        """
        text = text.replace(self._url, "[redacted]")
        if not self._password:
            return text
        for token in _password_tokens(self._password):
            text = text.replace(token, "[redacted]")
        return text


def store_for(value: str | None, state_path: Path) -> Store:
    """The store a configured value names, refusing an unknown shape without quoting the value back.

    A value is a store locator and the PostgreSQL form carries a password, so a refusal names the forms that
    are accepted and never the text it rejected: a mistyped URL must not leak through an error message. A
    SQLite path that resolves to one of the auxiliary files beside ``state_path`` is refused too: those files
    are replaced by their own writers, so the state document there would destroy one.
    """
    if not value:
        return JsonStore(state_path)
    if value.startswith(_SQLITE_PREFIX):
        path = Path(value[len(_SQLITE_PREFIX) :])
        if str(path) == ".":
            raise ValueError(_UNSUPPORTED_STORE)
        _refuse_reserved_neighbour(path, state_path)
        return SqliteStore(path)
    if value.startswith(("postgresql://", "postgres://")):
        return PostgreSqlStore(value)
    raise ValueError(_UNSUPPORTED_STORE)
