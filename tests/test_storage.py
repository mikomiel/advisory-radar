"""The state stores: one document, three places for its bytes, one contract.

Every test here runs without a network and without a PostgreSQL server: where the PostgreSQL SQL matters the
driver is faked, and the credential rule is asserted against what a caller can actually see -- a message and a
``repr``. Each implementation is pinned on what it could plausibly get wrong: the document round-trips, a
foreign schema is refused, the bytes on disk are private, and the lock excludes every other writer.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import stat
import sys
import threading
import time
import tomllib
from pathlib import Path

import pytest

from advisory_radar import core, pipeline, storage
from advisory_radar.config import ConfigError, load_config
from advisory_radar.state import LockBusy, SourceError, describe_schema, expect_schema, serialize_json

ROOT = Path(__file__).parent.parent

DOCUMENT = {
    "schema": storage.DEFAULT_SCHEMA,
    "pending": [{"tag": "warning", "title": "An advisory", "ids": ["CVE-2026-0001"]}],
    "cache": {"CVE-2026-0001": {"at": 1792600000, "cvss": 9.8, "ssvc": None, "remote_unauth": True}},
    "carried": {"debian": [{"guid": "src:debian:1", "retry": None}]},
}


def test_the_store_constants_are_the_document_constants():
    # The constants are repeated in storage.py so that reading the configuration cannot close the import cycle
    # core -> config -> storage; this test is what keeps the repetition honest.
    assert storage.DEFAULT_SCHEMA == core.STATE_SCHEMA
    assert storage.DEFAULT_OWNER == "advisory state"


# --------------------------------------------------------------------------
# JsonStore


def test_the_json_store_round_trips_the_document(tmp_path):
    store = storage.JsonStore(tmp_path / "state.json")
    assert store.load() is None
    store.save(DOCUMENT)
    assert store.load() == DOCUMENT


def test_a_deeply_nested_schema_value_is_named_not_represented():
    """#81 review: ``repr`` on a decoded container can recurse, so a non-string schema is named by its type."""
    deep: object = []
    for _ in range(10_000):
        deep = [deep]
    with pytest.raises(SourceError, match="reports a list schema"):
        expect_schema({"schema": deep}, storage.DEFAULT_SCHEMA, "advisory state")
    assert describe_schema("other.v9") == "schema 'other.v9'", "a string schema keeps its exact repr"


def test_the_json_store_refuses_a_foreign_schema(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"schema": "other.v9"}), encoding="utf-8")
    with pytest.raises(SourceError, match="advisory state .*state.json reports schema 'other.v9'"):
        storage.JsonStore(path).load()


def test_the_json_store_writes_the_document_0600(tmp_path):
    path = tmp_path / "state.json"
    storage.JsonStore(path).save(DOCUMENT)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_the_json_store_lock_is_the_state_lock(tmp_path):
    path = tmp_path / "state.json"
    with storage.JsonStore(path).lock():
        assert path.with_name("state.json.lock").exists()
        with pytest.raises(LockBusy), storage.JsonStore(path).lock(blocking=False):
            pass
    with storage.JsonStore(path).lock(blocking=False):
        pass


# --------------------------------------------------------------------------
# SqliteStore


def test_the_sqlite_store_round_trips_a_nested_document(tmp_path):
    path = tmp_path / "state.db"
    assert storage.SqliteStore(path).load() is None
    storage.SqliteStore(path).save(DOCUMENT)
    assert storage.SqliteStore(path).load() == DOCUMENT
    # The row is the text serialize_json produced, not a re-encoded copy, and the file is in WAL mode so that a
    # reader never waits for a writing pass.
    raw = sqlite3.connect(path)
    try:
        assert raw.execute("SELECT document FROM state WHERE id = 1").fetchone()[0] == serialize_json(DOCUMENT)
        assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    finally:
        raw.close()


def test_the_sqlite_store_refuses_a_foreign_schema(tmp_path):
    path = tmp_path / "state.db"
    storage.SqliteStore(path).save({"schema": "other.v9"})
    with pytest.raises(SourceError, match="advisory state .*state.db reports schema 'other.v9'"):
        storage.SqliteStore(path).load()


def test_the_sqlite_store_creates_a_private_directory_and_database(tmp_path):
    directory = tmp_path / "data"
    path = directory / "state.db"
    storage.SqliteStore(path).save(DOCUMENT)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_the_sqlite_lock_excludes_a_second_store(tmp_path):
    path = tmp_path / "state.db"
    first, second = storage.SqliteStore(path), storage.SqliteStore(path)
    with first.lock():
        assert path.with_name("state.db.lock").exists()
        with pytest.raises(LockBusy), second.lock(blocking=False):
            pass
    with second.lock(blocking=False):
        pass


def test_a_save_inside_the_sqlite_lock_succeeds_and_is_durable(tmp_path):
    # The pipeline saves inside the lock after every source and every delivery, so a lock that fought the
    # document database would make this store unusable. The sidecar exists for exactly this.
    path = tmp_path / "state.db"
    store = storage.SqliteStore(path)
    with store.lock():
        store.save(DOCUMENT)
        assert storage.SqliteStore(path).load() == DOCUMENT
    assert storage.SqliteStore(path).load() == DOCUMENT


def test_the_sqlite_lock_is_released_when_the_body_raises(tmp_path):
    store = storage.SqliteStore(tmp_path / "state.db")
    with pytest.raises(RuntimeError, match="boom"), store.lock():
        raise RuntimeError("boom")
    with store.lock(blocking=False):
        pass


def test_a_blocking_lock_waits_while_a_non_blocking_one_answers(tmp_path, monkeypatch):
    """``blocking=True`` waits however long the holder takes, as the JSON store's flock does.

    The store's ``timeout`` is one attempt's wait inside SQLite, not the deadline for acquiring the lock: the
    old code turned the first busy attempt into ``LockBusy``, so a pass that should have queued up behind a
    slow one failed instead. ``blocking=False`` still answers at once, and contention writes nothing.
    """
    path = tmp_path / "state.db"
    storage.SqliteStore(path).save(DOCUMENT)
    first, second = storage.SqliteStore(path, timeout=0.05), storage.SqliteStore(path, timeout=0.05)
    holding, release, contended = threading.Event(), threading.Event(), threading.Event()
    real_contention = storage._sqlite_contention

    def signalling(exc):
        contention = real_contention(exc)
        if contention:
            contended.set()
        return contention

    monkeypatch.setattr(storage, "_sqlite_contention", signalling)

    def holder() -> None:
        with first.lock():
            holding.set()
            assert release.wait(timeout=10)

    thread = threading.Thread(target=holder)
    thread.start()
    assert holding.wait(timeout=10), "the first lock was never taken"

    started = time.monotonic()
    with pytest.raises(LockBusy), second.lock(blocking=False):
        pass
    assert time.monotonic() - started < 1.0, "a non-blocking lock must not wait out the busy timeout"

    contended.clear()  # the non-blocking probe above is expected to see contention; the blocking one must too
    outcome: dict[str, object] = {}

    def blocking() -> None:
        try:
            with second.lock():
                outcome["elapsed"] = time.monotonic() - started
        except BaseException as exc:  # recorded so the assertion reports the refusal instead of a thread warning
            outcome["error"] = exc

    blocked = threading.Thread(target=blocking)
    started = time.monotonic()
    blocked.start()
    try:
        # Wait until the blocking attempt has met the held lock, so the release cannot race the acquisition.
        assert contended.wait(timeout=10), "the blocking attempt never met the held lock"
        release.set()
    finally:
        release.set()
        blocked.join(timeout=10)
        thread.join(timeout=10)
    assert not blocked.is_alive() and not thread.is_alive()
    assert "error" not in outcome, outcome.get("error")
    assert "elapsed" in outcome, "the blocking acquisition never entered the lock"
    assert outcome["elapsed"] >= 0.05, "the blocking lock waited for the holder"
    assert storage.SqliteStore(path).load() == DOCUMENT, "contention must not change the document"


def test_a_symlink_to_the_database_shares_its_lock(tmp_path):
    """One document, one lock: a sidecar named after the spelling would let two passes over one file proceed."""
    real = tmp_path / "state.db"
    storage.SqliteStore(real).save(DOCUMENT)
    alias = tmp_path / "alias.db"
    alias.symlink_to(real)
    assert storage.SqliteStore(alias).load() == DOCUMENT
    assert repr(storage.SqliteStore(alias)) == repr(storage.SqliteStore(real)), "both spellings name one store"

    with (
        storage.SqliteStore(real).lock(),
        pytest.raises(LockBusy),
        storage.SqliteStore(alias).lock(blocking=False),
    ):
        pass


def test_a_read_only_sqlite_store_is_unavailable_and_keeps_the_committed_document(tmp_path, read_only_sqlite):
    path = tmp_path / "state.db"
    storage.SqliteStore(path).save(DOCUMENT)
    read_only_sqlite(path)
    with pytest.raises(storage.StoreUnavailable) as caught:
        storage.SqliteStore(path).save({**DOCUMENT, "pending": [{"title": "x"}]})
    assert "unavailable" in str(caught.value)
    assert storage.SqliteStore(path).load() == DOCUMENT, "a refused write must not replace the committed document"


def test_a_directory_the_store_cannot_write_is_unavailable(tmp_path):
    # A parent that is a regular file raises OSError from mkdir; it must reach the caller as the store refusal,
    # not as a traceback out of a pass.
    blocker = tmp_path / "data"
    blocker.write_text("not a directory")
    with pytest.raises(storage.StoreUnavailable):
        storage.SqliteStore(blocker / "state.db").save(DOCUMENT)


def test_a_lock_fault_that_is_not_contention_is_a_store_error(tmp_path):
    # A sidecar that is not a database fails BEGIN IMMEDIATE with SQLITE_NOTADB, not SQLITE_BUSY. The caller
    # answers LockBusy with "try again shortly", so only a genuine busy/locked result may be labelled so.
    store = storage.SqliteStore(tmp_path / "state.db")
    (tmp_path / "state.db.lock").write_bytes(b"not a database")
    with pytest.raises(storage.StoreUnavailable), store.lock(blocking=False):
        pass


def test_a_filesystem_failure_reading_the_store_is_a_store_error(tmp_path, monkeypatch):
    """A database it can open but not chmod is a store that cannot be used -- and the refusal must close it.

    ``load`` only translated SQLite errors, so the ``PermissionError`` from the setup that runs after the handle
    is opened escaped: a probe became a 500 and a migration a traceback. The half-set-up handle leaked too.
    """
    path = tmp_path / "state.db"
    storage.SqliteStore(path).save(DOCUMENT)
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    def tracking_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    def denied(path, mode):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(storage.sqlite3, "connect", tracking_connect)
    monkeypatch.setattr(storage.os, "chmod", denied)
    with pytest.raises(storage.StoreUnavailable) as caught:
        storage.SqliteStore(path).load()
    assert not isinstance(caught.value, OSError)
    assert opened, "the database was opened before the failure"
    with pytest.raises(sqlite3.ProgrammingError):
        opened[-1].execute("SELECT 1")  # a closed handle: the refusal must not leak the connection


def test_a_failed_path_lookup_reading_the_store_is_a_store_error(tmp_path, monkeypatch):
    """The existence check is a filesystem read too: a lookup that raises is the store being unavailable.

    ``load`` used to ask ``Path.exists()`` before its protected block, so an inaccessible ancestor raised
    ``PermissionError`` straight into ``/readyz``, ``/metrics`` and ``migrate``.
    """

    def denied(self):
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(type(tmp_path), "exists", denied)
    with pytest.raises(storage.StoreUnavailable) as caught:
        storage.SqliteStore(tmp_path / "state.db").load()
    assert not isinstance(caught.value, OSError)


def test_a_pass_over_a_read_only_sqlite_store_fails_instead_of_raising(tmp_path, read_only_sqlite, caplog):
    path = tmp_path / "state.db"
    document = core.new_state()
    document["pending"].append({"tag": "warning", "title": "T", "ids": ["CVE-2026-1"]})
    storage.SqliteStore(path).save(document)
    read_only_sqlite(path)
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        f"sources: []\nnotifiers: []\nstate_path: {tmp_path}/state.json\nstorage: sqlite:///{path}\n"
    )
    cfg = load_config(config_path, {})
    with caplog.at_level(logging.ERROR):
        code = pipeline.run_pass(cfg, [], [], http=lambda method, url, headers, body: (404, {}, b""))
    assert code == 1, "a store that cannot be written is a failed pass, not a traceback"
    assert "unavailable" in caplog.text
    assert storage.SqliteStore(path).load() == document, "the pass must leave the committed document in place"


# --------------------------------------------------------------------------
# store_for


def test_the_configured_value_selects_the_store(tmp_path):
    state_path = tmp_path / "state.json"
    assert isinstance(storage.store_for(None, state_path), storage.JsonStore)
    assert isinstance(storage.store_for("", state_path), storage.JsonStore)

    sqlite = storage.store_for(f"sqlite:///{tmp_path}/state.db", state_path)
    assert isinstance(sqlite, storage.SqliteStore)
    sqlite.save(DOCUMENT)
    assert (tmp_path / "state.db").is_file()

    assert isinstance(storage.store_for("postgresql://radar@db.example/radar", state_path), storage.PostgreSqlStore)
    assert isinstance(storage.store_for("postgres://radar@db.example/radar", state_path), storage.PostgreSqlStore)


def test_an_unknown_store_is_refused_without_echoing_it(tmp_path):
    with pytest.raises(ValueError) as caught:
        storage.store_for("mysql://db.example/radar", tmp_path / "state.json")
    message = str(caught.value)
    assert "sqlite:///" in message
    assert "postgresql://" in message
    assert "mysql" not in message
    with pytest.raises(ValueError):
        storage.store_for("sqlite:///", tmp_path / "state.json")


def test_a_sqlite_target_at_an_auxiliary_file_beside_state_path_is_refused(tmp_path, monkeypatch):
    """The KEV cache and the settings overlay are replaced by their own writers; a document there destroys one."""
    data = tmp_path / "data"
    data.mkdir()
    state_path = data / "state.json"
    kev, overlay, scope = data / "kev.json", data / "settings.json", data / "watchlist.json"
    kev.write_text('{"schema": "advisory-radar-kev.v1", "cves": ["CVE-2026-1"]}', encoding="utf-8")
    overlay.write_text('{"schema": "advisory-radar-settings.v1", "settings": {}}', encoding="utf-8")
    scope.write_text('{"schema": "security-watchlist.v1"}', encoding="utf-8")
    before = (kev.read_bytes(), overlay.read_bytes(), scope.read_bytes())

    for target, role in ((kev, "KEV cache"), (overlay, "settings overlay"), (scope, "default watchlist")):
        with pytest.raises(ValueError) as caught:
            storage.store_for(f"sqlite:///{target}", state_path)
        message = str(caught.value)
        assert role in message, "the refusal names the file's role"
        assert str(target) not in message, "the refusal never names the path"

    # Three slashes are relative to the working directory: this spelling is the same file as the absolute one.
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="KEV cache"):
        storage.store_for("sqlite:///data/kev.json", state_path)

    # A SQLite document beside those files is exactly what a store is for.
    assert isinstance(storage.store_for(f"sqlite:///{data}/state.db", state_path), storage.SqliteStore)
    assert (kev.read_bytes(), overlay.read_bytes(), scope.read_bytes()) == before, "a refused target writes nothing"


def test_a_configured_sqlite_store_at_an_auxiliary_file_is_refused(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    kev, overlay, scope = data / "kev.json", data / "settings.json", data / "watchlist.json"
    kev.write_text('{"schema": "advisory-radar-kev.v1", "cves": ["CVE-2026-1"]}', encoding="utf-8")
    overlay.write_text('{"schema": "advisory-radar-settings.v1", "settings": {}}', encoding="utf-8")
    scope.write_text('{"schema": "security-watchlist.v1"}', encoding="utf-8")
    before = (kev.read_bytes(), overlay.read_bytes(), scope.read_bytes())
    config_path = tmp_path / "config.yml"

    for target, role in ((kev, "KEV cache"), (overlay, "settings overlay"), (scope, "default watchlist")):
        config_path.write_text(
            f"sources: []\nnotifiers: []\nstate_path: {data}/state.json\nstorage: sqlite:///{target}\n"
        )
        with pytest.raises(ConfigError) as caught:
            load_config(config_path, {})
        assert role in str(caught.value)
        assert str(target) not in str(caught.value)
    assert (kev.read_bytes(), overlay.read_bytes(), scope.read_bytes()) == before, "a refused target writes nothing"


# --------------------------------------------------------------------------
# PostgreSqlStore


class _FakeCursor:
    """The slice of a psycopg cursor this store uses, recording every statement it is sent."""

    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection
        self._result: tuple | None = None

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def execute(self, sql: str, params: tuple | None = None) -> None:
        self._connection.statements.append((sql, params))
        self._result = self._connection.result_for(sql)

    def fetchone(self) -> tuple | None:
        return self._result


class _FakeConnection:
    """A connection whose only job is to answer the statements this store sends."""

    def __init__(self, *, row: tuple | None = None, try_lock: bool = True) -> None:
        self.row = row
        self.try_lock = try_lock
        self.statements: list[tuple[str, tuple | None]] = []
        self.closed = False

    def cursor(self) -> _FakeCursor:
        if self.closed:
            raise RuntimeError("the session was closed")
        return _FakeCursor(self)

    def result_for(self, sql: str) -> tuple | None:
        if "pg_try_advisory_lock" in sql:
            return (self.try_lock,)
        if sql.strip().startswith("SELECT document"):
            return self.row
        return None

    def close(self) -> None:
        self.closed = True


def _sent(connection: _FakeConnection, fragment: str) -> list[str]:
    """The statements a fake connection was sent whose text contains ``fragment``."""
    return [sql for sql, _ in connection.statements if fragment in sql]


def test_a_postgres_url_never_reaches_a_repr():
    store = storage.PostgreSqlStore("postgresql://radar:s3cr3t-pass@db.example/radar")
    assert repr(store) == "PostgreSqlStore(host='db.example', database='radar')"


def test_a_malformed_postgres_url_is_refused_without_echoing_it():
    with pytest.raises(ValueError) as caught:
        storage.PostgreSqlStore("postgresql://[radar:s3cr3t-pass@db.example/radar")
    assert "sqlite:///" in str(caught.value)
    assert "s3cr3t-pass" not in str(caught.value)


def test_a_missing_driver_is_a_store_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "psycopg", None)
    store = storage.PostgreSqlStore("postgresql://radar:s3cr3t-pass@db.example/radar")
    with pytest.raises(storage.StoreUnavailable) as caught:
        store.load()
    assert not isinstance(caught.value, ImportError)
    message = str(caught.value)
    assert "uv sync --extra postgres" in message  # the recovery the documented interpreter can run
    assert "python -m pip" not in message
    assert "s3cr3t-pass" not in message


def test_the_postgres_extra_is_declared_and_the_image_installs_it():
    """Packaging evidence only: the optional driver is declared and both image layers request it.

    This says nothing about a live PostgreSQL server, which no test here reaches.
    """
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    extra = project["project"]["optional-dependencies"]["postgres"]
    assert any(requirement.startswith("psycopg[binary]") for requirement in extra)

    installs = [line for line in (ROOT / "Dockerfile").read_text().splitlines() if line.startswith("RUN uv sync")]
    assert len(installs) == 2, "the dependency layer and the project layer both install"
    assert all("--extra postgres" in line for line in installs)


def test_a_connection_failure_does_not_carry_the_credential(monkeypatch):
    class _Driver:
        @staticmethod
        def connect(url: str):
            raise OSError(f"connection to {url} refused")

    monkeypatch.setitem(sys.modules, "psycopg", _Driver)
    store = storage.PostgreSqlStore("postgresql://radar:s3cr3t-pass@db.example/radar")
    with pytest.raises(storage.StoreUnavailable) as caught:
        store.load()
    message = str(caught.value)
    assert "s3cr3t-pass" not in message
    assert "OSError" in message  # the reason survives, so an operator can still see what happened
    assert "db.example/radar" in message


def test_the_postgres_store_reads_its_document_from_the_row(monkeypatch):
    store = storage.PostgreSqlStore("postgresql://radar@db.example/radar")
    empty = _FakeConnection()
    monkeypatch.setattr(store, "_connect", lambda: empty)
    assert store.load() is None
    assert len(_sent(empty, "CREATE TABLE IF NOT EXISTS state")) == 1  # created on first use
    assert empty.closed

    filled = _FakeConnection(row=(serialize_json(DOCUMENT),))
    monkeypatch.setattr(store, "_connect", lambda: filled)
    assert store.load() == DOCUMENT
    assert _sent(filled, "CREATE TABLE") == []  # and not again on every call


def test_the_postgres_store_writes_the_serialised_document(monkeypatch):
    store = storage.PostgreSqlStore("postgresql://radar@db.example/radar")
    fake = _FakeConnection()
    monkeypatch.setattr(store, "_connect", lambda: fake)
    store.save(DOCUMENT)
    upserts = [params for sql, params in fake.statements if "INSERT INTO state" in sql]
    assert upserts == [(serialize_json(DOCUMENT),)]
    assert fake.closed


def test_the_postgres_store_refuses_a_foreign_schema(monkeypatch):
    store = storage.PostgreSqlStore("postgresql://radar@db.example/radar")
    fake = _FakeConnection(row=('{"schema": "other.v9"}',))
    monkeypatch.setattr(store, "_connect", lambda: fake)
    with pytest.raises(SourceError, match="advisory state .*db.example/radar reports schema 'other.v9'"):
        store.load()


def test_the_postgres_lock_is_taken_and_released(monkeypatch):
    store = storage.PostgreSqlStore("postgresql://radar@db.example/radar")
    held = _FakeConnection()
    monkeypatch.setattr(store, "_connect", lambda: held)
    with store.lock():
        assert _sent(held, "SELECT pg_advisory_lock(%s)")
    assert _sent(held, "SELECT pg_advisory_unlock(%s)")
    assert held.closed

    # The same release happens when the body raises, or the next pass would find the lock held by itself.
    failing = _FakeConnection()
    monkeypatch.setattr(store, "_connect", lambda: failing)
    with pytest.raises(RuntimeError, match="boom"), store.lock():
        raise RuntimeError("boom")
    assert _sent(failing, "SELECT pg_advisory_unlock(%s)")


def test_the_postgres_lock_refuses_a_lock_held_elsewhere(monkeypatch):
    store = storage.PostgreSqlStore("postgresql://radar@db.example/radar")
    fake = _FakeConnection(try_lock=False)
    monkeypatch.setattr(store, "_connect", lambda: fake)
    with pytest.raises(LockBusy), store.lock(blocking=False):
        pass
    assert _sent(fake, "SELECT pg_try_advisory_lock(%s)")
    assert _sent(fake, "SELECT pg_advisory_unlock(%s)") == []
    assert fake.closed


def test_a_write_inside_the_lock_uses_the_locking_session(monkeypatch):
    """A terminated locking session must fail the write, not let it land through a replacement connection.

    The advisory lock belongs to one session. If a save opened its own connection, a lock lost with that
    session would be acquired by another instance while this body still wrote -- and re-delivered.
    """
    connections: list[_FakeConnection] = []

    class _Driver:
        @staticmethod
        def connect(url: str) -> _FakeConnection:
            connection = _FakeConnection()
            connections.append(connection)
            return connection

    monkeypatch.setitem(sys.modules, "psycopg", _Driver)
    store = storage.PostgreSqlStore("postgresql://radar:s3cr3t-pass@db.example/radar")
    with store.lock():
        locking = connections[-1]
        locking.close()  # the server terminated the session that held the advisory lock
        with pytest.raises(storage.StoreUnavailable):
            store.save(DOCUMENT)
    assert len(connections) == 1, "the write must not be sent through a replacement session"
    assert not [sql for sql, _ in locking.statements if "INSERT INTO state" in sql]


def test_an_operation_outside_the_lock_still_uses_its_own_connection(monkeypatch):
    # The binding is scoped to the lock: a plain save must open and close a connection exactly as before.
    connections: list[_FakeConnection] = []

    class _Driver:
        @staticmethod
        def connect(url: str) -> _FakeConnection:
            connection = _FakeConnection()
            connections.append(connection)
            return connection

    monkeypatch.setitem(sys.modules, "psycopg", _Driver)
    store = storage.PostgreSqlStore("postgresql://radar@db.example/radar")
    store.save(DOCUMENT)
    assert len(connections) == 1
    assert connections[0].closed
    assert [params for sql, params in connections[0].statements if "INSERT INTO state" in sql] == [
        (serialize_json(DOCUMENT),)
    ]


def test_a_malformed_percent_escape_is_refused_before_the_driver_runs(monkeypatch, tmp_path):
    """libpq quotes the offending token -- the password -- so the shape is refused while it cannot leak."""
    driver_calls: list[str] = []

    class _Driver:
        @staticmethod
        def connect(url: str):
            driver_calls.append(url)
            raise AssertionError("the driver must not be reached")

    monkeypatch.setitem(sys.modules, "psycopg", _Driver)
    url = "postgresql://radar:bad%password@db.example/radar"
    with pytest.raises(ValueError) as caught:
        storage.PostgreSqlStore(url)
    message = str(caught.value)
    assert "bad%password" not in message
    assert "%password" not in message
    assert driver_calls == []
    # A configuration reaches the same refusal through the one parser.
    with pytest.raises(ValueError):
        storage.store_for(url, tmp_path / "state.json")


def test_a_password_hidden_in_the_path_is_refused_and_never_printed():
    """A raw ``/`` moves the password into the path for ``urlsplit``; libpq keeps it in the userinfo.

    The shape is refused before a host, database or password exists, so no ``repr`` or ``_unavailable`` can be
    built from it. The same secret in the one position this program understands is never printed either.
    """
    url = "postgresql://radar:/synthetic-secret@db.example/radar"
    with pytest.raises(ValueError) as caught:
        storage.PostgreSqlStore(url)
    assert "synthetic-secret" not in str(caught.value)

    store = storage.PostgreSqlStore("postgresql://radar:synthetic-secret@db.example/radar")
    assert "synthetic-secret" not in repr(store)
    reason = RuntimeError('invalid percent-encoded token: "synthetic-secret"')
    assert "synthetic-secret" not in store._unavailable(reason)


@pytest.mark.parametrize(
    "url",
    [
        # The password's raw "/" leaves a path a credential cannot legally occupy.
        "postgresql://radar:/synthetic-secret@db.example/radar",
        # A trailing ":" is a password separator whose password the path took.
        "postgresql://radar:/synthetic-secret",
        # Two "@" leave the userinfo and the host ambiguous.
        "postgresql://radar@db.example@host/radar",
        # A port that is not a number: its text may be a misplaced password, and urlsplit's own error quotes it.
        "postgresql://db.example:synthetic-secret/radar",
        # A netloc urlsplit normalises beyond the host's case: a leading-zero port does not round-trip.
        "postgresql://db.example:05432/radar",
    ],
)
def test_an_ambiguous_postgres_target_is_refused_before_the_driver(url, monkeypatch):
    driver_calls: list[str] = []

    class _Driver:
        @staticmethod
        def connect(url: str):
            driver_calls.append(url)
            raise AssertionError("the driver must not be reached")

    monkeypatch.setitem(sys.modules, "psycopg", _Driver)
    with pytest.raises(ValueError) as caught:
        storage.PostgreSqlStore(url)
    assert "synthetic-secret" not in str(caught.value)
    assert driver_calls == []


def test_a_driver_message_that_names_the_token_alone_is_scrubbed(monkeypatch):
    # A malformed escape is refused above, but a driver message may still repeat the password without the
    # "@" the old rule needed. The scrubber must remove the token wherever it appears.
    class _Driver:
        @staticmethod
        def connect(url: str):
            raise RuntimeError('invalid percent-encoded token: "s3cr3t%2Dpass"')

    monkeypatch.setitem(sys.modules, "psycopg", _Driver)
    store = storage.PostgreSqlStore("postgresql://radar:s3cr3t%2Dpass@db.example/radar")
    with pytest.raises(storage.StoreUnavailable) as caught:
        store.load()
    message = str(caught.value)
    assert "s3cr3t" not in message
    assert "[redacted]" in message
    assert "db.example/radar" in message, "the reason stays useful"


@pytest.mark.parametrize(
    ("url", "option", "value"),
    [
        # A non-credential option is refused too: the rule is the query string, not a list of credential names.
        ("postgresql://db.example/radar?sslmode=require", "sslmode", "require"),
        # PostgreSQL 18's OAuth secret is why the list was dropped: libpq can add a keyword this program has
        # never heard of, and it must not slip through.
        ("postgresql://db.example/radar?oauth_client_secret=s3cr3t-oauth", "oauth_client_secret", "s3cr3t-oauth"),
        ("postgresql://db.example/radar?password=bad%password", "password", "bad%password"),
        # A percent-encoded option name is the same option to libpq.
        ("postgresql://db.example/radar?pass%77ord=s3cr3t-encoded", "password", "s3cr3t-encoded"),
    ],
)
def test_a_postgres_query_string_is_refused_before_the_driver(url, option, value, tmp_path, monkeypatch):
    """This program does not parse libpq options, so the whole query string is refused, not a list of names.

    libpq keeps adding keywords -- PostgreSQL 18's ``oauth_client_secret`` was the last one -- so a list of
    credential names would always trail it. The static refusal is checked before a driver exists, and it carries
    neither the option name nor its value: a ``migrate`` target's credentials are in no configuration this
    process redacts.
    """
    driver_calls: list[str] = []

    class _Driver:
        @staticmethod
        def connect(url: str):
            driver_calls.append(url)
            raise AssertionError("the driver must not be reached")

    monkeypatch.setitem(sys.modules, "psycopg", _Driver)
    with pytest.raises(ValueError) as caught:
        storage.PostgreSqlStore(url)
    message = str(caught.value)
    assert "does not parse libpq options" in message, "the refusal says why every option is out of scope"
    # The only option-like words are the uppercase PG* environment variables the message tells the operator to
    # use; the lowercase option name from the URL never appears, and neither does its value.
    assert option not in message, "the refusal must not echo the parameter name"
    assert value not in message, "the refusal must not echo the value"
    assert url.split("?", 1)[1] not in message, "the raw query string is never repeated"
    assert driver_calls == []
    # A configuration reaches the same refusal through the one parser, so `migrate --to` cannot skip it.
    with pytest.raises(ValueError):
        storage.store_for(url, tmp_path / "state.json")
    assert driver_calls == []


@pytest.mark.parametrize(
    "url",
    [
        # urlsplit starts a fragment, so no query parameter exists for this program; libpq keeps the "#" in the
        # database name and parses the password option, then quotes the bad token.
        "postgresql://db.example/radar#?password=bad%password",
        # The same disagreement in the userinfo: libpq reads the password before the "@", urlsplit sees none.
        "postgresql://radar:bad%password#x@db.example/radar",
    ],
)
def test_a_raw_fragment_in_the_postgres_target_is_refused_before_the_driver(url, tmp_path, monkeypatch):
    """Both credential checks read the URL the way ``urlsplit`` does, so a raw ``#`` is refused rather than
    mirrored: libpq would read the same text differently and could quote a password this code never saw."""
    driver_calls: list[str] = []

    class _Driver:
        @staticmethod
        def connect(url: str):
            driver_calls.append(url)
            raise AssertionError("the driver must not be reached")

    monkeypatch.setitem(sys.modules, "psycopg", _Driver)
    with pytest.raises(ValueError) as caught:
        storage.PostgreSqlStore(url)
    message = str(caught.value)
    assert "fragment" in message, "the refusal says what is wrong"
    for part in ("bad%password", "%password", "bad"):
        assert part not in message, "no part of the credential may appear in the refusal"
    assert driver_calls == []
    with pytest.raises(ValueError):
        storage.store_for(url, tmp_path / "state.json")
    assert driver_calls == []


def test_an_encoded_fragment_in_the_userinfo_stays_a_password_position():
    # A properly percent-encoded # is not a fragment: it is part of the password, and the store accepts it.
    store = storage.PostgreSqlStore("postgresql://radar:s3cr3t%23pass@db.example/radar")
    assert repr(store) == "PostgreSqlStore(host='db.example', database='radar')"


def test_a_fragment_free_query_string_cannot_even_carry_a_non_credential_option():
    # The rule is the query string itself, so there is no option list to keep in step with libpq.
    with pytest.raises(ValueError, match="may not carry a query string"):
        storage.PostgreSqlStore("postgresql://db.example/radar?sslmode=require")
