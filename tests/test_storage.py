"""The state stores: one document, three places for its bytes, one contract.

Every test here runs without a network and without a PostgreSQL server: where the PostgreSQL SQL matters the
driver is faked, and the credential rule is asserted against what a caller can actually see -- a message and a
``repr``. Each implementation is pinned on what it could plausibly get wrong: the document round-trips, a
foreign schema is refused, the bytes on disk are private, and the lock excludes every other writer.
"""

from __future__ import annotations

import json
import sqlite3
import stat
import sys

import pytest

from advisory_radar import core, storage
from advisory_radar.state import LockBusy, SourceError, serialize_json

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
    assert "python -m pip install 'psycopg[binary]'" in str(caught.value)
    assert "s3cr3t-pass" not in str(caught.value)


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
