"""The migrate command: copy the state document to another store, and never lose the one that exists.

Every test drives ``cli.main`` because the command is the contract: which store is read, which is refused,
and what the operator sees. No PostgreSQL server is needed; an unusable target fails on the missing driver.
"""

from __future__ import annotations

import contextlib
import logging
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

from advisory_radar import cli, core
from advisory_radar.state import load_state_document, save_state
from advisory_radar.storage import SqliteStore


def make_config(tmp_path: Path, *, storage: str = "") -> Path:
    """A configuration that needs no plugin and no secret: a migration is a state-only command."""
    path = tmp_path / "config.yml"
    body = f"sources: []\nnotifiers: []\nstate_path: {tmp_path}/state.json\n"
    if storage:
        body += f"storage: {storage}\n"
    path.write_text(body)
    return path


def make_document() -> dict:
    state = core.new_state()
    state["pending"].append({"kind": "new", "tag": "warning", "title": "T", "body": "b", "ids": ["CVE-2026-1"]})
    return state


def test_migrate_copies_the_document_and_names_only_the_stores(tmp_path, capsys):
    config = make_config(tmp_path)
    document = make_document()
    save_state(tmp_path / "state.json", document)
    target = f"sqlite:///{tmp_path}/state.db"

    assert cli.main(["migrate", "--config", str(config), "--to", target], env={}) == 0
    assert SqliteStore(tmp_path / "state.db").load() == document
    assert (tmp_path / "state.json").is_file(), "a migration copies; it does not delete the source"

    printed = capsys.readouterr().out
    assert "JsonStore(" in printed and "SqliteStore(" in printed
    # The message names the stores by their redacted reprs, never by the configured value: a PostgreSQL
    # locator carries a password and this line is output an operator may paste into an issue.
    assert "sqlite:///" not in printed


def test_migrate_refuses_a_target_that_already_holds_a_document(tmp_path, caplog):
    config = make_config(tmp_path)
    save_state(tmp_path / "state.json", make_document())
    kept = {"schema": core.STATE_SCHEMA, "pending": [{"title": "already here"}]}
    SqliteStore(tmp_path / "state.db").save(kept)

    with caplog.at_level(logging.ERROR):
        code = cli.main(["migrate", "--config", str(config), "--to", f"sqlite:///{tmp_path}/state.db"], env={})
    assert code == 1
    assert "already holds a state document" in caplog.text
    assert SqliteStore(tmp_path / "state.db").load() == kept, "a refused migration writes nothing"


def test_migrate_refuses_the_configured_store(tmp_path, caplog):
    target = f"sqlite:///{tmp_path}/state.db"
    config = make_config(tmp_path, storage=target)
    SqliteStore(tmp_path / "state.db").save(make_document())

    with caplog.at_level(logging.ERROR):
        assert cli.main(["migrate", "--config", str(config), "--to", target], env={}) == 1
    assert "would move nothing" in caplog.text


def test_migrate_refuses_a_source_that_holds_no_document(tmp_path, caplog):
    config = make_config(tmp_path)
    with caplog.at_level(logging.ERROR):
        code = cli.main(["migrate", "--config", str(config), "--to", f"sqlite:///{tmp_path}/state.db"], env={})
    assert code == 1
    assert "nothing to migrate" in caplog.text
    assert not (tmp_path / "state.db").exists(), "an empty source must not create the target"


def test_migrate_refuses_an_unusable_target_without_echoing_it(tmp_path, monkeypatch, caplog):
    config = make_config(tmp_path)
    save_state(tmp_path / "state.json", make_document())
    monkeypatch.setitem(sys.modules, "psycopg", None)

    with caplog.at_level(logging.ERROR):
        code = cli.main(
            ["migrate", "--config", str(config), "--to", "postgresql://radar:s3cr3t-pass@db.example/radar"],
            env={},
        )
    assert code == 1
    assert "psycopg" in caplog.text, "the refusal names the missing piece"
    assert "s3cr3t-pass" not in caplog.text


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://db.example/radar?password=bad%password",
        # A keyword this program has never heard of is refused the same way: the query string is out of scope,
        # not a list of names that libpq would keep outgrowing.
        "postgresql://db.example/radar?oauth_client_secret=bad%password",
    ],
)
def test_migrate_refuses_a_postgres_query_string_before_the_driver(url, tmp_path, monkeypatch, caplog):
    """A ``--to`` credential is in no configuration this process redacts, and libpq can quote the value alone.

    The refusal is static and names no option, so neither the value nor the parameter name can reach the log an
    operator pastes into an issue.
    """
    driver_calls: list[str] = []

    class _Driver:
        @staticmethod
        def connect(url: str):
            driver_calls.append(url)
            raise RuntimeError('invalid percent-encoded token: "bad%password"')

    monkeypatch.setitem(sys.modules, "psycopg", _Driver)
    config = make_config(tmp_path)
    save_state(tmp_path / "state.json", make_document())
    with caplog.at_level(logging.ERROR):
        code = cli.main(["migrate", "--config", str(config), "--to", url], env={})
    assert code == 1
    assert driver_calls == [], "the URL must be refused before the driver can quote it"
    assert "does not parse libpq options" in caplog.text
    assert "bad%password" not in caplog.text
    assert "%password" not in caplog.text
    for option in ("password", "oauth_client_secret"):
        assert option not in caplog.text, "the log names no option, because none is parsed"


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://db.example/radar#?password=bad%password",
        "postgresql://radar:bad%password#x@db.example/radar",
    ],
)
def test_migrate_refuses_a_fragment_target_before_the_driver(url, tmp_path, monkeypatch, caplog):
    """A raw ``#`` is where Python's parser and libpq disagree, and ``--to`` credentials are in no redactor."""
    driver_calls: list[str] = []

    class _Driver:
        @staticmethod
        def connect(url: str):
            driver_calls.append(url)
            raise RuntimeError('invalid percent-encoded token: "bad%password"')

    monkeypatch.setitem(sys.modules, "psycopg", _Driver)
    config = make_config(tmp_path)
    save_state(tmp_path / "state.json", make_document())
    with caplog.at_level(logging.ERROR):
        code = cli.main(["migrate", "--config", str(config), "--to", url], env={})
    assert code == 1
    assert driver_calls == [], "the URL must be refused before the driver can quote it"
    assert "fragment" in caplog.text
    assert "bad%password" not in caplog.text
    assert "%password" not in caplog.text


def test_the_document_is_the_same_after_a_round_trip_through_sqlite(tmp_path):
    """A migration is a byte-for-byte move of the text, so a document can come back unchanged."""
    document = make_document()
    config = make_config(tmp_path)
    save_state(tmp_path / "state.json", document)
    assert cli.main(["migrate", "--config", str(config), "--to", f"sqlite:///{tmp_path}/state.db"], env={}) == 0

    back = make_config(tmp_path, storage=f"sqlite:///{tmp_path}/state.db")
    (tmp_path / "state.json").unlink()
    assert cli.main(["migrate", "--config", str(back), "--to", ""], env={}) == 0
    assert load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state") == document


def test_two_migrations_against_the_same_target_cannot_both_write(tmp_path):
    """The check and the save are one critical section: the second migration waits, then sees the document."""
    first_document = make_document()
    save_state(tmp_path / "state.json", first_document)
    other = tmp_path / "second"
    other.mkdir()
    second_document = make_document()
    second_document["pending"][0]["title"] = "the other migration"
    save_state(other / "state.json", second_document)
    target = f"sqlite:///{tmp_path}/state.db"

    real_save, real_lock = SqliteStore.save, SqliteStore.lock
    locked = threading.Event()
    attempted = threading.Event()
    release = threading.Event()
    attempts: list[bool] = []
    saves: list[dict] = []

    @contextlib.contextmanager
    def signalling_lock(self, *, blocking: bool = True):
        attempts.append(blocking)
        if len(attempts) == 1:
            locked.set()
        else:
            attempted.set()
        with real_lock(self, blocking=blocking):
            yield

    def gated_save(self, document: dict) -> None:
        saves.append(document)
        if len(saves) == 1:
            assert release.wait(timeout=10)
        real_save(self, document)

    SqliteStore.lock, SqliteStore.save = signalling_lock, gated_save
    try:
        results: dict[str, int] = {}

        def migrate(config: Path, key: str) -> None:
            results[key] = cli.main(["migrate", "--config", str(config), "--to", target], env={})

        first = threading.Thread(target=migrate, args=(make_config(tmp_path), "first"))
        first.start()
        assert locked.wait(timeout=10), "the first migration never took the target lock"
        second = threading.Thread(target=migrate, args=(make_config(other), "second"))
        second.start()
        # With the lock the second migration waits for it, so this event says the attempt happened; without the
        # lock it never asks, and the bound keeps the failing case from hanging instead of going red.
        attempted.wait(timeout=2)
        release.set()
        first.join(timeout=10)
        second.join(timeout=10)
        assert not first.is_alive() and not second.is_alive()
    finally:
        SqliteStore.lock, SqliteStore.save = real_lock, real_save

    assert sorted(results.values()) == [0, 1], "exactly one migration may create the target document"
    assert SqliteStore(tmp_path / "state.db").load() == first_document


def test_a_write_between_the_check_and_the_save_cannot_overwrite_the_document(tmp_path, caplog):
    """A migration started after the check waits for the target lock, then sees the document and refuses.

    The lock spans the check and the save, so there is no window in which a second writer can create the
    document unseen; it must never replace the first migration's write.
    """
    outer_document = make_document()
    save_state(tmp_path / "state.json", outer_document)
    other = tmp_path / "injected"
    other.mkdir()
    injected_document = make_document()
    injected_document["pending"][0]["title"] = "injected while the first migration checked"
    save_state(other / "state.json", injected_document)
    target = f"sqlite:///{tmp_path}/state.db"

    real_load = SqliteStore.load
    second: dict[str, int] = {}
    workers: list[threading.Thread] = []

    def loading(self):
        document = real_load(self)
        if not workers:
            # The first migration's check: start the second migration in the window before the first saves.
            worker = threading.Thread(
                target=lambda: second.update(
                    code=cli.main(["migrate", "--config", str(make_config(other)), "--to", target], env={})
                )
            )
            worker.start()
            workers.append(worker)
        return document

    SqliteStore.load = loading
    try:
        with caplog.at_level(logging.ERROR):
            assert cli.main(["migrate", "--config", str(make_config(tmp_path)), "--to", target], env={}) == 0
            for worker in workers:
                worker.join(timeout=10)
                assert not worker.is_alive(), "the injected migration did not finish"
    finally:
        SqliteStore.load = real_load

    assert second.get("code") == 1, "the injected migration must be refused rather than replacing the document"
    assert "already holds a state document" in caplog.text
    assert SqliteStore(tmp_path / "state.db").load() == outer_document


def test_migrate_refuses_a_target_at_an_auxiliary_file(tmp_path, caplog):
    """``--to`` a path beside ``state_path`` is refused before the KEV cache or the settings overlay is touched."""
    config = make_config(tmp_path)
    save_state(tmp_path / "state.json", make_document())
    kev, overlay = tmp_path / "kev.json", tmp_path / "settings.json"
    kev.write_text('{"schema": "advisory-radar-kev.v1", "cves": ["CVE-2026-1"]}', encoding="utf-8")
    overlay.write_text('{"schema": "advisory-radar-settings.v1", "settings": {}}', encoding="utf-8")
    before = (kev.read_bytes(), overlay.read_bytes())

    for target, role in ((kev, "KEV cache"), (overlay, "settings overlay")):
        with caplog.at_level(logging.ERROR):
            caplog.clear()
            code = cli.main(["migrate", "--config", str(config), "--to", f"sqlite:///{target}"], env={})
        assert code == 1
        assert role in caplog.text, "the refusal names the file's role"
        assert str(target) not in caplog.text, "the log never names the path"
    assert (kev.read_bytes(), overlay.read_bytes()) == before, "a refused migration must not touch either file"


def test_migrate_refuses_a_read_only_target_without_writing(tmp_path, read_only_sqlite, caplog):
    """A target that cannot be written is the store refusal, not a traceback and not a half-migration."""
    config = make_config(tmp_path)
    document = make_document()
    save_state(tmp_path / "state.json", document)
    target = tmp_path / "state.db"
    SqliteStore(target).save(core.new_state())
    connection = sqlite3.connect(target)
    try:
        connection.execute("DELETE FROM state")
        connection.commit()
    finally:
        connection.close()
    assert SqliteStore(target).load() is None, "the target must be empty for the migration to try"
    read_only_sqlite(target)

    with caplog.at_level(logging.ERROR):
        code = cli.main(["migrate", "--config", str(config), "--to", f"sqlite:///{target}"], env={})
    assert code == 1
    assert "unavailable" in caplog.text
    assert SqliteStore(target).load() is None, "a refused migration writes nothing"
