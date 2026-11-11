"""The migrate command: copy the state document to another store, and never lose the one that exists.

Every test drives ``cli.main`` because the command is the contract: which store is read, which is refused,
and what the operator sees. No PostgreSQL server is needed; an unusable target fails on the missing driver.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

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
