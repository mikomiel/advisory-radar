"""Shared test setup.

The web session cookie is ``Secure`` by default, so a plain-HTTP test client would never send it back. Tests
opt out explicitly through the same switch a plaintext development instance uses; production deployments keep
the default.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _insecure_cookies_for_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADVISORY_RADAR_INSECURE_COOKIES", "1")


@pytest.fixture
def real_directory_sync() -> None:
    """Ask for the real directory sync after a save; see ``_skip_the_directory_sync``."""


@pytest.fixture(autouse=True)
def _skip_the_directory_sync(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    """Leave out the directory sync a save ends with.

    It is a second ``fsync`` per save, which on a slow disk doubles the time of every test that saves a document
    and which none of them can observe. The tests that pin the sync itself request ``real_directory_sync``.
    """
    if "real_directory_sync" in request.fixturenames:
        return
    from advisory_radar import state

    monkeypatch.setattr(state, "_sync_directory", lambda directory: None)


@pytest.fixture
def read_only_sqlite(monkeypatch: pytest.MonkeyPatch):
    """Make one SQLite document database read-only at the engine, and leave every other file alone.

    A ``chmod 0400`` database is not read-only for this suite, because the tests run as root and root ignores
    the permission bits. ``query_only`` is the engine's own read-only mode: reads and the already committed row
    still work, while the write fails with the real ``SQLITE_READONLY`` error a read-only file or a full disk
    produces. The patched factory is shared by the store and the command that drives it, so the read and the
    write of one migration are both covered.
    """
    import sqlite3
    from pathlib import Path

    from advisory_radar import storage

    def read_only(path: Path) -> None:
        real_connect = sqlite3.connect

        def connect(database, *args, **kwargs):
            connection = real_connect(database, *args, **kwargs)
            if str(database) == str(path):
                connection.execute("PRAGMA query_only = ON")
            return connection

        monkeypatch.setattr(storage.sqlite3, "connect", connect)

    return read_only
