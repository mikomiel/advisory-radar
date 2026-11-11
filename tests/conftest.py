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
