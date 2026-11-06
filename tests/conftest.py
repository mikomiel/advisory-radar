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
