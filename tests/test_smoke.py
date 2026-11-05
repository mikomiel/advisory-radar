"""Smoke test: the package imports and reports its version."""

import advisory_radar


def test_version() -> None:
    assert advisory_radar.__version__ == "0.1.0"
