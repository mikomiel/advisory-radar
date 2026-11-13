"""Smoke test: the package imports and reports the version the project declares."""

from __future__ import annotations

import tomllib
from pathlib import Path

import advisory_radar

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_version() -> None:
    # release-please bumps both declarations in its release pull request; a literal here would fail that pull
    # request's checks instead of proving the two places agree.
    declared = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    assert advisory_radar.__version__ == declared
