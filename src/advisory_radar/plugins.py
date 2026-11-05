"""Plugin protocols and registry for advisory-radar.

Three seams: sources produce candidate items, notifiers deliver queued
messages. Enrichment (CVE facts) lives in core.Intel because every source
shares it; sources that need a vendor page (Debian tracker, php.net, ...)
use Intel's bounded fetchers. Plugins are configured, never hardcoded:
config.py instantiates the built-ins below from the YAML config.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .core import Item
from .http import Http


@dataclass(frozen=True)
class SourceWindow:
    """One fetch of a source: its items, and whether the source held more than it returned."""

    source_id: str
    items: tuple[Item, ...]
    truncated: bool
    #: The host items from this source are attributed to when rendering (feed host).
    host: str


class Source(Protocol):
    """A configured feed-like input. ``fetch`` must be idempotent and bounded."""

    id: str

    def fetch(self, http: Http) -> SourceWindow: ...


class Notifier(Protocol):
    """A configured delivery channel. ``send`` returns the HTTP status (0 = network error)."""

    id: str

    def send(self, entry: dict, http: Http) -> int: ...
