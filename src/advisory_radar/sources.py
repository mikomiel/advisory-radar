"""Built-in source plugins: generic RSS/Atom and the FreshRSS GReader export."""

from __future__ import annotations

from . import feeds
from .core import Item, _host, dsa_id, extract_ids
from .http import Http
from .plugins import Source, SourceWindow


def _items(export: feeds.FeedExport) -> tuple[Item, ...]:
    items = []
    for entry in export.items:
        explicit = extract_ids(entry.title, entry.summary, entry.link)
        dsa = dsa_id(entry.title)
        items.append(
            Item(
                entry.guid,
                entry.title,
                entry.link,
                entry.summary,
                entry.published,
                (*explicit, dsa) if dsa and dsa not in explicit else explicit,
                entry.source_title,
                entry.source_url,
            )
        )
    return tuple(items)


class RssSource:
    """Any RSS 2.0 / Atom feed URL; the whole feed is read in one GET."""

    def __init__(self, source_id: str, url: str) -> None:
        self.id = source_id
        self.url = url

    def fetch(self, http: Http) -> SourceWindow:
        export = feeds.fetch_rss(http, self.url)
        return SourceWindow(self.id, _items(export), export.truncated, _host(self.url))


class FreshRssSource:
    """A FreshRSS shared query exported as GReader JSON (``f=greader``)."""

    def __init__(self, source_id: str, base_url: str, token: str, user: str = "admin") -> None:
        self.id = source_id
        self.base_url = base_url
        self.token = token
        self.user = user

    def fetch(self, http: Http) -> SourceWindow:
        export = feeds.fetch_feed(http, self.base_url, self.token, self.user)
        return SourceWindow(self.id, _items(export), export.truncated, _host(self.base_url))


#: Config ``type`` -> builder(config dict, env) -> Source. Secret fields are
#: ``${VAR}`` placeholders resolved by config.load_config at load time.
SOURCE_BUILDERS = {
    "rss": lambda cfg, env: RssSource(cfg["id"], cfg["url"]),
    "freshrss": lambda cfg, env: FreshRssSource(cfg["id"], cfg["url"], cfg["token"], cfg.get("user", "admin")),
}


def build_source(cfg: dict, env: dict[str, str]) -> Source:
    kind = cfg.get("type")
    builder = SOURCE_BUILDERS.get(kind or "")
    if builder is None:
        raise ValueError(f"unknown source type (id {cfg.get('id')!r}); built-ins: {sorted(SOURCE_BUILDERS)}")
    return builder(cfg, env)


__all__ = ["FreshRssSource", "RssSource", "SOURCE_BUILDERS", "build_source"]
