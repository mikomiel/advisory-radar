"""Built-in source plugins: generic RSS/Atom and the FreshRSS GReader export."""

from __future__ import annotations

import hashlib

from . import feeds
from .core import Item, _host, dsa_id, extract_ids
from .http import Http, parse_json
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
    """Any RSS 2.0 / Atom feed URL; the whole feed is read in one GET.

    The publisher's ``ETag``/``Last-Modified`` are kept per source, so an unchanged feed answers ``304`` - the
    common case for a feed polled every 15 minutes, and the one that keeps a free publisher's bandwidth ours
    rather than theirs.
    """

    kind = "feed"

    def __init__(self, source_id: str, url: str) -> None:
        self.id = source_id
        self.url = url
        #: Validators from this window, stored only by ``commit`` once the pipeline captured the candidates.
        self._store: dict[str, str] | None = None

    def fetch(self, http: Http, state: dict) -> SourceWindow:
        stored = state.get("feeds", {}).get(self.id)
        validators: dict[str, str] = {}
        # The validators belong to the URL that issued them. An operator may repoint a source id at another
        # feed, and an ``ETag`` is unique per resource, not per repository: sending the old one to the new URL
        # can earn a legitimate ``304`` for a feed that was never read, which silently drops its advisories.
        if isinstance(stored, dict) and stored.get("url") == self.url:
            if isinstance(stored.get("etag"), str):
                validators["If-None-Match"] = stored["etag"]
            if isinstance(stored.get("last_modified"), str):
                validators["If-Modified-Since"] = stored["last_modified"]
        export, fresh = feeds.fetch_rss(http, self.url, validators)
        # ``None`` is a 304: keep what is stored. Anything else is this window's validators -- held until
        # ``commit``, because a window whose candidates never reached pending or carry must be read in full again.
        self._store = fresh
        return SourceWindow(self.id, _items(export), export.truncated, _host(self.url))

    def commit(self, state: dict) -> None:
        """Advance the stored validators only once the pipeline has captured this window's candidates.

        The same rule the changedetection cursor follows: arming the ``304`` fast path before the work is
        durable would make an unchanged feed return an empty window for advisories that were never queued.
        """
        fresh, self._store = self._store, None
        if fresh is None:
            return  # a 304 carries no validators and must not forget the stored ones
        if fresh:
            state.setdefault("feeds", {})[self.id] = {"url": self.url, **fresh}
        elif state.get("feeds"):
            # A 200 without validators replaces the stored ones with nothing: keeping them would send a stale
            # If-None-Match for a feed that has stopped offering one.
            state["feeds"].pop(self.id, None)


class FreshRssSource:
    """A FreshRSS shared query exported as GReader JSON (``f=greader``)."""

    kind = "feed"

    def __init__(self, source_id: str, base_url: str, token: str, user: str = "admin") -> None:
        self.id = source_id
        self.base_url = base_url
        self.token = token
        self.user = user

    def fetch(self, http: Http, state: dict) -> SourceWindow:
        export = feeds.fetch_feed(http, self.base_url, self.token, self.user)
        return SourceWindow(self.id, _items(export), export.truncated, _host(self.base_url))


class ChangedetectionSource:
    """Poll a changedetection.io instance: one item per watch whose ``last_changed`` moved.

    API: ``GET {url}/api/v1/watch`` with header ``x-api-key`` (docs/api_v1). The
    response maps uuid -> watch object. Seen ``last_changed`` values live in
    ``state["changedetection"][id]``.
    """

    kind = "changedetection"

    def __init__(self, source_id: str, url: str, api_key: str, tag: str | None = None) -> None:
        self.id = source_id
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.tag = tag

    def fetch(self, http: Http, state: dict) -> SourceWindow:
        query = f"?tag={self.tag}" if self.tag else ""
        status, _, body = http("GET", f"{self.url}/api/v1/watch{query}", {"x-api-key": self.api_key}, None)
        if status != 200:
            raise RuntimeError(
                f"changedetection.io answered HTTP {status}" if status else "changedetection.io is unreachable"
            )
        document = parse_json(body)
        watches = document if isinstance(document, dict) else None
        if watches is None:
            raise RuntimeError("changedetection.io response is not a watch map")
        seen = state.get("changedetection", {}).get(self.id, {})
        # Cursors are *not* advanced here: a fetch whose candidates never reach pending/carry would lose them.
        pending_cursors: dict[str, int] = {}
        items: list[Item] = []
        for uuid, watch in watches.items():
            if not isinstance(watch, dict) or not isinstance(uuid, str):
                continue
            if watch.get("paused") or watch.get("notification_muted"):
                continue
            changed = watch.get("last_changed")
            if not isinstance(changed, (int, float)) or isinstance(changed, bool):
                continue
            changed = int(changed)
            if seen.get(uuid, 0) >= changed:
                continue
            pending_cursors[uuid] = changed
            title = str(watch.get("title") or watch.get("page_title") or uuid)
            link = str(watch.get("link") or watch.get("url") or "")
            summary = f"Page changed (last_changed={changed})."
            explicit = extract_ids(title, summary, link)
            items.append(
                Item(
                    f"cd:{uuid}:{changed}",
                    f"{title} — changedetection.io",
                    link,
                    summary,
                    changed,
                    explicit,
                    title,
                    link,
                )
            )
        self._pending_cursors = pending_cursors
        return SourceWindow(self.id, tuple(items), False, _host(self.url))

    def commit(self, state: dict) -> None:
        """Advance the cursors only once the pipeline has captured this window's candidates."""
        cursors = getattr(self, "_pending_cursors", None)
        if not cursors:
            return
        state.setdefault("changedetection", {}).setdefault(self.id, {}).update(cursors)
        self._pending_cursors = {}


class WebhookSource:
    """Items pushed to ``POST /webhooks/<id>`` land in ``state["webhook_inbox"][id]``; this source reads them."""

    kind = "webhook"

    def __init__(self, source_id: str) -> None:
        self.id = source_id

    def fetch(self, http: Http, state: dict) -> SourceWindow:
        inbox = state.get("webhook_inbox", {}).get(self.id, [])
        items = tuple(
            Item(
                str(entry.get("guid", "")),
                str(entry.get("title", "")),
                str(entry.get("link", "")),
                str(entry.get("summary", "")),
                entry.get("published") if isinstance(entry.get("published"), int) else None,
                extract_ids(str(entry.get("title", "")), str(entry.get("summary", "")), str(entry.get("link", ""))),
                str(entry.get("source_title", "")),
                str(entry.get("source_url", "")),
            )
            for entry in inbox
            if isinstance(entry, dict)
        )
        return SourceWindow(self.id, items, False, "")


def webhook_item_from_payload(payload: object) -> dict | None:
    """Map a generic or changedetection.io-native webhook JSON body to an inbox entry."""
    if not isinstance(payload, dict):
        return None
    if "watch_uuid" in payload or "watch_url" in payload:  # changedetection.io native shape
        diff = str(payload.get("diff") or "")
        guid = "wh:cd:" + hashlib.sha1((str(payload.get("watch_uuid")) + diff).encode()).hexdigest()[:16]
        return {
            "guid": guid,
            "title": str(payload.get("watch_title") or payload.get("watch_url") or "change"),
            "link": str(payload.get("watch_url") or ""),
            "summary": diff or "page changed",
            "source_title": "changedetection.io",
            "source_url": str(payload.get("watch_url") or ""),
        }
    title = payload.get("title")
    if not isinstance(title, str) or not title.strip():
        return None
    summary = str(payload.get("summary") or payload.get("text") or payload.get("body") or "")
    link = str(payload.get("link") or payload.get("url") or "")
    ids = payload.get("ids")
    guid = str(payload.get("guid") or hashlib.sha1((title + summary + link).encode()).hexdigest()[:16])
    entry = {
        "guid": f"wh:{guid}",
        "title": title,
        "link": link,
        "summary": summary,
        "source_title": str(payload.get("source") or "webhook"),
        "source_url": "",
    }
    if isinstance(ids, list) and all(isinstance(i, str) for i in ids):
        entry["explicit_ids"] = ids
    return entry


#: Config ``type`` -> builder(config dict, env) -> Source. Secret fields are
#: ``${VAR}`` placeholders resolved by config.load_config at load time.
SOURCE_BUILDERS = {
    "rss": lambda cfg, env: RssSource(cfg["id"], cfg["url"]),
    "freshrss": lambda cfg, env: FreshRssSource(cfg["id"], cfg["url"], cfg["token"], cfg.get("user", "admin")),
    "changedetection": lambda cfg, env: ChangedetectionSource(cfg["id"], cfg["url"], cfg["api_key"], cfg.get("tag")),
    "webhook": lambda cfg, env: WebhookSource(cfg["id"]),
}


def build_source(cfg: dict, env: dict[str, str]) -> Source:
    kind = cfg.get("type")
    builder = SOURCE_BUILDERS.get(kind or "")
    if builder is None:
        raise ValueError(f"unknown source type (id {cfg.get('id')!r}); built-ins: {sorted(SOURCE_BUILDERS)}")
    return builder(cfg, env)


__all__ = [
    "ChangedetectionSource",
    "FreshRssSource",
    "RssSource",
    "SOURCE_BUILDERS",
    "WebhookSource",
    "build_source",
    "webhook_item_from_payload",
]
