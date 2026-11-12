"""Built-in source plugins: generic RSS/Atom and the FreshRSS GReader export."""

from __future__ import annotations

import hashlib
import urllib.parse

from . import feeds
from .catalogue import SOURCE_SPECS
from .core import Item, _host, dsa_id, extract_ids
from .http import Http, json_text, parse_json
from .plugins import Source, SourceWindow


def _url_digest(url: str) -> str:
    """A stable, non-reversible name for a feed URL.

    The URL is configuration, and configuration may carry a credential -- ``?token=${FEED_TOKEN}`` is expanded
    before the source is built. Writing the URL into the state document would put that credential into
    ``state.json`` and into the state API; the digest answers the only question the validators ask, which is
    whether this is still the same feed.
    """
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


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
    """Any feed URL: RSS 2.0, Atom, RSS 1.0 (RDF), JSON Feed, or a page that advertises one.

    The format is sniffed from the document rather than configured, so an existing ``rss`` source gains a
    format without a new key. The publisher's ``ETag``/``Last-Modified`` are kept per source, so an unchanged
    feed answers ``304`` - the common case for a feed polled every 15 minutes, and the one that keeps a free
    publisher's bandwidth ours rather than theirs.
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
        if isinstance(stored, dict) and stored.get("url_digest") == _url_digest(self.url):
            if isinstance(stored.get("etag"), str):
                validators["If-None-Match"] = stored["etag"]
            if isinstance(stored.get("last_modified"), str):
                validators["If-Modified-Since"] = stored["last_modified"]
        export, fresh = feeds.fetch_any(http, self.url, validators)
        # ``None`` is a 304: keep what is stored. ``{}`` is a 200 that issued no validator -- including a page
        # whose autodiscovery hop found the feed, because that validator describes the feed, not the page the
        # next poll requests. Both are held until ``commit``; see there for why the empty answer must clear.
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
            state.setdefault("feeds", {})[self.id] = {"url_digest": _url_digest(self.url), **fresh}
        elif state.get("feeds"):
            # A 200 without validators replaces the stored ones with nothing: keeping them would send a stale
            # If-None-Match for a feed that has stopped offering one. An autodiscovered page is the important
            # case: the stored validator belonged to the feed the URL used to answer directly, and the page
            # would answer 304 for a feed whose changes are now behind the hop -- hiding every later advisory.
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
        query = f"?{urllib.parse.urlencode({'tag': self.tag})}" if self.tag else ""
        status, _, body = http("GET", f"{self.url}/api/v1/watch{query}", {"x-api-key": self.api_key}, None)
        if status != 200:
            raise RuntimeError(
                f"changedetection.io answered HTTP {status}" if status else "changedetection.io is unreachable"
            )
        text = json_text(body)
        if text is None:
            raise RuntimeError("changedetection.io response is not valid UTF-8")
        document = parse_json(text)
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
        def identities(entry: dict) -> tuple[str, ...]:
            """The validated structured ids first, then the ones the entry's own text names: one union."""
            stored = entry.get("explicit_ids")
            structured = (str(value) for value in stored if isinstance(value, str)) if isinstance(stored, list) else ()
            prose = extract_ids(str(entry.get("title", "")), str(entry.get("summary", "")), str(entry.get("link", "")))
            return tuple(dict.fromkeys((*structured, *prose)))

        inbox = state.get("webhook_inbox", {}).get(self.id, [])
        items = tuple(
            Item(
                str(entry.get("guid", "")),
                str(entry.get("title", "")),
                str(entry.get("link", "")),
                str(entry.get("summary", "")),
                entry.get("published") if isinstance(entry.get("published"), int) else None,
                identities(entry),
                str(entry.get("source_title", "")),
                str(entry.get("source_url", "")),
            )
            for entry in inbox
            if isinstance(entry, dict)
        )
        return SourceWindow(self.id, items, False, "")


def webhook_item_from_payload(payload: object) -> dict | None:
    """Map a generic or changedetection.io-native webhook JSON body to an inbox entry.

    ``ValueError`` is the refused-payload signal the intake turns into a 400: an ``ids`` value must be a list
    of identifiers the text extractor understands, and a text field must be UTF-8 representable because it is
    hashed to derive a default guid. A lone surrogate is valid JSON but not a Unicode scalar value, so encoding
    it would raise after the request was accepted.
    """

    def checked(value: object) -> str:
        text = str(value)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("payload text is not valid Unicode") from None
        return text

    def declared_ids(value: object) -> tuple[str, ...]:
        """The supported structured ids, normalised and deduplicated; anything else is refused."""
        if value is None:
            return ()
        if not isinstance(value, list):
            raise ValueError("ids must be a list of identifier strings")
        found: dict[str, None] = {}
        for item in value:
            if not isinstance(item, str):
                raise ValueError("ids must be a list of identifier strings")
            text = item.strip()
            extracted = extract_ids(text)
            if len(extracted) != 1 or extracted[0].casefold() != text.casefold():
                raise ValueError("ids may contain only CVE, GHSA or PSA identifiers")
            found[extracted[0]] = None
        return tuple(found)

    def merged(title: str, summary: str, link: str, value: object) -> list[str] | None:
        """The union of the ids the text names and the structured ones; None when the entry names none."""
        union = tuple(dict.fromkeys((*extract_ids(title, summary, link), *declared_ids(value))))
        return list(union) if union else None

    if not isinstance(payload, dict):
        return None
    if "watch_uuid" in payload or "watch_url" in payload:  # changedetection.io native shape
        diff = checked(payload.get("diff") or "")
        watch_uuid = checked(payload.get("watch_uuid"))
        watch_url = checked(payload.get("watch_url") or "")
        title = checked(payload.get("watch_title") or payload.get("watch_url") or "change")
        summary = diff or "page changed"
        entry = {
            "guid": "wh:cd:" + hashlib.sha1((watch_uuid + diff).encode()).hexdigest()[:16],
            "title": title,
            "link": watch_url,
            "summary": summary,
            "source_title": "changedetection.io",
            "source_url": watch_url,
        }
        ids = merged(title, summary, watch_url, payload.get("ids"))
        if ids:
            entry["explicit_ids"] = ids
        return entry
    title = payload.get("title")
    if not isinstance(title, str) or not title.strip():
        return None
    title = checked(title)
    summary = checked(payload.get("summary") or payload.get("text") or payload.get("body") or "")
    link = checked(payload.get("link") or payload.get("url") or "")
    source = checked(payload.get("source") or "webhook")
    ids = merged(title, summary, link, payload.get("ids"))
    guid = str(payload.get("guid") or hashlib.sha1((title + summary + link).encode()).hexdigest()[:16])
    entry = {
        "guid": f"wh:{guid}",
        "title": title,
        "link": link,
        "summary": summary,
        "source_title": source,
        "source_url": "",
    }
    if ids:
        entry["explicit_ids"] = ids
    return entry


#: Config ``type`` -> builder(config dict, env) -> Source. Secret fields are
#: ``${VAR}`` placeholders resolved by config.load_config at load time. The
#: catalogue (``catalogue.py``) owns every other fact about a kind -- summary,
#: keys, example and docs anchor -- and is re-exported here for callers that
#: already import this module.
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
    "SOURCE_SPECS",
    "WebhookSource",
    "build_source",
    "webhook_item_from_payload",
]
