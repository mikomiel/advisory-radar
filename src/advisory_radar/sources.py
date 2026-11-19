"""Built-in source plugins: generic RSS/Atom, the FreshRSS GReader export, changedetection.io, webhooks and CSAF."""

from __future__ import annotations

import hashlib
import time
import urllib.parse
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from . import csaf, feeds, messages
from .catalogue import SOURCE_SPECS
from .core import Item, _host, dsa_id, extract_ids, stored_text_keys
from .http import Http, json_text, parse_json
from .plugins import Source, SourceWindow


def _english(key: str, **fields: str) -> str:
    """The catalogue words of ``key`` in English, which is how an item holds the words the service wrote.

    ``title`` and ``summary`` are read for matching and shown in the web UI, so they hold one language. The item
    (or the stored inbox entry) also names the key, and the notification is written from that in the configured
    language: see ``core.item_headline``.
    """
    return messages.text(messages.DEFAULT_LANGUAGE, key, **fields)


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
            fields = {"changed": str(changed)}
            summary = _english("item.summary.page_changed", **fields)
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
                    summary_key="item.summary.page_changed",
                    text_fields=tuple(fields.items()),
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


def _csaf_directory(url: object) -> str:
    """The provider directory URL with a trailing slash, or ``ValueError`` naming what is wrong with it.

    Every document is requested as this URL plus a path from ``changes.csv`` and is shown to the reader as the
    provenance of an alert, so a URL that carries a credential of its own (user information, a query, a fragment)
    is refused here rather than printed later. A message never repeats the URL: a rejected one may be a credential.
    """
    if not isinstance(url, str) or not url.isascii() or any(char.isspace() or not char.isprintable() for char in url):
        raise ValueError("csaf source: url must be a plain ASCII web address")
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise ValueError("csaf source: url is not a valid web address") from None
    if parts.scheme not in ("http", "https") or not host:
        raise ValueError("csaf source: url must be an http or https address with a host")
    if "@" in parts.netloc:
        raise ValueError("csaf source: url must not carry a user name or password")
    if "?" in url or "#" in url:
        raise ValueError("csaf source: url must not carry a query or a fragment")
    return url if url.endswith("/") else url + "/"


@dataclass(frozen=True)
class _Cursor:
    """How far a directory's ``changes.csv`` has been read: an instant, and the rows read at that very instant.

    The index has a resolution of one second and a provider can list a score of documents within one, so the
    instant alone cannot say whether a row dated exactly at the cursor was read. The paths read at that second
    travel with it: a row is unread when it is newer than the instant, or at it and not among them. That is also
    what reads a row that is listed late inside a second already read, which a bare instant would skip for good.
    """

    release: int
    at: frozenset[str]

    def is_new(self, row: csaf.Row) -> bool:
        return row.release > self.release or (row.release == self.release and row.path not in self.at)

    def advance(self, passed: Sequence[csaf.Row]) -> _Cursor:
        """The cursor after ``passed``: the first unread rows in index order, so the newest of them is the last."""
        if not passed:
            return self
        release = max(self.release, passed[-1].release)
        kept = self.at if release == self.release else frozenset()
        return _Cursor(release, kept | {row.path for row in passed if row.release == release})


def _shaped(value: object, **kinds: type) -> bool:
    """Whether ``value`` is a dict holding every named key as the named type (a bool is never an int)."""
    return isinstance(value, dict) and all(
        isinstance(value.get(key), kind) and not (kind is int and isinstance(value.get(key), bool))
        for key, kind in kinds.items()
    )


@dataclass(frozen=True)
class _Stored:
    """What ``state["csaf"][id]`` holds that is still valid for this source: every field is checked, none trusted."""

    cursor: _Cursor | None = None
    #: The one document being retried: its path, the release of the revision, and how many reads of it failed.
    retry: tuple[str, int, int] | None = None
    #: Documents given up on, by path: ``{"release": int, "since": int, "reason": str}``.
    given_up: dict[str, dict] = field(default_factory=dict)


class CsafSource:
    """A vendor's CSAF 2.0 provider directory, read through its ``changes.csv``: one item per new or revised advisory.

    The index says which documents changed and when; the source reads the ones its cursor has not passed, oldest
    first, at most ``csaf.MAX_DOCUMENTS`` and for at most ``csaf.PASS_SECONDS`` a pass (the first document is always
    read), validates each against the CSAF 2.0 schema (``csaf.parse_document``) and turns what the vendor states into
    an item. The item says whose words they are and that they are not a check of anything the reader runs: this
    source compares no version, and a ``known_not_affected`` statement can neither raise an alert nor take the
    identity of one that another source raises (``csaf.concerned_cves``).

    A failure is never an empty window, and neither is falling behind. An index that cannot be read raises, so the
    pass records the source as failed and keeps its cursor. A document that cannot be read or validated stops the
    pass at that document for ``csaf.MAX_ATTEMPTS`` reads, so a transient fault does not skip it; then it is given
    up, the pass goes on past it, and the window reports it in ``problems`` until a newer revision of it replaces
    the report or ``csaf.PROBLEM_RETENTION`` ends. Documents read before the failure are delivered in the same
    window. Rows the pass did not reach are read next time, and once the oldest of them was listed more than
    ``csaf.LAG_LIMIT`` ago the window says so in ``problems`` too, which turns the source red and keeps it red
    until it has caught up.

    State, under ``state["csaf"][id]``: the cursor, the one document being retried, and the documents given up on,
    all written by ``commit`` and keyed by a digest of the directory URL (which is configuration and may be private).
    """

    kind = "csaf"

    def __init__(
        self,
        source_id: str,
        url: str,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.id = source_id
        self.base = _csaf_directory(url)
        self._digest = _url_digest(self.base)
        self._clock = clock
        self._monotonic = monotonic
        #: The record ``commit`` stores. Set by a successful ``fetch`` and cleared by every one, so a fetch that
        #: raises cannot leave an earlier window's record behind for the pipeline's next ``commit`` to store.
        self._pending: dict | None = None

    def fetch(self, http: Http, state: dict) -> SourceWindow:
        self._pending = None
        started = self._monotonic()
        now = int(self._clock())
        rows = self._index(http, now)
        stored = self._stored(state, now)
        cursor = stored.cursor
        if cursor is None:
            # A new source starts from the newest documents: the older ones are history, and a directory lists
            # tens of thousands of them. Rows before the newest few are passed without being read.
            cursor = _Cursor(0, frozenset()).advance(rows[: max(0, len(rows) - csaf.START_DOCUMENTS)])
        given_up = dict(stored.given_up)
        items: list[Item] = []
        passed: list[csaf.Row] = []
        retry: dict | None = None
        retrying = ""
        unread = [row for row in rows if cursor.is_new(row)]
        for number, row in enumerate(unread[: csaf.MAX_DOCUMENTS]):
            if number and self._monotonic() - started >= csaf.PASS_SECONDS:
                break  # out of time: the rest is read next pass, and the first document of a pass is always read
            given_up.pop(row.path, None)  # a newer revision replaces what was reported about the older one
            try:
                document = self._document(http, row)
            except csaf.CsafError as exc:
                same = stored.retry is not None and stored.retry[:2] == (row.path, row.release)
                attempt = stored.retry[2] + 1 if same and stored.retry else 1
                if attempt < csaf.MAX_ATTEMPTS:
                    # Stop here and read this document again next pass: going on would move the cursor past it.
                    retry = {"path": row.path, "release": row.release, "n": attempt}
                    retrying = f"{row.path}: {exc} (attempt {attempt} of {csaf.MAX_ATTEMPTS})"
                    break
                given_up[row.path] = {"release": row.release, "since": now, "reason": str(exc)}
                passed.append(row)
                continue
            passed.append(row)
            item = _csaf_item(document, self.base + row.path)
            if item is not None:
                items.append(item)
        cursor = cursor.advance(passed)
        newest = sorted(given_up.items(), key=lambda entry: (-entry[1]["release"], entry[0]))
        record: dict = {"dir": self._digest, "release": cursor.release, "at": sorted(cursor.at)}
        if retry is not None:
            record["retry"] = retry
        if newest:
            record["given_up"] = dict(newest[: csaf.MAX_KEPT_PROBLEMS])
        self._pending = record
        # What this pass did not reach, oldest first. A source is behind when the oldest of it has waited too long.
        waiting = unread[len(passed) :]
        problems = []
        if waiting and now - waiting[0].release > csaf.LAG_LIMIT:
            age = _ago(now - waiting[0].release)
            problems.append(f"behind: {len(waiting)} listed document(s) not read yet, the oldest listed {age} ago")
        if retrying:
            problems.append(retrying)
        problems += [
            f"{path}: {entry['reason']} (given up after {csaf.MAX_ATTEMPTS} attempt(s))"
            for path, entry in newest[: csaf.MAX_LISTED_PROBLEMS]
        ]
        if len(newest) > csaf.MAX_LISTED_PROBLEMS:
            problems.append(f"{len(newest) - csaf.MAX_LISTED_PROBLEMS} more document(s) given up")
        return SourceWindow(self.id, tuple(items), False, _host(self.base), tuple(problems))

    def commit(self, state: dict) -> None:
        """Store the cursor and the failure record once the pipeline has captured this window's candidates.

        The same rule the other cursors follow: moving the cursor before the items are durable would pass
        advisories that were never queued, and they would never be read again.
        """
        record, self._pending = self._pending, None
        if record is None:
            return  # the fetch failed: the stored cursor stays where it was
        group = state.get("csaf")
        if not isinstance(group, dict):
            group = state["csaf"] = {}
        group[self.id] = record

    def _index(self, http: Http, now: int) -> tuple[csaf.Row, ...]:
        status, _, raw = http("GET", self.base + "changes.csv", {"Accept": "text/csv, */*;q=0.1"}, None)
        if status != 200:
            raise csaf.CsafError("changes.csv: unreachable" if status == 0 else f"changes.csv: HTTP {status}")
        return csaf.parse_index(raw, now)

    def _document(self, http: Http, row: csaf.Row) -> csaf.Document:
        status, _, raw = http("GET", self.base + row.path, {"Accept": "application/json"}, None)
        if status != 200:
            raise csaf.CsafError("unreachable" if status == 0 else f"HTTP {status}")
        return csaf.parse_document(raw)

    def _stored(self, state: dict, now: int) -> _Stored:
        """The stored record for this source and directory, field by field; anything damaged counts as absent.

        A record that names another directory is dropped whole: its cursor describes another index. A cursor dated
        beyond the clock (a damaged file, or a clock that was wrong) would hide every later row, so it is dropped
        too and the source starts over from the newest documents.
        """
        group = state.get("csaf")
        record = group.get(self.id) if isinstance(group, dict) else None
        if not (_shaped(record, dir=str) and record["dir"] == self._digest):
            return _Stored()
        cursor = None
        release, at = record.get("release"), record.get("at")
        if isinstance(release, int) and not isinstance(release, bool) and 0 <= release <= now + csaf.FUTURE_SLACK:
            paths = frozenset(path for path in at if isinstance(path, str)) if isinstance(at, list) else frozenset()
            cursor = _Cursor(release, paths)
        retry = record.get("retry")
        retrying = (
            (retry["path"], retry["release"], retry["n"]) if _shaped(retry, path=str, release=int, n=int) else None
        )
        given_up: dict[str, dict] = {}
        stored = record.get("given_up")
        for path, entry in (stored if isinstance(stored, dict) else {}).items():
            if not (isinstance(path, str) and len(path) <= csaf.MAX_PATH_CHARS):
                continue
            if (
                _shaped(entry, release=int, since=int, reason=str)
                and -csaf.FUTURE_SLACK < now - entry["since"] < csaf.PROBLEM_RETENTION
            ):
                given_up[path] = {"release": entry["release"], "since": entry["since"], "reason": entry["reason"][:300]}
        return _Stored(cursor, retrying, given_up)


def _ago(seconds: int) -> str:
    """A span as one number an operator reads at a glance: hours up to two days, then days."""
    hours = seconds // 3600
    return f"{hours} h" if hours < 48 else f"{hours // 24} d"


def _csaf_item(document: csaf.Document, url: str) -> Item | None:
    """The item for a document that makes a statement other than "not affected", else None.

    The guid is the document's identity and the digest of its statements, so a revision that says something else
    is a new item and a file that is rewritten to say the same is never one twice. The vendor's version number
    cannot be the revision here: the first provider writes the same one into every document it has. ``explicit``
    claims only the vulnerabilities the document concerns: the alert pipeline dedupes by claimed identifier across
    sources, so a claim made on a not-affected vulnerability would silently drop another source's alert for it. The
    item is dated by when the vendor last changed the document, so an old advisory that is written again is history
    and not news. The words are the service's, in the catalogue (``item.summary.csaf``), and the statements in them
    are the vendor's.
    """
    cves = csaf.concerned_cves(document)
    if not cves:
        return None
    fields = {"version": document.version, "id": document.id, "statements": csaf.statements_text(document)}
    return Item(
        f"{document.id}@{document.revision}",
        document.title,
        document.url or url,
        _english("item.summary.csaf", **fields),
        document.release,
        cves,
        document.publisher,
        url,
        summary_key="item.summary.csaf",
        text_fields=tuple(fields.items()),
    )


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
                **stored_text_keys(entry),
            )
            for entry in inbox
            if isinstance(entry, dict)
        )
        return SourceWindow(self.id, items, False, "")


class WebhookPayloadRefused(ValueError):
    """A webhook payload the intake contract refuses.

    The intake answers one with a fixed 400 and never with exception text. The class carries the reason, not
    an interpolated value, so a response cannot leak what a future caller puts into a message.
    """

    message = "payload is not acceptable"

    def __init__(self) -> None:
        super().__init__(self.message)


class WebhookIdsUnsupported(WebhookPayloadRefused):
    """``ids`` is not a list of the identifiers the text extractor understands."""

    message = "ids must be a list of CVE, GHSA or PSA identifier strings"


class WebhookTextNotEncodable(WebhookPayloadRefused):
    """A text field is not UTF-8 representable, so it cannot be hashed or stored as JSON text."""

    message = "payload text is not valid Unicode"


def webhook_item_from_payload(payload: object) -> dict | None:
    """Map a generic or changedetection.io-native webhook JSON body to an inbox entry.

    ``WebhookPayloadRefused`` (a ``ValueError``) is the refused-payload signal the intake turns into a 400: an
    ``ids`` value must be a list of identifiers the text extractor understands, and a text field must be UTF-8
    representable because it is hashed to derive a default guid. A lone surrogate is valid JSON but not a
    Unicode scalar value, so encoding it would raise after the request was accepted.
    """

    def checked(value: object) -> str:
        text = str(value)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            raise WebhookTextNotEncodable() from None
        return text

    def declared_ids(value: object) -> tuple[str, ...]:
        """The supported structured ids, normalised and deduplicated; anything else is refused."""
        if value is None:
            return ()
        if not isinstance(value, list):
            raise WebhookIdsUnsupported()
        found: dict[str, None] = {}
        for item in value:
            if not isinstance(item, str):
                raise WebhookIdsUnsupported()
            text = item.strip()
            extracted = extract_ids(text)
            if len(extracted) != 1 or extracted[0].casefold() != text.casefold():
                raise WebhookIdsUnsupported()
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
        _ = checked(payload.get("watch_uuid"))  # validated before main's fingerprint line hashes it
        watch_url = checked(payload.get("watch_url") or "")
        named = payload.get("watch_title") or payload.get("watch_url")
        title = checked(named or _english("item.title.change"))
        summary = diff or _english("item.summary.no_diff")
        ids = merged(title, summary, watch_url, payload.get("ids"))
        # Words the service wrote (no title or URL, no diff) carry their catalogue key, so the notification can
        # write them in the configured language; the sender's own words carry none and are never translated.
        written = {
            **({} if named else {"title_key": "item.title.change"}),
            **({} if diff else {"summary_key": "item.summary.no_diff"}),
        }
        # This line is deliberately unchanged from main: the PR adds no new hash use, and the validation above
        # proves the value is encodable before it is hashed. An untouched line is what lets code scanning
        # attribute the pre-existing weak-hash alert to main rather than to this change.
        guid = "wh:cd:" + hashlib.sha1((str(payload.get("watch_uuid")) + diff).encode()).hexdigest()[:16]
        return {
            "guid": guid,
            "title": title,
            "link": watch_url,
            "summary": summary,
            "source_title": "changedetection.io",
            "source_url": watch_url,
            **written,
            **({"explicit_ids": ids} if ids else {}),
        }
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
    "csaf": lambda cfg, env: CsafSource(cfg["id"], cfg["url"]),
}


def build_source(cfg: dict, env: dict[str, str]) -> Source:
    kind = cfg.get("type")
    builder = SOURCE_BUILDERS.get(kind or "")
    if builder is None:
        raise ValueError(f"unknown source type (id {cfg.get('id')!r}); built-ins: {sorted(SOURCE_BUILDERS)}")
    return builder(cfg, env)


__all__ = [
    "ChangedetectionSource",
    "CsafSource",
    "FreshRssSource",
    "RssSource",
    "SOURCE_BUILDERS",
    "SOURCE_SPECS",
    "WebhookIdsUnsupported",
    "WebhookPayloadRefused",
    "WebhookSource",
    "WebhookTextNotEncodable",
    "build_source",
    "webhook_item_from_payload",
]
