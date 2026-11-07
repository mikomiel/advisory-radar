"""Feed readers: the GReader (FreshRSS) JSON export and generic RSS/Atom XML."""

from __future__ import annotations

import datetime
import html.parser
import re
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from email.utils import parsedate_to_datetime

from .http import header, parse_json

Http = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, dict[str, str], bytes]]
FEED_ITEMS = 100
GREADER_ID = re.compile(r"^tag:google\.com,2005:reader/item/([0-9a-fA-F]+)$")


class FeedError(Exception):
    pass


@dataclass(frozen=True)
class FeedEntry:
    guid: str
    title: str
    link: str
    summary: str
    published: int | None
    source_title: str
    source_url: str


@dataclass(frozen=True)
class FeedExport:
    items: tuple[FeedEntry, ...]
    truncated: bool


#: Tags that end a run of text. Joining their neighbours without a space would merge words and hide a
#: watchlist product alias ("libfoo" + "fixed" -> "libfoofixed").
_BLOCK_TAGS = frozenset(
    {
        "p",
        "div",
        "br",
        "li",
        "ul",
        "ol",
        "tr",
        "td",
        "th",
        "table",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "section",
        "article",
        "header",
        "footer",
        "blockquote",
        "pre",
        "hr",
    }
)


class _TextExtractor(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in _BLOCK_TAGS:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in _BLOCK_TAGS:
            self.parts.append(" ")


def clean_text(value: str) -> str:
    extractor = _TextExtractor()
    extractor.feed(value)
    extractor.close()
    return " ".join("".join(extractor.parts).split())


def _text(value: object) -> str:
    return clean_text(value) if isinstance(value, str) else ""


def _first_href(links: object) -> str:
    for entry in links if isinstance(links, list) else []:
        href = entry.get("href") if isinstance(entry, dict) else None
        if isinstance(href, str) and href.strip():
            return href.strip()
    return ""


def parse_feed(body: bytes) -> FeedExport:
    document = parse_json(body)
    if not isinstance(document, dict):
        raise FeedError("feed is not a JSON object")
    entries = document.get("items")
    if not isinstance(entries, list):
        raise FeedError("feed has no items list")
    items = []
    for node in entries:
        if not isinstance(node, dict):
            raise FeedError("feed entry is not an object")
        identifier = node.get("id")
        match = GREADER_ID.match(identifier if isinstance(identifier, str) else "")
        link = _first_href(node.get("canonical")) or _first_href(node.get("alternate"))
        guid = str(int(match.group(1), 16)) if match else link
        title = _text(node.get("title"))
        if not guid or not title:
            raise FeedError("feed entry has no usable id or title")
        # Both fields are read: a short summary and a full content block are commonly both present, and the
        # identifiers or product name often live only in the longer one.
        summary = " ".join(
            text
            for text in (
                _text(node.get(field).get("content")) if isinstance(node.get(field), dict) else ""
                for field in ("summary", "content")
            )
            if text
        )
        published = node.get("published")
        origin = node.get("origin")
        origin = origin if isinstance(origin, dict) else {}
        source_url = origin.get("htmlUrl")
        # origin.feedUrl is a private transform/query URL, never input to a caller.
        items.append(
            FeedEntry(
                guid,
                title,
                link,
                summary,
                published if type(published) is int and _plausible(published) else None,
                _text(origin.get("title")),
                source_url.strip() if isinstance(source_url, str) else "",
            )
        )
    return FeedExport(tuple(items), bool(document.get("continuation")) or len(entries) >= FEED_ITEMS)


def fetch_feed(http: Http, base_url: str, token: str, user: str = "admin") -> FeedExport:
    """A FreshRSS shared query is owned by one account, so the user is part of the request."""
    query = urllib.parse.urlencode({"user": user, "t": token, "f": "greader", "nb": FEED_ITEMS})
    url = f"{base_url.rstrip('/')}/api/query.php?{query}"
    status, _, body = http("GET", url, {"Accept": "application/json"}, None)
    if status != 200:
        raise FeedError(f"FreshRSS answered HTTP {status}" if status else "FreshRSS is unreachable")
    return parse_feed(body)


# --------------------------------------------------------------------------
# Generic RSS 2.0 / Atom feeds


class RssError(Exception):
    pass


_ATOM = "{http://www.w3.org/2005/Atom}"
_RSS = "{http://purl.org/rss/1.0/}"


#: XHTML elements that end a run of text. Inline elements (``<span>``, ``<b>``, ``<a>``) must stay adjacent,
#: or "CVE-<span>2026</span>-1234" and "lib<span>foo</span>" would be split.
_XHTML_BLOCKS = frozenset(
    {
        "p",
        "div",
        "br",
        "li",
        "ul",
        "ol",
        "tr",
        "td",
        "th",
        "table",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "section",
        "article",
        "header",
        "footer",
        "blockquote",
        "pre",
        "hr",
    }
)


def _text_of(node: ET.Element | None) -> str:
    if node is None:
        return ""
    parts: list[str] = []

    def walk(element: ET.Element) -> None:
        tag = element.tag.rsplit("}", 1)[-1] if isinstance(element.tag, str) else ""
        block = tag in _XHTML_BLOCKS
        if block:
            parts.append(" ")
        if element.text:
            parts.append(element.text)
        for child in list(element):
            walk(child)
            if child.tail:
                parts.append(child.tail)
        if block:
            parts.append(" ")

    walk(node)
    return clean_text("".join(parts))


#: A feed date outside this window is treated as absent: a stray huge integer must not survive to
#: rendering, where ``datetime.fromtimestamp`` would raise.
EARLIEST_EPOCH = 631152000  # 1990-01-01
LATEST_EPOCH = 4102444800  # 2100-01-01


def _plausible(epoch: int) -> bool:
    return EARLIEST_EPOCH <= epoch <= LATEST_EPOCH


def _published_of(node: ET.Element | None) -> int | None:
    if node is None:
        return None
    raw = (node.text or "").strip()
    if not raw:
        return None
    for parse in (parsedate_to_datetime, datetime.datetime.fromisoformat):
        try:
            epoch = int(parse(raw).timestamp())
        except (TypeError, ValueError, OverflowError):
            continue
        return epoch if _plausible(epoch) else None  # a year-10000 date must not reach the renderer
    return None


def parse_rss(body: bytes) -> FeedExport:
    """RSS 2.0 and Atom feeds; the whole feed is read, so the window is never truncated."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise RssError(f"feed is not XML: {exc}") from exc
    items: list[FeedEntry] = []
    channel_title = ""
    channel_link = ""
    entries: list[ET.Element] = []
    if root.tag == "rss" or root.tag.endswith("}rss"):
        channel = root.find("channel")
        if channel is None:
            raise RssError("RSS has no channel")
        channel_title = _text_of(channel.find("title"))
        channel_link = _text_of(channel.find("link"))
        entries = list(channel.findall("item"))
        for node in entries:
            link = _text_of(node.find("link"))
            guid = _text_of(node.find("guid")) or link
            title = _text_of(node.find("title"))
            if not guid or not title:
                raise RssError("feed entry has no usable id or title")
            summary = " ".join(
                text
                for text in (
                    _text_of(node.find("description")),
                    _text_of(node.find("{http://purl.org/rss/1.0/modules/content/}encoded")),
                )
                if text
            )
            items.append(
                FeedEntry(guid, title, link, summary, _published_of(node.find("pubDate")), channel_title, channel_link)
            )
    elif root.tag == f"{_ATOM}feed":
        channel_title = _text_of(root.find(f"{_ATOM}title"))
        # Only an alternate link is a public site. A rel="self" link is the subscription URL and can carry a
        # feed credential, which must never reach a notification.
        channel_link = ""
        for candidate in root.findall(f"{_ATOM}link"):
            if candidate.get("rel") in (None, "alternate") and candidate.get("href"):
                channel_link = candidate.get("href", "")
                break
        for node in root.findall(f"{_ATOM}entry"):
            link = ""
            for candidate in node.findall(f"{_ATOM}link"):
                if candidate.get("rel") in (None, "alternate") and candidate.get("href"):
                    link = candidate.get("href", "")
                    break
            guid = _text_of(node.find(f"{_ATOM}id")) or link
            title = _text_of(node.find(f"{_ATOM}title"))
            if not guid or not title:
                raise RssError("feed entry has no usable id or title")
            summary = " ".join(
                text
                for text in (_text_of(node.find(f"{_ATOM}summary")), _text_of(node.find(f"{_ATOM}content")))
                if text
            )
            published = _published_of(node.find(f"{_ATOM}published")) or _published_of(node.find(f"{_ATOM}updated"))
            items.append(FeedEntry(guid, title, link, summary, published, channel_title, channel_link))
    else:
        raise RssError("feed is neither RSS nor Atom")
    return FeedExport(tuple(items), False)


def fetch_rss(http: Http, url: str, validators: Mapping[str, str] | None = None) -> tuple[FeedExport, dict[str, str]]:
    """One RSS/Atom GET, plus the caching validators to keep for the next one.

    A ``304 Not Modified`` is an empty export, not an error: the publisher says nothing changed, so no cursor
    moves and no window gap is implied. Sending ``If-None-Match``/``If-Modified-Since`` turns most polls of an
    unchanged feed into that answer instead of the whole body, which is the difference between a poll every 15
    minutes and one a publisher is happy to serve.
    """
    headers = {"Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml"}
    if validators:
        headers.update(validators)
    status, response_headers, body = http("GET", url, headers, None)
    if status == 304:
        return FeedExport((), False), None
    if status != 200:
        raise RssError(f"feed answered HTTP {status}" if status else "feed is unreachable")
    stored: dict[str, str] = {}
    etag = header(response_headers, "ETag")
    if etag:
        stored["etag"] = etag
    modified = header(response_headers, "Last-Modified")
    if modified:
        stored["last_modified"] = modified
    return parse_rss(body), stored
