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

from .http import parse_json

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


class _TextExtractor(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


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
            continue
        identifier = node.get("id")
        match = GREADER_ID.match(identifier if isinstance(identifier, str) else "")
        link = _first_href(node.get("canonical")) or _first_href(node.get("alternate"))
        guid = str(int(match.group(1), 16)) if match else link
        title = _text(node.get("title"))
        if not guid or not title:
            continue
        summary = ""
        for field in ("summary", "content"):
            content = node.get(field)
            summary = _text(content.get("content")) if isinstance(content, dict) else ""
            if summary:
                break
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
                published if type(published) is int else None,
                _text(origin.get("title")),
                source_url.strip() if isinstance(source_url, str) else "",
            )
        )
    return FeedExport(tuple(items), bool(document.get("continuation")) or len(entries) >= FEED_ITEMS)


def fetch_feed(http: Http, base_url: str, token: str) -> FeedExport:
    query = urllib.parse.urlencode({"user": "admin", "t": token, "f": "greader", "nb": FEED_ITEMS})
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


def _text_of(node: ET.Element | None) -> str:
    return clean_text("".join(node.itertext())) if node is not None else ""


def _published_of(node: ET.Element | None) -> int | None:
    if node is None:
        return None
    raw = (node.text or "").strip()
    if not raw:
        return None
    try:
        return int(parsedate_to_datetime(raw).timestamp())
    except (TypeError, ValueError, OverflowError):
        try:
            return int(datetime.datetime.fromisoformat(raw).timestamp())
        except ValueError:
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
                continue
            summary = _text_of(node.find("description"))
            items.append(
                FeedEntry(guid, title, link, summary, _published_of(node.find("pubDate")), channel_title, channel_link)
            )
    elif root.tag == f"{_ATOM}feed":
        channel_title = _text_of(root.find(f"{_ATOM}title"))
        link_node = root.find(f"{_ATOM}link")
        channel_link = link_node.get("href", "") if link_node is not None else ""
        for node in root.findall(f"{_ATOM}entry"):
            link = ""
            for candidate in node.findall(f"{_ATOM}link"):
                if candidate.get("rel") in (None, "alternate") and candidate.get("href"):
                    link = candidate.get("href", "")
                    break
            guid = _text_of(node.find(f"{_ATOM}id")) or link
            title = _text_of(node.find(f"{_ATOM}title"))
            if not guid or not title:
                continue
            summary = _text_of(node.find(f"{_ATOM}summary")) or _text_of(node.find(f"{_ATOM}content"))
            published = _published_of(node.find(f"{_ATOM}published")) or _published_of(node.find(f"{_ATOM}updated"))
            items.append(FeedEntry(guid, title, link, summary, published, channel_title, channel_link))
    else:
        raise RssError("feed is neither RSS nor Atom")
    return FeedExport(tuple(items), False)


def fetch_rss(http: Http, url: str) -> FeedExport:
    status, _, body = http(
        "GET", url, {"Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml"}, None
    )
    if status != 200:
        raise RssError(f"feed answered HTTP {status}" if status else "feed is unreachable")
    return parse_rss(body)
