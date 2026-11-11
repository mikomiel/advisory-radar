"""Feed readers for every shape this program reads, and the sniffing that chooses one.

Every reader returns the frozen ``FeedExport``/``FeedEntry`` contract, so a new format adds a parser and a
dispatch branch, never a new field. An empty export is a claim that the publisher said nothing changed, so a
document this module cannot read raises instead: a silent empty export would mark an unread source healthy.
"""

from __future__ import annotations

import datetime
import html.parser
import re
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from email.utils import parsedate_to_datetime

from .http import header, parse_json, private_destination

Http = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, dict[str, str], bytes]]
FEED_ITEMS = 100
GREADER_ID = re.compile(r"^tag:google\.com,2005:reader/item/([0-9a-fA-F]+)$")
#: A JSON Feed names itself in ``version`` (``https://jsonfeed.org/version/1.1``); no other JSON export does.
JSON_FEED_VERSION = "jsonfeed.org"
#: A title derived from an untitled item's content is cut here: a notification title is a headline, not the
#: first paragraph of the advisory.
DERIVED_TITLE_CHARS = 200


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


def _encodable(value: str) -> str:
    """``value`` with characters UTF-8 cannot encode replaced, so a response can always render it.

    A JSON string may carry an escaped unpaired surrogate: ``json.loads`` accepts it, but ``str.encode`` and
    the web response encoder refuse it, which would turn one bad item into a 500 page. Feed text is
    untrusted, so it is made encodable when it leaves the reader, not at each response.
    """
    return value.encode("utf-8", "replace").decode("utf-8")


def clean_text(value: str) -> str:
    extractor = _TextExtractor()
    extractor.feed(value)
    extractor.close()
    return _encodable(" ".join("".join(extractor.parts).split()))


def _text(value: object) -> str:
    return clean_text(value) if isinstance(value, str) else ""


def _plain(value: object) -> str:
    """Whitespace-normalised plain text, without HTML parsing.

    ``content_text`` is already text, so running it through the HTML parser would eat a legitimate ``<`` --
    "fixed in <2.0" would lose the version, and with it the shard of evidence the source was added for.
    """
    return _encodable(" ".join(value.split())) if isinstance(value, str) else ""


def _string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


#: Characters a feed identity must never carry: C0 controls, DEL, and the Unicode line and paragraph
#: separators. A log record is one line, so a preserved newline in an identity lets a publisher write what
#: looks like a second application record; the same characters would also reach a state key and a metric label.
_IDENTITY_CONTROLS = re.compile("[\x00-\x1f\x7f\u2028\u2029]")


def normalise_identity(value: object) -> str:
    """A feed identity that is safe to log and store, or "" when nothing usable remains.

    Normalised at the boundary that owns the value -- the readers, and the state loader that may hold their
    older answers -- rather than at each log call, so every present and future caller of ``FeedEntry.guid``
    gets a single-line identity. A string that is not a Unicode scalar value (an escaped unpaired surrogate)
    is refused as empty too, because it cannot be written to a log or a response at all. The caller still
    decides whether an empty result is an error, because a JSON document and an XML feed refuse one with
    their own error type; the deduplication identity is the normalised string, so no other behaviour moves.
    """
    raw = value.strip() if isinstance(value, str) else ""
    try:
        raw.encode("utf-8")
    except UnicodeEncodeError:
        return ""
    return _IDENTITY_CONTROLS.sub("", raw).strip()


def _local(tag: object) -> str:
    """An ElementTree tag without its namespace, lowercased for HTML/OPML name comparisons."""
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _first_href(links: object) -> str:
    for entry in links if isinstance(links, list) else []:
        href = entry.get("href") if isinstance(entry, dict) else None
        if isinstance(href, str) and href.strip():
            return href.strip()
    return ""


#: A feed date outside this window is treated as absent: a stray huge integer must not survive to
#: rendering, where ``datetime.fromtimestamp`` would raise.
EARLIEST_EPOCH = 631152000  # 1990-01-01
LATEST_EPOCH = 4102444800  # 2100-01-01


def _plausible(epoch: int) -> bool:
    return EARLIEST_EPOCH <= epoch <= LATEST_EPOCH


def _epoch_of(value: object) -> int | None:
    """A date string as an epoch inside the plausibility window, or None.

    RFC 3339 and RFC 822 both occur in the wild across the formats this module reads, so both parsers are
    tried. A value the window rejects is returned as absent rather than as a year-10000 timestamp.
    """
    raw = value.strip() if isinstance(value, str) else ""
    if not raw:
        return None
    for parse in (parsedate_to_datetime, datetime.datetime.fromisoformat):
        try:
            epoch = int(parse(raw).timestamp())
        except (TypeError, ValueError, OverflowError):
            continue
        return epoch if _plausible(epoch) else None
    return None


def _is_json_feed(document: object) -> bool:
    if not isinstance(document, dict):
        return False
    version = document.get("version")
    return isinstance(version, str) and JSON_FEED_VERSION in version.lower()


def _is_greader_export(document: object) -> bool:
    """Whether a JSON object carries positive evidence of the GReader stream format.

    An ``items`` list alone is not evidence: any JSON API can have one, and reading ``{"items": []}`` as a
    healthy, unchanged GReader export would make a misconfigured endpoint look like a publisher with no news.
    The stream ``id`` is the marker an empty-but-real FreshRSS/Google Reader answer carries; otherwise at
    least one item must have the format's own item id.
    """
    if not isinstance(document, dict):
        return False
    stream = document.get("id")
    if isinstance(stream, str) and stream.startswith(("user/", "feed/")):
        return True
    entries = document.get("items")
    return isinstance(entries, list) and any(
        isinstance(node, dict) and isinstance(node.get("id"), str) and GREADER_ID.match(node["id"]) is not None
        for node in entries
    )


def _first_line(value: object, *, html_text: bool) -> str:
    """The first non-empty line of one item field, without HTML parsing plain text.

    Only ``content_html`` is treated as markup: ``content_text`` may legitimately contain ``<``, and the HTML
    parser would drop the version that follows it.
    """
    if not isinstance(value, str):
        return ""
    for line in value.splitlines():
        line = _text(line) if html_text else _plain(line)
        if line:
            return line
    return ""


def _derived_title(node: Mapping[str, object]) -> str:
    """A usable title for a JSON Feed item that has none, from its content or summary, capped.

    ``title`` is optional in JSON Feed 1.0/1.1, so one untitled item must not make every advisory in the
    document unreadable. The caller falls back to the item id when even the content is empty.
    """
    for field, html_text in (("content_text", False), ("content_html", True), ("summary", False)):
        line = _first_line(node.get(field), html_text=html_text)[:DERIVED_TITLE_CHARS].strip()
        if line:
            return line
    return ""


def parse_feed(body: bytes) -> FeedExport:
    """The FreshRSS GReader JSON export."""
    return _greader_export(parse_json(body))


def _greader_export(document: object) -> FeedExport:
    if not isinstance(document, dict):
        raise FeedError("feed is not a JSON object")
    if _is_json_feed(document):
        # The two JSON shapes share an ``items`` list. Reading a JSON Feed here would find no GReader id and
        # call a healthy feed broken, so the version is checked before the items are touched.
        raise FeedError("feed is JSON Feed, not a GReader export")
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
        guid = normalise_identity(str(int(match.group(1), 16)) if match else link)
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
                _encodable(link),
                summary,
                published if type(published) is int and _plausible(published) else None,
                _text(origin.get("title")),
                _encodable(source_url.strip()) if isinstance(source_url, str) else "",
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
# JSON Feed 1.0 / 1.1


def parse_json_feed(body: bytes) -> FeedExport:
    """JSON Feed 1.0 and 1.1, which is JSON but not the GReader export.

    ``items`` is required by the specification but may legitimately be empty: a feed publishing nothing yet
    is not the same as a document that cannot be read, and the latter raises. There is no continuation
    token in this format, so the whole feed is always read and ``truncated`` is always false.
    """
    return _json_feed_export(parse_json(body))


def _json_feed_export(document: object) -> FeedExport:
    if not isinstance(document, dict):
        raise FeedError("feed is not a JSON object")
    if not _is_json_feed(document):
        raise FeedError("feed is not JSON Feed")
    entries = document.get("items")
    if not isinstance(entries, list):
        raise FeedError("feed has no items list")
    feed_title = _text(document.get("title"))
    feed_link = _encodable(_string(document.get("home_page_url")))
    items = []
    for node in entries:
        if not isinstance(node, dict):
            raise FeedError("feed entry is not an object")
        # ``url`` is the item's public page; ``external_url`` is used when the item has no page on this
        # site, and either is a better link than none. The id is the stable identity and wins outright.
        link = _string(node.get("url")) or _string(node.get("external_url"))
        guid = normalise_identity(node.get("id")) or normalise_identity(link)
        if not guid:
            raise FeedError("feed entry has no usable id")
        title = _text(node.get("title"))
        if not title:
            # ``title`` is optional in JSON Feed 1.0/1.1, so one untitled item must not make the whole
            # document unreadable; the content's first line, then the item id, stand in for it.
            title = _derived_title(node) or guid[:DERIVED_TITLE_CHARS]
        # Both content fields are read, because some publishers put the advisory identifier in only one.
        # An exact duplicate is kept once: JSON Feed requires the two renderings to say the same thing, so
        # joining both unconditionally would repeat every advisory in the evidence and in the notification.
        summary = " ".join(
            dict.fromkeys(part for part in (_plain(node.get("content_text")), _text(node.get("content_html"))) if part)
        )
        if not summary:
            # The item ``summary`` is a rendering of the content, so it is only a fallback; JSON Feed
            # without either content field is technically invalid but does occur.
            summary = _plain(node.get("summary"))
        published = _epoch_of(node.get("date_published")) or _epoch_of(node.get("date_modified"))
        items.append(FeedEntry(guid, title, _encodable(link), summary, published, feed_title, feed_link))
    return FeedExport(tuple(items), False)


# --------------------------------------------------------------------------
# Generic RSS 2.0 / Atom / RSS 1.0 (RDF) feeds


class RssError(Exception):
    pass


_ATOM = "{http://www.w3.org/2005/Atom}"
_RSS = "{http://purl.org/rss/1.0/}"
_RDF = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}"
_DC = "{http://purl.org/dc/elements/1.1/}"
_CONTENT = "{http://purl.org/rss/1.0/modules/content/}"


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


def _published_of(node: ET.Element | None) -> int | None:
    return _epoch_of(node.text) if node is not None else None


def parse_rss(body: bytes) -> FeedExport:
    """RSS 2.0, Atom and RSS 1.0 (RDF) feeds; the whole feed is read, so the window is never truncated.

    The three shapes share a vocabulary but not a structure. RSS 1.0 in particular is not RSS 2.0 under
    another name: its ``item`` elements are siblings of the ``channel`` under an RDF root, and its dates
    come from Dublin Core. Reading such a document with the RSS 2.0 rules finds no items at all, which
    would look exactly like a feed whose publisher said nothing changed.
    """
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise RssError(f"feed is not XML: {exc}") from exc
    if root.tag == "rss" or root.tag.endswith("}rss"):
        return _rss_2_export(root)
    if root.tag == f"{_ATOM}feed":
        return _atom_export(root)
    if root.tag == f"{_RDF}RDF":
        return _rdf_export(root)
    raise RssError("feed is neither RSS, Atom nor RDF")


def _rss_2_export(root: ET.Element) -> FeedExport:
    channel = root.find("channel")
    if channel is None:
        raise RssError("RSS has no channel")
    channel_title = _text_of(channel.find("title"))
    channel_link = _text_of(channel.find("link"))
    items = []
    for node in channel.findall("item"):
        link = _text_of(node.find("link"))
        guid = normalise_identity(_text_of(node.find("guid"))) or normalise_identity(link)
        title = _text_of(node.find("title"))
        if not guid or not title:
            raise RssError("feed entry has no usable id or title")
        summary = " ".join(
            text for text in (_text_of(node.find("description")), _text_of(node.find(_CONTENT + "encoded"))) if text
        )
        items.append(
            FeedEntry(guid, title, link, summary, _published_of(node.find("pubDate")), channel_title, channel_link)
        )
    return FeedExport(tuple(items), False)


def _atom_export(root: ET.Element) -> FeedExport:
    channel_title = _text_of(root.find(f"{_ATOM}title"))
    # Only an alternate link is a public site. A rel="self" link is the subscription URL and can carry a
    # feed credential, which must never reach a notification.
    channel_link = ""
    for candidate in root.findall(f"{_ATOM}link"):
        if candidate.get("rel") in (None, "alternate") and candidate.get("href"):
            channel_link = candidate.get("href", "")
            break
    items = []
    for node in root.findall(f"{_ATOM}entry"):
        link = ""
        for candidate in node.findall(f"{_ATOM}link"):
            if candidate.get("rel") in (None, "alternate") and candidate.get("href"):
                link = candidate.get("href", "")
                break
        guid = normalise_identity(_text_of(node.find(f"{_ATOM}id"))) or normalise_identity(link)
        title = _text_of(node.find(f"{_ATOM}title"))
        if not guid or not title:
            raise RssError("feed entry has no usable id or title")
        summary = " ".join(
            text for text in (_text_of(node.find(f"{_ATOM}summary")), _text_of(node.find(f"{_ATOM}content"))) if text
        )
        published = _published_of(node.find(f"{_ATOM}published")) or _published_of(node.find(f"{_ATOM}updated"))
        items.append(FeedEntry(guid, title, link, summary, published, channel_title, channel_link))
    return FeedExport(tuple(items), False)


def _rdf_export(root: ET.Element) -> FeedExport:
    """RSS 1.0: the channel and the items are siblings under the RDF root.

    An RDF root with a channel but no item is refused rather than read as an empty feed. The reader cannot
    tell it apart from a malformed document, and an empty export would tell the pipeline the source is
    healthy and unchanged on every poll.
    """
    channel = root.find(f"{_RSS}channel")
    if channel is None:
        raise RssError("RDF has no RSS 1.0 channel")
    channel_title = _text_of(channel.find(f"{_RSS}title"))
    channel_link = _text_of(channel.find(f"{_RSS}link"))
    entries = root.findall(f"{_RSS}item")
    if not entries:
        raise RssError("RDF feed has no items")
    items = []
    for node in entries:
        link = _text_of(node.find(f"{_RSS}link"))
        # rdf:about is the item's identity and survives a link change; the link is the fallback.
        guid = normalise_identity(node.get(f"{_RDF}about")) or normalise_identity(link)
        title = _text_of(node.find(f"{_RSS}title"))
        if not guid or not title:
            raise RssError("feed entry has no usable id or title")
        summary = " ".join(
            text
            for text in (_text_of(node.find(f"{_RSS}description")), _text_of(node.find(_CONTENT + "encoded")))
            if text
        )
        items.append(
            FeedEntry(guid, title, link, summary, _published_of(node.find(f"{_DC}date")), channel_title, channel_link)
        )
    return FeedExport(tuple(items), False)


def _validators_of(response_headers: Mapping[str, str]) -> dict[str, str]:
    """The caching validators to send on the next poll; an absent header is simply not stored."""
    stored: dict[str, str] = {}
    etag = header(response_headers, "ETag")
    if etag:
        stored["etag"] = etag
    modified = header(response_headers, "Last-Modified")
    if modified:
        stored["last_modified"] = modified
    return stored


def fetch_rss(
    http: Http, url: str, validators: Mapping[str, str] | None = None
) -> tuple[FeedExport, dict[str, str] | None]:
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
        if not validators:
            # A 304 answers a conditional request. Without one the publisher -- or a proxy in front of it --
            # never told us what the feed holds, and reading it as "unchanged" would mark an unread source
            # healthy and seed it with nothing.
            raise RssError("feed answered 304 to an unconditional request")
        return FeedExport((), False), None
    if status != 200:
        raise RssError(f"feed answered HTTP {status}" if status else "feed is unreachable")
    return parse_rss(body), _validators_of(response_headers)


# --------------------------------------------------------------------------
# OPML import


def parse_opml(body: bytes) -> tuple[tuple[str, str, str], ...]:
    """Flatten an OPML 2.0 subscription list into ``(title, xml_url, html_url)`` feeds.

    A folder is an outline without an ``xmlUrl``, and an export usually puts every feed inside one, so the
    walk descends into an outline that names no feed instead of skipping its children. Document order is
    kept because it is the only ordering signal OPML carries.
    """
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise FeedError(f"OPML is not XML: {exc}") from exc
    if _local(root.tag) != "opml":
        raise FeedError("document is not OPML")
    feeds: list[tuple[str, str, str]] = []

    def walk(element: ET.Element) -> None:
        for child in list(element):
            if _local(child.tag) == "outline":
                xml_url = (child.get("xmlUrl") or "").strip()
                if xml_url:
                    # ``text`` is the required OPML label and ``title`` the optional prettier one; a
                    # folder without a feed is skipped, so only a real subscription reaches this branch.
                    title = (child.get("title") or child.get("text") or "").strip()
                    feeds.append((title, xml_url, (child.get("htmlUrl") or "").strip()))
            walk(child)

    walk(root)
    return tuple(feeds)


# --------------------------------------------------------------------------
# HTML autodiscovery


#: Link types a page may use to advertise a feed. ``application/json`` is included because some publishers
#: serve JSON Feed under it; ``text/html`` and ``application/xhtml+xml`` are deliberately absent.
_FEED_TYPES = frozenset(
    {
        "application/rss+xml",
        "application/atom+xml",
        "application/feed+json",
        "application/json",
    }
)


class _AlternateLinks(html.parser.HTMLParser):
    """Collect the ``href`` of every ``<link rel="alternate">`` whose type is a feed type."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "link":
            return
        values = {name.lower(): value or "" for name, value in attrs}
        rel = values.get("rel", "").lower().split()
        # A link type may carry a charset parameter; only the media type takes part in the decision.
        mime = values.get("type", "").split(";", 1)[0].strip().lower()
        href = values.get("href", "").strip()
        if href and "alternate" in rel and mime in _FEED_TYPES:
            self.hrefs.append(href)


def discover_feed(body: bytes, page_url: str) -> str | None:
    """The first feed an HTML page advertises, as an absolute URL, or None.

    Only ``rel="alternate"`` counts: a stylesheet or a preload can carry a feed MIME type by accident, and
    following one would fetch a resource that is not a subscription. Relative ``href`` values are resolved
    here because they are only meaningful against the page that carried them; this function fetches nothing.
    """
    finder = _AlternateLinks()
    finder.feed(body.decode("utf-8", "replace"))
    finder.close()
    if not finder.hrefs:
        return None
    return urllib.parse.urljoin(page_url, finder.hrefs[0])


# --------------------------------------------------------------------------
# Format dispatch


#: A page that is not well-formed XML still declares itself in its first bytes, sometimes after a comment.
#: A well-formed page is recognised by its root element instead, so a feed whose CDATA contains "<html>"
#: is not mistaken for one; a malformed feed that is mistaken for a page still raises, it just raises the
#: other error, which is why this fallback may be generous.
_HTML_HEAD_BYTES = 1024


def _looks_like_html(body: bytes) -> bool:
    try:
        return _local(ET.fromstring(body).tag) == "html"
    except (ET.ParseError, ValueError):
        head = body.lstrip(b"\xef\xbb\xbf")[:_HTML_HEAD_BYTES].lower()
        return b"<!doctype html" in head or b"<html" in head


def parse_any(body: bytes) -> FeedExport:
    """Parse whichever feed format these bytes are, deciding from what the document says about itself.

    A caller's guess is not evidence: sniffing on the presence of an ``items`` key would read a JSON Feed
    with the GReader rules and a GReader export with the JSON Feed rules, and would read any unrelated JSON
    API's ``{"items": []}`` as a healthy GReader source with no news. The JSON branch therefore needs the
    JSON Feed version or positive GReader evidence. An HTML page is refused here because autodiscovery needs
    the page URL, which only ``fetch_any`` has.
    """
    head = body.lstrip(b"\xef\xbb\xbf \t\r\n")
    if head[:1] in (b"{", b"["):
        document = parse_json(body)
        if isinstance(document, dict) and _is_json_feed(document):
            return _json_feed_export(document)
        if _is_greader_export(document):
            return _greader_export(document)
        raise FeedError("feed is neither JSON Feed nor a GReader export")
    if _looks_like_html(body):
        raise FeedError("page is not a feed")
    return parse_rss(body)


_FEED_ACCEPT = (
    "application/rss+xml, application/atom+xml, application/feed+json, application/json, application/xml, text/xml"
)

#: The port a scheme connects to when the URL names none, so ``https://host`` and ``https://host:443`` agree.
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin(url: str) -> tuple[str, str | None, int | None] | None:
    """A URL's origin as ``(scheme, host, effective port)``, or None when it has no usable authority.

    ``urlsplit`` lowercases the scheme and host and raises for a malformed port or IPv6 bracket. Such a URL is
    not this page's origin, and None keeps the caller's comparison from raising on remote-authored text. A
    missing port means the scheme's default: a link that spells out ``:443`` names the same origin as one that
    does not.
    """
    try:
        parts = urllib.parse.urlsplit(url)
        return parts.scheme, parts.hostname, parts.port or _DEFAULT_PORTS.get(parts.scheme)
    except ValueError:
        return None


def fetch_any(
    http: Http, url: str, validators: Mapping[str, str] | None = None
) -> tuple[FeedExport, dict[str, str] | None]:
    """One GET for any supported feed format, plus the caching validators to keep for the next one.

    A source may be configured with the page that advertises a feed rather than the feed itself, so an HTML
    answer is followed through exactly one autodiscovery hop. A page that advertises another page is refused
    instead of followed again: the source is a subscription, not a crawl.

    Conditional requests behave exactly as ``fetch_rss`` does. A 304 is an empty export only when this
    call asked conditionally, because otherwise nothing has said the feed is unchanged.
    """
    headers = {"Accept": f"{_FEED_ACCEPT}, text/html"}
    if validators:
        headers.update(validators)
    status, response_headers, body = http("GET", url, headers, None)
    if status == 304:
        if not validators:
            raise RssError("feed answered 304 to an unconditional request")
        return FeedExport((), False), None
    if status != 200:
        raise RssError(f"feed answered HTTP {status}" if status else "feed is unreachable")
    if _looks_like_html(body):
        target = discover_feed(body, url)
        if target is None:
            raise FeedError("page offers no feed link")
        # The page is remote-authored, so its link is too. The page's own host is the one the operator already
        # chose, so discovery may not redirect the reader to a host an attacker picked: the feed must share the
        # page's scheme, host and port. A feed genuinely served from another host is configured directly. The
        # private-destination rule stays as well, and ``allow_private_sources`` deliberately applies to neither
        # -- that allowance is for an operator-authored source URL. Both refusals have to come before the
        # request; a rejection after the response cannot unmake the internal GET.
        advertised = _origin(target)
        if advertised is None or advertised != _origin(url):
            raise FeedError("page advertises a feed on another origin")
        if private_destination(target):
            raise FeedError("page advertises a feed on a private address")
        status, _, body = http("GET", target, {"Accept": _FEED_ACCEPT}, None)
        if status != 200:
            raise RssError(f"feed answered HTTP {status}" if status else "feed is unreachable")
        # No validators are stored for a page. They describe the page, and a 304 on it would say nothing
        # about the feed it advertises; storing the feed's own ETag instead would send it to the wrong
        # resource. Polling the page unconditionally costs one extra GET and cannot hide a changed feed.
        return parse_any(body), {}
    return parse_any(body), _validators_of(response_headers)
