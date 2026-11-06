"""Adobe Commerce / Magento security bulletins: the Trust Center list and one bulletin page.

``ops.security_advisories`` reads two public, unauthenticated, undocumented documents and trusts neither:

* the Trust Center CaaS list (one GET per pass), which names every bulletin of every Adobe product. A card is a
  Commerce bulletin only when ``contentArea.detailText`` is ``caas:mnemonics/adobe-commerce``. Its APSB id
  (``contentArea.title``) is the identity; the priority is in the description and the CVE ids in ``search.search``;
* the bulletin page on the Edge Delivery origin (``<apsb>.plain.html``), which carries the per-CVE severity, the
  version tables and Adobe's statement on exploitation. Enrichment is best effort: ``parse_detail`` returns None
  for a page that holds none of it, and the caller still delivers the bulletin.

Everything here is pure: no network, no state. Version strings are returned verbatim, never parsed as numbers
(``2.4.8-2026-oct`` is a month-style release, not a dotted version). The page is untrusted markup: it is read as
text with the standard-library parser, never evaluated, and its size and nesting are bounded.
"""

from __future__ import annotations

import html.parser
import re
from dataclasses import dataclass

from .http import parse_json

CAAS_URL = (
    "https://www.adobe.com/chimera-api/collection?originSelection=hawks,milo"
    "&contentTypeTags=caas:content-type/documentation&language=en&country=us"
    "&complexQuery=((%22caas%3Atrust-center%2Fsecurity-bulletin%22))&draft=false&size=250&flatFile=false"
)
DETAIL_URL = "https://main--da-cc--adobecom.aem.live/trust/security/products/commerce/{apsb}.plain.html"
COMMERCE_MNEMONIC = "caas:mnemonics/adobe-commerce"
#: The id is placed in a URL and in a message title, so only this shape is accepted.
APSB_RE = re.compile(r"APSB\d{2}-\d{1,5}")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
PRIORITY_RE = re.compile(r"Priority (\d)")
#: A page larger than this is not a bulletin; it is not parsed.
PAGE_LIMIT = 1_000_000
#: Deeper markup is ignored rather than recursed into.
MAX_DEPTH = 100
#: "Adobe is aware of CVE-... being exploited in the wild", within one sentence. "Adobe is not aware of any
#: exploits in the wild" does not match: it holds neither "is aware" nor "exploited".
_EXPLOITED = re.compile(r"\bis aware\b[^.]{0,300}?\bexploited in the wild", re.IGNORECASE)
_VOID = frozenset({"br", "hr", "img", "source", "link", "meta", "input", "wbr"})
_SKIPPED = frozenset({"script", "style"})
_BLOCKS = frozenset({"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"})


@dataclass(frozen=True)
class Bulletin:
    apsb: str
    #: Adobe's priority from the card description; None when it is not stated.
    priority: int | None
    cves: tuple[str, ...]
    url: str


@dataclass(frozen=True)
class CveDetail:
    cve: str
    #: Lower-case ("critical"); Adobe's older pages say "important" and "moderate".
    severity: str
    #: True for "Yes", False for "No", None when the page does not say.
    auth_required: bool | None
    cvss: float | None


@dataclass(frozen=True)
class Detail:
    cves: tuple[CveDetail, ...]
    #: ``(product, versions)`` rows of the "Affected Versions" and "Solution" tables, versions verbatim.
    affected: tuple[tuple[str, tuple[str, ...]], ...]
    fixed: tuple[tuple[str, tuple[str, ...]], ...]
    #: The first paragraph outside a table that mentions a hotfix, or "".
    hotfix_note: str
    #: Adobe's positive sentence. Its "not aware" sentence is never recorded: Adobe does not update it.
    exploited: bool


def detail_url(apsb: str) -> str:
    return DETAIL_URL.format(apsb=apsb.lower())


def parse_caas(body: bytes) -> tuple[Bulletin, ...] | None:
    """The Commerce bulletins in a CaaS response; None when the response is not a usable list.

    A Commerce card whose title is not an APSB id makes the whole response unusable: a changed shape must fail,
    not be skipped.
    """
    document = parse_json(body)
    cards = document.get("cards") if isinstance(document, dict) else None
    if not isinstance(cards, list):
        return None
    found: dict[str, Bulletin] = {}
    for card in cards:
        area = card.get("contentArea") if isinstance(card, dict) else None
        if not isinstance(area, dict) or area.get("detailText") != COMMERCE_MNEMONIC:
            continue
        title = area.get("title")
        if not isinstance(title, str) or not APSB_RE.fullmatch(title):
            return None
        description = area.get("description")
        priority = PRIORITY_RE.search(description) if isinstance(description, str) else None
        search = card.get("search")
        listed = search.get("search") if isinstance(search, dict) else None
        named = CVE_RE.findall(listed if isinstance(listed, str) else "")
        cves = tuple(dict.fromkeys(match.upper() for match in named))
        url = area.get("url")
        found.setdefault(
            title, Bulletin(title, int(priority[1]) if priority else None, cves, url if isinstance(url, str) else "")
        )
    return tuple(found.values())


# --------------------------------------------------------------------------
# The bulletin page


class _Node:
    __slots__ = ("tag", "classes", "children")

    def __init__(self, tag: str, classes: tuple[str, ...]) -> None:
        self.tag = tag
        self.classes = classes
        self.children: list[_Node | str] = []


class _Tree(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _Node("root", ())
        self._stack = [self.root]
        self._skipped = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIPPED:
            self._skipped += 1
        elif not self._skipped and len(self._stack) < MAX_DEPTH:
            node = _Node(tag, tuple((dict(attrs).get("class") or "").split()))
            self._stack[-1].children.append(node)
            if tag not in _VOID:
                self._stack.append(node)

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIPPED:
            self._skipped = max(self._skipped - 1, 0)
        elif not self._skipped and tag not in _VOID:
            for index in range(len(self._stack) - 1, 0, -1):
                if self._stack[index].tag == tag:
                    del self._stack[index:]
                    return

    def handle_data(self, data: str) -> None:
        if not self._skipped:
            self._stack[-1].children.append(data)


def _lines(node: _Node) -> list[str]:
    """The node's text, one entry per block or ``<br>`` boundary, whitespace collapsed, empties dropped."""
    parts: list[str] = []

    def walk(current: _Node) -> None:
        for child in current.children:
            if isinstance(child, str):
                parts.append(child)
                continue
            boundary = child.tag in _BLOCKS
            parts.append("\n" if boundary else "")
            walk(child)
            parts.append("\n" if boundary else "")

    walk(node)
    return [line for line in (" ".join(raw.split()) for raw in "".join(parts).split("\n")) if line]


def _text(node: _Node) -> str:
    return " ".join(_lines(node))


def _children(node: _Node) -> list[_Node]:
    return [child for child in node.children if isinstance(child, _Node)]


@dataclass
class _Found:
    accordions: list[_Node]
    tables: list[_Node]
    paragraphs: list[str]


def _scan(node: _Node, found: _Found) -> None:
    """Collect the parts the parser reads. A table or accordion is not descended into, nor is a paragraph."""
    for child in _children(node):
        if "table" in child.classes:
            found.tables.append(child)
        elif "accordion" in child.classes:
            found.accordions.append(child)
        elif child.tag == "p":
            found.paragraphs.append(_text(child))
        else:
            _scan(child, found)


def _value(lines: list[str], label: str) -> str:
    for line in lines:
        if line.lower().startswith(label):
            return line[len(label) :].strip()
    return ""


def _cve_details(accordion: _Node) -> list[CveDetail]:
    """The accordion alternates a CVE heading and its body; a heading without a body yields nothing."""
    details: list[CveDetail] = []
    current = ""
    for child in _children(accordion):
        text = _text(child)
        if CVE_RE.fullmatch(text):
            current = text.upper()
            continue
        if not current:
            continue
        lines = _lines(child)
        authentication = _value(lines, "authentication required to exploit?").lower()
        score = re.match(r"\d+(?:\.\d+)?", _value(lines, "cvss base score:"))
        cvss = float(score[0]) if score and float(score[0]) <= 10.0 else None
        details.append(
            CveDetail(
                current,
                _value(lines, "severity:").lower(),
                True if authentication.startswith("yes") else False if authentication.startswith("no") else None,
                cvss,
            )
        )
        current = ""
    return details


def _table_rows(table: _Node) -> tuple[str, list[tuple[str, tuple[str, ...]]]]:
    """(``affected`` | ``fixed`` | "", rows) of a Product / Version table; any other table reads as ""."""
    rows = [[_lines(cell) for cell in _children(row)] for row in _children(table)]
    header = [" ".join(cell).lower() for cell in rows[0]] if rows else []
    kind = ""
    if len(header) > 1 and header[0] == "product":
        kind = {"version": "affected", "updated version": "fixed"}.get(header[1], "")
    parsed = [(" ".join(row[0]), tuple(row[1])) for row in rows[1:] if len(row) > 1 and row[0] and row[1]]
    return kind, parsed


def parse_detail(body: bytes) -> Detail | None:
    """What a bulletin page states; None when it holds none of the parts below (the caller says so)."""
    if len(body) > PAGE_LIMIT:
        return None
    tree = _Tree()
    tree.feed(body.decode("utf-8", "replace"))
    tree.close()
    found = _Found([], [], [])
    _scan(tree.root, found)
    tables: dict[str, list[tuple[str, tuple[str, ...]]]] = {}
    for table in found.tables:
        kind, rows = _table_rows(table)
        if kind and kind not in tables:
            tables[kind] = rows
    cves = tuple(detail for accordion in found.accordions for detail in _cve_details(accordion))
    hotfix = next((text for text in found.paragraphs if "hotfix" in text.lower()), "")
    exploited = any(_EXPLOITED.search(text) for text in found.paragraphs)
    detail = Detail(cves, tuple(tables.get("affected", ())), tuple(tables.get("fixed", ())), hotfix, exploited)
    return detail if cves or detail.affected or detail.fixed or exploited else None
