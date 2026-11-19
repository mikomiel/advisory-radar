"""CSAF 2.0 documents and the directory index that lists them: the pure half of the ``csaf`` source.

CSAF (Common Security Advisory Framework, OASIS Standard of 18 November 2022) is how a vendor publishes advisories
as JSON. This module reads the two things a provider directory serves and nothing else:

* a **document**, checked against the CSAF 2.0 JSON schema and then against what the schema cannot say (the
  profile, whether every product id a statement uses is defined, that no product id has two names), and returned
  as a ``Document`` of plain values; and
* ``changes.csv``, the headerless two-column list of ``path,timestamp`` rows that names every document and when it
  last changed, returned as ``Row`` values, oldest first.

The schema files are vendored in ``csaf_schema/`` (``NOTICE.md`` there records their source, licence and digest)
and read from the package, so checking a document never touches the network, and the check takes a time in
proportion to the size of the document (``schema_validator``). Both reads refuse what they cannot trust and say
why in one short sentence that the source shows the operator. ``sources.CsafSource`` owns the requests, the cursor
and the failure bookkeeping; this module owns what a statement is.

A document is identified by its ``id`` and a digest of the statements it carries (``Document.revision``), and
dated by the last time the vendor changed what it says (``Document.release``), because the version number and the
release date of a file say that only for a vendor that keeps them for that purpose, and the first provider does not.

A statement is the vendor's own assertion about one vulnerability and one product. It is kept apart from anything
this program knows about the reader's installed versions: nothing here compares a version, and an item built from
a statement says so. ``known_not_affected`` is a statement about the vulnerability it sits under and the products
listed there, and nothing else: ``concerned_cves`` never returns a vulnerability that carries only that status,
and ``statements_text`` counts the products under it instead of naming them.
"""

from __future__ import annotations

import csv
import functools
import hashlib
import io
import itertools
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, validators
from jsonschema.exceptions import ValidationError, best_match
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT4, DRAFT7, DRAFT202012

from .http import json_text, parse_json

#: Where the vendored schema files are read from (never fetched).
SCHEMA_DIR = Path(__file__).with_name("csaf_schema")

#: The largest document and the largest index this reader parses. The transport stops any answer at 64 MiB; these
#: are the sizes it is willing to hold as Python objects. A body above either cap is reported, not read. The first
#: provider's index is under 5 MiB and its documents are mostly under 2 MiB, but 2 of 80 sampled advisories were above
#: 8 MiB and the largest seen was 22.5 MiB (``docs/sources.md``), so raising the document cap is a decision about
#: memory, not about the provider.
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_INDEX_BYTES = 16 * 1024 * 1024

#: The newest documents a new source reads: older ones are history, and a directory lists tens of thousands.
START_DOCUMENTS = 20
#: The most documents one pass reads, oldest first, and the seconds one pass may take, counted from its first
#: request. The first provider changes thousands of documents in a burst, and a pass of 20 fell up to six days behind
#: it where 200 never fell more than ten hours (replayed in ``docs/sources.md``). A pass that meets the time first
#: stops before the next document, and always reads one, so a slow provider still makes progress.
MAX_DOCUMENTS = 200
PASS_SECONDS = 120
#: How long before now the oldest unread row may have been listed before the source says it is behind, in seconds.
#: A source that says so is red, and a red source keeps the instant of its last success (of its first answer, when it
#: has had none), from which ``core`` judges whether an item is news: this limit is at most half of
#: ``core.BACKLOG_OUTAGE_SLACK``, so what a late pass reads is still news (``tests/test_csaf_source.py`` pins the
#: relation).
LAG_LIMIT = 12 * 60 * 60
#: How many times one revision of one document may fail before the source gives up on it and goes on.
MAX_ATTEMPTS = 3
#: How long a document given up on stays reported when no newer revision replaces it, in seconds.
PROBLEM_RETENTION = 30 * 24 * 60 * 60
#: How many given-up documents one window names (the rest are counted), and how many are remembered at all.
MAX_LISTED_PROBLEMS = 5
MAX_KEPT_PROBLEMS = 20
#: How far into the future an index timestamp may be before the index is refused, in seconds. A row dated ahead
#: of the pass would park the cursor in the future and hide every later row.
FUTURE_SLACK = 600

#: The longest sentence of statements an item carries. The excerpt of a message is cut at 500 characters, and the
#: words the service writes around the statements take about 100 of them.
MAX_STATEMENTS_CHARS = 300
MAX_PRODUCT_CHARS = 120
MAX_TITLE_CHARS = 500
MAX_PUBLISHER_CHARS = 200
MAX_ID_CHARS = 256
MAX_PATH_CHARS = 256
MAX_URL_CHARS = 2048

#: The two profiles whose statements this reader interprets. Another profile (csaf_base, an informational
#: advisory) may carry no product status at all, so reading it as a statement would be a guess.
PROFILES = ("csaf_security_advisory", "csaf_vex")
#: The product statuses of the schema, in the order a statement lists them. All are kept as the vendor wrote them.
STATUSES = (
    "known_affected",
    "first_affected",
    "last_affected",
    "under_investigation",
    "recommended",
    "fixed",
    "first_fixed",
    "known_not_affected",
)
NOT_AFFECTED = "known_not_affected"

#: The summary the first provider gives the last entry of every revision history it writes: the entry is the run of
#: its generator and not a change of the advisory (``_released``). Checked on 2026-11-19 in 12 advisories and 1 VEX.
GENERATED_SUMMARY = "Last generated version"

_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
#: Every character a CSAF file name may hold (the standard lowercases the id and replaces the rest with ``_``),
#: with a ``/`` between folders. No percent sign, query or fragment can occur, so a path is never quoted.
_PATH = re.compile(r"[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*\.json")
#: RFC 3339 ``date-time``, ASCII only and with a zone: the form CSAF and the provider indexes use. The groups are the
#: time to the second, the fraction of the second (one to nine digits) and the zone.
_DATE_TIME = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})"
)


class CsafError(ValueError):
    """A provider answer this reader cannot use. The message is one short sentence for the operator."""


class DocumentRejected(CsafError):
    """One document that must not be used: it breaks the schema, a pinned rule or a size limit."""


@dataclass(frozen=True)
class Assertion:
    """What the vendor says about one vulnerability and one product name: a status and how many ids say it.

    ``product`` is the name of the product a statement concerns. A component of a product is reported as that
    product, so ``count`` is the number of product ids that resolve to the name, not a number of products.
    """

    cve: str
    status: str
    product: str
    count: int


@dataclass(frozen=True)
class Document:
    """A validated CSAF document, reduced to the facts an alert needs and where they came from."""

    #: ``document.tracking.id``: the identity of the advisory, the same for every revision of it.
    id: str
    #: ``document.tracking.version``: the revision, as the vendor wrote it (an integer or a semantic version).
    #: It is shown, never relied on: the first provider writes ``3`` into every document it has.
    version: str
    #: When the vendor last changed what the document says, as an epoch (``_released``).
    release: int
    #: A digest of the statements the document carries: the same for a rewritten file that says the same, another
    #: when a statement differs, whatever the order the vendor lists them in. This tells revisions apart.
    revision: str
    publisher: str
    category: str
    title: str
    #: The document's own ``self`` reference when it is a web address, else ``""``.
    url: str
    assertions: tuple[Assertion, ...]


@dataclass(frozen=True)
class Row:
    """One line of ``changes.csv``: a document path below the directory and the instant it last changed."""

    path: str
    #: The instant, in whole seconds of the epoch.
    release: int
    #: The nanoseconds after those seconds: an index may time a row finer than a second, to the ninth digit.
    nanos: int = 0

    @property
    def listing(self) -> str:
        """What a cursor remembers of a row it read: the path, and the fraction of the second when there is one.

        A document revised within the second it was read in is listed again with the same path and the same whole
        second, so the fraction is all that tells the revision from the row already read. A row in whole seconds is
        its bare path, which is what an earlier version stored. The two forms never collide because no path holds an
        ``@`` (``_PATH``).
        """
        return f"{self.path}@{self.nanos}" if self.nanos else self.path


def _clean(text: str, limit: int) -> str:
    """``text`` as one printable line of at most ``limit`` characters.

    A character that cannot be shown (a control, a newline, a bidi override) becomes a space, runs of whitespace
    collapse, and a cut ends in an ellipsis. Everything a document supplies that reaches a message, a log record
    or a page goes through this first.
    """
    line = " ".join("".join(char if char.isprintable() else " " for char in text).split())
    return line if len(line) <= limit else line[: max(limit - 3, 0)] + "..."


def _moment(value: object) -> tuple[int, int] | None:
    """An RFC 3339 date-time with a zone as whole epoch seconds and the nanoseconds after them, else None.

    None is anything else (a bare date, no zone, nonsense). The fraction is read from the text, to the ninth digit
    the pattern accepts, because ``datetime`` keeps six and a float timestamp fewer still.
    """
    match = _DATE_TIME.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return None
    clock, fraction, zone = match.groups()
    try:
        seconds = int(datetime.fromisoformat(clock + zone).timestamp())
    except (ValueError, OverflowError, OSError):
        return None
    return seconds, int((fraction or "").ljust(9, "0"))


def _instant(value: object) -> int | None:
    """The epoch second of an RFC 3339 date-time with a zone, or None: a document is dated to the second."""
    moment = _moment(value)
    return None if moment is None else moment[0]


def _unique_items(validator, unique, instance, schema):
    """``uniqueItems`` in time proportional to the size of the array.

    The library compares objects one pair at a time, so an array of 32,000 small objects (an 8 MiB document can hold
    six times as many) took more than four minutes to check. Elements that are equal have the same canonical text,
    so one set of texts is the whole check. A cap on how long an array may be would instead refuse real documents:
    the first provider's list several hundred product ids under one status and a thousand relationships.
    """
    if unique and validator.is_type(instance, "array"):
        seen: set[str] = set()
        for element in instance:
            canonical = json.dumps(element, sort_keys=True, separators=(",", ":"))
            if canonical in seen:
                yield ValidationError("the array has non-unique elements")
                return
            seen.add(canonical)


_Validator = validators.extend(Draft202012Validator, {"uniqueItems": _unique_items})


@functools.cache
def schema_validator() -> Draft202012Validator:
    """The CSAF 2.0 schema as a validator, with its three CVSS references answered from the vendored copies.

    The schema points at the FIRST CVSS schemas by URL. They are registered under those URLs, so resolving a
    reference is a lookup in this package and never a request. The one keyword changed is ``uniqueItems``
    (``_unique_items``), whose meaning is the same.
    """

    def load(name: str) -> dict:
        return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))

    schema = load("csaf_json_schema.json")
    first = "https://www.first.org/cvss/"
    registry = Registry().with_resources(
        [
            (schema["$id"], Resource(contents=schema, specification=DRAFT202012)),
            (f"{first}cvss-v2.0.json", Resource(contents=load("cvss-v2.0.json"), specification=DRAFT4)),
            (f"{first}cvss-v3.0.json", Resource(contents=load("cvss-v3.0.json"), specification=DRAFT4)),
            (f"{first}cvss-v3.1.json", Resource(contents=load("cvss-v3.1.json"), specification=DRAFT7)),
        ]
    )
    return _Validator(schema, registry=registry)


def _schema_reason(document: dict) -> str | None:
    """Why the document breaks the schema, in one bounded sentence, or None when it does not.

    Only the most relevant of the first few errors is reported: a document that breaks the schema usually breaks
    it in many places, and the operator needs one place to look. The sentence names where in the document and what
    is wrong, never the whole offending value.
    """
    try:
        error = best_match(itertools.islice(schema_validator().iter_errors(document), 25))
    except RecursionError:
        return "schema: the document is nested too deeply to check"
    if error is None:
        return None
    where = "/".join(str(part) for part in error.absolute_path) or "document root"
    return f"schema: {_clean(where, 120)}: {_clean(error.message, 160)}"


def _object(raw: bytes) -> dict:
    """The body as a JSON object, or ``DocumentRejected``: size first, then encoding, then syntax."""
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise DocumentRejected(f"document is larger than {MAX_DOCUMENT_BYTES} bytes")
    text = json_text(raw)
    document = parse_json(text) if text is not None else None
    if not isinstance(document, dict):
        raise DocumentRejected("body is not a JSON object")
    return document


def _undefined(product_id: str) -> DocumentRejected:
    return DocumentRejected(f"product id {_clean(product_id, 80)!r} is not defined in the product tree")


def _product_names(tree: dict) -> tuple[dict[str, str], dict[str, str]]:
    """Every product id the tree defines with its name, and for a component the id of the product it belongs to.

    The schema cannot see that a status refers to a product that exists, so this does. An id with two names would
    leave a statement ambiguous, so it is refused. The standard forbids defining an id twice at all, but real
    provider documents repeat an identical definition (a Red Hat VEX document does, for 32 of its 1,882 ids), and
    the id still names one product; so a repeat that agrees is accepted, and a component of a relationship, whose
    id also says which product it belongs to, must be defined once.
    """
    names: dict[str, str] = {}

    def define(full_product_name: dict) -> None:
        product_id, name = full_product_name["product_id"], full_product_name["name"]
        if names.setdefault(product_id, name) != name:
            raise DocumentRejected(f"product id {_clean(product_id, 80)!r} is defined twice with different names")

    for full_product_name in tree.get("full_product_names", ()):
        define(full_product_name)
    branches = list(tree.get("branches", ()))
    while branches:  # iterative: a branch tree may be deeper than the interpreter recurses
        branch = branches.pop()
        if "product" in branch:
            define(branch["product"])
        branches.extend(branch.get("branches", ()))
    relationships = tree.get("relationships", ())
    for relationship in relationships:
        component = relationship["full_product_name"]
        if component["product_id"] in names:
            raise DocumentRejected(f"product id {_clean(component['product_id'], 80)!r} is defined twice")
        define(component)
    parent: dict[str, str] = {}
    for relationship in relationships:
        for reference in (relationship["product_reference"], relationship["relates_to_product_reference"]):
            if reference not in names:
                raise _undefined(reference)
        parent[relationship["full_product_name"]["product_id"]] = relationship["relates_to_product_reference"]
    return names, parent


def _assertions(vulnerabilities: list, names: dict[str, str], parent: dict[str, str]) -> tuple[Assertion, ...]:
    """The statements of every vulnerability that names a CVE, in document order and then status order.

    A vulnerability without a CVE makes no statement: the alert pipeline identifies a finding by its CVE, and a
    statement about something it cannot name could only ever be misattributed. A product id that resolves to a
    component is reported as the product the component belongs to; ids that resolve to one name are counted together.
    """
    found: list[Assertion] = []
    for number, vulnerability in enumerate(vulnerabilities):
        cve = vulnerability.get("cve")
        if cve is None:
            continue
        if _CVE.fullmatch(cve) is None:  # the schema's pattern also accepts a trailing newline
            raise DocumentRejected(f"schema: vulnerabilities/{number}/cve: {_clean(cve, 40)!r} is not a CVE id")
        status = vulnerability.get("product_status") or {}
        for key in STATUSES:
            counts: dict[str, int] = {}
            for product_id in status.get(key, ()):
                if product_id not in names:
                    raise _undefined(product_id)
                name = _clean(names[parent.get(product_id, product_id)], MAX_PRODUCT_CHARS)
                counts[name] = counts.get(name, 0) + 1
            found.extend(Assertion(cve, key, name, count) for name, count in counts.items())
    return tuple(found)


def _web_address(value: object) -> str:
    """``value`` when it is an http(s) URL with a host and nothing a reader could not see, else ``""``."""
    if not isinstance(value, str) or len(value) > MAX_URL_CHARS:
        return ""
    if any(char.isspace() or not char.isprintable() for char in value):
        return ""
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        return ""
    return value if parts.scheme in ("http", "https") and host else ""


def _released(tracking: dict) -> int:
    """When the vendor last changed what the document says, as an epoch, or ``DocumentRejected`` when it cannot be read.

    That is ``current_release_date``, except for a provider that regenerates its documents. The first one does:
    it rewrites every file it serves from time to time, sets ``current_release_date`` (and the date of its
    generator) to that run, and ends the revision history with an entry whose summary is ``GENERATED_SUMMARY``, of
    the same instant. An advisory from 2020 then says it was released today. The entry before that one holds the
    date of the last change, so a document whose history ends that way is dated by it.
    """
    release = _instant(tracking["current_release_date"])
    if release is None:
        raise DocumentRejected("schema: document/tracking/current_release_date: not an RFC 3339 date-time with a zone")
    history = tracking["revision_history"]
    if len(history) > 1 and history[-1]["summary"] == GENERATED_SUMMARY:
        release = _instant(history[-2]["date"])
        if release is None:
            where = f"document/tracking/revision_history/{len(history) - 2}/date"
            raise DocumentRejected(f"schema: {where}: not an RFC 3339 date-time with a zone")
    return release


def _revision(assertions: tuple[Assertion, ...]) -> str:
    """A digest of the statements, independent of the order they are listed in and of anything else in the file."""
    canonical = "\n".join(sorted(f"{a.cve}|{a.status}|{a.product}|{a.count}" for a in assertions))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def parse_document(raw: bytes) -> Document:
    """A CSAF 2.0 document as a ``Document``, or ``DocumentRejected`` saying why it must not be used.

    The order is size, encoding and syntax, then the schema, then the pinned profiles and the product mapping.
    A document is accepted whole or not at all: a half-read advisory would be a statement nobody made.
    """
    document = _object(raw)
    reason = _schema_reason(document)
    if reason:
        raise DocumentRejected(reason)
    header = document["document"]
    category = header["category"]
    if category not in PROFILES:
        raise DocumentRejected(f"profile {_clean(category, 60)!r} is not read here; only {' and '.join(PROFILES)} are")
    tracking = header["tracking"]
    ident, version = tracking["id"], tracking["version"]
    if not (ident.isprintable() and version.isprintable()) or max(len(ident), len(version)) > MAX_ID_CHARS:
        raise DocumentRejected("tracking id or version is too long or holds a character that cannot be shown")
    release = _released(tracking)
    names, parent = _product_names(document.get("product_tree") or {})
    url = next(
        (
            address
            for reference in header.get("references", ())
            if reference.get("category") == "self" and (address := _web_address(reference.get("url")))
        ),
        "",
    )
    assertions = _assertions(document.get("vulnerabilities") or (), names, parent)
    return Document(
        id=ident,
        version=version,
        release=release,
        revision=_revision(assertions),
        publisher=_clean(header["publisher"]["name"], MAX_PUBLISHER_CHARS),
        category=category,
        title=_clean(header["title"], MAX_TITLE_CHARS),
        url=url,
        assertions=assertions,
    )


def concerned_cves(document: Document) -> tuple[str, ...]:
    """The vulnerabilities the document says something other than "not affected" about, in document order.

    This is the only list of vulnerabilities an alert may claim. A vulnerability that carries ``known_not_affected``
    and nothing else is absent from it, so a statement that a product is not affected can neither raise an alert for
    that vulnerability nor take the identity of an alert another source raises.
    """
    return tuple(dict.fromkeys(a.cve for a in document.assertions if a.status != NOT_AFFECTED))


def statements_text(document: Document) -> str:
    """The statements as one language-neutral sentence, cut to ``MAX_STATEMENTS_CHARS``.

    ``CVE-2026-0001: fixed: Widget 2.0 (2); known_not_affected (1). CVE-2026-0002: ...``. The status is the
    vendor's word. A not-affected statement is a count and never a name, so the sentence can never read as saying
    something about a product a watchlist should match.
    """
    by_cve: dict[str, list[Assertion]] = {}
    for assertion in document.assertions:
        by_cve.setdefault(assertion.cve, []).append(assertion)
    blocks: list[str] = []
    length = 0
    for cve, assertions in by_cve.items():
        parts = []
        for status in STATUSES:
            members = [a for a in assertions if a.status == status]
            if not members:
                continue
            if status == NOT_AFFECTED:
                parts.append(f"{status} ({sum(a.count for a in members)})")
            else:
                parts.append(f"{status}: " + ", ".join(f"{a.product} ({a.count})" for a in members))
        blocks.append(f"{cve}: " + "; ".join(parts))
        length += len(blocks[-1]) + 2
        if length > MAX_STATEMENTS_CHARS:
            break  # the rest would be cut anyway
    text = ". ".join(blocks)
    return text if len(text) <= MAX_STATEMENTS_CHARS else text[: MAX_STATEMENTS_CHARS - 3] + "..."


def _row_path_ok(path: str) -> bool:
    return (
        len(path) <= MAX_PATH_CHARS
        and _PATH.fullmatch(path) is not None
        and not any(set(part) == {"."} for part in path.split("/"))
    )


def parse_index(raw: bytes, now: float) -> tuple[Row, ...]:
    """``changes.csv`` as rows, oldest first to the nanosecond (ties by path), or ``CsafError`` if any is untrusted.

    The index is refused whole rather than read around: a row that is skipped is a document that is never read,
    and nothing would say so. Every path must be a plain relative ``.json`` name below the directory (no scheme,
    no ``..``, no empty folder, no character that would change the request), each path may appear once, and no
    timestamp may be later than ``now`` by more than ``FUTURE_SLACK``.
    """
    if len(raw) > MAX_INDEX_BYTES:
        raise CsafError(f"changes.csv is larger than {MAX_INDEX_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CsafError("changes.csv is not UTF-8 text") from None
    seen: set[str] = set()
    rows: list[Row] = []
    latest = now + FUTURE_SLACK
    try:
        for number, fields in enumerate(csv.reader(io.StringIO(text, newline=""), strict=True), start=1):
            if not fields:
                continue
            if len(fields) != 2:
                raise CsafError(f"changes.csv row {number} has {len(fields)} column(s), not 2")
            path, stamp = fields
            if not _row_path_ok(path):
                raise CsafError(f"changes.csv row {number}: the path is not a plain relative .json name")
            moment = _moment(stamp)
            if moment is None:
                raise CsafError(f"changes.csv row {number}: the timestamp is not an RFC 3339 date-time with a zone")
            release, nanos = moment
            if release > latest:
                raise CsafError(f"changes.csv row {number}: the timestamp is in the future")
            if path in seen:
                raise CsafError(f"changes.csv row {number}: the path is listed twice")
            seen.add(path)
            rows.append(Row(path, release, nanos))
    except csv.Error:
        raise CsafError("changes.csv is not well-formed CSV") from None
    if not rows:
        raise CsafError("changes.csv lists no documents")
    return tuple(sorted(rows, key=lambda row: (row.release, row.nanos, row.path)))
