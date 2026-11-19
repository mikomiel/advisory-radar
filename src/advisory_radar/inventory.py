"""The installed-software inventory: a bounded, never-executed import of a scan result or an SBOM.

Three JSON inputs reach one stored document: OSV-Scanner results, CycloneDX and SPDX 2.x SBOMs. Each import is
parsed as data only -- nothing in a file is run, fetched or followed -- and is refused loudly, as a whole, when it
is over a limit or a member of the file's own structure has the wrong shape. The OSV record that a scan embeds in
a finding is the exception: it is read only to show the fix, so a part of it that cannot be read is left out.
A refused import never changes the stored inventory. An accepted one records where it came from (format, file
name, digest, size, time) and replaces the previous inventory in one atomic write.

Whatever a file or the stored document holds, nothing but :class:`InventoryError` leaves :func:`parse` or
:func:`load`: a fault no check foresaw is turned into one there, so a malformed file cannot fail the pass that reads
it or the page that offers it.

The document lives beside the state file (``inventory.json``), not inside it: an inventory is thousands of
components, and the state document is written again in full by every pass.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import urllib.parse
from collections.abc import Iterable, Mapping
from pathlib import Path

from .feeds import MAX_FEED_BYTES
from .state import save_json, state_lock
from .versions import MAX_VERSION_CHARS, SUPPORTED_ECOSYSTEMS, evaluate

LOG = logging.getLogger("advisory_radar")

INVENTORY_NAME = "inventory.json"
SCHEMA = "advisory-radar-inventory.v1"
FORMATS = ("osv-scanner", "cyclonedx", "spdx")
#: One import is read whole, so it is capped like a feed: the same 8 MiB, for the same reason (a parsed tree costs
#: many times its source in memory).
MAX_INVENTORY_BYTES = MAX_FEED_BYTES
#: The most one import may list of each kind: SBOM components (the subject included) and, in a scan, packages, findings
#: and call-analysis groups, each counted as the file lists it, repeats included. A larger inventory is refused, never
#: truncated: a truncated one would answer "no matching component" for packages it dropped.
MAX_ENTRIES = 20_000
#: The deepest nesting of CycloneDX components that is followed.
MAX_DEPTH = 12
MAX_NAME_CHARS = 256
MAX_PURL_CHARS = 512
MAX_ID_CHARS = 64
MAX_IDS_PER_FINDING = 32
MAX_FILENAME_CHARS = 120
#: Directory entries one drop-directory look examines: a directory that holds more is not a drop directory.
MAX_DROP_ENTRIES = 1000
#: The origins an import records: the web upload and the file dropped in the configured directory.
ORIGINS = ("upload", "drop")
#: purl types read, and the OSV ecosystem each one names. Others (distro packages, containers) are skipped and
#: counted: an advisory about a language package cannot be judged against them.
_PURL_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
}


class InventoryError(ValueError):
    """An import or a stored inventory that is refused.

    The message names the limit or the field, or the kind of error for a fault no check foresaw. Never a value.
    """


def normalise_id(identifier: str) -> str:
    """The identifier as the pass spells it: GHSA ids lower case after the prefix, every other id upper case.

    The same rule as ``core._normalise_id``; ``tests/test_inventory.py`` pins the two together.
    """
    return "GHSA-" + identifier[5:].lower() if identifier.upper().startswith("GHSA-") else identifier.upper()


def normalise_name(ecosystem: str, name: str) -> str:
    """The name an ecosystem treats as one package: PyPI collapses ``-_.`` runs, npm and crates.io ignore case."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "npm":
        return name.lower()
    if ecosystem == "crates.io":
        return name.lower().replace("_", "-")
    return name


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """``(ecosystem, name, version)`` of a package URL, or ``None`` when its type is not read or it is malformed."""
    if len(purl) > MAX_PURL_CHARS or purl[:4].lower() != "pkg:":
        return None
    rest = purl[4:].lstrip("/").split("#", 1)[0].split("?", 1)[0]
    kind, _, path = rest.partition("/")
    ecosystem = _PURL_ECOSYSTEMS.get(kind.lower())
    if ecosystem is None or not path:
        return None
    head, separator, version = path.rpartition("@")
    # The version separator is the last "@" and only when no "/" follows it: an unencoded npm scope is not one.
    if separator and "/" not in version:
        path = head
    else:
        version = ""
    segments = [urllib.parse.unquote(segment) for segment in path.split("/") if segment]
    if not segments:
        return None
    if ecosystem == "Maven" and len(segments) > 1:
        name = f"{'.'.join(segments[:-1])}:{segments[-1]}"
    else:
        name = "/".join(segments)
    version = urllib.parse.unquote(version)
    if not name or len(name) > MAX_NAME_CHARS:
        return None
    return ecosystem, name, version if len(version) <= MAX_VERSION_CHARS else ""


def _text(value: object, where: str, limit: int, *, required: bool = False) -> str:
    """A string field: absent is ``""`` unless ``required``; any other type, or an over-long text, is refused."""
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value):
        raise InventoryError(f"{where} must be a string")
    if len(value) > limit:
        raise InventoryError(f"{where} is longer than {limit} characters")
    return value


def _list(value: object, where: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise InventoryError(f"{where} must be a list")
    return value


def _object(value: object, where: str) -> Mapping:
    if not isinstance(value, dict):
        raise InventoryError(f"{where} must be an object")
    return value


def _component(ecosystem: str, name: str, version: str) -> dict:
    return {"ecosystem": ecosystem, "name": name, "version": version}


def _sbom_component(purl: str, version: str) -> dict | None:
    """One SBOM component keyed on its package URL. Its own version field must agree with the URL's, else unknown."""
    parsed = parse_purl(purl)
    if parsed is None:
        return None
    ecosystem, name, from_purl = parsed
    if version and from_purl and version != from_purl:
        return _component(ecosystem, name, "")  # a document that disagrees with itself confirms nothing
    return _component(ecosystem, name, version or from_purl)


def _cyclonedx(document: Mapping) -> tuple[list[dict], str, int]:
    _text(document.get("specVersion"), "specVersion", 16, required=True)
    metadata = document.get("metadata")
    info = _object(metadata, "metadata") if metadata else {}
    created = _text(info.get("timestamp"), "metadata.timestamp", 40)
    found: list[dict] = []
    skipped = visited = 0
    stack = [(item, 1, "components[]") for item in reversed(_list(document.get("components"), "components"))]
    # The subject (``metadata.component``) is the software the document describes, and it can carry components of its
    # own. It is read like a top-level component, from the same stack, so it shares their count, depth and field
    # checks, and a subject that cannot be placed is skipped like any other. ``null`` is no subject; any other type
    # is refused when it is read. It goes on last so that it is read first, as the document lists it.
    subject = info.get("component")
    if subject is not None:
        stack.append((subject, 1, "metadata.component"))
    while stack:
        item, depth, where = stack.pop()
        visited += 1
        if visited > MAX_ENTRIES:
            raise InventoryError(f"the document has more than {MAX_ENTRIES} components")
        entry = _object(item, where)
        purl = _text(entry.get("purl"), f"{where}.purl", MAX_PURL_CHARS)
        version = _text(entry.get("version"), f"{where}.version", MAX_VERSION_CHARS)
        children = _list(entry.get("components"), f"{where}.components")
        if children and depth >= MAX_DEPTH:
            raise InventoryError(f"components are nested deeper than {MAX_DEPTH} levels")
        stack.extend((child, depth + 1, "components[]") for child in reversed(children))
        component = _sbom_component(purl, version) if purl else None
        if component is None:
            skipped += 1
        else:
            found.append(component)
    return found, created, skipped


def _spdx(document: Mapping) -> tuple[list[dict], str, int]:
    _text(document.get("spdxVersion"), "spdxVersion", 16, required=True)
    info = document.get("creationInfo")
    created = _text(_object(info, "creationInfo").get("created"), "creationInfo.created", 40) if info else ""
    packages = _list(document.get("packages"), "packages")
    if len(packages) > MAX_ENTRIES:
        raise InventoryError(f"the document has more than {MAX_ENTRIES} packages")
    found: list[dict] = []
    skipped = 0
    for item in packages:
        entry = _object(item, "packages[]")
        version = _text(entry.get("versionInfo"), "packages[].versionInfo", MAX_VERSION_CHARS)
        component = None
        for reference in _list(entry.get("externalRefs"), "packages[].externalRefs"):
            reference = _object(reference, "packages[].externalRefs[]")
            if _text(reference.get("referenceType"), "packages[].externalRefs[].referenceType", 64) != "purl":
                continue
            locator = _text(reference.get("referenceLocator"), "packages[].externalRefs[].referenceLocator", 512)
            component = _sbom_component(locator, version)
            if component is not None:
                break
        if component is None:
            skipped += 1
        else:
            found.append(component)
    return found, created, skipped


#: The member of a ``groups[]`` entry that carries call analysis, in the two spellings OSV-Scanner's layouts use. Both
#: are read, so a scanner release that changed the spelling cannot silently turn reachability into "not analysed".
_ANALYSIS_KEYS = ("experimentalAnalysis", "experimental_analysis")


def _analysis(groups: list) -> dict[str, bool]:
    """The call analysis of one package, read and validated once: every identifier an analysis names, normalised, and
    whether any analysis says it is called. Each finding of the package then looks its ids up here; rescanning
    ``groups`` for every finding cost findings x groups visits, which a small file could make enormous."""
    called: dict[str, bool] = {}
    for group in groups:
        group = _object(group, "groups[]")
        for key in _ANALYSIS_KEYS:
            analysis = group.get(key)
            if analysis is None:
                continue
            for identifier, detail in _object(analysis, f"groups[].{key}").items():
                verdict = detail.get("called") if isinstance(detail, dict) else None
                if isinstance(verdict, bool):
                    identifier = normalise_id(identifier)
                    called[identifier] = called.get(identifier, False) or verdict
    return called


def _called(analysis: Mapping[str, bool], ids: Iterable[str]) -> bool | None:
    """The scanner's reachability verdict for one finding: ``True`` if any analysis says called, ``False`` if all
    say not called, ``None`` when no analysis names it. An annotation only: it never removes a finding."""
    verdicts = [analysis[identifier] for identifier in ids if identifier in analysis]
    return any(verdicts) if verdicts else None


def _merge_called(first: bool | None, second: bool | None) -> bool | None:
    """Two reachability verdicts for one finding: called if either says so, not called only if both say so."""
    if True in (first, second):
        return True
    return False if first is False and second is False else None


def _fixed(ecosystem: str, name: str, version: str, affected: object) -> str:
    """The fix a vulnerability record names for this package, for display: precise where the ecosystem is
    comparable, else the distinct fixed versions the record lists for the package."""
    fixes: list[str] = []
    for entry in affected if isinstance(affected, list) else []:
        package = entry.get("package") if isinstance(entry, dict) else None
        if not isinstance(package, dict) or package.get("name") != name or package.get("ecosystem") != ecosystem:
            continue
        listed = entry.get("ranges")  # read only as a list, like ``events`` below: this record only decorates a finding
        ranges = [item for item in listed if isinstance(item, dict)] if isinstance(listed, list) else []
        if ecosystem in SUPPORTED_ECOSYSTEMS:
            verdict = evaluate(ecosystem, version, ranges, ())
            if verdict.fixed:
                return verdict.fixed
        for item in ranges:
            events = item.get("events")
            for event in events if isinstance(events, list) else []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixes.append(event["fixed"])
    return ", ".join(dict.fromkeys(fixes[:3]))[:MAX_NAME_CHARS]


def _osv_scanner(document: Mapping) -> tuple[list[dict], list[dict]]:
    """Components and findings from OSV-Scanner's JSON output (``results[].packages[]``).

    A finding is one vulnerability the scanner matched to one installed package version: its ids (the record id
    and its aliases), the package, the fix and, when the scan ran call analysis, whether the code is reachable.

    The work is bounded by what the file lists, not by the product of two lists. Packages, vulnerability records and
    call-analysis groups are each counted as listed, repeats included, over the whole file, and a list over the
    bound is refused before any of it is read. The groups of a package are indexed once, not rescanned per record.
    """
    components: dict[tuple, dict] = {}
    findings: dict[tuple, dict] = {}
    listed = {"packages": 0, "findings": 0, "call-analysis groups": 0}

    def count(what: str, items: list) -> None:
        listed[what] += len(items)
        if listed[what] > MAX_ENTRIES:
            raise InventoryError(f"the document has more than {MAX_ENTRIES} {what}")

    for result in _list(document.get("results"), "results"):
        packages = _list(_object(result, "results[]").get("packages"), "results[].packages")
        count("packages", packages)
        for item in packages:
            entry = _object(item, "results[].packages[]")
            package = _object(entry.get("package"), "results[].packages[].package")
            where = "results[].packages[].package"
            ecosystem = _text(package.get("ecosystem"), f"{where}.ecosystem", 64, required=True)
            name = _text(package.get("name"), f"{where}.name", MAX_NAME_CHARS, required=True)
            version = _text(package.get("version"), f"{where}.version", MAX_VERSION_CHARS)
            components[(ecosystem, name, version)] = _component(ecosystem, name, version)
            groups = _list(entry.get("groups"), "results[].packages[].groups")
            vulnerabilities = _list(entry.get("vulnerabilities"), "results[].packages[].vulnerabilities")
            count("call-analysis groups", groups)
            count("findings", vulnerabilities)
            analysis = _analysis(groups)
            for record in vulnerabilities:
                record = _object(record, "results[].packages[].vulnerabilities[]")
                where = "results[].packages[].vulnerabilities[]"
                raw = [_text(record.get("id"), f"{where}.id", MAX_ID_CHARS, required=True)]
                aliases = _list(record.get("aliases"), f"{where}.aliases")
                if len(aliases) > MAX_IDS_PER_FINDING:
                    raise InventoryError(f"{where}.aliases lists more than {MAX_IDS_PER_FINDING} identifiers")
                raw += [_text(alias, f"{where}.aliases[]", MAX_ID_CHARS, required=True) for alias in aliases]
                ids = list(dict.fromkeys(normalise_id(identifier) for identifier in raw))
                key = (tuple(ids), ecosystem, name, version)
                called = _called(analysis, ids)
                previous = findings.get(key)
                if previous is not None:  # the same finding in another lockfile of one scan
                    previous["called"] = _merge_called(previous["called"], called)
                    continue
                findings[key] = {
                    "ids": ids,
                    **_component(ecosystem, name, version),
                    "fixed": _fixed(ecosystem, name, version, record.get("affected")),
                    "called": called,
                }
    return list(components.values()), list(findings.values())


def display_name(name: str) -> str:
    """A file name as display text: the last path segment, printable characters only, bounded."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = "".join(char for char in base if char.isprintable()).strip()
    return cleaned[:MAX_FILENAME_CHARS] or "unnamed"


def parse(data: bytes, *, name: str, now: int, origin: str) -> dict:
    """The stored inventory document for one import, or :class:`InventoryError` and nothing else.

    "Nothing else" holds whatever ``data`` holds; an unknown ``origin`` is a caller's bug and raises ``ValueError``.
    Nothing here runs, fetches or resolves anything in ``data``: it is decoded as UTF-8 JSON and read field by
    field. A document that is not one of the three supported formats is refused rather than guessed at. So is a
    file that trips a fault no check foresaw: the message then names only the kind of error, so the callers
    (a pass, an upload) need no net of their own.
    """
    if origin not in ORIGINS:
        raise ValueError(f"unknown origin {origin!r}")
    if not data:
        raise InventoryError("the file is empty")
    if len(data) > MAX_INVENTORY_BYTES:
        raise InventoryError(f"the file is larger than {MAX_INVENTORY_BYTES // (1024 * 1024)} MiB")
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise InventoryError("the file is not UTF-8 JSON") from None
    if not isinstance(document, dict):
        raise InventoryError("the top level of the file must be a JSON object")
    created = ""
    skipped = 0
    findings: list[dict] = []
    try:
        if document.get("bomFormat") == "CycloneDX":
            fmt = "cyclonedx"
            components, created, skipped = _cyclonedx(document)
        elif "spdxVersion" in document:
            fmt = "spdx"
            if not str(document["spdxVersion"]).startswith("SPDX-2."):
                raise InventoryError("only SPDX 2.x JSON documents are supported")
            components, created, skipped = _spdx(document)
        elif "results" in document:
            fmt = "osv-scanner"
            components, findings = _osv_scanner(document)
        else:
            raise InventoryError("the file is not an OSV-Scanner result, a CycloneDX SBOM or an SPDX 2.x SBOM")
    except InventoryError:
        raise
    except Exception as exc:
        # The readers refuse each shape they foresaw with an InventoryError of their own, so anything else is a defect
        # in one of them. An import is optional evidence: it must refuse this one file, not fail the pass that reads it
        # or the page that offers it. Only the kind of error is named, since its text can quote the file.
        raise InventoryError(f"the file could not be processed: unexpected {type(exc).__name__}") from exc
    if fmt != "osv-scanner" and not components:
        raise InventoryError("the SBOM lists no component with a package URL of a supported type")
    if len(components) > MAX_ENTRIES:
        raise InventoryError(f"the document has more than {MAX_ENTRIES} components")
    return {
        "schema": SCHEMA,
        "format": fmt,
        "name": display_name(name),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "imported_at": now,
        "origin": origin,
        "created": "".join(char for char in created if char.isprintable()),
        # A scan result lists the packages it found something in; only an SBOM claims to list every component.
        "complete": fmt != "osv-scanner",
        "skipped": skipped,
        "components": components,
        "findings": findings,
    }


class Inventory:
    """A stored inventory document, checked on load, with the two lookups the judge needs."""

    def __init__(self, document: object) -> None:
        if not isinstance(document, dict) or document.get("schema") != SCHEMA:
            raise InventoryError("the stored inventory is not a document this version wrote")
        try:
            self.format = _text(document.get("format"), "format", 32, required=True)
            self.name = _text(document.get("name"), "name", MAX_FILENAME_CHARS, required=True)
            self.sha256 = _text(document.get("sha256"), "sha256", 64, required=True)
            self.origin = _text(document.get("origin"), "origin", 16, required=True)
            self.created = _text(document.get("created"), "created", 40)
            self.imported_at = document.get("imported_at")
            self.size = document.get("size")
            self.skipped = document.get("skipped")
            if self.format not in FORMATS or self.origin not in ORIGINS:
                raise InventoryError("the stored inventory names an unknown format or origin")
            for number in (self.imported_at, self.size, self.skipped):
                if not isinstance(number, int) or isinstance(number, bool) or number < 0:
                    raise InventoryError("the stored inventory has a malformed number")
            self.complete = document.get("complete")
            if not isinstance(self.complete, bool):
                raise InventoryError("the stored inventory has a malformed flag")
            self.components = _stored(document.get("components"), "components", ("ecosystem", "name", "version"))
            self.findings = _stored(document.get("findings"), "findings", ("ecosystem", "name", "version", "fixed"))
        except InventoryError as exc:
            raise InventoryError(f"the stored inventory is damaged: {exc}") from None
        # A dict per package keeps the listed order and makes the repeat check constant-time (a list made it quadratic).
        seen: dict[tuple[str, str], dict[str, None]] = {}
        for component in self.components:
            key = (component["ecosystem"], normalise_name(component["ecosystem"], component["name"]))
            seen.setdefault(key, {})[component["version"]] = None
        self._versions: dict[tuple[str, str], list[str]] = {key: list(versions) for key, versions in seen.items()}
        self._by_id: dict[str, list[dict]] = {}
        for finding in self.findings:
            ids = finding.get("ids")
            if not isinstance(ids, list) or not all(isinstance(identifier, str) for identifier in ids):
                raise InventoryError("the stored inventory is damaged: findings[].ids must be a list of strings")
            called = finding.get("called")
            if called is not None and not isinstance(called, bool):
                raise InventoryError("the stored inventory is damaged: findings[].called must be a flag")
            for identifier in ids:
                self._by_id.setdefault(identifier, []).append(finding)

    def versions_of(self, ecosystem: str, name: str) -> list[str]:
        """The installed versions listed for a package (``""`` for a component with no version); empty if absent."""
        return self._versions.get((ecosystem, normalise_name(ecosystem, name)), [])

    def findings_for(self, ids: Iterable[str]) -> list[dict]:
        """The scan findings naming any of ``ids``, each once."""
        found: dict[int, dict] = {}
        for identifier in ids:
            for finding in self._by_id.get(normalise_id(identifier), []):
                found[id(finding)] = finding
        return list(found.values())


def _stored(value: object, where: str, fields: tuple[str, ...]) -> list[dict]:
    items = _list(value, where)
    if len(items) > MAX_ENTRIES:
        raise InventoryError(f"{where} is longer than {MAX_ENTRIES}")
    for item in items:
        entry = _object(item, f"{where}[]")
        for field in fields:
            optional = field in ("version", "fixed")
            # An import writes every field, an empty text for one it has no value for. A field that is absent is a
            # damaged document, and the judge and the pages index it.
            if field not in entry:
                raise InventoryError(f"{where}[].{field} must be a string")
            _text(entry.get(field), f"{where}[].{field}", MAX_NAME_CHARS, required=not optional)
    return items


def inventory_path(state_path: Path) -> Path:
    """Where the stored inventory lives: beside the state file, like the other documents on the data volume."""
    return state_path.with_name(INVENTORY_NAME)


def save(path: Path, document: dict) -> None:
    """Replace the stored inventory atomically, under its own lock (never the state lock a pass holds)."""
    with state_lock(path):
        save_json(path, document, compact=True)


def load(path: Path) -> Inventory | None:
    """The stored inventory, ``None`` when there is none, :class:`InventoryError` when it cannot be read.

    An unreadable inventory is never read as an absent one: the page says so, and no evidence is shown from it.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError):
        raise InventoryError("the stored inventory cannot be read") from None
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        raise InventoryError("the stored inventory is not valid JSON") from None
    try:
        return Inventory(document)
    except InventoryError:
        raise
    except Exception as exc:
        # The constructor refuses each damage it foresaw with an InventoryError of its own, so anything else is a defect
        # there. Reported as damage, it reaches the page and the log by name; raised, it would fail every pass and every
        # page that asks for the inventory, and the page that replaces it among them.
        raise InventoryError(f"the stored inventory is damaged: unexpected {type(exc).__name__}") from exc


# --- the drop directory ---------------------------------------------------------------------------------


def _newest_file(directory: Path) -> tuple[str, os.stat_result] | None:
    """The name and stat of the newest regular ``*.json`` file in ``directory``; links are never followed."""
    newest: tuple[int, str, os.stat_result] | None = None
    with os.scandir(directory) as entries:
        for position, entry in enumerate(entries):
            if position >= MAX_DROP_ENTRIES:
                break
            if entry.name.startswith(".") or not entry.name.lower().endswith(".json"):
                continue
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode) and (newest is None or (info.st_mtime_ns, entry.name) > newest[:2]):
                newest = (info.st_mtime_ns, entry.name, info)
    return None if newest is None else (newest[1], newest[2])


def _read(path: Path) -> bytes:
    """At most one byte over the cap of a regular file, opened without following a link."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    try:
        handle = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
    with handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise InventoryError("the file is not a regular file")
        return handle.read(MAX_INVENTORY_BYTES + 1)


def pick_up(directory: Path, state: dict, path: Path, now: int) -> None:
    """Import the newest file in the drop ``directory`` when it is not the one the last look already handled.

    The file's own digest is what is remembered (``state["inventory_drop"]``), not the stored inventory's: an
    upload made since must not be undone by a drop file nobody changed, and a file that is refused is refused
    once -- the next look finds the same digest and says nothing. A refused or unreadable file never changes
    the stored inventory and never fails the pass: ``parse`` raises nothing but ``InventoryError`` for any file
    content, so that and ``OSError`` are every fault to expect here. A file that parses but cannot be stored is
    not remembered, so the next pass tries it again.
    """
    try:
        newest = _newest_file(directory)
    except OSError:
        LOG.debug("inventory drop directory %s cannot be read", directory)
        return
    if newest is None:
        return
    name, info = newest
    shown = display_name(name)
    previous = state.get("inventory_drop")
    last = previous.get("seen") if isinstance(previous, dict) else None
    seen = f"stat:{name}:{info.st_size}:{info.st_mtime_ns}:{info.st_ctime_ns}"
    document, error = None, ""
    try:
        if info.st_size > MAX_INVENTORY_BYTES:
            raise InventoryError(f"the file is larger than {MAX_INVENTORY_BYTES // (1024 * 1024)} MiB")
        data = _read(directory / name)
        seen = hashlib.sha256(data).hexdigest()
        if seen != last:
            document = parse(data, name=name, now=now, origin="drop")
    except (InventoryError, OSError) as exc:
        error = str(exc) if isinstance(exc, InventoryError) else "the file could not be read"
    if seen == last:
        return
    if document is None:
        LOG.warning("inventory file %s was refused (%s); the previous inventory stays", shown, error)
    else:
        try:
            save(path, document)
        except OSError:
            LOG.warning("inventory file %s could not be stored; the next pass tries again", shown)
            return
        LOG.info("inventory: imported %s from the drop directory", shown)
    outcome = "refused" if document is None else "imported"
    state["inventory_drop"] = {"seen": seen, "name": shown, "at": now, "outcome": outcome, "error": error}


def refresh(state_path: Path, directory: Path | None, state: dict, now: int) -> Inventory | None:
    """What a pass does about the inventory: take a new drop file, then return the stored inventory if it reads.

    ``load`` raises nothing but ``InventoryError``, so an inventory that cannot be read is logged and skipped here,
    never raised into the pass.
    """
    path = inventory_path(state_path)
    if directory is not None:
        pick_up(directory, state, path, now)
    try:
        return load(path)
    except InventoryError as exc:
        LOG.warning("%s; no applicability evidence is recorded until it is replaced", exc)
        return None
