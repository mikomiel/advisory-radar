"""Does an advisory apply to what is installed? Evidence from an imported inventory, kept apart from text relevance.

Text relevance is the watchlist's decision and is untouched here: it says an advisory mentions something the
operator watches. This module answers a different question from different data -- the installed versions of an
imported inventory against the versions the advisory says are affected -- and only ever adds a line of evidence to
what a page shows. It never changes what is queued, delivered or routed.

Two sources feed the answer, both read offline at render time:

* the findings of an imported OSV-Scanner result, which already pair an advisory with an installed version;
* the affected packages and ranges of the OSV record a pass fetched for a GHSA id, kept in ``state["affected"]``
  from the moment an inventory exists.

Nothing guesses. A version that does not parse, an ecosystem without a comparator and an advisory without
comparable ranges are "unknown"; a package the inventory does not list is "unknown", worded as no matching
component, because an SBOM or a scan can omit packages; an inventory older than the configured age can no longer
confirm that an advisory does not apply. An advisory that names a CVE or GHSA id no stored record covers is
"unknown" too: the data of its sibling cannot clear it. A scan lists only the packages it found something in, so it
can confirm that an advisory applies but never clear one: only an SBOM can say "not affected".
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from .core import CVE_RE, GHSA_RE
from .inventory import Inventory, normalise_id
from .versions import MAX_VERSION_CHARS, SUPPORTED_ECOSYSTEMS, evaluate, version_key

DAY = 86400
#: Advisories whose affected data the state keeps; the oldest go first. One advisory is a few hundred bytes.
MAX_FACT_ADVISORIES = 1000
MAX_AFFECTED_ENTRIES = 16
MAX_RANGES = 8
MAX_EVENTS = 32
MAX_LISTED_VERSIONS = 64
#: CVE ids kept as the aliases of one advisory. An alias past the bound is not covered, which can only withhold a
#: "not affected".
MAX_FACT_CVES = 16
_EVENT_KINDS = ("introduced", "fixed", "last_affected", "limit")
STATUSES = ("applies", "not_affected", "unknown")


@dataclass(frozen=True)
class Evidence:
    """One verdict: ``status`` is ``applies``, ``not_affected`` or ``unknown``; ``reason`` says why.

    Reasons: ``affected`` (installed version is in a range, or a scan reported it), ``fixed`` (installed version is
    at or after the fix), ``outside`` (before the first affected version), ``no_component`` (the inventory lists no
    such package), ``unknown_version`` (the component has no comparable version), ``unsupported`` (the ecosystem has
    no comparator), ``no_facts`` (no comparable advisory data, or none for every vulnerability the advisory names),
    ``stale`` (the inventory is too old to confirm that the advisory does not apply) and ``partial`` (the inventory is
    a scan, which lists only the packages it found something in, so it can confirm that an advisory applies but not
    that it does not).
    """

    status: str
    reason: str
    package: str = ""
    installed: str = ""
    fixed: str = ""
    #: The scanner's reachability verdict: extra evidence on an ``applies``, never a reason to hide one.
    called: bool | None = None
    stale: bool = False
    age_days: int = 0


def _event(event: object) -> dict:
    """An OSV event reduced to its known kinds; one whose version is not text is emptied, which reads as unknown."""
    if not isinstance(event, dict):
        return {}
    kept = {kind: event[kind] for kind in _EVENT_KINDS if kind in event}
    return kept if all(isinstance(value, str) for value in kept.values()) else {}


def trim_affected(affected: object) -> tuple[list[dict], bool]:
    """The compact form of an OSV record's ``affected`` list that is stored, and whether every entry was kept.

    An entry or a listed version that is malformed or over a bound is dropped, and a list of versions over its
    bound is cut, and the advisory is marked incomplete: a later verdict can still say "applies" from what was kept
    but never "not affected" from it. A cut list loses affected versions without inventing any, so the entry and
    its ranges stay; a cut range or event list could drop a ``fixed`` event and read as open, so that entry goes.
    """
    if not isinstance(affected, list):
        return [], False
    kept: list[dict] = []
    complete = True
    for entry in affected:
        package = entry.get("package") if isinstance(entry, dict) else None
        ecosystem = package.get("ecosystem") if isinstance(package, dict) else None
        name = package.get("name") if isinstance(package, dict) else None
        ranges = entry.get("ranges", []) if isinstance(entry, dict) else None
        versions = entry.get("versions", []) if isinstance(entry, dict) else None
        usable = (
            isinstance(ecosystem, str)
            and 0 < len(ecosystem) <= 64
            and isinstance(name, str)
            and 0 < len(name) <= 256
            and isinstance(ranges, list)
            and len(ranges) <= MAX_RANGES
            and all(isinstance(item, dict) and isinstance(item.get("events"), list) for item in ranges)
            and all(len(item["events"]) <= MAX_EVENTS for item in ranges)
            and isinstance(versions, list)
            and len(kept) < MAX_AFFECTED_ENTRIES
        )
        if not usable:
            complete = False
            continue
        head = versions[:MAX_LISTED_VERSIONS]
        listed = [version for version in head if isinstance(version, str) and len(version) <= MAX_VERSION_CHARS]
        complete = complete and len(listed) == len(versions)
        kept.append(
            {
                "ecosystem": ecosystem,
                "name": name,
                "ranges": [
                    {
                        "type": item.get("type") if isinstance(item.get("type"), str) else "",
                        "events": [_event(event) for event in item["events"]],
                    }
                    for item in ranges
                ],
                "versions": listed,
            }
        )
    return kept, complete


def _aliased(cves: object) -> list[str]:
    """The CVE ids an OSV record aliases, normalised and bounded; anything else is dropped."""
    if not isinstance(cves, list):
        return []
    found = dict.fromkeys(normalise_id(cve) for cve in cves if isinstance(cve, str) and CVE_RE.fullmatch(cve))
    return list(found)[:MAX_FACT_CVES]


def record_facts(state: dict, found: Mapping[str, Mapping], now: int) -> None:
    """Keep what the OSV records a pass fetched say about their advisories, newest ``MAX_FACT_ADVISORIES`` only.

    ``found`` maps an advisory id to its record's ``cves`` (the CVE ids it aliases) and ``affected`` list. Called only
    while an inventory exists, so an installation without one writes no extra key.
    """
    if not found:
        return
    stored = state.get("affected")
    facts = stored if isinstance(stored, dict) else {}
    for identifier, record in found.items():
        entries, complete = trim_affected(record.get("affected"))
        facts[normalise_id(identifier)] = {
            "at": now,
            "cves": _aliased(record.get("cves")),
            "entries": entries,
            "complete": complete,
        }
    if len(facts) > MAX_FACT_ADVISORIES:
        newest = sorted(facts, key=lambda key: _at(facts[key]), reverse=True)[:MAX_FACT_ADVISORIES]
        facts = {key: facts[key] for key in newest}
    state["affected"] = facts


def _at(fact: object) -> int:
    value = fact.get("at") if isinstance(fact, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _names_a_vulnerability(identifier: str) -> bool:
    return bool(CVE_RE.fullmatch(identifier) or GHSA_RE.fullmatch(identifier))


def facts_for(state: Mapping, ids: Sequence[str]) -> tuple[list[dict], bool]:
    """The stored affected entries of an advisory's identifiers, and whether they may clear it.

    ``complete`` holds only when every fact found is complete **and** every CVE or GHSA id the advisory names is
    covered: it is the id of a fact found, or a CVE that fact's record aliases. An id nothing was stored for may be
    affected, so the facts of its sibling cannot speak for it. Any other identifier (a vendor's, a feed item's guid)
    names no vulnerability here and does not count.
    """
    stored = state.get("affected")
    facts = stored if isinstance(stored, dict) else {}
    entries: list[dict] = []
    covered: set[str] = set()
    complete = True
    for identifier in ids:
        key = normalise_id(identifier)
        fact = facts.get(key)
        if not isinstance(fact, dict):
            continue
        covered.add(key)
        covered.update(_aliased(fact.get("cves")))
        complete = complete and fact.get("complete") is True
        items = fact.get("entries")
        entries += [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    named = {normalise_id(identifier) for identifier in ids if _names_a_vulnerability(identifier)}
    return entries, complete and named <= covered


def _scan_evidence(inventory: Inventory, ids: Sequence[str], stale: bool, age_days: int) -> Evidence | None:
    hits = inventory.findings_for(ids)
    if not hits:
        return None
    first = hits[0]
    reach = [hit.get("called") for hit in hits]
    called = True if True in reach else (False if all(item is False for item in reach) else None)
    return Evidence(
        "applies",
        "affected",
        f"{first['ecosystem']} {first['name']}",
        first["version"],
        first["fixed"],
        called,
        stale,
        age_days,
    )


def _entry_evidence(inventory: Inventory, entry: Mapping, complete: bool) -> list[Evidence]:
    """The verdict of one affected entry against every installed version of its package."""
    ecosystem, name = entry.get("ecosystem"), entry.get("name")
    if not isinstance(ecosystem, str) or not isinstance(name, str):
        return []
    package = f"{ecosystem} {name}"
    installed = inventory.versions_of(ecosystem, name)
    if not installed:
        return [Evidence("unknown", "no_component", package)]
    found: list[Evidence] = []
    for version in installed:
        if ecosystem not in SUPPORTED_ECOSYSTEMS:
            found.append(Evidence("unknown", "unsupported", package, version))
        elif version_key(ecosystem, version) is None:
            found.append(Evidence("unknown", "unknown_version", package, version))
        else:
            verdict = evaluate(ecosystem, version, entry.get("ranges") or (), entry.get("versions") or ())
            if verdict.affected is True:
                found.append(Evidence("applies", "affected", package, version, verdict.fixed))
            elif verdict.affected is False and complete:
                reason = "fixed" if verdict.fixed else "outside"
                found.append(Evidence("not_affected", reason, package, version, verdict.fixed))
            else:
                found.append(Evidence("unknown", "no_facts", package, version))
    return found


def _absence_is_proof(inventory: Inventory, item: Evidence) -> bool:
    """Whether a package the inventory does not list is known not to be installed.

    Only an SBOM that skipped nothing, for an ecosystem whose package names are compared here. A scan lists only
    what it found something in; a skipped component (no package URL, or a type not read) may be the package; and
    another ecosystem's names may be spelled differently in the advisory than in a package URL.
    """
    ecosystem = item.package.split(" ", 1)[0]
    return inventory.complete and inventory.skipped == 0 and ecosystem in SUPPORTED_ECOSYSTEMS


def judge(
    inventory: Inventory,
    ids: Sequence[str],
    entries: Sequence[Mapping],
    complete: bool,
    now: int,
    max_age_days: int,
) -> Evidence:
    """The evidence for one advisory: scan findings first, then the stored affected entries, else unknown."""
    age = max(0, now - inventory.imported_at)
    stale = age > max_age_days * DAY
    age_days = age // DAY
    scanned = _scan_evidence(inventory, ids, stale, age_days)
    if scanned is not None:
        return scanned
    verdicts = [verdict for entry in entries for verdict in _entry_evidence(inventory, entry, complete)]
    chosen = None
    # The first verdict of the strongest kind wins: applies, then any unknown that could hide an affected version,
    # then not affected, and only then the weakest unknown (no component at all). See ``_absence_is_proof`` for when
    # a package the inventory does not list hides nothing beside a cleared sibling.
    for ranked in (
        lambda item: item.status == "applies",
        lambda item: (
            item.status == "unknown" and (item.reason != "no_component" or not _absence_is_proof(inventory, item))
        ),
        lambda item: item.status == "not_affected",
    ):
        chosen = next((item for item in verdicts if ranked(item)), None)
        if chosen is not None:
            break
    if chosen is None:
        chosen = verdicts[0] if verdicts else Evidence("unknown", "no_facts")
    if chosen.status == "not_affected" and not inventory.complete:
        # A scan lists only what it found something in. It can confirm that an advisory applies but never that it does
        # not: a clean copy of the package, another version of it, can be missing from the file.
        return replace(chosen, status="unknown", reason="partial", stale=stale, age_days=age_days)
    if stale and chosen.status == "not_affected":
        # Old data cannot clear an advisory; it can still raise one.
        return replace(chosen, status="unknown", reason="stale", stale=True, age_days=age_days)
    return replace(chosen, stale=stale, age_days=age_days)


def evidence_for(state: Mapping, inventory: Inventory, ids: Sequence[str], now: int, max_age_days: int) -> Evidence:
    """The evidence for an advisory named by ``ids``, from the state's stored affected data and the inventory."""
    entries, complete = facts_for(state, ids)
    return judge(inventory, ids, entries, complete, now, max_age_days)
