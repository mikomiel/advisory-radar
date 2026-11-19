"""The CVEs a delivered message left unmeasured: durable remaining work, drained fairly inside the pass budget.

An advisory can name far more CVEs than one item may look up (``core.MAX_ITEM_CVE_LOOKUPS``). The rest are watched
for KEV only, which costs no request, and this module owns what happens to them next.

State. A watch entry with ``kev_only`` has never been measured. A lookup that the pass time budget or the NVD
allowance ended (``deferred``), or that a provider did not answer in full (``failed``), leaves
``entry["enrich"]`` (``state``, ``since``, ``tries``, ``at``); a complete measurement removes it and clears
``kev_only``. ``state["enrich_cursor"]`` is the source that last got a lookup. Both keys are additive: a state
written before them reads as "every ``kev_only`` entry is waiting and nothing has been tried", which is what it is.

Fairness. ``select`` serves one waiting CVE per source in turn, starting after the cursor, and stops at ``PER_PASS``.
No source can hold the pass while another waits, and when there are more sources than the cap the cursor makes the
unserved ones go first next time. Inside a source the CVE tried longest ago goes first. A lookup that never began
(the budget or the NVD allowance ended before its request) keeps its place, and one that failed goes to the back. So
does one whose request began and the budget cut (``interrupted``): it spent the time the others needed, so without a
turn of its own a persistently slow CVE would be first in every pass and the rest would never start. It is stored as
``deferred``, because no provider failed: it is asked again next pass, behind the CVEs that waited.

Window. A watch entry is kept for ``core.REEVAL_WINDOW``, and up to ``EXTENDED_WINDOW`` while its enrichment is
outstanding, so a CVE the passes could not measure in time is not dropped unmeasured. The counts and the oldest wait
(``coverage``) are what the dashboard and the metrics show.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

_DAY = 86400

#: An entry whose enrichment is outstanding stays watched this long, counted from its message
#: (``core.REEVAL_WINDOW`` is the ordinary 14 days).
EXTENDED_WINDOW = 30 * _DAY
#: Capped CVEs one pass may look up, on top of its daily re-scores (``core.MAX_REEVAL``). A lookup is one CVE.org
#: request, one NVD request when CVE.org has no score (these share the pass's ``core.MAX_NVD_CALLS``) and a share
#: of one EPSS request per 100 ids; the pass budget (``budget``) bounds the time all of them may take.
PER_PASS = 10
#: NVD requests the drain may make in one pass, half of ``core.MAX_NVD_CALLS``: the re-scores and the new items share
#: that allowance with it, so a large advisory cannot leave them without a score for as many passes as it needs.
NVD_PER_PASS = 5
#: A failed lookup waits this long, as a failed daily re-score does, instead of being asked again every pass.
RETRY_AFTER = _DAY

KEV_ONLY, DEFERRED, FAILED, MEASURED = "kev_only", "deferred", "failed", "measured"
STATES = (MEASURED, KEV_ONLY, DEFERRED, FAILED)
#: An outcome, never a state: a lookup whose request began and the pass budget cut. It is recorded as ``deferred``.
INTERRUPTED = "interrupted"


@dataclass(frozen=True)
class Coverage:
    """How the watched CVEs stand: one count per state, and the longest wait among those still outstanding."""

    measured: int
    kev_only: int
    deferred: int
    failed: int
    #: Seconds the longest-waiting CVE with outstanding enrichment has waited, ``None`` when none is outstanding.
    oldest_age: int | None

    @property
    def outstanding(self) -> int:
        return self.kev_only + self.deferred + self.failed


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _marker(entry: Mapping) -> Mapping | None:
    """The lookup record of an entry, or ``None`` when it has none or the state document damaged it."""
    marker = entry.get("enrich")
    return marker if isinstance(marker, dict) and marker.get("state") in (DEFERRED, FAILED) else None


def _source(entry: Mapping) -> str:
    source = entry.get("source_id")
    return source if isinstance(source, str) else ""


def outstanding(entry: object) -> str | None:
    """How a watch entry's enrichment stands: ``kev_only``, ``deferred`` or ``failed``, or ``None`` once measured."""
    if not isinstance(entry, dict):
        return None
    marker = _marker(entry)
    if marker is not None:
        return str(marker["state"])
    return KEV_ONLY if entry.get("kev_only") is True else None


def _since(entry: Mapping) -> int | None:
    """When the entry's enrichment became outstanding: its message for a capped CVE, else its first failure."""
    marker = _marker(entry)
    stamp = _int(marker.get("since")) if marker is not None else None
    return stamp if stamp is not None else _int(entry.get("since"))


def keeps(entry: Mapping, now: int, window: int) -> bool:
    """Whether a watch entry is still watched: inside ``window``, or inside ``EXTENDED_WINDOW`` while outstanding."""
    age = now - entry["since"]
    return age <= window or (age <= EXTENDED_WINDOW and outstanding(entry) is not None)


def record(entry: dict, outcome: str, now: int) -> None:
    """Note what one lookup of the entry's CVE came to.

    ``measured`` means complete facts: the entry joins the daily re-evaluation. ``deferred`` means the time budget
    or the NVD allowance ended the lookup, not a provider, so no try is counted. ``interrupted`` is a ``deferred``
    one whose request began and was cut by the budget: no try is counted either, but ``at`` moves to ``now``, which
    sends it behind the CVEs that waited (``select``). ``failed`` means a request was made and a provider did not
    answer in full.
    """
    if outcome == MEASURED:
        entry.pop("enrich", None)
        if "kev_only" in entry:
            entry["kev_only"] = False
        return
    held = _marker(entry) or {}
    began = _int(held.get("since"))
    if began is None:
        began = _int(entry.get("since")) if entry.get("kev_only") is True else None
    tries = _int(held.get("tries")) or 0
    entry["enrich"] = {
        "state": DEFERRED if outcome == INTERRUPTED else outcome,
        "since": now if began is None else began,
        "tries": tries + (outcome == FAILED),
        "at": now if outcome in (FAILED, INTERRUPTED) else _int(held.get("at")) or 0,
    }


def _ready(entry: Mapping, now: int) -> bool:
    marker = _marker(entry)
    if marker is None or marker["state"] != FAILED:
        return True
    return now - (_int(marker.get("at")) or 0) >= RETRY_AFTER


def select(state: Mapping, now: int, limit: int = PER_PASS) -> list[str]:
    """The capped CVEs to look up this pass, one source in turn, in the order they are to be tried."""
    watch = state.get("watch")
    if not isinstance(watch, dict):
        return []
    waiting = sorted(
        (
            cve
            for cve, entry in watch.items()
            if isinstance(entry, dict) and entry.get("kev_only") is True and _ready(entry, now)
        ),
        key=lambda cve: (_int((_marker(watch[cve]) or {}).get("at")) or 0, _int(watch[cve].get("since")) or 0, cve),
    )
    queues: dict[str, list[str]] = {}
    for cve in waiting:
        queues.setdefault(_source(watch[cve]), []).append(cve)
    sources = sorted(queues)
    cursor = state.get("enrich_cursor")
    if isinstance(cursor, str):
        sources = [name for name in sources if name > cursor] + [name for name in sources if name <= cursor]
    picks: list[str] = []
    while queues and len(picks) < limit:
        for name in sources:
            if name in queues and len(picks) < limit:
                picks.append(queues[name].pop(0))
                if not queues[name]:
                    del queues[name]
    return picks


def served(state: dict, picks: Sequence[str], outcomes: Mapping[str, str]) -> None:
    """Move the cursor to the source of the last pick that took a turn.

    A pick took one when its request was made: it was measured, a provider failed it, or the budget cut it
    (``interrupted``). A pick the budget ended before any request is no turn, so its source goes first again.
    """
    watch = state.get("watch")
    watch = watch if isinstance(watch, dict) else {}
    done = [cve for cve in picks if outcomes.get(cve) in (MEASURED, FAILED, INTERRUPTED)]
    if done and isinstance(watch.get(done[-1]), dict):
        state["enrich_cursor"] = _source(watch[done[-1]])
    if not any(isinstance(entry, dict) and entry.get("kev_only") is True for entry in watch.values()):
        state.pop("enrich_cursor", None)


def coverage(watch: object, now: int) -> Coverage:
    """One count per state over the watched CVEs, and the longest wait of those with outstanding enrichment."""
    counts = dict.fromkeys(STATES, 0)
    oldest: int | None = None
    for entry in watch.values() if isinstance(watch, dict) else ():
        if not isinstance(entry, dict):
            continue
        state = outstanding(entry) or MEASURED
        counts[state] += 1
        began = _since(entry)
        if state != MEASURED and began is not None:
            oldest = max(oldest or 0, now - began, 0)
    return Coverage(counts[MEASURED], counts[KEV_ONLY], counts[DEFERRED], counts[FAILED], oldest)
