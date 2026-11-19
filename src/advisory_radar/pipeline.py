"""One pass of the pipeline: fetch sources, classify, re-evaluate, deliver."""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import replace

from . import core, enrichment, retention, watchlist
from .budget import CLASSIFY_STAGE, FETCH_STAGE, BudgetedHttp, PassBudget
from .config import Config, secret_values
from .http import Http, RedactFilter, urllib_http
from .kev import load_kev
from .notifiers import build_notifier
from .plugins import Source, SourceWindow
from .sources import build_source
from .state import LockBusy, SourceError
from .storage import Store, StoreUnavailable

LOG = logging.getLogger("advisory_radar")

KEV_CACHE_NAME = "kev.json"

#: ``run_pass`` exit code for "another pass held the lock, so nothing ran" on the non-blocking path. It is
#: separate from 1 so a caller (the web UI's Run a pass now) can tell a skipped request from a failed one.
PASS_BUSY = 2

#: The Adobe Commerce pass in ``state["fetch_deferred"]``: it is deferred and resumed like a source. The ``@`` keeps
#: it from ever equalling a configured source id.
ADOBE_UNIT = "@adobe"

#: The health error of a source whose fetch the pass budget ended. The source did nothing wrong, so it is not a fault
#: of the pass (``source_ok``), but its health record still has to say that it did not answer.
BUDGET_CUT_ERROR = "the pass budget ended this fetch before the source answered; it is read again next pass"


def _stored_deferred(state: dict) -> list[str]:
    """The units the last pass's budget left for this pass, in the order it left them."""
    stored = state.get("fetch_deferred")
    return list(dict.fromkeys(item for item in stored if isinstance(item, str))) if isinstance(stored, list) else []


def _fetch_order(sources: Sequence[Source], state: dict) -> list[Source]:
    """The sources in the order this pass reads them: the ones the last pass's budget deferred first.

    A source the budget cut short, or that failed, is not in the list: it had its turn, so it goes behind the
    deferred ones and one slow source cannot keep the sources after it waiting for ever. The rest keep the
    configured order.
    """
    first = [source for identifier in _stored_deferred(state) for source in sources if source.id == identifier]
    return [*first, *(source for source in sources if source not in first)]


def _set_deferred(state: dict, identifiers: Sequence[str]) -> None:
    """Record which due units the pass budget left for the next pass; the key exists only while any are waiting."""
    if identifiers:
        state["fetch_deferred"] = list(identifiers)
    else:
        state.pop("fetch_deferred", None)


def _discard_pending(source: Source) -> None:
    """Forget the validators or cursors a dropped window staged on its source.

    A source stages them in ``fetch`` and writes them in ``commit``. Committing into a throwaway document empties
    that staging without advancing anything the state holds; a later ``commit`` for the same source (one that is
    only carrying candidates) would otherwise write the dropped window's validators.
    """
    commit = getattr(source, "commit", None)
    if commit is not None:
        commit({})


def _record_cut(state: dict, source: Source, now: int) -> None:
    """Note a source whose fetch the pass budget ended: its window is dropped whole, so no cursor or validator moves."""
    _discard_pending(source)
    LOG.warning("source %s: the pass budget ended its fetch; it is read again next pass", source.id)
    _record_health(state, source.id, now, ok=False, error=BUDGET_CUT_ERROR)


def _adobe_turn(
    upstream: BudgetedHttp, state: dict, kev: frozenset[str], kev_known: bool, now: int, **language_kwargs: str
) -> tuple[bool, str]:
    """Run the Adobe Commerce pass inside the budget: ``(ok, status)`` with status ``ran``, ``deferred`` or ``cut``.

    Deferred means the budget was spent before it could start, so it is read first next pass. Cut means the budget
    ended one of its requests: the pass reads its bulletin list before anything else and records nothing when that
    fails, so a failure that came with a refused request is the budget's and not the source's. It is told when the
    budget is spent (``out_of_time``) so that a detail page the budget cut is not counted as one Adobe failed.
    """
    if upstream.expired():
        return True, "deferred"
    refused = upstream.refused
    ok = core.adobe_pass(state, upstream, kev, kev_known, now, out_of_time=upstream.expired, **language_kwargs)
    if upstream.refused > refused:
        return True, "cut"
    return ok, "ran"


def _drop_removed_sources(
    state: dict, declared_ids: Collection[str], enabled_ids: Collection[str], *, complete: bool
) -> None:
    """Discard a removed source's unclassified work, validators, cursors and health record.

    The first three have to go together. Dropping the carry while keeping the validators lets a re-added source
    with an unchanged feed answer ``304`` on its next read, so the candidates just discarded could not be
    recovered from the feed at all; a kept changedetection cursor does the same to a page whose
    ``last_changed`` has not moved again. ``carry`` is the source of truth for what is still owed.

    Removal is not disablement: a source still declared in the configuration with ``enabled: false`` is simply
    not polled, so its carry, validators and cursors stay. Only a source missing from ``declared_ids`` was
    discarded. Health is kept for a source that still runs only: a record for a source nobody polls would
    outlive the reason it existed.

    ``complete`` says every declared id could be resolved. When it is False one declared id is still an
    ``${NAME}`` reference, so the set cannot tell a removed source from stored work under the id that reference
    previously expanded to; nothing is pruned then, because removal is undecidable and keeping stored work is
    the safe direction. Health still follows the enabled sources.
    """
    carried = state.setdefault("carry", {})
    if not complete:
        LOG.info(
            "a declared source id cannot be resolved; keeping stored source work until the configuration resolves it"
        )
    else:
        for stale in [source_id for source_id in carried if source_id not in declared_ids]:
            carried.pop(stale, None)
        for stored in (state.get("feeds"), state.get("changedetection")):
            if isinstance(stored, dict):
                for stale in [source_id for source_id in stored if source_id not in declared_ids]:
                    stored.pop(stale, None)
    health = state.get("source_health")
    if isinstance(health, dict):
        for stale in [source_id for source_id in health if source_id not in enabled_ids]:
            health.pop(stale, None)


def _fetch_due(record: object, now: int, interval: int) -> bool:
    """Whether a source is due for a fetch, given the last attempt the state recorded.

    The last *attempt* decides, not only the last success: a source whose fetch failed is due again on the very
    next pass, because waiting out its interval would turn one transient error into an outage for the whole
    window. A successful attempt becomes due once its age reaches the interval.
    """
    health = record if isinstance(record, dict) else {}
    if health.get("ok") is not True:
        return True
    at = health.get("at")
    if not isinstance(at, int) or isinstance(at, bool):
        return True
    return now - at >= interval


def _record_health(state: dict, source_id: str, now: int, *, ok: bool, items: int = 0, error: str = "") -> None:
    """Record this window's outcome for one source; the last success survives a later failure.

    This answers the question the run history cannot: *which* feed is broken right now. ``ok_at`` is preserved
    so a source that answered an hour ago and fails now shows both facts rather than looking dead since boot.
    The error text is the message a human needs, and the caller redacts it before it is stored.
    """
    health = state.setdefault("source_health", {})
    previous = health.get(source_id)
    previous = previous if isinstance(previous, dict) else {}
    ok_at = now if ok else previous.get("ok_at", 0)
    health[source_id] = {
        "at": now,
        "ok": ok,
        "ok_at": ok_at if isinstance(ok_at, int) and not isinstance(ok_at, bool) else 0,
        "items": items,
        "error": error,
    }


def _last_success(state: dict, source_id: str) -> int:
    """The epoch of a source's last successful window, or 0 when no success is on record.

    Read before ``_record_health`` writes this pass's outcome, so it is the success *before* the one now being
    classified: the point from which an outage is measured (see ``core.classify_new``). A removed or disabled
    source has no record, and neither has one that never answered, so the plain age rule applies to both.
    """
    health = state.get("source_health")
    record = health.get(source_id) if isinstance(health, dict) else None
    ok_at = record.get("ok_at") if isinstance(record, dict) else 0
    return ok_at if isinstance(ok_at, int) and not isinstance(ok_at, bool) and ok_at > 0 else 0


def _reset_validators_on_policy_change(state: dict, policy: object) -> None:
    """Drop stored feed validators when the scope changed.

    A ``304`` means "the feed is unchanged", not "nothing in it is new to you": an entry outside the old
    policy was dropped before classification, so after a watchlist change the cached answer hides exactly the
    advisory that just became in scope. One full read per source after a change is the price of not missing it.
    """
    digest = hashlib.sha256(repr(policy).encode("utf-8")).hexdigest()
    if state.get("policy_digest") == digest:
        return
    state["feeds"] = {}
    state["policy_digest"] = digest


def _namespaced(item: core.Item, source_id: str) -> core.Item:
    """Give an item a source-scoped guid: two feeds may both publish guid ``1`` for unrelated advisories.

    The publisher's guid is kept exactly: a namespace is a scope, not a rewriting. Transforming the value here
    would let two distinct advisories share one identity, and the second would look already claimed and be
    dropped silently.
    """
    return replace(item, guid=f"{source_id}:{item.guid}")


def _source_windows(state: dict) -> dict:
    return state.setdefault("windows", {})


def run_pass(
    cfg: Config,
    sources: list[Source],
    notifiers: list,
    *,
    http: Http = urllib_http,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    dry_run: bool = False,
    lock_blocking: bool = True,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Run one pass under the state lock: exit 0 when every owed message landed, 1 on any fault.

    The lock is held for the whole read/classify/deliver/write transaction, so the scheduler, the web
    UI's "run now" and a CLI ``once`` can never deliver the same pending message twice or overwrite each
    other's state. ``lock_blocking=False`` returns :data:`PASS_BUSY` immediately when another pass holds it,
    so the web UI can say nothing ran.

    The time the pass spends waiting on upstream servers is bounded by ``cfg.pass_budget_seconds``, measured on
    ``monotonic`` so that a step of the wall clock cannot stretch or shorten it (see ``budget``). Work the budget
    leaves undone is deferred and recorded, and a pass that deferred some still exits 0: it is incomplete, not
    failed. Delivery is outside the budget.

    The blocking default has no timeout: every store waits for the holder however long that takes, so a pass
    that never finishes keeps each later blocking caller waiting. It returns 1 only when a store refuses the lock
    outright (``LockBusy`` on a blocking call) or cannot be used (``StoreUnavailable``), which is the failure the
    CLI and scheduler already report.
    """
    store = cfg.store()
    if dry_run:
        return _run_pass(
            cfg, store, sources, notifiers, http=http, clock=clock, sleep=sleep, monotonic=monotonic, dry_run=True
        )
    try:
        with store.lock(blocking=lock_blocking):
            return _run_pass(
                cfg, store, sources, notifiers, http=http, clock=clock, sleep=sleep, monotonic=monotonic, dry_run=False
            )
    except LockBusy:
        LOG.warning("another pass holds the state lock; skipped this run")
        return 1 if lock_blocking else PASS_BUSY
    except StoreUnavailable as exc:
        # A missing driver or an unreachable server is a deployment fault: the pass did not run, and saying so
        # with the code the caller already reports is better than a traceback out of the scheduler.
        LOG.error("%s; the pass did not run", exc)
        return 1


def _run_pass(
    cfg: Config,
    store: Store,
    sources: list[Source],
    notifiers: list,
    *,
    http: Http,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
    dry_run: bool,
) -> int:
    """The pass itself; ``run_pass`` owns the state lock around it."""
    now = int(clock())
    # Started with the lock held, so time spent waiting for the lock is not time spent upstream. Everything that
    # reads from another server goes through ``upstream``; delivery below is handed the plain ``http``.
    budget = PassBudget(cfg.pass_budget_seconds, monotonic)
    upstream = BudgetedHttp(http, budget)
    try:
        stored = store.load()
    except (SourceError, StoreUnavailable) as exc:
        # An unavailable store reads like an unreadable document here, and for the same reason: treating it
        # as absent would re-seed the state and replay history the moment the server came back.
        LOG.error("%s; not re-seeding", exc)
        return 1
    try:
        policy = watchlist.load_policy(watchlist.active_path(cfg.watchlist_path, cfg.state_path))
    except SourceError as exc:
        # /watchlist writes this document, so an unreadable one is a state the program can reach on its own. A
        # failed pass that says so, like an unreadable state document, beats an exception out of the scheduler.
        LOG.error("%s; the pass did not run", exc)
        return 1
    core.HIDDEN_SOURCE_HOSTS = cfg.hidden_source_hosts
    # The language of the text the four steps below write (``messages``).
    language_kwargs = {"language": cfg.language}

    state = core.new_state() if stored is None else stored
    # A pass may deliver or drop an entry written before ownership was recorded; settle that before anything
    # leaves a queue, so delivery writes the same history the inbox displays.
    core._ensure_ownership(state)
    _reset_validators_on_policy_change(state, policy)
    state.setdefault("parked", [])
    core._prune(state, now)
    if not dry_run:
        # After ownership was settled above, which reads the snapshots it is about to move.
        retention.retire_deliveries(state, cfg.state_path, now)
    # Both of these must come from the state document that is actually written: a detached dict never
    # reaches disk, so the first window was lost and the 24h cache was never persisted.
    windows = _source_windows(state)
    stored_windows = dict(windows)  # what the previous pass observed, for the gap check
    cache = state.setdefault("cache", {})
    live_guids: set[str] = set()
    gap = False
    source_ok = True
    kev, kev_known = load_kev(upstream, cfg.state_path.with_name(KEV_CACHE_NAME), save=not dry_run)
    intel = core.Intel(upstream, cache, clock, sleep, nvd_key=cfg.nvd_api_key, remaining=upstream.remaining)
    # Re-evaluate before classification: both share one NVD budget, and a busy news day must not starve a due
    # watch of the measurement that could escalate it. A watch created later this pass is evaluated next pass.
    # Every clause of the decision reads a source's own numbers, so both entry points take the resolved block:
    # the global one is the fallback, never a second opinion about a source that states its own.
    # The CVEs a delivered message left unmeasured are drained here, one source in turn, inside the same stage: the
    # refresh share of the pass budget bounds their time with the daily re-scores, ``enrichment.PER_PASS`` their count.
    work = enrichment.select(state, now)
    outcomes: dict[str, str] = {}
    core.reevaluate(
        state,
        intel,
        kev,
        kev_known,
        now,
        "",
        thresholds=cfg.thresholds,
        source_thresholds=cfg.source_thresholds,
        work=work,
        outcomes=outcomes,
        **language_kwargs,
    )
    enrichment.served(state, work, outcomes)

    fetched_ids: set[str] = set()
    answered: list[tuple[object, object]] = []
    # What the pass budget keeps from this pass. A unit it never started is deferred, and the next pass starts with
    # it. A source whose fetch it ended has had its turn: it is read again, but behind the deferred ones.
    deferred_ids: list[str] = []
    cut_short = 0
    adobe_ok, adobe_status = True, ""
    # The Adobe Commerce pass runs after classification, unless the budget deferred it last time: then it goes first.
    adobe_first = cfg.adobe_commerce and ADOBE_UNIT in _stored_deferred(state)
    upstream.stage = FETCH_STAGE
    if adobe_first:
        adobe_ok, adobe_status = _adobe_turn(upstream, state, kev, kev_known, now, **language_kwargs)
    for source in _fetch_order(sources, state):
        interval = cfg.source_intervals.get(source.id)
        health = state.get("source_health")
        if interval and not _fetch_due(health.get(source.id) if isinstance(health, dict) else None, now, interval):
            # Polling is throttled; re-evaluation, escalation and delivery still run for this source below, and
            # a source with carried candidates still joins the fairness rotation.
            LOG.debug("source %s: not due until %ds after its last fetch", source.id, interval)
            continue
        if source.kind != "webhook" and upstream.expired():
            # The fetch stage is over. A webhook source reads no network, so the budget cannot help it; this one
            # is deferred whole, with no health recorded, and the next pass reads it first.
            deferred_ids.append(source.id)
            continue
        refused = upstream.refused
        try:
            window = source.fetch(upstream, state)
        except Exception as exc:  # a source fault fails the pass but keeps state
            if upstream.refused > refused:
                # The budget ended a request of this fetch, so the fault is the budget's and not the source's.
                _record_cut(state, source, now)
                cut_short += 1
                continue
            LOG.error("source %s: %s: %s; state kept", source.id, type(exc).__name__, exc)
            source_ok = False
            _record_health(
                state,
                source.id,
                now,
                ok=False,
                error=redact(f"{type(exc).__name__}: {exc}", secret_values(cfg)),
            )
            continue  # other sources still bootstrap; this one is seeded when it first answers
        if upstream.refused > refused:
            # A window that came back after a request of its fetch was refused may be partial, and a source need not
            # check: dropping it whole costs one read next pass, while adopting it could skip an advisory for ever.
            _record_cut(state, source, now)
            cut_short += 1
            continue
        window = SourceWindow(
            source.id,
            tuple(_namespaced(item, source.id) for item in window.items),
            window.truncated,
            window.host,
        )
        previous = stored_windows.get(source.id)
        # Only a source that knows its own page size can prove it returned a complete window (a FreshRSS
        # export, a changedetection watch). An RSS/Atom feed is bounded by its publisher, so a rotation
        # there is undetectable; see docs/configuration.md#gap-detection.
        # An empty previous window proves nothing: the source had no entries, so "no overlap" is expected and a
        # gap there would reject every later full window forever.
        if window.truncated and previous and not set(previous) & {item.guid for item in window.items}:
            LOG.error(
                "source %s: window gap: the window is full (%d entries) and shares none with the previous "
                "pass; items may have been missed. Keeping the last trusted window and deferring this source",
                source.id,
                len(window.items),
            )
            # Fail closed: do not adopt a window we cannot trust. The next pass compares against the same
            # trusted window, so a genuinely recovered export clears the gap and a damaged one keeps failing.
            gap = True
            _record_health(
                state,
                source.id,
                now,
                ok=False,
                error=(
                    "window gap: the window is full and shares no entry with the previous pass; "
                    "the source is deferred until it answers a complete window"
                ),
            )
            continue
        fetched_ids.add(source.id)
        live_guids.update(item.guid for item in window.items)
        # The window is written together with the results below: advancing it here would let a checkpoint
        # after another source persist this one's new window before its candidates were classified.
        answered.append((source, window))

    # Written with the first save below, so the next pass finds the deferral. Losing it would cost only the order:
    # a source that was never read is still due.
    _set_deferred(state, deferred_ids)
    # The fetch stage is over; what was captured is classified in the rest of the budget.
    upstream.stage = CLASSIFY_STAGE

    carried = state.setdefault("carry", {})
    enabled_ids = {source.id for source in sources}
    answered_now = {source.id for source, _ in answered}
    # Only a source removed from the configuration may have its stored work discarded; one that is merely
    # disabled is not polled, but it keeps its carry, validators and cursors for when it comes back.
    _drop_removed_sources(state, cfg.declared_source_ids, enabled_ids, complete=cfg.declared_source_ids_complete)
    carried = state["carry"]

    # One work list for fairness: freshly fetched sources and sources whose only remaining work is carried
    # candidates. A busy healthy source must not take every slot while a failed source's captured candidates
    # wait, so both kinds share the rotation and the per-source share.
    units: list[tuple[object, object]] = [(source, window) for source, window in answered]
    units += [(source, None) for source in sources if source.id not in answered_now and carried.get(source.id)]
    if len(units) > 1:
        turn = int(state.get("classify_turn", 0)) % len(units)
        units = units[turn:] + units[:turn]
        state["classify_turn"] = turn + 1

    # What the state already owns, read once: an out-of-scope webhook retry must not record a disposition for
    # an identifier that a queued or parked message owns and will report itself.
    claimed_before = core._claimed(state)
    budget_carried = 0
    for source, window in units:
        if window is None:
            host = ""
            items = []
        else:
            host = window.host
            items = []
            for item in window.items:
                if core.passes_filter(item, policy):
                    items.append(item)
                elif source.kind == "webhook":
                    # An out-of-scope webhook entry gets a terminal disposition, so the inbox can release it
                    # instead of letting irrelevant entries fill the capacity that real advisories need. The
                    # guid is already namespaced, and classification claims ``src:<namespaced guid>``; another
                    # prefix here would not match the identity the inbox cleanup looks for. A retry the sender
                    # makes after a scope change must not overwrite a queued message's own identifier.
                    identity = f"src:{item.guid}"
                    if identity not in claimed_before:
                        state["seen"].setdefault(identity, {"at": now, "outcome": "filtered"})
        # Items carried from an earlier pass come first: the window they arrived in is already gone.
        earlier = [core.item_from_state(row) for row in carried.pop(source.id, [])]
        # The policy may have changed while these waited: scope applies at classification time, not arrival.
        earlier = [item for item in earlier if core.passes_filter(item, policy)]
        trusted = {item.guid for item in earlier}
        if earlier:
            known = {item.guid for item in items}
            items = [item for item in earlier if item.guid not in known] + items
        seeded = state.setdefault("seeded", {})
        if source.id not in seeded:
            # Bootstrap is per source: a source that failed on the first pass must still be seeded when it
            # recovers, or its history would be delivered as news.
            candidates = core.seed(state, items, now)
            seeded[source.id] = True
            LOG.info(
                "first run on %s: %d older item(s) recorded as backlog, %d recent item(s) queued",
                source.id,
                len(items) - len(candidates),
                len(candidates),
            )
        else:
            candidates = items
        left = core.classify_new(
            state,
            candidates,
            intel,
            kev,
            kev_known,
            now,
            host,
            policy,
            share=max(1, core.DELIVERY_CAP // max(1, len(units))),
            trusted=trusted,
            # Recorded on every queued message so routing can match on the source and its products.
            source_id=source.id,
            # One source is classified at a time, so its own block is the whole rule set for these items.
            thresholds=cfg.thresholds_for(source.id),
            # Admission counts only what delivery may send now, so a queue held by quiet hours cannot block a
            # newly arrived critical advisory.
            quiet_hours=cfg.quiet_hours,
            **language_kwargs,
            # An item published while this source could not be read is news, however old it is by now.
            last_ok=_last_success(state, source.id),
            # Once the pass budget is spent the rest is carried to the next pass rather than looked up.
            out_of_time=intel.out_of_time,
        )
        if left:
            carried[source.id] = [core.item_to_state(item) for item in left]
            if intel.out_of_time():
                budget_carried += len(left)  # carried either way; the spent budget makes the pass incomplete
        if window is not None:
            windows[source.id] = [item.guid for item in window.items]
            # Health follows the same rule as the validators: recorded only once this window's candidates are
            # durable, so a crash between fetch and classification cannot report a source healthy for work it
            # never queued.
            _record_health(state, source.id, now, ok=True, items=len(window.items))
        # A source that tracks a cursor advances it only now: the same write carries the candidates, so a crash
        # between fetch and classification cannot skip an advisory forever.
        commit = getattr(source, "commit", None)
        if commit is not None:
            commit(state)
        if source.kind == "webhook":
            # An entry is done once every identity it can be known by is claimed: the ids its text names, and the
            # source-scoped identity used for an entry that names none. Both namespaces must match what
            # classification records, or a delivered entry stays in the inbox forever.
            inbox = state.get("webhook_inbox", {}).get(source.id, [])
            claimed = core._claimed(state)
            kept = []
            for entry in inbox:
                # An entry is done when every identity it can be known by has been claimed: the ids its text
                # names, the structured ids it queued, or its source-scoped identity (filtered out of scope, or
                # delivered with no identifier at all). The scoped identity is built exactly as the source door
                # builds it -- the guid kept raw -- so a value no reader can spell still matches what
                # classification recorded.
                identities = list(
                    core.extract_ids(
                        str(entry.get("title", "")), str(entry.get("summary", "")), str(entry.get("link", ""))
                    )
                )
                structured = entry.get("explicit_ids")
                if isinstance(structured, list):
                    # Validated and normalised at intake by the payload mapper; classification claims an item's
                    # explicit ids when it has any, so the text-only set would never match a structured entry.
                    identities.extend(str(identifier) for identifier in structured if isinstance(identifier, str))
                identities = list(dict.fromkeys(identities))
                guid = str(entry.get("guid", ""))
                scoped = f"src:{source.id}:{guid}"
                done = scoped in claimed or (
                    bool(identities) and all(identifier in claimed for identifier in identities)
                )
                if not done:
                    kept.append(entry)
            if kept:
                state.setdefault("webhook_inbox", {})[source.id] = kept
            else:
                state.get("webhook_inbox", {}).pop(source.id, None)

        if not dry_run:
            store.save(state)

    if not carried:
        state.pop("carry", None)  # only after every source has written into the attached dict

    # Nothing was read, but only the pass budget is to blame: that is an incomplete pass like any other (the sources
    # are deferred, and the next one starts with them), not the failure the branch below reports.
    budget_only = source_ok and bool(deferred_ids or cut_short)
    if stored is None and not fetched_ids and not cfg.adobe_commerce and not budget_only:
        # Nothing was read, so nothing may be classified -- but a failed read is evidence, and a fresh install
        # whose every source fails would otherwise report "not polled yet" for each of them while this log line
        # said otherwise. Only health is added to a seeded-empty document: no validator moves and no source is
        # marked seeded, so the first pass that does read a feed still bootstraps that feed's history.
        if not dry_run and state.get("source_health"):
            store.save(state)
        LOG.error("no source could be read on the first pass; only the source health was recorded")
        return 1

    # Prune once, against every window fetched this pass, and only for sources that answered: a source
    # outage must not wipe that source's retry deadlines.
    # Carried candidates keep their retry clocks: they are no longer in any window but are still owed a pass.
    carried_guids = {
        str(row.get("guid"))
        for rows in (state.get("carry") or {}).values()
        if isinstance(rows, list)
        for row in rows
        if isinstance(row, dict)
    }
    # Compared exactly: an identity is never rewritten, so a document written before this version already
    # holds the publisher's raw guid and its clock key is the same value read back.
    live = live_guids | carried_guids
    for key in ("enrich_retry", "enrich_pending"):
        kept = {guid for guid in (state.get(key) or {}) if guid.split(":", 1)[0] not in fetched_ids or guid in live}
        core._prune_enrich_clock(state, key, kept)

    if cfg.adobe_commerce and not adobe_first:
        adobe_ok, adobe_status = _adobe_turn(upstream, state, kev, kev_known, now, **language_kwargs)
    if adobe_status == "deferred":
        deferred_ids.append(ADOBE_UNIT)
    elif adobe_status == "cut":
        cut_short += 1
    _set_deferred(state, deferred_ids)

    if dry_run:
        for entry in state["pending"][: core.DELIVERY_CAP]:
            print(f"[dry-run] tag={entry['tag']}\n{entry['title']}\n{entry['body']}")
        LOG.info("dry run: nothing sent, no state written")
        return 0 if source_ok and adobe_ok and not gap else 1

    store.save(state)  # pending is durable before the first POST
    queued, parked_before = len(state["pending"]), len(state["parked"])
    if not notifiers and state["pending"]:
        LOG.error(
            "no enabled notifiers: %d message(s) stay pending until one is configured",
            len(state["pending"]),
        )
        delivered = False
    else:
        delivered = core.deliver(
            state,
            notifiers,
            http,
            now,
            persist=lambda: store.save(state),
            routes=cfg.routes,
            default=cfg.default_notifiers,
            digest=cfg.digest,
            quiet_hours=cfg.quiet_hours,
            **language_kwargs,
        )
    store.save(state)
    newly_parked = len(state["parked"]) - parked_before
    sent = queued - len(state["pending"]) - newly_parked
    LOG.info("pass: %d sent, %d parked, %d pending", sent, newly_parked, len(state["pending"]))
    if state["parked"]:
        LOG.warning(
            "%d message(s) parked, newest %s; run release-parked or drop-parked",
            len(state["parked"]),
            core._audit_ids(state["parked"][-1]),
        )
    code = 0 if delivered and not state["parked"] and not gap and adobe_ok and source_ok else 1
    runs = state.setdefault("runs", [])
    record = {
        # ``at`` is the pass start, which is what the record has always held; ``finished_at`` is what
        # readiness and the metric must measure, or a slow pass reports itself stale on completion.
        "at": now,
        "finished_at": int(clock()),
        "sent": sent,
        "parked": newly_parked,
        "pending": len(state["pending"]),
        "code": code,
    }
    left_over = len(deferred_ids) + cut_short + budget_carried
    if left_over:
        # Incomplete is an outcome beside the code, not a failure: the budget did what it is for, and the work it
        # left is stored. A pass that left none writes neither key, as a record has always looked.
        record["outcome"] = "incomplete"
        record["deferred"] = left_over
        LOG.warning(
            "pass incomplete: the %d s budget left %d unit(s) of work (%d deferred, %d cut short, %d candidate(s))",
            cfg.pass_budget_seconds,
            left_over,
            len(deferred_ids),
            cut_short,
            budget_carried,
        )
    runs.append(record)
    del runs[:-200]
    store.save(state)  # the run record is part of the state, so it must be saved
    return code


def state_cache(stored: dict | None) -> dict:
    return stored["cache"] if stored is not None else {}


def build_plugins(cfg: Config, env: Mapping[str, str]):
    sources = [build_source(dict(entry), env) for entry in cfg.sources]
    notifiers = [build_notifier(dict(entry), env) for entry in cfg.notifiers]
    return sources, notifiers


def attach_redaction(secrets: list[str]) -> RedactFilter:
    redactor = RedactFilter(secrets)
    LOG.addFilter(redactor)
    return redactor


def redact(text: str, secrets: Sequence[str]) -> str:
    """The log filter's replacement applied to text that is about to be rendered or logged.

    ``RedactFilter`` owns the replacement, including the percent-encoded form of a token in a URL;
    routing a rendered error through it keeps a page and the log from disagreeing about what is a
    secret.
    """
    record = logging.LogRecord(LOG.name, logging.INFO, __file__, 0, text, None, None)
    RedactFilter(secrets).filter(record)
    return record.getMessage()
