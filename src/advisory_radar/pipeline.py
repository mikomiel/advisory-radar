"""One pass of the pipeline: fetch sources, classify, re-evaluate, deliver."""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from . import core
from .config import Config, secret_values
from .http import Http, RedactFilter, urllib_http
from .kev import load_kev
from .notifiers import build_notifier
from .plugins import Source, SourceWindow
from .sources import build_source
from .state import LockBusy, SourceError, load_state_document, save_state, state_lock
from .watchlist import load_policy

LOG = logging.getLogger("advisory_radar")

KEV_CACHE_NAME = "kev.json"


def _drop_disabled_sources(state: dict, enabled_ids: set[str]) -> None:
    """Discard a removed source's unclassified work, its stored validators and its health record.

    The first two have to go together. Dropping the carry while keeping the validators lets a re-enabled source
    with an unchanged feed answer ``304`` on its next read, so the candidates just discarded could not be
    recovered from the feed at all. ``carry`` is the source of truth for what is still owed. Health is kept for
    a configured source only: a record for a source nobody configured would outlive the reason it existed.
    """
    carried = state.setdefault("carry", {})
    feeds = state.get("feeds")
    for stale in [source_id for source_id in carried if source_id not in enabled_ids]:
        carried.pop(stale, None)
        if isinstance(feeds, dict):
            feeds.pop(stale, None)
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
    return core.Item(
        f"{source_id}:{item.guid}",
        item.title,
        item.link,
        item.summary,
        item.published,
        item.explicit,
        item.source_title,
        item.source_url,
    )


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
) -> int:
    """Run one pass under the state lock: exit 0 when every owed message landed, 1 on any fault.

    The lock is held for the whole read/classify/deliver/write transaction, so the scheduler, the web
    UI's "run now" and a CLI ``once`` can never deliver the same pending message twice or overwrite each
    other's state. ``lock_blocking=False`` returns 1 immediately when another pass holds it.
    """
    if dry_run:
        return _run_pass(cfg, sources, notifiers, http=http, clock=clock, sleep=sleep, dry_run=True)
    try:
        with state_lock(cfg.state_path, blocking=lock_blocking):
            return _run_pass(cfg, sources, notifiers, http=http, clock=clock, sleep=sleep, dry_run=False)
    except LockBusy:
        LOG.warning("another pass holds the state lock; skipped this run")
        return 1


def _run_pass(
    cfg: Config,
    sources: list[Source],
    notifiers: list,
    *,
    http: Http,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    dry_run: bool,
) -> int:
    """The pass itself; ``run_pass`` owns the state lock around it."""
    now = int(clock())
    try:
        stored = load_state_document(cfg.state_path, core.STATE_SCHEMA, "advisory state")
    except SourceError as exc:
        LOG.error("%s; not re-seeding", exc)
        return 1
    policy = load_policy(cfg.watchlist_path) if cfg.watchlist_path else _default_policy()
    core.HIDDEN_SOURCE_HOSTS = cfg.hidden_source_hosts

    state = core.new_state() if stored is None else stored
    _reset_validators_on_policy_change(state, policy)
    state.setdefault("parked", [])
    core._prune(state, now)
    # Both of these must come from the state document that is actually written: a detached dict never
    # reaches disk, so the first window was lost and the 24h cache was never persisted.
    windows = _source_windows(state)
    stored_windows = dict(windows)  # what the previous pass observed, for the gap check
    cache = state.setdefault("cache", {})
    live_guids: set[str] = set()
    gap = False
    source_ok = True
    kev, kev_known = load_kev(http, cfg.state_path.with_name(KEV_CACHE_NAME), save=not dry_run)
    intel = core.Intel(http, cache, clock, sleep, nvd_key=cfg.nvd_api_key)
    # Re-evaluate before classification: both share one NVD budget, and a busy news day must not starve a due
    # watch of the measurement that could escalate it. A watch created later this pass is evaluated next pass.
    # Every clause of the decision reads a source's own numbers, so both entry points take the resolved block:
    # the global one is the fallback, never a second opinion about a source that states its own.
    core.reevaluate(
        state, intel, kev, kev_known, now, "", thresholds=cfg.thresholds, source_thresholds=cfg.source_thresholds
    )

    fetched_ids: set[str] = set()
    answered: list[tuple[object, object]] = []
    for source in sources:
        interval = cfg.source_intervals.get(source.id)
        health = state.get("source_health")
        if interval and not _fetch_due(health.get(source.id) if isinstance(health, dict) else None, now, interval):
            # Polling is throttled; re-evaluation, escalation and delivery still run for this source below, and
            # a source with carried candidates still joins the fairness rotation.
            LOG.debug("source %s: not due until %ds after its last fetch", source.id, interval)
            continue
        try:
            window = source.fetch(http, state)
        except Exception as exc:  # a source fault fails the pass but keeps state
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
        window = SourceWindow(
            source.id,
            tuple(_namespaced(item, source.id) for item in window.items),
            window.truncated,
            window.host,
        )
        previous = stored_windows.get(source.id)
        # Only a source that knows its own page size can prove it returned a complete window (a FreshRSS
        # export, a changedetection watch). An RSS/Atom feed is bounded by its publisher, so a rotation
        # there is undetectable; see README, "Sources".
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

    carried = state.setdefault("carry", {})
    enabled_ids = {source.id for source in sources}
    answered_now = {source.id for source, _ in answered}
    # Only a source that still exists may push work through carry, or keep a cached answer to it.
    _drop_disabled_sources(state, enabled_ids)
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
                    # prefix here would not match the identity the inbox cleanup looks for.
                    state["seen"].setdefault(f"src:{item.guid}", {"at": now, "outcome": "filtered"})
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
                "first run on %s: %d older item(s) marked delivered, %d recent item(s) queued",
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
        )
        if left:
            carried[source.id] = [core.item_to_state(item) for item in left]
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
                # An entry is done when either disposition has been recorded for it: the ids its text names
                # (classified in scope) or its source-scoped identity (filtered out of scope, or delivered with
                # no identifier at all). The scoped identity is built exactly as the source door builds it --
                # the guid kept raw -- so a value no reader can spell still matches what classification recorded.
                identities = core.extract_ids(
                    str(entry.get("title", "")), str(entry.get("summary", "")), str(entry.get("link", ""))
                )
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
            save_state(cfg.state_path, state)

    if not carried:
        state.pop("carry", None)  # only after every source has written into the attached dict

    if stored is None and not fetched_ids and not cfg.adobe_commerce:
        # Nothing was read, so nothing may be classified -- but a failed read is evidence, and a fresh install
        # whose every source fails would otherwise report "not polled yet" for each of them while this log line
        # said otherwise. Only health is added to a seeded-empty document: no validator moves and no source is
        # marked seeded, so the first pass that does read a feed still bootstraps that feed's history.
        if not dry_run and state.get("source_health"):
            save_state(cfg.state_path, state)
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

    adobe_ok = core.adobe_pass(state, http, kev, kev_known, now) if cfg.adobe_commerce else True

    if dry_run:
        for entry in state["pending"][: core.DELIVERY_CAP]:
            print(f"[dry-run] tag={entry['tag']}\n{entry['title']}\n{entry['body']}")
        LOG.info("dry run: nothing sent, no state written")
        return 0 if source_ok and adobe_ok and not gap else 1

    save_state(cfg.state_path, state)  # pending is durable before the first POST
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
            persist=lambda: save_state(cfg.state_path, state),
            routes=cfg.routes,
            default=cfg.default_notifiers,
        )
    save_state(cfg.state_path, state)
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
    runs.append(
        {
            # ``at`` is the pass start, which is what the record has always held; ``finished_at`` is what
            # readiness and the metric must measure, or a slow pass reports itself stale on completion.
            "at": now,
            "finished_at": int(clock()),
            "sent": sent,
            "parked": newly_parked,
            "pending": len(state["pending"]),
            "code": code,
        }
    )
    del runs[:-200]
    save_state(cfg.state_path, state)  # the run record is part of the state, so it must be saved
    return code


def state_cache(stored: dict | None) -> dict:
    return stored["cache"] if stored is not None else {}


def _default_policy():
    """The packaged default watchlist (allow every Debian package, no product scope)."""
    return load_policy(Path(__file__).with_name("watchlist.default.json"))


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
