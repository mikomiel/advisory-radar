"""One pass of the pipeline: fetch sources, classify, re-evaluate, deliver."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from pathlib import Path

from . import core
from .config import Config
from .http import Http, RedactFilter, urllib_http
from .kev import load_kev
from .notifiers import build_notifier
from .plugins import Source
from .sources import build_source
from .state import SourceError, load_state_document, save_state
from .watchlist import load_policy

LOG = logging.getLogger("advisory_radar")

KEV_CACHE_NAME = "kev.json"


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
) -> int:
    """Exit 0 when every owed message landed (or none was owed); 1 on any fault, with state kept."""
    now = int(clock())
    try:
        stored = load_state_document(cfg.state_path, core.STATE_SCHEMA, "advisory state")
    except SourceError as exc:
        LOG.error("%s; not re-seeding", exc)
        return 1
    policy = load_policy(cfg.watchlist_path) if cfg.watchlist_path else _default_policy()
    core.HIDDEN_SOURCE_HOSTS = cfg.hidden_source_hosts

    kev, kev_known = load_kev(http, cfg.state_path.with_name(KEV_CACHE_NAME), save=not dry_run)
    intel = core.Intel(http, state_cache(stored), clock, sleep)

    gap = False
    source_ok = True
    windows = _source_windows(stored) if stored is not None else {}
    state = core.new_state() if stored is None else stored
    state.setdefault("parked", [])
    core._prune(state, now)

    for source in sources:
        try:
            window = source.fetch(http)
        except Exception as exc:  # a source fault fails the pass but keeps state
            LOG.error("source %s: %s: %s; state kept", source.id, type(exc).__name__, exc)
            source_ok = False
            if stored is None:
                return 1  # a first run has nothing to persist safely
            continue
        previous = windows.get(source.id)
        if window.truncated and previous is not None and not set(previous) & {item.guid for item in window.items}:
            LOG.error(
                "source %s: window gap: the window is full (%d entries) and shares none with the previous "
                "pass; items may have been missed",
                source.id,
                len(window.items),
            )
            gap = True
        windows[source.id] = [item.guid for item in window.items]
        for key in ("enrich_retry", "enrich_pending"):
            core._prune_enrich_clock(state, key, {item.guid for item in window.items})
        items = [item for item in window.items if core.passes_filter(item, policy)]
        if stored is None:
            candidates = core.seed(state, items, now)
            LOG.info(
                "first run on %s: %d older item(s) marked delivered, %d recent item(s) queued",
                source.id,
                len(items) - len(candidates),
                len(candidates),
            )
        else:
            candidates = items
        core.classify_new(state, candidates, intel, kev, kev_known, now, window.host, policy)
        if not dry_run:
            save_state(cfg.state_path, state)

    adobe_ok = core.adobe_pass(state, http, kev, kev_known, now) if cfg.adobe_commerce else True
    core.reevaluate(state, intel, kev, kev_known, now, "")

    if dry_run:
        for entry in state["pending"][: core.DELIVERY_CAP]:
            print(f"[dry-run] tag={entry['tag']}\n{entry['title']}\n{entry['body']}")
        LOG.info("dry run: nothing sent, no state written")
        return 0 if source_ok and adobe_ok else 1

    save_state(cfg.state_path, state)  # pending is durable before the first POST
    queued, parked_before = len(state["pending"]), len(state["parked"])
    delivered = core.deliver(state, notifiers, http, now)
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
    if not dry_run:
        runs = state.setdefault("runs", [])
        runs.append({"at": now, "sent": sent, "parked": newly_parked, "pending": len(state["pending"]), "code": code})
        del runs[:-200]
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
