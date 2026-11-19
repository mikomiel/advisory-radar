#!/usr/bin/env python3
"""Measure what a growing state costs, for the JSON and the SQLite store.

The state is one document that every store keeps whole: a page loads all of it and a save writes all of it. This
script builds a synthetic history of a chosen size, puts it in each store and measures

* the size of the document and of what the store keeps on disk,
* how long a load and a save take, and the Python memory each needs; the save is of a document with one more
  record in it each time, because SQLite writes nothing for a row whose text has not changed,
* how long the Alerts list, the same list with a text filter and one advisory page take, over the real web app; a
  history with no delivery (``--deliveries 0``, or a ``--seen`` below 5, whose default fifth is none) has no advisory
  page to open, so that time is reported as unavailable: ``n/a`` in the tables, null with ``--json``,
* what a pass writes: the number of saves, the bytes each one handed to the kernel as a multiple of the document,
  and what one acknowledgement wrote, for a pass with nothing to do and for a pass that delivers the most messages
  it may. SQLite writes nothing for a save whose text is the stored text, so the saves of a pass differ.

Run it from a checkout, in the repository root. The defaults measure a small history, the project's target (100,000
seen identifiers and 20,000 deliveries) and the same target spread over four years, so that half of its deliveries
are older than the retention line and the first pass has something to archive:

    uv run python scripts/benchmark_state.py
    uv run python scripts/benchmark_state.py --profiles target --stores json --repeat 3
    uv run python scripts/benchmark_state.py --seen 300000 --deliveries 60000 --json
    uv run python scripts/benchmark_state.py --check        # exit 1 when a measured row misses the budgets

Everything is synthetic and the same for one ``--seed``: no real state, source or channel is read, and nothing
leaves the machine. The work directory decides the filesystem the saves are measured on, so pick the one the data
volume uses with ``--workdir``; the report states the cost of one small ``fsync`` there, so that a number can be
read against the disk it came from. The memory columns are what Python allocated above the baseline
(``tracemalloc``), not the resident size of the process. PostgreSQL is not measured: it needs a server, and it
keeps the same indented text the SQLite store does.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import gc
import hashlib
import json
import logging
import os
import platform
import random
import secrets
import shutil
import sqlite3
import statistics
import sys
import tempfile
import time
import tracemalloc
import urllib.parse
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import NamedTuple

from advisory_radar import core, pipeline, retention
from advisory_radar.kev import KEV_URL
from advisory_radar.plugins import SourceWindow
from advisory_radar.runtime import Runtime
from advisory_radar.state import serialize_json
from advisory_radar.web import _advisory_token, create_app

#: 2026-10-21 16:26:40 UTC. A fixed clock keeps the retention line, and so every run, the same.
NOW = 1792600000
DAY = core.DAY
#: The budgets the maintainer set for the target (issue 86), in seconds.
ALERTS_BUDGET = 1.0
SAVE_BUDGET = 2.0
STORES = ("json", "sqlite")


class Profile(NamedTuple):
    seen: int
    deliveries: int
    span_days: int


PROFILES = {
    "small": Profile(1_000, 200, 365),
    "target": Profile(100_000, 20_000, 365),
    "aged": Profile(100_000, 20_000, 4 * 365),
}
DEFAULT_PROFILES = tuple(PROFILES)

#: How many identifiers one delivered message names, in turn: 1.8 on average, which is a few CVEs per advisory.
IDS_PER_DELIVERY = (1, 2, 1, 3, 2)
#: What the rest of the seen set holds, and in what share: the dispositions that deliver nothing.
FILLER_OUTCOMES = ("backlog", "suppressed", "alias", "not-security", "filtered")
FILLER_WEIGHTS = (35, 35, 5, 10, 15)
PRODUCTS = ("widget", "gadget", "sprocket", "flange", "bracket", "gizmo")
SOURCE_IDS = ("vendor-feed", "mirror-feed", "tracker-feed")
#: A word that appears in the titles of about a sixth of the delivered messages.
FILTER_TEXT = "sprocket"
#: The number of the first advisory a measured pass delivers: above any identifier ``build_state`` counts up to.
NEWS_FIRST = 9_000_000

WATCHLIST = {
    "schema": "security-watchlist.v1",
    "debian_source_packages": ["curl"],
    "excluded_products": [],
    "products": [],
}


# --- the synthetic history ----------------------------------------------------------------------------------------


def _snapshot(rng: random.Random, identifiers: list[str], at: int) -> dict:
    """One delivery event with the keys ``core._delivery_snapshot`` writes, filled with invented values."""
    tag = rng.choice(("critical", "warning"))
    product = rng.choice(PRODUCTS)
    return {
        "tag": tag,
        "source_id": rng.choice(SOURCE_IDS),
        "source": f"{product.title()} {rng.randint(1, 9)}.{rng.randint(0, 20)} security update",
        "title": f"{tag.upper()}: {identifiers[0]} in {product}",
        "link": f"https://vendor.example.net/advisories/{identifiers[0]}",
        "kind": "new",
        "ids": list(identifiers),
        "cves": list(identifiers),
        "kev_only": [],
        "products": [product],
        "levels": dict.fromkeys(identifiers, tag),
        "scores": {identifier: round(rng.uniform(7.0, 10.0), 1) for identifier in identifiers},
        "delivered_to": ["hook"],
        "at": at,
        "outcome": "delivered",
        "queued_at": at - 90,
    }


def build_state(seen: int, deliveries: int, *, span_days: int, seed: int, now: int = NOW) -> dict:
    """A state with exactly ``seen`` identifiers and ``deliveries`` delivery events, spread over ``span_days``.

    Each delivery names one to three identifiers, and each of those has a seen record that points at it, as
    ``core._delivered`` writes them. The remaining identifiers are dispositions that delivered nothing. Records
    are added oldest first, so the document is in the order a real one grows in.
    """
    if deliveries < 0 or seen < deliveries:
        raise ValueError("a delivery names at least one seen identifier: --seen must not be below --deliveries")
    rng = random.Random(seed)
    spare = seen - deliveries
    sizes = []
    for number in range(deliveries):
        extra = min(IDS_PER_DELIVERY[number % len(IDS_PER_DELIVERY)] - 1, spare)
        spare -= extra
        sizes.append(1 + extra)
    kinds = [True] * deliveries + [False] * (seen - sum(sizes))
    rng.shuffle(kinds)
    state = core.new_state()
    state["seen"] = records = {}
    state["deliveries"] = events = {}
    start, span = now - span_days * DAY, span_days * DAY
    serial = delivered = 0
    for index, is_delivery in enumerate(kinds):
        at = start + index * span // len(kinds)
        year = time.gmtime(at).tm_year
        if is_delivery:
            identifiers = []
            for _ in range(sizes[delivered]):
                serial += 1
                identifiers.append(f"CVE-{year}-{serial:05d}")
            key = hashlib.sha256(f"{seed}:{delivered}".encode()).hexdigest()[:16]
            events[key] = _snapshot(rng, identifiers, at)
            for identifier in identifiers:
                records[identifier] = {"at": at, "outcome": "delivered", "delivery": key}
            delivered += 1
        else:
            serial += 1
            outcome = rng.choices(FILLER_OUTCOMES, FILLER_WEIGHTS)[0]
            identifier = (
                f"src:bench:https://feed.example.net/items/{serial}"
                if outcome == "filtered"
                else f"CVE-{year}-{serial:05d}"
            )
            records[identifier] = {"at": at, "outcome": outcome}
    # The parts that are bounded stay at the size they reach: 200 run records, a source that has been seeded.
    state["seeded"] = {"bench": True}
    state["runs"] = [
        {"at": t, "finished_at": t + 4, "sent": 0, "parked": 0, "pending": 0, "code": 0}
        for t in (now - (200 - number) * 900 for number in range(200))
    ]
    return state


# --- measuring ----------------------------------------------------------------------------------------------------


def _stats(samples: list[float]) -> dict:
    return {"median": statistics.median(samples), "min": min(samples), "max": max(samples), "runs": len(samples)}


def _timed(function: Callable[[], object], repeat: int) -> dict:
    samples = []
    for _ in range(repeat):
        gc.collect()
        start = time.perf_counter()
        function()
        samples.append(time.perf_counter() - start)
    return _stats(samples)


def _peak_mib(function: Callable[[], object]) -> float:
    """The Python memory ``function`` allocated above what was already held, at its highest point."""
    gc.collect()
    tracemalloc.start()
    try:
        before, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        function()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return (peak - before) / 2**20


def _written_bytes() -> int | None:
    """Bytes this process has handed to ``write``, from ``/proc``; None where the kernel does not say."""
    try:
        for line in Path("/proc/self/io").read_text(encoding="ascii").splitlines():
            if line.startswith("wchar:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


def _fsync_ms(directory: Path, samples: int = 20) -> float:
    """The median time of writing 4 KiB to a new file in ``directory`` and syncing it."""
    times = []
    for number in range(samples):
        path = directory / f"fsync-{number}"
        with path.open("wb") as handle:
            handle.write(b"x" * 4096)
            handle.flush()
            start = time.perf_counter()
            os.fsync(handle.fileno())
            times.append(time.perf_counter() - start)
        path.unlink()
    return statistics.median(times) * 1000


@contextlib.contextmanager
def _quiet_logging() -> Iterator[None]:
    """No log lines while measuring, and the previous level back afterwards: a caller may be a test run."""
    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(previous)


def _size_on_disk(directory: Path, store: str) -> int:
    names = ["state.json"] if store == "json" else ["state.db", "state.db-wal"]
    return sum((directory / name).stat().st_size for name in names if (directory / name).exists())


# --- the web app, without a web client ----------------------------------------------------------------------------


class _Client:
    """Just enough of an ASGI client to sign in and fetch pages: the script needs only the standard library."""

    def __init__(self, app) -> None:
        self._app = app
        self._cookie = ""

    async def request(
        self, method: str, target: str, body: bytes = b"", content_type: str = ""
    ) -> tuple[int, list, bytes]:
        path, _, query = target.partition("?")
        headers = [(b"host", b"benchmark"), (b"accept", b"text/html")]
        if content_type:
            headers.append((b"content-type", content_type.encode()))
        if self._cookie:
            headers.append((b"cookie", self._cookie.encode()))
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": query.encode(),
            "root_path": "",
            "headers": headers,
            "client": ("127.0.0.1", 50000),
            "server": ("benchmark", 80),
        }
        pending = [{"type": "http.request", "body": body, "more_body": False}]
        sent: list[dict] = []

        async def receive() -> dict:
            return pending.pop(0) if pending else {"type": "http.disconnect"}

        async def send(message: dict) -> None:
            sent.append(message)

        await self._app(scope, receive, send)
        start = next(message for message in sent if message["type"] == "http.response.start")
        payload = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
        return start["status"], start["headers"], payload

    async def sign_in(self, token: str) -> None:
        form = urllib.parse.urlencode({"token": token}).encode()
        status, headers, _ = await self.request("POST", "/login", form, "application/x-www-form-urlencoded")
        cookie = next((value for name, value in headers if name == b"set-cookie"), b"")
        if status != 303 or not cookie:
            raise RuntimeError(f"sign-in answered {status}")
        self._cookie = cookie.decode().split(";", 1)[0]

    async def get(self, target: str) -> bytes:
        status, _, payload = await self.request("GET", target)
        if status != 200:
            raise RuntimeError(f"{target.split('?')[0]} answered {status}")
        return payload


async def _measure_pages(app, token: str, repeat: int, advisory: str | None) -> dict:
    """Time the pages; ``advisory`` is the token of the one to open, None for a history with no delivery to open."""
    client = _Client(app)
    await client.sign_in(token)
    pages = {"alerts": "/alerts", "alerts_filtered": f"/alerts?q={FILTER_TEXT}"}
    if advisory is not None:
        pages["advisory"] = f"/advisories/{advisory}"
    result = {}
    for name, target in pages.items():
        await client.get(target)  # the first request pays for imports and caches nothing a later one reuses
        samples = []
        for _ in range(repeat):
            gc.collect()
            start = time.perf_counter()
            await client.get(target)
            samples.append(time.perf_counter() - start)
        result[name] = _stats(samples)
    result.setdefault("advisory", None)  # unavailable, which the report prints as n/a
    gc.collect()
    tracemalloc.start()
    try:
        before, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        await client.get("/alerts")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    result["alerts_peak_mib"] = (peak - before) / 2**20
    return result


# --- a pass -------------------------------------------------------------------------------------------------------


def _http(method: str, url: str, headers: dict, body: object) -> tuple[int, dict, bytes]:
    """Answers every lookup a pass makes, for any CVE, with a critical score: no network, and the same every time."""
    if url.startswith(core.CVE_ORG_URL):
        metric = {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"}
        document = {
            "cveMetadata": {"cveId": url[len(core.CVE_ORG_URL) :], "state": "PUBLISHED"},
            "containers": {"cna": {"metrics": [{"cvssV3_1": metric}]}},
        }
        return 200, {}, json.dumps(document).encode()
    if url.startswith(core.EPSS_URL):
        data = [{"cve": cve, "epss": "0.50", "percentile": "0.99"} for cve in url[len(core.EPSS_URL) :].split(",")]
        return 200, {}, json.dumps({"data": data}).encode()
    if url == KEV_URL:
        return 200, {}, json.dumps({"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-2000-0001"}]}).encode()
    return 404, {}, b""


class _Feed:
    """A source that answers one fixed window, with the interface a configured source has."""

    kind = "feed"
    host = ""

    def __init__(self, source_id: str, items: list[core.Item]) -> None:
        self.id = source_id
        self._items = tuple(items)

    def fetch(self, http, state=None) -> SourceWindow:
        return SourceWindow(self.id, self._items, False, self.host)


class _Notifier:
    id = "hook"

    def __init__(self) -> None:
        self.sent = 0

    def send(self, entry, http) -> int:
        self.sent += 1
        return 200


class _CountingStore:
    """The store a pass saves into, recording every save: how long it took and how many bytes it wrote.

    ``sent`` says how many messages have gone out. The first save after a message went out is that message's
    acknowledgement: the pass records the one message in the document, and that save is measured on its own, because
    what it writes is the cost a message adds to a pass. A byte count is None where the kernel does not say.
    """

    def __init__(self, inner, sent: Callable[[], int] = lambda: 0) -> None:
        self._inner = inner
        self._sent = sent
        self._messages = 0
        self.saving = 0.0
        self.bytes_per_save: list[int | None] = []
        self.acknowledgements: list[int | None] = []

    def load(self):
        return self._inner.load()

    def save(self, document: dict) -> None:
        before = _written_bytes()
        start = time.perf_counter()
        self._inner.save(document)
        self.saving += time.perf_counter() - start
        after = _written_bytes()
        written = None if before is None or after is None else after - before
        self.bytes_per_save.append(written)
        sent = self._sent()
        if sent > self._messages:
            self.acknowledgements.append(written)
        self._messages = sent

    def lock(self, *, blocking: bool = True):
        return self._inner.lock(blocking=blocking)


def _news(count: int, now: int) -> list[core.Item]:
    """``count`` advisories published an hour ago, each naming a CVE the history has never seen.

    The history counts its identifiers up from 1, so seven-digit numbers are free for any history a person would
    measure; ``_measure_passes`` checks that the pass delivered them all, because a claimed one is delivered to no one.
    """
    items = []
    for number in range(count):
        cve = f"CVE-2026-{NEWS_FIRST + number}"
        title = f"Vendor advisory {cve}"
        items.append(
            core.Item(f"news-{number}", title, f"https://vendor.example.net/{cve}", f"Fixes {cve}.", now - 3600, (cve,))
        )
    return items


def _known(values: list[int | None]) -> list[int] | None:
    """``values`` when each of them is a number; None when the kernel left any of them out."""
    return None if None in values else values


def _run_pass(runtime: Runtime, items: list[core.Item], now: int) -> dict:
    """One real pass over the store, with every save recorded."""
    cfg = runtime.cfg
    notifier = _Notifier()
    counting = _CountingStore(cfg.store(), lambda: notifier.sent)
    original = type(cfg).store
    type(cfg).store = lambda self: counting
    try:
        gc.collect()
        start = time.perf_counter()
        code = pipeline.run_pass(
            cfg, [_Feed("bench", items)], [notifier], http=_http, clock=lambda: float(now), sleep=lambda seconds: None
        )
        elapsed = time.perf_counter() - start
    finally:
        type(cfg).store = original
    per_save = _known(counting.bytes_per_save)
    return {
        "code": code,
        "sources": 1,
        "delivered": notifier.sent,
        "saves": len(counting.bytes_per_save),
        "acknowledgements": len(counting.acknowledgements),
        "saving_seconds": counting.saving,
        "save_bytes": per_save,
        "written_bytes": None if per_save is None else sum(per_save),
        "acknowledgement_bytes": _known(counting.acknowledgements),
        "seconds": elapsed,
    }


def _document_size(document: dict, store: str) -> int:
    """The bytes of the text a store keeps for ``document``: the JSON store writes it compact, SQLite indented."""
    return len(serialize_json(document, compact=(store == "json")).encode("utf-8"))


def _measure_passes(runtime: Runtime, store: str, now: int) -> dict:
    """A pass with nothing to do, then a pass that delivers the most messages one pass may."""
    kept = runtime.cfg.store()
    idle_document = _document_size(kept.load(), store)
    idle = _run_pass(runtime, [], now)
    busy_document = _document_size(kept.load(), store)
    busy = _run_pass(runtime, _news(core.DELIVERY_CAP, now), now)
    if busy["delivered"] != core.DELIVERY_CAP:
        raise RuntimeError(
            f"the full pass delivered {busy['delivered']} of {core.DELIVERY_CAP} messages: "
            "the history already claims an identifier the pass was given, so its numbers would not be a full pass"
        )
    after_document = _document_size(kept.load(), store)
    for result, size in ((idle, idle_document), (busy, busy_document)):
        saves = result["save_bytes"]
        result["x_document"] = None if saves is None else [written / size for written in saves]
    delivered = busy["delivered"]
    acknowledged = busy["acknowledgement_bytes"]
    return {
        "idle": idle,
        "full": busy,
        # What one acknowledgement save wrote, to record what one message adds to the document.
        "per_acknowledgement_bytes": statistics.fmean(acknowledged) if acknowledged else None,
        "recorded_per_message_bytes": (after_document - busy_document) / delivered if delivered else None,
    }


# --- one history in one store -------------------------------------------------------------------------------------


def _write_config(directory: Path, storage: str) -> Path:
    (directory / "watchlist.json").write_text(json.dumps(WATCHLIST), encoding="utf-8")
    lines = [
        "sources:",
        "  - id: bench",
        "    type: rss",
        "    url: https://feeds.example.com/bench",
        "notifiers:",
        "  - id: hook",
        "    type: webhook",
        "    url: https://hooks.example.com/hook",
        f"state_path: {json.dumps(str(directory / 'state.json'))}",
        f"watchlist: {json.dumps(str(directory / 'watchlist.json'))}",
    ]
    if storage:
        lines.append(f"storage: {json.dumps(storage)}")
    path = directory / "config.yml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _probe(state: dict) -> str | None:
    """The newest delivered identifier: the advisory page that has a snapshot to read; None when none was delivered."""
    for identifier, record in reversed(state["seen"].items()):
        if record["outcome"] == "delivered":
            return identifier
    return None


def time_load_and_save(kept, state: dict, *, repeat: int, now: int) -> dict:
    """Time a load and a save of ``state`` through ``kept``, and measure their memory; leave ``state`` as found.

    Each timed save is of a document with one more seen record in it, as every save of a pass is of a document that
    differs from the last: SQLite does not write a row whose new text is byte for byte the old, so saving one
    unchanged document again and again would time a save that does nothing.
    """
    added: list[str] = []

    def save_a_change() -> None:
        added.append(f"CVE-2099-{len(added):05d}")
        state["seen"][added[-1]] = {"at": now, "outcome": "backlog"}
        kept.save(state)

    result = {
        "save": _timed(save_a_change, repeat),
        "load": _timed(kept.load, repeat),
        "save_peak_mib": _peak_mib(save_a_change),
        "load_peak_mib": _peak_mib(kept.load),
    }
    for identifier in added:
        del state["seen"][identifier]
    kept.save(state)  # the store holds the history as it was built again, for the pages and the passes
    return result


def measure_store(state: dict, store: str, directory: Path, *, repeat: int, now: int) -> dict:
    """Put ``state`` into one store under ``directory`` and measure it."""
    directory.mkdir(parents=True)
    storage = "" if store == "json" else f"sqlite:///{directory / 'state.db'}"
    token = secrets.token_urlsafe(32)
    runtime = Runtime.build(
        _write_config(directory, storage), {"ADVISORY_RADAR_AUTH_TOKEN": token}, clock=lambda: float(now)
    )
    kept = runtime.cfg.store()
    kept.save(state)  # the first write creates the file; it is not a measurement
    result = {
        "store": store,
        "seen": len(state["seen"]),
        "live_deliveries": len(state["deliveries"]),
        "document_bytes": _document_size(state, store),
        "disk_bytes": _size_on_disk(directory, store),
    }
    result |= time_load_and_save(kept, state, repeat=repeat, now=now)
    app = create_app(runtime, {"ADVISORY_RADAR_AUTH_TOKEN": token}, clock=lambda: float(now))
    probe = _probe(state)
    advisory = None if probe is None else _advisory_token(probe)
    result["pages"] = asyncio.run(_measure_pages(app, token, repeat, advisory))
    result["passes"] = _measure_passes(runtime, store, now)
    return result


def measure_profile(
    name: str, profile: Profile, stores: tuple[str, ...], base: Path, *, repeat: int, seed: int
) -> dict:
    """Build a history, let a pass archive what is past the retention line, and measure each store with the rest."""
    state = build_state(profile.seen, profile.deliveries, span_days=profile.span_days, seed=seed)
    directory = base / name
    directory.mkdir()
    before = len(serialize_json(state, compact=True))
    start = time.perf_counter()
    retired = retention.retire_deliveries(state, directory / "state.json", NOW)
    seconds = time.perf_counter() - start
    archived = sum(path.stat().st_size for path in directory.glob(f"{retention.ARCHIVE_PREFIX}*.json"))
    result = {
        "profile": name,
        "span_days": profile.span_days,
        "retention": {
            "retired": retired,
            "live_deliveries": len(state["deliveries"]),
            "seconds": seconds,
            "archive_bytes": archived,
            "state_bytes_before": before,
            "state_bytes_after": len(serialize_json(state, compact=True)),
        },
        "stores": [],
    }
    for store in stores:
        result["stores"].append(measure_store(state, store, directory / store, repeat=repeat, now=NOW))
    return result


# --- the report ---------------------------------------------------------------------------------------------------


def _mib(value: float | None) -> str:
    return "n/a" if value is None else f"{value / 2**20:.1f}"


def _seconds(stats: dict | None) -> str:
    return "n/a" if stats is None else f"{stats['median']:.3f}"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def _per_save(multiples: list[float] | None) -> str:
    """What each save wrote, as a multiple of the document, in the order the pass saved."""
    return "n/a" if multiples is None else " ".join(f"{value:.1f}" for value in multiples)


def render(report: dict) -> str:
    env = report["environment"]
    out = [
        f"Python {env['python']} on {env['system']} {env['machine']}, {env['cpus']} CPUs, SQLite {env['sqlite']}; "
        f"a 4 KiB fsync takes {env['fsync_ms']:.2f} ms here. Seed {env['seed']}, {env['repeat']} runs, medians.",
        "",
    ]
    size, memory, writes, shed = [], [], [], []
    for profile in report["profiles"]:
        retired = profile["retention"]
        shed.append(
            [
                profile["profile"],
                f"{profile['span_days']}",
                str(retired["retired"]),
                str(retired["live_deliveries"]),
                _mib(retired["archive_bytes"]),
                f"{_mib(retired['state_bytes_before'])} to {_mib(retired['state_bytes_after'])}",
                f"{retired['seconds']:.3f}",
            ]
        )
        for row in profile["stores"]:
            pages, passes = row["pages"], row["passes"]
            label = [profile["profile"], row["store"]]
            size.append(
                [
                    *label,
                    str(row["seen"]),
                    str(row["live_deliveries"]),
                    _mib(row["document_bytes"]),
                    _mib(row["disk_bytes"]),
                    _seconds(row["load"]),
                    _seconds(row["save"]),
                    _seconds(pages["alerts"]),
                    _seconds(pages["alerts_filtered"]),
                    _seconds(pages["advisory"]),
                ]
            )
            memory.append(
                [
                    *label,
                    f"{row['load_peak_mib']:.0f}",
                    f"{row['save_peak_mib']:.0f}",
                    f"{pages['alerts_peak_mib']:.0f}",
                ]
            )
            for kind in ("idle", "full"):
                run = passes[kind]
                writes.append(
                    [
                        *label,
                        kind,
                        str(run["saves"]),
                        _mib(run["written_bytes"]),
                        _per_save(run["x_document"]),
                        f"{run['saving_seconds']:.2f}",
                        f"{run['seconds']:.2f}",
                    ]
                )
    out += ["State size and latency (seconds)", ""]
    out.append(
        _table(
            [
                "profile",
                "store",
                "seen",
                "live deliveries",
                "document MiB",
                "on disk MiB",
                "load",
                "save",
                "/alerts",
                "/alerts?q",
                "advisory",
            ],
            size,
        )
    )
    out += ["", "Python memory above the baseline, at the peak (MiB)", ""]
    out.append(_table(["profile", "store", "load", "save", "/alerts"], memory))
    out += ["", "What a pass writes (a full pass delivers the most messages one pass may)", ""]
    out.append(
        _table(
            ["profile", "store", "pass", "saves", "written MiB", "per save, x document", "in saves s", "whole pass s"],
            writes,
        )
    )
    for profile in report["profiles"]:
        for row in profile["stores"]:
            passes = row["passes"]
            if passes["per_acknowledgement_bytes"] is not None:
                out.append(
                    f"\n{profile['profile']} {row['store']}: one acknowledgement wrote "
                    f"{_mib(passes['per_acknowledgement_bytes'])} MiB to record "
                    f"{passes['recorded_per_message_bytes']:.0f} bytes of new state."
                )
    out += ["", "What the first pass archives (deliveries older than two years)", ""]
    out.append(
        _table(["profile", "span days", "archived", "kept", "archive MiB", "state MiB", "archive seconds"], shed)
    )
    verdicts = report["budget"]
    out += ["", f"Budget: /alerts under {verdicts['alerts']:.1f} s, a save under {verdicts['save']:.1f} s."]
    out += [
        f"  {entry['profile']} {entry['store']}: /alerts {entry['alerts']:.3f} s, save {entry['save']:.3f} s: "
        + ("PASS" if entry["ok"] else "FAIL")
        for entry in verdicts["rows"]
    ]
    return "\n".join(out)


def _budget(profiles: list[dict], alerts: float, save: float) -> dict:
    rows = []
    for profile in profiles:
        for row in profile["stores"]:
            seen = row["pages"]["alerts"]["median"]
            wrote = row["save"]["median"]
            rows.append(
                {
                    "profile": profile["profile"],
                    "store": row["store"],
                    "alerts": seen,
                    "save": wrote,
                    "ok": seen <= alerts and wrote <= save,
                }
            )
    return {"alerts": alerts, "save": save, "rows": rows}


def _environment(directory: Path, seed: int, repeat: int) -> dict:
    return {
        "python": platform.python_version(),
        "system": platform.system(),
        "machine": platform.machine(),
        "cpus": os.cpu_count(),
        "sqlite": sqlite3.sqlite_version,
        "fsync_ms": _fsync_ms(directory),
        "bytes_written_known": _written_bytes() is not None,
        "seed": seed,
        "repeat": repeat,
    }


def _parse(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--profiles", default=",".join(DEFAULT_PROFILES), help=f"comma list of {', '.join(PROFILES)}")
    parser.add_argument("--stores", default=",".join(STORES), help="comma list of json, sqlite")
    parser.add_argument("--seen", type=int, help="measure one custom history with this many seen identifiers")
    parser.add_argument("--deliveries", type=int, help="... and this many delivery events (default: a fifth of --seen)")
    parser.add_argument("--span-days", type=int, default=365, help="... spread over this many days (default 365)")
    parser.add_argument("--repeat", type=int, default=5, help="runs per timing; the median is reported")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--workdir", type=Path, help="where to write the stores: the filesystem that is measured")
    parser.add_argument("--json", action="store_true", help="print every measurement as JSON instead of the tables")
    parser.add_argument("--check", action="store_true", help="exit 1 when a row misses the budgets")
    parser.add_argument("--alerts-budget", type=float, default=ALERTS_BUDGET, help="seconds for /alerts")
    parser.add_argument("--save-budget", type=float, default=SAVE_BUDGET, help="seconds for a state save")
    return parser.parse_args(argv)


def _select(args: argparse.Namespace) -> tuple[tuple[str, ...], dict[str, Profile]] | str:
    """The stores and the histories to measure, or the sentence that says why the arguments cannot be measured."""
    stores = tuple(name.strip() for name in args.stores.split(",") if name.strip())
    if not stores or any(name not in STORES for name in stores):
        return f"--stores takes {', '.join(STORES)}"
    if args.repeat < 1 or args.span_days < 1:
        return "--repeat and --span-days take at least 1"
    if args.seen is not None:
        deliveries = args.deliveries if args.deliveries is not None else args.seen // 5
        if not 0 <= deliveries <= args.seen:
            return "--deliveries lies between 0 and --seen: every delivery names a seen identifier"
        return stores, {"custom": Profile(args.seen, deliveries, args.span_days)}
    names = [name.strip() for name in args.profiles.split(",") if name.strip()]
    if not names or any(name not in PROFILES for name in names):
        return f"--profiles takes {', '.join(PROFILES)}"
    return stores, {name: PROFILES[name] for name in names}


def main(argv: list[str] | None = None) -> int:
    args = _parse(argv)
    chosen = _select(args)
    if isinstance(chosen, str):
        print(chosen, file=sys.stderr)
        return 2
    stores, selected = chosen
    if args.workdir:
        args.workdir.mkdir(parents=True, exist_ok=True)
    base = Path(tempfile.mkdtemp(prefix="advisory-radar-bench-", dir=args.workdir))
    try:
        with _quiet_logging():
            report = {"environment": _environment(base, args.seed, args.repeat), "profiles": []}
            for name, profile in selected.items():
                report["profiles"].append(
                    measure_profile(name, profile, stores, base, repeat=args.repeat, seed=args.seed)
                )
    finally:
        shutil.rmtree(base, ignore_errors=True)
    report["budget"] = _budget(report["profiles"], args.alerts_budget, args.save_budget)
    print(json.dumps(report, indent=2) if args.json else render(report))
    if args.check and not all(row["ok"] for row in report["budget"]["rows"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
