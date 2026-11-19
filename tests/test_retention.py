"""Retention: a pass moves delivery events older than two years into a dated archive file beside the state.

Behaviour, not mechanism: nearly every case runs a real pass over a real state file and reads the files it leaves.
Seen records stay where they are, because they are what deduplication reads; only the event a seen record points at
moves, and a seen record whose event moved is a shape the pages and the ownership rules already handle. The pages are
read through the signed-in client over the state a pass really wrote, so the wording they show for it is pinned where
an operator reads it, and one case compares the deployment guide with the file name the code writes.

A "no archive" assertion is worth something only if the helper that looks for archives can find one, so every negative
case shares ``archives()`` with the positive cases that prove it does.
"""

from __future__ import annotations

import copy
import errno
import json
import logging
import os
import re
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NamedTuple

import pytest

from advisory_radar import core, pipeline, retention
from advisory_radar import state as state_module
from advisory_radar.config import Config, load_config
from advisory_radar.http import RedactFilter
from advisory_radar.plugins import SourceWindow
from advisory_radar.state import save_state
from advisory_radar.web import _advisory_token
from test_ui import INBOX_ROW_RE, make_client, page_ids, sign_in

LOG = logging.getLogger("advisory_radar")
ROOT = Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs" / "deployment.md"

NOW = 1792600000  # 2026-10-21 16:26:40 UTC
DAY = 86400
TWO_YEARS = 730 * DAY
#: The line a pass at NOW cuts at: midnight UTC at the start of the day 730 days before NOW's day. It is spelled out
#: with the calendar so that the cases do not repeat the arithmetic they pin.
LINE = int((datetime.fromtimestamp(NOW, UTC) - timedelta(days=730)).replace(hour=0, minute=0, second=0).timestamp())
#: The documented name: ``state-archive-<UTC day of the line>-<digest of the content>.json``.
ARCHIVE_NAME = re.compile(r"state-archive-(\d{4}-\d{2}-\d{2})-([0-9a-f]{12})\.json")
#: The dash a page prints in a cell that has no value. Written as an escape so that this file holds no dash.
NO_VALUE = "\u2014"
CVE = "CVE-2026-4242"

CVE_ORG = {
    "cveMetadata": {"cveId": CVE, "state": "PUBLISHED"},
    "containers": {
        "cna": {"metrics": [{"cvssV3_1": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"}}]}
    },
}
EPSS = {"data": [{"cve": CVE, "epss": "0.50", "percentile": "0.99"}]}
KEV = {"catalogVersion": "1", "vulnerabilities": []}

#: The three records the page cases read. MOVED was delivered 800 days ago and escalated 20 days ago, so its first
#: event moves and its escalation stays. KEPT was delivered 700 days ago and stays whole. UNPOINTED is a seen record
#: that no snapshot ever described, like one an older version wrote.
MOVED = "CVE-2024-6001"
KEPT = "CVE-2025-6002"
UNPOINTED = "CVE-2023-6003"


@pytest.fixture(autouse=True)
def _detach_log_redaction():
    """A runtime installs a log filter; one test's secrets must not redact the next test's output."""
    yield
    for installed in list(LOG.filters):
        if isinstance(installed, RedactFilter):
            LOG.removeFilter(installed)


def fake_http(method, url, headers, body):
    if "cveawg.mitre.org" in url:
        return 200, {}, json.dumps(CVE_ORG).encode()
    if "api.first.org" in url:
        return 200, {}, json.dumps(EPSS).encode()
    if "cisa.gov" in url:
        return 200, {"ETag": "k1"}, json.dumps(KEV).encode()
    return 404, {}, b""


class FakeNotifier:
    def __init__(self) -> None:
        self.id = "fake"
        self.sent: list[dict] = []

    def send(self, entry, http):
        self.sent.append(entry)
        return 200


class WindowSource:
    """A source that returns a fixed window, so a test controls the items and their identities."""

    kind = "feed"

    def __init__(self, items) -> None:
        self.id = "test"
        self._items = tuple(items)
        self.host = ""

    def fetch(self, http, state=None):
        return SourceWindow(self.id, self._items, False, self.host)


def make_config(directory: Path) -> Config:
    (directory / "watchlist.json").write_text(
        json.dumps(
            {
                "schema": "security-watchlist.v1",
                "debian_source_packages": ["curl"],
                "excluded_products": [],
                "products": [],
            }
        )
    )
    cfg_path = directory / "config.yml"
    cfg_path.write_text(
        "sources:\n  - id: test\n    type: rss\n    url: https://feeds.example.com/rss\n"
        "notifiers:\n  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
        f"state_path: {directory}/state.json\n"
        f"watchlist: {directory}/watchlist.json\n"
    )
    return load_config(cfg_path, {})


def queue_entry(cve: str, *, kind: str = "new", tag: str = "critical", **extra) -> dict:
    """One queue entry, shaped like ``core.classify_new`` writes it."""
    entry = {
        "kind": kind,
        "tag": tag,
        "title": f"{tag.upper()}: {cve}",
        "body": "the rendered message",
        "ids": [cve],
        "fresh": [cve],
        "cves": [cve],
        "levels": {cve: tag},
        "scores": {cve: 9.8},
        "kev_only": [],
        "source": "Vendor Feed",
        "link": f"https://vendor.example.net/advisories/{cve}",
        "source_id": "test",
        "products": [],
    }
    entry.update(extra)
    return entry


def deliver(state: dict, cve: str, at: int, *, kind: str = "new", **extra) -> str:
    """Record one accepted delivery with the writer a pass uses, and return the id of the event it wrote."""
    before = set(state.get("deliveries", {}))
    core._delivered(state, queue_entry(cve, kind=kind, **extra), at, "delivered", ["fake"])
    (event_id,) = set(state["deliveries"]) - before
    return event_id


def write_state(cfg: Config, state: dict) -> None:
    state.setdefault("seeded", {})["test"] = True  # the source was bootstrapped on an earlier pass
    save_state(cfg.state_path, state)


def stored(cfg: Config) -> dict:
    return json.loads(cfg.state_path.read_text())


def archives(directory: Path) -> list[Path]:
    """Every file in a directory that is, or could be taken for, an archive: anything with ``archive`` in its name."""
    return sorted(path for path in directory.iterdir() if "archive" in path.name.lower())


def the_archive(directory: Path, *, apart_from: Path | None = None) -> Path:
    """The one archive in a directory, apart from one a case already holds; a readable failure when it is not one."""
    found = [path for path in archives(directory) if path != apart_from]
    assert len(found) == 1, f"expected one archive file, found {[path.name for path in found]}"
    return found[0]


def read_archive(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run_pass(cfg: Config, items=(), *, dry_run: bool = False, clock: int = NOW):
    notifier = FakeNotifier()
    code = pipeline.run_pass(
        cfg,
        [WindowSource(items)],
        [notifier],
        http=fake_http,
        clock=lambda: float(clock),
        sleep=lambda seconds: None,
        dry_run=dry_run,
    )
    return code, notifier


def undated_item() -> core.Item:
    """An item with no publication date that names ``CVE``: nothing about it says it is history."""
    return core.Item("g1", f"Vendor advisory {CVE}", "https://vendor.example.com/a1", f"Fixes {CVE}.", None, (CVE,))


# --- what moves ---------------------------------------------------------------------------------------------


def test_a_pass_moves_a_delivery_older_than_two_years_into_a_dated_archive_file(tmp_path):
    cfg = make_config(tmp_path)
    state = core.new_state()
    old = deliver(state, "CVE-2024-1111", NOW - 800 * DAY)
    young = deliver(state, "CVE-2025-2222", NOW - 700 * DAY)
    event = copy.deepcopy(state["deliveries"][old])
    write_state(cfg, state)

    code, _ = run_pass(cfg)

    assert code == 0
    path = the_archive(tmp_path)
    match = ARCHIVE_NAME.fullmatch(path.name)
    assert match, f"{path.name} is not state-archive-<day>-<digest>.json"
    assert match.group(1) == "2024-10-21", "the day in the name is the line the file was cut at"
    assert read_archive(path) == {
        "schema": "advisory-radar-archive.v1",
        "archived_at": NOW,
        "before": LINE,
        "deliveries": {old: event},
    }, "the snapshot is archived as the state held it"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600, "the archive is as private as the state"
    after = stored(cfg)
    assert old not in after["deliveries"], "an archived event leaves the state"
    assert young in after["deliveries"], "an event inside the two years stays"


def test_a_delivery_moves_only_when_it_lies_before_the_start_of_the_day_two_years_back(tmp_path):
    cfg = make_config(tmp_path)
    state = core.new_state()
    before_the_line = deliver(state, "CVE-2024-2001", LINE - 1)
    on_the_line = deliver(state, "CVE-2024-2002", LINE)
    # Older than 730 days to the second, but inside the day the line starts: a pass counts days, not instants.
    over_by_a_second = deliver(state, "CVE-2024-2003", NOW - TWO_YEARS - 1)
    write_state(cfg, state)

    run_pass(cfg)

    path = the_archive(tmp_path)
    assert set(read_archive(path)["deliveries"]) == {before_the_line}
    assert set(stored(cfg)["deliveries"]) == {on_the_line, over_by_a_second}


def test_a_delivery_on_the_line_moves_on_the_first_pass_of_the_next_day(tmp_path):
    cfg = make_config(tmp_path)
    state = core.new_state()
    on_the_line = deliver(state, "CVE-2024-3001", LINE)
    over_by_a_second = deliver(state, "CVE-2024-3002", NOW - TWO_YEARS - 1)
    write_state(cfg, state)
    run_pass(cfg)
    assert archives(tmp_path) == []
    assert set(stored(cfg)["deliveries"]) == {on_the_line, over_by_a_second}

    run_pass(cfg, clock=NOW + DAY)

    path = the_archive(tmp_path)
    document = read_archive(path)
    assert set(document["deliveries"]) == {on_the_line, over_by_a_second}
    assert document["before"] == LINE + DAY
    assert ARCHIVE_NAME.fullmatch(path.name).group(1) == "2024-10-22"
    assert stored(cfg)["deliveries"] == {}


def test_a_later_batch_goes_to_a_file_of_its_own_and_the_earlier_file_is_not_touched(tmp_path):
    cfg = make_config(tmp_path)
    state = core.new_state()
    first = deliver(state, "CVE-2024-4001", NOW - 800 * DAY)
    write_state(cfg, state)
    run_pass(cfg)
    earlier = the_archive(tmp_path)
    written = earlier.read_bytes()
    state = stored(cfg)
    # Inside the two years at NOW, outside them a day later.
    second = deliver(state, "CVE-2024-4002", LINE + 100)
    save_state(cfg.state_path, state)

    run_pass(cfg, clock=NOW + DAY)

    later = the_archive(tmp_path, apart_from=earlier)
    assert earlier.read_bytes() == written, "an archive is never rewritten or extended"
    assert set(read_archive(earlier)["deliveries"]) == {first}
    assert set(read_archive(later)["deliveries"]) == {second}
    assert stored(cfg)["deliveries"] == {}


def test_an_escalation_and_a_bulletin_older_than_two_years_move_too(tmp_path):
    cfg = make_config(tmp_path)
    state = core.new_state()
    escalation = deliver(state, "CVE-2024-5001", NOW - 800 * DAY, kind="escalation")
    bulletin = deliver(state, "APSB24-1", NOW - 800 * DAY, kind="adobe")
    write_state(cfg, state)

    run_pass(cfg)

    path = the_archive(tmp_path)
    assert set(read_archive(path)["deliveries"]) == {escalation, bulletin}
    assert stored(cfg)["deliveries"] == {}


@pytest.mark.parametrize(
    "event",
    [
        {"ids": ["CVE-2024-5001"]},
        {"ids": ["CVE-2024-5001"], "at": None},
        {"ids": ["CVE-2024-5001"], "at": "yesterday"},
        {"ids": ["CVE-2024-5001"], "at": True},
        {"ids": ["CVE-2024-5001"], "at": 0},
        {"ids": ["CVE-2024-5001"], "at": -5},
        {"ids": ["CVE-2024-5001"], "at": 1500000000.0},
        "not an object",
        None,
        42,
    ],
    ids=["no-at", "null", "text", "bool", "zero", "negative", "float", "string", "none", "number"],
)
def test_an_event_without_a_usable_time_is_never_moved(tmp_path, event):
    """A time that cannot be read is not evidence that the event is old, so the event stays where it is."""
    cfg = make_config(tmp_path)
    state = core.new_state()
    state["deliveries"] = {"odd": event}
    write_state(cfg, state)

    code, _ = run_pass(cfg)

    assert code == 0
    assert stored(cfg)["deliveries"] == {"odd": event}
    assert archives(tmp_path) == []


def test_a_pass_with_nothing_expired_creates_no_archive(tmp_path):
    cfg = make_config(tmp_path)
    state = core.new_state()
    deliver(state, "CVE-2025-6001", NOW - 700 * DAY)
    write_state(cfg, state)

    run_pass(cfg)

    assert archives(tmp_path) == []


@pytest.mark.parametrize("deliveries", [None, [], "none"], ids=["absent", "list", "text"])
def test_a_state_without_a_delivery_map_has_nothing_to_move(tmp_path, deliveries):
    state = core.new_state()
    if deliveries is not None:
        state["deliveries"] = deliveries

    assert retention.retire_deliveries(state, tmp_path / "state.json", NOW) == 0

    assert state.get("deliveries") == deliveries
    assert archives(tmp_path) == []


# --- what stays -----------------------------------------------------------------------------------------------


def test_a_seen_record_older_than_two_years_is_never_archived_whatever_its_outcome(tmp_path):
    """Deduplication reads the seen identifiers, so retention must not shorten the set, for any outcome."""
    cfg = make_config(tmp_path)
    state = core.new_state()
    old = NOW - 800 * DAY
    deliver(state, "CVE-2024-1501", old)
    state["seen"].update(
        {
            "CVE-2024-1502": {"at": old, "outcome": "backlog"},
            "CVE-2024-1503": {"at": old, "outcome": "suppressed"},
            "CVE-2024-1504": {"at": old, "outcome": "dropped"},
            "src:g-old": {"at": old, "outcome": "backlog"},
        }
    )
    write_state(cfg, state)
    before = copy.deepcopy(state["seen"])

    run_pass(cfg)

    assert stored(cfg)["seen"] == before
    path = the_archive(tmp_path)
    assert set(read_archive(path)) == {"schema", "archived_at", "before", "deliveries"}, "no seen record is archived"


def test_the_seen_record_stays_so_an_undated_item_naming_it_is_still_not_announced(tmp_path):
    """The undated item has no date that says "old", so only the seen record stops it from being news."""
    cfg = make_config(tmp_path)
    state = core.new_state()
    old = deliver(state, CVE, NOW - 800 * DAY)
    record = dict(state["seen"][CVE])
    write_state(cfg, state)

    code, notifier = run_pass(cfg, [undated_item()])

    path = the_archive(tmp_path)
    assert old in read_archive(path)["deliveries"], "the event moved"
    assert code == 0
    assert notifier.sent == [], "an archived identifier is still a duplicate"
    assert stored(cfg)["seen"][CVE] == record, "the record keeps its first-seen facts and its pointer to the event"


def test_the_same_undated_item_is_announced_when_nothing_has_seen_its_identifier(tmp_path):
    """The control for the test above: its silence is deduplication, not a lookup that failed."""
    cfg = make_config(tmp_path)
    write_state(cfg, core.new_state())

    code, notifier = run_pass(cfg, [undated_item()])

    assert code == 0
    assert len(notifier.sent) == 1


class Played(NamedTuple):
    """What a pass did on each of two clocks, and what the state held afterwards."""

    passes: list[tuple[list[dict], dict]]
    deliveries: dict
    archives: list[Path]


def queued_and_parked_state() -> tuple[dict, dict[str, int]]:
    """A state whose only owners are legacy: two old deliveries, and a parked and a queued message that name them.

    Each message was queued between the moment the delivered one was queued and the moment it was delivered, so the
    snapshot (which holds the earlier ``queued_at``) says the delivered message was owed first, while the seen
    record alone (which holds only the later ``at``) says the new one was. Neither queue entry carries ``fresh``,
    as one written before ownership was recorded does not.
    """
    state = core.new_state()
    delivered_at = NOW - 800 * DAY
    between = delivered_at - 1800
    events = {}
    for cve in ("CVE-2024-7001", "CVE-2024-7002"):
        events[cve] = deliver(state, cve, delivered_at, queued_at=delivered_at - 3600)
    parked = queue_entry(
        "CVE-2024-7001", attempts=3, queued_at=between, first_attempt_at=between, parked_at=between, sent_to=[]
    )
    queued = queue_entry("CVE-2024-7002", queued_at=between)
    for entry in (parked, queued):
        del entry["fresh"]
    state["parked"].append(parked)
    state["pending"].append(queued)
    return state, events


def test_moving_a_snapshot_changes_nothing_a_pass_does_with_queued_and_parked_work(tmp_path):
    """The same two passes, with the old snapshots kept and with them moved, send and store the same.

    Ownership is settled from the snapshots, so a pass that moved them first would hand each identifier to the
    message that merely mentions it. The case fails if the move runs before ``core._ensure_ownership``.
    """

    def play(label: str, *, retire: bool) -> Played:
        directory = tmp_path / label
        directory.mkdir()
        cfg = make_config(directory)
        write_state(cfg, queued_and_parked_state()[0])
        passes = []
        with pytest.MonkeyPatch.context() as patch:
            if not retire:
                patch.setattr(retention, "retire_deliveries", lambda state, state_path, now: 0)
            for clock in (NOW, NOW + 60):
                _, notifier = run_pass(cfg, clock=clock)
                after = stored(cfg)
                passes.append((notifier.sent, {key: value for key, value in after.items() if key != "deliveries"}))
        return Played(passes, stored(cfg)["deliveries"], archives(directory))

    kept = play("kept", retire=False)
    moved = play("moved", retire=True)

    events = set(queued_and_parked_state()[1].values())
    assert events <= set(kept.deliveries) and not events & set(moved.deliveries), "the two runs differ by the move"
    assert len(moved.archives) == 1 and kept.archives == []
    first_pass_state = kept.passes[0][1]
    assert first_pass_state["parked"][0]["fresh"] == [], "the parked message lost its claim to the delivered one"
    assert [entry["fresh"] for entry in kept.passes[0][0]] == [[]], "so did the queued message that was sent"
    assert moved.passes[0] == kept.passes[0], "the first pass did the same"
    assert moved.passes[1] == kept.passes[1], "and so did the next one, which reads the moved state"


def test_a_message_waiting_for_a_decision_is_not_touched_however_old_it_is(tmp_path):
    cfg = make_config(tmp_path)
    state = core.new_state()
    stamp = NOW - 800 * DAY
    parked = queue_entry(
        "CVE-2024-7101", attempts=3, queued_at=stamp, first_attempt_at=stamp, parked_at=stamp, sent_to=[]
    )
    state["parked"].append(parked)
    deliver(state, "CVE-2024-7102", stamp)
    write_state(cfg, state)

    run_pass(cfg)

    assert stored(cfg)["parked"] == [parked]
    assert len(archives(tmp_path)) == 1, "the old delivery moved, and the parked message beside it did not"


def test_a_queued_message_older_than_two_years_is_still_delivered(tmp_path):
    """Retention reads delivery events only: the queue is work, not history."""
    cfg = make_config(tmp_path)
    state = core.new_state()
    state["pending"].append(queue_entry(CVE, queued_at=NOW - 800 * DAY))
    write_state(cfg, state)

    code, notifier = run_pass(cfg)

    assert code == 0
    assert [entry["ids"] for entry in notifier.sent] == [[CVE]]
    event = next(iter(stored(cfg)["deliveries"].values()))
    assert event["at"] == NOW, "the event is dated by the delivery, so it is not two years old"
    assert archives(tmp_path) == []


# --- how it is written ----------------------------------------------------------------------------------------


def test_the_archive_is_written_like_the_state_synced_then_renamed_then_the_directory_synced(tmp_path, monkeypatch):
    events: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(descriptor):
        events.append("sync file")
        real_fsync(descriptor)

    def replace(source, destination):
        events.append("rename")
        real_replace(source, destination)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(state_module, "_sync_directory", lambda directory: events.append("sync directory"))
    state = core.new_state()
    deliver(state, "CVE-2024-8001", NOW - 800 * DAY)

    assert retention.retire_deliveries(state, tmp_path / "state.json", NOW) == 1

    assert events == ["sync file", "rename", "sync directory"]
    path = the_archive(tmp_path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert sorted(entry.name for entry in tmp_path.iterdir()) == [path.name], "no temporary file is left behind"


def test_the_same_records_get_the_same_file_name_and_other_records_another(tmp_path):
    """The name is what lets a retry find the file it wrote, so it must follow the content and nothing else."""

    def archive_name(label: str, cves: list[str]) -> str:
        directory = tmp_path / label
        directory.mkdir()
        state = core.new_state()
        for cve in cves:
            deliver(state, cve, NOW - 800 * DAY)
        assert retention.retire_deliveries(state, directory / "state.json", NOW) == len(cves)
        path = the_archive(directory)
        return path.name

    one = archive_name("one", ["CVE-2024-8101"])

    assert archive_name("again", ["CVE-2024-8101"]) == one
    assert archive_name("two", ["CVE-2024-8101", "CVE-2024-8102"]) != one


def test_a_second_pass_does_not_write_again_what_the_first_one_moved(tmp_path):
    cfg = make_config(tmp_path)
    state = core.new_state()
    deliver(state, "CVE-2024-8201", NOW - 800 * DAY)
    write_state(cfg, state)
    run_pass(cfg)
    first = the_archive(tmp_path)
    written = first.read_bytes()

    run_pass(cfg, clock=NOW + 60)

    assert archives(tmp_path) == [first]
    assert first.read_bytes() == written


def test_a_pass_that_stopped_after_writing_the_archive_finds_it_and_writes_nothing_twice(tmp_path):
    """A pass that dies after the archive was written and before the state was saved leaves the event in the state."""
    cfg = make_config(tmp_path)
    state = core.new_state()
    old = deliver(state, "CVE-2024-8301", NOW - 800 * DAY)
    write_state(cfg, state)
    assert retention.retire_deliveries(stored(cfg), cfg.state_path, NOW) == 1  # the state is not saved
    first = the_archive(tmp_path)
    written = first.read_bytes()
    assert old in stored(cfg)["deliveries"]

    code, _ = run_pass(cfg, clock=NOW + 60)

    assert code == 0
    assert archives(tmp_path) == [first], "the retry found the file it had written"
    assert first.read_bytes() == written, "and left it as the first attempt wrote it"
    assert old not in stored(cfg)["deliveries"], "while the state now holds the event no longer"


def test_a_retry_after_midnight_may_write_a_second_file_with_the_same_snapshots(tmp_path):
    """The guide says so: the day is in the name, so the first retry after midnight finds no file of that name."""
    cfg = make_config(tmp_path)
    state = core.new_state()
    old = deliver(state, "CVE-2024-8302", NOW - 800 * DAY)
    write_state(cfg, state)
    assert retention.retire_deliveries(stored(cfg), cfg.state_path, NOW) == 1  # the state is not saved
    first = the_archive(tmp_path)

    code, _ = run_pass(cfg, clock=(NOW // DAY + 1) * DAY + 60)

    assert code == 0
    second = the_archive(tmp_path, apart_from=first)
    assert list(read_archive(first)["deliveries"]) == [old]
    assert read_archive(second)["deliveries"] == read_archive(first)["deliveries"]
    assert ARCHIVE_NAME.fullmatch(second.name).group(2) == ARCHIVE_NAME.fullmatch(first.name).group(2), "same digest"
    assert ARCHIVE_NAME.fullmatch(second.name).group(1) != ARCHIVE_NAME.fullmatch(first.name).group(1), "next day"
    assert old not in stored(cfg)["deliveries"]


def test_a_dry_run_writes_no_archive_and_leaves_the_state_alone(tmp_path):
    cfg = make_config(tmp_path)
    state = core.new_state()
    deliver(state, "CVE-2024-8401", NOW - 800 * DAY)
    write_state(cfg, state)
    before = cfg.state_path.read_bytes()

    code, _ = run_pass(cfg, dry_run=True)

    assert code == 0
    assert archives(tmp_path) == []
    assert cfg.state_path.read_bytes() == before


def test_an_archive_that_cannot_be_written_keeps_the_events_and_the_pass_carries_on(tmp_path, caplog, monkeypatch):
    """A full disk or a read-only volume fails the archive, never the pass, and a later pass that can write it does.

    Only the archive writer is made to fail: the pass saves the state through ``state.save_json``, a different name.
    """
    cfg = make_config(tmp_path)
    state = core.new_state()
    old = deliver(state, "CVE-2024-8501", NOW - 800 * DAY)
    write_state(cfg, state)
    caplog.set_level(logging.WARNING, logger="advisory_radar")

    def disk_full(path, document, **kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    with monkeypatch.context() as patch:
        patch.setattr(retention, "save_json", disk_full)
        code, _ = run_pass(cfg)

    assert code == 0, "an archive that fails is not a failed pass"
    after = stored(cfg)
    assert old in after["deliveries"], "an event that is not in an archive is still in the state"
    assert after["runs"], "the pass still wrote its run record"
    assert archives(tmp_path) == []
    warnings = [record.getMessage() for record in caplog.records if record.levelno == logging.WARNING]
    assert any("could not archive" in text and "stay in the state" in text for text in warnings)

    code, _ = run_pass(cfg, clock=NOW + 60)

    assert code == 0
    assert old not in stored(cfg)["deliveries"]
    path = the_archive(tmp_path)
    assert set(read_archive(path)["deliveries"]) == {old}


def test_no_pass_reads_an_archive_file_that_is_already_there(tmp_path):
    """Nothing in a pass looks inside an archive: a file that is not even JSON beside the state changes nothing."""
    cfg = make_config(tmp_path)
    state = core.new_state()
    old = deliver(state, "CVE-2024-8601", NOW - 800 * DAY)
    write_state(cfg, state)
    neighbour = tmp_path / "state-archive-2023-01-01-000000000000.json"
    neighbour.write_bytes(b"\xff\xfe this is not JSON")

    code, _ = run_pass(cfg)

    assert code == 0
    assert neighbour.read_bytes() == b"\xff\xfe this is not JSON"
    written = the_archive(tmp_path, apart_from=neighbour)
    assert set(read_archive(written)["deliveries"]) == {old}


# --- what an operator reads -----------------------------------------------------------------------------------


def moved_state(tmp_path: Path) -> dict:
    """What a real pass leaves behind after it moved the first event of ``MOVED``; the page cases read this."""
    cfg = make_config(tmp_path)
    state = core.new_state()
    moved_event = deliver(state, MOVED, NOW - 800 * DAY)
    deliver(state, MOVED, NOW - 20 * DAY, kind="escalation")
    kept_event = deliver(state, KEPT, NOW - 700 * DAY)
    state["seen"][UNPOINTED] = {"at": NOW - 900 * DAY, "outcome": "delivered"}
    write_state(cfg, state)

    code, _ = run_pass(cfg)

    after = stored(cfg)
    assert code == 0
    assert moved_event not in after["deliveries"], "the pass moved the old event"
    assert kept_event in after["deliveries"], "and only that one"
    assert after["seen"][MOVED]["delivery"] == moved_event, "the record still points at the event that moved"
    return after


def signed_in(tmp_path: Path, state: dict):
    client, token, _ = make_client(tmp_path, state=state)
    sign_in(client, token)
    return client


def alert_cells(page: str, identifier: str) -> list[str]:
    """The text of each cell in the row ``/alerts`` lists for one identifier."""
    link = f"<a href='/advisories/{_advisory_token(identifier)}'>{identifier}</a>"
    assert link in page, f"/alerts lists no row for {identifier}"
    start = page.index(link)
    row = page[page.rindex("<tr>", 0, start) : page.index("</tr>", start)]
    return [re.sub(r"<[^>]+>", "", cell).strip() for cell in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]


def test_the_advisory_page_of_a_record_whose_snapshot_moved_says_where_the_details_went(tmp_path):
    client = signed_in(tmp_path, moved_state(tmp_path))

    page = client.get(f"/advisories/{_advisory_token(MOVED)}")

    assert page.status_code == 200
    assert "details are no longer in the state" in page.text
    assert "state-archive file beside the state file" in page.text
    assert "older version" not in page.text and "were not recorded" not in page.text
    assert "delivered" in page.text, "the outcome the seen record holds is still shown"
    assert datetime.fromtimestamp(NOW - 800 * DAY, UTC).strftime("%Y-%m-%d %H:%M") in page.text
    assert "<h2>Notifications</h2>" in page.text, "the later escalation did not move, so the page still lists it"


def test_a_record_with_no_pointer_to_a_snapshot_still_says_an_older_version_wrote_it(tmp_path):
    """The other side of the same branch: no pointer means nothing was ever archived, so the page says what it did."""
    client = signed_in(tmp_path, moved_state(tmp_path))

    unpointed = client.get(f"/advisories/{_advisory_token(UNPOINTED)}")
    kept = client.get(f"/advisories/{_advisory_token(KEPT)}")

    assert unpointed.status_code == 200
    assert "older version" in unpointed.text
    assert "details are no longer in the state" not in unpointed.text
    assert kept.status_code == 200
    assert f"CRITICAL: {KEPT}" in kept.text, "a record whose snapshot stayed still shows it"
    assert "details are no longer in the state" not in kept.text


def test_alerts_lists_a_record_whose_snapshot_moved_with_no_tag_source_or_title_and_says_why(tmp_path):
    client = signed_in(tmp_path, moved_state(tmp_path))

    page = client.get("/alerts").text

    assert {MOVED, KEPT, UNPOINTED} <= set(page_ids(page))
    moved = alert_cells(page, MOVED)
    assert moved[1:4] == [NO_VALUE, NO_VALUE, NO_VALUE], "the tag, the source id and the title moved with the snapshot"
    assert moved[4] == "delivered"
    assert alert_cells(page, KEPT)[1:4] == ["critical", "test", f"CRITICAL: {KEPT}"]
    assert "whose snapshot moved to an archive file after two years" in page


def test_the_inbox_still_lists_a_record_whose_snapshot_moved(tmp_path):
    client = signed_in(tmp_path, moved_state(tmp_path))

    page = client.get("/inbox")

    assert page.status_code == 200
    assert {MOVED, KEPT, UNPOINTED} <= set(INBOX_ROW_RE.findall(page.text))


def test_the_deployment_guide_names_the_file_the_code_writes_and_the_two_years_it_counts():
    """The guide, the code and the cases above must name one file: a guide that names another sends a reader nowhere."""
    guide = GUIDE.read_text(encoding="utf-8")
    configuration = (ROOT / "docs" / "configuration.md").read_text(encoding="utf-8")

    assert f"{retention.ARCHIVE_PREFIX}<day>-<digest>.json" in guide
    assert "730 days" in guide
    assert "\n### State size and retention\n" in guide
    assert '"State size and retention"' in configuration, "the configuration guide points at that section by name"
