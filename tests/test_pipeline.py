"""Pipeline and config tests with fake HTTP and fake plugins."""

from __future__ import annotations

import json
import logging
import sys
import types
import urllib.parse
from pathlib import Path

import pytest

from advisory_radar import core, pipeline, storage
from advisory_radar.config import DEFAULT_THRESHOLDS, Config, ConfigError, load_config
from advisory_radar.plugins import SourceWindow
from advisory_radar.sources import ChangedetectionSource, RssSource, WebhookSource
from advisory_radar.state import save_state
from advisory_radar.watchlist import load_policy


def make_policy(tmp_path: Path):
    watch = tmp_path / "watchlist.json"
    watch.write_text(
        json.dumps(
            {
                "schema": "security-watchlist.v1",
                "debian_source_packages": ["curl"],
                "excluded_products": [],
                "products": [],
            }
        )
    )
    return load_policy(watch)


def rss_source(body: bytes, url: str = "https://feeds.example.com/rss"):
    def http(method, url_, headers, payload):
        if url_ == url:
            return 200, {}, body
        return 404, {}, b""

    source = RssSource("test", url)
    return source, http


FEED = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>T</title><link>https://feeds.example.com/</link>
<item><title>Vendor advisory CVE-2026-4242</title><link>https://vendor.example.com/a1</link>
<guid>g1</guid><description>Fixes CVE-2026-4242.</description><pubDate>Wed, 21 Oct 2026 10:00:00 +0000</pubDate></item>
</channel></rss>"""

CVE_ORG = {
    "cveMetadata": {"cveId": "CVE-2026-4242", "state": "PUBLISHED"},
    "containers": {
        "cna": {"metrics": [{"cvssV3_1": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"}}]}
    },
}
EPSS = {"data": [{"cve": "CVE-2026-4242", "epss": "0.50", "percentile": "0.99"}]}
KEV = {"catalogVersion": "1", "vulnerabilities": []}


CURRENT_FEED = FEED


def fake_http(method, url, headers, body):
    if "cveawg.mitre.org" in url:
        return 200, {}, json.dumps(CVE_ORG).encode()
    if "api.first.org" in url:
        return 200, {}, json.dumps(EPSS).encode()
    if "cisa.gov" in url:
        return 200, {"ETag": "k1"}, json.dumps(KEV).encode()
    if url == "https://feeds.example.com/rss":
        return 200, {}, CURRENT_FEED
    return 404, {}, b""


class FakeNotifier:
    def __init__(self, status=200):
        self.id = "fake"
        self.status = status
        self.sent = []

    def send(self, entry, http):
        self.sent.append(entry)
        return self.status


class WindowSource:
    """A source that returns a fixed window, so a test controls the items and their identities."""

    kind = "feed"

    def __init__(self, source_id: str, items, host: str = "") -> None:
        self.id = source_id
        self._items = tuple(items)
        self.host = host

    def fetch(self, http, state=None):
        return SourceWindow(self.id, self._items, False, self.host)


def make_config(tmp_path: Path, **overrides):
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(
        "sources:\n  - id: test\n    type: rss\n    url: https://feeds.example.com/rss\n"
        "notifiers:\n  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
        f"state_path: {tmp_path}/state.json\n"
        f"watchlist: {tmp_path}/watchlist.json\n" + "".join(f"{k}: {v}\n" for k, v in overrides.items())
    )
    return load_config(cfg_path, {})


def test_full_pass_delivers_critical(tmp_path):
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    source, _ = rss_source(FEED)
    notifier = FakeNotifier(200)
    code = pipeline.run_pass(
        cfg, [source], [notifier], http=fake_http, clock=lambda: 1792600000.0, sleep=lambda s: None
    )
    assert code == 0
    assert len(notifier.sent) == 1
    entry = notifier.sent[0]
    assert entry["tag"] == "critical"
    assert "CVE-2026-4242" in entry["title"] or "CVE-2026-4242" in entry["body"]
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["seen"]["CVE-2026-4242"]["outcome"] == "delivered"


def test_failed_notifier_parks_after_attempts(tmp_path):
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    source, _ = rss_source(FEED)
    notifier = FakeNotifier(500)
    now = 1792600000
    for _ in range(core.MAX_DELIVERY_ATTEMPTS):
        code = pipeline.run_pass(
            cfg, [source], [notifier], http=fake_http, clock=lambda: float(now), sleep=lambda s: None
        )
        assert code == 1
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["parked"], "the message must be parked after MAX_DELIVERY_ATTEMPTS"
    assert len(notifier.sent) == core.MAX_DELIVERY_ATTEMPTS


def test_old_items_seeded_not_alerted(tmp_path):
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    global CURRENT_FEED
    CURRENT_FEED = FEED.replace(b"Wed, 21 Oct 2026 10:00:00 +0000", b"Wed, 01 Jan 2020 10:00:00 +0000")
    source, _ = rss_source(FEED)
    notifier = FakeNotifier(200)
    code = pipeline.run_pass(
        cfg, [source], [notifier], http=fake_http, clock=lambda: 1792600000.0, sleep=lambda s: None
    )
    assert code == 0
    assert notifier.sent == []
    state = json.loads((tmp_path / "state.json").read_text())
    # A bootstrap records history, it does not deliver it: the outcome is backlog, never "delivered".
    assert state["seen"]["CVE-2026-4242"]["outcome"] == "backlog"


def test_seeding_a_second_source_preserves_existing_records_and_claims_no_delivery(tmp_path):
    """A bootstrap must not rewrite what earlier passes recorded, nor claim it sent anything (#69)."""
    cfg = _sources_config(
        tmp_path,
        "  - id: s1\n    type: rss\n    url: https://feeds.example.com/a\n",
        "  - id: s2\n    type: rss\n    url: https://feeds.example.com/b\n",
    )
    old = NOW - 30 * 86400  # well outside the seed window, so every item below is history
    bodies = {
        "https://feeds.example.com/a": _rss_document(),
        "https://feeds.example.com/b": _rss_document(
            _rss_item("Historical advisory CVE-2026-1001", "old-1", old),
            _rss_item("Historical advisory CVE-2026-1002", "old-2", old),
            _rss_item("Historical advisory CVE-2026-1003", "old-3", old),
            _rss_item("Historical advisory CVE-2026-1009", "old-9", old),
        ),
    }
    kev = {"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-2020-0001"}]}

    def http(method, url, headers, payload):
        if url in bodies:
            return 200, {}, bodies[url]
        if _is_kev_request(url):
            return 200, {}, json.dumps(kev).encode()
        return 404, {}, b""

    state = core.new_state()
    state["seeded"] = {"s1": True}  # s1 bootstrapped on an earlier pass; only s2 seeds here
    state["seen"] = {
        "CVE-2026-1001": {"at": NOW - 5000, "outcome": "suppressed"},
        "CVE-2026-1002": {"at": NOW - 4000, "outcome": "dropped", "delivery": "snap-2"},
        "CVE-2026-1003": {"at": NOW - 3000, "outcome": "delivered", "delivery": "snap-1"},
    }
    state["deliveries"] = {"snap-1": {"tag": "critical", "ids": ["CVE-2026-1003"]}}
    cfg.store().save(state)

    notifier = FakeNotifier(200)
    assert (
        pipeline.run_pass(
            cfg,
            [RssSource("s1", "https://feeds.example.com/a"), RssSource("s2", "https://feeds.example.com/b")],
            [notifier],
            http=http,
            clock=lambda: float(NOW),
            sleep=lambda seconds: None,
        )
        == 0
    )
    stored = cfg.store().load()
    assert stored["seen"]["CVE-2026-1001"] == {"at": NOW - 5000, "outcome": "suppressed"}
    assert stored["seen"]["CVE-2026-1002"] == {"at": NOW - 4000, "outcome": "dropped", "delivery": "snap-2"}
    assert stored["seen"]["CVE-2026-1003"] == {"at": NOW - 3000, "outcome": "delivered", "delivery": "snap-1"}
    assert stored["seen"]["CVE-2026-1009"] == {"at": NOW, "outcome": "backlog"}, (
        "a bootstrap record states history, it must not claim a notification was sent"
    )
    assert "delivery" not in stored["seen"]["CVE-2026-1009"], "nothing was delivered for a bootstrap record"
    assert stored["deliveries"] == {"snap-1": {"tag": "critical", "ids": ["CVE-2026-1003"]}}
    assert notifier.sent == [], "seeded history is never delivered"


def test_source_fault_fails_pass_but_keeps_state(tmp_path):
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    source, _ = rss_source(FEED)

    def broken(method, url, headers, body):
        if url == "https://feeds.example.com/rss":
            return 0, {}, b""
        return fake_http(method, url, headers, body)

    code = pipeline.run_pass(cfg, [source], [FakeNotifier()], http=broken, clock=lambda: 1.0, sleep=lambda s: None)
    assert code == 1
    # A first run with no readable source records the failure and nothing else: a fresh install whose every
    # source fails must not look like one that never polled, and must still bootstrap when a source answers.
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["source_health"]["test"]["ok"] is False
    assert "unreachable" in state["source_health"]["test"]["error"]
    assert state["seen"] == {}
    assert state["watch"] == {}
    assert state["feeds"] == {}, "no validator may advance for a source that never answered"
    assert not state.get("seeded"), "nothing was seeded, so a first successful pass still bootstraps"


def test_storage_defaults_to_the_json_file_and_validates_at_load(tmp_path):
    plain = tmp_path / "plain.yml"
    plain.write_text("sources: []\nnotifiers: []\n")
    cfg = load_config(plain, {})
    assert cfg.storage == ""
    assert isinstance(cfg.store(), storage.JsonStore)

    sqlite = tmp_path / "sqlite.yml"
    sqlite.write_text(f"sources: []\nnotifiers: []\nstorage: sqlite:///{tmp_path}/state.db\n")
    assert isinstance(load_config(sqlite, {}).store(), storage.SqliteStore)

    # A malformed value fails with every other bad key, and the refusal never quotes what it rejected:
    # the value can be a PostgreSQL URL with a password in it.
    bad = tmp_path / "bad.yml"
    bad.write_text("sources: []\nnotifiers: []\nstorage: mysql://db.example/radar\n")
    with pytest.raises(ConfigError) as caught:
        load_config(bad, {})
    assert "sqlite:///" in str(caught.value)
    assert "mysql" not in str(caught.value)


def test_a_pass_delivers_identically_from_a_sqlite_store(tmp_path):
    """The document model does not change with the store: the same pass produces the same document."""
    global CURRENT_FEED
    CURRENT_FEED = FEED  # an earlier test leaves the stale window behind, and this one needs today's
    make_policy(tmp_path)
    json_cfg = make_config(tmp_path)
    assert (
        pipeline.run_pass(
            json_cfg,
            [rss_source(FEED)[0]],
            [FakeNotifier(200)],
            http=fake_http,
            clock=lambda: 1792600000.0,
            sleep=lambda s: None,
        )
        == 0
    )
    sqlite_cfg = make_config(tmp_path, storage=f"sqlite:///{tmp_path}/state.db")
    notifier = FakeNotifier(200)
    assert (
        pipeline.run_pass(
            sqlite_cfg,
            [rss_source(FEED)[0]],
            [notifier],
            http=fake_http,
            clock=lambda: 1792600000.0,
            sleep=lambda s: None,
        )
        == 0
    )
    from_json = json.loads((tmp_path / "state.json").read_text())
    from_sqlite = sqlite_cfg.store().load()
    assert from_sqlite == from_json, "the store must not change what a pass reads and writes"
    assert notifier.sent[0]["tag"] == "critical"
    assert from_sqlite["seen"]["CVE-2026-4242"]["outcome"] == "delivered"


def test_a_dry_run_over_a_new_sqlite_store_writes_nothing(tmp_path):
    global CURRENT_FEED
    CURRENT_FEED = FEED
    make_policy(tmp_path)
    cfg = make_config(tmp_path, storage=f"sqlite:///{tmp_path}/state.db")
    code = pipeline.run_pass(
        cfg,
        [rss_source(FEED)[0]],
        [FakeNotifier()],
        http=fake_http,
        clock=lambda: 1792600000.0,
        sleep=lambda s: None,
        dry_run=True,
    )
    assert code == 0
    assert not (tmp_path / "state.db").exists(), "a dry run reads the configured store and creates nothing"


def test_an_unavailable_store_fails_a_dry_run_without_reseeding(tmp_path, monkeypatch, caplog):
    # No driver is installed, so the store cannot be opened: a deployment fault, never an empty document.
    monkeypatch.setitem(sys.modules, "psycopg", None)
    make_policy(tmp_path)
    cfg = make_config(tmp_path, storage="postgresql://radar:s3cr3t-pass@db.example/radar")
    with caplog.at_level(logging.ERROR):
        code = pipeline.run_pass(
            cfg,
            [rss_source(FEED)[0]],
            [FakeNotifier()],
            http=fake_http,
            clock=lambda: 1.0,
            sleep=lambda s: None,
            dry_run=True,
        )
    assert code == 1
    assert "not re-seeding" in caplog.text, "an unavailable store must read like an unreadable document"
    assert "psycopg" in caplog.text
    assert "s3cr3t-pass" not in caplog.text


def test_an_unavailable_store_fails_a_pass_instead_of_raising(tmp_path, monkeypatch, caplog):
    monkeypatch.setitem(sys.modules, "psycopg", None)
    make_policy(tmp_path)
    cfg = make_config(tmp_path, storage="postgresql://radar@db.example/radar")
    with caplog.at_level(logging.ERROR):
        code = pipeline.run_pass(
            cfg, [rss_source(FEED)[0]], [FakeNotifier()], http=fake_http, clock=lambda: 1.0, sleep=lambda s: None
        )
    assert code == 1, "an unavailable lock is a failed pass, not a traceback"
    assert "the pass did not run" in caplog.text
    assert not (tmp_path / "state.json").exists(), "a failed pass must not have written a document"


def test_config_env_expansion_and_unknown_key(tmp_path):
    cfg_path = tmp_path / "c.yml"
    cfg_path.write_text(
        "sources:\n  - id: s\n    type: webhook\n    url: https://hooks.example.com/${HOOK_PATH}\nnotifiers: []\n"
    )
    cfg = load_config(cfg_path, {"HOOK_PATH": "abc"})
    assert cfg.sources[0]["url"] == "https://hooks.example.com/abc"
    bad = tmp_path / "bad.yml"
    bad.write_text("sources: []\nnotifiers: []\nbogus: 1\n")
    with pytest.raises(ConfigError):
        load_config(bad, {})
    missing = tmp_path / "m.yml"
    missing.write_text("sources:\n  - id: s\n    type: rss\n    url: ${NOPE}\nnotifiers: []\n")
    with pytest.raises(ConfigError):
        load_config(missing, {})


# --- a source may be polled at its own pace ------------------------------------------------------

NOW = 1792600000


class CountingSource:
    """A source that counts its fetches; its window is empty, so the pass has nothing to classify."""

    kind = "feed"

    def __init__(self, source_id: str) -> None:
        self.id = source_id
        self.calls = 0

    def fetch(self, http, state):
        self.calls += 1
        return SourceWindow(self.id, (), False, "")


def interval_config(tmp_path: Path, entries: list[dict]):
    """A config whose sources carry the intervals under test; notifiers are absent, so nothing is sent."""
    make_policy(tmp_path)
    lines = ["sources:"]
    for entry in entries:
        lines.append(f"  - id: {entry['id']}\n    type: rss\n    url: https://feeds.example.com/{entry['id']}")
        if entry.get("interval"):
            lines.append(f"    interval: {entry['interval']}")
    lines.append("notifiers: []")
    lines.append(f"state_path: {tmp_path}/state.json")
    lines.append(f"watchlist: {tmp_path}/watchlist.json")
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text("\n".join(lines) + "\n")
    return load_config(cfg_path, {})


def run_at(cfg, sources, now: int, notifier=None) -> int:
    return pipeline.run_pass(
        cfg,
        sources,
        [notifier if notifier is not None else FakeNotifier()],
        http=fake_http,
        clock=lambda: float(now),
        sleep=lambda s: None,
    )


def test_a_source_interval_thins_its_fetch_but_not_the_pass(tmp_path):
    cfg = interval_config(tmp_path, [{"id": "slow", "interval": "30m"}])
    assert cfg.source_intervals == {"slow": 1800}
    source = CountingSource("slow")
    assert run_at(cfg, [source], NOW) == 0
    assert source.calls == 1
    # The pass still runs its re-evaluation and delivery steps; only this source's fetch is deferred.
    assert run_at(cfg, [source], NOW + 600) == 0
    assert source.calls == 1, "younger than its interval, so not fetched"
    assert run_at(cfg, [source], NOW + 1800) == 0
    assert source.calls == 2, "due once the interval has elapsed since the last attempt"


def test_a_failed_fetch_retries_on_the_next_pass(tmp_path):
    """A transient error must not turn into an outage for the whole interval."""

    class Flaky:
        id = "slow"
        kind = "feed"
        calls = 0

        def fetch(self, http, state):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("transient")
            return SourceWindow(self.id, (), False, "")

    cfg = interval_config(tmp_path, [{"id": "slow", "interval": "12h"}])
    source = Flaky()
    assert run_at(cfg, [source], NOW) == 1
    assert source.calls == 1
    assert run_at(cfg, [source], NOW + 60) == 0
    assert source.calls == 2, "a failed attempt is not a reason to wait out the interval"


def test_a_fast_and_a_slow_source_are_polled_at_their_own_paces(tmp_path):
    cfg = interval_config(tmp_path, [{"id": "fast", "interval": "1m"}, {"id": "slow", "interval": "12h"}])
    assert cfg.source_intervals == {"fast": 60, "slow": 43200}
    fast, slow = CountingSource("fast"), CountingSource("slow")
    run_at(cfg, [fast, slow], NOW)
    assert (fast.calls, slow.calls) == (1, 1)
    run_at(cfg, [fast, slow], NOW + 120)
    assert (fast.calls, slow.calls) == (2, 1)
    run_at(cfg, [fast, slow], NOW + 240)
    assert (fast.calls, slow.calls) == (3, 1)


def test_a_skipped_source_keeps_its_carry_clocks_seen_and_pending(tmp_path):
    """The interval skips the fetch only: work already in the state is neither dropped nor duplicated."""
    cfg = interval_config(tmp_path, [{"id": "slow", "interval": "12h"}])
    source = CountingSource("slow")
    state = core.new_state()
    state["seeded"] = {"slow": True}
    state["source_health"] = {"slow": {"at": NOW, "ok": True, "ok_at": NOW, "items": 0, "error": ""}}
    carried = core.Item("slow:carried", "carried advisory", "https://vendor.example.net/a", "notes", NOW - 60, ())
    state["carry"] = {"slow": [core.item_to_state(carried)]}
    state["enrich_retry"] = {"slow:carried": NOW - 10}
    state["enrich_pending"] = {"slow:carried": NOW - 10}
    state["seen"] = {"CVE-2026-9999": {"at": NOW - 100, "outcome": "delivered"}}
    queued = [
        {
            "kind": "new",
            "tag": "warning",
            "title": f"queued {index}",
            "body": "b",
            "ids": [f"src:queued-{index}"],
            "cves": [],
            "levels": {},
            "source": "other",
            "link": "",
        }
        for index in range(core.DELIVERY_CAP)
    ]
    state["pending"] = queued
    save_state(cfg.state_path, state)

    # A failing notifier leaves the queue in place; delivery still ran, which is the point of not throttling it.
    assert run_at(cfg, [source], NOW + 60, notifier=FakeNotifier(500)) == 1
    assert source.calls == 0
    saved = json.loads(cfg.state_path.read_text())
    assert saved["source_health"]["slow"]["at"] == NOW, "a skipped fetch records no attempt"
    assert [row["guid"] for row in saved["carry"]["slow"]] == ["slow:carried"]
    assert saved["enrich_retry"]["slow:carried"] == NOW - 10
    assert saved["enrich_pending"]["slow:carried"] == NOW - 10
    assert saved["seen"]["CVE-2026-9999"]["outcome"] == "delivered"
    assert [entry["ids"] for entry in saved["pending"]] == [entry["ids"] for entry in queued]


def test_a_pass_where_no_source_is_due_fetches_nothing_and_still_succeeds(tmp_path):
    cfg = interval_config(tmp_path, [{"id": "a", "interval": "12h"}, {"id": "b", "interval": "12h"}])
    a, b = CountingSource("a"), CountingSource("b")
    assert run_at(cfg, [a, b], NOW) == 0
    assert (a.calls, b.calls) == (1, 1)
    before = json.loads(cfg.state_path.read_text())["source_health"]
    assert run_at(cfg, [a, b], NOW + 60) == 0, "a pass with every source deferred is not a failure"
    assert (a.calls, b.calls) == (1, 1), "nothing was due, so nothing was fetched"
    assert json.loads(cfg.state_path.read_text())["source_health"] == before, "no attempt rewrote the health"


# --- a feed identity cannot forge a log line ------------------------------------------------------

FORGED = "2026-10-22 INFO forged operational message"


def assert_no_forged_log_line(caplog) -> None:
    messages = [record.getMessage() for record in caplog.records]
    assert any("classified" in message for message in messages), "the identity must reach the log path"
    assert all("\n" not in message and "\r" not in message for message in messages)
    assert all(not line.startswith(FORGED) for message in messages for line in message.splitlines())


def test_a_forged_newline_in_a_json_feed_identity_never_becomes_a_log_line(tmp_path, caplog):
    """The id is remote-authored and reaches LOG.info("%s"); it must not split its record in two."""
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    body = (
        b'{"version": "https://jsonfeed.org/version/1.1", "title": "Vendor", "items": ['
        b'{"id": "advisory-2\\n2026-10-22 INFO forged operational message", '
        b'"content_text": "Security update", "date_published": "2026-10-21T10:00:00Z"}]}'
    )

    def http(method, url, headers, payload):
        if url == "https://feeds.example.com/rss":
            return 200, {}, body
        return fake_http(method, url, headers, payload)

    caplog.set_level(logging.INFO)
    code = pipeline.run_pass(
        cfg,
        [RssSource("test", "https://feeds.example.com/rss")],
        [FakeNotifier()],
        http=http,
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code == 0
    assert_no_forged_log_line(caplog)


def test_a_forged_newline_in_an_rss_identity_never_becomes_a_log_line(tmp_path, caplog):
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    body = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Vendor</title><link>https://vendor.example.com/</link>
<item><title>Security update</title><link>https://vendor.example.com/a</link>
<guid>advisory-2
2026-10-22 INFO forged operational message</guid>
<description>Security update.</description>
<pubDate>Wed, 21 Oct 2026 10:00:00 +0000</pubDate></item>
</channel></rss>"""

    def http(method, url, headers, payload):
        if url == "https://feeds.example.com/rss":
            return 200, {}, body
        return fake_http(method, url, headers, payload)

    caplog.set_level(logging.INFO)
    code = pipeline.run_pass(
        cfg,
        [RssSource("test", "https://feeds.example.com/rss")],
        [FakeNotifier()],
        http=http,
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code == 0
    assert_no_forged_log_line(caplog)


def test_a_stored_legacy_identity_is_still_recognised_as_claimed(tmp_path, caplog):
    """An older document holds the publisher's raw guid, so the same raw guid read again must match exactly."""
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    state = core.new_state()
    # What an older version left behind: the raw guid, DEL included, in ``seen``; and a carried candidate whose
    # identity carries a publisher-authored newline. Neither is rewritten, so both are compared exactly.
    state["seen"]["src:test:https://vendor.example.com/a\u007f"] = {"at": NOW, "outcome": "delivered"}
    state["carry"] = {
        "test": [
            {
                "guid": "carry-1\n2026-10-22 INFO forged operational message",
                "title": "Carried advisory",
                "link": "",
                "summary": "no identifiers",
                "published": None,
                "explicit": [],
                "source_title": "",
                "source_url": "",
            }
        ]
    }
    state["seeded"] = {"test": True}
    save_state(cfg.state_path, state)
    body = (
        b'<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>'
        b"<item><title>Unrelated advisory</title><link>https://vendor.example.com/a</link>"
        b"<guid>https://vendor.example.com/a&#127;</guid><description>no identifiers</description></item>"
        b"</channel></rss>"
    )
    notifier = FakeNotifier()

    def http(method, url, headers, payload):
        if url == "https://feeds.example.com/rss":
            return 200, {}, body
        return fake_http(method, url, headers, payload)

    caplog.set_level(logging.INFO)
    code = pipeline.run_pass(
        cfg,
        [RssSource("test", "https://feeds.example.com/rss")],
        [notifier],
        http=http,
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code == 0
    assert_no_forged_log_line(caplog)
    assert not [entry for entry in notifier.sent if entry.get("link") == "https://vendor.example.com/a"], (
        "the advisory recorded under the raw identity must not be delivered again"
    )
    stored = json.loads((tmp_path / "state.json").read_text())
    assert "src:test:https://vendor.example.com/a\u007f" in stored["seen"], (
        "the stored document is not rewritten: the raw claim is matched exactly"
    )


def test_two_unusable_guids_are_two_advisories_not_one(tmp_path):
    """The raw guids are already distinct; normalising one to an empty string used to fold them together."""
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    source = WindowSource(
        "s1",
        [
            core.Item("\ud800", "first vendor advisory", "https://vendor.example.com/a", "notes", NOW - 3600, ()),
            core.Item("\ud801", "second vendor advisory", "https://vendor.example.com/b", "notes", NOW - 3600, ()),
        ],
    )
    notifier = FakeNotifier()
    code = pipeline.run_pass(cfg, [source], [notifier], http=fake_http, clock=lambda: float(NOW), sleep=lambda s: None)
    assert code == 0
    assert len(notifier.sent) == 2, "the second advisory must not be dropped as already claimed"
    stored = json.loads((tmp_path / "state.json").read_text())
    identities = sorted(key for key in stored["seen"] if key.startswith("src:s1:"))
    assert identities == ["src:s1:\ud800", "src:s1:\ud801"], "each raw guid is its own identity"


def test_a_scalar_identity_survives_a_save_and_reload_without_a_second_delivery(tmp_path):
    """A reader's identity must be the same string after the state document is written and read back."""
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    scalar = "\U00010000"
    body = (
        b'{"version": "https://jsonfeed.org/version/1.1", "title": "Vendor", "items": [{"id": "apsb-'
        + scalar.encode()
        + b'", "title": "Vendor advisory", "content_text": "notes"}]}'
    )

    def http(method, url, headers, payload):
        if url == "https://feeds.example.com/rss":
            return 200, {}, body
        return fake_http(method, url, headers, payload)

    notifier = FakeNotifier()
    for _ in range(2):
        # Each pass loads the state from disk: the second one sees the identity the first one persisted.
        code = pipeline.run_pass(
            cfg,
            [RssSource("test", "https://feeds.example.com/rss")],
            [notifier],
            http=http,
            clock=lambda: float(NOW),
            sleep=lambda s: None,
        )
        assert code == 0
    assert len(notifier.sent) == 1, "the saved and reloaded identity must still be claimed on the second pass"
    stored = json.loads((tmp_path / "state.json").read_text())
    assert f"src:test:apsb-{scalar}" in stored["seen"], "the scalar is the same key after the round trip"


def test_a_stored_enrichment_clock_key_is_found_by_its_exact_identity(tmp_path):
    """A document written before this version already holds the raw key, so an exact lookup finds its clock."""
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    nodejs = core.Item(
        "wh:a\nb",
        "Wednesday, October 21, 2026 Security Releases",
        "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
        "notes",
        NOW - 3600,
        (),
    )
    state = core.new_state()
    state["seeded"] = {"s1": True}
    # The stored key is the publisher's raw identity, namespaced once. A transformed lookup would miss this
    # 3-hour-old 24-hour pending clock and start a fresh 2-hour retry clock instead.
    state["enrich_pending"] = {"s1:wh:a\nb": NOW - 3 * 3600}
    save_state(cfg.state_path, state)
    code = pipeline.run_pass(
        cfg,
        [WindowSource("s1", [nodejs], host="nodejs.org")],
        [FakeNotifier()],
        http=fake_http,
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code == 0
    stored = json.loads((tmp_path / "state.json").read_text())
    assert stored["carry"]["s1"][0]["guid"] == "s1:wh:a\nb", "the item waits on the pending clock"
    assert "enrich_retry" not in stored, "the pending clock must not restart as a 2-hour retry clock"
    assert stored["enrich_pending"] == {"s1:wh:a\nb": NOW - 3 * 3600}, (
        "the found key keeps its spelling and first-fault time; the document is not rewritten"
    )


def test_a_filtered_webhook_entry_is_released_from_the_inbox(tmp_path):
    """The claim must be ``src:<namespaced guid>``; another prefix leaves the inbox entry unclaimed forever."""
    watch = tmp_path / "watchlist.json"
    watch.write_text(
        json.dumps(
            {
                "schema": "security-watchlist.v1",
                "debian_source_packages": ["curl"],
                "excluded_products": [],
                "products": [{"id": "libfoo", "aliases": ["libfoo"], "domains": ["libfoo.example"]}],
            }
        )
    )
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(
        "sources:\n  - id: wh\n    type: webhook\nnotifiers: []\n"
        f"state_path: {tmp_path}/state.json\nwatchlist: {watch}\n"
    )
    cfg = load_config(cfg_path, {})
    state = core.new_state()
    state["seeded"] = {"wh": True}
    state["webhook_inbox"] = {"wh": [{"guid": "wh:noise", "title": "garden notes", "link": "", "summary": ""}]}
    save_state(cfg.state_path, state)
    code = pipeline.run_pass(
        cfg,
        [WebhookSource("wh")],
        [],
        http=fake_http,
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code == 0
    stored = json.loads((tmp_path / "state.json").read_text())
    assert stored.get("webhook_inbox", {}) == {}, "a filtered entry must be released, not held forever"
    assert stored["seen"]["src:wh:wh:noise"]["outcome"] == "filtered"


def _webhook_config(tmp_path: Path, watchlist: dict | None = None):
    """A configuration with one webhook source, and a watchlist when the test needs a filter."""
    watch = ""
    if watchlist is not None:
        path = tmp_path / "watchlist.json"
        path.write_text(json.dumps({"schema": "security-watchlist.v1", **watchlist}))
        watch = f"watchlist: {path}\n"
    path = tmp_path / "webhook.yml"
    path.write_text(
        f"sources:\n  - id: wh\n    type: webhook\nnotifiers:\n  - id: fake\n    type: webhook\n"
        f"    url: https://hooks.example.com/x\nstate_path: {tmp_path}/state.json\n{watch}"
    )
    return load_config(path, {})


# --- delivery policy wired from the configuration ----------------------------------------------


def queued_message(cve: str, tag: str = "warning") -> dict:
    """A queue entry shaped like ``core.classify_new`` writes it, complete enough for ``_delivered``."""
    return {
        "kind": "new",
        "tag": tag,
        "title": f"{tag.upper()}: {cve} in widget",
        "body": f"\n- **IDs:** {cve}",
        "ids": [cve],
        "cves": [cve],
        "levels": {cve: tag},
        "kev_only": [],
        "scores": {cve: 7.5},
        "thresholds": [9.0, 0.10, 4.0],
        "source": "Vendor",
        "source_id": "vendor",
        "link": f"https://vendor.example/{cve}",
    }


def pending_config(tmp_path: Path, extra: str = "") -> Config:
    """A configuration with no sources and one webhook notifier, so a pass only delivers the queue."""
    path = tmp_path / "delivery.yml"
    path.write_text(
        "sources: []\n"
        "notifiers:\n  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
        f"{extra}"
        f"state_path: {tmp_path}/state.json\n"
    )
    return load_config(path, {})


def test_two_carried_advisories_with_unusable_guids_both_survive(tmp_path):
    """Two raw carried identities stay distinct; a stand-in was only needed because normalising erased them."""
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    state = core.new_state()
    state["carry"] = {
        "test": [
            {
                "guid": f"test:{letter}\ud800",
                "title": f"Advisory {letter}",
                "link": "",
                "summary": "no identifiers",
                "published": None,
                "explicit": [],
                "source_title": "",
                "source_url": "",
            }
            for letter in ("a", "b")
        ]
    }
    state["seeded"] = {"test": True}
    save_state(cfg.state_path, state)
    body = b'<?xml version="1.0"?><rss version="2.0"><channel><title>T</title><link>https://v/</link></channel></rss>'
    notifier = FakeNotifier()

    def http(method, url, headers, payload):
        if url == "https://feeds.example.com/rss":
            return 200, {}, body
        return fake_http(method, url, headers, payload)

    code = pipeline.run_pass(
        cfg,
        [RssSource("test", "https://feeds.example.com/rss")],
        [notifier],
        http=http,
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code == 0
    assert len(notifier.sent) == 2, "both carried advisories must reach a channel"


def test_a_webhook_entry_whose_guid_cannot_be_encoded_leaves_the_inbox(tmp_path):
    """Cleanup builds the claim from the raw guid, so it matches what classification recorded."""
    from advisory_radar.sources import WebhookSource

    cfg = _webhook_config(tmp_path)
    state = core.new_state()
    state["webhook_inbox"] = {
        "wh": [{"guid": "\ud800legacy", "title": "Vendor advisory", "summary": "", "link": "https://v.example/a"}]
    }
    save_state(cfg.state_path, state)
    notifier = FakeNotifier()
    for _ in range(2):
        pipeline.run_pass(
            cfg,
            [WebhookSource("wh")],
            [notifier],
            http=lambda *a: (404, {}, b""),
            clock=lambda: float(NOW),
            sleep=lambda s: None,
        )
    assert len(notifier.sent) == 1, "the entry must be sent once, not on every pass"
    stored = json.loads((tmp_path / "state.json").read_text())
    assert not (stored.get("webhook_inbox") or {}).get("wh"), "an accepted entry must leave the inbox"


def test_a_filtered_webhook_entry_with_a_cve_leaves_the_inbox(tmp_path):
    """A filtered entry is terminal by its own claim, even when its text names an identifier."""
    from advisory_radar.sources import WebhookSource

    cfg = _webhook_config(
        tmp_path, {"debian_source_packages": ["curl"], "excluded_products": ["libbar"], "products": []}
    )
    state = core.new_state()
    state["webhook_inbox"] = {
        "wh": [{"guid": "noise", "title": "libbar fixes CVE-2026-1234", "summary": "", "link": "https://v.example/b"}]
    }
    save_state(cfg.state_path, state)
    notifier = FakeNotifier()
    pipeline.run_pass(
        cfg,
        [WebhookSource("wh")],
        [notifier],
        http=lambda *a: (404, {}, b""),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    stored = json.loads((tmp_path / "state.json").read_text())
    assert not (stored.get("webhook_inbox") or {}).get("wh"), "a filtered entry must not accumulate"


def test_two_webhook_guids_that_differ_only_by_a_control_character_both_arrive(tmp_path):
    """Stripping DEL made ``a\\x7fb`` and ``ab`` one identity, so one of the two advisories was silently lost."""
    from advisory_radar.sources import webhook_item_from_payload

    cfg = _webhook_config(tmp_path)
    state = core.new_state()
    state["webhook_inbox"] = {
        "wh": [
            webhook_item_from_payload(
                {"title": "Vendor advisory one", "text": "no identifiers", "guid": "a\x7fb", "url": "https://v/1"}
            ),
            webhook_item_from_payload(
                {"title": "Vendor advisory two", "text": "no identifiers", "guid": "ab", "url": "https://v/2"}
            ),
        ]
    }
    state["seeded"] = {"wh": True}
    save_state(cfg.state_path, state)
    notifier = FakeNotifier()
    for _ in range(2):
        code = pipeline.run_pass(
            cfg,
            [WebhookSource("wh")],
            [notifier],
            http=lambda *a: (404, {}, b""),
            clock=lambda: float(NOW),
            sleep=lambda s: None,
        )
        assert code == 0
    assert sorted(entry["link"] for entry in notifier.sent) == ["https://v/1", "https://v/2"], (
        "both distinct guids must reach a channel, and only once each"
    )
    stored = json.loads((tmp_path / "state.json").read_text())
    assert {"src:wh:wh:a\x7fb", "src:wh:wh:ab"} <= set(stored["seen"])
    assert not (stored.get("webhook_inbox") or {}).get("wh"), "both accepted entries must leave the inbox"


def local_epoch(hour: int, minute: int = 0) -> int:
    """An epoch whose *local* wall clock is this time, which is what a quiet-hours window reads."""
    import datetime

    return int(datetime.datetime(2026, 11, 11, hour, minute).timestamp())


def test_a_pass_delivers_three_queued_advisories_as_one_digest(tmp_path):
    cfg = pending_config(tmp_path, "digest: true\n")
    state = core.new_state()
    state["pending"] = [queued_message(f"CVE-2026-{number}") for number in (1, 2, 3)]
    cfg.store().save(state)
    notifier = FakeNotifier(200)
    code = pipeline.run_pass(
        cfg, [], [notifier], http=fake_http, clock=lambda: 1792600000.0, sleep=lambda seconds: None
    )
    assert code == 0
    assert len(notifier.sent) == 1, "one POST for the pass"
    assert notifier.sent[0]["kind"] == "digest"
    assert notifier.sent[0]["title"] == "WARNING: digest of 3 advisories"
    stored = cfg.store().load()
    assert stored["pending"] == []
    assert set(stored["seen"]) == {"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"}
    assert all(record["outcome"] == "delivered" for record in stored["seen"].values())


def test_a_pass_honours_the_quiet_hours_policy(tmp_path):
    cfg = pending_config(tmp_path, "quiet_hours: 22:00-07:00\n")
    assert cfg.quiet_hours is not None
    state = core.new_state()
    state["pending"] = [queued_message("CVE-2026-1"), queued_message("CVE-2026-2", "critical")]
    cfg.store().save(state)
    notifier = FakeNotifier(200)

    night = float(local_epoch(23))
    assert pipeline.run_pass(cfg, [], [notifier], http=fake_http, clock=lambda: night, sleep=lambda s: None) == 0
    assert [message["tag"] for message in notifier.sent] == ["critical"]
    assert [entry["ids"][0] for entry in cfg.store().load()["pending"]] == ["CVE-2026-1"]

    day = float(local_epoch(12))
    assert pipeline.run_pass(cfg, [], [notifier], http=fake_http, clock=lambda: day, sleep=lambda s: None) == 0
    assert [message["tag"] for message in notifier.sent] == ["critical", "warning"]
    assert cfg.store().load()["pending"] == []


# --- the watchlist document the page writes -----------------------------------------------------


def test_an_unconfigured_watchlist_is_read_beside_the_state_file(tmp_path):
    """What ``/watchlist`` creates must be what a pass reads, with no YAML change and no reload."""
    cfg = _webhook_config(tmp_path)  # no ``watchlist:`` key at all
    (tmp_path / "watchlist.json").write_text(
        json.dumps(
            {
                "schema": "security-watchlist.v1",
                "debian_source_packages": ["curl"],
                "excluded_products": [],
                "products": [{"id": "libfoo", "aliases": ["libfoo"], "domains": ["libfoo.example"]}],
            }
        )
    )
    state = core.new_state()
    state["seeded"] = {"wh": True}
    state["webhook_inbox"] = {
        "wh": [
            {"guid": "keep", "title": "libfoo advisory", "link": "https://libfoo.example/a", "summary": ""},
            {"guid": "drop", "title": "garden notes", "link": "https://other.example/b", "summary": ""},
        ]
    }
    save_state(cfg.state_path, state)
    notifier = FakeNotifier(200)
    code = pipeline.run_pass(
        cfg, [WebhookSource("wh")], [notifier], http=fake_http, clock=lambda: float(NOW), sleep=lambda s: None
    )
    assert code == 0
    assert len(notifier.sent) == 1, "the item the scope kept is the only message"
    stored = json.loads((tmp_path / "state.json").read_text())
    assert stored["seen"]["src:wh:drop"]["outcome"] == "filtered"
    assert stored["seen"].get("src:wh:keep", {}).get("outcome") != "filtered"
    assert stored.get("webhook_inbox", {}) == {}, "both entries are released from the inbox"


def test_an_unreadable_watchlist_fails_the_pass_instead_of_raising(tmp_path, caplog):
    """The document is writable through /watchlist now, so a broken one is a state this program can reach."""
    scope = tmp_path / "scope.json"
    scope.write_text("{not json")
    cfg_path = tmp_path / "broken.yml"
    cfg_path.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path}/state.json\nwatchlist: {scope}\n")
    cfg = load_config(cfg_path, {})
    with caplog.at_level(logging.ERROR, logger="advisory_radar"):
        code = pipeline.run_pass(cfg, [], [], http=fake_http, clock=lambda: float(NOW), sleep=lambda s: None)
    assert code == 1, "a scope that cannot be read must fail the pass, not judge everything"
    assert "did not run" in caplog.text


def test_a_broken_link_to_the_scope_fails_the_pass(tmp_path):
    """A scope that is present but unreadable must not fall back to the default, which judges every advisory."""
    cfg = _webhook_config(tmp_path)  # no ``watchlist:`` key, so the document is read beside the state file
    (tmp_path / "watchlist.json").symlink_to(tmp_path / "gone.json")
    assert pipeline.run_pass(cfg, [], [], http=fake_http, clock=lambda: float(NOW), sleep=lambda s: None) == 1


def test_a_scope_that_cannot_be_inspected_fails_the_pass(tmp_path, monkeypatch):
    """A permission error is not evidence of absence: falling back to the default would judge everything."""
    cfg = _webhook_config(tmp_path)
    (tmp_path / "watchlist.json").write_text(json.dumps({"schema": "security-watchlist.v1"}))

    def denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(pipeline.watchlist, "os", types.SimpleNamespace(lstat=denied))
    assert pipeline.run_pass(cfg, [], [], http=fake_http, clock=lambda: float(NOW), sleep=lambda s: None) == 1


def test_a_scope_nested_too_deeply_fails_the_pass(tmp_path):
    """A decoder that gives up is an unreadable document, not an exception out of the scheduler."""
    scope = tmp_path / "scope.json"
    scope.write_text("[" * 10_000 + "]" * 10_000)
    path = tmp_path / "deep.yml"
    path.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path}/state.json\nwatchlist: {scope}\n")
    cfg = load_config(path, {})
    assert pipeline.run_pass(cfg, [], [], http=fake_http, clock=lambda: float(NOW), sleep=lambda s: None) == 1


def test_a_scope_path_that_is_a_directory_fails_the_pass(tmp_path):
    cfg = _webhook_config(tmp_path)
    (tmp_path / "watchlist.json").mkdir()
    assert pipeline.run_pass(cfg, [], [], http=fake_http, clock=lambda: float(NOW), sleep=lambda s: None) == 1


def test_the_default_scope_is_in_force_beside_a_state_path_that_cannot_be_walked(tmp_path):
    """A `..` through a missing directory must not hide a saved scope behind the packaged default."""
    state_path = tmp_path / "missing" / ".." / "state.json"
    (tmp_path / "watchlist.json").write_text(
        json.dumps(
            {
                "schema": "security-watchlist.v1",
                "debian_source_packages": ["curl"],
                "excluded_products": [],
                "products": [{"id": "libfoo", "aliases": ["libfoo"], "domains": []}],
            }
        )
    )
    path = tmp_path / "walkless.yml"
    path.write_text(
        f"sources:\n  - id: wh\n    type: webhook\nstorage: sqlite:///{tmp_path}/store.db\nstate_path: {state_path}\n"
    )
    cfg = load_config(path, {})
    store = cfg.store()
    state = core.new_state()
    state["seeded"] = {"wh": True}
    state["webhook_inbox"] = {"wh": [{"guid": "noise", "title": "garden notes", "link": "", "summary": ""}]}
    store.save(state)
    code = pipeline.run_pass(
        cfg, [WebhookSource("wh")], [], http=fake_http, clock=lambda: float(NOW), sleep=lambda s: None
    )
    assert code == 0
    assert store.load()["seen"]["src:wh:noise"]["outcome"] == "filtered", "the saved scope was in force"


# --- classification admission during quiet hours --------------------------------------------------


def _is_kev_request(url: str) -> bool:
    """Whether this is the product's CISA KEV request, matched on the parsed host rather than a substring."""
    return urllib.parse.urlsplit(url).hostname == "www.cisa.gov"


def _rss_item(title: str, guid: str, published: int) -> str:
    from email.utils import formatdate

    return (
        f"<item><title>{title}</title><link>https://vendor.example.com/{guid}</link>"
        f"<guid>{guid}</guid><description>Fixes things.</description>"
        f"<pubDate>{formatdate(published, usegmt=True)}</pubDate></item>"
    )


def _rss_document(*items: str) -> bytes:
    return (
        '<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>'
        "<link>https://feeds.example.com/</link>" + "".join(items) + "</channel></rss>"
    ).encode()


def test_a_quiet_held_queue_does_not_block_a_new_critical(tmp_path):
    """Five warnings held by quiet hours must not stop a newly arrived critical advisory (#67).

    Holding is a delivery-time decision (``delivery.is_held``), so counting the raw pending length here let a
    queue of held warnings take the whole admission window and leave a critical advisory in carry.
    """
    night = local_epoch(23)
    path = tmp_path / "quiet.yml"
    path.write_text(
        "sources:\n  - id: vendor\n    type: rss\n    url: https://feeds.example.com/rss\n"
        "notifiers:\n  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
        "quiet_hours: 22:00-07:00\n"
        f"state_path: {tmp_path}/state.json\n"
    )
    cfg = load_config(path, {})
    state = core.new_state()
    state["seeded"] = {"vendor": True}
    held = []
    for number in range(1, 6):
        entry = queued_message(f"CVE-2026-{number}")
        entry["attempts"] = 1  # not a first attempt: the pass must leave it exactly as it found it
        held.append(entry)
    state["pending"] = held
    cfg.store().save(state)

    body = _rss_document(_rss_item("Vendor advisory CVE-2026-7777", "g1", night - 3600))
    kev = {"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-2026-7777"}]}

    def http(method, url, headers, payload):
        if url == "https://feeds.example.com/rss":
            return 200, {}, body
        if _is_kev_request(url):
            return 200, {}, json.dumps(kev).encode()
        return 404, {}, b""

    notifier = FakeNotifier(200)
    code = pipeline.run_pass(
        cfg,
        [RssSource("vendor", "https://feeds.example.com/rss")],
        [notifier],
        http=http,
        clock=lambda: float(night),
        sleep=lambda seconds: None,
    )
    assert code == 0
    assert [message["ids"] for message in notifier.sent] == [["CVE-2026-7777"]], (
        "a critical advisory whose CVE is in the KEV catalog must be classified and delivered in the same pass"
    )
    assert notifier.sent[0]["tag"] == "critical"
    stored = cfg.store().load()
    assert [entry["ids"][0] for entry in stored["pending"]] == [f"CVE-2026-{number}" for number in range(1, 6)]
    assert [entry["attempts"] for entry in stored["pending"]] == [1] * 5, "a held message is not an attempt"
    assert stored["seen"]["CVE-2026-7777"]["outcome"] == "delivered"


# --- a disabled source is not a removed source ----------------------------------------------------


CD_URL = "https://changes.example.net"
CD_SOURCE = f"  - id: cd\n    type: changedetection\n    url: {CD_URL}\n    api_key: k\n"
CD_DISABLED_SOURCE = CD_SOURCE + "    enabled: false\n"
#: The watch's ``last_changed``, recent enough that the item it produces is news, not history.
CD_CHANGED = NOW - 3600
RSS_SOURCE = "  - id: vendor\n    type: rss\n    url: https://feeds.example.com/rss\n"
WEBHOOK_SOURCE = "  - id: wh\n    type: webhook\n"


def _sources_config(tmp_path: Path, *blocks: str, env: dict[str, str] | None = None) -> Config:
    """A configuration whose declared sources are exactly ``blocks`` (YAML entries, no ``sources:`` key)."""
    declared = "sources:\n" + "".join(blocks) if blocks else "sources: []\n"
    path = tmp_path / "sources.yml"
    path.write_text(
        declared
        + "notifiers:\n  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
        + f"state_path: {tmp_path}/state.json\n"
    )
    return load_config(path, env or {})


def _watches_http(last_changed: int):
    """changedetection.io answering one watch whose ``last_changed`` does not move."""

    def http(method, url, headers, payload):
        if url.startswith(f"{CD_URL}/api/v1/watch"):
            watches = {
                "uuid-1": {
                    "uuid": "uuid-1",
                    "title": "Shop item",
                    "link": "https://shop.example.com/item",
                    "page_title": "Shop",
                    "paused": False,
                    "notification_muted": False,
                    "last_changed": last_changed,
                }
            }
            return 200, {}, json.dumps(watches).encode()
        if _is_kev_request(url):
            catalog = {"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-2020-0001"}]}
            return 200, {}, json.dumps(catalog).encode()
        return 404, {}, b""

    return http


def _captured_page_change(source_id: str = "cd") -> dict:
    """A changedetection candidate the pipeline had already captured into ``carry``."""
    return core.item_to_state(
        core.Item(
            guid=f"{source_id}:cd:uuid-1:{CD_CHANGED}",
            title="Shop item — changedetection.io",
            link="https://shop.example.com/item",
            summary=f"Page changed (last_changed={CD_CHANGED}).",
            published=CD_CHANGED,
            explicit=(),
        )
    )


def test_a_disabled_changedetection_source_keeps_its_capture_and_cursor(tmp_path):
    """A source merely turned off is not removed: its captured candidate and cursor must survive (#68)."""
    cfg_enabled = _sources_config(tmp_path, CD_SOURCE)
    state = core.new_state()
    state["seeded"] = {"cd": True}
    state["carry"] = {"cd": [_captured_page_change()]}
    state["changedetection"] = {"cd": {"uuid-1": CD_CHANGED}}
    cfg_enabled.store().save(state)

    quiet = FakeNotifier(200)
    cfg_disabled = _sources_config(tmp_path, CD_DISABLED_SOURCE)
    assert (
        pipeline.run_pass(
            cfg_disabled,
            [],
            [quiet],
            http=_watches_http(CD_CHANGED),
            clock=lambda: float(NOW),
            sleep=lambda seconds: None,
        )
        == 0
    )
    stored = cfg_enabled.store().load()
    assert [row["guid"] for row in (stored.get("carry") or {}).get("cd", [])] == [f"cd:cd:uuid-1:{CD_CHANGED}"], (
        "disabling a source must not discard work it already captured"
    )
    assert (stored.get("changedetection") or {}).get("cd") == {"uuid-1": CD_CHANGED}, (
        "a disabled source keeps its cursor"
    )
    assert not quiet.sent, "a disabled source is not polled and its capture is not processed"

    notifier = FakeNotifier(200)
    cfg_re_enabled = _sources_config(tmp_path, CD_SOURCE)
    assert (
        pipeline.run_pass(
            cfg_re_enabled,
            [ChangedetectionSource("cd", CD_URL, "k")],
            [notifier],
            http=_watches_http(CD_CHANGED),  # the page has not changed again
            clock=lambda: float(NOW),
            sleep=lambda seconds: None,
        )
        == 0
    )
    assert len(notifier.sent) == 1 and "Shop item" in notifier.sent[0]["title"], (
        "the candidate captured before the disablement must still be classified and delivered"
    )
    final = cfg_enabled.store().load()
    assert not (final.get("carry") or {}).get("cd")
    assert final["changedetection"]["cd"] == {"uuid-1": CD_CHANGED}, "nothing changed while it was disabled"


def test_removing_a_source_discards_its_cursors_with_its_carry_and_validators(tmp_path):
    """Removal is an explicit discard, so the cursor goes with the carry it can no longer recover (#68)."""
    cfg_declared = _sources_config(tmp_path, CD_SOURCE, RSS_SOURCE)
    state = core.new_state()
    state["seeded"] = {"cd": True, "vendor": True}
    state["carry"] = {"cd": [_captured_page_change()]}
    state["changedetection"] = {"cd": {"uuid-1": CD_CHANGED}}
    state["feeds"] = {"vendor": {"etag": '"v1"'}}
    state["source_health"] = {
        "cd": {"at": 1, "ok": True, "ok_at": 1, "items": 1, "error": ""},
        "vendor": {"at": 1, "ok": True, "ok_at": 1, "items": 1, "error": ""},
    }
    cfg_declared.store().save(state)

    cfg_removed = _sources_config(tmp_path)  # both sources removed from the configuration
    assert (
        pipeline.run_pass(
            cfg_removed,
            [],
            [FakeNotifier()],
            http=_watches_http(CD_CHANGED),
            clock=lambda: float(NOW),
            sleep=lambda s: None,
        )
        == 0
    )
    stored = cfg_declared.store().load()
    assert not (stored.get("carry") or {}), "a removed source's captured work is discarded"
    assert not (stored.get("feeds") or {}), "a removed source's validators are discarded with its carry"
    assert not (stored.get("changedetection") or {}), "a removed source's cursors are discarded with its carry"
    assert not (stored.get("source_health") or {}), "a health record never outlives its source"

    notifier = FakeNotifier(200)
    cfg_readded = _sources_config(tmp_path, CD_SOURCE)
    assert (
        pipeline.run_pass(
            cfg_readded,
            [ChangedetectionSource("cd", CD_URL, "k")],
            [notifier],
            http=_watches_http(CD_CHANGED),
            clock=lambda: float(NOW),
            sleep=lambda seconds: None,
        )
        == 0
    )
    assert len(notifier.sent) == 1 and "Shop item" in notifier.sent[0]["title"], (
        "re-adding the source must notice the page again instead of trusting the discarded cursor"
    )
    assert cfg_readded.store().load()["changedetection"]["cd"] == {"uuid-1": CD_CHANGED}


def test_a_disabled_source_capture_waits_and_another_source_is_unaffected(tmp_path):
    """Only polling stops while a source is disabled; other sources keep classifying and delivering (#68)."""
    cfg = _sources_config(tmp_path, CD_DISABLED_SOURCE, WEBHOOK_SOURCE)
    state = core.new_state()
    state["seeded"] = {"cd": True, "wh": True}
    state["carry"] = {"cd": [_captured_page_change()]}
    state["changedetection"] = {"cd": {"uuid-1": CD_CHANGED}}
    state["webhook_inbox"] = {
        "wh": [
            {
                "guid": "news",
                "title": "Unrelated vendor advisory",
                "summary": "",
                "link": "https://vendor.example/a",
            }
        ]
    }
    cfg.store().save(state)

    fetched = []

    def http(method, url, headers, payload):
        fetched.append(url)
        if _is_kev_request(url):
            catalog = {"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-2020-0001"}]}
            return 200, {}, json.dumps(catalog).encode()
        return 404, {}, b""

    notifier = FakeNotifier(200)
    assert (
        pipeline.run_pass(
            cfg, [WebhookSource("wh")], [notifier], http=http, clock=lambda: float(NOW), sleep=lambda seconds: None
        )
        == 0
    )
    assert not [url for url in fetched if CD_URL in url], "a disabled source must not be polled"
    assert [message["tag"] for message in notifier.sent] == ["warning"] and (
        "Unrelated vendor advisory" in notifier.sent[0]["title"]
    ), "an unrelated source must be classified and delivered as usual"
    stored = cfg.store().load()
    assert [row["guid"] for row in (stored.get("carry") or {}).get("cd", [])] == [f"cd:cd:uuid-1:{CD_CHANGED}"], (
        "a disabled source's capture waits instead of being processed or discarded"
    )
    assert (stored.get("changedetection") or {}).get("cd") == {"uuid-1": CD_CHANGED}


# --- a declared source id that cannot be resolved --------------------------------------------------

COMPOSED_SOURCE = "  - id: feed-${TENANT}\n    type: changedetection\n    url: " + CD_URL + "\n    api_key: k\n"
COMPOSED_DISABLED_SOURCE = COMPOSED_SOURCE + "    enabled: false\n"


def test_an_unresolvable_declared_id_keeps_its_stored_work(tmp_path, caplog):
    """A declared id that cannot be resolved leaves a removal undecidable, so stored work is kept (#68 review).

    ``feed-${TENANT}`` with ``TENANT`` unset still declares a source, but the pass cannot tell its stored id
    ``feed-acme`` apart from a source that was deleted. Pruning on that guess would lose exactly the work a
    temporary disablement protects, so an incomplete set keeps everything.
    """
    cfg_disabled = _sources_config(tmp_path, COMPOSED_DISABLED_SOURCE)  # TENANT is not in the environment
    assert cfg_disabled.declared_source_ids == {"feed-${TENANT}"}
    assert cfg_disabled.sources == ()

    captured = _captured_page_change("feed-acme")
    state = core.new_state()
    # Record the pass's policy digest first, so the first-run validator reset is not what the assertion below
    # observes: only the drop path may decide the validators' fate here.
    policy = load_policy(pipeline.watchlist.active_path(None, cfg_disabled.state_path))
    pipeline._reset_validators_on_policy_change(state, policy)
    state["seeded"] = {"feed-acme": True}
    state["carry"] = {"feed-acme": [captured]}
    state["feeds"] = {"feed-acme": {"url_digest": "d", "etag": "e"}}
    state["changedetection"] = {"feed-acme": {"uuid-1": CD_CHANGED}}
    cfg_disabled.store().save(state)

    with caplog.at_level(logging.INFO, logger="advisory_radar"):
        assert (
            pipeline.run_pass(
                cfg_disabled,
                [],
                [FakeNotifier()],
                http=_watches_http(CD_CHANGED),
                clock=lambda: float(NOW),
                sleep=lambda seconds: None,
            )
            == 0
        )
    stored = cfg_disabled.store().load()
    assert (stored.get("carry") or {}) == {"feed-acme": [captured]}, (
        "a declared id that cannot be resolved must not discard stored carry"
    )
    assert (stored.get("feeds") or {}) == {"feed-acme": {"url_digest": "d", "etag": "e"}}, (
        "validators are kept with the carry"
    )
    assert (stored.get("changedetection") or {}) == {"feed-acme": {"uuid-1": CD_CHANGED}}, (
        "cursors are kept with the carry"
    )
    assert cfg_disabled.declared_source_ids_complete is False
    assert "a declared source id cannot be resolved" in caplog.text, "the retention must be logged"

    cfg_enabled = _sources_config(tmp_path, COMPOSED_SOURCE, env={"TENANT": "acme"})
    assert cfg_enabled.declared_source_ids == {"feed-acme"}
    assert cfg_enabled.declared_source_ids_complete is True
    sources, _ = pipeline.build_plugins(cfg_enabled, {"TENANT": "acme"})
    assert [source.id for source in sources] == ["feed-acme"]
    notifier = FakeNotifier(200)
    assert (
        pipeline.run_pass(
            cfg_enabled,
            sources,
            [notifier],
            http=_watches_http(CD_CHANGED),  # the page has not changed again
            clock=lambda: float(NOW),
            sleep=lambda seconds: None,
        )
        == 0
    )
    assert len(notifier.sent) == 1 and "Shop item" in notifier.sent[0]["title"], (
        "the captured work kept through the unresolved id must be delivered when it resolves"
    )
    final = cfg_enabled.store().load()
    assert not (final.get("carry") or {}).get("feed-acme")
    assert final["changedetection"]["feed-acme"] == {"uuid-1": CD_CHANGED}


def test_a_resolved_composed_id_removal_still_discards_its_stored_work(tmp_path):
    """With every declared id resolved, removal is decidable and still drops carry, validators and cursors."""
    env = {"TENANT": "acme"}
    cfg_declared = _sources_config(tmp_path, COMPOSED_SOURCE, env=env)
    assert cfg_declared.declared_source_ids == {"feed-acme"}
    assert cfg_declared.declared_source_ids_complete is True
    state = core.new_state()
    # Pin the policy digest so the pass keeps the stored validators, which only the removal may drop.
    policy = load_policy(pipeline.watchlist.active_path(None, cfg_declared.state_path))
    pipeline._reset_validators_on_policy_change(state, policy)
    state["carry"] = {"feed-acme": [_captured_page_change("feed-acme")]}
    state["feeds"] = {"feed-acme": {"url_digest": "d", "etag": "e"}}
    state["changedetection"] = {"feed-acme": {"uuid-1": CD_CHANGED}}
    cfg_declared.store().save(state)

    cfg_removed = _sources_config(tmp_path, env=env)  # the entry was deleted from the configuration
    assert cfg_removed.declared_source_ids == frozenset()
    assert cfg_removed.declared_source_ids_complete is True
    assert (
        pipeline.run_pass(
            cfg_removed,
            [],
            [FakeNotifier()],
            http=_watches_http(CD_CHANGED),
            clock=lambda: float(NOW),
            sleep=lambda seconds: None,
        )
        == 0
    )
    stored = cfg_declared.store().load()
    assert not (stored.get("carry") or {}), "a resolved removal still discards the carry"
    assert not (stored.get("feeds") or {}), "a resolved removal still discards the validators"
    assert not (stored.get("changedetection") or {}), "a resolved removal still discards the cursors"


# --- admission keeps its independent bounds --------------------------------------------------------


def test_a_warning_queued_in_the_quiet_window_leaves_the_room_for_a_critical(tmp_path):
    """A warning classified inside the window is held, so the critical that follows fits in the same pass."""
    night = local_epoch(23)
    path = tmp_path / "quiet-two.yml"
    path.write_text(
        "sources:\n  - id: vendor\n    type: rss\n    url: https://feeds.example.com/rss\n"
        "notifiers:\n  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
        "quiet_hours: 22:00-07:00\n"
        f"state_path: {tmp_path}/state.json\n"
    )
    cfg = load_config(path, {})
    state = core.new_state()
    state["seeded"] = {"vendor": True}
    cfg.store().save(state)
    body = _rss_document(
        _rss_item("Vendor advisory with no identifier", "warning-1", night - 7200),
        _rss_item("Vendor advisory CVE-2026-7777", "critical-1", night - 3600),
    )
    kev = {"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-2026-7777"}]}

    def http(method, url, headers, payload):
        if url == "https://feeds.example.com/rss":
            return 200, {}, body
        if _is_kev_request(url):
            return 200, {}, json.dumps(kev).encode()
        return 404, {}, b""

    notifier = FakeNotifier(200)
    assert (
        pipeline.run_pass(
            cfg,
            [RssSource("vendor", "https://feeds.example.com/rss")],
            [notifier],
            http=http,
            clock=lambda: float(night),
            sleep=lambda seconds: None,
        )
        == 0
    )
    assert [message["ids"] for message in notifier.sent] == [["CVE-2026-7777"]], (
        "the warning queued during the window must not take the room the critical needs"
    )
    stored = cfg.store().load()
    assert [(entry["tag"], entry["ids"]) for entry in stored["pending"]] == [("warning", ["src:vendor:warning-1"])]
    assert "attempts" not in stored["pending"][0], "the held warning was never attempted"


def test_a_full_sendable_queue_still_leaves_new_items_in_carry(tmp_path):
    """DELIVERY_CAP still bounds admission: five sendable messages leave no room for a sixth."""
    policy = make_policy(tmp_path)
    state = core.new_state()
    state["pending"] = [queued_message(f"CVE-2026-{number}") for number in range(1, 6)]
    fresh = core.Item(
        "vendor:new",
        "Vendor advisory CVE-2026-9999",
        "https://vendor.example/new",
        "",
        NOW - 60,
        ("CVE-2026-9999",),
    )
    left = core.classify_new(
        state,
        [fresh],
        core.Intel(None, {}, lambda: 0.0, lambda seconds: None),
        frozenset(),
        True,
        NOW,
        "",
        policy,
        share=core.DELIVERY_CAP,
        thresholds=DEFAULT_THRESHOLDS,
    )
    assert [item.guid for item in left] == ["vendor:new"], "the sixth message must be carried, not queued"
    assert len(state["pending"]) == core.DELIVERY_CAP, "the sendable queue is still bounded by the delivery cap"


def test_admission_keeps_parking_and_the_lookup_budget_independent(tmp_path):
    """Admission counts delivery room only: parking is untouched and MAX_CLASSIFY still bounds lookups."""
    policy = make_policy(tmp_path)
    parked = {
        "kind": "new",
        "tag": "warning",
        "title": "WARNING: parked advisory",
        "body": "",
        "ids": ["CVE-2026-2"],
        "cves": ["CVE-2026-2"],
        "levels": {"CVE-2026-2": "warning"},
        "kev_only": [],
        "scores": {"CVE-2026-2": 7.5},
        "thresholds": [9.0, 0.10, 4.0],
        "source": "Vendor",
        "link": "https://vendor.example/2",
        "source_id": "vendor",
        "attempts": core.MAX_DELIVERY_ATTEMPTS,
        "first_attempt_at": NOW - 7200,
        "last_status": 500,
    }

    class LowIntel(core.Intel):
        """A complete, low measurement for any CVE: each item is suppressed, so nothing is queued."""

        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda seconds: None)

        def cves(self, cves, **ignored):
            return {cve: core.CveFacts(2.0, None, None, None, True) for cve in cves}

    state = core.new_state()
    state["parked"] = [dict(parked)]
    warning = core.Item("vendor:w", "Vendor advisory", "https://vendor.example/w", "", NOW - 60, ())
    assert (
        core.classify_new(
            state,
            [warning],
            LowIntel(),
            frozenset(),
            True,
            NOW,
            "",
            policy,
            share=core.DELIVERY_CAP,
            thresholds=DEFAULT_THRESHOLDS,
        )
        == []
    )
    assert state["parked"] == [parked], "classification admission must not touch a parked entry"

    bounded = core.new_state()
    items = [
        core.Item(
            f"vendor:{number}", f"Advisory CVE-2026-{1000 + number}", "", "", None, (f"CVE-2026-{1000 + number}",)
        )
        for number in range(core.MAX_CLASSIFY + 5)
    ]
    left = core.classify_new(
        bounded,
        items,
        LowIntel(),
        frozenset(),
        True,
        NOW,
        "",
        policy,
        share=core.DELIVERY_CAP,
        thresholds=DEFAULT_THRESHOLDS,
    )
    assert len(bounded["watch"]) == core.MAX_CLASSIFY, "MAX_CLASSIFY is still the independent lookup bound"
    assert len(left) == 5, "the items past the lookup budget are carried, not classified"
    assert bounded["pending"] == [], "a suppressed advisory is never queued"
