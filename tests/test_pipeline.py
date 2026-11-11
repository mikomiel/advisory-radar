"""Pipeline and config tests with fake HTTP and fake plugins."""

from __future__ import annotations

import json
import logging
import sys
import types
from pathlib import Path

import pytest

from advisory_radar import core, pipeline, storage
from advisory_radar.config import Config, ConfigError, load_config
from advisory_radar.plugins import SourceWindow
from advisory_radar.sources import RssSource, WebhookSource
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
    # first run seeds old items as delivered (history, not news); later passes mark them backlog
    assert state["seen"]["CVE-2026-4242"]["outcome"] == "delivered"


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
