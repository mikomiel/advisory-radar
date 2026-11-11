"""Pipeline and config tests with fake HTTP and fake plugins."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from advisory_radar import core, pipeline
from advisory_radar.config import ConfigError, load_config
from advisory_radar.plugins import SourceWindow
from advisory_radar.sources import RssSource
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


def test_a_document_from_an_older_reader_is_normalised_before_it_is_judged(tmp_path, caplog):
    """Identities an older reader stored must not deliver twice, nor forge a log line, on the next pass."""
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    state = core.new_state()
    # What the previous version could leave behind: a link-cased identity carrying DEL in ``seen``, and a
    # carried candidate whose identity carries a publisher-authored newline. Neither passes a reader again.
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
        b"<guid>https://vendor.example.com/a</guid><description>no identifiers</description></item>"
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
        "the advisory recorded under a control-bearing identity must not be delivered again"
    )
    stored = json.loads((tmp_path / "state.json").read_text())
    assert "src:test:https://vendor.example.com/a\u007f" in stored["seen"], (
        "the stored document is not rewritten: the claim is compared in its normalised form instead"
    )
