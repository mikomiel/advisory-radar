"""Pipeline and config tests with fake HTTP and fake plugins."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisory_radar import core, pipeline
from advisory_radar.config import ConfigError, load_config
from advisory_radar.sources import RssSource
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
    "containers": {
        "cna": {"metrics": [{"cvssV3_1": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"}}]}
    }
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
    assert not (tmp_path / "state.json").exists()  # first run with no readable source writes nothing


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
