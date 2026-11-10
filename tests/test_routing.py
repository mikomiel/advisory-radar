"""Routing tests: the pure matcher, the configuration validator and the queued-entry plumbing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisory_radar import core, pipeline, routing
from advisory_radar.config import ConfigError, load_config
from advisory_radar.sources import RssSource
from advisory_radar.watchlist import load_policy

NOW = 1792600000
FEED_URL = "https://feeds.example.com/a"
ENABLED = ["discord", "matrix", "phone"]


class TestSelect:
    """The matcher is a pure function: no state, plugins or HTTP."""

    def test_first_match_wins_rather_than_the_most_specific_rule(self):
        routes = [
            {"match": {"tag": "critical"}, "notifiers": ["phone"]},
            {"match": {"source": "php-releases"}, "notifiers": ["matrix"]},
        ]
        entry = {"tag": "critical", "source_id": "php-releases", "ids": ["CVE-2026-1"]}
        assert routing.select(entry, routes, ["discord"], ENABLED) == (["phone"], "route 1")

    def test_rule_order_is_the_configuration_order(self):
        routes = [
            {"match": {"ids": "CVE-2026-*"}, "notifiers": ["discord"]},
            {"match": {"ids": "CVE-*"}, "notifiers": ["phone"]},
        ]
        assert routing.select({"tag": "warning", "ids": ["CVE-2026-1"]}, routes, (), ENABLED) == (
            ["discord"],
            "route 1",
        )
        assert routing.select({"tag": "warning", "ids": ["CVE-2025-1"]}, routes, (), ENABLED) == (["phone"], "route 2")

    def test_source_matches_the_recorded_source_id(self):
        routes = [{"match": {"source": "php-releases"}, "notifiers": ["matrix"]}]
        entry = {"source_id": "php-releases", "tag": "warning"}
        assert routing.select(entry, routes, (), ENABLED) == (["matrix"], "route 1")
        # An entry without a source id (an escalation, an Adobe bulletin) never matches a source rule.
        assert routing.select({"tag": "warning"}, routes, ["discord"], ENABLED) == (["discord"], "default")
        assert routing.select({"source_id": "other", "tag": "warning"}, routes, (), ENABLED) == (ENABLED, "all")

    def test_tag_matches_exactly(self):
        routes = [{"match": {"tag": "critical"}, "notifiers": ["phone"]}]
        assert routing.select({"tag": "critical"}, routes, (), ENABLED) == (["phone"], "route 1")
        assert routing.select({"tag": "warning"}, routes, (), ENABLED) == (ENABLED, "all")

    def test_product_matches_a_recorded_watchlist_product(self):
        routes = [{"match": {"product": "magento"}, "notifiers": ["matrix"]}]
        assert routing.select({"products": ["magento", "php"]}, routes, (), ENABLED) == (["matrix"], "route 1")
        assert routing.select({"products": ["php"]}, routes, (), ENABLED) == (ENABLED, "all")

    def test_ids_match_a_wildcard_case_insensitively(self):
        routes = [{"match": {"ids": "cve-2026-*"}, "notifiers": ["phone"]}]
        assert routing.select({"ids": ["CVE-2026-4242"]}, routes, (), ENABLED) == (["phone"], "route 1")
        assert routing.select({"ids": ["GHSA-aaaa-bbbb-cccc"]}, routes, (), ENABLED) == (ENABLED, "all")

    def test_every_key_in_one_rule_must_match(self):
        routes = [{"match": {"tag": "critical", "product": "magento"}, "notifiers": ["phone"]}]
        assert routing.select({"tag": "critical", "products": ["magento"]}, routes, (), ENABLED) == (
            ["phone"],
            "route 1",
        )
        assert routing.select({"tag": "warning", "products": ["magento"]}, routes, (), ENABLED) == (ENABLED, "all")

    def test_default_applies_when_no_route_matches(self):
        routes = [{"match": {"tag": "critical"}, "notifiers": ["phone"]}]
        entry = {"tag": "warning", "source_id": "php-releases"}
        assert routing.select(entry, routes, ["discord"], ENABLED) == (["discord"], "default")

    def test_no_match_and_no_default_reaches_every_enabled_notifier(self):
        routes = [{"match": {"tag": "critical"}, "notifiers": ["phone"]}]
        assert routing.select({"tag": "warning"}, routes, (), ENABLED) == (ENABLED, "all")

    def test_no_routes_reaches_every_enabled_notifier(self):
        assert routing.select({"tag": "critical"}, [], (), ENABLED) == (ENABLED, "all")
        # A default alone does not change that: without a route the feature is off, exactly as before.
        assert routing.select({"tag": "critical"}, [], ["discord"], ENABLED) == (ENABLED, "all")

    def test_a_malformed_entry_does_not_raise(self):
        routes = [
            {"match": {"source": "php-releases"}, "notifiers": ["matrix"]},
            {"match": {"product": "magento"}, "notifiers": ["matrix"]},
        ]
        # No source id, a numeric source id, a string products, a number, and no ids at all.
        for entry in ({}, {"source_id": 7}, {"products": "magento"}, {"products": 7}, {"ids": None}):
            assert routing.select(entry, routes, (), ENABLED) == (ENABLED, "all")
        # A bare string ids is not iterated as characters, so "C*" cannot match "CVE-2026-1".
        assert routing.select(
            {"ids": "CVE-2026-1"}, [{"match": {"ids": "C*"}, "notifiers": ["phone"]}], (), ENABLED
        ) == (ENABLED, "all")
        # A malformed rule with no usable match key never swallows a message.
        assert routing.select({"tag": "critical"}, [{"match": {}}, {"notifiers": ["phone"]}], (), ENABLED) == (
            ENABLED,
            "all",
        )


def write_config(tmp_path: Path, extra: str = "") -> Path:
    """A config with three enabled notifiers and one disabled, plus the extra YAML block."""
    path = tmp_path / "config.yml"
    path.write_text(
        "sources: []\n"
        "notifiers:\n"
        "  - id: discord\n    type: webhook\n    url: https://hooks.example.com/d\n"
        "  - id: matrix\n    type: webhook\n    url: https://hooks.example.com/m\n"
        "  - id: phone\n    type: webhook\n    url: https://hooks.example.com/p\n"
        "  - id: disabled-channel\n    type: webhook\n    url: https://hooks.example.com/o\n    enabled: false\n"
        f"{extra}"
    )
    return path


def test_a_valid_block_loads_into_the_config(tmp_path):
    cfg = load_config(
        write_config(
            tmp_path,
            "routes:\n"
            "  - match: {source: php-releases}\n"
            "    notifiers: [matrix]\n"
            "  - match: {tag: critical}\n"
            "    notifiers: [phone, discord]\n"
            "default: [discord]\n",
        ),
        {},
    )
    assert cfg.routes == (
        {"match": {"source": "php-releases"}, "notifiers": ("matrix",)},
        {"match": {"tag": "critical"}, "notifiers": ("phone", "discord")},
    )
    assert cfg.default_notifiers == ("discord",)


def test_an_absent_or_empty_block_changes_nothing(tmp_path):
    for extra in ("", "routes: []\n"):
        cfg = load_config(write_config(tmp_path, extra), {})
        assert cfg.routes == () and cfg.default_notifiers == ()
        assert cfg.notifiers and all(notifier["id"] != "disabled-channel" for notifier in cfg.notifiers)


@pytest.mark.parametrize(
    "extra",
    [
        "routes:\n  - match: {severity: critical}\n    notifiers: [discord]\n",  # unknown match key
        "routes:\n  - match: {}\n    notifiers: [discord]\n",  # empty match
        "routes:\n  - notifiers: [discord]\n",  # match missing
        "routes:\n  - match: {tag: critical}\n",  # notifiers missing
        "routes:\n  - match: {tag: critical}\n    notifiers: []\n",  # empty list
        "routes:\n  - match: {tag: critical}\n    notifiers: [nope]\n",  # unknown notifier
        "routes:\n  - match: {tag: critical}\n    notifiers: [disabled-channel]\n",  # disabled notifier
        "routes:\n  - match: {tag: ''}\n    notifiers: [discord]\n",  # empty matcher value
        "routes:\n  - match: {tag: critical}\n    notifiers: [discord]\n    extra: 1\n",  # unknown route key
        "routes: {}\n",  # not a list
        "default: []\n",  # empty default
        "default: [disabled-channel]\n",  # disabled default
    ],
)
def test_an_invalid_routing_block_is_refused(tmp_path, extra):
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, extra), {})


def product_policy(tmp_path: Path):
    watch = tmp_path / "watchlist.json"
    watch.write_text(
        json.dumps(
            {
                "schema": "security-watchlist.v1",
                "debian_source_packages": ["curl"],
                "excluded_products": [],
                "products": [{"id": "magento", "aliases": ["magento"], "domains": ["vendor.example.com"]}],
            }
        )
    )
    return load_policy(watch)


def test_classify_new_records_the_source_id_and_matched_products(tmp_path):
    policy = product_policy(tmp_path)
    state = core.new_state()
    feed_item = core.Item("g1", "Magento security note", "https://vendor.example.com/a1", "notes", NOW - 60, ())
    # The item names no CVE, so the pipeline never calls a lookup this stub would have to answer.
    intel = core.Intel(None, {}, lambda: 0.0, lambda seconds: None)
    core.classify_new(
        state,
        [feed_item],
        intel,
        frozenset(),
        True,
        NOW,
        "vendor.example.com",
        policy,
        source_id="php-releases",
    )
    queued = state["pending"][0]
    assert queued["source_id"] == "php-releases"
    assert queued["products"] == ["magento"]


def feed(guid: str, title: str, link: str) -> bytes:
    return (
        '<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>'
        "<link>https://feeds.example.com/</link>"
        f"<item><title>{title}</title><link>{link}</link><guid>{guid}</guid>"
        "<description>notes</description><pubDate>Wed, 21 Oct 2026 10:00:00 +0000</pubDate></item>"
        "</channel></rss>"
    ).encode()


def http_for(feed_body: bytes):
    def http(method, url, headers, body):
        if url == FEED_URL:
            return 200, {}, feed_body
        if "cisa.gov" in url:
            return 200, {}, json.dumps({"vulnerabilities": []}).encode()
        return 404, {}, b""

    return http


class RecordingNotifier:
    """Records what it was asked to send and answers with its configured status."""

    def __init__(self, notifier_id: str, status: int = 200) -> None:
        self.id = notifier_id
        self.status = status
        self.sent: list[dict] = []

    def send(self, entry, http) -> int:
        self.sent.append(entry)
        return self.status


class FailingNotifier(RecordingNotifier):
    """Fails delivery, so the queued message stays in the state file where a test can read it back."""

    def __init__(self) -> None:
        super().__init__("fake", status=500)


def pass_config(tmp_path: Path, extra: str = ""):
    """One RSS source, two webhook notifiers and a product watchlist, plus the extra YAML block."""
    watch = tmp_path / "watchlist.json"
    watch.write_text(
        json.dumps(
            {
                "schema": "security-watchlist.v1",
                "debian_source_packages": ["curl"],
                "excluded_products": [],
                "products": [{"id": "magento", "aliases": ["magento"], "domains": ["vendor.example.com"]}],
            }
        )
    )
    path = tmp_path / "config.yml"
    path.write_text(
        "sources:\n"
        f"  - id: php-releases\n    type: rss\n    url: {FEED_URL}\n"
        "notifiers:\n"
        "  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
        "  - id: matrix\n    type: webhook\n    url: https://hooks.example.com/m\n"
        f"state_path: {tmp_path}/state.json\n"
        f"watchlist: {watch}\n"
        f"{extra}"
    )
    return load_config(path, {})


def test_the_pipeline_records_the_configured_source_id_on_a_queued_message(tmp_path):
    cfg = pass_config(tmp_path)
    notifier = FailingNotifier()
    code = pipeline.run_pass(
        cfg,
        [RssSource("php-releases", FEED_URL)],
        [notifier],
        http=http_for(feed("g1", "Magento security note", "https://vendor.example.com/a1")),
        clock=lambda: float(NOW),
        sleep=lambda seconds: None,
    )
    assert code == 1
    pending = json.loads(cfg.state_path.read_text())["pending"]
    assert pending[0]["source_id"] == "php-releases"
    assert pending[0]["products"] == ["magento"]


def test_the_pipeline_delivers_through_the_configured_routes(tmp_path):
    cfg = pass_config(
        tmp_path,
        "routes:\n  - match: {source: php-releases}\n    notifiers: [matrix]\ndefault: [fake]\n",
    )
    accepted, routed = RecordingNotifier("fake"), RecordingNotifier("matrix")
    code = pipeline.run_pass(
        cfg,
        [RssSource("php-releases", FEED_URL)],
        [accepted, routed],
        http=http_for(feed("g1", "Magento security note", "https://vendor.example.com/a1")),
        clock=lambda: float(NOW),
        sleep=lambda seconds: None,
    )
    assert code == 0
    assert len(routed.sent) == 1, "the route selects the source's channel"
    assert accepted.sent == [], "a channel the route does not select receives nothing"
    assert json.loads(cfg.state_path.read_text())["pending"] == []
