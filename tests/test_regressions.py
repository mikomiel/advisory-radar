"""Regression tests for the first independent review of the public repository.

Each test pins one defect the reviewer found: the packaged default watchlist, the
notifier config keys, the web auth token, the pass lock, an empty notifier list,
per-source enrichment clocks, secret collection and the persisted run record.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisory_radar import core, pipeline
from advisory_radar.config import collect_secrets, load_config
from advisory_radar.notifiers import AppriseNotifier, DiscordWebhookNotifier, build_notifier
from advisory_radar.sources import RssSource
from advisory_radar.state import state_lock
from advisory_radar.watchlist import load_policy

NOW = 1792600000
KIND = "security-watchlist.v1"


class Notifier:
    id = "fake"

    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.sent: list[dict] = []

    def send(self, entry, http):
        self.sent.append(entry)
        return self.status


def feed(guid: str, title: str, pub: str = "Thu, 21 Oct 2026 10:00:00 +0000") -> bytes:
    return (
        '<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>'
        "<link>https://feeds.example.com/</link>"
        f"<item><title>{title}</title><link>https://vendor.example.com/{guid}</link>"
        f"<guid>{guid}</guid><description>Fixes things.</description><pubDate>{pub}</pubDate></item>"
        "</channel></rss>"
    ).encode()


def http_for(feeds: dict[str, bytes]):
    def http(method, url, headers, body):
        if url in feeds:
            return 200, {}, feeds[url]
        if "cveawg.mitre.org" in url or "api.first.org" in url:
            return 404, {}, b"{}"
        if "cisa.gov" in url:
            return 200, {}, json.dumps({"vulnerabilities": []}).encode()
        return 404, {}, b""

    return http


def config(tmp_path: Path, *, watchlist: bool = True, notifiers: bool = True) -> object:
    path = tmp_path / "config.yml"
    body = "sources:\n  - id: s1\n    type: rss\n    url: https://feeds.example.com/a\n"
    body += "  - id: s2\n    type: rss\n    url: https://feeds.example.com/b\n"
    if notifiers:
        body += "notifiers:\n  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
    else:
        body += "notifiers: []\n"
    body += f"state_path: {tmp_path}/state.json\n"
    if watchlist:
        watch = tmp_path / "watchlist.json"
        watch.write_text(
            json.dumps({"schema": KIND, "debian_source_packages": ["curl"], "excluded_products": [], "products": []})
        )
        body += f"watchlist: {watch}\n"
    path.write_text(body)
    return load_config(path, {})


def test_packaged_default_watchlist_loads():
    """A fresh clone must run with no watchlist configured."""
    policy = load_policy(Path("src/advisory_radar/watchlist.default.json"))
    assert policy is not None


def test_notifiers_build_from_the_keys_the_config_accepts():
    """`password` and `url` are the documented keys; `*_env` variants are rejected by the parser."""
    apprise = build_notifier({"id": "a", "type": "apprise", "url": "https://apprise.example.com", "password": "pw"}, {})
    assert isinstance(apprise, AppriseNotifier) and apprise.password == "pw"
    discord = build_notifier({"id": "d", "type": "discord_webhook", "url": "https://discord.example/x"}, {})
    assert isinstance(discord, DiscordWebhookNotifier) and discord.url == "https://discord.example/x"


def test_web_ui_refuses_an_empty_auth_token(tmp_path):
    from advisory_radar.web import create_app

    with pytest.raises(ValueError):
        create_app(config(tmp_path), {})


def test_pass_skips_when_another_pass_holds_the_lock(tmp_path):
    cfg = config(tmp_path)
    notifier = Notifier()
    feeds = {"https://feeds.example.com/a": feed("g1", "CVE-2026-4242 thing")}
    with state_lock(cfg.state_path):
        code = pipeline.run_pass(
            cfg,
            [RssSource("s1", "https://feeds.example.com/a")],
            [notifier],
            http=http_for(feeds),
            clock=lambda: float(NOW),
            sleep=lambda s: None,
            lock_blocking=False,
        )
    assert code == 1
    assert not notifier.sent


def test_empty_notifier_list_keeps_messages_pending(tmp_path):
    cfg = config(tmp_path, notifiers=False)
    failing = Notifier(500)  # leaves the message pending for the next pass
    feeds = {"https://feeds.example.com/a": feed("g1", "CVE-2026-4242 thing")}
    source = RssSource("s1", "https://feeds.example.com/a")
    pipeline.run_pass(cfg, [source], [failing], http=http_for(feeds), clock=lambda: float(NOW), sleep=lambda s: None)
    code = pipeline.run_pass(cfg, [source], [], http=http_for(feeds), clock=lambda: float(NOW), sleep=lambda s: None)
    assert code == 1
    state = json.loads(cfg.state_path.read_text())
    assert state["pending"], "an empty notifier list must not consume the pending message"
    assert all(entry["outcome"] != "delivered" for entry in state["seen"].values())


def test_enrichment_clocks_survive_a_second_source(tmp_path):
    cfg = config(tmp_path)
    state = core.new_state()
    # item guids are source-scoped in state
    state["enrich_retry"] = {"s1:g1": 1, "s2:g2": 2}
    state["enrich_pending"] = {"s1:g1": 1, "s2:g2": 2}
    from advisory_radar.state import save_state

    save_state(cfg.state_path, state)
    feeds = {
        "https://feeds.example.com/a": feed("g1", "first"),
        "https://feeds.example.com/b": feed("g2", "second"),
    }
    pipeline.run_pass(
        cfg,
        [RssSource("s1", "https://feeds.example.com/a"), RssSource("s2", "https://feeds.example.com/b")],
        [Notifier()],
        http=http_for(feeds),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    reloaded = json.loads(cfg.state_path.read_text())
    assert set(reloaded["enrich_retry"]) == {"s1:g1", "s2:g2"}, "one source must not erase the other's retry clock"


def test_collect_secrets_reads_names_before_expansion(tmp_path):
    path = tmp_path / "c.yml"
    path.write_text("sources: []\nnotifiers: []\nstate_path: /tmp/x.json\n")
    cfg = load_config(path, {})
    assert collect_secrets(cfg) == []
    path.write_text(
        "sources: []\nnotifiers:\n  - id: d\n    type: discord_webhook\n    url: ${HOOK_URL}\nstate_path: /tmp/x.json\n"
    )
    assert collect_secrets(load_config(path, {"HOOK_URL": "https://secret.example/x"})) == ["HOOK_URL"]


def test_run_record_is_persisted(tmp_path):
    cfg = config(tmp_path)
    feeds = {"https://feeds.example.com/a": feed("g1", "first")}
    pipeline.run_pass(
        cfg,
        [RssSource("s1", "https://feeds.example.com/a")],
        [Notifier()],
        http=http_for(feeds),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    state = json.loads(cfg.state_path.read_text())
    assert state["runs"], "the pass record must be on disk, not only in memory"
    assert state["runs"][-1]["at"] == NOW


# ---------------------------------------------------------------------------
# Second review round


class WindowSource:
    """A source that returns a fixed window, so a test controls truncation and identity."""

    def __init__(self, source_id: str, items, truncated: bool = False, host: str = "feeds.example.com") -> None:
        self.id = source_id
        self._items = tuple(items)
        self.truncated = truncated
        self.host = host

    def fetch(self, http):
        from advisory_radar.plugins import SourceWindow

        return SourceWindow(self.id, self._items, self.truncated, self.host)


def item(guid: str, title: str, link: str = "https://vendor.example.com/a", summary: str = "notes") -> core.Item:
    return core.Item(guid, title, link, summary, NOW - 3600, ())


def test_malformed_link_does_not_stop_a_pass(tmp_path):
    cfg = config(tmp_path)
    policy = load_policy(Path(cfg.watchlist_path))
    assert core.passes_filter(item("g1", "note", link="https://["), policy) is True
    code = pipeline.run_pass(
        cfg,
        [WindowSource("s1", [item("g1", "vendor note", link="https://[")])],
        [Notifier()],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code == 0


def test_guid_collision_across_sources_keeps_both(tmp_path):
    cfg = config(tmp_path)
    notifier = Notifier()
    sources = [
        WindowSource("s1", [item("g1", "first vendor note")]),
        WindowSource("s2", [item("g1", "second vendor note")]),
    ]
    pipeline.run_pass(cfg, sources, [notifier], http=http_for({}), clock=lambda: float(NOW), sleep=lambda s: None)
    state = json.loads(cfg.state_path.read_text())
    assert {"src:s1:g1", "src:s2:g1"} <= set(state["seen"]), "two feeds may legitimately use the same guid"


def test_intelligence_cache_is_persisted(tmp_path):
    cfg = config(tmp_path)
    feeds = {"https://feeds.example.com/a": feed("g1", "CVE-2026-4242 thing")}

    def http(method, url, headers, body):
        if "cveawg.mitre.org" in url:
            body = {"containers": {"cna": {"metrics": [{"cvssV3_1": {"baseScore": 9.8}}]}}}
            return 200, {}, json.dumps(body).encode()
        if "api.first.org" in url:
            return 200, {}, json.dumps({"data": []}).encode()
        if "cisa.gov" in url:
            return 200, {}, json.dumps({"vulnerabilities": []}).encode()
        if url in feeds:
            return 200, {}, feeds[url]
        return 404, {}, b""

    pipeline.run_pass(
        cfg,
        [RssSource("s1", "https://feeds.example.com/a")],
        [Notifier()],
        http=http,
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    state = json.loads(cfg.state_path.read_text())
    assert state["cache"], "lookups made during the pass must reach the state file"


def test_configured_product_scope_filters_items(tmp_path):
    watch = tmp_path / "watchlist.json"
    watch.write_text(
        json.dumps(
            {
                "schema": KIND,
                "debian_source_packages": ["curl"],
                "excluded_products": [],
                "products": [{"id": "libfoo", "aliases": ["foo"], "domains": ["vendor.example.com"]}],
            }
        )
    )
    policy = load_policy(watch)
    assert core.passes_filter(item("g1", "libfoo advisory"), policy) is True
    assert core.passes_filter(item("g2", "unrelated product news", link="https://other.example.com/x"), policy) is False
    excluded = tmp_path / "excluded.json"
    excluded.write_text(
        json.dumps(
            {
                "schema": KIND,
                "debian_source_packages": ["curl"],
                "excluded_products": ["libfoo"],
                "products": [{"id": "libfoo", "aliases": ["libfoo"], "domains": ["vendor.example.com"]}],
            }
        )
    )
    assert core.passes_filter(item("g3", "libfoo advisory"), load_policy(excluded)) is False


def test_first_run_window_is_saved_and_gap_detected(tmp_path):
    cfg = config(tmp_path)
    first = pipeline.run_pass(
        cfg,
        [WindowSource("s1", [item("g1", "first")], truncated=True)],
        [Notifier()],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert first == 0
    state = json.loads(cfg.state_path.read_text())
    assert state["windows"]["s1"] == ["s1:g1"], "the first window must be persisted for the next pass"
    second = pipeline.run_pass(
        cfg,
        [WindowSource("s1", [item("g2", "second")], truncated=True)],
        [Notifier()],
        http=http_for({}),
        clock=lambda: float(NOW + 60),
        sleep=lambda s: None,
    )
    assert second == 1, "a full window disjoint from the previous one must report a gap"
