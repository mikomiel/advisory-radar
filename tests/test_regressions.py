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

    def fetch(self, http, state=None):  # the state-aware protocol is a superset of fetch(http)
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


# ---------------------------------------------------------------------------
# Third review round


class EchoNotifier(Notifier):
    def __init__(self, status: int = 200) -> None:
        super().__init__(status)
        self.calls = 0

    def send(self, entry, http):
        self.calls += 1
        return super().send(entry, http)


class ExplodingNotifier(Notifier):
    id = "boom"

    def send(self, entry, http):
        raise RuntimeError("bad url")


class FailingSource(WindowSource):
    def fetch(self, http, state=None):
        raise RuntimeError("feed down")


def test_a_non_string_watchlist_is_refused(tmp_path):
    path = tmp_path / "c.yml"
    path.write_text("sources: []\nnotifiers: []\nwatchlist:\n  products: [x]\n")
    from advisory_radar.config import ConfigError

    with pytest.raises(ConfigError):
        load_config(path, {})


def test_an_excluded_product_is_matched_without_a_product_definition(tmp_path):
    watch = tmp_path / "w.json"
    watch.write_text(
        json.dumps(
            {
                "schema": KIND,
                "debian_source_packages": ["curl"],
                "excluded_products": ["legacy-app"],
                "products": [{"id": "nodejs", "aliases": ["node.js"], "domains": ["nodejs.org"]}],
            }
        )
    )
    policy = load_policy(watch)
    assert core.passes_filter(item("g1", "nodejs advisory"), policy) is True
    assert core.passes_filter(item("g2", "legacy-app advisory"), policy) is False
    assert core.passes_filter(item("g3", "nodejs and legacy-app"), policy) is False


def test_a_raising_notifier_is_a_failed_attempt_not_a_crash(tmp_path):
    cfg = config(tmp_path)
    working = EchoNotifier()
    feeds = {"https://feeds.example.com/a": feed("g1", "CVE-2026-4242 thing")}
    for _ in range(2):
        pipeline.run_pass(
            cfg,
            [RssSource("s1", "https://feeds.example.com/a")],
            [working, ExplodingNotifier()],
            http=http_for(feeds),
            clock=lambda: float(NOW),
            sleep=lambda s: None,
        )
    assert working.calls == 1, "a retry must not re-send to the notifier that already had it"
    state = json.loads(cfg.state_path.read_text())
    assert state["pending"] and state["pending"][0]["attempts"] == 2


def test_a_source_outage_keeps_that_sources_retry_clocks(tmp_path):
    cfg = config(tmp_path)
    state = core.new_state()
    state["enrich_retry"] = {"s1:g1": 1, "s2:g2": 2}
    from advisory_radar.state import save_state

    save_state(cfg.state_path, state)
    pipeline.run_pass(
        cfg,
        [FailingSource("s1", []), WindowSource("s2", [item("g2", "second")])],
        [Notifier()],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    reloaded = json.loads(cfg.state_path.read_text())
    assert "s1:g1" in reloaded["enrich_retry"], "an outage must not erase the retry deadline"
    assert "s2:g2" in reloaded["enrich_retry"]


# ---------------------------------------------------------------------------
# Fourth review round


def test_file_backed_secret_values_are_redacted(tmp_path):
    import logging

    from advisory_radar.config import secret_values
    from advisory_radar.http import RedactFilter

    secret_file = tmp_path / "hook"
    secret_file.write_text("https://hooks.example.com/SUPERSECRET\n")
    cfg_path = tmp_path / "c.yml"
    cfg_path.write_text(
        "sources: []\nnotifiers:\n  - id: d\n    type: discord_webhook\n    url: ${HOOK_URL_FILE}\n"
        "state_path: /tmp/x.json\n"
    )
    cfg = load_config(cfg_path, {"HOOK_URL_FILE": str(secret_file)})
    assert cfg.notifiers[0]["url"] == "https://hooks.example.com/SUPERSECRET"
    assert "https://hooks.example.com/SUPERSECRET" in secret_values(cfg)
    record = logging.LogRecord(
        "t", logging.ERROR, __file__, 1, "bad url %s", ("https://hooks.example.com/SUPERSECRET",), None
    )
    RedactFilter(secret_values(cfg)).filter(record)
    assert "SUPERSECRET" not in record.getMessage()


def test_a_malformed_kev_catalog_is_not_trusted(tmp_path):
    from advisory_radar.kev import KEV_CACHE_SCHEMA, load_kev
    from advisory_radar.state import save_state

    cache = tmp_path / "kev.json"
    save_state(cache, {"schema": KEV_CACHE_SCHEMA, "etag": "", "last_modified": "", "cves": ["CVE-2026-1111"]})

    def http(method, url, headers, body):
        return 200, {}, json.dumps({"vulnerabilities": [{"nope": 1}]}).encode()

    cves, known = load_kev(http, cache, save=False)
    assert known is True and cves == frozenset({"CVE-2026-1111"}), "a reshaped catalog must fall back to the cache"

    def empty(method, url, headers, body):
        return 200, {}, json.dumps({"vulnerabilities": []}).encode()

    cves, known = load_kev(empty, tmp_path / "none.json", save=False)
    assert known is False and cves == frozenset()


def test_non_finite_and_out_of_range_numbers_are_unknown():
    assert core._number("Infinity") is None
    assert core._number(float("nan")) is None
    assert core._bounded(-1.0, 0.0, 10.0) is None
    assert core._bounded(9.8, 0.0, 10.0) == 9.8


def test_a_vendor_feed_keeps_its_advisory_link():
    title, body = core.render(
        "critical",
        "CVE-2026-4242 in node",
        ["CVE-2026-4242"],
        "9.8",
        "",
        "https://nodejs.org/en/blog/vulnerability/x",
        "notes",
        NOW,
        "nodejs.org",
        "Node.js feed",
        "https://nodejs.org/en/feed",
    )
    assert "https://nodejs.org/en/blog/vulnerability/x" in (title + body)


# ---------------------------------------------------------------------------
# Fifth review round


def test_a_notifier_redirect_is_not_a_successful_delivery(tmp_path):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from advisory_radar.http import urllib_http

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == "/hook":
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, _ = urllib_http("POST", f"http://127.0.0.1:{server.server_port}/hook", {}, b"{}")
    finally:
        server.shutdown()
    assert status == 302, "a redirect must be reported as such, not followed into a 200"


def test_a_failing_watch_does_not_starve_the_next_one():
    state = core.new_state()
    now = 1792600000
    failing = [f"CVE-2026-{1000 + index}" for index in range(core.MAX_REEVAL)]
    healthy = "CVE-2026-9999"
    for cve in (*failing, healthy):
        state["watch"][cve] = {"since": now - 10 * 86400, "last_eval": now - 2 * 86400, "level": "warning"}

    class Intel:
        def cves(self, cves, force=False):
            facts = {cve: core.CveFacts(None, None, None, None, False) for cve in cves}
            if healthy in cves:
                facts[healthy] = core.CveFacts(None, None, None, None, True)
            return facts

    core.reevaluate(state, Intel(), frozenset(), True, now, "")
    core.reevaluate(state, Intel(), frozenset(), True, now, "")
    assert state["watch"][healthy]["last_eval"] == now, "a failing batch must not block a healthy watch"


def test_a_source_that_fails_on_the_first_pass_is_seeded_when_it_recovers(tmp_path):
    cfg = config(tmp_path)
    notifier = Notifier()
    old = core.Item("g9", "old historical advisory", "https://vendor.example.com/old", "notes", NOW - 2 * 86400, ())
    first = pipeline.run_pass(
        cfg,
        [WindowSource("s2", [item("g1", "fresh")]), FailingSource("s1", [])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert first == 1
    pipeline.run_pass(
        cfg,
        [WindowSource("s2", [item("g1", "fresh")]), WindowSource("s1", [old])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW + 60),
        sleep=lambda s: None,
    )
    state = json.loads(cfg.state_path.read_text())
    assert "src:s1:g9" in state["seen"], "a recovering source's history must be seeded, not delivered"
    assert not any("old historical" in entry["title"] for entry in notifier.sent)


def test_dry_run_reports_a_window_gap(tmp_path):
    cfg = config(tmp_path)
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", [item("g1", "first")], truncated=True)],
        [Notifier()],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    code = pipeline.run_pass(
        cfg,
        [WindowSource("s1", [item("g2", "second")], truncated=True)],
        [Notifier()],
        http=http_for({}),
        clock=lambda: float(NOW + 60),
        sleep=lambda s: None,
        dry_run=True,
    )
    assert code == 1
