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
            body = {
                "cveMetadata": {"cveId": "CVE-2026-4242", "state": "PUBLISHED"},
                "containers": {"cna": {"metrics": [{"cvssV3_1": {"baseScore": 9.8}}]}},
            }
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
    assert cves == frozenset({"CVE-2026-1111"}), "a reshaped catalog must fall back to the cache for promotion"
    assert known is False, "an unvalidated cache never authorizes a suppression"

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
        def cves(self, cves, force=False, deferred=None):
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


# ---------------------------------------------------------------------------
# Sixth review round


def test_a_config_error_never_echoes_a_secret(tmp_path):
    from advisory_radar.config import ConfigError

    path = tmp_path / "c.yml"
    path.write_text("sources: []\nnotifiers: []\npoll_interval: ${SECRET_INTERVAL}\nstate_path: /tmp/x.json\n")
    with pytest.raises(ConfigError) as caught:
        load_config(path, {"SECRET_INTERVAL": "sup3rsecretvalue"})
    assert "sup3rsecretvalue" not in str(caught.value)


def test_an_unrepresentable_feed_date_does_not_abort_a_pass(tmp_path):
    cfg = config(tmp_path)
    crazy = (
        b'<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>'
        b"<link>https://feeds.example.com/</link>"
        b"<item><title>weird date advisory</title><link>https://vendor.example.com/x</link>"
        b"<guid>gx</guid><description>notes</description><pubDate>Wed, 21 Oct 9999 10:00:00 +0000</pubDate>"
        b"</item></channel></rss>"
    )
    feeds = {"https://feeds.example.com/a": crazy}
    notifier = Notifier()
    code = pipeline.run_pass(
        cfg,
        [RssSource("s1", "https://feeds.example.com/a")],
        [notifier],
        http=http_for(feeds),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code in (0, 1), "an extreme date must not raise out of the pass"
    state = json.loads(cfg.state_path.read_text())
    assert "src:s1:gx" in state["seen"], "the item is recorded, so later passes are not blocked either"


def test_stopping_the_server_does_not_run_another_pass(tmp_path, monkeypatch):
    """`run` returns after uvicorn stops; it must not fall through to an extra pass."""
    import time

    from advisory_radar import cli

    cfg_path = tmp_path / "c.yml"
    cfg_path.write_text(
        "sources:\n  - id: s\n    type: rss\n    url: https://feeds.example.com/a\n"
        "notifiers: []\nstate_path: " + str(tmp_path / "state.json") + "\n"
    )
    calls: list[int] = []

    def fake_run(app, host=None, port=None, log_level=None):
        for _ in range(200):  # let the scheduler take its first pass, then stop like a SIGTERM would
            if calls:
                return None
            time.sleep(0.01)
        return None

    monkeypatch.setattr("uvicorn.run", fake_run)
    monkeypatch.setattr(cli.pipeline, "run_pass", lambda *a, **k: calls.append(1) or 0)
    monkeypatch.setenv("ADVISORY_RADAR_AUTH_TOKEN", "test-token")
    code = cli.main(["--config", str(cfg_path), "run"])
    assert code == 0
    assert len(calls) == 1, "shutdown must not start an extra pass"


def test_a_kev_hit_escalates_even_when_the_scored_lookups_fail():
    """KEV is a local fact: an incomplete CVE.org/EPSS answer must not hide it."""
    state = core.new_state()
    now = 1792600000
    cve = "CVE-2026-5555"
    state["watch"][cve] = {
        "since": now - 3 * 86400,
        "last_eval": now - 2 * 86400,
        "level": "warning",
        "title": "original advisory",
        "link": "https://vendor.example.com/adv",
    }

    class Intel:
        def cves(self, cves, force=False, deferred=None):
            return {name: core.CveFacts(None, None, None, None, False) for name in cves}

    core.reevaluate(state, Intel(), frozenset({cve}), True, now, "")
    queued = [entry for entry in state["pending"] if entry["kind"] == "escalation"]
    assert queued and queued[0]["cves"] == [cve], "a known KEV hit must escalate"
    assert queued[0]["tag"] == "critical"


# ---------------------------------------------------------------------------
# Eighth review round


def test_a_failing_first_source_does_not_block_the_next_one(tmp_path):
    cfg = config(tmp_path)
    notifier = Notifier()
    code = pipeline.run_pass(
        cfg,
        [FailingSource("s1", []), WindowSource("s2", [item("g1", "healthy advisory")])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code == 1  # the fault is reported
    assert notifier.sent, "the healthy source must still be processed"
    state = json.loads(cfg.state_path.read_text())
    assert "s2" in state["seeded"] and "s1" not in state["seeded"]


def test_a_malformed_source_url_does_not_leak_its_token():
    import logging

    from advisory_radar.http import RedactFilter, urllib_http

    status, _, _ = urllib_http("GET", "not-a-url/with?token=a/b+c&d", {}, None)
    assert status == 0
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "bad %s", ("a/b+c&d",), None)
    RedactFilter(["a/b+c&d"]).filter(record)
    assert "a%2Fb%2Bc%26d" not in record.getMessage()
    assert "a/b+c&d" not in record.getMessage()


def test_two_ids_that_expand_to_one_value_are_refused(tmp_path):
    from advisory_radar.config import ConfigError

    path = tmp_path / "c.yml"
    path.write_text(
        "sources: []\nnotifiers:\n  - id: a${X}\n    type: webhook\n    url: https://x.example/y\n"
        "  - id: a${Y}\n    type: webhook\n    url: https://x.example/z\n"
    )
    with pytest.raises(ConfigError, match="expand to the same value"):
        load_config(path, {"X": "same", "Y": "same"})
    # and the same configuration with distinct expansions is accepted
    assert load_config(path, {"X": "one", "Y": "two"}).notifiers[0]["id"] == "aone"


def test_an_overflowing_metric_is_unknown_not_fatal(tmp_path):
    huge = int("9" * 400)
    cfg = config(tmp_path)
    notifier = Notifier()
    feeds = {"https://feeds.example.com/a": feed("g1", "CVE-2026-4242 thing")}

    def http(method, url, headers, body):
        if "cveawg.mitre.org" in url:
            body = {
                "cveMetadata": {"cveId": "CVE-2026-4242", "state": "PUBLISHED"},
                "containers": {"cna": {"metrics": [{"cvssV3_1": {"baseScore": huge}}]}},
            }
            return 200, {}, json.dumps(body).encode()
        if "api.first.org" in url:
            return 200, {}, json.dumps({"data": []}).encode()
        if "cisa.gov" in url:
            return 200, {}, json.dumps({"vulnerabilities": []}).encode()
        return 200, {}, feeds.get(url, b"")

    code = pipeline.run_pass(
        cfg,
        [RssSource("s1", "https://feeds.example.com/a")],
        [notifier],
        http=http,
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code == 0 and notifier.sent, "an overflowing score must not block delivery"


# ---------------------------------------------------------------------------
# Ninth review round


def test_low_ghsa_does_not_suppress_an_unmeasured_one():
    facts = {"CVE-2026-1": core.CveFacts(None, None, None, None, True)}
    verdict = core.judge([], facts, frozenset(), True, 3.9, osv_complete=False)
    assert verdict.tag != "suppressed", "an unmeasured advisory must keep the item visible"
    verdict_measured = core.judge([], facts, frozenset(), True, 3.9, osv_complete=True)
    assert verdict_measured.tag == "suppressed"


def test_an_osv_404_leaves_the_item_unsuppressed():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            return 404, None

    assert Intel().ghsa("GHSA-aaaa-bbbb-cccc").complete is False


def test_deeply_nested_json_is_a_failed_lookup_not_a_crash():
    from advisory_radar.http import parse_json

    body = ("[" * 200000 + "]" * 200000).encode()
    assert parse_json(body) is None


def test_unknown_web_keys_are_refused(tmp_path):
    from advisory_radar.config import ConfigError

    path = tmp_path / "c.yml"
    path.write_text("sources: []\nnotifiers: []\nweb:\n  hots: 127.0.0.1\n")
    with pytest.raises(ConfigError):
        load_config(path, {})


# ---------------------------------------------------------------------------
# Tenth review round


def test_an_osv_object_without_alias_or_severity_is_unmeasured():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            return 200, {"id": "GHSA-aaaa-bbbb-cccc"}

    assert Intel().ghsa("GHSA-aaaa-bbbb-cccc").complete is False


def test_an_adobe_only_configuration_bootstraps(tmp_path, monkeypatch):
    cfg_path = tmp_path / "c.yml"
    cfg_path.write_text(
        "sources: []\nnotifiers: []\nadobe_commerce: true\nstate_path: " + str(tmp_path / "state.json") + "\n"
    )
    from advisory_radar.config import load_config

    cfg = load_config(cfg_path, {})
    called = []

    def fake_adobe(state, http, kev, kev_known, now):
        called.append(now)
        return True

    monkeypatch.setattr(core, "adobe_pass", fake_adobe)
    code = pipeline.run_pass(cfg, [], [Notifier()], http=http_for({}), clock=lambda: float(NOW), sleep=lambda s: None)
    assert called, "an Adobe-only configuration must still run the Adobe pass on the first run"
    assert (tmp_path / "state.json").exists()
    assert code == 0


def test_a_malformed_feed_entry_fails_the_source():
    from advisory_radar.feeds import FeedError, parse_feed

    with pytest.raises(FeedError):
        parse_feed(b'{"items": [{}]}')
    with pytest.raises(FeedError):
        parse_feed(b'{"items": [1, 2]}')


# ---------------------------------------------------------------------------
# Eleventh review round


def test_a_busy_first_source_does_not_starve_the_second(tmp_path):
    cfg = config(tmp_path)
    notifier = Notifier()
    busy = [item(f"b{index}", f"vendor note {index}") for index in range(20)]
    quiet = [item("q1", "quiet source advisory")]
    code = pipeline.run_pass(
        cfg,
        [WindowSource("s1", busy), WindowSource("s2", quiet)],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code == 0
    titles = [entry["title"] for entry in notifier.sent]
    assert any("quiet source" in title for title in titles), "each source gets a share of the queue"


def test_rss_and_atom_reject_unusable_entries():
    from advisory_radar.feeds import RssError, parse_rss

    with pytest.raises(RssError):
        parse_rss(b"<rss><channel><item><description>x</description></item></channel></rss>")
    with pytest.raises(RssError):
        parse_rss(b'<feed xmlns="http://www.w3.org/2005/Atom"><entry></entry></feed>')
    export = parse_rss(b"<rss><channel><item><title>t</title><guid>g</guid></item></channel></rss>")
    assert export.items[0].guid == "g"


def test_a_colon_in_a_plugin_id_is_refused(tmp_path):
    from advisory_radar.config import ConfigError

    path = tmp_path / "c.yml"
    path.write_text("sources:\n  - id: vendor:prod\n    type: rss\n    url: https://x.example/f\nnotifiers: []\n")
    with pytest.raises(ConfigError):
        load_config(path, {})


def test_an_unmeasured_osv_answer_stays_unmeasured_through_the_cache():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)
            self.calls = 0

        def _get(self, url):
            self.calls += 1
            return 200, {"id": "GHSA-aaaa-bbbb-cccc"}

    intel = Intel()
    assert intel.ghsa("GHSA-aaaa-bbbb-cccc").complete is False
    assert intel.ghsa("GHSA-aaaa-bbbb-cccc").complete is False, "the cache must not turn it into a measurement"
    assert intel.calls == 1


# ---------------------------------------------------------------------------
# Twelfth review round


def test_an_osv_score_never_judges_an_unrelated_cve():
    """A LOW GHSA aliases its own CVE; it must not become the score of a different, unmeasured CVE."""
    facts = {"CVE-2026-7777": core.CveFacts(None, None, None, None, True)}
    verdict = core.judge(
        ["CVE-2026-7777"],
        facts,
        frozenset(),
        True,
        3.9,
        True,
        osv_fallbacks={"CVE-2026-8888": 3.9},
    )
    assert verdict.tag == "warning", "an unrelated LOW score must not suppress this CVE"
    aliased = core.judge(["CVE-2026-7777"], facts, frozenset(), True, 3.9, True, osv_fallbacks={"CVE-2026-7777": 3.9})
    assert aliased.tag == "suppressed"


def test_a_private_atom_self_link_never_reaches_a_notification():
    from advisory_radar.feeds import parse_rss

    atom = (
        b'<feed xmlns="http://www.w3.org/2005/Atom">'
        b'<link rel="self" href="https://feeds.example/atom?token=SECRET"/>'
        b'<link rel="alternate" href="https://vendor.example/blog"/>'
        b"<entry><id>urn:1</id><title>t</title></entry></feed>"
    )
    export = parse_rss(atom)
    assert export.items[0].source_url == "https://vendor.example/blog"
    assert "SECRET" not in export.items[0].source_url


def test_classification_rotates_across_more_sources_than_the_queue(tmp_path):
    cfg = config(tmp_path)
    notifier = Notifier()
    sources = [WindowSource(f"s{index}", [item(f"g{index}", f"source {index} note")]) for index in range(6)]
    delivered = set()
    for _ in range(6):
        notifier.sent.clear()
        pipeline.run_pass(
            cfg,
            sources,
            [notifier],
            http=http_for({}),
            clock=lambda: float(NOW),
            sleep=lambda s: None,
        )
        delivered.update(entry["title"] for entry in notifier.sent)
    assert any("source 5" in title for title in delivered), "the last source must eventually be classified"


def test_a_damaged_kev_cache_is_not_a_known_catalog(tmp_path):
    from advisory_radar.kev import KEV_CACHE_SCHEMA, load_kev
    from advisory_radar.state import save_state

    cache = tmp_path / "kev.json"
    save_state(cache, {"schema": KEV_CACHE_SCHEMA, "cves": ["not-a-cve"]})

    def http(method, url, headers, body):
        return 500, {}, b""

    cves, known = load_kev(http, cache, save=False)
    assert cves == frozenset() and known is False


def test_a_two_ghsa_item_does_not_lend_one_score_to_the_others_cve():
    facts = {"CVE-2026-7777": core.CveFacts(None, None, None, None, True)}
    verdict = core.judge(["CVE-2026-7777"], facts, frozenset(), True, 3.9, True, osv_fallbacks={})
    assert verdict.tag == "warning", "no GHSA aliases this CVE, so no OSV score judges it"


def test_delivery_persists_each_acknowledgement():
    state = core.new_state()
    entry = {
        "kind": "new",
        "tag": "warning",
        "title": "t",
        "body": "b",
        "ids": ["src:x"],
        "cves": [],
        "levels": {},
        "source": "s",
        "link": "",
        "first_attempt_at": NOW,
    }
    state["pending"].append(entry)
    calls = []
    core.deliver(state, [Notifier(200), ExplodingNotifier()], http_for({}), NOW, persist=lambda: calls.append(1))
    assert calls, "a successful channel must be persisted before the next one is attempted"
    assert state["pending"][0]["sent_to"] == ["fake"]


def test_an_empty_kev_cache_is_not_a_known_catalog(tmp_path):
    from advisory_radar.kev import KEV_CACHE_SCHEMA, load_kev
    from advisory_radar.state import save_state

    for payload in ({"schema": KEV_CACHE_SCHEMA}, {"schema": KEV_CACHE_SCHEMA, "cves": []}):
        cache = tmp_path / f"kev-{len(payload)}.json"
        save_state(cache, payload)
        cves, known = load_kev(lambda *a: (500, {}, b""), cache, save=False)
        assert cves == frozenset() and known is False


def test_a_zero_poll_interval_is_refused(tmp_path):
    from advisory_radar.config import ConfigError

    path = tmp_path / "c.yml"
    path.write_text("sources: []\nnotifiers: []\npoll_interval: 0s\n")
    with pytest.raises(ConfigError):
        load_config(path, {})


# ---------------------------------------------------------------------------
# Fourteenth review round


def test_an_unclaimed_ghsa_survives_a_claimed_cve(tmp_path):
    """A new GHSA must not be swallowed by a CVE an earlier message already claimed."""
    cfg = config(tmp_path)
    state = core.new_state()
    state["seen"]["CVE-2026-1234"] = {"at": NOW - 3600, "outcome": "delivered"}
    from advisory_radar.state import save_state

    save_state(cfg.state_path, state)
    entry = core.Item(
        "g1",
        "CVE-2026-1234 and GHSA-aaaa-bbbb-cccc in one advisory",
        "https://vendor.example.com/a",
        "notes",
        NOW - 60,
        ("CVE-2026-1234", "GHSA-aaaa-bbbb-cccc"),
    )
    notifier = Notifier()
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", [entry])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert notifier.sent, "the unclaimed GHSA is a reason to notify"


def test_a_disabled_plugin_does_not_need_its_secret(tmp_path):
    path = tmp_path / "c.yml"
    path.write_text(
        "sources: []\n"
        "notifiers:\n"
        "  - id: disabled-channel\n    type: discord_webhook\n    url: ${MISSING_SECRET}\n    enabled: false\n"
        "  - id: active-channel\n    type: webhook\n    url: https://hooks.example.com/x\n"
    )
    cfg = load_config(path, {})  # must not raise
    assert [entry["id"] for entry in cfg.notifiers] == ["active-channel"]


# ---------------------------------------------------------------------------
# Fifteenth review round


def test_an_aliased_ghsa_does_not_override_its_cve(monkeypatch):
    """A GHSA that aliases a CVE speaks through that CVE's authoritative score, not on its own."""
    facts = {"CVE-2026-1111": core.CveFacts(7.5, None, None, None, True)}
    verdict = core.judge(
        ["CVE-2026-1111"],
        facts,
        frozenset(),
        True,
        9.8,
        True,
        osv_fallbacks={"CVE-2026-1111": 9.8},
        independent_ghsa_cvss=None,
    )
    assert verdict.tag == "warning", "an aliased GHSA must not force critical"


def test_an_alias_free_critical_ghsa_alone_is_critical():
    verdict = core.judge([], {}, frozenset(), True, 9.8, True, osv_fallbacks={}, independent_ghsa_cvss=9.8)
    assert verdict.tag == "critical", "a CRITICAL advisory with no CVE alias is critical by itself"


def test_an_alias_free_ghsa_cannot_be_hidden_by_a_low_cve():
    facts = {"CVE-2026-2222": core.CveFacts(2.0, None, 0.001, 0.1, True)}
    verdict = core.judge(
        ["CVE-2026-2222"], facts, frozenset(), True, 9.8, True, osv_fallbacks={}, independent_ghsa_cvss=9.8
    )
    assert verdict.tag == "critical"


def test_freshrss_uses_the_configured_user():
    from advisory_radar.feeds import fetch_feed

    seen = {}

    def http(method, url, headers, body):
        seen["url"] = url
        return 200, {}, b'{"items": []}'

    fetch_feed(http, "https://rss.example.com", "tok", "joasia")
    from urllib.parse import parse_qs, urlsplit

    query = parse_qs(urlsplit(seen["url"]).query)
    assert query["user"] == ["joasia"], "a shared query belongs to the account that owns it"


def test_the_freshrss_user_comes_from_configuration(tmp_path):
    from advisory_radar.sources import build_source

    source = build_source({"id": "fr", "type": "freshrss", "url": "https://rss.example.com", "token": "t"}, {"T": "t"})
    assert source.user == "admin"
    source = build_source(
        {"id": "fr", "type": "freshrss", "url": "https://rss.example.com", "token": "t", "user": "joasia"},
        {"T": "t"},
    )
    assert source.user == "joasia"


# ---------------------------------------------------------------------------
# Sixteenth review round


def test_an_item_with_many_ghsas_cannot_monopolise_the_pass(monkeypatch):
    looked: list[str] = []

    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def ghsa(self, ghsa):
            looked.append(ghsa)
            return core.OsvFacts((), None, True)

    state = core.new_state()
    many = core.Item(
        "g1",
        "bulk advisory",
        "https://vendor.example.com/a",
        "notes",
        NOW - 60,
        tuple(f"GHSA-aaaa-bbbb-{index:04d}" for index in range(200)),
    )
    policy = core.Policy(("curl",), (), ())
    core.classify_new(state, [many], Intel(), frozenset(), True, NOW, "vendor.example.com", policy)
    assert len(looked) <= core.MAX_ITEM_GHSA_LOOKUPS, "OSV lookups per item are bounded"
    # the unmeasured remainder keeps the item out of the suppressed bucket
    assert all(entry["tag"] != "suppressed" for entry in state["pending"])


def test_two_measured_low_advisories_stay_suppressed():
    facts = {"CVE-2026-3333": core.CveFacts(2.0, None, 0.001, 0.1, True)}
    verdict = core.judge(
        ["CVE-2026-3333"], facts, frozenset(), True, 3.9, True, osv_fallbacks={}, independent_ghsa_cvss=3.9
    )
    assert verdict.tag == "suppressed", "LOW + LOW is not news"
    high = core.judge(
        ["CVE-2026-3333"], facts, frozenset(), True, 7.5, True, osv_fallbacks={}, independent_ghsa_cvss=7.5
    )
    assert high.tag == "warning"


def test_block_level_html_keeps_word_boundaries():
    from advisory_radar.feeds import clean_text

    assert clean_text("<p>libfoo</p><p>fixed a bug</p>") == "libfoo fixed a bug"
    text = clean_text("<div><b>libfoo</b><br>remote code execution</div>")
    assert "libfoo remote" in text


# ---------------------------------------------------------------------------
# Seventeenth review round


def test_a_pass_with_no_notifiers_and_nothing_owed_succeeds(tmp_path):
    cfg = config(tmp_path, notifiers=False)
    code = pipeline.run_pass(
        cfg,
        [WindowSource("s1", [])],
        [],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code == 0, "an empty queue with no notifiers is not a delivery failure"
    assert core.deliver(core.new_state(), [], http_for({}), NOW) is True


def test_a_claimed_cve_beside_a_new_ghsa_does_not_let_the_ghsa_speak_for_it():
    """The GHSA aliases a CVE that is not judged here, so its label is not independent evidence."""
    verdict = core.judge(
        [],
        {},
        frozenset(),
        True,
        9.8,
        True,
        osv_fallbacks={},
        independent_ghsa_cvss=None,
        osv_scores_are_aliased=True,
    )
    assert verdict.tag == "warning", "an aliased advisory must not escalate on its own label"


# ---------------------------------------------------------------------------
# Eighteenth review round


def test_an_independent_critical_ghsa_wins_regardless_of_identifier_order():
    for independent_first in (True, False):
        verdict = core.judge(
            [],
            {},
            frozenset(),
            True,
            9.8,
            True,
            osv_fallbacks={},
            independent_ghsa_cvss=9.8 if independent_first else None,
            osv_scores_are_aliased=not independent_first,
        )
        expected = "critical" if independent_first else "warning"
        assert verdict.tag == expected


def test_atom_xhtml_keeps_word_boundaries_through_filtering():
    from advisory_radar.feeds import parse_rss

    atom = (
        b'<feed xmlns="http://www.w3.org/2005/Atom">'
        b'<link rel="alternate" href="https://aggregator.example/feed"/>'
        b"<entry><id>urn:1</id><title>Security update</title>"
        b'<content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">'
        b"<p>libfoo</p><p>fixed a vulnerability</p></div></content></entry></feed>"
    )
    export = parse_rss(atom)
    assert "libfoo fixed" in export.items[0].summary
    watch = {
        "schema": KIND,
        "debian_source_packages": ["curl"],
        "excluded_products": [],
        "products": [{"id": "libfoo", "aliases": ["libfoo"], "domains": ["libfoo.example"]}],
    }
    import json as _json

    policy = load_policy_from(_json.dumps(watch), pytest.importorskip("pathlib").Path)
    assert core.passes_filter(export.items[0], policy) is True


def load_policy_from(text, path_module):

    import os
    import tempfile

    from advisory_radar.watchlist import load_policy

    fd, name = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
    try:
        return load_policy(path_module(name))
    finally:
        os.unlink(name)


def test_an_absurd_cve_suffix_does_not_raise():
    cve = "CVE-2026-" + "9" * 5000
    assert core._cve_age(cve) == (2026, 0)
    assert core.parse_nodejs_page(f"security releases {cve}") is not None


# ---------------------------------------------------------------------------
# Nineteenth review round


def test_a_gap_keeps_the_last_trusted_window(tmp_path):
    cfg = config(tmp_path)
    notifier = Notifier()
    trusted = pipeline.run_pass(
        cfg,
        [WindowSource("s1", [item("g1", "first")], truncated=True)],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert trusted == 0
    for _ in range(2):  # the same untrustworthy window twice must keep failing
        code = pipeline.run_pass(
            cfg,
            [WindowSource("s1", [item("g2", "second")], truncated=True)],
            [notifier],
            http=http_for({}),
            clock=lambda: float(NOW + 60),
            sleep=lambda s: None,
        )
        assert code == 1, "a gap must not be adopted as the new baseline"
        state = json.loads(cfg.state_path.read_text())
        assert state["windows"]["s1"] == ["s1:g1"], "the trusted window is kept"


def test_a_state_file_named_kev_json_is_refused(tmp_path):
    from advisory_radar.config import ConfigError

    path = tmp_path / "c.yml"
    path.write_text("sources: []\nnotifiers: []\nstate_path: /data/kev.json\n")
    with pytest.raises(ConfigError, match="kev.json"):
        load_config(path, {})


def test_a_ghsa_decided_verdict_renders_the_ghsa_evidence():
    facts = {"CVE-2026-4444": core.CveFacts(2.0, None, 0.001, 0.1, True)}
    verdict = core.judge(
        ["CVE-2026-4444"], facts, frozenset(), True, 9.8, True, osv_fallbacks={}, independent_ghsa_cvss=9.8
    )
    assert verdict.tag == "critical"
    assert "OSV GHSA severity" in verdict.line, "the deciding evidence must be shown, not the unrelated CVE score"
    assert "without a CVE id" in verdict.note


# ---------------------------------------------------------------------------
# Twentieth review round


def test_epss_requests_are_bounded_per_call():
    calls = []

    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            calls.append(url)
            if "api.first.org" in url:
                return 200, {"data": []}
            return 404, None

    facts = Intel().cves([f"CVE-2026-{index:05d}" for index in range(5000)])
    epss_calls = [url for url in calls if "api.first.org" in url]
    assert len(epss_calls) <= core.MAX_EPSS_IDS // 100 + 1, "EPSS work per call is bounded"
    assert any(fact.skipped for fact in facts.values()), "ids past the budget are unmeasured, not complete"


def test_confirmed_ssvc_active_escalates_through_an_epss_outage():
    state = core.new_state()
    cve = "CVE-2026-6666"
    state["watch"][cve] = {
        "since": NOW - 3 * 86400,
        "last_eval": NOW - 2 * 86400,
        "level": "warning",
        "title": "original",
        "link": "https://vendor.example.com/a",
    }

    class Intel:
        def cves(self, cves, force=False, deferred=None):
            return {name: core.CveFacts(None, "active", None, None, False) for name in cves}

    core.reevaluate(state, Intel(), frozenset(), True, NOW, "")
    queued = [entry for entry in state["pending"] if entry["kind"] == "escalation"]
    assert queued and queued[0]["tag"] == "critical", "SSVC active decides without EPSS"


# ---------------------------------------------------------------------------
# Twenty-first review round


def test_candidates_beyond_the_queue_are_carried_to_the_next_pass(tmp_path):
    """A saturated queue must not let a rotating window drop the items it could not classify."""
    cfg = config(tmp_path)
    notifier = Notifier(500)  # delivery fails, so the queue stays full
    many = [item(f"g{index}", f"advisory {index}") for index in range(20)]
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", many)],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    state = json.loads(cfg.state_path.read_text())
    assert state.get("carry", {}).get("s1"), "unclassified items are carried, not dropped"
    carried = len(state["carry"]["s1"])
    # the next pass brings an overlapping window that no longer contains the carried items
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", [many[-1]])],
        [Notifier()],
        http=http_for({}),
        clock=lambda: float(NOW + 60),
        sleep=lambda s: None,
    )
    state = json.loads(cfg.state_path.read_text())
    assert "s1" in state.get("carry", {}), "the unclassified remainder is still carried"
    assert carried >= 1


def test_an_undated_item_is_not_consumed_as_history(tmp_path):
    cfg = config(tmp_path)
    notifier = Notifier()
    undated = core.Item("g1", "vendor advisory without a date", "https://vendor.example.com/a", "notes", None, ())
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", [undated])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert notifier.sent, "an undated current advisory must be classified, not recorded as delivered"
    state = json.loads(cfg.state_path.read_text())
    assert state["seen"]["src:s1:g1"]["outcome"] == "delivered"


def test_any_state_filename_gets_its_own_lock_file(tmp_path):
    """The sidecar appends its suffix, so a *.lock state file cannot be its own lock."""
    path = tmp_path / "c.yml"
    path.write_text("sources: []\nnotifiers: []\nstate_path: /data/alerts.lock\n")
    load_config(path, {})
    from advisory_radar.state import state_lock

    fresh = tmp_path / "alerts.lock"
    with state_lock(fresh):
        assert not fresh.exists(), "acquiring the lock must not create the state file"
    assert (tmp_path / "alerts.lock.lock").exists()


# ---------------------------------------------------------------------------
# Twenty-second review round


def test_the_carry_map_survives_a_source_that_finishes_first(tmp_path):
    """The first source emptying its share must not detach the map the second source writes into."""
    cfg = config(tmp_path)
    notifier = Notifier(500)  # the queue stays full: nothing is delivered
    first = [item("a1", "first source advisory")]
    many = [item(f"b{index}", f"second source advisory {index}") for index in range(12)]
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", first), WindowSource("s2", many)],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    state = json.loads(cfg.state_path.read_text())
    assert "s2" in state.get("carry", {}), "the overflowing source's items are retained"


def test_a_deferred_enrichment_item_is_carried(tmp_path, monkeypatch):
    """An item waiting on its enrichment retry clock must survive the window rotating out."""
    config(tmp_path)
    dsa = core.Item(
        "g1", "DSA-6558-1 curl - security update", "https://lists.debian.org/x", "notes", NOW - 3600, ("DSA-6558-1",)
    )

    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: float(NOW), lambda s: None)
            self.tracker_left = 1

        def dsa_cves(self, dsa):
            return None  # the tracker page fails, so the item waits

    state = core.new_state()
    policy = core.Policy(("curl",), (), ())
    left = core.classify_new(state, [dsa], Intel(), frozenset(), True, NOW, "lists.debian.org", policy)
    assert [entry.guid for entry in left] == ["g1"], "a deferred item is returned for the next pass"
    assert state["enrich_retry"]["g1"] == NOW


# ---------------------------------------------------------------------------
# Twenty-third review round


def test_a_carried_advisory_is_not_turned_into_backlog_by_its_age(tmp_path):
    """It was recent when it arrived; an outage must not age it into history."""
    cfg = config(tmp_path)
    notifier = Notifier()
    state = {
        "schema": core.STATE_SCHEMA,
        "seen": {},
        "pending": [],
        "parked": [],
        "watch": {},
        "cache": {},
        "windows": {},
        "seeded": {"s1": True},
        "carry": {
            "s1": [
                core.item_to_state(
                    core.Item("g1", "carried advisory", "https://vendor.example.com/a", "notes", NOW - 3600, ())
                )
            ]
        },
    }
    from advisory_radar.state import save_state

    save_state(cfg.state_path, state)
    later = NOW + core.BACKLOG_AGE + 300  # delivery only recovers after the backlog window
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", [])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(later),
        sleep=lambda s: None,
    )
    assert any("carried advisory" in entry["title"] for entry in notifier.sent), (
        "a carried item must still be delivered, not recorded as backlog"
    )


def test_a_carried_item_keeps_its_enrichment_retry_clock(tmp_path):
    """A DSA waiting out its tracker retry is carried; rotating the feed must not delete its deadline."""
    cfg = config(tmp_path)
    dsa = core.Item(
        "g1", "DSA-6558-1 curl - security update", "https://lists.debian.org/x", "notes", NOW - 3600, ("DSA-6558-1",)
    )
    # the tracker answers 404, so the item starts its retry clock and is carried
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", [dsa], host="lists.debian.org")],
        [Notifier()],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    state = json.loads(cfg.state_path.read_text())
    assert state.get("carry", {}).get("s1"), "the deferred DSA is carried"
    assert "s1:g1" in state.get("enrich_retry", {}), "it starts a retry clock"
    # the feed rotates the item out; the clock must survive the prune
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", [], host="lists.debian.org")],
        [Notifier()],
        http=http_for({}),
        clock=lambda: float(NOW + 60),
        sleep=lambda s: None,
    )
    state = json.loads(cfg.state_path.read_text())
    assert "s1:g1" in state.get("enrich_retry", {}), "a carried item keeps its retry deadline"


def test_a_carried_item_follows_the_current_watchlist(tmp_path):
    cfg = config(tmp_path)
    (tmp_path / "watchlist.json").write_text(
        json.dumps(
            {
                "schema": KIND,
                "debian_source_packages": ["curl"],
                "excluded_products": ["legacy"],
                "products": [{"id": "libfoo", "aliases": ["libfoo"], "domains": ["libfoo.example"]}],
            }
        )
    )
    notifier = Notifier()
    state = core.new_state()
    state["seeded"] = {"s1": True}
    state["carry"] = {
        "s1": [core.item_to_state(core.Item("g1", "legacy advisory", "https://vendor.example.com/a", "", NOW - 60, ()))]
    }
    from advisory_radar.state import save_state

    save_state(cfg.state_path, state)
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", [])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert not notifier.sent, "an excluded product must not be delivered from carry either"


# ---------------------------------------------------------------------------
# Twenty-fourth review round


def test_a_window_is_saved_together_with_its_classification(tmp_path, monkeypatch):
    """A checkpoint after source A must not persist source B's new window before B was classified."""
    cfg = config(tmp_path)
    snapshots = []
    import advisory_radar.pipeline as pipeline_module

    real_save = pipeline_module.save_state

    def recording(state_path, state):
        real_save(state_path, state)
        snapshots.append(json.loads(json.dumps(state)))

    monkeypatch.setattr(pipeline_module, "save_state", recording)
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", [item("a1", "first source")]), WindowSource("s2", [item("b1", "second source")])],
        [Notifier()],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert snapshots, "the pass saved state"
    first = snapshots[0]
    assert "s2" not in first["windows"], "s2's window must not advance before s2 is classified"
    final = snapshots[-1]
    assert set(final["windows"]) == {"s1", "s2"}


def test_saturation_does_not_carry_a_historical_item_as_news(tmp_path):
    cfg = config(tmp_path)
    state = core.new_state()
    state["seeded"] = {"s1": True}  # already bootstrapped: the seed pass is not what decides this
    from advisory_radar.state import save_state

    save_state(cfg.state_path, state)
    notifier = Notifier(500)  # the queue stays full, so classification stops early
    fresh = [item(f"f{index}", f"fresh {index}") for index in range(core.DELIVERY_CAP)]
    stale = core.Item("old", "old advisory", "https://vendor.example.com/old", "notes", NOW - 30 * 86400, ())
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", fresh + [stale])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    state = json.loads(cfg.state_path.read_text())
    carried = {row["guid"] for row in state.get("carry", {}).get("s1", [])}
    assert "old" not in carried, "history is recorded as backlog, never carried as a current candidate"
    assert state["seen"]["src:s1:old"]["outcome"] == "backlog"


# ---------------------------------------------------------------------------
# Twenty-fifth review round


def test_the_carried_tail_still_gets_the_history_decision(tmp_path):
    cfg = config(tmp_path)
    state = core.new_state()
    state["seeded"] = {"s1": True}
    from advisory_radar.state import save_state

    save_state(cfg.state_path, state)
    notifier = Notifier(500)  # the queue fills and stays full
    undated = [
        core.Item(f"u{index}", f"undated {index}", "https://vendor.example.com/u", "n", None, ()) for index in range(6)
    ]
    old = core.Item("old", "old advisory", "https://vendor.example.com/old", "notes", NOW - 30 * 86400, ())
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", undated + [old])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    state = json.loads(cfg.state_path.read_text())
    carried = {row["guid"] for row in state.get("carry", {}).get("s1", [])}
    assert "old" not in carried, "a historical item in the tail is backlog, never carry"
    assert state["seen"]["src:s1:old"]["outcome"] == "backlog"


def test_a_malformed_epss_row_is_not_a_complete_measurement(tmp_path):
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            if "api.first.org" in url:
                return 200, {"data": [{"cve": "CVE-2026-1234", "epss": "not-a-number", "percentile": "0.5"}]}
            return 404, None

    facts = Intel().cves(["CVE-2026-1234"])
    assert facts["CVE-2026-1234"].complete is False, "an unusable number is a failed measurement"


# ---------------------------------------------------------------------------
# Twenty-sixth review round


def test_a_populated_but_unusable_epss_response_is_a_failure():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            if "api.first.org" in url:
                return 200, {"data": [{}]}
            return 404, None

    facts = Intel().cves(["CVE-2026-1234"])
    assert facts["CVE-2026-1234"].complete is False

    class Empty(Intel):
        def _get(self, url):
            if "api.first.org" in url:
                return 200, {"data": []}  # a valid empty result stays a measurement
            return 404, None

    assert Empty().cves(["CVE-2026-1234"])["CVE-2026-1234"].epss is None


def test_carried_candidates_progress_while_their_source_fails(tmp_path):
    cfg = config(tmp_path)
    notifier = Notifier()
    state = core.new_state()
    state["seeded"] = {"s1": True}
    state["carry"] = {
        "s1": [
            core.item_to_state(core.Item("g1", "captured advisory", "https://vendor.example.com/a", "n", NOW - 60, ()))
        ]
    }
    from advisory_radar.state import save_state

    save_state(cfg.state_path, state)
    pipeline.run_pass(
        cfg,
        [FailingSource("s1", [])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert any("captured advisory" in entry["title"] for entry in notifier.sent), (
        "a source outage must not freeze already captured candidates"
    )


# ---------------------------------------------------------------------------
# Twenty-seventh review round


def test_a_mixed_valid_and_malformed_epss_batch_fails():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            if "api.first.org" in url:
                return 200, {"data": [{"cve": "CVE-2026-1111", "epss": "0.5"}, {"nope": 1}]}
            return 404, None

    facts = Intel().cves(["CVE-2026-1111", "CVE-2026-2222"])
    assert facts["CVE-2026-1111"].complete is False, "one malformed row fails the whole measurement"


def test_hidden_source_hosts_must_be_a_list(tmp_path):
    from advisory_radar.config import ConfigError

    path = tmp_path / "c.yml"
    path.write_text("sources: []\nnotifiers: []\nhidden_source_hosts: rsshub.internal\n")
    with pytest.raises(ConfigError, match="hidden_source_hosts"):
        load_config(path, {})
    ok = tmp_path / "ok.yml"
    ok.write_text("sources: []\nnotifiers: []\nhidden_source_hosts:\n  - rsshub.internal\n")
    assert load_config(ok, {}).hidden_source_hosts == frozenset({"rsshub.internal"})


def test_a_disabled_source_does_not_deliver_its_carry(tmp_path):
    cfg = config(tmp_path)
    state = core.new_state()
    state["seeded"] = {"s1": True, "s2": True}
    state["carry"] = {
        "gone": [
            core.item_to_state(core.Item("g1", "orphaned advisory", "https://vendor.example.com/a", "n", NOW - 60, ()))
        ]
    }
    from advisory_radar.state import save_state

    save_state(cfg.state_path, state)
    notifier = Notifier()
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", []), WindowSource("s2", [])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert not notifier.sent, "a source that is no longer configured must not push its carry"


# ---------------------------------------------------------------------------
# Twenty-eighth review round


def test_an_epss_row_without_numbers_is_a_failure():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            if "api.first.org" in url:
                return 200, {"data": [{"cve": "CVE-2026-1234"}]}
            return 404, None

    assert Intel().cves(["CVE-2026-1234"])["CVE-2026-1234"].complete is False


def test_an_rss_cve_in_content_encoded_is_classified_and_watched(tmp_path):
    from advisory_radar.feeds import parse_rss

    feed = (
        b'<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">'
        b"<channel><title>T</title><link>https://vendor.example.com/</link>"
        b"<item><title>Security update</title><guid>advisory-1</guid>"
        b"<content:encoded><![CDATA[Fixes CVE-2026-1234.]]></content:encoded></item>"
        b"</channel></rss>"
    )
    export = parse_rss(feed)
    entry = export.items[0]
    assert "CVE-2026-1234" in entry.summary, "the full content must be read, not just the description"
    assert "CVE-2026-1234" in core.extract_ids(entry.title, entry.summary, entry.link)


# ---------------------------------------------------------------------------
# Twenty-ninth review round


def test_a_cve_only_in_full_content_is_still_found():
    from advisory_radar.feeds import parse_rss

    rss = (
        b'<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">'
        b"<channel><title>T</title><link>https://vendor.example.com/</link>"
        b"<item><title>Security update</title><guid>g1</guid>"
        b"<description>Security update available</description>"
        b"<content:encoded><![CDATA[Fixes CVE-2026-1234 in libfoo.]]></content:encoded></item>"
        b"</channel></rss>"
    )
    entry = parse_rss(rss).items[0]
    assert "Security update available" in entry.summary and "CVE-2026-1234" in entry.summary

    atom = (
        b'<feed xmlns="http://www.w3.org/2005/Atom"><link rel="alternate" href="https://vendor.example.com/"/>'
        b"<entry><id>urn:1</id><title>t</title><summary>Update</summary>"
        b"<content>Fixes CVE-2026-9999</content></entry></feed>"
    )
    entry = parse_rss(atom).items[0]
    assert "Fixes CVE-2026-9999" in entry.summary


def test_the_rendered_score_belongs_to_the_shown_cve():
    facts = {
        "CVE-2026-1111": core.CveFacts(None, None, None, None, True),
        "CVE-2026-2222": core.CveFacts(None, None, None, None, True),
    }
    verdict = core.judge(
        ["CVE-2026-1111", "CVE-2026-2222"],
        facts,
        frozenset(),
        True,
        3.9,
        True,
        osv_fallbacks={"CVE-2026-2222": 3.9},
    )
    assert verdict.tag == "warning"
    assert "CVE-2026-1111" in verdict.line and "3.9" not in verdict.line, (
        "the GHSA score belongs to CVE-2026-2222; showing it beside CVE-2026-1111 would be false evidence"
    )


# ---------------------------------------------------------------------------
# Thirtieth review round


def test_a_malformed_nvd_response_is_a_failed_lookup():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            if "services.nvd.nist.gov" in url:
                return 200, {"error": "unavailable"}
            if "api.first.org" in url:
                return 200, {"data": [{"cve": "CVE-2026-1234", "epss": "0.5", "percentile": "0.9"}]}
            return 404, None

    assert Intel().cves(["CVE-2026-1234"])["CVE-2026-1234"].complete is False


def test_a_mixed_case_hidden_host_still_hides_the_url():
    from advisory_radar.config import load_config

    path = Path(__file__).parent / "_hidden.yml"
    path.write_text("sources: []\nnotifiers: []\nhidden_source_hosts:\n  - RSSHub.Internal\n")
    try:
        cfg = load_config(path, {})
    finally:
        path.unlink()
    assert cfg.hidden_source_hosts == frozenset({"rsshub.internal"})
    core.HIDDEN_SOURCE_HOSTS = cfg.hidden_source_hosts
    try:
        title, body = core.render(
            "critical",
            "CVE-2026-1111",
            ["CVE-2026-1111"],
            "9.8",
            "",
            "https://RSSHub.Internal/private-query?token=abc",
            "notes",
            NOW,
            "rsshub.internal",
            "Feed",
            "https://RSSHub.Internal/private-query?token=abc",
        )
        assert "private-query" not in title + body, "a hidden host must not leak its URL, whatever the case"
    finally:
        core.HIDDEN_SOURCE_HOSTS = frozenset()


def test_a_busy_source_cannot_starve_a_failed_sources_carry(tmp_path):
    cfg = config(tmp_path)
    notifier = Notifier()
    state = core.new_state()
    state["seeded"] = {"s1": True, "s2": True}
    state["carry"] = {
        "s2": [
            core.item_to_state(core.Item("of1", "captured from s2", "https://vendor.example.com/o", "n", NOW - 60, ()))
        ]
    }
    from advisory_radar.state import save_state

    save_state(cfg.state_path, state)
    busy = [item(f"a{index}", f"busy {index}") for index in range(12)]
    sent_titles: list[str] = []
    for _ in range(4):
        notifier.sent.clear()
        pipeline.run_pass(
            cfg,
            [WindowSource("s1", busy), FailingSource("s2", [])],
            [notifier],
            http=http_for({}),
            clock=lambda: float(NOW),
            sleep=lambda s: None,
        )
        sent_titles.extend(entry["title"] for entry in notifier.sent)
    assert any("captured from s2" in title for title in sent_titles), (
        "a failed source's captured advisory must not starve behind a busy one"
    )


# ---------------------------------------------------------------------------
# Thirty-first review round


def test_an_unrelated_nvd_record_is_a_failed_lookup():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            if "services.nvd.nist.gov" in url:
                record = {"id": "CVE-2026-9999", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 2.0}}]}}
                return 200, {"vulnerabilities": [{"cve": record}]}
            if "api.first.org" in url:
                return 200, {"data": [{"cve": "CVE-2026-1234", "epss": "0.5", "percentile": "0.9"}]}
            return 404, None

    assert Intel().cves(["CVE-2026-1234"])["CVE-2026-1234"].complete is False, (
        "another CVE's score must never become this CVE's measurement"
    )


def test_an_unrelated_cve_org_record_is_a_failed_lookup():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            if "cveawg.mitre.org" in url:
                return 200, {"cveMetadata": {"cveId": "CVE-2026-9999"}, "containers": {}}
            return 404, None

    assert Intel()._cve_org("CVE-2026-1234")[0] is False


def test_php_enrichment_keeps_both_cves_and_ghsas():
    from advisory_radar.core import Intel

    class FakeIntel(Intel):
        def __init__(self):
            super().__init__(lambda *a: (404, {}, b""), {}, lambda: 0.0, lambda s: None)

        def php_cves(self, slug):
            class Release:
                cves = ("CVE-2026-1111",)
                ghsas = ("GHSA-aaaa-bbbb-cccc",)
                versions = ()
                detail = ""

            return Release()

    state = core.new_state()
    policy = core.Policy(("curl",), (), ())
    release_item = core.Item(
        "g1",
        "PHP 8.4.26 released!",
        "https://www.php.net/archive/2026.php",
        "notes",
        NOW - 60,
        (),
        "PHP",
        "https://www.php.net/",
    )
    looked: list[str] = []

    def ghsa(self, identifier):
        looked.append(identifier)
        return core.OsvFacts((), 9.8, True)

    FakeIntel.ghsa = ghsa
    core.classify_new(state, [release_item], FakeIntel(), frozenset(), True, NOW, "www.php.net", policy)
    assert "GHSA-aaaa-bbbb-cccc" in looked, "a PHP release names both ids and both must be used"
    assert any(entry["tag"] == "critical" for entry in state["pending"]), "the alias-free CRITICAL GHSA decides"


# ---------------------------------------------------------------------------
# Thirty-second review round


def test_a_capped_out_cve_is_still_watched():
    facts = {
        f"CVE-2026-{1000 + index}": core.CveFacts(None, None, None, None, False, skipped=True) for index in range(12)
    }
    verdict = core.judge(list(facts), facts, frozenset(), True, None, True, osv_fallbacks={})
    watched = dict(verdict.levels)
    assert len(watched) <= core.MAX_ITEM_CVE_LOOKUPS + 12, "watching skipped CVEs stays bounded"
    assert any(level == "warning" for level in watched.values()), (
        "a capped-out CVE must still be watched, or a later KEV addition would never escalate it"
    )


def test_a_malformed_cve_org_record_is_a_failed_lookup():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            return 200, {"error": "unavailable"}

    assert Intel()._cve_org("CVE-2026-1234")[0] is False


def test_an_osv_record_for_another_advisory_is_not_used():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            return 200, {"id": "GHSA-9999-9999-9999", "database_specific": {"severity": "LOW"}}

    facts = Intel().ghsa("GHSA-aaaa-bbbb-cccc")
    assert facts.complete is False and facts.cvss is None


def test_the_config_page_does_not_print_a_source_token(tmp_path):
    from starlette.testclient import TestClient

    from advisory_radar.web import create_app

    path = tmp_path / "c.yml"
    path.write_text(
        "sources:\n  - id: s\n    type: rss\n"
        "    url: https://user:pw@feeds.example.com/private/SECRET123/rss?token=SECRET456\n"
        "notifiers: []\nstate_path: " + str(tmp_path / "state.json") + "\n"
    )
    cfg = load_config(path, {})
    client = TestClient(create_app(cfg, {"ADVISORY_RADAR_AUTH_TOKEN": "t"}))
    client.post("/login", data={"token": "t"}, follow_redirects=False)
    body = client.get("/config").text
    assert "SECRET123" not in body and "SECRET456" not in body and "pw@" not in body
    assert "feeds.example.com" in body


# ---------------------------------------------------------------------------
# Thirty-third review round


def test_every_cve_in_a_large_advisory_is_watched():
    facts = {
        f"CVE-2026-{2000 + index}": core.CveFacts(None, None, None, None, False, skipped=True) for index in range(25)
    }
    verdict = core.judge(list(facts), facts, frozenset(), True, None, True, osv_fallbacks={})
    assert len(verdict.levels) == 25, "every claimed CVE needs a watch entry"
    assert set(verdict.skipped) == set(facts), "the unmeasured ones are flagged KEV-only"


def test_a_kev_addition_escalates_a_capped_out_cve(tmp_path):
    (tmp_path / "watchlist.json").write_text(
        json.dumps({"schema": KIND, "debian_source_packages": ["curl"], "excluded_products": [], "products": []})
    )
    cfg = config(tmp_path)
    state = core.new_state()
    later = "CVE-2026-9999"
    state["watch"][later] = {
        "since": NOW - 2 * 86400,
        "last_eval": NOW - 2 * 86400,
        "level": "warning",
        "kev_only": True,
        "title": "big advisory",
        "link": "https://vendor.example.com/a",
    }
    from advisory_radar.state import save_state

    save_state(cfg.state_path, state)

    class Intel:
        def cves(self, cves, force=False, deferred=None):
            raise AssertionError("a KEV-only watch must not spend an enrichment request")

    core.reevaluate(state, Intel(), frozenset({later}), True, NOW, "")
    queued = [entry for entry in state["pending"] if entry["kind"] == "escalation"]
    assert queued and queued[0]["cves"] == [later], "a KEV addition escalates a watch that was never enriched"


# ---------------------------------------------------------------------------
# Thirty-fourth review round


def test_an_environment_false_does_not_enable_adobe(tmp_path):
    from advisory_radar.config import ConfigError

    path = tmp_path / "c.yml"
    path.write_text("sources: []\nnotifiers: []\nadobe_commerce: ${ADOBE}\n")
    assert load_config(path, {"ADOBE": "false"}).adobe_commerce is False
    assert load_config(path, {"ADOBE": "true"}).adobe_commerce is True
    with pytest.raises(ConfigError):
        load_config(path, {"ADOBE": "perhaps"})


def test_a_deferred_nvd_lookup_does_not_advance_the_daily_clock():
    state = core.new_state()
    cve = "CVE-2026-7777"
    state["watch"][cve] = {
        "since": NOW - 3 * 86400,
        "last_eval": NOW - 2 * 86400,
        "level": "warning",
        "title": "t",
        "link": "https://vendor.example.com/a",
    }

    class Intel:
        def cves(self, cves, force=False, deferred=None):
            (deferred if deferred is not None else set()).update(cves)  # budget ran out: no request made
            return {name: core.CveFacts(None, None, None, None, False) for name in cves}

    core.reevaluate(state, Intel(), frozenset(), True, NOW, "")
    assert state["watch"][cve]["last_eval"] == NOW - 2 * 86400, "a deferred lookup is not an attempt"


def test_suppressing_a_new_cve_keeps_an_earlier_record():
    """A delivered CVE keeps its history when a later item suppresses a different, new CVE."""
    state = core.new_state()
    state["seen"]["CVE-2026-1111"] = {"at": NOW - 7200, "outcome": "delivered"}
    item = core.Item(
        "g1",
        "CVE-2026-1111 and CVE-2026-2222",
        "https://vendor.example.com/a",
        "n",
        NOW - 60,
        ("CVE-2026-1111", "CVE-2026-2222"),
    )
    facts = {"CVE-2026-2222": core.CveFacts(2.0, None, 0.001, 0.1, True)}
    verdict = core.judge(["CVE-2026-2222"], facts, frozenset(), True, None, True, osv_fallbacks={})
    assert verdict.tag == "suppressed"
    core._suppressed(state, ["CVE-2026-1111", "CVE-2026-2222"], verdict, item, {}, NOW)
    assert state["seen"]["CVE-2026-1111"] == {"at": NOW - 7200, "outcome": "delivered"}
    assert state["seen"]["CVE-2026-2222"]["outcome"] == "suppressed"


# ---------------------------------------------------------------------------
# Thirty-fifth review round


def test_a_confirmed_kev_hit_escalates_even_when_the_lookup_was_deferred():
    state = core.new_state()
    cve = "CVE-2026-8888"
    state["watch"][cve] = {
        "since": NOW - 3 * 86400,
        "last_eval": NOW - 2 * 86400,
        "level": "warning",
        "title": "t",
        "link": "https://vendor.example.com/a",
    }

    class Intel:
        def cves(self, cves, force=False, deferred=None):
            (deferred if deferred is not None else set()).update(cves)  # budget ran out
            return {name: core.CveFacts(None, None, None, None, False) for name in cves}

    core.reevaluate(state, Intel(), frozenset({cve}), True, NOW, "")
    queued = [entry for entry in state["pending"] if entry["kind"] == "escalation"]
    assert queued and queued[0]["tag"] == "critical", "a confirmed KEV hit must not wait for the budget"


def test_a_boolean_error_does_not_echo_the_value(tmp_path):
    from advisory_radar.config import ConfigError

    path = tmp_path / "c.yml"
    path.write_text("sources: []\nnotifiers: []\nadobe_commerce: ${SECRET}\n")
    with pytest.raises(ConfigError) as caught:
        load_config(path, {"SECRET": "s3cr3t-value"})
    assert "s3cr3t-value" not in str(caught.value)


# ---------------------------------------------------------------------------
# Thirty-sixth review round


def test_an_epss_row_for_another_cve_is_a_failed_measurement():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            if "api.first.org" in url:
                return 200, {"data": [{"cve": "CVE-2026-9999", "epss": "0.5", "percentile": "0.9"}]}
            return 404, None

    assert Intel().cves(["CVE-2026-1234"])["CVE-2026-1234"].complete is False


def test_independent_low_evidence_wins_over_a_mixed_aggregate():
    """An alias-free HIGH score must not be promoted by another advisory's CRITICAL aggregate."""
    verdict = core.judge(
        [],
        {},
        frozenset(),
        True,
        9.0,
        True,
        osv_fallbacks={},
        independent_ghsa_cvss=8.9,
        osv_scores_are_aliased=False,
    )
    assert verdict.tag == "warning", "the independent score decides, and HIGH is not critical"


def test_inline_xhtml_stays_adjacent():
    from advisory_radar.feeds import parse_rss

    atom = (
        b'<feed xmlns="http://www.w3.org/2005/Atom"><link rel="alternate" href="https://vendor.example.com/"/>'
        b"<entry><id>urn:1</id><title>t</title>"
        b'<content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">'
        b"<p>CVE-<span>2026</span>-1234 affects lib<span>foo</span></p>"
        b"<p>second paragraph</p></div></content></entry></feed>"
    )
    summary = parse_rss(atom).items[0].summary
    assert "CVE-2026-1234" in summary and "libfoo" in summary
    assert "second paragraph" in summary


# ---------------------------------------------------------------------------
# Thirty-seventh review round


def test_an_empty_previous_window_does_not_create_a_gap(tmp_path):
    cfg = config(tmp_path)
    notifier = Notifier()
    first = pipeline.run_pass(
        cfg,
        [WindowSource("s1", [], truncated=True)],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert first == 0
    many = [item(f"g{index}", f"advisory {index}") for index in range(5)]
    second = pipeline.run_pass(
        cfg,
        [WindowSource("s1", many, truncated=True)],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW + 60),
        sleep=lambda s: None,
    )
    assert second == 0, "an empty baseline must not be read as a gap"
    assert notifier.sent, "the new advisories are processed"


def test_a_stale_kev_cache_does_not_authorize_suppression():
    import tempfile
    from pathlib import Path

    from advisory_radar.kev import KEV_CACHE_SCHEMA, load_kev
    from advisory_radar.state import save_state

    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "kev.json"
        save_state(cache, {"schema": KEV_CACHE_SCHEMA, "cves": ["CVE-2026-1111"]})
        cves, known = load_kev(lambda *a: (500, {}, b""), cache, save=False)
    assert cves == frozenset({"CVE-2026-1111"}), "cached hits still promote"
    assert known is False, "an outage must not let the old catalog's silence suppress a CVE"
