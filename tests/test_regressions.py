"""Regression tests for the first independent review of the public repository.

Each test pins one defect the reviewer found: the packaged default watchlist, the
notifier config keys, the web auth token, the pass lock, an empty notifier list,
per-source enrichment clocks, secret collection and the persisted run record.
"""

from __future__ import annotations

import contextlib
import copy
import errno
import json
import re
import socketserver
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

from advisory_radar import core, pipeline
from advisory_radar.config import (
    DEFAULT_THRESHOLDS,
    MIN_SECRET_LENGTH,
    ConfigError,
    collect_secrets,
    env_secret,
    load_config,
)
from advisory_radar.notifiers import AppriseNotifier, DiscordWebhookNotifier, build_notifier
from advisory_radar.sources import RssSource
from advisory_radar.state import LockBusy, state_lock
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


#: A token and a webhook secret of the length ``openssl rand -hex 24`` makes half of: the shortest accepted.
MINIMUM_SECRET = "k" * 24


@pytest.mark.parametrize("token", ["Zq", "Zq7-ci-tok", "Zq" + "x" * 21], ids=["2", "10", "23"])
def test_web_ui_refuses_a_short_auth_token(tmp_path, token):
    """A one-character token was accepted, and the session cookie is signed with it (W7)."""
    from advisory_radar.web import create_app

    with pytest.raises(ConfigError) as raised:
        create_app(config(tmp_path), {"ADVISORY_RADAR_AUTH_TOKEN": token})
    message = str(raised.value)
    assert "ADVISORY_RADAR_AUTH_TOKEN" in message and "at least 24" in message
    assert "openssl rand -hex 24" in message, "the refusal says how to make a token that is accepted"
    assert token not in message, "a refused secret is never echoed"


def test_web_ui_accepts_an_auth_token_of_exactly_the_minimum_length(tmp_path):
    from advisory_radar.web import create_app

    create_app(config(tmp_path), {"ADVISORY_RADAR_AUTH_TOKEN": MINIMUM_SECRET})


CI_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
SMOKE_STEP = "Container image builds and starts"


def smoke_test_token(run: str) -> str:
    """The login token the image smoke test would hand the container, as the container would read it.

    Two shapes are recognised: a literal, and ``"$(openssl rand -hex N)"``, which is N bytes written as 2N hex
    characters. Anything else cannot be judged from the text, so it is refused here instead of being assumed
    long enough.
    """
    generated = re.search(r'-e ADVISORY_RADAR_AUTH_TOKEN="\$\(openssl rand -hex (\d+)\)"', run)
    if generated:
        return "f" * (2 * int(generated[1]))
    literal = re.search(r"-e ADVISORY_RADAR_AUTH_TOKEN=([\w.~+-]+)(?=\s)", run)
    assert literal, 'the smoke test must pass the token as a literal or as "$(openssl rand -hex N)"'
    return literal[1]


def test_the_ci_image_smoke_test_starts_the_container_with_a_token_run_accepts():
    """``run`` refuses a short token, so a smoke test that still passes one never gets /healthz answered (W7).

    The token is judged by the same ``env_secret`` call that ``create_app`` makes, so tightening the minimum again
    fails here before it fails the required ``ci`` check on a pull request.
    """
    steps = [
        step
        for step in yaml.safe_load(CI_WORKFLOW.read_text())["jobs"]["ci"]["steps"]
        if step.get("name") == SMOKE_STEP
    ]
    assert len(steps) == 1, "the ci job must have exactly one image smoke-test step"
    env = {"ADVISORY_RADAR_AUTH_TOKEN": smoke_test_token(steps[0]["run"])}
    try:
        env_secret(env, "ADVISORY_RADAR_AUTH_TOKEN", minimum=MIN_SECRET_LENGTH)
    except ConfigError as exc:
        pytest.fail(f"the container would exit 1 and /healthz would never answer: {exc}")


def test_web_ui_refuses_a_short_webhook_secret_but_not_an_absent_one(tmp_path):
    """A set webhook secret is held to the token's rule; an unset one still just disables the intake (W7)."""
    from advisory_radar.web import create_app

    base = {"ADVISORY_RADAR_AUTH_TOKEN": MINIMUM_SECRET}
    with pytest.raises(ConfigError) as raised:
        create_app(config(tmp_path), {**base, "ADVISORY_RADAR_WEBHOOK_SECRET": "Zq-short"})
    assert "ADVISORY_RADAR_WEBHOOK_SECRET" in str(raised.value) and "Zq-short" not in str(raised.value)
    assert "openssl rand -hex 24" in str(raised.value)
    create_app(config(tmp_path), base)
    create_app(config(tmp_path), {**base, "ADVISORY_RADAR_WEBHOOK_SECRET": ""})
    create_app(config(tmp_path), {**base, "ADVISORY_RADAR_WEBHOOK_SECRET": "w" * 24})


def sign_in_status(client, token: str) -> int:
    return client.post("/login", data={"token": token}, follow_redirects=False).status_code


def test_the_auth_token_may_come_from_a_file(tmp_path):
    """There was no ``_FILE`` form: the token had to sit in the environment, where a process listing shows it (W8b)."""
    from fastapi.testclient import TestClient

    from advisory_radar.web import create_app

    token_file = tmp_path / "token"
    token_file.write_text("f" * 24 + "\n")  # an editor or `echo` leaves a newline; it is not part of the secret
    client = TestClient(create_app(config(tmp_path), {"ADVISORY_RADAR_AUTH_TOKEN_FILE": str(token_file)}))
    assert sign_in_status(client, "f" * 24) == 303
    assert sign_in_status(client, "g" * 24) == 200, "a wrong token is shown the sign-in form again"


def test_the_auth_token_is_read_once_at_startup(tmp_path):
    """The login compare re-read the variable on every request, so it could drift from the cookie key (W8b)."""
    from fastapi.testclient import TestClient

    from advisory_radar.web import create_app

    token_file = tmp_path / "token"
    token_file.write_text("o" * 24)
    client = TestClient(create_app(config(tmp_path), {"ADVISORY_RADAR_AUTH_TOKEN_FILE": str(token_file)}))
    token_file.write_text("n" * 24)  # a rotation takes a restart, like every other startup-bound value
    assert sign_in_status(client, "n" * 24) == 200
    assert sign_in_status(client, "o" * 24) == 303


def test_the_auth_token_and_its_file_together_are_refused(tmp_path):
    from advisory_radar.web import create_app

    token_file = tmp_path / "token"
    token_file.write_text("b" * 24)
    env = {"ADVISORY_RADAR_AUTH_TOKEN": "Zq" + "a" * 22, "ADVISORY_RADAR_AUTH_TOKEN_FILE": str(token_file)}
    with pytest.raises(ConfigError) as raised:
        create_app(config(tmp_path), env)
    message = str(raised.value)
    assert "ADVISORY_RADAR_AUTH_TOKEN" in message and "ADVISORY_RADAR_AUTH_TOKEN_FILE" in message
    assert "both" in message
    assert "Zq" + "a" * 22 not in message and "b" * 24 not in message and str(token_file) not in message


@pytest.mark.parametrize(
    ("contents", "reason"),
    [
        (b"", "the file is empty"),
        (b" \r\n", "the file is empty"),
        (b"\xff\xfe" + b"x" * 30, "the file is not UTF-8 text"),
        (None, "no readable file"),
    ],
    ids=["empty", "blank", "not-utf8", "absent"],
)
def test_an_unusable_auth_token_file_is_refused_naming_the_variable_only(tmp_path, contents, reason):
    """Every failed read is a ``ConfigError`` that names ``ADVISORY_RADAR_AUTH_TOKEN_FILE`` and nothing else (W8b)."""
    from advisory_radar.web import create_app

    token_file = tmp_path / "token"
    if contents is not None:
        token_file.write_bytes(contents)
    with pytest.raises(ConfigError) as raised:
        create_app(config(tmp_path), {"ADVISORY_RADAR_AUTH_TOKEN_FILE": str(token_file)})
    assert str(raised.value) == f"ADVISORY_RADAR_AUTH_TOKEN_FILE: {reason}"


@pytest.mark.parametrize("name", ["ADVISORY_RADAR_AUTH_TOKEN", "ADVISORY_RADAR_WEBHOOK_SECRET"])
def test_a_short_secret_in_a_file_is_refused_naming_the_file_variable(tmp_path, name):
    from advisory_radar.web import create_app

    short = tmp_path / "short"
    short.write_text("Zq-short\n")
    # The other secret is valid, so the refusal can only be about this one.
    other = {} if name == "ADVISORY_RADAR_AUTH_TOKEN" else {"ADVISORY_RADAR_AUTH_TOKEN": MINIMUM_SECRET}
    with pytest.raises(ConfigError) as raised:
        create_app(config(tmp_path), {**other, f"{name}_FILE": str(short)})
    assert str(raised.value).startswith(f"{name}_FILE:")
    assert "Zq-short" not in str(raised.value)


def test_run_exits_with_a_config_error_instead_of_a_traceback_on_a_short_token(tmp_path, monkeypatch, caplog):
    """The refusal is a startup error like any other: logged as ``config: ...``, exit code 1, no server (W7)."""
    import logging

    from advisory_radar import cli

    cfg_path = tmp_path / "c.yml"
    cfg_path.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path / 'state.json'}\n")

    def serve(*args, **kwargs):
        raise AssertionError("a refused token must not start the server")

    monkeypatch.setattr("uvicorn.run", serve)
    with caplog.at_level(logging.ERROR, logger=cli.LOG.name):
        code = cli.main(["--config", str(cfg_path), "run"], env={"ADVISORY_RADAR_AUTH_TOKEN": "Zq-short"})
    assert code == 1
    assert "config: ADVISORY_RADAR_AUTH_TOKEN" in caplog.text and "Zq-short" not in caplog.text


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
    assert code == pipeline.PASS_BUSY, "the web path needs the skipped outcome, not the generic failure"
    assert not notifier.sent


def test_a_blocking_pass_still_reports_one_when_the_store_refuses_the_lock(tmp_path, monkeypatch):
    """The CLI and scheduler keep their ``1 = failed`` contract; only the non-blocking web path has a skip code.

    No store times a blocking acquisition out, so this is a store that refuses the lock outright.
    """
    cfg = config(tmp_path)

    class BusyStore:
        def lock(self, *, blocking: bool = True):
            raise LockBusy

    # ``Config`` is frozen, so the store factory is replaced on the class rather than on the instance.
    monkeypatch.setattr(type(cfg), "store", lambda self: BusyStore())
    assert pipeline.run_pass(cfg, [], []) == 1


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
        self.kind = "rss"  # later protocol versions read it
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


def file_reference_config(tmp_path):
    """A configuration whose one notifier reads its url from ``${HOOK_FILE}``."""
    cfg_path = tmp_path / "c.yml"
    cfg_path.write_text(
        "sources: []\nnotifiers:\n  - id: d\n    type: discord_webhook\n    url: ${HOOK_FILE}\n"
        f"state_path: {tmp_path / 'state.json'}\n"
    )
    return cfg_path


def test_an_undecodable_secret_file_is_a_config_error_that_names_the_reference_only(tmp_path):
    """A secret file holding bytes that are not UTF-8 raised a bare ``UnicodeDecodeError`` (W8).

    That exception's text quotes the offending byte, so it would also have put part of the secret in the log.
    """
    secret_file = tmp_path / "hook"
    secret_file.write_bytes(b"https://hooks.example.com/\xff\xfeSUPERSECRET")
    with pytest.raises(ConfigError) as raised:
        load_config(file_reference_config(tmp_path), {"HOOK_FILE": str(secret_file)})
    assert "${HOOK_FILE}" in str(raised.value) and "UTF-8" in str(raised.value)
    assert "SUPERSECRET" not in str(raised.value) and "xff" not in str(raised.value).lower()
    assert str(secret_file) not in str(raised.value), "the path may itself be the secret, so it is never printed"


def test_an_unreadable_secret_file_is_a_config_error_that_names_the_reference_only(tmp_path, monkeypatch):
    """``PermissionError`` escaped as an ``OSError`` that quotes the path (W8).

    The suite runs as root, which ignores file modes, so the read is made to fail the way an unreadable file does.
    """
    secret_file = tmp_path / "hook"
    secret_file.write_text("https://hooks.example.com/SUPERSECRET")
    real = Path.read_text

    def denied(self, *args, **kwargs):
        if self == secret_file:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied)
    with pytest.raises(ConfigError) as raised:
        load_config(file_reference_config(tmp_path), {"HOOK_FILE": str(secret_file)})
    assert str(raised.value).startswith("${HOOK_FILE}: no readable file")
    assert str(secret_file) not in str(raised.value) and "SUPERSECRET" not in str(raised.value)


@pytest.mark.parametrize(
    ("code", "reason"),
    [(errno.ENAMETOOLONG, "File name too long"), (errno.EACCES, "Permission denied")],
    ids=["name-too-long", "permission-denied"],
)
def test_a_secret_file_whose_stat_fails_is_a_config_error_that_names_the_reference_only(
    tmp_path, monkeypatch, code, reason
):
    """Python 3.13's ``Path.is_file`` re-raises an ``OSError`` that quotes the path; 3.14 returns ``False`` (W8).

    The image runs 3.13, where the check sat outside the ``try`` and a long or unsearchable path ended the start
    with a traceback that prints the path. The stat is made to fail the way 3.13 does, so the test holds on both.
    """
    secret_file = tmp_path / "hook"
    secret_file.write_text("https://hooks.example.com/SUPERSECRET")
    real = Path.is_file

    def failing(self, *args, **kwargs):
        if self == secret_file:
            raise OSError(code, reason, str(self))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", failing)
    with pytest.raises(ConfigError) as raised:
        load_config(file_reference_config(tmp_path), {"HOOK_FILE": str(secret_file)})
    assert str(raised.value) == "${HOOK_FILE}: no readable file"
    assert str(secret_file) not in str(raised.value) and "SUPERSECRET" not in str(raised.value)


@pytest.mark.parametrize("contents", ["", "\n", "  \r\n\t "])
def test_an_empty_secret_file_is_refused_instead_of_loading_an_empty_secret(tmp_path, contents):
    """An empty file resolved to ``''`` and the notifier came up with no credential at all (W8)."""
    secret_file = tmp_path / "hook"
    secret_file.write_text(contents)
    with pytest.raises(ConfigError) as raised:
        load_config(file_reference_config(tmp_path), {"HOOK_FILE": str(secret_file)})
    assert "${HOOK_FILE}: the file is empty" in str(raised.value)


def test_a_missing_secret_file_names_the_reference_as_written(tmp_path):
    """``${X_FILE}`` is read through the variable ``X_FILE``; the message used to name ``${X_FILE_FILE}`` (W8)."""
    with pytest.raises(ConfigError) as raised:
        load_config(file_reference_config(tmp_path), {"HOOK_FILE": str(tmp_path / "absent")})
    assert str(raised.value) == "${HOOK_FILE}: no readable file"
    with pytest.raises(ConfigError) as unset:
        load_config(file_reference_config(tmp_path), {})
    assert str(unset.value) == "${HOOK_FILE}: no readable file"


def test_a_state_only_command_tolerates_any_unusable_secret_file(tmp_path):
    """``lenient`` leaves the reference alone for every way a file can fail, as it already did for a missing one."""
    cfg_path = file_reference_config(tmp_path)
    bad = tmp_path / "bad"
    bad.write_bytes(b"\xff\xfe")
    empty = tmp_path / "empty"
    empty.write_text("")
    for path in (bad, empty, tmp_path / "absent"):
        cfg = load_config(cfg_path, {"HOOK_FILE": str(path)}, lenient=True)
        assert cfg.notifiers[0]["url"] == "${HOOK_FILE}", path.name


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

    core.reevaluate(state, Intel(), frozenset(), True, now, "", thresholds=DEFAULT_THRESHOLDS)
    core.reevaluate(state, Intel(), frozenset(), True, now, "", thresholds=DEFAULT_THRESHOLDS)
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

    def fake_run(app, host=None, port=None, log_level=None, **kwargs):
        for _ in range(200):  # let the scheduler take its first pass, then stop like a SIGTERM would
            if calls:
                return None
            time.sleep(0.01)
        return None

    monkeypatch.setattr("uvicorn.run", fake_run)
    monkeypatch.setattr(cli.pipeline, "run_pass", lambda *a, **k: calls.append(1) or 0)
    monkeypatch.setenv("ADVISORY_RADAR_AUTH_TOKEN", MINIMUM_SECRET)
    code = cli.main(["--config", str(cfg_path), "run"])
    assert code == 0
    assert len(calls) == 1, "shutdown must not start an extra pass"


FORWARDED = "ADVISORY_RADAR_FORWARDED_ALLOW_IPS"


def run_with_stub_server(tmp_path, monkeypatch, env: dict[str, str]):
    """Run ``advisory-radar run`` against a stub server; return the exit code and the keywords it was started with."""
    from advisory_radar import cli

    cfg_path = tmp_path / "c.yml"
    cfg_path.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path / 'state.json'}\n")
    started: dict = {}

    def stub_run(app, **kwargs):
        started.update(kwargs)

    monkeypatch.setattr("uvicorn.run", stub_run)
    monkeypatch.setattr(cli.pipeline, "run_pass", lambda *args, **kwargs: 0)
    code = cli.main(["--config", str(cfg_path), "run"], env={"ADVISORY_RADAR_AUTH_TOKEN": MINIMUM_SECRET, **env})
    return code, started


def test_run_starts_the_server_with_an_explicit_loopback_default(tmp_path, monkeypatch):
    """Without a value uvicorn reads its own ``FORWARDED_ALLOW_IPS``, which this project does not document (W2)."""
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    code, started = run_with_stub_server(tmp_path, monkeypatch, {})
    assert code == 0
    assert started["forwarded_allow_ips"] == ["127.0.0.1", "::1"], "an explicit value, so uvicorn's variable is unused"


def test_run_trusts_the_proxies_the_documented_variable_names(tmp_path, monkeypatch):
    """Behind a reverse proxy every login came from the proxy's address, so one throttle served every client (W2)."""
    code, started = run_with_stub_server(tmp_path, monkeypatch, {FORWARDED: "192.0.2.10, 198.51.100.0/24,"})
    assert code == 0
    assert started["forwarded_allow_ips"] == ["192.0.2.10", "198.51.100.0/24"]
    code, started = run_with_stub_server(tmp_path, monkeypatch, {FORWARDED: "2001:db8::1"})
    assert started["forwarded_allow_ips"] == ["2001:db8::1"]
    code, started = run_with_stub_server(tmp_path, monkeypatch, {FORWARDED: " "})
    assert started["forwarded_allow_ips"] == ["127.0.0.1", "::1"], "a blank value is an unset one"


@pytest.mark.parametrize(
    "value",
    ["*", "0.0.0.0/0", "::/0", "192.0.2.10,*", "proxy.example.net", "192.0.2.999", "192.0.2.0/33", "192.0.2.10/24"],
)
def test_run_refuses_a_forwarded_list_that_trusts_everyone_or_that_uvicorn_would_drop(
    tmp_path, monkeypatch, caplog, value
):
    """uvicorn turns a malformed entry into a literal that never matches, so a typo would trust no proxy (W2)."""
    import logging

    from advisory_radar import cli

    with caplog.at_level(logging.ERROR, logger=cli.LOG.name):
        code, started = run_with_stub_server(tmp_path, monkeypatch, {FORWARDED: value})
    assert code == 1
    assert started == {}, "the server must not start with a trust list that was refused"
    assert f"config: {FORWARDED}:" in caplog.text


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

    core.reevaluate(state, Intel(), frozenset({cve}), True, now, "", thresholds=DEFAULT_THRESHOLDS)
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


def test_a_credential_escaped_for_the_log_is_still_redacted():
    """``_log_id`` escapes the argument before the filter sees it, so the filter must know that spelling too."""
    import logging

    from advisory_radar.core import _log_id
    from advisory_radar.http import RedactFilter

    for secret in ("demo\\credential", "pässwörd"):
        escaped = _log_id(secret)
        assert escaped != secret, "each case must actually reach the escaped spelling"
        record = logging.LogRecord("t", logging.ERROR, __file__, 1, "bad identity %s", (escaped,), None)
        RedactFilter([secret]).filter(record)
        text = record.getMessage()
        assert secret not in text, "the raw credential must not survive"
        assert escaped not in text, "nor the escaped spelling the logger emitted"
        assert "[redacted]" in text


def test_a_finished_log_record_is_bounded_after_redaction():
    """A feed can supply a multi-megabyte identifier; the bound must not cut a credential into a prefix."""
    import logging

    from advisory_radar.http import LOG_RECORD_LIMIT, RedactFilter

    secret = "SECRET-TOKEN"
    # The secret starts four characters before the bound, so truncating first would leave "SECR" behind, which
    # the redactor can no longer match.
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "%s%s", ("x" * (LOG_RECORD_LIMIT - 4), secret), None)
    RedactFilter([secret]).filter(record)
    text = record.getMessage()
    assert len(text) == LOG_RECORD_LIMIT
    assert secret[:4] not in text


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
    verdict = core.judge([], facts, frozenset(), True, 3.9, osv_complete=False, thresholds=DEFAULT_THRESHOLDS)
    assert verdict.tag != "suppressed", "an unmeasured advisory must keep the item visible"
    verdict_measured = core.judge([], facts, frozenset(), True, 3.9, osv_complete=True, thresholds=DEFAULT_THRESHOLDS)
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

    def fake_adobe(state, http, kev, kev_known, now, **kwargs):
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
        thresholds=DEFAULT_THRESHOLDS,
    )
    assert verdict.tag == "warning", "an unrelated LOW score must not suppress this CVE"
    aliased = core.judge(
        ["CVE-2026-7777"],
        facts,
        frozenset(),
        True,
        3.9,
        True,
        osv_fallbacks={"CVE-2026-7777": 3.9},
        thresholds=DEFAULT_THRESHOLDS,
    )
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
    verdict = core.judge(
        ["CVE-2026-7777"], facts, frozenset(), True, 3.9, True, osv_fallbacks={}, thresholds=DEFAULT_THRESHOLDS
    )
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


# ---------------------------------------------------------------------------
# Notification routing (#29)


class TargetNotifier(Notifier):
    """A notifier with its own id, so a routing test can see which channels received a message."""

    def __init__(self, notifier_id: str, status: int = 200) -> None:
        super().__init__(status)
        self.id = notifier_id


def queue_message(state: dict, *, tag: str = "critical", ids: list[str] | None = None) -> dict:
    """One pending message, so a delivery test controls exactly what routing sees."""
    entry = {
        "kind": "new",
        "tag": tag,
        "title": "t",
        "body": "b",
        "ids": ids or ["src:x"],
        "cves": [],
        "levels": {},
        "source": "s",
        "link": "",
    }
    state["pending"].append(entry)
    return entry


def test_a_route_sends_a_matching_message_only_to_its_notifiers():
    state = core.new_state()
    queue_message(state, tag="critical", ids=["CVE-2026-1"])
    discord, matrix = TargetNotifier("discord"), TargetNotifier("matrix")
    routes = [{"match": {"tag": "critical"}, "notifiers": ["matrix"]}]
    assert core.deliver(state, [discord, matrix], http_for({}), NOW, routes=routes) is True
    assert [message["ids"] for message in matrix.sent] == [["CVE-2026-1"]]
    assert discord.sent == []
    assert state["pending"] == []


def test_an_unmatched_message_goes_to_the_default():
    state = core.new_state()
    queue_message(state, tag="warning", ids=["CVE-2026-2"])
    discord, matrix = TargetNotifier("discord"), TargetNotifier("matrix")
    routes = [{"match": {"tag": "critical"}, "notifiers": ["matrix"]}]
    assert core.deliver(state, [discord, matrix], http_for({}), NOW, routes=routes, default=["discord"]) is True
    assert len(discord.sent) == 1
    assert matrix.sent == []


def test_a_message_routed_to_no_enabled_notifier_stays_queued():
    state = core.new_state()
    entry = queue_message(state, tag="critical", ids=["CVE-2026-3"])
    discord = TargetNotifier("discord")
    routes = [{"match": {"tag": "critical"}, "notifiers": ["gone"]}]
    assert core.deliver(state, [discord], http_for({}), NOW, routes=routes) is False
    assert discord.sent == []
    assert state["pending"] == [entry], "a message routed to no enabled notifier is a failed pass, never silence"
    assert "sent_to" not in entry, "nothing accepted the message, so no channel may be recorded as done"
    assert "attempts" not in entry, "a routing fault is a configuration error, not a delivery attempt"


def test_only_the_failed_routed_leg_is_retried():
    state = core.new_state()
    queue_message(state, tag="critical", ids=["CVE-2026-4"])
    accepted, failing = TargetNotifier("discord"), TargetNotifier("phone", status=500)
    routes = [{"match": {"tag": "critical"}, "notifiers": ["discord", "phone"]}]
    assert core.deliver(state, [accepted, failing], http_for({}), NOW, routes=routes) is False
    failing.status = 200
    assert core.deliver(state, [accepted, failing], http_for({}), NOW, routes=routes) is True
    assert len(accepted.sent) == 1, "a channel that already accepted the message must not receive it again"
    assert len(failing.sent) == 2, "the failed leg is retried once and then the pass completes"
    assert state["pending"] == []


def test_without_routes_every_enabled_notifier_receives_the_message():
    state = core.new_state()
    queue_message(state, tag="warning", ids=["CVE-2026-5"])
    discord, matrix = TargetNotifier("discord"), TargetNotifier("matrix")
    assert core.deliver(state, [discord, matrix], http_for({}), NOW) is True
    assert len(discord.sent) == 1
    assert len(matrix.sent) == 1


def test_an_empty_route_list_ignores_the_default_and_notifies_everyone():
    """An empty ``routes`` block is the pre-routing behaviour, so a default alone cannot narrow it."""
    state = core.new_state()
    queue_message(state, tag="warning", ids=["CVE-2026-6"])
    discord, matrix = TargetNotifier("discord"), TargetNotifier("matrix")
    assert core.deliver(state, [discord, matrix], http_for({}), NOW, routes=[], default=["discord"]) is True
    assert len(discord.sent) == 1
    assert len(matrix.sent) == 1


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
        thresholds=DEFAULT_THRESHOLDS,
    )
    assert verdict.tag == "warning", "an aliased GHSA must not force critical"


def test_an_alias_free_critical_ghsa_alone_is_critical():
    verdict = core.judge(
        [], {}, frozenset(), True, 9.8, True, osv_fallbacks={}, independent_ghsa_cvss=9.8, thresholds=DEFAULT_THRESHOLDS
    )
    assert verdict.tag == "critical", "a CRITICAL advisory with no CVE alias is critical by itself"


def test_an_alias_free_ghsa_cannot_be_hidden_by_a_low_cve():
    facts = {"CVE-2026-2222": core.CveFacts(2.0, None, 0.001, 0.1, True)}
    verdict = core.judge(
        ["CVE-2026-2222"],
        facts,
        frozenset(),
        True,
        9.8,
        True,
        osv_fallbacks={},
        independent_ghsa_cvss=9.8,
        thresholds=DEFAULT_THRESHOLDS,
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
    core.classify_new(
        state, [many], Intel(), frozenset(), True, NOW, "vendor.example.com", policy, thresholds=DEFAULT_THRESHOLDS
    )
    assert len(looked) <= core.MAX_ITEM_GHSA_LOOKUPS, "OSV lookups per item are bounded"
    # the unmeasured remainder keeps the item out of the suppressed bucket
    assert all(entry["tag"] != "suppressed" for entry in state["pending"])


def test_two_measured_low_advisories_stay_suppressed():
    facts = {"CVE-2026-3333": core.CveFacts(2.0, None, 0.001, 0.1, True)}
    verdict = core.judge(
        ["CVE-2026-3333"],
        facts,
        frozenset(),
        True,
        3.9,
        True,
        osv_fallbacks={},
        independent_ghsa_cvss=3.9,
        thresholds=DEFAULT_THRESHOLDS,
    )
    assert verdict.tag == "suppressed", "LOW + LOW is not news"
    high = core.judge(
        ["CVE-2026-3333"],
        facts,
        frozenset(),
        True,
        7.5,
        True,
        osv_fallbacks={},
        independent_ghsa_cvss=7.5,
        thresholds=DEFAULT_THRESHOLDS,
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
        thresholds=DEFAULT_THRESHOLDS,
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
            thresholds=DEFAULT_THRESHOLDS,
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
        ["CVE-2026-4444"],
        facts,
        frozenset(),
        True,
        9.8,
        True,
        osv_fallbacks={},
        independent_ghsa_cvss=9.8,
        thresholds=DEFAULT_THRESHOLDS,
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

    core.reevaluate(state, Intel(), frozenset(), True, NOW, "", thresholds=DEFAULT_THRESHOLDS)
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
    left = core.classify_new(
        state, [dsa], Intel(), frozenset(), True, NOW, "lists.debian.org", policy, thresholds=DEFAULT_THRESHOLDS
    )
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
    from advisory_radar.storage import JsonStore

    real_save = JsonStore.save

    def recording(store, document):
        real_save(store, document)
        snapshots.append(json.loads(json.dumps(document)))

    monkeypatch.setattr(JsonStore, "save", recording)
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
        thresholds=DEFAULT_THRESHOLDS,
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
    core.classify_new(
        state, [release_item], FakeIntel(), frozenset(), True, NOW, "www.php.net", policy, thresholds=DEFAULT_THRESHOLDS
    )
    assert "GHSA-aaaa-bbbb-cccc" in looked, "a PHP release names both ids and both must be used"
    assert any(entry["tag"] == "critical" for entry in state["pending"]), "the alias-free CRITICAL GHSA decides"


# ---------------------------------------------------------------------------
# Thirty-second review round


def test_a_capped_out_cve_is_still_watched():
    facts = {
        f"CVE-2026-{1000 + index}": core.CveFacts(None, None, None, None, False, skipped=True) for index in range(12)
    }
    verdict = core.judge(
        list(facts), facts, frozenset(), True, None, True, osv_fallbacks={}, thresholds=DEFAULT_THRESHOLDS
    )
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
    # The cookie flag follows the environment the app is given (W12), so a plain-HTTP client opts out in it.
    env = {"ADVISORY_RADAR_AUTH_TOKEN": MINIMUM_SECRET, "ADVISORY_RADAR_INSECURE_COOKIES": "1"}
    client = TestClient(create_app(cfg, env))
    client.post("/login", data={"token": MINIMUM_SECRET}, follow_redirects=False)
    body = client.get("/config").text
    assert "SECRET123" not in body and "SECRET456" not in body and "pw@" not in body
    assert "feeds.example.com" in body


# ---------------------------------------------------------------------------
# Thirty-third review round


def test_every_cve_in_a_large_advisory_is_watched():
    facts = {
        f"CVE-2026-{2000 + index}": core.CveFacts(None, None, None, None, False, skipped=True) for index in range(25)
    }
    verdict = core.judge(
        list(facts), facts, frozenset(), True, None, True, osv_fallbacks={}, thresholds=DEFAULT_THRESHOLDS
    )
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

    core.reevaluate(state, Intel(), frozenset({later}), True, NOW, "", thresholds=DEFAULT_THRESHOLDS)
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

    core.reevaluate(state, Intel(), frozenset(), True, NOW, "", thresholds=DEFAULT_THRESHOLDS)
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
    verdict = core.judge(
        ["CVE-2026-2222"], facts, frozenset(), True, None, True, osv_fallbacks={}, thresholds=DEFAULT_THRESHOLDS
    )
    assert verdict.tag == "suppressed"
    core._suppressed(state, ["CVE-2026-1111", "CVE-2026-2222"], verdict, item, {}, NOW, DEFAULT_THRESHOLDS)
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

    core.reevaluate(state, Intel(), frozenset({cve}), True, NOW, "", thresholds=DEFAULT_THRESHOLDS)
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
        thresholds=DEFAULT_THRESHOLDS,
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


# ---------------------------------------------------------------------------
# Thirty-eighth review round


def test_a_cached_kev_hit_escalates_without_a_fresh_catalog():
    """kev_known=False marks an unrefreshed catalog; membership is still positive evidence."""
    state = core.new_state()
    cve = "CVE-2026-3333"
    state["watch"][cve] = {
        "since": NOW - 3 * 86400,
        "last_eval": NOW - 2 * 86400,
        "level": "warning",
        "kev_only": True,
        "title": "t",
        "link": "https://vendor.example.com/a",
    }

    class Intel:
        def cves(self, cves, force=False, deferred=None):
            return {name: core.CveFacts(None, None, None, None, False) for name in cves}

    core.reevaluate(state, Intel(), frozenset({cve}), False, NOW, "", thresholds=DEFAULT_THRESHOLDS)
    queued = [entry for entry in state["pending"] if entry["kind"] == "escalation"]
    assert queued and queued[0]["tag"] == "critical"


def test_a_percentile_only_epss_row_is_a_failed_measurement():
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            if "api.first.org" in url:
                return 200, {"data": [{"cve": "CVE-2026-1234", "percentile": "0.9"}]}
            return 404, None

    assert Intel().cves(["CVE-2026-1234"])["CVE-2026-1234"].complete is False


# ---------------------------------------------------------------------------
# Thirty-ninth review round


def test_a_claimed_ghsa_does_not_promote_a_new_low_finding():
    """An advisory already delivered is not evidence about the new finding in this item."""
    state = core.new_state()
    claimed_ghsa = "GHSA-aaaa-bbbb-cccc"
    state["seen"][claimed_ghsa] = {"at": NOW - 7200, "outcome": "delivered"}
    item = core.Item(
        "g1",
        "GHSA-aaaa-bbbb-cccc and CVE-2026-2222",
        "https://vendor.example.com/a",
        "notes",
        NOW - 60,
        (claimed_ghsa, "CVE-2026-2222"),
    )

    class Intel(core.Intel):
        def __init__(self):
            super().__init__(lambda *a: (404, {}, b""), {}, lambda: float(NOW), lambda s: None)

        def ghsa(self, ghsa):
            return core.OsvFacts((), 9.8, True)  # the already-delivered advisory is CRITICAL

    policy = core.Policy(("curl",), (), ())
    core.classify_new(
        state,
        [item],
        Intel(),
        frozenset(),
        True,
        NOW,
        "vendor.example.com",
        policy,
        thresholds=DEFAULT_THRESHOLDS,
    )
    tags = [entry["tag"] for entry in state["pending"]]
    assert "critical" not in tags, "a claimed advisory must not promote the new finding"


@pytest.mark.parametrize(
    "plugins",
    [
        "sources:\n  - id: s\n    type: ${PLUGIN_KIND}\n    url: https://feeds.example.com/x.xml\nnotifiers: []\n",
        # A notifier type is refused before it is expanded; a source type still reaches the builder expanded.
        "sources: []\nnotifiers:\n  - id: n\n    type: ${PLUGIN_KIND}\n    url: https://hooks.example.com/x\n",
    ],
    ids=["source", "notifier"],
)
def test_a_plugin_type_error_does_not_echo_the_expanded_value(tmp_path, caplog, plugins):
    import logging

    from advisory_radar import cli

    path = tmp_path / "c.yml"
    path.write_text(plugins + "state_path: " + str(tmp_path / "state.json") + "\n")
    env = {"PLUGIN_KIND": "https://hooks.example.com/SUPERSECRET"}
    with caplog.at_level(logging.ERROR):
        code = cli.main(["--config", str(path), "once"], env=env)
    assert code == 1, "a bad plugin type is a configuration error, not a traceback"
    assert "SUPERSECRET" not in caplog.text


# ---------------------------------------------------------------------------
# Fortieth review round


def test_an_adobe_list_that_rotates_normally_still_delivers_new_bulletins(tmp_path):
    import advisory_radar.adobe as adobe_module

    state = core.new_state()
    state["adobe"] = {
        "window": ["APSB26-01"],
        "seen": {"APSB26-01": {"cves": ["CVE-2026-1"], "at": NOW, "exploited": False}},
    }
    bulletins = (adobe_module.Bulletin("APSB26-02", None, ("CVE-2026-2",), "https://helpx.adobe.com/x"),)

    def fake_list(http, stored):
        return bulletins

    original = core._adobe_list
    core._adobe_list = fake_list
    try:
        ok = core.adobe_pass(state, lambda *a: (200, {}, b""), frozenset(), True, NOW)
    finally:
        core._adobe_list = original
    assert ok, "a rotated window is not a source fault"
    assert state["adobe"]["window"] == ["APSB26-02"]


def test_a_claimed_alias_free_ghsa_does_not_set_the_item_aggregate():
    state = core.new_state()
    claimed = "GHSA-aaaa-bbbb-cccc"
    state["seen"][claimed] = {"at": NOW - 7200, "outcome": "delivered"}
    item = core.Item(
        "g1",
        f"{claimed} and GHSA-dddd-eeee-ffff",
        "https://vendor.example.com/a",
        "n",
        NOW - 60,
        (claimed, "GHSA-dddd-eeee-ffff"),
    )

    class Intel(core.Intel):
        def __init__(self):
            super().__init__(lambda *a: (404, {}, b""), {}, lambda: float(NOW), lambda s: None)

        def ghsa(self, ghsa):
            if ghsa == claimed:
                return core.OsvFacts((), 9.8, True)  # already delivered: CRITICAL
            return core.OsvFacts((), None, False)  # the new one is unmeasured

    policy = core.Policy(("curl",), (), ())
    core.classify_new(
        state, [item], Intel(), frozenset(), True, NOW, "vendor.example.com", policy, thresholds=DEFAULT_THRESHOLDS
    )
    assert all(entry["tag"] != "critical" for entry in state["pending"]), (
        "a delivered advisory must not promote an unmeasured new one"
    )


# ---------------------------------------------------------------------------
# Forty-first review round


def test_a_kev_identifier_with_a_trailing_newline_is_rejected():
    import tempfile
    from pathlib import Path

    from advisory_radar.kev import KEV_CACHE_SCHEMA, _catalog_is_usable, load_kev
    from advisory_radar.state import save_state

    assert _catalog_is_usable([{"cveID": "CVE-2026-1234"}]) is True
    assert _catalog_is_usable([{"cveID": "CVE-2026-1234\n"}]) is False
    assert _catalog_is_usable([{"cveID": 1234}]) is False
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "kev.json"
        save_state(cache, {"schema": KEV_CACHE_SCHEMA, "cves": ["CVE-2026-1234\n"]})
        cves, known = load_kev(lambda *a: (500, {}, b""), cache, save=False)
    assert known is False and cves == frozenset(), "a malformed cached id authorizes nothing"


def test_re_evaluation_runs_before_classification(tmp_path):
    """A busy classification pass must not take the NVD budget a due watch needs."""
    cfg = config(tmp_path)
    order: list[str] = []
    original_reevaluate, original_classify = core.reevaluate, core.classify_new

    def spy_reevaluate(*args, **kwargs):
        order.append("reevaluate")
        return original_reevaluate(*args, **kwargs)

    def spy_classify(*args, **kwargs):
        order.append("classify")
        return original_classify(*args, **kwargs)

    core.reevaluate, core.classify_new = spy_reevaluate, spy_classify
    try:
        pipeline.run_pass(
            cfg,
            [WindowSource("s1", [item("g1", "advisory with CVE-2026-9999")])],
            [Notifier()],
            http=http_for({}),
            clock=lambda: float(NOW),
            sleep=lambda s: None,
        )
    finally:
        core.reevaluate, core.classify_new = original_reevaluate, original_classify
    assert order and order[0] == "reevaluate", "due watches are measured before new items are classified"


# ---------------------------------------------------------------------------
# Forty-second review round


def test_an_adobe_bulletin_outstanding_from_an_earlier_window_is_still_delivered():
    import advisory_radar.adobe as adobe_module

    state = core.new_state()
    state["adobe"] = {
        "window": ["APSB26-01"],
        "seen": {},
        "retry": {"APSB26-01": NOW - 60},
        "backlog": {
            "APSB26-01": {
                "cves": ["CVE-2026-1"],
                "url": "https://helpx.adobe.com/x",
                "first": NOW - 60,
            }
        },
    }
    # the next response no longer lists APSB26-01 at all
    original_list, original_detail = core._adobe_list, core._adobe_detail
    core._adobe_list = lambda http, stored: (adobe_module.Bulletin("APSB26-02", None, ("CVE-2026-2",), "u"),)
    core._adobe_detail = lambda http, apsb: adobe_module.Detail((), (), (), "", False)
    try:
        assert core.adobe_pass(state, lambda *a: (200, {}, b""), frozenset(), True, NOW) is True
        queued = [entry for entry in state["pending"] if "APSB26-01" in entry.get("ids", "")]
        assert queued, "a bulletin that rotated out of the list is still owed its message"
    finally:
        core._adobe_list, core._adobe_detail = original_list, original_detail


def test_parked_queue_can_be_dropped_without_notifier_credentials(tmp_path):
    from advisory_radar import cli
    from advisory_radar.state import load_state_document, save_state

    state_path = tmp_path / "state.json"
    state = core.new_state()
    state["parked"] = [{"kind": "alert", "tag": "warning", "title": "t", "body": "b", "ids": ["CVE-2026-1"]}]
    save_state(state_path, state)
    path = tmp_path / "c.yml"
    path.write_text(
        "sources: []\n"
        "notifiers:\n  - id: n\n    type: discord_webhook\n    url: ${DISCORD_WEBHOOK_URL}\n"
        f"state_path: {state_path}\n"
    )
    code = cli.main(["--config", str(path), "drop-parked"], env={})  # the referenced variable is missing
    assert code == 0, "a state-only command must not need plugin credentials"
    assert not load_state_document(state_path, core.STATE_SCHEMA, "state").get("parked")


def test_an_unreadable_supported_cvss_metric_prevents_suppression():
    """A readable LOW beside an unreadable CRITICAL must not authorize a suppression."""
    document = {
        "cveMetadata": {"cveId": "CVE-2026-1234"},
        "containers": {
            "cna": {
                "metrics": [
                    {"cvssV3_1": {"baseScore": 2.0, "vectorString": "AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}},
                    {"cvssV4_0": {"baseScore": "not-a-number"}},
                ]
            }
        },
    }
    cvss, _ssvc, _remote, malformed = core.cve_org_facts(document)
    assert cvss == 2.0
    assert malformed is True, "an unreadable supported metric makes the severity incomplete"

    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            if "cve.org" in url or "cveawg" in url:
                return 200, document
            return 404, None

    facts = Intel().cves(["CVE-2026-1234"])["CVE-2026-1234"]
    assert facts.complete is False


def test_parked_queue_recovery_survives_an_unbuildable_plugin(tmp_path):
    """Recovery must not depend on a plugin that cannot even be built."""
    from advisory_radar import cli
    from advisory_radar.state import load_state_document, save_state

    state_path = tmp_path / "state.json"
    state = core.new_state()
    state["parked"] = [{"kind": "alert", "tag": "warning", "title": "t", "body": "b", "ids": ["CVE-2026-1"]}]
    save_state(state_path, state)
    path = tmp_path / "c.yml"
    path.write_text(
        "sources: []\n"
        "notifiers:\n  - id: n\n    type: no_such_notifier\n    url: ${WEBHOOK_URL_FILE}\n"
        f"state_path: {state_path}\n"
    )
    code = cli.main(["--config", str(path), "drop-parked"], env={})
    assert code == 0
    assert not load_state_document(state_path, core.STATE_SCHEMA, "state").get("parked")


# ---------------------------------------------------------------------------
# Audit R04: a withdrawn OSV record is lifecycle, not current severity


def _osv_intel(document, cache=None):
    """An ``Intel`` whose only answer is this OSV document (or a pre-filled cache)."""

    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {} if cache is None else cache, lambda: 0.0, lambda seconds: None)

        def _get(self, url):
            return 200, document

    return Intel()


def test_a_withdrawn_osv_record_keeps_its_lifecycle_without_current_severity():
    """OSV still serves withdrawn records; the lifecycle is kept, but it is not current severity evidence."""
    ghsa = "GHSA-aaaa-bbbb-cccc"
    withdrawn = {
        "id": ghsa,
        "aliases": ["CVE-2026-1234"],
        "database_specific": {"severity": "CRITICAL"},
        "withdrawn": "2026-01-02T00:00:00Z",
    }
    intel = _osv_intel(withdrawn)
    facts = intel.ghsa(ghsa)
    assert facts.withdrawn is True, "the withdrawn lifecycle must be retained"
    assert facts.cvss is None, "a withdrawn record supplies no current CVSS"
    assert facts.complete is False, "a withdrawn record makes no complete-measurement claim"
    cached = intel._cache[ghsa]
    assert cached["withdrawn"] is True and cached["cvss"] is None and cached["complete"] is False
    assert intel.ghsa(ghsa) == facts, "the cached answer keeps the lifecycle fact"

    active = _osv_intel({key: value for key, value in withdrawn.items() if key != "withdrawn"}).ghsa(ghsa)
    assert active.withdrawn is False and active.complete is True
    assert active.cvss == core.OSV_SEVERITY_SCORE["CRITICAL"]

    legacy = _osv_intel(withdrawn, cache={ghsa: {"at": 0, "cves": ["CVE-2026-1234"], "cvss": 9.0, "complete": True}})
    assert legacy.ghsa(ghsa).withdrawn is False, "a cache entry written before the field existed is not withdrawn"

    for shape in (None, "", 0, {"at": "2026-01-02T00:00:00Z"}, ["2026-01-02T00:00:00Z"]):
        relaxed = _osv_intel({**withdrawn, "withdrawn": shape}).ghsa(ghsa)
        assert relaxed.withdrawn is False, f"an unreadable withdrawn shape must not claim the lifecycle: {shape!r}"
        assert relaxed.cvss == core.OSV_SEVERITY_SCORE["CRITICAL"], "and it is not current severity evidence"

    # A non-empty string is not a withdrawal unless it is a valid RFC3339 timestamp: malformed text must not
    # strip an active record's severity, and the cache must not remember it as withdrawn either.
    for malformed in (
        "not-a-timestamp",
        "2026-99-99T00:00:00Z",
        "2026-01-02",  # a date only: no time and no offset
        "2026-01-02T00:00:00",  # no offset: RFC3339 requires one
        "2026-01-02T25:00:00Z",  # an impossible hour
        "2026-01-02X00:00:00Z",  # an arbitrary separator: ISO 8601 accepts it, RFC3339 does not
        "2026-01-02T00:00+00:00",  # missing seconds: ISO 8601 accepts it, RFC3339 does not
        "2026-01-02T00:00:00+00:60",  # offset minute out of range: the parser would normalise it
        "2026-01-02T00:00:00+24:00",  # offset hour out of range
        " 2026-01-02T00:00:00Z",  # surrounding whitespace is not part of the field
        "2026-01-02T00:00:00Z\n",
        "2026-01-02T00:00:00.123456\u0661Z",  # an Arabic-Indic digit: \d would match it, RFC3339 does not
        "2026-01-02T00:00:60Z",  # ":60" is a leap second only at 23:59:60 UTC on 30 June or 31 December
        "2026-06-30T23:58:60Z",  # a leap second one minute early
        "2016-12-31T23:59:60Z",  # a leap second is deliberately unsupported: it must never strip severity
        "2017-01-01T00:59:60+01:00",  # nor may its offset spelling
    ):
        intel = _osv_intel({**withdrawn, "withdrawn": malformed})
        first = intel.ghsa(ghsa)
        assert first.withdrawn is False, f"malformed withdrawal text must not claim the lifecycle: {malformed!r}"
        assert first.cvss == core.OSV_SEVERITY_SCORE["CRITICAL"], "malformed withdrawal text must not strip severity"
        assert first.complete is True, "and it leaves the record a complete measurement"
        assert intel._cache[ghsa]["withdrawn"] is False, "the cache must not persist a malformed withdrawal"
        assert intel.ghsa(ghsa) == first, "a cache hit reads the malformed value as active too"

    # RFC3339 allows a lower-case "t" and "z", and a numeric offset in place of "Z"; all are withdrawals.
    for valid in (
        "2026-01-02t00:00:00z",
        "2026-01-02T00:00:00+01:00",
        "2026-01-02T00:00:00-23:59",
        "2026-01-02T00:00:00.5+23:59",
    ):
        assert _osv_intel({**withdrawn, "withdrawn": valid}).ghsa(ghsa).withdrawn is True, valid


def test_a_withdrawn_alias_free_ghsa_is_not_a_current_critical():
    """A withdrawn CRITICAL label must not produce a current critical verdict, and never a suppression."""
    document = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": [],
        "database_specific": {"severity": "CRITICAL"},
        "withdrawn": "2026-01-02T00:00:00Z",
    }
    state = core.new_state()
    item = core.Item(
        "g1",
        "GHSA-aaaa-bbbb-cccc advisory",
        "https://vendor.example/x",
        "notes",
        NOW - 60,
        ("GHSA-aaaa-bbbb-cccc",),
    )
    core.classify_new(
        state,
        [item],
        _osv_intel(document),
        frozenset(),
        True,
        NOW,
        "",
        core.Policy((), (), ()),
        thresholds=DEFAULT_THRESHOLDS,
    )
    assert [entry["tag"] for entry in state["pending"]] == ["warning"], (
        "a withdrawn advisory is history, not a current critical finding"
    )
    assert state["pending"][0]["levels"] == {}, "no CVE was measured"
    assert "treated as unknown" in state["pending"][0]["body"]


def test_a_withdrawn_ghsa_does_not_decide_a_mixed_item():
    """Withdrawing one advisory must not suppress unrelated CVEs: their own evidence still decides."""
    document = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": [],
        "database_specific": {"severity": "CRITICAL"},
        "withdrawn": "2026-01-02T00:00:00Z",
    }

    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda seconds: None)

        def _get(self, url):
            return 200, document

        def cves(self, cves, **ignored):
            return {cve: core.CveFacts(9.8, None, 0.5, 0.99, True, remote_unauth=True) for cve in cves}

    state = core.new_state()
    item = core.Item(
        "g2",
        "GHSA-aaaa-bbbb-cccc and CVE-2026-5555",
        "https://vendor.example/x",
        "notes",
        NOW - 60,
        ("GHSA-aaaa-bbbb-cccc", "CVE-2026-5555"),
    )
    core.classify_new(
        state,
        [item],
        Intel(),
        frozenset({"CVE-2026-5555"}),
        True,
        NOW,
        "",
        core.Policy((), (), ()),
        thresholds=DEFAULT_THRESHOLDS,
    )
    entry = state["pending"][0]
    assert entry["tag"] == "critical"
    assert entry["levels"] == {"CVE-2026-5555": "critical"}, "the active CVE decides on its own evidence"
    assert "OSV GHSA severity" not in entry["body"], "the withdrawn advisory supplies no deciding score"
    assert "without a CVE id decides the severity" not in entry["body"]


def test_a_withdrawn_ghsas_alias_is_judged_on_its_own_cve_evidence():
    """The advisory's lifecycle must not hide its alias: the CVE is looked up and its own facts decide."""
    document = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": ["CVE-2026-7777"],  # the CVE does not appear in the item's own text
        "database_specific": {"severity": "CRITICAL"},
        "withdrawn": "2026-01-02T00:00:00Z",
    }
    looked_up = []

    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda seconds: None)

        def _get(self, url):
            return 200, document

        def cves(self, cves, **ignored):
            looked_up.extend(cves)
            return {cve: core.CveFacts(9.8, None, 0.5, 0.99, True, remote_unauth=True) for cve in cves}

    state = core.new_state()
    item = core.Item(
        "g3",
        "GHSA-aaaa-bbbb-cccc advisory",
        "https://vendor.example/x",
        "notes",
        NOW - 60,
        ("GHSA-aaaa-bbbb-cccc",),
    )
    core.classify_new(
        state,
        [item],
        Intel(),
        frozenset(),
        True,
        NOW,
        "",
        core.Policy((), (), ()),
        thresholds=DEFAULT_THRESHOLDS,
    )
    assert looked_up == ["CVE-2026-7777"], "the withdrawn advisory's alias is still looked up"
    entry = state["pending"][0]
    assert entry["tag"] == "critical", "the aliased CVE's own CVE.org/NVD evidence still decides"
    assert entry["levels"] == {"CVE-2026-7777": "critical"}
    assert "CVE-2026-7777" in entry["ids"], "the alias stays in the queued identity"


def test_withdrawal_does_not_rewrite_delivered_history():
    """The lifecycle fact changes the current verdict only; seen, deliveries and watch keep what happened."""
    document = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": [],
        "database_specific": {"severity": "CRITICAL"},
        "withdrawn": "2026-01-02T00:00:00Z",
    }
    seen = {"CVE-2026-5555": {"at": NOW - 9000, "outcome": "delivered", "delivery": "snap-1"}}
    deliveries = {"snap-1": {"tag": "critical", "ids": ["CVE-2026-5555"], "delivered_to": ["fake"]}}
    watch = {
        "CVE-2026-5555": {
            "since": NOW - 9000,
            "last_eval": NOW - 9000,
            "level": "critical",
            "judged": "critical",
            "title": "vendor widget",
            "link": "https://vendor.example/x",
            "cvss": 9.8,
            "thresholds": [9.0, 0.10, 4.0],
        }
    }
    state = core.new_state()
    state["seen"] = copy.deepcopy(seen)
    state["deliveries"] = copy.deepcopy(deliveries)
    state["watch"] = copy.deepcopy(watch)
    item = core.Item(
        "g2",
        "GHSA-aaaa-bbbb-cccc and CVE-2026-5555",
        "https://vendor.example/x",
        "notes",
        NOW - 60,
        ("GHSA-aaaa-bbbb-cccc", "CVE-2026-5555"),
    )
    core.classify_new(
        state,
        [item],
        _osv_intel(document),
        frozenset(),
        True,
        NOW,
        "",
        core.Policy((), (), ()),
        thresholds=DEFAULT_THRESHOLDS,
    )
    assert state["seen"] == seen, "a delivered record keeps its time, outcome and snapshot"
    assert state["deliveries"] == deliveries
    assert state["watch"] == watch
    assert [entry["tag"] for entry in state["pending"]] == ["warning"], (
        "the withdrawn advisory is not current critical evidence"
    )


def test_a_suppressed_item_leaves_an_identifier_another_message_owns():
    """Suppression must not record history for an identifier a queued message introduced."""
    state = core.new_state()
    state["pending"].append(
        {
            "kind": "new",
            "queued_at": NOW,
            "fresh": ["CVE-2026-1111"],
            "tag": "critical",
            "title": "queued",
            "body": "",
            "ids": ["CVE-2026-1111"],
            "cves": ["CVE-2026-1111"],
            "levels": {"CVE-2026-1111": "critical"},
            "source": "s",
            "link": "https://x.example",
        }
    )
    item = core.Item(
        "g1", "CVE-2026-1111 and CVE-2026-2222", "https://x.example/a", "n", NOW, ("CVE-2026-1111", "CVE-2026-2222")
    )
    verdict = core.Verdict("suppressed", (), "CVSS 2.0", "")
    core._suppressed(state, ["CVE-2026-1111", "CVE-2026-2222"], verdict, item, {}, NOW, DEFAULT_THRESHOLDS)
    assert "CVE-2026-1111" not in state["seen"], "the queued message owns it and will report it"
    assert state["seen"]["CVE-2026-2222"]["outcome"] == "suppressed"


def test_bootstrap_history_does_not_take_a_queued_identifier():
    """Seeding an old item must not record an identifier a queued message owns, or its delivery event is lost."""
    state = core.new_state()
    state["pending"].append(
        {
            "kind": "new",
            "queued_at": NOW,
            "fresh": ["CVE-2026-1111"],
            "tag": "warning",
            "title": "WARNING: CVE-2026-1111 in widget",
            "body": "",
            "ids": ["CVE-2026-1111"],
            "cves": ["CVE-2026-1111"],
            "levels": {"CVE-2026-1111": "warning"},
            "source": "s",
            "link": "https://x.example",
        }
    )
    old = core.Item(
        "g1",
        "CVE-2026-1111 and CVE-2026-2222",
        "https://x.example/a",
        "",
        NOW - 40 * 86400,
        ("CVE-2026-1111", "CVE-2026-2222"),
    )
    core.seed(state, [old], NOW)
    assert "CVE-2026-1111" not in state["seen"], "the queued message owns it and will report it"
    assert state["seen"]["CVE-2026-2222"]["outcome"] == "backlog"


def test_settlement_is_idempotent_across_a_serialisation():
    """Settling a state twice, with a save between, changes nothing: recorded ownership is never rewritten."""
    state = core.new_state()
    state["parked"].append(
        {
            "kind": "new",
            "queued_at": NOW - 7200,
            "tag": "critical",
            "title": "legacy owner",
            "body": "",
            "ids": ["CVE-2026-3333"],
            "cves": ["CVE-2026-3333"],
            "levels": {"CVE-2026-3333": "critical"},
            "source": "s",
            "link": "https://x.example",
        }
    )
    state["pending"].append(
        {
            "kind": "new",
            "queued_at": NOW - 3600,
            "fresh": ["CVE-2026-4444"],
            "tag": "warning",
            "title": "modern mention",
            "body": "",
            "ids": ["CVE-2026-3333", "CVE-2026-4444"],
            "cves": ["CVE-2026-4444"],
            "levels": {"CVE-2026-4444": "warning"},
            "source": "s",
            "link": "https://x.example",
        }
    )
    core._ensure_ownership(state)
    once = json.dumps(state, sort_keys=True)
    # A save and a load are a JSON round trip: settlement must produce the same state on the other side.
    reloaded = json.loads(once)
    core._ensure_ownership(reloaded)
    assert json.dumps(reloaded, sort_keys=True) == once


# ---------------------------------------------------------------------------
# Pipeline robustness and delivery correctness review


def _health(ok_at: int, *, ok: bool = False) -> dict:
    """One ``source_health`` record the way ``pipeline._record_health`` writes it."""
    return {"at": ok_at, "ok": ok, "ok_at": ok_at, "items": 0, "error": "" if ok else "OSError: down"}


def _seeded_state(source_health: dict | None = None) -> dict:
    state = core.new_state()
    state["seeded"] = {"s1": True}
    if source_health is not None:
        state["source_health"] = source_health
    return state


def test_an_advisory_published_during_an_outage_is_news_not_backlog(tmp_path):
    """A source down for longer than BACKLOG_AGE returns what it missed; age alone must not call that history."""
    cfg = config(tmp_path)
    cfg.store().save(_seeded_state({"s1": _health(NOW - 10 * core.DAY)}))
    missed = core.Item(
        "missed", "vendor advisory missed", "https://vendor.example.com/m", "notes", NOW - 9 * core.DAY, ()
    )
    notifier = Notifier()
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", [missed])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert [entry["title"] for entry in notifier.sent] == ["WARNING: vendor advisory missed"]
    seen = cfg.store().load()["seen"]
    assert seen["src:s1:missed"]["outcome"] == "delivered", (
        "an item the outage hid is reported, not recorded as history"
    )


def test_history_older_than_the_last_success_is_still_backlog_after_an_outage(tmp_path):
    cfg = config(tmp_path)
    cfg.store().save(_seeded_state({"s1": _health(NOW - 10 * core.DAY)}))
    old = core.Item("old", "vendor advisory old", "https://vendor.example.com/o", "notes", NOW - 30 * core.DAY, ())
    notifier = Notifier()
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", [old])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert notifier.sent == []
    assert cfg.store().load()["seen"]["src:s1:old"]["outcome"] == "backlog"


def test_a_source_that_never_answered_keeps_the_age_rule(tmp_path):
    """No recorded success (a re-enabled source has its health dropped) means age alone decides, as before."""
    cfg = config(tmp_path)
    cfg.store().save(_seeded_state())
    nine_days = core.Item(
        "nine", "vendor advisory nine", "https://vendor.example.com/n", "notes", NOW - 9 * core.DAY, ()
    )
    notifier = Notifier()
    pipeline.run_pass(
        cfg,
        [WindowSource("s1", [nine_days])],
        [notifier],
        http=http_for({}),
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert notifier.sent == []
    assert cfg.store().load()["seen"]["src:s1:nine"]["outcome"] == "backlog"


class _NoLookups(core.Intel):
    def __init__(self) -> None:
        super().__init__(None, {}, lambda: float(NOW), lambda s: None)


def _classify(state: dict, published: int, **extra) -> core.Item:
    entry = core.Item("g1", "vendor advisory", "https://vendor.example.com/a", "notes", published, ())
    core.classify_new(
        state,
        [entry],
        _NoLookups(),
        frozenset(),
        True,
        NOW,
        "vendor.example.com",
        core.Policy(("curl",), (), ()),
        thresholds=DEFAULT_THRESHOLDS,
        **extra,
    )
    return entry


def test_the_outage_slack_decides_the_boundary_of_history():
    """History is older than BACKLOG_AGE and published before the last success minus one day of slack."""
    last_ok = NOW - 10 * core.DAY
    edge = last_ok - core.BACKLOG_OUTAGE_SLACK
    news, history = core.new_state(), core.new_state()
    _classify(news, edge, last_ok=last_ok)
    _classify(history, edge - 1, last_ok=last_ok)
    assert len(news["pending"]) == 1, "published exactly at the edge is news"
    assert history["pending"] == [] and history["seen"]["src:g1"]["outcome"] == "backlog"


def test_the_age_rule_alone_applies_without_a_last_success():
    state = core.new_state()
    _classify(state, NOW - 8 * core.DAY, last_ok=0)
    assert state["pending"] == [] and state["seen"]["src:g1"]["outcome"] == "backlog"


def test_a_last_success_in_the_future_cannot_turn_history_into_news():
    """A clock that stepped backwards must not make every old item look like one an outage hid."""
    state = core.new_state()
    _classify(state, NOW - 30 * core.DAY, last_ok=NOW + 365 * core.DAY)
    assert state["pending"] == [] and state["seen"]["src:g1"]["outcome"] == "backlog"


def test_the_tail_left_by_a_full_queue_gets_the_same_outage_decision():
    """The tail past the delivery room is decided by the same rule, so the carry holds only news."""
    last_ok = NOW - 10 * core.DAY
    state = core.new_state()
    # Undated items sort first and fill the room, so the two dated items below are the tail.
    undated = [core.Item(f"u{n}", f"undated {n}", "https://vendor.example.com/u", "n", None, ()) for n in range(6)]
    missed = core.Item("missed", "missed", "https://vendor.example.com/m", "n", NOW - 9 * core.DAY, ())
    old = core.Item("old", "old", "https://vendor.example.com/o", "n", NOW - 30 * core.DAY, ())
    left = core.classify_new(
        state,
        [*undated, missed, old],
        _NoLookups(),
        frozenset(),
        True,
        NOW,
        "vendor.example.com",
        core.Policy(("curl",), (), ()),
        thresholds=DEFAULT_THRESHOLDS,
        last_ok=last_ok,
    )
    assert {entry.guid for entry in left} == {"u5", "missed"}, "news the room could not take is carried"
    assert state["seen"]["src:old"]["outcome"] == "backlog", "history in the tail is still recorded, never carried"


def _kev_http(*cves: str):
    body = json.dumps({"catalogVersion": "1", "vulnerabilities": [{"cveID": cve} for cve in cves]}).encode()

    def http(method, url, headers, payload):
        return 200, {"ETag": "e1"}, body

    return http


def test_a_failed_kev_cache_write_still_returns_the_fresh_catalog(tmp_path, caplog):
    """The cache is an optimisation: a write fault must not discard the catalog that was just fetched."""
    from advisory_radar.kev import load_kev

    blocker = tmp_path / "blocker"
    blocker.write_text("a file where the cache directory should be")
    with caplog.at_level("WARNING", logger="advisory_radar"):
        cves, known = load_kev(_kev_http("CVE-2026-1111"), blocker / "kev.json", save=True)
    assert cves == frozenset({"CVE-2026-1111"}) and known is True
    assert "could not be written" in caplog.text and str(blocker) in caplog.text


def test_the_kev_cache_is_written_on_one_line_and_read_back(tmp_path):
    """The cache is saved like the state document, so it is not padded, and the next fetch still reads it."""
    from advisory_radar.kev import load_kev

    cache = tmp_path / "kev.json"
    load_kev(_kev_http("CVE-2026-1111", "CVE-2026-2222"), cache, save=True)
    assert "\n" not in cache.read_text(encoding="utf-8")[:-1], "one line"

    def not_modified(method, url, headers, payload):
        assert headers["If-None-Match"] == "e1", "the validator stored in the compact cache is sent back"
        return 304, {}, b""

    cves, known = load_kev(not_modified, cache, save=False)
    assert cves == frozenset({"CVE-2026-1111", "CVE-2026-2222"}) and known is True


def test_a_pass_survives_an_unwritable_kev_cache(tmp_path):
    cfg = config(tmp_path)
    (tmp_path / "kev.json").mkdir()  # the cache cannot be replaced by a file, so the write fails
    notifier = Notifier()

    def http(method, url, headers, payload):
        if urlsplit(url).hostname == "www.cisa.gov":
            return _kev_http("CVE-2026-4242")(method, url, headers, payload)
        return http_for({})(method, url, headers, payload)

    code = pipeline.run_pass(
        cfg,
        [WindowSource("s1", [item("g1", "vendor note")])],
        [notifier],
        http=http,
        clock=lambda: float(NOW),
        sleep=lambda s: None,
    )
    assert code == 0, "an unwritable cache is a warning, never a failed pass"
    assert len(notifier.sent) == 1


class _Clock:
    """A monotonic clock a test moves by hand, installed as the ``time`` the HTTP transport reads."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


class _Dribble:
    """A response body a peer sends one byte at a time, each read costing simulated seconds, with no socket.

    ``read`` behaves as ``http.client`` does: it keeps reading until it has the requested bytes or the peer
    closes, however many reads (and however much time) that takes. ``read1`` returns after one read.
    """

    status = 200
    headers: dict = {}

    def __init__(self, clock: _Clock, seconds_per_byte: float, size: int = 2000) -> None:
        self.clock = clock
        self.seconds_per_byte = seconds_per_byte
        self.left = size
        self.reads = 0

    def read1(self, size: int = -1) -> bytes:
        if self.left <= 0:
            return b""
        self.reads += 1
        self.clock.now += self.seconds_per_byte
        self.left -= 1
        return b"x"

    def read(self, size: int = -1) -> bytes:
        body = b""
        while (size < 0 or len(body) < size) and (chunk := self.read1(1)):
            body += chunk
        return body

    def close(self) -> None:  # ``HTTPError`` closes the body it wraps when it is collected
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        return False


def _http_with(monkeypatch, opened):
    """``urllib_http`` over a fake opener and a hand-moved clock; returns the clock."""
    import types

    from advisory_radar import http as transport

    clock = _Clock()
    monkeypatch.setattr(transport, "time", types.SimpleNamespace(monotonic=clock.monotonic))
    monkeypatch.setattr(transport._OPENER, "open", opened)
    return clock, transport


def test_a_body_that_dribbles_past_the_deadline_is_a_network_error(monkeypatch):
    """HTTP_TIMEOUT bounds one socket operation; a peer sending a byte every few seconds must still be cut off."""
    body: _Dribble | None = None

    def opened(request, timeout):
        nonlocal body
        body = _Dribble(clock, seconds_per_byte=10.0)
        return body

    clock, transport = _http_with(monkeypatch, opened)
    assert transport.urllib_http("GET", "https://feeds.example.com/slow", {}, None) == (0, {}, b"")
    assert body is not None and body.reads <= transport.HTTP_DEADLINE // 10 + 1, "it stopped reading at the deadline"


def test_the_deadline_counts_the_time_spent_before_the_first_byte(monkeypatch):
    """The clock starts before the connection, so a slow connect or header wait spends the same budget, and a
    request that reaches its first body read with nothing left ends there. This one has no socket: a wait for the
    headers is itself cut at the deadline by the real transport, which the loopback tests below cover."""

    def opened(request, timeout):
        clock.now += transport.HTTP_DEADLINE + 1  # connecting and waiting for the headers took that long
        return _Dribble(clock, seconds_per_byte=0.0, size=10)

    clock, transport = _http_with(monkeypatch, opened)
    assert transport.urllib_http("GET", "https://feeds.example.com/late", {}, None) == (0, {}, b"")


def test_a_refusal_that_dribbles_its_body_keeps_its_status(monkeypatch):
    import urllib.error

    def opened(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url, 503, "busy", {"Retry-After": "30"}, _Dribble(clock, seconds_per_byte=10.0)
        )

    clock, transport = _http_with(monkeypatch, opened)
    status, headers, payload = transport.urllib_http("GET", "https://feeds.example.com/busy", {}, None)
    assert status == 503 and headers == {"Retry-After": "30"}, "the refusal is the answer; only its body was lost"
    assert payload == b""


def test_a_body_inside_the_deadline_is_returned_whole_and_bounded_by_the_limit(monkeypatch):
    clock, transport = _http_with(monkeypatch, lambda request, timeout: _Dribble(clock, 0.01, size=100))
    monkeypatch.setattr(transport, "MAX_RESPONSE_BYTES", 10)
    status, _, payload = transport.urllib_http("GET", "https://feeds.example.com/big", {}, None)
    assert status == 200 and payload == b"x" * 11, "callers rely on receiving MAX_RESPONSE_BYTES + 1 bytes"
    monkeypatch.setattr(transport, "MAX_RESPONSE_BYTES", 1000)
    assert transport.urllib_http("GET", "https://feeds.example.com/small", {}, None)[2] == b"x" * 100


# ---------------------------------------------------------------------------
# PR #140 review round: what the transport keeps of an answer it could not finish, and where it stops waiting


class _LosesItsBody(_Dribble):
    """A response whose status line arrived and whose body ends in a connection reset."""

    def read1(self, size: int = -1) -> bytes:
        raise ConnectionResetError("reset by peer")


@pytest.mark.parametrize(
    "body",
    [
        lambda clock: _Dribble(clock, seconds_per_byte=10.0),
        lambda clock: _LosesItsBody(clock, seconds_per_byte=0.0),
    ],
    ids=["dribbled-past-the-deadline", "reset"],
)
def test_a_post_keeps_the_status_its_receiver_answered_when_the_body_is_lost(monkeypatch, body):
    """A notifier POST is judged by its status alone, and a 200 is the receiver's answer whatever follows it.

    Reporting status 0 for it says "not delivered", so the message is posted again and the receiver gets it twice.
    A GET that reads a document is the opposite: a truncated document is not the document, so it stays an error.
    """
    clock, transport = _http_with(monkeypatch, lambda request, timeout: body(clock))
    assert transport.urllib_http("POST", "https://hooks.example.com/x", {}, b"{}") == (200, {}, b"")
    assert transport.urllib_http("GET", "https://feeds.example.com/x", {}, None) == (0, {}, b"")


def test_a_webhook_that_answered_200_is_not_told_apart_from_one_that_finished(monkeypatch):
    from advisory_radar.notifiers import WebhookNotifier

    clock, transport = _http_with(monkeypatch, lambda request, timeout: _Dribble(clock, seconds_per_byte=10.0))
    entry = {"title": "t", "body": "b", "tag": "warning", "kind": "new", "ids": ["CVE-2026-1"]}
    assert WebhookNotifier("hook", "https://hooks.example.com/x").send(entry, transport.urllib_http) == 200


_HTTP_200 = b"HTTP/1.1 200 OK\r\nConnection: close\r\n"
_CHUNKED = _HTTP_200 + b"Transfer-Encoding: chunked\r\n\r\n"
#: Places inside one response where a peer can stall, as ``(sent before the stall, sent after it)``. The stall is a
#: run of single bytes in a chunk extension, a trailer or a header: reading the body in pieces never covers them.
_STALLS = {
    "chunk-size-extension": (_CHUNKED + b"5;e=", b"\r\nhello\r\n0\r\n\r\n"),
    "last-chunk-extension": (_CHUNKED + b"5\r\nhello\r\n0;e=", b"\r\n\r\n"),
    "trailer": (_CHUNKED + b"5\r\nhello\r\n0\r\nX-T: ", b"\r\n\r\n"),
    "header": (_HTTP_200 + b"Content-Length: 5\r\nX-Slow: ", b"\r\n\r\nhello"),
}


def _dribble(count: int, interval: float) -> list:
    """``count`` single bytes, each followed by a pause of ``interval`` seconds."""
    return [part for _ in range(count) for part in (b"x", interval)]


@contextlib.contextmanager
def _scripted_server(monkeypatch, *script):
    """A loopback server that answers every request by playing ``script``: bytes are sent, numbers are pauses.

    Yields the URL and an event that is set when a send failed because the client had gone away, which is how a
    test sees that the client stopped reading while the server still had bytes to send.
    """
    gone = threading.Event()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            received = b""
            while b"\r\n\r\n" not in received:  # the request head, and with it a small body
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                received += chunk
            try:
                for part in script:
                    if isinstance(part, bytes):
                        self.request.sendall(part)
                    else:
                        time.sleep(part)
            except OSError:
                gone.set()

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    # An environment proxy must not stand between the test and the loopback server it starts.
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/", gone
    finally:
        server.shutdown()
        server.server_close()


def _short_limits(monkeypatch, deadline: float = 0.4):
    """The transport with a short deadline and a socket timeout no test pause comes near.

    A test that expects the request to fail may use the 0.4 s default: a slow machine only makes it fail sooner.
    A test that expects an answer to arrive passes a deadline its loopback exchange cannot plausibly miss.
    """
    from advisory_radar import http as transport

    monkeypatch.setattr(transport, "HTTP_DEADLINE", deadline)
    monkeypatch.setattr(transport, "HTTP_TIMEOUT", 5)
    return transport


@pytest.mark.parametrize("stall", _STALLS)
def test_a_peer_that_dribbles_framing_bytes_is_cut_off_at_the_deadline(monkeypatch, stall):
    """``read1`` returns after one read of the body, but it can sit inside a chunk-size line, a trailer or a header
    for as long as bytes keep arriving inside the socket timeout; the deadline has to stop that too."""
    transport = _short_limits(monkeypatch)
    before, after = _STALLS[stall]
    with _scripted_server(monkeypatch, before, *_dribble(100, 0.05), after) as (url, gone):
        assert transport.urllib_http("GET", url, {}, None) == (0, {}, b"")
        assert gone.wait(3), "the client gave up while the server was still sending: the deadline stopped it"


@pytest.mark.parametrize("stall", _STALLS)
def test_framing_that_arrives_in_time_is_read_whole(monkeypatch, stall):
    """The control for the test above: the same responses, without the stall, are read exactly as before."""
    transport = _short_limits(monkeypatch, deadline=10)
    before, after = _STALLS[stall]
    with _scripted_server(monkeypatch, before, *_dribble(3, 0.0), after) as (url, _):
        status, headers, payload = transport.urllib_http("GET", url, {}, None)
    assert (status, payload) == (200, b"hello")
    assert ("X-Slow" in headers) == (stall == "header")


def test_a_read_that_waits_for_the_server_ends_at_the_deadline_not_at_the_socket_timeout(monkeypatch):
    """Nothing is in flight here, so one receive is waiting for the peer: it must not outlast the deadline."""
    transport = _short_limits(monkeypatch)
    with _scripted_server(monkeypatch, _HTTP_200 + b"Content-Length: 5\r\n\r\n", 3.0, b"hello") as (url, _):
        started = time.monotonic()
        result = transport.urllib_http("GET", url, {}, None)
        elapsed = time.monotonic() - started
    assert result == (0, {}, b"")
    assert elapsed < 2.5, "the receive was cut at the 0.4 s deadline; the socket timeout (5 s) never applied"


def test_a_webhook_that_answers_200_and_then_stalls_its_body_is_still_a_200(monkeypatch):
    """The same loss as above, over a real connection: the receiver answered, so the answer is its status.

    The 200 has to arrive inside the deadline for this to be the case, so the deadline is a second here, not the
    0.4 s of the tests that expect a failure; the stall that follows the 200 lasts five.
    """
    transport = _short_limits(monkeypatch, deadline=1.0)
    with _scripted_server(monkeypatch, _HTTP_200 + b"Content-Length: 100000\r\n\r\n", *_dribble(100, 0.05)) as (
        url,
        gone,
    ):
        status, _, payload = transport.urllib_http("POST", url, {"Content-Type": "application/json"}, b"{}")
        assert gone.wait(3), "the client stopped waiting at the deadline"
        assert (status, payload) == (200, b""), "a receiver that answered 200 was not asked twice"
        assert transport.urllib_http("GET", url, {}, None) == (0, {}, b""), "a document read is still incomplete"


# ---------------------------------------------------------------------------
# PR #160 review round: the request ceiling bounds the connection too, not only the answer


def _connecting_to(monkeypatch, *addresses: str, connect):
    """``urllib_http`` on a hand-moved clock, with a name that resolves to ``addresses`` and a ``connect`` of ours.

    No packet leaves the machine: ``connect(clock, sock, address)`` stands in for the kernel's, so a test decides how
    long each address takes and whether it answers. The limits are the ones the transport ships with.
    """
    import socket
    import types

    from advisory_radar import http as transport

    clock = _Clock()
    monkeypatch.setattr(transport, "time", types.SimpleNamespace(monotonic=clock.monotonic))
    monkeypatch.setattr(transport, "HTTP_TIMEOUT", 30)
    monkeypatch.setattr(transport, "HTTP_DEADLINE", 120)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addresses],
    )
    monkeypatch.setattr(socket.socket, "connect", lambda sock, address: connect(clock, sock, address))
    # An environment proxy would take the request to a place this test did not stub.
    monkeypatch.setenv("no_proxy", "*")
    monkeypatch.setenv("NO_PROXY", "*")
    return clock, transport


def test_a_name_with_several_unreachable_addresses_gets_the_deadline_not_a_timeout_per_address(monkeypatch):
    """``socket.create_connection`` gives every address the whole socket timeout, one after the other, so a name that
    resolves to four dead addresses held a request for four timeouts however little the pass budget had left."""
    waited: list[float] = []

    def blackhole(clock, sock, address):
        waited.append(sock.gettimeout())
        clock.now += sock.gettimeout()  # nobody answers: the attempt lasts as long as it is allowed to
        raise TimeoutError("timed out")

    clock, transport = _connecting_to(
        monkeypatch, "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", connect=blackhole
    )
    start = clock.now
    with transport.request_ceiling(lambda: 50.0 - (clock.now - start)):
        assert transport.urllib_http("GET", "http://feeds.example.com/slow", {}, None) == (0, {}, b"")
    assert clock.now - start <= 50.0, "the request outlived what the budget left it"
    assert waited == [30.0, 20.0], "an attempt waits for what is left, and none is started once nothing is"


def test_the_tls_handshake_gets_what_the_connect_left_of_the_deadline(monkeypatch):
    """The handshake takes its time from the socket's timeout. A connect that used 25 of the 50 seconds the budget left
    must therefore have set it again: left as the attempt set it, the handshake would be given 30 seconds of 25."""
    import ssl

    handshakes: list[float] = []

    def slow(clock, sock, address):
        clock.now += 25.0  # the address answers, after half of what the request has

    def stalls(context, sock, *args, **kwargs):
        handshakes.append(sock.gettimeout())
        raise ssl.SSLError("the handshake timed out")

    clock, transport = _connecting_to(monkeypatch, "192.0.2.1", connect=slow)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", stalls)
    start = clock.now
    with transport.request_ceiling(lambda: 50.0 - (clock.now - start)):
        assert transport.urllib_http("GET", "https://feeds.example.com/slow", {}, None) == (0, {}, b"")
    assert handshakes == [25.0]


def test_a_tls_handshake_that_stalls_ends_at_the_deadline_not_at_the_socket_timeout(monkeypatch):
    """A peer that accepts the connection and never speaks TLS: the handshake waits for it, and for no longer than the
    request has left. The silent server here is the scripted one with nothing to say."""
    transport = _short_limits(monkeypatch)
    with _scripted_server(monkeypatch) as (url, _):
        started = time.monotonic()
        result = transport.urllib_http("GET", url.replace("http://", "https://", 1), {}, None)
        elapsed = time.monotonic() - started
    assert result == (0, {}, b"")
    assert elapsed < 2.5, "the handshake was cut at the 0.4 s deadline; the socket timeout (5 s) never applied"


def test_an_address_that_refuses_falls_through_to_the_next_one_that_answers(monkeypatch):
    """The control for the tests above: a refusal is instant, so the next address of the name serves the request."""
    import socket

    transport = _short_limits(monkeypatch, deadline=10)
    refusing = socket.socket()
    refusing.bind(("127.0.0.1", 0))  # bound and never listening: a connect to it is refused at once
    try:
        with _scripted_server(monkeypatch, _HTTP_200 + b"Content-Length: 5\r\n\r\n", b"hello") as (url, _):
            port = urlsplit(url).port
            monkeypatch.setattr(
                socket,
                "getaddrinfo",
                lambda host, number, *args, **kwargs: [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", refusing.getsockname()[1])),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
                ],
            )
            monkeypatch.setenv("no_proxy", "*")
            monkeypatch.setenv("NO_PROXY", "*")
            status, _, payload = transport.urllib_http("GET", f"http://feeds.example.com:{port}/", {}, None)
    finally:
        refusing.close()
    assert (status, payload) == (200, b"hello")
