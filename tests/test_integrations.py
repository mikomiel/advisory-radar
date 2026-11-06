"""P4 integration tests: changedetection.io polling, webhook intake, extra notifiers."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from advisory_radar.config import load_config
from advisory_radar.notifiers import GotifyNotifier, MatrixWebhookNotifier, NtfyNotifier
from advisory_radar.sources import ChangedetectionSource, WebhookSource, webhook_item_from_payload
from advisory_radar.web import create_app

WATCHES_V1 = {
    "uuid-1": {
        "uuid": "uuid-1",
        "url": "https://shop.example.com/item",
        "link": "https://shop.example.com/item",
        "title": "Shop item",
        "page_title": "Shop",
        "paused": False,
        "notification_muted": False,
        "last_checked": 1000,
        "last_changed": 900,
    },
}
WATCHES_V2 = {
    "uuid-1": {**WATCHES_V1["uuid-1"], "last_changed": 2000},
    "uuid-2": {
        "uuid": "uuid-2",
        "url": "https://news.example.com/",
        "title": "News",
        "paused": True,
        "last_changed": 2100,
    },
}


def cd_http_factory(version):
    def http(method, url, headers, body):
        assert headers.get("x-api-key") == "KEY"
        assert url.endswith("/api/v1/watch")
        return 200, {}, json.dumps(version).encode()

    return http


def test_changedetection_source_emits_only_new_changes():
    source = ChangedetectionSource("cd", "https://cd.example.com", "KEY")
    state: dict = {}
    first = source.fetch(cd_http_factory(WATCHES_V1), state)
    assert [i.guid for i in first.items] == ["cd:uuid-1:900"]
    assert not state.get("changedetection"), "fetch alone must not advance the cursor"
    source.commit(state)  # the pipeline commits after classification
    again = source.fetch(cd_http_factory(WATCHES_V1), state)
    assert again.items == ()  # unchanged -> nothing new
    second = source.fetch(cd_http_factory(WATCHES_V2), state)
    assert [i.guid for i in second.items] == ["cd:uuid-1:2000"]  # paused uuid-2 skipped
    assert second.items[0].link == "https://shop.example.com/item"


def test_webhook_payload_mapping():
    entry = webhook_item_from_payload(
        {"watch_uuid": "u1", "watch_title": "Shop", "watch_url": "https://x.example", "diff": "price changed"}
    )
    assert entry and entry["title"] == "Shop" and "price changed" in entry["summary"]
    generic = webhook_item_from_payload(
        {"title": "CVE-2026-1 announced", "text": "fixes CVE-2026-1", "url": "https://v.example/a"}
    )
    assert generic and generic["guid"].startswith("wh:")
    assert webhook_item_from_payload({"no": "title"}) is None
    assert webhook_item_from_payload([1, 2]) is None


def test_webhook_intake_and_source_roundtrip(tmp_path):
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(f"sources:\n  - id: wh\n    type: webhook\nnotifiers: []\nstate_path: {tmp_path}/state.json\n")
    cfg = load_config(cfg_path, {})
    app = create_app(
        cfg,
        {"ADVISORY_RADAR_AUTH_TOKEN": "t", "ADVISORY_RADAR_WEBHOOK_SECRET": "s3cret"},
        sources=[WebhookSource("wh")],
    )
    client = TestClient(app)
    # an unconfigured source id is refused outright, before any authentication is considered
    assert client.post("/webhooks/other", json={"title": "x"}).status_code == 404
    # a configured source without the bearer secret is unauthorized, and writes nothing
    assert client.post("/webhooks/wh", json={"title": "x"}).status_code == 401
    assert not (tmp_path / "state.json").exists()
    response = client.post(
        "/webhooks/wh",
        json={"title": "Vendor advisory CVE-2026-7777", "text": "fixes CVE-2026-7777", "url": "https://v.example/a"},
        headers={"Authorization": "Bearer s3cret"},
    )
    assert response.status_code == 200
    state = json.loads((tmp_path / "state.json").read_text())
    source = WebhookSource("wh")
    window = source.fetch(lambda *a: (0, {}, b""), state)
    assert len(window.items) == 1
    assert window.items[0].explicit == ("CVE-2026-7777",)


def test_notifier_payload_shapes():
    calls = []

    def http(method, url, headers, body):
        calls.append((method, url, dict(headers), body))
        return 204, {}, b""

    entry = {
        "title": "CRITICAL: X",
        "body": "\n- **Severity:** CVSS 9.8",
        "tag": "critical",
        "kind": "new",
        "ids": ["CVE-2026-1"],
        "link": "https://v.example",
        "source": "s",
    }
    assert MatrixWebhookNotifier("m", "https://matrix.example/hook").send(entry, http) == 204
    assert NtfyNotifier("n", "https://ntfy.example", "alerts").send(entry, http) == 204
    assert GotifyNotifier("g", "https://gotify.example", "tok").send(entry, http) == 204
    matrix_call = next(c for c in calls if "matrix" in c[1])
    assert json.loads(matrix_call[3])["msgtype"] == "m.text"
    ntfy_call = next(c for c in calls if "ntfy" in c[1])
    # JSON body, not a Title header: a header cannot carry a non-Latin-1 title
    published = json.loads(ntfy_call[3])
    assert ntfy_call[1].endswith("/alerts") and published["title"] == "CRITICAL: X"
    assert published["topic"] == "alerts" and published["priority"] == 3
    gotify_call = next(c for c in calls if "gotify" in c[1])
    assert "token=tok" in gotify_call[1]


def test_every_built_in_is_configurable_through_yaml(tmp_path):
    """A builder key the config parser rejects is an integration nobody can configure."""
    from advisory_radar.config import load_config
    from advisory_radar.pipeline import build_plugins

    configs = {
        "changedetection": "sources:\n  - id: c\n    type: changedetection\n    url: https://cd.example.com\n"
        "    api_key: k\n    tag: advisories\n",
        "ntfy": "notifiers:\n  - id: n\n    type: ntfy\n    url: https://ntfy.example.com\n    topic: alerts\n"
        "    priority: 4\n",
        "gotify": "notifiers:\n  - id: g\n    type: gotify\n    url: https://gotify.example.com\n    token: t\n"
        "    priority: 5\n",
        "smtp": "notifiers:\n  - id: s\n    type: smtp\n    host: smtp.example.com\n    port: 587\n"
        "    from: radar@example.com\n    to: ops@example.com\n    username: u\n    password: p\n"
        "    use_tls: true\n",
    }
    for name, body in configs.items():
        path = tmp_path / f"{name}.yml"
        state = tmp_path / f"{name}.json"
        path.write_text(body + f"state_path: {state}\n")
        cfg = load_config(path, {})
        assert build_plugins(cfg, {}) is not None, name


def test_a_delivered_webhook_entry_leaves_the_inbox(tmp_path):
    """Both an id-bearing and an id-less entry must be cleaned up, or the inbox grows forever."""
    from advisory_radar import core, pipeline
    from advisory_radar.config import load_config
    from advisory_radar.sources import WebhookSource
    from advisory_radar.state import load_state_document

    path = tmp_path / "c.yml"
    path.write_text(f"sources:\n  - id: wh\n    type: webhook\nnotifiers: []\nstate_path: {tmp_path}/state.json\n")
    cfg = load_config(path, {})
    state = core.new_state()
    state["webhook_inbox"] = {
        "wh": [
            {"guid": "with-id", "title": "CVE-2026-1111 fixed", "summary": "", "link": "https://v.example/a"},
            {"guid": "no-ids", "title": "routine maintenance", "summary": "", "link": "https://v.example/b"},
        ]
    }
    core.save_state(cfg.state_path, state)

    sent = []

    class Recorder:
        id = "rec"

        def send(self, entry, http):
            sent.append(entry)
            return 200

    # two passes: the first classifies and delivers, the second sees the entries claimed and drops them
    for _ in range(2):
        pipeline.run_pass(
            cfg,
            [WebhookSource("wh")],
            [Recorder()],
            http=lambda *a: (404, {}, b""),
            clock=lambda: 1_700_000_000.0,
            sleep=lambda s: None,
        )
    state = load_state_document(cfg.state_path, core.STATE_SCHEMA, "state")
    # the point is the cleanup: whatever the classification decided, the entry has been accounted for
    assert not state.get("webhook_inbox", {}).get("wh"), "a handled entry is removed from the inbox"


def test_a_non_latin1_title_is_delivered_by_ntfy():
    """An em dash in a header would fail on every retry; the JSON body carries it."""
    calls = []

    def http(method, url, headers, body):
        calls.append((url, dict(headers), body))
        return 200, {}, b""

    entry = {"title": "CRITICAL: fixed — 修正", "body": "b", "tag": "critical"}
    assert NtfyNotifier("n", "https://ntfy.example", "alerts").send(entry, http) == 200
    body = calls[0][2]
    assert isinstance(body, bytes)
    decoded = json.loads(body.decode("utf-8"))
    assert decoded["title"] == "CRITICAL: fixed — 修正"
    assert not any("Title" in name for name in calls[0][1])


def test_smtp_verifies_the_server_certificate():
    """Both TLS paths must use a validating context, or the login is handed to an interceptor."""
    import smtplib
    import ssl

    from advisory_radar.notifiers import SmtpNotifier

    init_contexts: list[object] = []
    starttls_contexts: list[object] = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None, context=None):
            init_contexts.append(context)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context=None):
            starttls_contexts.append(context)

        def ehlo(self):
            return None

        def login(self, user, password):
            return None

        def send_message(self, message):
            return None

    original_smtp, original_ssl = smtplib.SMTP, smtplib.SMTP_SSL
    smtplib.SMTP, smtplib.SMTP_SSL = FakeSMTP, FakeSMTP
    try:
        submission = SmtpNotifier("s", "h", 587, "a@example.com", ["b@example.com"], "u", "p", True, False)
        assert submission.send({"title": "t", "body": "b"}, lambda *a: (0, {}, b"")) == 200
        implicit = SmtpNotifier("s", "h", 465, "a@example.com", ["b@example.com"], "u", "p", False, True)
        assert implicit.send({"title": "t", "body": "b"}, lambda *a: (0, {}, b"")) == 200
    finally:
        smtplib.SMTP, smtplib.SMTP_SSL = original_smtp, original_ssl
    assert starttls_contexts and all(isinstance(c, ssl.SSLContext) for c in starttls_contexts), (
        "STARTTLS must be given a validating context"
    )
    assert any(isinstance(c, ssl.SSLContext) for c in init_contexts), "implicit TLS must be given a validating context"


def test_a_full_webhook_inbox_refuses_rather_than_discards(tmp_path):
    """An acknowledged, unprocessed advisory must never be dropped to make room."""

    from fastapi.testclient import TestClient

    from advisory_radar.config import load_config
    from advisory_radar.state import load_state_document
    from advisory_radar.web import create_app

    path = tmp_path / "c.yml"
    path.write_text(f"sources:\n  - id: wh\n    type: webhook\nnotifiers: []\nstate_path: {tmp_path}/state.json\n")
    cfg = load_config(path, {})
    app = create_app(
        cfg,
        {"ADVISORY_RADAR_AUTH_TOKEN": "t", "ADVISORY_RADAR_WEBHOOK_SECRET": "s"},
        sources=[WebhookSource("wh")],
    )
    client = TestClient(app)
    headers = {"Authorization": "Bearer s"}
    for index in range(500):
        response = client.post("/webhooks/wh", json={"title": f"advisory {index}"}, headers=headers)
        assert response.status_code == 200
    refused = client.post("/webhooks/wh", json={"title": "one too many"}, headers=headers)
    assert refused.status_code == 429, "a full inbox refuses the new entry"
    state = load_state_document(
        cfg.state_path, __import__("advisory_radar.core", fromlist=["STATE_SCHEMA"]).STATE_SCHEMA, "state"
    )
    inbox = state["webhook_inbox"]["wh"]
    assert len(inbox) == 500
    assert inbox[0]["title"] == "advisory 0", "the first accepted entry is still there"
