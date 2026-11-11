"""P4 integration tests: changedetection.io polling, webhook intake, extra notifiers."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging

import pytest
from fastapi.testclient import TestClient

from advisory_radar.http import RedactFilter
from advisory_radar.notifiers import GotifyNotifier, MatrixWebhookNotifier, NtfyNotifier, WebhookNotifier
from advisory_radar.runtime import Runtime
from advisory_radar.sources import ChangedetectionSource, WebhookSource, webhook_item_from_payload
from advisory_radar.web import create_app

LOG = logging.getLogger("advisory_radar")


@pytest.fixture(autouse=True)
def _detach_log_redaction():
    """A runtime installs a log filter; one test's secrets must not redact the next test's output."""
    yield
    for installed in list(LOG.filters):
        if isinstance(installed, RedactFilter):
            LOG.removeFilter(installed)


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


def test_a_changedetection_response_that_is_not_valid_utf8_is_refused():
    """A watch uuid is part of an item identity; raw WTF-8 would be rewritten by the next state save."""
    source = ChangedetectionSource("cd", "https://cd.example.com", "KEY")

    def http(method, url, headers, body):
        return 200, {}, b'{"' + b"\xed\xa0\x80\xed\xb0\x80" + b'": {"last_changed": 1}}'

    with pytest.raises(RuntimeError, match="not valid UTF-8"):
        source.fetch(http, {})


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
    environment = {"ADVISORY_RADAR_AUTH_TOKEN": "t", "ADVISORY_RADAR_WEBHOOK_SECRET": "s3cret"}
    app = create_app(Runtime.build(cfg_path, environment), environment)
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


def test_a_webhook_guid_that_cannot_be_encoded_is_still_accepted(tmp_path):
    """The entry is persisted first; its guid must not then turn an accepted request into a 500."""
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(f"sources:\n  - id: wh\n    type: webhook\nnotifiers: []\nstate_path: {tmp_path}/state.json\n")
    environment = {"ADVISORY_RADAR_AUTH_TOKEN": "t", "ADVISORY_RADAR_WEBHOOK_SECRET": "s3cret"}
    app = create_app(Runtime.build(cfg_path, environment), environment)
    client = TestClient(app)
    # An escaped unpaired surrogate is valid JSON but not a Unicode scalar value, so a response that encodes it
    # verbatim fails after the entry is already on disk. The sender escapes JSON by default, as here.
    response = client.post(
        "/webhooks/wh",
        content=b'{"title": "Vendor advisory", "guid": "\\ud800legacy"}',
        headers={"Authorization": "Bearer s3cret", "Content-Type": "application/json"},
    )
    assert response.status_code == 200
    assert response.json()["queued"] == "wh:\ud800legacy"
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["webhook_inbox"]["wh"][0]["guid"] == "wh:\ud800legacy"


def test_a_webhook_body_that_is_not_valid_utf8_is_refused(tmp_path):
    """The guid is an identity; ``json.loads`` on bytes would accept WTF-8 that a save then rewrites."""
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(f"sources:\n  - id: wh\n    type: webhook\nnotifiers: []\nstate_path: {tmp_path}/state.json\n")
    environment = {"ADVISORY_RADAR_AUTH_TOKEN": "t", "ADVISORY_RADAR_WEBHOOK_SECRET": "s3cret"}
    app = create_app(Runtime.build(cfg_path, environment), environment)
    client = TestClient(app)
    response = client.post(
        "/webhooks/wh",
        content=b'{"title": "Vendor advisory", "guid": "' + b"\xed\xa0\x80\xed\xb0\x80" + b'"}',
        headers={"Authorization": "Bearer s3cret", "Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert not (tmp_path / "state.json").exists(), "a refused intake writes nothing"


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
    assert ntfy_call[1] == "https://ntfy.example" and published["title"] == "CRITICAL: X"
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
    cfg.store().save(state)

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
            return {}

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

    from advisory_radar import core
    from advisory_radar.state import load_state_document
    from advisory_radar.web import create_app

    path = tmp_path / "c.yml"
    path.write_text(f"sources:\n  - id: wh\n    type: webhook\nnotifiers: []\nstate_path: {tmp_path}/state.json\n")
    environment = {"ADVISORY_RADAR_AUTH_TOKEN": "t", "ADVISORY_RADAR_WEBHOOK_SECRET": "s"}
    runtime = Runtime.build(path, environment)
    app = create_app(runtime, environment)
    client = TestClient(app)
    headers = {"Authorization": "Bearer s"}
    for index in range(500):
        response = client.post("/webhooks/wh", json={"title": f"advisory {index}"}, headers=headers)
        assert response.status_code == 200
    refused = client.post("/webhooks/wh", json={"title": "one too many"}, headers=headers)
    assert refused.status_code == 429, "a full inbox refuses the new entry"
    state = load_state_document(runtime.cfg.state_path, core.STATE_SCHEMA, "state")
    inbox = state["webhook_inbox"]["wh"]
    assert len(inbox) == 500
    assert inbox[0]["title"] == "advisory 0", "the first accepted entry is still there"


def test_an_oversized_login_body_is_refused_before_buffering(tmp_path):
    from fastapi.testclient import TestClient

    from advisory_radar.runtime import Runtime
    from advisory_radar.web import LOGIN_BODY_LIMIT, create_app

    path = tmp_path / "c.yml"
    path.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path}/state.json\n")
    environment = {"ADVISORY_RADAR_AUTH_TOKEN": "t"}
    client = TestClient(create_app(Runtime.build(path, environment), environment))
    big = b"token=" + b"x" * (LOGIN_BODY_LIMIT + 1)
    assert client.post("/login", content=big).status_code == 413


def test_a_config_spelling_error_does_not_disable_smtp_tls(tmp_path):
    """A misspelled boolean must be rejected: silently meaning "off" would authenticate in plaintext."""
    import pytest

    from advisory_radar.config import load_config
    from advisory_radar.pipeline import build_plugins

    path = tmp_path / "c.yml"
    path.write_text(
        "sources: []\nnotifiers:\n  - id: s\n    type: smtp\n    host: h\n    from: a@example.com\n"
        "    to: b@example.com\n    use_tls: ${SMTP_TLS}\n" + f"state_path: {tmp_path}/state.json\n"
    )
    with pytest.raises((ValueError, KeyError)):
        build_plugins(load_config(path, {"SMTP_TLS": "treu"}), {"SMTP_TLS": "treu"})


def test_implicit_tls_is_a_configurable_key(tmp_path):
    from advisory_radar.config import load_config
    from advisory_radar.pipeline import build_plugins

    path = tmp_path / "c.yml"
    path.write_text(
        "sources: []\nnotifiers:\n  - id: s\n    type: smtp\n    host: h\n    port: 465\n"
        "    from: a@example.com\n    to: b@example.com\n    implicit_tls: true\n"
        + f"state_path: {tmp_path}/state.json\n"
    )
    sources, notifiers = build_plugins(load_config(path, {}), {})
    assert notifiers[0].implicit_tls is True


def test_a_partial_smtp_refusal_is_not_a_delivery():
    import smtplib

    from advisory_radar.notifiers import SmtpNotifier

    class FakeSMTP:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context=None):
            return None

        def ehlo(self):
            return None

        def login(self, user, password):
            return None

        def send_message(self, message):
            return {"refused@example.com": (550, b"no such user")}

    original = smtplib.SMTP
    smtplib.SMTP = FakeSMTP
    try:
        notifier = SmtpNotifier("s", "h", 587, "a@example.com", ["b@example.com"], None, None, True, False)
        assert notifier.send({"title": "t", "body": "b"}, lambda *a: (0, {}, b"")) == 0, (
            "a refused recipient means the alert must stay pending"
        )
    finally:
        smtplib.SMTP = original


def test_a_webhook_guid_carrying_a_newline_is_released_and_sent_once(tmp_path):
    """The inbox is released on the identity classification records, so the same entry is not re-sent."""
    from advisory_radar import core, pipeline
    from advisory_radar.config import load_config
    from advisory_radar.sources import WebhookSource
    from advisory_radar.state import load_state_document

    path = tmp_path / "c.yml"
    path.write_text(f"sources:\n  - id: wh\n    type: webhook\nnotifiers: []\nstate_path: {tmp_path}/state.json\n")
    cfg = load_config(path, {})
    state = core.new_state()
    state["webhook_inbox"] = {
        "wh": [{"guid": "a\nb", "title": "routine maintenance", "summary": "", "link": "https://v.example/b"}]
    }
    from advisory_radar.state import save_state

    save_state(cfg.state_path, state)

    sent = []

    class Recorder:
        id = "rec"

        def send(self, entry, http):
            sent.append(entry)
            return 200

    # Two passes: a second delivery would mean the inbox never recognised the claim it recorded.
    for _ in range(2):
        pipeline.run_pass(
            cfg,
            [WebhookSource("wh")],
            [Recorder()],
            http=lambda *a: (404, {}, b""),
            clock=lambda: 1_700_000_000.0,
            sleep=lambda s: None,
        )
    assert not (load_state_document(cfg.state_path, core.STATE_SCHEMA, "state").get("webhook_inbox") or {}).get("wh")
    assert len(sent) == 1, "the same inbox entry must not be classified and sent on every pass"
# --- the signed generic webhook ------------------------------------------------------------------


def webhook_payload(entry: dict) -> dict:
    """What ``WebhookNotifier`` posts, spelled out so a test can pin the exact body."""
    return {
        "title": entry["title"],
        "body": entry["body"],
        "tag": entry["tag"],
        "kind": entry["kind"],
        "ids": entry["ids"],
        "link": entry.get("link", ""),
        "source": entry.get("source", ""),
    }


def webhook_entry() -> dict:
    return {
        "title": "CRITICAL: fixed — 修正",
        "body": "\n- **Severity:** CVSS 9.8",
        "tag": "critical",
        "kind": "new",
        "ids": ["CVE-2026-1"],
        "link": "https://v.example/a",
        "source": "vendor.example",
    }


def recording_http(calls: list):
    def http(method, url, headers, body):
        calls.append((method, url, dict(headers), body))
        return 204, {}, b""

    return http


def test_a_signed_webhook_verifies_over_the_exact_posted_bytes():
    calls: list = []
    notifier = WebhookNotifier(
        "w", "https://hooks.example/x", {"X-Custom": "1"}, secret="s3cret", clock=lambda: 1_700_000_000.9
    )
    entry = webhook_entry()
    assert notifier.send(entry, recording_http(calls)) == 204
    method, url, headers, body = calls[0]
    assert (method, url) == ("POST", "https://hooks.example/x")
    assert headers["Content-Type"] == "application/json" and headers["X-Custom"] == "1"
    assert headers["X-ADR-Timestamp"] == "1700000000", "the header is the clock's whole seconds"
    # Recompute exactly as the module docstring tells a receiver to: over the bytes that were posted.
    expected = "sha256=" + hmac.new(b"s3cret", b"1700000000." + body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(headers["X-ADR-Signature"], expected)
    assert json.loads(body) == webhook_payload(entry)
    assert body == json.dumps(webhook_payload(entry)).encode(), "the signed bytes are the posted bytes"


def test_a_wrong_secret_fails_verification():
    entry = webhook_entry()
    signatures = []
    for secret in ("right-secret", "wrong-secret"):
        calls: list = []
        notifier = WebhookNotifier("w", "https://hooks.example/x", secret=secret, clock=lambda: 1_700_000_000.0)
        assert notifier.send(entry, recording_http(calls)) == 204
        signatures.append(calls[0][2])
    body = calls[0][3]
    right, wrong = signatures
    assert right["X-ADR-Signature"] != wrong["X-ADR-Signature"]
    assert hmac.compare_digest(
        right["X-ADR-Signature"],
        "sha256=" + hmac.new(b"right-secret", b"1700000000." + body, hashlib.sha256).hexdigest(),
    )
    assert not hmac.compare_digest(
        right["X-ADR-Signature"],
        "sha256=" + hmac.new(b"wrong-secret", b"1700000000." + body, hashlib.sha256).hexdigest(),
    )


def test_without_a_secret_the_request_is_unchanged():
    calls: list = []
    entry = webhook_entry()
    notifier = WebhookNotifier("w", "https://hooks.example/x", {"X-Custom": "1"})
    assert notifier.send(entry, recording_http(calls)) == 204
    _, url, headers, body = calls[0]
    assert url == "https://hooks.example/x"
    assert headers == {"Content-Type": "application/json", "X-Custom": "1"}
    assert body == json.dumps(webhook_payload(entry)).encode(), "no secret, the same bytes as before signing"


def test_the_signed_body_is_serialised_once(monkeypatch):
    """A second serialisation would be signed, and the receiver's bytes would not match it."""
    from advisory_radar import notifiers as notifier_module

    calls: list = []
    real_dumps = json.dumps
    serialisations = iter(range(100))

    def shifting_dumps(payload):
        # Each call yields different bytes, so a signature taken over a re-serialisation cannot match the body.
        return real_dumps(payload) + " " * next(serialisations)

    monkeypatch.setattr(notifier_module.json, "dumps", shifting_dumps)
    entry = webhook_entry()
    notifier = WebhookNotifier("w", "https://hooks.example/x", secret="s3cret", clock=lambda: 1_700_000_000.0)
    assert notifier.send(entry, recording_http(calls)) == 204
    headers, body = calls[0][2], calls[0][3]
    expected = "sha256=" + hmac.new(b"s3cret", b"1700000000." + body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(headers["X-ADR-Signature"], expected)
    assert json.loads(body) == webhook_payload(entry)


def test_a_configured_header_cannot_spoof_the_signature():
    calls: list = []
    notifier = WebhookNotifier(
        "w",
        "https://hooks.example/x",
        {"X-ADR-Signature": "sha256=spoofed", "x-adr-timestamp": "1"},
        secret="s3cret",
        clock=lambda: 1_700_000_000.0,
    )
    assert notifier.send(webhook_entry(), recording_http(calls)) == 204
    headers = calls[0][2]
    names = [name.lower() for name in headers]
    assert names.count("x-adr-signature") == 1 and names.count("x-adr-timestamp") == 1
    assert headers["X-ADR-Timestamp"] == "1700000000"
    assert headers["X-ADR-Signature"] != "sha256=spoofed"


def test_the_webhook_builder_carries_the_secret():
    from advisory_radar.notifiers import build_notifier

    notifier = build_notifier({"id": "w", "type": "webhook", "url": "https://hooks.example/x", "secret": "s3cret"}, {})
    assert isinstance(notifier, WebhookNotifier)
    assert notifier.secret == "s3cret"


def test_a_webhook_signing_secret_reaches_the_built_notifier(tmp_path):
    """The YAML key, the builder and the signature are one path.

    A secret that never reaches the notifier would sign nothing, so the test goes through the real builder.
    """
    from advisory_radar.config import load_config
    from advisory_radar.pipeline import build_plugins

    path = tmp_path / "c.yml"
    path.write_text(
        "sources: []\n"
        "notifiers:\n"
        "  - id: hooks\n"
        "    type: webhook\n"
        "    url: ${HOOK}\n"
        "    secret: ${SIGNING}\n"
        f"state_path: {tmp_path}/state.json\n"
    )
    environment = {"HOOK": "https://hooks.example.net/x", "SIGNING": "s3cret-value"}
    _, notifiers = build_plugins(load_config(path, environment), environment)
    notifier = notifiers[0]
    assert notifier.secret == "s3cret-value"
    calls: list = []
    assert notifier.send(webhook_entry(), recording_http(calls)) == 204
    _, url, headers, body = calls[0]
    assert url == "https://hooks.example.net/x"
    timestamp = headers["X-ADR-Timestamp"].encode("ascii")
    expected = "sha256=" + hmac.new(b"s3cret-value", timestamp + b"." + body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(headers["X-ADR-Signature"], expected)
