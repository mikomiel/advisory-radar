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
    app = create_app(cfg, {"ADVISORY_RADAR_AUTH_TOKEN": "t", "ADVISORY_RADAR_WEBHOOK_SECRET": "s3cret"})
    client = TestClient(app)
    # no secret -> 401
    assert client.post("/webhooks/wh", json={"title": "x"}).status_code == 401
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
    assert ntfy_call[1].endswith("/alerts") and ntfy_call[2]["Title"] == "CRITICAL: X"
    gotify_call = next(c for c in calls if "gotify" in c[1])
    assert "token=tok" in gotify_call[1]
