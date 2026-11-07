"""Web UI tests: health/metrics are open, pages need the auth cookie."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from advisory_radar import core
from advisory_radar.config import load_config
from advisory_radar.state import save_state
from advisory_radar.web import create_app


def make_client(tmp_path: Path, token: str = "secret-token", clock: float | None = None):
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path}/state.json\nweb:\n  port: 8080\n")
    cfg = load_config(cfg_path, {})
    state = core.new_state()
    state["seen"]["CVE-2026-1"] = {"at": 1792600000, "outcome": "delivered"}
    state["pending"].append(
        {
            "kind": "new",
            "tag": "warning",
            "title": "T",
            "body": "b",
            "ids": ["CVE-2026-2"],
            "cves": [],
            "levels": {},
            "source": "s",
            "link": "",
        }
    )
    state.setdefault("runs", []).append({"at": 1792600000, "sent": 1, "parked": 0, "pending": 1, "code": 0})
    save_state(cfg.state_path, state)
    app = create_app(cfg, {"ADVISORY_RADAR_AUTH_TOKEN": token}, clock=(lambda: clock) if clock else time.time)
    return TestClient(app), token


def test_healthz_and_metrics_open(tmp_path):
    client, _ = make_client(tmp_path)
    assert client.get("/healthz").text == "ok"
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "advisory_radar_pending 1" in metrics.text
    assert "advisory_radar_seen_total 1" in metrics.text


def test_pages_require_auth(tmp_path):
    client, _ = make_client(tmp_path)
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303 and "/login" in response.headers["location"]
    assert client.get("/api/state").status_code == 401


def test_login_and_dashboard(tmp_path):
    client, token = make_client(tmp_path)
    response = client.post("/login", data={"token": token}, follow_redirects=False)
    assert response.status_code == 303
    cookie = response.cookies.get("advisory_radar_session")
    assert cookie
    client.cookies.set("advisory_radar_session", cookie)
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Pending: <b>1</b>" in dashboard.text
    assert client.get("/alerts").status_code == 200
    assert "CVE-2026-1" in client.get("/alerts").text
    assert client.get("/runs").status_code == 200
    assert client.get("/config").status_code == 200
    assert client.get("/api/state").status_code == 200
    # wrong token stays on the login page
    other, _ = make_client(tmp_path, token="other")
    bad = other.post("/login", data={"token": "nope"})
    assert "Wrong token" in bad.text


def test_readyz_is_ready_just_after_a_pass(tmp_path):
    client, _ = make_client(tmp_path, clock=1792600060)  # one minute after the recorded pass
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.text == "ready"
    assert "advisory_radar_ready 1" in client.get("/metrics").text


def test_readyz_reports_a_stale_pass(tmp_path):
    client, _ = make_client(tmp_path)  # real clock: the recorded pass is long past
    response = client.get("/readyz")
    assert response.status_code == 503
    assert "the last pass finished" in response.text
    metrics = client.get("/metrics").text
    assert "advisory_radar_ready 0" in metrics
    assert "advisory_radar_last_pass_timestamp_seconds 1792600000" in metrics


def test_readyz_without_a_recorded_pass(tmp_path):
    client, _ = make_client(tmp_path)
    state = core.new_state()  # a fresh instance: nothing has run yet
    save_state(tmp_path / "state.json", state)
    response = client.get("/readyz")
    assert response.status_code == 503
    assert "no pass has completed yet" in response.text


def test_readyz_reports_an_unreadable_state(tmp_path):
    client, _ = make_client(tmp_path)
    (tmp_path / "state.json").write_text("{not json")
    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.text.startswith("not ready:")


def test_metrics_carry_the_watch_and_run_counts(tmp_path):
    client, _ = make_client(tmp_path, clock=1792600060)
    metrics = client.get("/metrics").text
    assert "advisory_radar_runs_total 1" in metrics
    assert "advisory_radar_watch_total 0" in metrics
    assert "advisory_radar_last_pass_sent 1" in metrics
    assert "advisory_radar_last_pass_exit 0" in metrics
