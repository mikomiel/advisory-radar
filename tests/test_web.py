"""Web UI tests: health/metrics are open, pages need the auth cookie."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from advisory_radar import core
from advisory_radar.config import load_config
from advisory_radar.state import load_state_document, save_state
from advisory_radar.web import LoginThrottle, create_app


def make_client(tmp_path: Path, token: str = "secret-token"):
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
    app = create_app(cfg, {"ADVISORY_RADAR_AUTH_TOKEN": token})
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


CSRF_RE = re.compile(r'name="csrf" value="([0-9a-f]{64})"')


def signed_in(client, token: str) -> str:
    """Log in and return the CSRF token the dashboard rendered."""
    response = client.post("/login", data={"token": token}, follow_redirects=False)
    assert response.status_code == 303
    client.cookies.set("advisory_radar_session", response.cookies.get("advisory_radar_session"))
    dashboard = client.get("/")
    match = CSRF_RE.search(dashboard.text)
    assert match, "an authenticated page must carry a form token"
    return match.group(1)


def test_security_headers_are_sent_with_every_response(tmp_path):
    client, _ = make_client(tmp_path)
    health = client.get("/healthz")
    assert health.headers["x-content-type-options"] == "nosniff"
    assert health.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in health.headers["content-security-policy"]
    assert "default-src 'none'" in health.headers["content-security-policy"]
    # an authenticated page holds advisories: a shared proxy must not keep it
    login = client.get("/login")
    assert login.headers["cache-control"] == "no-store"
    assert "strict-transport-security" not in health.headers  # opt-in only


def test_hsts_is_opt_in(tmp_path):
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path}/state.json\n")
    from advisory_radar.config import load_config as load

    app = create_app(load(cfg_path, {}), {"ADVISORY_RADAR_AUTH_TOKEN": "t", "ADVISORY_RADAR_PUBLIC_HTTPS": "1"})
    response = TestClient(app).get("/healthz")
    assert response.headers["strict-transport-security"] == "max-age=31536000"


def test_a_state_changing_post_needs_the_form_token(tmp_path):
    client, token = make_client(tmp_path)
    csrf = signed_in(client, token)
    refused = client.post("/run", follow_redirects=False)
    assert refused.status_code == 403
    wrong = client.post("/run", data={"csrf": "0" * 64}, follow_redirects=False)
    assert wrong.status_code == 403
    accepted = client.post("/run", data={"csrf": csrf}, follow_redirects=False)
    assert accepted.status_code == 303
    # a non-browser caller may carry the token in a header instead
    header = client.post("/parked/release", headers={"x-csrf-token": csrf}, follow_redirects=False)
    assert header.status_code == 303


def test_a_form_token_from_another_session_is_refused(tmp_path):
    client, token = make_client(tmp_path)
    csrf = signed_in(client, token)
    other, other_token = make_client(tmp_path, token="another-instance-token")
    signed_in(other, other_token)
    # the token is bound to the session cookie, not merely to the auth token
    assert client.post("/run", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    stolen = other.post("/run", data={"csrf": csrf}, follow_redirects=False)
    assert stolen.status_code == 403


def test_login_is_throttled_after_repeated_failures(tmp_path):
    client, token = make_client(tmp_path)
    for _ in range(5):
        response = client.post("/login", data={"token": "wrong"}, follow_redirects=False)
        assert response.status_code == 200
        assert "Wrong token" in response.text
    blocked = client.post("/login", data={"token": token}, follow_redirects=False)
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0
    assert "advisory_radar_session" not in blocked.cookies


def test_sign_out_clears_the_session(tmp_path):
    client, token = make_client(tmp_path)
    csrf = signed_in(client, token)
    out = client.post("/logout", data={"csrf": csrf}, follow_redirects=False)
    assert out.status_code == 303 and out.headers["location"] == "/login"
    # the instruction the browser acts on; the test client's own jar keeps a hand-set cookie, so assert the header
    cleared = out.headers["set-cookie"]
    assert "advisory_radar_session=" in cleared
    assert "Max-Age=0" in cleared
    assert "HttpOnly" in cleared


# --- the login throttle's contract (the merge review found the first version bypassable) -------------


def test_the_throttle_reflects_failures_recorded_after_an_earlier_check():
    """The endpoint checks before and after reading the body; the second check must see the first's outcome."""
    now = [1000.0]
    throttle = LoginThrottle(window=60, attempts=2, clock=lambda: now[0])
    assert throttle.refusal("peer") is None
    throttle.failed("peer")
    assert throttle.refusal("peer") is None  # one failure: still allowed
    throttle.failed("peer")
    assert throttle.refusal("peer") is not None  # the re-check refuses without waiting for the window


def test_the_throttle_forgets_every_expired_peer_not_just_the_caller():
    now = [1000.0]
    throttle = LoginThrottle(window=60, attempts=1, clock=lambda: now[0])
    throttle.failed("peer")
    assert throttle.refusal("peer") is not None
    now[0] += 61
    assert throttle.refusal("peer") is None
    assert throttle.tracked == 0  # a peer that never returns must not be remembered forever


def test_the_throttle_is_bounded_and_evicts_the_least_recent_peer():
    now = [1000.0]
    throttle = LoginThrottle(window=60, attempts=5, peers=2, clock=lambda: now[0])
    throttle.failed("a")
    throttle.failed("b")
    assert throttle.tracked == 2
    now[0] += 1
    throttle.failed("c")
    assert throttle.tracked == 2  # bounded: a rotating-address attacker cannot grow it
    assert throttle.refusal("a") is None  # the least recently failing peer is evicted, a new one is not refused


def test_a_success_clears_the_peer():
    now = [1000.0]
    throttle = LoginThrottle(window=60, attempts=2, clock=lambda: now[0])
    throttle.failed("peer")
    throttle.succeeded("peer")
    assert throttle.refusal("peer") is None
    assert throttle.tracked == 0


def test_a_non_ascii_form_token_is_refused_not_a_server_error(tmp_path):
    client, token = make_client(tmp_path)
    csrf = signed_in(client, token)
    # "%C3%A9" reached hmac.compare_digest as a str and raised TypeError before this was fixed
    assert client.post("/run", data={"csrf": "é"}, follow_redirects=False).status_code == 403
    assert client.post("/run", data={"csrf": csrf}, follow_redirects=False).status_code == 303


def test_a_refused_post_leaves_the_queue_untouched(tmp_path):
    """A rejected token must be a rejected action, not a rejected-but-executed one."""
    client, token = make_client(tmp_path)
    state = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    state["parked"] = [
        {
            "kind": "new",
            "tag": "warning",
            "title": "P",
            "body": "b",
            "ids": ["CVE-2026-3"],
            "cves": [],
            "levels": {},
            "source": "s",
            "link": "",
            "attempts": 3,
            "first_attempt_at": 1792600000,
            "parked_at": 1792600000,
        }
    ]
    save_state(tmp_path / "state.json", state)
    csrf = signed_in(client, token)
    assert client.post("/parked/release", follow_redirects=False).status_code == 403
    assert len(load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")["parked"]) == 1
    assert client.post("/parked/release", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    assert load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")["parked"] == []
