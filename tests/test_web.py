"""Web UI tests: health/metrics are open, pages need the auth cookie."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from fastapi.testclient import TestClient

from advisory_radar import core
from advisory_radar.config import load_config
from advisory_radar.state import load_state_document, save_state
from advisory_radar.web import LoginThrottle, _epoch, _when, create_app, readiness


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


def test_pages_render_timestamps_as_utc_dates(tmp_path):
    client, token = make_client(tmp_path)
    signed_in(client, token)
    for path in ("/", "/alerts", "/runs"):
        page = client.get(path).text
        assert "2026-10-21 16:26" in page, path
        assert "1792600000" not in page, f"{path} still prints the raw epoch"
    assert "First seen (UTC)" in client.get("/alerts").text
    assert "At (UTC)" in client.get("/runs").text


def test_the_time_helper_survives_a_value_it_cannot_render():
    assert _when(1792600000) == "2026-10-21 16:26"
    assert _epoch(1792600000) == 1792600000
    # A hand-edited or older state can hold any of these; a page must render rather than take the UI down.
    for unusable in (None, "never", "", float("nan"), float("inf"), 10**20, -1, True):
        assert _when(unusable) == "", repr(unusable)
        assert _epoch(unusable) is None, repr(unusable)


def test_pages_tolerate_records_that_are_not_objects_or_not_times(tmp_path):
    client, token = make_client(tmp_path)
    state = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    assert state is not None
    valid_run = {"at": 1792600000, "sent": 1, "parked": 0, "pending": 0, "code": 0}
    # A malformed entry before a valid latest one must not hide the valid one, and the record that is not an
    # object must be skipped by the alerts sort rather than raising from the comparison.
    state["runs"] = [None, "nope", valid_run]
    state["seen"]["CVE-2026-3"] = "not-an-object"
    # A timestamp outside the representable range is blank on the page, so it must not be counted as recent.
    state["seen"]["CVE-2026-4"] = {"at": 10**20, "outcome": "delivered"}
    state["seen"]["CVE-2026-5"] = {"at": int(time.time()), "outcome": "delivered"}
    save_state(tmp_path / "state.json", state)
    signed_in(client, token)

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Last pass: 2026-10-21 16:26" in dashboard.text
    assert "Seen in last 24h: <b>1</b>" in dashboard.text

    alerts = client.get("/alerts")
    assert alerts.status_code == 200
    assert "not-an-object" not in alerts.text
    assert "CVE-2026-5" in alerts.text

    runs = client.get("/runs")
    assert runs.status_code == 200 and "At (UTC)" in runs.text
    assert "None" not in runs.text and "nope" not in runs.text


def test_a_last_run_that_is_not_an_object_renders_as_never(tmp_path):
    client, token = make_client(tmp_path)
    state = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    assert state is not None
    state["runs"] = [None, "nope"]
    save_state(tmp_path / "state.json", state)
    signed_in(client, token)
    assert "Last pass: never" in client.get("/").text
    assert client.get("/runs").status_code == 200


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


def test_readyz_is_ready_just_after_a_pass(tmp_path):
    client, _ = make_client(tmp_path, clock=1792600060)  # one minute after the recorded pass
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.text == "ready"
    assert "advisory_radar_ready 1" in client.get("/metrics").text


def test_readyz_reports_a_stale_pass(tmp_path):
    # The fixture's pass is at 1792600000; inject a clock past the limit (3 x 900 s) instead of relying on the
    # wall clock being later than a fixed timestamp, which would make this test time-travel-dependent.
    client, _ = make_client(tmp_path, clock=1792600000 + 3000)
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


def test_readyz_reports_a_state_path_that_is_a_directory(tmp_path):
    """A state path that cannot be read is unreadable, not absent: the probe must still answer."""
    client, _ = make_client(tmp_path)
    (tmp_path / "state.json").unlink()
    (tmp_path / "state.json").mkdir()
    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.text.startswith("not ready:")
    assert "advisory_radar_ready 0" in client.get("/metrics").text


def test_readyz_reports_invalid_utf8(tmp_path):
    client, _ = make_client(tmp_path)
    (tmp_path / "state.json").write_bytes(b"\xff\xfe\x00")
    assert client.get("/readyz").status_code == 503
    assert "advisory_radar_state_readable 0" in client.get("/metrics").text


def test_readiness_uses_the_completion_time_not_the_start(tmp_path):
    """A pass slower than the limit must not be stale the moment it completes."""
    client, _ = make_client(tmp_path, clock=1792600000 + 400)
    state = json.loads((tmp_path / "state.json").read_text())
    state["runs"][-1]["at"] = 1792600000 - 600  # started ten minutes ago
    state["runs"][-1]["finished_at"] = 1792600000 + 390  # finished ten seconds before the clock
    (tmp_path / "state.json").write_text(json.dumps(state))
    response = client.get("/readyz")
    assert response.status_code == 200
    assert "advisory_radar_last_pass_timestamp_seconds 1792600390" in client.get("/metrics").text


def test_metrics_carry_the_watch_and_run_counts(tmp_path):
    client, _ = make_client(tmp_path, clock=1792600060)
    metrics = client.get("/metrics").text
    assert "advisory_radar_runs_retained 1" in metrics
    assert "advisory_radar_watch_total 0" in metrics
    assert "advisory_radar_last_pass_sent 1" in metrics
    assert "advisory_radar_last_pass_exit 0" in metrics


def test_readyz_treats_a_future_run_as_unready(tmp_path):
    """A replaced state file or a clock jump must not hide a stopped scheduler."""
    client, _ = make_client(tmp_path, clock=1792600000 - 600)
    response = client.get("/readyz")
    assert response.status_code == 503
    assert "in the future" in response.text


def cfg_with_interval(tmp_path: Path, interval: str):
    path = tmp_path / f"c-{interval}.yml"
    path.write_text(f"sources: []\nnotifiers: []\npoll_interval: {interval}\nstate_path: {tmp_path}/s.json\n")
    return load_config(path, {})


def test_readiness_uses_three_intervals_with_a_five_minute_floor(tmp_path):
    now = 1792600000
    state = {"runs": [{"at": now - 299, "code": 0}]}
    # a 30 s interval: 3 x 30 s would be 90 s, and the 300 s floor keeps a fast poll from flapping
    assert readiness(cfg_with_interval(tmp_path, "30s"), state, now)[0] is True
    assert readiness(cfg_with_interval(tmp_path, "30s"), {"runs": [{"at": now - 301, "code": 0}]}, now)[0] is False
    # a 15 m interval: 3 x 900 s = 2700 s, and both sides of that boundary are exact
    fifteen = cfg_with_interval(tmp_path, "15m")
    assert readiness(fifteen, {"runs": [{"at": now - 2700, "code": 0}]}, now)[0] is True
    assert readiness(fifteen, {"runs": [{"at": now - 2701, "code": 0}]}, now)[0] is False


def test_a_nan_timestamp_does_not_break_the_probe_or_the_scrape(tmp_path):
    """Python's JSON reader accepts NaN; int(nan) raises, which would turn a scrape into a 500."""
    client, _ = make_client(tmp_path)
    state = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    state["runs"] = [{"at": float("nan"), "code": 0}]
    save_state(tmp_path / "state.json", state)
    assert client.get("/readyz").status_code == 503  # no usable timestamp is not readiness
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "advisory_radar_last_pass_timestamp_seconds 0" in metrics.text


def test_metrics_still_answer_when_the_state_is_unreadable(tmp_path):
    """The documented alert is `advisory_radar_ready == 0`; a failed scrape would produce no sample at all."""
    client, _ = make_client(tmp_path)
    (tmp_path / "state.json").write_text("{not json")
    assert client.get("/healthz").status_code == 200  # liveness stays independent of the state
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "advisory_radar_ready 0" in response.text
    assert "advisory_radar_state_readable 0" in response.text
    assert "advisory_radar_pending" not in response.text  # unknown, not zero


def test_metrics_report_a_readable_state(tmp_path):
    client, _ = make_client(tmp_path)
    assert "advisory_radar_state_readable 1" in client.get("/metrics").text


def test_a_malformed_runs_value_does_not_break_the_probe_or_the_scrape(tmp_path):
    """A hand-edited document can put anything under `runs`; both endpoints must still answer."""
    client, _ = make_client(tmp_path)
    state = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    state["runs"] = {"at": 1, "code": 0}  # a mapping, not a list
    save_state(tmp_path / "state.json", state)
    assert client.get("/readyz").status_code == 503
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "advisory_radar_last_pass_exit -1" in metrics.text


def test_a_malformed_collection_does_not_break_the_scrape(tmp_path):
    client, _ = make_client(tmp_path)
    state = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    state["watch"] = None
    state["seen"] = None
    state["pending"] = None
    save_state(tmp_path / "state.json", state)
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "advisory_radar_watch_total 0" in metrics.text
    assert "advisory_radar_pending 0" in metrics.text
