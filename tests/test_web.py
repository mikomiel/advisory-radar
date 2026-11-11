"""Web UI tests: health/metrics are open, pages need the auth cookie."""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from advisory_radar import core
from advisory_radar.config import load_config
from advisory_radar.http import RedactFilter
from advisory_radar.runtime import Runtime
from advisory_radar.settings import load_settings, load_settings_document, save_settings, settings_path
from advisory_radar.state import load_state_document, save_state, state_lock
from advisory_radar.web import LoginThrottle, _epoch, _when, create_app, readiness

LOG = logging.getLogger("advisory_radar")


@pytest.fixture(autouse=True)
def _detach_log_redaction():
    """A runtime installs a log filter; one test's secrets must not redact the next test's output."""
    yield
    for installed in list(LOG.filters):
        if isinstance(installed, RedactFilter):
            LOG.removeFilter(installed)


def make_app_client(
    tmp_path: Path,
    token: str = "secret-token",
    clock: float | None = None,
    environment: dict[str, str] | None = None,
):
    """A signed-out client, its token and the runtime the app serves."""
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path}/state.json\nweb:\n  port: 8080\n")
    env = {"ADVISORY_RADAR_AUTH_TOKEN": token, **(environment or {})}
    runtime = Runtime.build(cfg_path, env, clock=(lambda: clock) if clock else time.time)
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
    save_state(runtime.cfg.state_path, state)
    app = create_app(runtime, env, clock=(lambda: clock) if clock else time.time)
    return TestClient(app), token, runtime


def make_client(tmp_path: Path, token: str = "secret-token", clock: float | None = None):
    client, token, _ = make_app_client(tmp_path, token, clock)
    return client, token


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
    assert "<span class='stat-label'>Pending</span><span class='stat-value'>1</span>" in dashboard.text
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
    # Replace the fixture's seen map rather than adding to it: the expected count must not depend on when the
    # suite happens to run, and the fixture's 2026-10-21 timestamp is inside 24h on an earlier wall clock.
    state["seen"] = {
        "CVE-2026-3": "not-an-object",
        # A timestamp outside the representable range is blank on the page, so it must not be counted as recent.
        "CVE-2026-4": {"at": 10**20, "outcome": "delivered"},
        # A string timestamp inside an object reaches the same sort key as the integers: mixed types must not raise.
        "CVE-2026-6": {"at": "yesterday", "outcome": "delivered"},
        "CVE-2026-5": {"at": int(time.time()), "outcome": "delivered"},
    }
    save_state(tmp_path / "state.json", state)
    signed_in(client, token)

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Last pass: 2026-10-21 16:26" in dashboard.text
    assert "<span class='stat-label'>Seen in last 24h</span><span class='stat-value'>1</span>" in dashboard.text

    alerts = client.get("/alerts")
    assert alerts.status_code == 200
    assert "not-an-object" not in alerts.text
    assert "yesterday" not in alerts.text  # unreadable time renders blank, it is not copied into the table
    assert "CVE-2026-5" in alerts.text and "CVE-2026-6" in alerts.text

    runs = client.get("/runs")
    assert runs.status_code == 200 and "At (UTC)" in runs.text
    assert "2026-10-21 16:26" in runs.text
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


FINGERPRINT_RE = re.compile(r"name='fingerprint' value='([0-9a-f]{64})'")
NOW = 1792600000
PREDICATE_CONFIG = """\
sources:
  - id: nodejs
    type: rss
    url: https://feeds.example.net/nodejs.xml
    thresholds: {critical_cvss: 7.0}
notifiers:
  - id: ops
    type: ntfy
    url: ${OPS_HOOK}
    topic: advisories
  - id: phone
    type: ntfy
    url: ${PHONE_HOOK}
    topic: alerts
routes:
  - match: {min_cvss: 9.5, epss_gte: 0.3, kev: true}
    notifiers: [phone]
default: [ops]
"""
PREDICATE_ENV = {"OPS_HOOK": "https://ntfy.example.net/OPS", "PHONE_HOOK": "https://ntfy.example.net/PHONE"}


def predicate_client(tmp_path: Path, token: str = "secret-token"):
    """A signed-out client over a configuration with a source block and a predicate route."""
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(f"{PREDICATE_CONFIG}state_path: {tmp_path}/state.json\n")
    env = {"ADVISORY_RADAR_AUTH_TOKEN": token, **PREDICATE_ENV}
    runtime = Runtime.build(cfg_path, env, clock=lambda: float(NOW))
    save_state(runtime.cfg.state_path, core.new_state())
    app = create_app(runtime, env, clock=lambda: float(NOW))
    return TestClient(app), token, runtime


def config_form(client, token: str) -> tuple[str, str]:
    """Log in, load /config and return its form token and the fingerprint of the configuration it renders."""
    csrf = signed_in(client, token)
    page = client.get("/config").text
    match = FINGERPRINT_RE.search(page)
    assert match, "every settings form must carry the configuration fingerprint"
    return csrf, match.group(1)


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
    environment = {"ADVISORY_RADAR_AUTH_TOKEN": "t", "ADVISORY_RADAR_PUBLIC_HTTPS": "1"}
    app = create_app(Runtime.build(cfg_path, environment), environment)
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


# --- the settings overlay: /config, its POSTs and /reload -------------------------------------


def test_two_saved_notifiers_survive_while_the_application_is_blocked(tmp_path):
    client, token, runtime = make_app_client(tmp_path, environment={"HOOK": "https://hooks.example.net/x"})
    with state_lock(runtime.cfg.state_path):  # a pass holds the lock, so neither save can be applied
        csrf, fingerprint = config_form(client, token)
        first = client.post(
            "/config/notifiers",
            data={
                "csrf": csrf,
                "fingerprint": fingerprint,
                "new:id": "first",
                "new:type": "ntfy",
                "new:reference": "${HOOK}",
                "new:topic": "advisories",
            },
            follow_redirects=False,
        )
        assert first.status_code == 303
        # the redirect reloads the page: the second save carries the revision the first one produced
        csrf, fingerprint = config_form(client, token)
        second = client.post(
            "/config/notifiers",
            data={
                "csrf": csrf,
                "fingerprint": fingerprint,
                # the page re-rendered the first notifier's row; a browser submits those fields too
                "enabled:first": "1",
                "field:first:topic": "advisories",
                "new:id": "second",
                "new:type": "ntfy",
                "new:reference": "${HOOK}",
                "new:topic": "alerts",
            },
            follow_redirects=False,
        )
        assert second.status_code == 303
    overlay = load_settings(settings_path(runtime.cfg.state_path))
    assert [(entry["id"], entry.get("enabled", True), entry["topic"]) for entry in overlay["notifiers"]] == [
        ("first", True, "advisories"),
        ("second", True, "alerts"),
    ], "the second save must not disable or strip the first notifier"
    runtime.reload(blocking=False)
    assert [notifier.id for notifier in runtime.notifiers] == ["first", "second"]


def test_a_yaml_notifier_with_headers_can_still_be_edited_from_the_form(tmp_path):
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(
        "sources: []\nnotifiers:\n  - id: hook\n    type: webhook\n    url: ${HOOK}\n"
        "    headers:\n      Authorization: Bearer ${TOKEN}\n"
        f"state_path: {tmp_path}/state.json\n"
    )
    environment = {
        "ADVISORY_RADAR_AUTH_TOKEN": "t",
        "HOOK": "https://hooks.example.net/x",
        "TOKEN": "tok",
    }
    runtime = Runtime.build(cfg_path, environment)
    client = TestClient(create_app(runtime, environment))
    csrf, fingerprint = config_form(client, "t")
    response = client.post(
        "/config/notifiers",
        data={"csrf": csrf, "fingerprint": fingerprint, "field:hook:url": "${HOOK}"},
        follow_redirects=False,
    )
    assert response.status_code == 303, "the YAML headers must not make every notifier save fail"
    saved = load_settings(settings_path(runtime.cfg.state_path))
    assert "headers" not in saved["notifiers"][0], "the overlay never stores a header mapping"
    assert saved["notifiers"][0].get("enabled") is False, "the form did not submit the enable checkbox"
    assert runtime.notifiers == [], "the disabled notifier is gone from the live runtime"
    from advisory_radar.config import load_document

    merged = load_document(cfg_path, settings=saved)
    assert merged["notifiers"][0]["headers"] == {"Authorization": "Bearer ${TOKEN}"}, (
        "the YAML headers must still reach the builder"
    )


def test_a_failing_reference_does_not_echo_the_environment_value(tmp_path, caplog):
    # A *_FILE variable can wrongly hold the credential itself; the expansion error names the variable, and
    # must not print what it held, on the page or in a SIGHUP log.
    from advisory_radar import cli

    secret = "https://hooks.example.net/SUPERSECRET-FROM-ENV"
    client, token, runtime = make_app_client(tmp_path, environment={"HOOK_FILE": secret})
    csrf, fingerprint = config_form(client, token)
    response = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:id": "hook",
            "new:type": "webhook",
            "new:reference": "${HOOK_FILE}",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "no readable file" in response.text
    assert "SUPERSECRET-FROM-ENV" not in response.text
    save_settings(
        settings_path(runtime.cfg.state_path),
        {"notifiers": [{"id": "hook", "type": "webhook", "url": "${HOOK_FILE}"}]},
        now=1,
    )
    try:
        with caplog.at_level(logging.ERROR, logger="advisory_radar"):
            cli._reload_blocking(runtime)
        assert "no readable file" in caplog.text
        assert "SUPERSECRET-FROM-ENV" not in caplog.text
    finally:
        runtime.detach_redaction()


def test_an_omitted_optional_notifier_field_can_be_set_cleared_and_restored(tmp_path):
    client, token, runtime = make_app_client(tmp_path, environment={"HOOK": "https://ntfy.example.net/x"})
    csrf, fingerprint = config_form(client, token)
    added = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:id": "phone",
            "new:type": "ntfy",
            "new:reference": "${HOOK}",
            "new:topic": "advisories",
        },
        follow_redirects=False,
    )
    assert added.status_code == 303
    page = client.get("/config").text
    assert "name='field:phone:priority'" in page, "a defaulted field must still be offered"
    csrf, fingerprint = config_form(client, token)
    set_priority = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "enabled:phone": "1",
            "field:phone:topic": "advisories",
            "field:phone:priority": "4",
        },
        follow_redirects=False,
    )
    assert set_priority.status_code == 303
    assert runtime.notifiers[0].priority == 4
    csrf, fingerprint = config_form(client, token)
    cleared = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "enabled:phone": "1",
            "field:phone:topic": "advisories",
        },
        follow_redirects=False,
    )
    assert cleared.status_code == 303
    assert "name='field:phone:priority'" in client.get("/config").text, "a cleared field must stay editable"
    csrf, fingerprint = config_form(client, token)
    restored = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "enabled:phone": "1",
            "field:phone:topic": "advisories",
            "field:phone:priority": "2",
        },
        follow_redirects=False,
    )
    assert restored.status_code == 303
    assert runtime.notifiers[0].priority == 2


def test_a_stale_notifier_form_is_refused(tmp_path):
    # Two tabs opened before either save: the second one would rewrite the whole list from rows that do not
    # know about the first save, disabling it and dropping its fields. The revision it carries is the check.
    client, token, runtime = make_app_client(tmp_path, environment={"HOOK": "https://hooks.example.net/x"})
    csrf, stale_fingerprint = config_form(client, token)
    first = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": stale_fingerprint,
            "new:id": "first",
            "new:type": "ntfy",
            "new:reference": "${HOOK}",
            "new:topic": "advisories",
        },
        follow_redirects=False,
    )
    assert first.status_code == 303
    stale = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": stale_fingerprint,
            "new:id": "second",
            "new:type": "ntfy",
            "new:reference": "${HOOK}",
            "new:topic": "alerts",
        },
        follow_redirects=False,
    )
    assert stale.status_code == 409
    overlay = load_settings(settings_path(runtime.cfg.state_path))
    assert [entry["id"] for entry in overlay["notifiers"]] == ["first"], "a stale form must not rewrite the list"
    assert overlay["notifiers"][0].get("enabled", True) is True
    assert overlay["notifiers"][0]["topic"] == "advisories"


def test_a_form_from_a_recreated_overlay_is_refused(tmp_path):
    client, token, runtime = make_app_client(tmp_path, environment={"HOOK": "https://hooks.example.net/x"})
    csrf, fingerprint = config_form(client, token)
    first = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:id": "first",
            "new:type": "ntfy",
            "new:reference": "${HOOK}",
            "new:topic": "advisories",
        },
        follow_redirects=False,
    )
    assert first.status_code == 303
    csrf, old_fingerprint = config_form(client, token)  # the tab that stays open at revision 1
    settings_path(runtime.cfg.state_path).unlink()
    assert client.post("/reload", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    csrf, fingerprint = config_form(client, token)  # a new overlay, also revision 1
    second = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:id": "second",
            "new:type": "ntfy",
            "new:reference": "${HOOK}",
            "new:topic": "alerts",
        },
        follow_redirects=False,
    )
    assert second.status_code == 303
    stale = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": old_fingerprint,
            "new:id": "first",
            "new:type": "ntfy",
            "new:reference": "${HOOK}",
            "new:topic": "advisories",
        },
        follow_redirects=False,
    )
    assert stale.status_code == 409, "a reused revision number must not validate the old form"
    overlay = load_settings(settings_path(runtime.cfg.state_path))
    assert [entry["id"] for entry in overlay["notifiers"]] == ["second"]
    assert overlay["notifiers"][0].get("enabled", True) is True


def test_a_form_is_refused_after_the_yaml_changed(tmp_path):
    client, token, runtime = make_app_client(tmp_path)
    csrf, fingerprint = config_form(client, token)
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(
        cfg_path.read_text().replace(
            "sources: []",
            "sources:\n  - id: added\n    type: rss\n    url: https://feeds.example.net/x.xml",
        )
    )
    stale = client.post("/config/sources", data={"csrf": csrf, "fingerprint": fingerprint}, follow_redirects=False)
    assert stale.status_code == 409, "the form never saw the source the YAML now defines"
    assert not settings_path(runtime.cfg.state_path).exists()


def test_deleting_the_overlay_file_is_reported_as_not_live(tmp_path):
    client, token, runtime = make_app_client(tmp_path)
    csrf, fingerprint = config_form(client, token)
    saved = client.post(
        "/config/settings",
        data={"csrf": csrf, "fingerprint": fingerprint, "poll_interval": "30s"},
        follow_redirects=False,
    )
    assert saved.status_code == 303
    assert runtime.cfg.poll_interval_seconds == 30, "with the lock free the save is live at once"
    settings_path(runtime.cfg.state_path).unlink()
    page = client.get("/config").text
    assert "no overlay file" in page and "Reload to return to the YAML" in page
    # The page advertises that Reload returns to the YAML; the advertised action has to work, so a missing
    # overlay is applied as revision 0 rather than refused as an older revision.
    reloaded = client.post("/reload", data={"csrf": csrf}, follow_redirects=False)
    assert reloaded.status_code == 303
    assert runtime.cfg.poll_interval_seconds == 900, "the reload must fall back to the YAML configuration"


def test_the_config_page_and_its_posts_require_auth(tmp_path):
    client, _ = make_client(tmp_path)
    response = client.get("/config", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    # without a session a POST redirects to the login page and writes nothing
    assert client.post("/config/settings", data={"poll_interval": "30s"}, follow_redirects=False).status_code == 303
    assert not settings_path(tmp_path / "state.json").exists()


def test_a_config_post_needs_the_form_token(tmp_path):
    client, token, runtime = make_app_client(tmp_path)
    signed_in(client, token)
    assert client.post("/config/settings", data={"poll_interval": "30s"}).status_code == 403
    assert client.post("/reload").status_code == 403
    assert runtime.cfg.poll_interval_seconds == 900
    assert not settings_path(runtime.cfg.state_path).exists()


def test_a_refused_setting_renders_the_error_and_writes_nothing(tmp_path):
    client, token, runtime = make_app_client(tmp_path)
    csrf, fingerprint = config_form(client, token)
    response = client.post(
        "/config/settings",
        data={"csrf": csrf, "fingerprint": fingerprint, "poll_interval": "banana", "hidden_source_hosts": ""},
    )
    assert response.status_code == 400
    assert "poll_interval must look like 15m, 30s or 12h" in response.text
    assert not settings_path(runtime.cfg.state_path).exists()
    assert runtime.cfg.poll_interval_seconds == 900


def test_a_saved_setting_is_live_after_the_post(tmp_path):
    client, token, runtime = make_app_client(tmp_path, clock=1792600000.0)
    csrf, fingerprint = config_form(client, token)
    response = client.post(
        "/config/settings",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "poll_interval": "30s",
            "hidden_source_hosts": "internal.example.com\necho.example.net",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/config?saved=1"
    assert runtime.cfg.poll_interval_seconds == 30
    assert runtime.cfg.hidden_source_hosts == frozenset({"internal.example.com", "echo.example.net"})
    assert load_settings_document(settings_path(runtime.cfg.state_path))["revision"] == 1
    state = load_state_document(runtime.cfg.state_path, core.STATE_SCHEMA, "advisory state")
    assert state["settings"]["revision"] == 1
    assert state["settings"]["applied_at"] == 1792600000
    assert len(state["settings"]["fingerprint"]) == 64
    # the next pass reads this snapshot, which already carries the saved value
    cfg, _, _ = runtime.snapshot()
    assert cfg.poll_interval_seconds == 30
    page = client.get("/config?saved=1").text
    assert "saved and live" in page
    assert "last applied" in page


def test_a_saved_but_unapplied_setting_is_not_reported_live(tmp_path):
    client, token, runtime = make_app_client(tmp_path)
    csrf, fingerprint = config_form(client, token)
    with state_lock(runtime.cfg.state_path):  # a pass holds the lock for its whole transaction
        response = client.post(
            "/config/settings",
            data={"csrf": csrf, "fingerprint": fingerprint, "poll_interval": "30s"},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert runtime.cfg.poll_interval_seconds == 900, "the live configuration must not change"
    assert load_settings(settings_path(runtime.cfg.state_path)) == {
        "poll_interval": "30s",
        "hidden_source_hosts": [],
    }
    page = client.get("/config?saved=1").text
    assert "not live yet" in page
    assert "saved and live" not in page


def test_reload_refuses_with_409_while_a_pass_holds_the_lock(tmp_path):
    client, token, runtime = make_app_client(tmp_path)
    csrf = signed_in(client, token)
    with state_lock(runtime.cfg.state_path):
        response = client.post("/reload", data={"csrf": csrf})
    assert response.status_code == 409
    assert "A pass or another reload is running" in response.text


def test_reload_applies_a_saved_overlay(tmp_path):
    client, token, runtime = make_app_client(tmp_path, clock=1792600000.0)
    csrf = signed_in(client, token)
    save_settings(settings_path(runtime.cfg.state_path), {"poll_interval": "12h"}, now=1)
    assert runtime.cfg.poll_interval_seconds == 900
    response = client.post("/reload", data={"csrf": csrf}, follow_redirects=False)
    assert response.status_code == 303
    assert runtime.cfg.poll_interval_seconds == 12 * 3600
    state = load_state_document(runtime.cfg.state_path, core.STATE_SCHEMA, "advisory state")
    assert state["settings"]["revision"] == 1
    assert state["settings"]["applied_at"] == 1792600000
    assert len(state["settings"]["fingerprint"]) == 64


def test_a_refused_reload_keeps_the_running_configuration(tmp_path):
    client, token, runtime = make_app_client(tmp_path)
    csrf = signed_in(client, token)
    overlay = settings_path(runtime.cfg.state_path)
    overlay.write_text(
        json.dumps(
            {
                "schema": "advisory-radar-settings.v1",
                "revision": 4,
                "updated_at": 0,
                "settings": {"poll_interval": "banana"},
            }
        )
    )
    response = client.post("/reload", data={"csrf": csrf})
    assert response.status_code == 400
    assert "poll_interval must look like 15m, 30s or 12h" in response.text
    assert runtime.cfg.poll_interval_seconds == 900
    assert load_settings(overlay) == {"poll_interval": "banana"}, "the file is left for the operator"


def test_a_source_disabled_on_the_form_is_gone_from_the_next_pass(tmp_path):
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(
        "sources:\n  - id: one\n    type: rss\n    url: https://feeds.example.com/one.xml\n"
        "  - id: two\n    type: rss\n    url: https://feeds.example.com/two.xml\n"
        f"notifiers: []\nstate_path: {tmp_path}/state.json\n"
    )
    environment = {"ADVISORY_RADAR_AUTH_TOKEN": "t"}
    runtime = Runtime.build(cfg_path, environment)
    client = TestClient(create_app(runtime, environment))
    csrf, fingerprint = config_form(client, "t")
    response = client.post(
        "/config/sources",
        data={"csrf": csrf, "fingerprint": fingerprint, "enabled:two": "1", "tag:one": "", "tag:two": "security"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert [source.id for source in runtime.sources] == ["two"]
    sources = runtime.document["sources"]
    assert sources[0]["enabled"] is False
    assert sources[1]["tag"] == "security"


def test_a_notifier_added_on_the_form_keeps_a_reference_and_live_value(tmp_path):
    client, token, runtime = make_app_client(tmp_path, environment={"OPS_HOOK": "https://ntfy.example.com/OPS-TOPIC"})
    csrf, fingerprint = config_form(client, token)
    response = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:id": "ops",
            "new:type": "ntfy",
            "new:reference": "${OPS_HOOK}",
            "new:topic": "alerts",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert [notifier.id for notifier in runtime.notifiers] == ["ops"]
    assert runtime.notifiers[0].url == "https://ntfy.example.com/OPS-TOPIC"
    overlay = settings_path(runtime.cfg.state_path)
    assert load_settings(overlay) == {
        "notifiers": [{"id": "ops", "type": "ntfy", "url": "${OPS_HOOK}", "topic": "alerts"}]
    }
    assert "ntfy.example.com/OPS-TOPIC" not in overlay.read_text()


def test_editing_a_notifier_keeps_its_reference_and_never_stores_the_value(tmp_path):
    secret = "https://hooks.example.com/SUPERSECRET"
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(
        "sources: []\nnotifiers:\n  - id: hook\n    type: discord_webhook\n    url: ${HOOK_URL}\n"
        f"state_path: {tmp_path}/state.json\n"
    )
    environment = {"ADVISORY_RADAR_AUTH_TOKEN": "t", "HOOK_URL": secret}
    runtime = Runtime.build(cfg_path, environment)
    client = TestClient(create_app(runtime, environment))
    csrf, fingerprint = config_form(client, "t")
    response = client.post(
        "/config/notifiers",
        data={"csrf": csrf, "fingerprint": fingerprint, "enabled:hook": "1"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert [notifier.id for notifier in runtime.notifiers] == ["hook"]
    overlay = settings_path(runtime.cfg.state_path).read_text()
    assert "${HOOK_URL}" in overlay and "SUPERSECRET" not in overlay
    page = client.get("/config").text
    assert "${HOOK_URL}" in page and "SUPERSECRET" not in page


def test_no_secret_value_reaches_the_config_page_or_a_log_line(tmp_path, caplog):
    secret = "https://hooks.example.com/SUPERSECRET-WEBHOOK"
    cfg_path = tmp_path / "config.yml"
    cfg_path.write_text(
        "sources:\n  - id: feed\n    type: rss\n"
        "    url: https://user:pw@feeds.example.com/private/SECRET123/rss?token=SECRET456\n"
        "notifiers:\n  - id: hook\n    type: discord_webhook\n    url: ${HOOK_URL}\n"
        f"state_path: {tmp_path}/state.json\n"
    )
    environment = {"ADVISORY_RADAR_AUTH_TOKEN": "t", "HOOK_URL": secret}
    runtime = Runtime.build(cfg_path, environment)
    client = TestClient(create_app(runtime, environment))
    csrf, fingerprint = config_form(client, "t")
    page = client.get("/config").text
    assert "SUPERSECRET-WEBHOOK" not in page
    assert "SECRET123" not in page and "SECRET456" not in page and "pw@" not in page
    assert "feeds.example.com" in page, "the public origin is still shown"
    assert "${HOOK_URL}" in page, "the reference name is not a secret"
    # a literal typed into the reference field is refused and never echoed
    response = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:id": "extra",
            "new:type": "discord_webhook",
            "new:reference": secret,
        },
    )
    assert response.status_code == 400
    assert "SUPERSECRET-WEBHOOK" not in response.text
    # a hand-edited overlay whose builder error carries an expanded value is redacted on the page and in the log
    settings_path(runtime.cfg.state_path).write_text(
        json.dumps(
            {
                "schema": "advisory-radar-settings.v1",
                "revision": 2,
                "updated_at": 0,
                "settings": {
                    "notifiers": [
                        {
                            "id": "n",
                            "type": "ntfy",
                            "url": "${HOOK_URL}",
                            "topic": "x",
                            "priority": "${HOOK_URL}",
                        }
                    ]
                },
            }
        )
    )
    with caplog.at_level(logging.DEBUG):
        refused = client.post("/reload", data={"csrf": csrf})
    assert refused.status_code == 400
    assert "SUPERSECRET-WEBHOOK" not in refused.text
    assert "SUPERSECRET-WEBHOOK" not in caplog.text


# --- the route predicates on the form and in the preview ---------------------------------------


def test_the_routes_form_renders_and_saves_the_three_predicates(tmp_path):
    client, token, runtime = predicate_client(tmp_path)
    csrf, fingerprint = config_form(client, token)
    page = client.get("/config").text
    assert "name='route:1:min_cvss' size='4' value='9.5'" in page
    assert "name='route:1:epss_gte' size='4' value='0.3'" in page
    assert "name='route:1:kev'" in page and "value='true' selected" in page, "the boolean is prefilled"

    saved = client.post(
        "/config/routes",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "route:1:min_cvss": "8.0",
            "route:1:epss_gte": "0.2",
            "route:1:kev": "false",
            "route:1:notifiers": ["phone"],
            "default": ["ops"],
        },
        follow_redirects=False,
    )

    assert saved.status_code == 303
    assert runtime.cfg.routes == ({"match": {"min_cvss": 8.0, "epss_gte": 0.2, "kev": False}, "notifiers": ("phone",)},)
    overlay = load_settings(settings_path(runtime.cfg.state_path))
    assert overlay["routes"][0]["match"] == {"min_cvss": 8.0, "epss_gte": 0.2, "kev": False}, (
        "the numbers are stored as numbers, so the next load judges them as the validator expects"
    )


def test_a_predicate_alone_is_a_rule(tmp_path):
    client, token, runtime = predicate_client(tmp_path)
    csrf, fingerprint = config_form(client, token)

    saved = client.post(
        "/config/routes",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "route:1:kev": "true",
            "route:1:notifiers": ["phone"],
            "default": ["ops"],
        },
        follow_redirects=False,
    )

    assert saved.status_code == 303
    assert runtime.cfg.routes == ({"match": {"kev": True}, "notifiers": ("phone",)},)


def test_a_refused_predicate_writes_nothing(tmp_path):
    client, token, runtime = predicate_client(tmp_path)
    csrf, fingerprint = config_form(client, token)

    refused = client.post(
        "/config/routes",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "route:1:min_cvss": "11",
            "route:1:notifiers": ["phone"],
        },
        follow_redirects=False,
    )

    assert refused.status_code == 400
    assert "match.min_cvss must be above 0 and at most 10" in refused.text
    assert not (tmp_path / "settings.json").exists()
    assert runtime.cfg.routes[0]["match"]["min_cvss"] == 9.5, "the running configuration is unchanged"


def test_the_preview_predicts_a_numeric_and_kev_predicate(tmp_path):
    client, token, _ = predicate_client(tmp_path)
    signed_in(client, token)

    matched = client.get(
        "/thresholds",
        params={"preview": "1", "cvss": "9.8", "epss": "0.4", "kev": "yes", "ids": "CVE-2026-1234"},
    ).text
    assert "Routing:" in matched and "route 1" in matched and "phone" in matched
    assert "overrides the global block" not in matched, "no source was previewed, so the global block applies"

    # Each predicate has to be satisfied by what the message measured, and one missing value is enough.
    for query in (
        {"cvss": "9.0", "epss": "0.4", "kev": "yes"},  # below min_cvss
        {"cvss": "9.8", "kev": "yes"},  # no EPSS was typed
        {"cvss": "9.8", "epss": "0.4", "kev": "unknown"},  # membership not measured
        {"cvss": "9.8", "epss": "0.4"},  # not in KEV, so kev: true fails
    ):
        page = client.get("/thresholds", params={"preview": "1", "ids": "CVE-2026-1234", **query}).text
        assert "Routing: <b>default</b>" in page or "cannot be predicted" in page, query


def test_the_preview_attributes_a_measured_score_to_a_cve_only(tmp_path):
    """The queue entry is scored per CVE, so a GHSA id stands for no measurement at all."""
    client, token, _ = predicate_client(tmp_path)
    signed_in(client, token)

    # A lower-case id is the same CVE: the classifier's pattern is case-insensitive, and so is this one.
    predicted = client.get(
        "/thresholds",
        params={"preview": "1", "cvss": "9.8", "epss": "0.4", "kev": "yes", "ids": "cve-2026-1234"},
    ).text
    assert "Routing:" in predicted and "route 1" in predicted and "phone" in predicted

    for identifier in ("GHSA-aaaa-bbbb-cccc", "", "CVE-26-1"):
        params = {"preview": "1", "cvss": "9.8", "epss": "0.4", "kev": "yes"}
        if identifier:
            params["ids"] = identifier
        page = client.get("/thresholds", params=params).text
        assert "Routing:" not in page, identifier
        assert "cannot be predicted" in page and "CVE id" in page, identifier
        assert "an advisory-level score is not a CVE measurement" in page, identifier


def test_the_preview_will_not_predict_a_kev_rule_against_an_unknown_catalogue(tmp_path):
    client, token, _ = predicate_client(tmp_path)
    signed_in(client, token)

    page = client.get(
        "/thresholds",
        params={"preview": "1", "cvss": "9.8", "epss": "0.4", "kev": "unknown", "ids": "CVE-2026-1234"},
    ).text

    assert "Routing:" not in page
    assert "matches on KEV membership" in page and "cannot be predicted" in page


def test_a_kev_value_that_is_not_a_boolean_is_refused(tmp_path):
    """Dropping it would silently broaden the rule to every message; the validator must refuse it."""
    client, token, runtime = predicate_client(tmp_path)
    csrf, fingerprint = config_form(client, token)

    refused = client.post(
        "/config/routes",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "route:1:tag": "critical",
            "route:1:kev": "yes",
            "route:1:notifiers": ["phone"],
        },
        follow_redirects=False,
    )

    assert refused.status_code == 400
    assert "match.kev must be true or false" in refused.text
    assert not (tmp_path / "settings.json").exists()
    assert runtime.cfg.routes[0]["match"]["kev"] is True, "the running rules are unchanged"


def test_a_legacy_identity_utf8_cannot_encode_still_renders_the_alerts_page(tmp_path):
    """One record written before identities were normalised must not turn the whole page into a 500."""
    client, token = make_client(tmp_path)
    path = tmp_path / "state.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["seen"]["src:test:x\ud800y"] = {"at": 1792600000, "outcome": "delivered"}
    path.write_text(json.dumps(state), encoding="utf-8")
    signed_in(client, token)
    assert client.get("/alerts").status_code == 200
    # The API returns the document itself, so it has to survive the same record: the value is preserved and
    # only its JSON spelling is escaped.
    assert client.get("/api/state").status_code == 200
