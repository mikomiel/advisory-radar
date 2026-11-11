"""The risk thresholds: the configuration block, the decision it drives, and the two pages that edit and preview it.

Behaviour, not markup: a threshold is changed the way an operator changes it, through the form the page renders,
and the effect is asserted on the decision the pass makes -- including the promise that a saved threshold
re-baselines what is already watched instead of sending the backlog out under the new numbers.
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from advisory_radar import core
from advisory_radar.config import DEFAULT_THRESHOLDS, ConfigError, Thresholds, load_config
from advisory_radar.runtime import Runtime
from advisory_radar.settings import load_settings, settings_path
from advisory_radar.state import save_state
from advisory_radar.web import create_app

TOKEN = "secret-token"
NOW = 1792600000  # 2026-10-21 16:26:40 UTC
DAY = 86400
CSRF_RE = re.compile(r'name="csrf" value="([0-9a-f]{64})"')
FINGERPRINT_RE = re.compile(r"name='fingerprint' value='([0-9a-f]{64})'")
BODY = """\
sources:
  - id: nodejs
    type: rss
    url: https://feeds.example.net/nodejs.xml
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
  - match: {source: nodejs, tag: critical}
    notifiers: [phone]
default: [ops]
"""
BODY_IDS = """\
sources: []
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
  - match: {ids: "CVE-2026-*"}
    notifiers: [phone]
default: [ops]
"""
ENVIRONMENT = {"OPS_HOOK": "https://ntfy.example.net/OPS", "PHONE_HOOK": "https://ntfy.example.net/PHONE"}


# --- helpers -----------------------------------------------------------------------------------


def write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "config.yml"
    path.write_text(textwrap.dedent(body))
    return path


def load(tmp_path: Path, body: str, *, settings: dict | None = None, env: dict[str, str] | None = None):
    return load_config(write_config(tmp_path, body), env or {}, settings=settings)


def make_client(tmp_path: Path, *, body: str = BODY, state: dict | None = None):
    path = write_config(tmp_path, f"{body}\nstate_path: {tmp_path / 'state.json'}\n")
    env = {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN, **ENVIRONMENT}
    runtime = Runtime.build(path, env, clock=lambda: float(NOW))
    save_state(runtime.cfg.state_path, state if state is not None else core.new_state())
    client = TestClient(create_app(runtime, env, clock=lambda: float(NOW)))
    return client, TOKEN, runtime


def sign_in(client: TestClient) -> str:
    response = client.post("/login", data={"token": TOKEN}, follow_redirects=False)
    assert response.status_code == 303
    client.cookies.set("advisory_radar_session", response.cookies.get("advisory_radar_session"))
    match = CSRF_RE.search(client.get("/").text)
    assert match, "an authenticated page must carry a form token"
    return match.group(1)


def config_form(client: TestClient) -> tuple[str, str]:
    csrf = sign_in(client)
    match = FINGERPRINT_RE.search(client.get("/config").text)
    assert match, "every settings form must carry the configuration fingerprint"
    return csrf, match.group(1)


def save_thresholds(
    client: TestClient,
    csrf: str,
    fingerprint: str,
    *,
    critical_cvss: str = "",
    critical_epss: str = "",
    suppress_below_cvss: str = "",
    follow_redirects: bool = False,
):
    return client.post(
        "/config/thresholds",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "threshold:critical_cvss": critical_cvss,
            "threshold:critical_epss": critical_epss,
            "threshold:suppress_below_cvss": suppress_below_cvss,
        },
        follow_redirects=follow_redirects,
    )


def facts(cvss=None, epss=None, ssvc=None, *, remote=False, complete=True) -> core.CveFacts:
    return core.CveFacts(cvss, ssvc, epss, None, complete, remote_unauth=remote)


class Facts:
    """A deterministic Intel for ``reevaluate``: one answer per CVE, no cache, no network."""

    def __init__(self, **answers: core.CveFacts) -> None:
        self.answers = {key.replace("_", "-"): value for key, value in answers.items()}

    def cves(self, cves, force=False, deferred=None):
        return {cve: self.answers.get(cve, core.CveFacts(None, None, None, None, False)) for cve in cves}


def watch_entry(cve: str, **extra) -> dict:
    entry = {
        "since": NOW - 3 * DAY,
        "last_eval": NOW - 2 * DAY,
        "level": "warning",
        "title": "adv",
        "link": "https://vendor.example.com/a",
    }
    entry.update(extra)
    return entry


# --- the configuration block -------------------------------------------------------------------


def test_the_thresholds_default_to_the_documented_numbers(tmp_path):
    config = load(tmp_path, "sources: []\nnotifiers: []\n")
    assert config.thresholds == Thresholds(9.0, 0.10, 4.0)
    assert config.thresholds == DEFAULT_THRESHOLDS


def test_a_thresholds_block_sets_each_number(tmp_path):
    config = load(
        tmp_path,
        """\
        sources: []
        notifiers: []
        thresholds:
          critical_cvss: 7.5
          critical_epss: 0.25
          suppress_below_cvss: 3
        """,
    )
    assert config.thresholds == Thresholds(7.5, 0.25, 3.0)
    assert isinstance(config.thresholds.suppress_below_cvss, float), "a whole number is still a number"


def test_an_overlay_merges_the_block_key_by_key(tmp_path):
    """One saved number must not reset the other two, which is why this block merges instead of replacing."""
    config = load(
        tmp_path,
        "sources: []\nnotifiers: []\nthresholds:\n  critical_cvss: 7.0\n  critical_epss: 0.3\n",
        settings={"thresholds": {"critical_cvss": 8.0}},
    )
    assert config.thresholds == Thresholds(8.0, 0.3, 4.0)


@pytest.mark.parametrize(
    ("block", "message"),
    [
        ({"critical_cvss": "high"}, "thresholds.critical_cvss must be a number"),
        ({"critical_cvss": True}, "thresholds.critical_cvss must be a number"),
        ({"critical_cvss": 0}, "thresholds.critical_cvss must be above 0 and at most 10"),
        ({"critical_cvss": 10.5}, "thresholds.critical_cvss must be above 0 and at most 10"),
        ({"critical_epss": 0}, "thresholds.critical_epss must be above 0 and at most 1"),
        ({"critical_epss": 1.5}, "thresholds.critical_epss must be above 0 and at most 1"),
        ({"suppress_below_cvss": 9.5}, "thresholds.suppress_below_cvss must be between 0 and thresholds.critical_cvss"),
        ({"nonsense": 1}, "thresholds: unknown keys ['nonsense']"),
        ("not-a-mapping", "thresholds must be a mapping"),
    ],
)
def test_every_invalid_threshold_is_refused(tmp_path, block, message):
    body = f"sources: []\nnotifiers: []\nthresholds: {block!r}\n"
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, body)
    assert str(exc.value) == message


def test_a_damaged_snapshot_falls_back_to_the_defaults():
    assert Thresholds.from_snapshot([7.0, 0.2, 3.0]) == Thresholds(7.0, 0.2, 3.0)
    for damaged in (None, [], [7.0, 0.2], ["7", 0.2, 3.0], [True, 0.2, 3.0], "7.0/0.2/3.0"):
        assert Thresholds.from_snapshot(damaged) == DEFAULT_THRESHOLDS
    assert Thresholds(7.0, 0.2, 3.0).snapshot() == [7.0, 0.2, 3.0]


# --- the decision ------------------------------------------------------------------------------


def test_the_critical_bar_is_the_configured_one():
    strict = Thresholds(critical_cvss=9.5)
    loose = Thresholds(critical_cvss=7.0)
    remote = facts(9.2, remote=True)
    assert core.level_of(remote, False, True, thresholds=strict) == ("warning", None)
    assert core.level_of(remote, False, True, thresholds=loose) == ("critical", "remote")


def test_the_epss_rule_uses_the_configured_probability():
    cve = facts(9.5, epss=0.2)
    assert core.level_of(cve, False, True, thresholds=Thresholds(critical_epss=0.5)) == ("warning", None)
    assert core.level_of(cve, False, True, thresholds=Thresholds(critical_epss=0.15)) == ("critical", "epss")


def test_the_suppression_floor_is_the_configured_one():
    cve = facts(3.5)
    assert core.level_of(cve, False, True, thresholds=DEFAULT_THRESHOLDS) == ("suppressed", None)
    assert core.level_of(cve, False, True, thresholds=Thresholds(suppress_below_cvss=3.0)) == ("warning", None)
    # An unmeasured CVE is never suppressed, whatever the floor says.
    assert core.level_of(facts(3.5, complete=False), False, True, thresholds=DEFAULT_THRESHOLDS) == ("warning", None)


def test_judge_uses_the_configured_thresholds_on_both_paths():
    facts_by_cve = {"CVE-2026-1": facts(9.4, remote=True)}
    strict = core.judge(["CVE-2026-1"], facts_by_cve, frozenset(), True, None, thresholds=Thresholds(9.8))
    loose = core.judge(["CVE-2026-1"], facts_by_cve, frozenset(), True, None, thresholds=Thresholds(9.0))
    assert strict.tag == "warning" and loose.tag == "critical"
    # The OSV-only path reads the same numbers: an advisory with no CVE id is judged by its label alone.
    osv = core.judge([], {}, frozenset(), True, 9.4, thresholds=Thresholds(9.8))
    assert osv.tag == "warning"
    assert core.judge([], {}, frozenset(), True, 9.4, thresholds=Thresholds(9.0)).tag == "critical"
    assert core.judge([], {}, frozenset(), True, 3.5, thresholds=Thresholds(suppress_below_cvss=3.0)).tag == "warning"


def test_the_remote_note_names_the_configured_bar():
    assert "CVSS >= 7.5," in core.reason_note("remote", Thresholds(critical_cvss=7.5))
    assert "CVSS >= 9," not in core.reason_note("remote", Thresholds(critical_cvss=7.5))
    assert "9.0" not in core.reason_note("remote", Thresholds(critical_cvss=7.5))
    # KEV and SSVC are observed exploitation: they need no threshold in their note.
    assert core.reason_note("kev") == ""
    assert core.reason_note("ssvc") == ""


def test_an_escalation_note_names_the_configured_bar():
    note = core.change_note("remote", Thresholds(critical_cvss=7.5))
    assert "CVSS >= 7.5" in note
    assert "0.3" in core.change_note("epss", Thresholds(critical_epss=0.3))


# --- a saved threshold re-baselines the watch list ---------------------------------------------


def test_a_threshold_change_rebaselines_a_watched_cve_without_queueing():
    state = core.new_state()
    cve = "CVE-2026-7000"
    state["watch"][cve] = watch_entry(cve, cvss=5.0)
    intel = Facts(**{cve: facts(9.5, remote=True)})

    core.reevaluate(state, intel, frozenset(), True, NOW, "", thresholds=Thresholds(critical_cvss=7.0))

    assert state["pending"] == [], "a rule change is not news: nothing may be sent"
    assert state["watch"][cve]["judged"] == "critical", "the new rules' verdict is recorded..."
    assert state["watch"][cve]["level"] == "warning", "...but the reader was told warning, and still has been"
    assert state["watch"][cve]["thresholds"] == [7.0, 0.10, 4.0]
    assert state["watch"][cve]["last_eval"] == NOW


def test_a_stricter_threshold_records_the_downgrade():
    state = core.new_state()
    cve = "CVE-2026-7001"
    state["watch"][cve] = watch_entry(cve, level="critical", judged="critical", cvss=9.5)
    intel = Facts(**{cve: facts(9.5, remote=True)})

    core.reevaluate(state, intel, frozenset(), True, NOW, "", thresholds=Thresholds(critical_cvss=9.9))

    assert state["pending"] == []
    assert state["watch"][cve]["judged"] == "warning"
    assert state["watch"][cve]["level"] == "critical", "a downgrade is not news either, and the record stays true"


def test_evidence_after_a_re_baseline_still_escalates():
    """A silent re-baseline must not swallow the KEV hit that arrives with the next evaluation."""
    state = core.new_state()
    cve = "CVE-2026-7004"
    state["watch"][cve] = watch_entry(cve, cvss=8.0)  # sent as a warning under the defaults
    looser = Thresholds(critical_cvss=7.0)
    remote = Facts(**{cve: facts(8.0, remote=True)})

    core.reevaluate(state, remote, frozenset(), True, NOW, "", thresholds=looser)
    assert state["pending"] == []
    assert state["watch"][cve]["judged"] == "critical"
    assert state["watch"][cve]["level"] == "warning"

    # The next daily evaluation finds the CVE in KEV: that is evidence, and the reader has never had it.
    core.reevaluate(state, remote, frozenset({cve}), True, NOW + core.REEVAL_INTERVAL, "", thresholds=looser)

    queued = [entry for entry in state["pending"] if entry["kind"] == "escalation"]
    assert queued and queued[0]["cves"] == [cve] and queued[0]["tag"] == "critical"


def test_a_kev_hit_still_escalates_across_a_threshold_change():
    """Observed exploitation outranks a settings edit: a reader must hear about it whatever the bar is."""
    state = core.new_state()
    cve = "CVE-2026-7002"
    state["watch"][cve] = watch_entry(cve, cvss=None)
    intel = Facts(**{cve: facts(None)})

    core.reevaluate(state, intel, frozenset({cve}), True, NOW, "", thresholds=Thresholds(critical_cvss=7.0))

    queued = [entry for entry in state["pending"] if entry["kind"] == "escalation"]
    assert queued and queued[0]["cves"] == [cve] and queued[0]["tag"] == "critical"
    assert queued[0]["thresholds"] == [7.0, 0.10, 4.0]


def test_a_watch_entry_without_a_snapshot_judges_normally():
    """Entries written before thresholds were configurable were judged by the defaults, and still are."""
    state = core.new_state()
    cve = "CVE-2026-7003"
    state["watch"][cve] = watch_entry(cve, cvss=5.0)
    intel = Facts(**{cve: facts(9.5, remote=True)})

    core.reevaluate(state, intel, frozenset(), True, NOW, "", thresholds=DEFAULT_THRESHOLDS)

    queued = [entry for entry in state["pending"] if entry["kind"] == "escalation"]
    assert queued and queued[0]["tag"] == "critical", "a genuinely new score still escalates"
    assert state["watch"][cve]["thresholds"] == DEFAULT_THRESHOLDS.snapshot()


# --- the /config form --------------------------------------------------------------------------


def test_the_thresholds_form_saves_them_and_applies_them(tmp_path):
    client, _, runtime = make_client(tmp_path)
    csrf, fingerprint = config_form(client)

    saved = save_thresholds(
        client, csrf, fingerprint, critical_cvss="7.5", critical_epss="0.25", suppress_below_cvss="3"
    )

    assert saved.status_code == 303
    assert runtime.cfg.thresholds == Thresholds(7.5, 0.25, 3.0), "with the lock free the save is live at once"
    page = client.get("/config").text
    assert "value='7.5'" in page and "value='0.25'" in page and "value='3'" in page
    assert "Risk thresholds" in page


def test_an_empty_threshold_field_falls_back_to_the_yaml(tmp_path):
    body = "sources: []\nnotifiers: []\nthresholds:\n  critical_cvss: 7.0\n  critical_epss: 0.3\n"
    client, _, runtime = make_client(tmp_path, body=body)
    csrf, fingerprint = config_form(client)

    assert save_thresholds(client, csrf, fingerprint, critical_epss="0.2").status_code == 303

    assert runtime.cfg.thresholds == Thresholds(7.0, 0.2, 4.0), "an empty field uses the YAML value"
    # Clearing every field removes the block: the YAML is the whole threshold configuration again.
    csrf, fingerprint = config_form(client)
    assert save_thresholds(client, csrf, fingerprint).status_code == 303
    assert runtime.cfg.thresholds == Thresholds(7.0, 0.3, 4.0)
    assert "thresholds" not in load_settings(settings_path(runtime.cfg.state_path))


def test_a_refused_threshold_writes_nothing(tmp_path):
    client, _, runtime = make_client(tmp_path)
    csrf, fingerprint = config_form(client)

    refused = save_thresholds(client, csrf, fingerprint, critical_cvss="banana")

    assert refused.status_code == 400
    assert "thresholds.critical_cvss must be a number" in refused.text
    assert runtime.cfg.thresholds == DEFAULT_THRESHOLDS
    assert not (tmp_path / "settings.json").exists()


def test_a_stale_threshold_form_is_refused(tmp_path):
    client, _, _ = make_client(tmp_path)
    csrf, _ = config_form(client)

    stale = save_thresholds(client, csrf, "0" * 64, critical_cvss="7.5")

    assert stale.status_code == 409
    assert not (tmp_path / "settings.json").exists()


# --- the /thresholds preview -------------------------------------------------------------------


def preview(client: TestClient, **query: str) -> str:
    return client.get("/thresholds", params={"preview": "1", **query}).text


def test_the_preview_reports_the_level_the_reason_and_the_route(tmp_path):
    client, _, _ = make_client(tmp_path)
    sign_in(client)
    page = preview(client, cvss="9.8", kev="yes", source="nodejs")
    assert "Critical" in page
    assert "CISA KEV catalog" in page, "the page explains which rule decided"
    assert "route 1" in page and "phone" in page, "and where the message would go"


def test_the_preview_reports_a_suppressed_item(tmp_path):
    client, _, _ = make_client(tmp_path)
    sign_in(client)
    page = preview(client, cvss="2.0")
    assert "Suppressed" in page
    assert "recorded and watched and no message is sent" in page
    assert "Routing:" not in page, "a message that is never sent cannot be said to reach a notifier"


def test_the_preview_keeps_a_source_it_does_not_know(tmp_path):
    """A shared link can outlive the source it names: the answer must stay true to what was asked."""
    client, _, _ = make_client(tmp_path)
    sign_in(client)
    page = preview(client, cvss="5.0", source="ghost")
    assert "ghost (not configured)" in page
    assert "default" in page, "the routing answer is computed for the source that was asked about"


def test_the_preview_reports_the_default_selection(tmp_path):
    client, _, _ = make_client(tmp_path)
    sign_in(client)
    page = preview(client, cvss="5.0", source="nodejs")  # a warning from a source only a critical rule names
    assert "Warning" in page
    assert "default" in page and "ops" in page


def test_the_preview_will_not_predict_a_route_that_needs_identifiers(tmp_path):
    """A rule can match on the ids, so without them the page must say so rather than guess."""
    client, _, _ = make_client(tmp_path, body=BODY_IDS)
    sign_in(client)
    page = preview(client, cvss="9.8", kev="yes")
    assert "Routing:" not in page
    assert "cannot be predicted without them" in page


def test_the_preview_uses_the_identifiers_it_is_given(tmp_path):
    client, _, _ = make_client(tmp_path, body=BODY_IDS)
    sign_in(client)
    page = preview(client, cvss="9.8", kev="yes", ids="CVE-2026-1234")
    assert "Routing:" in page and "route 1" in page and "phone" in page
    # A different identifier falls through the same rule to the default.
    assert "default" in preview(client, cvss="9.8", kev="yes", ids="CVE-2025-1234")


def test_the_preview_refuses_a_bad_number(tmp_path):
    client, _, _ = make_client(tmp_path)
    sign_in(client)
    assert client.get("/thresholds", params={"preview": "1", "cvss": "nine"}).status_code == 400
    assert client.get("/thresholds", params={"preview": "1", "cvss": "11"}).status_code == 400
    assert client.get("/thresholds", params={"preview": "1", "epss": "2"}).status_code == 400


def test_the_preview_writes_nothing(tmp_path):
    client, _, runtime = make_client(tmp_path)
    sign_in(client)
    state_path = runtime.cfg.state_path
    before = (state_path.read_bytes(), (tmp_path / "settings.json").exists())

    preview(client, cvss="9.8", kev="yes", source="nodejs")

    assert (state_path.read_bytes(), (tmp_path / "settings.json").exists()) == before


def test_the_preview_and_the_form_require_auth(tmp_path):
    client, _, _ = make_client(tmp_path)
    response = client.get("/thresholds", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert client.post("/config/thresholds", data={}, follow_redirects=False).status_code == 303
