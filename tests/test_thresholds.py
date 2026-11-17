"""The risk thresholds: the configuration block, the decision it drives, and the two pages that edit and preview it.

Behaviour, not markup: a threshold is changed the way an operator changes it, through the form the page renders,
and the effect is asserted on the decision the pass makes -- including the promise that a saved threshold
re-baselines what is already watched instead of sending the backlog out under the new numbers.
"""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from advisory_radar import core, routing
from advisory_radar.config import DEFAULT_THRESHOLDS, ConfigError, Thresholds, load_config
from advisory_radar.runtime import Runtime
from advisory_radar.settings import load_settings, save_settings, settings_path
from advisory_radar.state import save_state, state_lock
from advisory_radar.watchlist import Policy
from advisory_radar.web import create_app

TOKEN = "secret-token-0123456789abcdef"
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


def make_client(tmp_path: Path, *, body: str = BODY, state: dict | None = None, overlay: dict | None = None):
    path = write_config(tmp_path, f"{body}\nstate_path: {tmp_path / 'state.json'}\n")
    env = {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN, **ENVIRONMENT}
    if overlay is not None:
        # Written before the runtime is built, so the overlay is part of the configuration the page renders.
        save_settings(settings_path(tmp_path / "state.json"), overlay, now=NOW)
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


def save_source_threshold(client: TestClient, csrf: str, fingerprint: str, **fields: str):
    """Post the thresholds form with empty global fields and one field per ``<source id>:<key>`` pair."""
    data = {
        "csrf": csrf,
        "fingerprint": fingerprint,
        "threshold:critical_cvss": "",
        "threshold:critical_epss": "",
        "threshold:suppress_below_cvss": "",
    }
    data.update({f"source_threshold:{name}": value for name, value in fields.items()})
    return client.post("/config/thresholds", data=data, follow_redirects=False)


def source_threshold_value(page: str, identifier: str, key: str) -> str:
    """The value one source's threshold input was rendered with, or a failure naming the field."""
    match = re.search(rf"name='source_threshold:{re.escape(identifier)}:{key}'[^>]*value='([^']*)'", page)
    assert match, f"the form must render source_threshold:{identifier}:{key}"
    return match.group(1)


def facts(cvss=None, epss=None, ssvc=None, *, remote=False, complete=True) -> core.CveFacts:
    return core.CveFacts(cvss, ssvc, epss, None, complete, remote_unauth=remote)


class Facts:
    """A deterministic Intel for ``reevaluate``: one answer per CVE, no cache, no network."""

    def __init__(self, **answers: core.CveFacts) -> None:
        self.answers = {key.replace("_", "-"): value for key, value in answers.items()}

    def cves(self, cves, force=False, deferred=None, **ignored):
        # ``**ignored``: ``classify_new`` passes its own lookup limit, which this stub has no use for.
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
    assert "CVSS >= 7.500001," in core.reason_note("remote", Thresholds(critical_cvss=7.500001)), (
        "the note names the decision boundary exactly, not a rounded display value"
    )
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


def test_raising_the_floor_silently_rebaselines_a_suppressed_cve():
    """The other flood: a lower floor must not turn every recorded-low CVE into a warning message."""
    state = core.new_state()
    cve = "CVE-2026-7005"
    state["watch"][cve] = watch_entry(cve, level="suppressed", judged="suppressed", cvss=3.0)
    intel = Facts(**{cve: facts(3.0)})

    core.reevaluate(state, intel, frozenset(), True, NOW, "", thresholds=Thresholds(suppress_below_cvss=2.0))

    assert state["pending"] == []
    assert state["watch"][cve]["judged"] == "warning"
    assert state["watch"][cve]["level"] == "suppressed", "the reader was told nothing, and that stays true"


@pytest.mark.parametrize("evidence", ["kev", "ssvc"])
def test_evidence_after_a_re_baseline_still_escalates(evidence):
    """A silent re-baseline must not swallow the exploitation signal that arrives with the next evaluation."""
    state = core.new_state()
    cve = "CVE-2026-7004"
    state["watch"][cve] = watch_entry(cve, cvss=8.0)  # sent as a warning under the defaults
    looser = Thresholds(critical_cvss=7.0)
    remote = Facts(**{cve: facts(8.0, remote=True)})

    core.reevaluate(state, remote, frozenset(), True, NOW, "", thresholds=looser)
    assert state["pending"] == []
    assert state["watch"][cve]["judged"] == "critical"
    assert state["watch"][cve]["level"] == "warning"

    # The next daily evaluation finds the evidence: the reader has never had it, so it must go out.
    later = NOW + core.REEVAL_INTERVAL
    if evidence == "kev":
        found, kev = remote, frozenset({cve})
    else:
        found, kev = Facts(**{cve: facts(8.0, remote=True, ssvc="active")}), frozenset()
    core.reevaluate(state, found, kev, True, later, "", thresholds=looser)
    queued = [entry for entry in state["pending"] if entry["kind"] == "escalation"]
    assert queued and queued[0]["cves"] == [cve] and queued[0]["tag"] == "critical"

    # Once it is delivered, the same evidence is not a second escalation.
    core._delivered(state, queued[0], later, "delivered", ("phone",))
    state["pending"] = [entry for entry in state["pending"] if entry is not queued[0]]
    core.reevaluate(state, found, kev, True, later + core.REEVAL_INTERVAL, "", thresholds=looser)
    assert [entry for entry in state["pending"] if entry["kind"] == "escalation"] == []


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
    assert "value='7.5'" in page and "value='0.25'" in page and "value='3.0'" in page
    assert "Risk thresholds" in page


def test_saving_the_form_does_not_round_a_precise_threshold(tmp_path):
    """The rendered value must be the value: a browser resubmits every field, including the untouched ones."""
    body = "sources: []\nnotifiers: []\nthresholds:\n  critical_cvss: 7.500001\n"
    client, _, runtime = make_client(tmp_path, body=body)
    csrf, fingerprint = config_form(client)
    page = client.get("/config").text
    rendered = dict(re.findall(r"name='threshold:(\w+)' size='5'[^>]*value='([^']*)'", page))
    assert rendered["critical_cvss"] == "7.500001", "the form must not round the number it was given"

    saved = save_thresholds(
        client,
        csrf,
        fingerprint,
        critical_cvss=rendered["critical_cvss"],
        critical_epss="0.2",
        suppress_below_cvss=rendered["suppress_below_cvss"],
    )

    assert saved.status_code == 303
    assert runtime.cfg.thresholds == Thresholds(7.500001, 0.2, 4.0)


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


def test_a_save_that_is_not_live_yet_does_not_render_its_old_values(tmp_path):
    """A reset saved while a pass holds the lock must not come back on the next save of the form.

    The form renders the saved document, so a deferred save shows what was saved -- rendering the still-running
    values instead would make the browser resubmit them and undo the reset.
    """
    client, _, runtime = make_client(tmp_path)  # the YAML declares no thresholds block
    csrf, fingerprint = config_form(client)
    assert save_thresholds(client, csrf, fingerprint, critical_cvss="7.0").status_code == 303
    assert runtime.cfg.thresholds.critical_cvss == 7.0

    with state_lock(runtime.cfg.state_path, blocking=False):
        csrf, fingerprint = config_form(client)
        assert save_thresholds(client, csrf, fingerprint).status_code == 303  # clear every field
    assert runtime.cfg.thresholds.critical_cvss == 7.0, "the reload was deferred, so the live value is stale"

    page = client.get("/config").text
    rendered = dict(re.findall(r"name='threshold:(\w+)' size='5'[^>]*value='([^']*)'", page))
    assert rendered["critical_cvss"] == "9.0", "the form shows the saved default, not the stale live value"
    assert rendered["critical_epss"] == "0.1" and rendered["suppress_below_cvss"] == "4.0"
    assert "name='poll_interval' value='15m'" in page, "the poll interval has the same fallback"

    # Saving the form as rendered must leave the configuration where the reset put it.
    csrf, fingerprint = config_form(client)
    saved = save_thresholds(
        client,
        csrf,
        fingerprint,
        critical_cvss=rendered["critical_cvss"],
        critical_epss=rendered["critical_epss"],
        suppress_below_cvss=rendered["suppress_below_cvss"],
    )
    assert saved.status_code == 303
    assert runtime.cfg.thresholds == DEFAULT_THRESHOLDS, "the reset was not undone by a plain save"


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


def test_the_preview_explains_why_an_unmeasured_item_is_a_warning(tmp_path):
    """A warning is not always "above the floor": an unknown score or KEV catalog is why it was not suppressed."""
    client, _, _ = make_client(tmp_path)
    sign_in(client)

    unknown_kev = preview(client, cvss="2.0", kev="unknown")
    assert "Warning" in unknown_kev
    assert "KEV catalog is unknown" in unknown_kev
    assert "at or above the suppression floor" not in unknown_kev

    no_score = preview(client)
    assert "Warning" in no_score
    assert "no score is known" in no_score
    assert "at or above the suppression floor" not in no_score


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


# --- a source's own block ----------------------------------------------------------------------


BODY_SOURCE_OVERRIDE = """\
sources:
  - id: nodejs
    type: rss
    url: https://feeds.example.net/nodejs.xml
    thresholds: {critical_cvss: 7.0}
  - id: legacy
    type: rss
    url: https://feeds.example.net/legacy.xml
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


def test_a_source_block_completes_itself_from_the_global_one(tmp_path):
    """A source states only the numbers it changes; the rest are the global block's, not the defaults."""
    config = load(
        tmp_path,
        """\
        sources:
          - id: nodejs
            type: rss
            url: https://feeds.example.net/nodejs.xml
            thresholds:
              critical_cvss: 7.5
          - id: legacy
            type: rss
            url: https://feeds.example.net/legacy.xml
        notifiers: []
        thresholds:
          critical_epss: 0.25
          suppress_below_cvss: 3
        """,
    )
    assert config.thresholds == Thresholds(9.0, 0.25, 3.0)
    assert config.thresholds_for("nodejs") == Thresholds(7.5, 0.25, 3.0)
    assert config.thresholds_for("legacy") == Thresholds(9.0, 0.25, 3.0), "no block means the global numbers"
    assert config.thresholds_for("ghost") == config.thresholds, "an id the configuration no longer defines"
    assert config.thresholds_for(None) == config.thresholds, "a message that came from no source at all"


@pytest.mark.parametrize(
    ("block", "message"),
    [
        ({"critical_cvss": "high"}, "nodejs: thresholds.critical_cvss must be a number"),
        ({"critical_cvss": True}, "nodejs: thresholds.critical_cvss must be a number"),
        ({"critical_cvss": 0}, "nodejs: thresholds.critical_cvss must be above 0 and at most 10"),
        ({"critical_epss": 1.5}, "nodejs: thresholds.critical_epss must be above 0 and at most 1"),
        (
            {"suppress_below_cvss": 9.5},
            "nodejs: thresholds.suppress_below_cvss must be between 0 and thresholds.critical_cvss",
        ),
        ({"nonsense": 1}, "nodejs: thresholds: unknown keys ['nonsense']"),
        ("not-a-mapping", "nodejs: thresholds must be a mapping"),
    ],
)
def test_a_source_block_is_refused_by_the_same_rules(tmp_path, block, message):
    """The wording is the global block's, prefixed by the source so a refusal says whose block it is."""
    body = (
        "sources:\n"
        "  - id: nodejs\n"
        "    type: rss\n"
        "    url: https://feeds.example.net/nodejs.xml\n"
        f"    thresholds: {block!r}\n"
        "notifiers: []\n"
    )
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, body)
    assert str(exc.value) == message


def test_a_source_override_from_the_overlay_merges_key_by_key(tmp_path):
    """A saved number must not drop the YAML's other keys for that source, exactly as for the global block."""
    merged = load(
        tmp_path,
        """\
        sources:
          - id: nodejs
            type: rss
            url: https://feeds.example.net/nodejs.xml
            thresholds: {critical_cvss: 7.0, critical_epss: 0.2}
        notifiers: []
        """,
        settings={"sources": {"nodejs": {"thresholds": {"critical_cvss": 8.0}}}},
    )
    assert merged.thresholds_for("nodejs") == Thresholds(8.0, 0.2, 4.0)
    added = load(
        tmp_path,
        "sources:\n  - id: nodejs\n    type: rss\n    url: https://feeds.example.net/nodejs.xml\nnotifiers: []\n",
        settings={"sources": {"nodejs": {"thresholds": {"critical_epss": 0.4}}}},
    )
    assert added.thresholds_for("nodejs") == Thresholds(9.0, 0.4, 4.0), "a source with no block may still gain one"


def test_a_disabled_source_block_is_not_resolved(tmp_path):
    """A disabled plugin is not built, so its block is not judged either; enabling one judges it then."""
    config = load(
        tmp_path,
        """\
        sources:
          - id: paused
            type: rss
            url: https://feeds.example.net/off.xml
            enabled: false
            thresholds: {critical_cvss: high}
        notifiers: []
        """,
    )
    assert config.sources == ()
    assert config.source_thresholds == {}


# --- the decision per source -------------------------------------------------------------------


def test_classify_new_judges_with_the_source_block(tmp_path):
    config = load(tmp_path, BODY_SOURCE_OVERRIDE, env=ENVIRONMENT)
    item = core.Item(
        "g1", "CVE-2026-8000 remote bug", "https://vendor.example.net/a", "notes", NOW - 60, ("CVE-2026-8000",)
    )
    intel = Facts(**{"CVE-2026-8000": facts(7.5, 0.2, remote=True)})

    def classify(source_id: str) -> dict:
        classified = core.new_state()
        core.classify_new(
            classified,
            [item],
            intel,
            frozenset(),
            True,
            NOW,
            "vendor.example.net",
            Policy((), (), ()),
            source_id=source_id,
            thresholds=config.thresholds_for(source_id),
        )
        return classified

    loose = classify("nodejs")
    strict = classify("legacy")
    assert loose["pending"][0]["tag"] == "critical", "7.5 is critical under this source's own bar"
    assert strict["pending"][0]["tag"] == "warning", "the global bar still decides for a source without a block"
    assert loose["pending"][0]["thresholds"] == [7.0, 0.10, 4.0]


def test_a_suppressed_advisory_records_the_source_that_queued_it(tmp_path):
    """A suppressed CVE is watched too, so the source is what lets a later evaluation use its own numbers."""
    config = load(tmp_path, BODY_SOURCE_OVERRIDE, env=ENVIRONMENT)
    state = core.new_state()
    item = core.Item("g1", "CVE-2026-8001 low", "https://vendor.example.net/a", "notes", NOW - 60, ("CVE-2026-8001",))
    core.classify_new(
        state,
        [item],
        Facts(**{"CVE-2026-8001": facts(2.0)}),
        frozenset(),
        True,
        NOW,
        "vendor.example.net",
        Policy((), (), ()),
        source_id="nodejs",
        thresholds=config.thresholds_for("nodejs"),
    )
    assert state["pending"] == []
    assert state["watch"]["CVE-2026-8001"]["source_id"] == "nodejs"
    assert state["watch"]["CVE-2026-8001"]["thresholds"] == [7.0, 0.10, 4.0]


def test_a_delivered_message_records_the_source_on_its_watch_entry():
    state = core.new_state()
    entry = {
        "kind": "new",
        "tag": "critical",
        "title": "adv",
        "body": "b",
        "ids": ["CVE-2026-8002"],
        "cves": ["CVE-2026-8002"],
        "levels": {"CVE-2026-8002": "critical"},
        "kev_only": [],
        "scores": {"CVE-2026-8002": 9.8},
        "epss": {"CVE-2026-8002": 0.5},
        "kev": True,
        "thresholds": [7.0, 0.1, 4.0],
        "source": "adv",
        "link": "",
        "source_id": "nodejs",
        "products": [],
    }
    core._delivered(state, entry, NOW, "delivered", ("ops",))
    assert state["watch"]["CVE-2026-8002"]["source_id"] == "nodejs"
    assert state["watch"]["CVE-2026-8002"]["thresholds"] == [7.0, 0.1, 4.0]

    # A message queued before the key existed still records a watch entry, without inventing a source.
    legacy = dict(entry, ids=["CVE-2026-8003"], cves=["CVE-2026-8003"], levels={"CVE-2026-8003": "critical"})
    legacy.pop("source_id")
    core._delivered(state, legacy, NOW, "delivered", ("ops",))
    assert "source_id" not in state["watch"]["CVE-2026-8003"]


def test_reevaluate_applies_the_source_block_not_the_global_one():
    state = core.new_state()
    cve = "CVE-2026-8004"
    # Queued unscored by the nodejs source, under a block that has not changed since.
    state["watch"][cve] = watch_entry(cve, cvss=None, source_id="nodejs", thresholds=[7.0, 0.10, 4.0])
    intel = Facts(**{cve: facts(7.5, 0.2, remote=True)})

    core.reevaluate(
        state,
        intel,
        frozenset(),
        True,
        NOW,
        "",
        thresholds=DEFAULT_THRESHOLDS,
        source_thresholds={"nodejs": Thresholds(critical_cvss=7.0)},
    )

    queued = [entry for entry in state["pending"] if entry["kind"] == "escalation"]
    assert queued and queued[0]["tag"] == "critical", "the source's own bar is the one that applies"
    assert queued[0]["thresholds"] == [7.0, 0.10, 4.0]
    assert queued[0]["scores"] == {cve: 7.5} and queued[0]["epss"] == {cve: 0.2}
    assert queued[0]["kev"] is False, "a catalogue was read and this CVE is not in it"


def test_reevaluate_without_the_source_block_treats_it_as_a_rule_change():
    """The same entry judged by the global block: the source's numbers differ, so this is a re-baseline."""
    state = core.new_state()
    cve = "CVE-2026-8005"
    state["watch"][cve] = watch_entry(cve, cvss=None, source_id="nodejs", thresholds=[7.0, 0.10, 4.0])
    intel = Facts(**{cve: facts(7.5, 0.2, remote=True)})

    core.reevaluate(state, intel, frozenset(), True, NOW, "", thresholds=DEFAULT_THRESHOLDS)

    assert state["pending"] == [], "a change of rules never sends the backlog out"
    assert state["watch"][cve]["judged"] == "warning"
    assert state["watch"][cve]["thresholds"] == DEFAULT_THRESHOLDS.snapshot()


def test_a_global_change_does_not_replay_a_source_whose_own_block_is_unchanged():
    state = core.new_state()
    cve = "CVE-2026-8006"
    state["watch"][cve] = watch_entry(
        cve, level="critical", judged="critical", cvss=7.5, source_id="nodejs", thresholds=[7.0, 0.10, 4.0]
    )
    intel = Facts(**{cve: facts(7.5, 0.2, remote=True)})

    # The global bar moved from 9.0 to 9.9; the source's block did not move at all.
    core.reevaluate(
        state,
        intel,
        frozenset(),
        True,
        NOW,
        "",
        thresholds=Thresholds(critical_cvss=9.9),
        source_thresholds={"nodejs": Thresholds(critical_cvss=7.0)},
    )

    assert state["pending"] == []
    assert state["watch"][cve]["judged"] == "critical", "the source's rules still say critical, so nothing changed"
    assert state["watch"][cve]["level"] == "critical"


@pytest.mark.parametrize(
    "damage",
    [
        {"source_id": 7},
        {"source_id": ["nodejs"]},
        {"source_id": ""},
        {"source_id": "nodejs", "thresholds": "not-a-snapshot"},
        {"thresholds": [1, 2]},
    ],
)
def test_a_damaged_watch_record_judges_without_raising(damage):
    """The state file is hand-editable JSON: a record that cannot be read must fall back, never raise."""
    state = core.new_state()
    cve = "CVE-2026-8007"
    entry = watch_entry(cve, cvss=None)
    entry.update(damage)
    state["watch"][cve] = entry

    core.reevaluate(
        state,
        Facts(**{cve: facts(7.5, 0.2, remote=True)}),
        frozenset(),
        True,
        NOW,
        "",
        thresholds=Thresholds(critical_cvss=7.0),
        source_thresholds={"nodejs": Thresholds(critical_cvss=7.0)},
    )

    assert state["pending"] == [], "an unreadable record is re-baselined, not escalated and not raised on"
    assert state["watch"][cve]["thresholds"] == [7.0, 0.10, 4.0]


# --- the /config form per source ---------------------------------------------------------------


def test_the_thresholds_form_saves_a_source_override(tmp_path):
    client, _, runtime = make_client(tmp_path)
    csrf, fingerprint = config_form(client)

    saved = save_source_threshold(client, csrf, fingerprint, **{"nodejs:critical_cvss": "7.5"})

    assert saved.status_code == 303
    assert runtime.cfg.thresholds_for("nodejs") == Thresholds(7.5, 0.10, 4.0)
    assert runtime.cfg.thresholds == DEFAULT_THRESHOLDS, "the global block is untouched"
    stored = load_settings(settings_path(runtime.cfg.state_path))
    assert stored["sources"]["nodejs"]["thresholds"] == {"critical_cvss": 7.5}
    page = client.get("/config").text
    assert source_threshold_value(page, "nodejs", "critical_cvss") == "7.5"
    assert source_threshold_value(page, "nodejs", "critical_epss") == "", (
        "an inherited number is not rendered as a value"
    )


def test_clearing_a_source_override_stops_overriding(tmp_path):
    client, _, runtime = make_client(tmp_path)
    csrf, fingerprint = config_form(client)
    assert save_source_threshold(client, csrf, fingerprint, **{"nodejs:critical_cvss": "7.5"}).status_code == 303

    csrf, fingerprint = config_form(client)
    cleared = save_source_threshold(client, csrf, fingerprint, **{"nodejs:critical_cvss": ""})

    assert cleared.status_code == 303
    assert runtime.cfg.thresholds_for("nodejs") == DEFAULT_THRESHOLDS
    assert "sources" not in load_settings(settings_path(runtime.cfg.state_path)), "an empty block keeps no entry"


def test_a_source_override_saved_while_a_pass_holds_the_lock_renders_what_was_saved(tmp_path):
    client, _, runtime = make_client(tmp_path)
    with state_lock(runtime.cfg.state_path, blocking=False):
        csrf, fingerprint = config_form(client)
        assert save_source_threshold(client, csrf, fingerprint, **{"nodejs:critical_cvss": "7.5"}).status_code == 303
    assert runtime.cfg.thresholds_for("nodejs") == DEFAULT_THRESHOLDS, "the reload was deferred"

    page = client.get("/config").text
    assert source_threshold_value(page, "nodejs", "critical_cvss") == "7.5", "the form shows the saved block"

    # Resubmitting the form as rendered must leave the saved configuration where it is.
    csrf, fingerprint = config_form(client)
    saved = save_source_threshold(
        client, csrf, fingerprint, **{"nodejs:critical_cvss": source_threshold_value(page, "nodejs", "critical_cvss")}
    )
    assert saved.status_code == 303
    assert load_settings(settings_path(runtime.cfg.state_path))["sources"]["nodejs"]["thresholds"] == {
        "critical_cvss": 7.5
    }, "resubmitting the rendered form must not undo the save"


def test_a_refused_source_threshold_writes_nothing(tmp_path):
    client, _, runtime = make_client(tmp_path)
    csrf, fingerprint = config_form(client)

    refused = save_source_threshold(client, csrf, fingerprint, **{"nodejs:critical_cvss": "banana"})

    assert refused.status_code == 400
    assert "nodejs: thresholds.critical_cvss must be a number" in refused.text
    assert runtime.cfg.thresholds_for("nodejs") == DEFAULT_THRESHOLDS
    assert not (tmp_path / "settings.json").exists()


def test_an_overlay_added_source_keeps_its_override_in_its_own_entry(tmp_path):
    added = [{"id": "added", "type": "rss", "url": "https://feeds.example.net/added.xml"}]
    client, _, runtime = make_client(tmp_path, overlay={"sources_added": added})
    csrf, fingerprint = config_form(client)

    saved = save_source_threshold(client, csrf, fingerprint, **{"added:critical_cvss": "6.5"})

    assert saved.status_code == 303
    stored = load_settings(settings_path(runtime.cfg.state_path))
    assert stored["sources_added"][0]["thresholds"] == {"critical_cvss": 6.5}
    assert "sources" not in stored, "an added source is stored whole, not as a YAML edit"
    assert runtime.cfg.thresholds_for("added") == Thresholds(6.5, 0.10, 4.0)


def test_a_threshold_form_that_rendered_no_source_rows_cannot_clear_an_override(tmp_path):
    """A hand-built POST is not a browser's: it must not read an absent per-source field as a cleared one."""
    client, _, runtime = make_client(tmp_path)
    csrf, fingerprint = config_form(client)
    assert save_source_threshold(client, csrf, fingerprint, **{"nodejs:critical_cvss": "7.5"}).status_code == 303

    csrf, fingerprint = config_form(client)
    saved = save_thresholds(client, csrf, fingerprint, critical_cvss="8.0")

    assert saved.status_code == 303
    assert runtime.cfg.thresholds == Thresholds(8.0, 0.10, 4.0)
    assert runtime.cfg.thresholds_for("nodejs") == Thresholds(7.5, 0.10, 4.0), "the override survived"


# --- the /thresholds preview per source --------------------------------------------------------


def test_the_preview_uses_the_previewed_sources_block(tmp_path):
    client, _, _ = make_client(tmp_path, body=BODY_SOURCE_OVERRIDE)
    sign_in(client)

    loose = preview(client, cvss="7.5", remote="1", source="nodejs")
    assert "Critical" in loose, "7.5 is critical under this source's own bar"
    assert "overrides the global block" in loose, "the page says which numbers it used"

    strict = preview(client, cvss="7.5", remote="1", source="legacy")
    assert "Warning" in strict, "a source without a block is judged by the global numbers"
    assert "overrides the global block" not in strict

    ghost = preview(client, cvss="7.5", remote="1", source="ghost")
    assert "Warning" in ghost, "an id no source defines is judged by the global numbers too"
    assert "overrides the global block" not in ghost


# --- the /thresholds preview of an escalation --------------------------------------------------
#
# ``core.reevaluate`` queues an escalation with no ``source_id`` and no ``products``, so a rule that names a
# source or a product never matches it (#89). The preview has to say so, and what it says has to be what delivery
# does: each routing case below queues a real escalation through ``core.reevaluate``, delivers it through
# ``core.deliver`` and previews the same facts, so the two cannot drift apart unnoticed.

ESCALATION_BODY = """\
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
"""
ESCALATED_CVE = "CVE-2026-1234"
ROUTING_LINE = re.compile(r"Routing: <b>([^<]*)</b> · (?:notifiers <b>([^<]*)</b>|no notifier)")


@dataclass(frozen=True)
class Measured:
    """One watched CVE: who queued it, what its first message told, and what the next evaluation measures.

    ``product`` and ``also`` are typed into the preview only. A watch entry records neither, which is the point:
    an escalation does not carry them.
    """

    cvss: float | None
    epss: float | None = None
    kev: bool = False
    kev_known: bool = True
    remote: bool = False
    told: str = "warning"
    source: str = ""
    product: str = ""
    also: str = ""

    def current(self) -> core.CveFacts:
        return facts(self.cvss, self.epss, remote=self.remote)

    def query(self) -> dict[str, str]:
        """The preview's inputs for the same facts, as the form submits them."""
        query = {
            "preview": "1",
            "kind": "escalation",
            "ids": f"{ESCALATED_CVE} {self.also}".strip(),
            "cvss": "" if self.cvss is None else str(self.cvss),
            "epss": "" if self.epss is None else str(self.epss),
            "kev": "yes" if self.kev else ("" if self.kev_known else "unknown"),
            "source": self.source,
            "product": self.product,
        }
        if self.remote:
            query["remote"] = "1"
        return query


#: Critical through KEV, whatever the first message told.
KEV_HIT = Measured(9.8, epss=0.4, kev=True)
#: A CVE recorded as LOW and never sent, now measured above the floor: the one way an escalation is a warning.
NOW_ABOVE_THE_FLOOR = Measured(5.0, told="suppressed")


class Recorder:
    """A notifier stub that accepts everything and records what delivery offered it."""

    def __init__(self, notifier_id: str) -> None:
        self.id = notifier_id
        self.sent: list[dict] = []

    def send(self, entry, http) -> int:
        self.sent.append(entry)
        return 200


def routed(*rules: tuple[str, str], default: str = "") -> str:
    """The ``routes`` and ``default`` blocks of a configuration: one ``(match, notifier)`` pair per rule."""
    text = ""
    if rules:
        text = "routes:\n" + "".join(f"  - match: {match}\n    notifiers: [{notifier}]\n" for match, notifier in rules)
    return text + (f"default: [{default}]\n" if default else "")


def evaluate(runtime: Runtime, measured: Measured) -> dict:
    """The state the daily pass leaves for a watched CVE that now measures ``measured``."""
    state = core.new_state()
    extra = {"source_id": measured.source} if measured.source else {}
    state["watch"][ESCALATED_CVE] = watch_entry(
        ESCALATED_CVE,
        level=measured.told,
        # What the CVE scored when it was queued, so that the score now measured is news to the remote rule.
        cvss=3.0 if measured.told == "suppressed" else 5.0,
        # The numbers it was judged under: a watch without them looks like a threshold change and stays silent.
        thresholds=runtime.cfg.thresholds_for(measured.source).snapshot(),
        **extra,
    )
    core.reevaluate(
        state,
        Facts(**{ESCALATED_CVE: measured.current()}),
        frozenset({ESCALATED_CVE}) if measured.kev else frozenset(),
        measured.kev_known,
        NOW,
        "",
        thresholds=runtime.cfg.thresholds,
        source_thresholds=runtime.cfg.source_thresholds,
    )
    return state


def previewed_route(page: str) -> tuple[str, list[str]]:
    """The rule or fallback and the sorted notifier ids on the page's ``Routing:`` line."""
    match = ROUTING_LINE.search(page)
    assert match, "the preview must answer with a Routing line"
    return match.group(1), sorted(match.group(2).split(", ")) if match.group(2) else []


@pytest.mark.parametrize(
    ("config", "measured", "expected"),
    [
        pytest.param(
            routed(("{source: nodejs}", "phone"), default="ops"),
            Measured(9.8, epss=0.4, kev=True, source="nodejs"),
            ("default", ["ops"]),
            id="a source rule never matches an escalation, even from the source that queued the watch",
        ),
        pytest.param(
            routed(("{product: magento}", "phone"), default="ops"),
            Measured(9.8, epss=0.4, kev=True, product="magento"),
            ("default", ["ops"]),
            id="a product rule never matches an escalation, whatever product was typed",
        ),
        pytest.param(
            routed(
                ("{source: nodejs, tag: critical}", "phone"),
                ("{product: magento}", "phone"),
                ("{tag: critical}", "ops"),
                default="phone",
            ),
            Measured(9.8, epss=0.4, kev=True, source="nodejs", product="magento"),
            ("route 3", ["ops"]),
            id="source and product rules are skipped and the first rule that can match wins",
        ),
        pytest.param(
            routed(("{tag: critical}", "phone"), default="ops"),
            KEV_HIT,
            ("route 1", ["phone"]),
            id="a tag rule routes a critical escalation",
        ),
        pytest.param(
            routed(("{tag: warning}", "phone"), default="ops"),
            NOW_ABOVE_THE_FLOOR,
            ("route 1", ["phone"]),
            id="a tag rule routes a warning escalation",
        ),
        pytest.param(
            routed(("{tag: critical}", "phone"), default="ops"),
            NOW_ABOVE_THE_FLOOR,
            ("default", ["ops"]),
            id="a critical-only rule leaves a warning escalation to the default",
        ),
        pytest.param(
            routed(("{ids: 'CVE-2026-*'}", "phone"), default="ops"),
            KEV_HIT,
            ("route 1", ["phone"]),
            id="an ids rule matches the CVE the escalation names",
        ),
        pytest.param(
            routed(("{ids: 'CVE-2025-*'}", "phone"), default="ops"),
            KEV_HIT,
            ("default", ["ops"]),
            id="an ids rule for another year does not",
        ),
        pytest.param(
            routed(("{ids: 'GHSA-*'}", "phone"), default="ops"),
            Measured(9.8, epss=0.4, kev=True, also="GHSA-aaaa-bbbb-cccc"),
            ("default", ["ops"]),
            id="an escalation carries only its CVE id, not the other ids typed for the advisory",
        ),
        pytest.param(
            routed(("{min_cvss: 9.5}", "phone"), default="ops"),
            KEV_HIT,
            ("route 1", ["phone"]),
            id="min_cvss reads the score the escalation carries",
        ),
        pytest.param(
            routed(("{min_cvss: 9.9}", "phone"), default="ops"),
            KEV_HIT,
            ("default", ["ops"]),
            id="a higher min_cvss does not match",
        ),
        pytest.param(
            routed(("{epss_gte: 0.3}", "phone"), default="ops"),
            KEV_HIT,
            ("route 1", ["phone"]),
            id="epss_gte reads the EPSS the escalation carries",
        ),
        pytest.param(
            routed(("{epss_gte: 0.5}", "phone"), default="ops"),
            KEV_HIT,
            ("default", ["ops"]),
            id="a higher epss_gte does not match",
        ),
        pytest.param(
            routed(("{kev: true}", "phone"), default="ops"),
            KEV_HIT,
            ("route 1", ["phone"]),
            id="kev: true matches the KEV hit that decided the escalation",
        ),
        pytest.param(
            routed(("{kev: false}", "phone"), default="ops"),
            KEV_HIT,
            ("default", ["ops"]),
            id="kev: false does not",
        ),
        pytest.param(
            routed(("{tag: critical}", "phone"), default="ops"),
            Measured(7.5, remote=True, source="nodejs"),
            ("route 1", ["phone"]),
            id="the source still picks the thresholds that make the escalation critical, though not its route",
        ),
        pytest.param(
            routed(("{tag: warning}", "phone")),
            KEV_HIT,
            ("all", ["ops", "phone"]),
            id="no rule matches and no default is set: every enabled notifier",
        ),
        pytest.param(
            routed(default="ops"),
            KEV_HIT,
            ("all", ["ops", "phone"]),
            id="a default without any route changes nothing: every enabled notifier",
        ),
    ],
)
def test_the_escalation_preview_is_what_delivery_selects(tmp_path, config, measured, expected):
    client, _, runtime = make_client(tmp_path, body=ESCALATION_BODY + config)
    sign_in(client)

    # The real thing: a watched CVE that the daily pass re-evaluates queues the escalation, and delivery routes it.
    state = evaluate(runtime, measured)
    [queued] = [entry for entry in state["pending"] if entry["kind"] == "escalation"]
    assert "source_id" not in queued and "products" not in queued, "the premise: an escalation has no context"
    enabled = [str(entry["id"]) for entry in runtime.cfg.notifiers]
    selected, label = routing.select(dict(queued), runtime.cfg.routes, runtime.cfg.default_notifiers, enabled)
    recorders = [Recorder(identifier) for identifier in enabled]
    assert core.deliver(state, recorders, None, NOW, routes=runtime.cfg.routes, default=runtime.cfg.default_notifiers)
    delivered = sorted(recorder.id for recorder in recorders if recorder.sent)
    assert delivered == sorted(selected)
    assert (label, delivered) == expected, "the case must exercise the rule it names"

    page = client.get("/thresholds", params=measured.query()).text

    assert previewed_route(page) == (label, delivered), "the preview must equal what delivery selects"


def test_the_escalation_preview_lists_the_rules_it_skips(tmp_path):
    config = routed(
        ("{source: nodejs, tag: critical}", "phone"),
        ("{product: magento}", "phone"),
        ("{tag: warning}", "phone"),
        ("{source: legacy, product: magento}", "phone"),
        default="ops",
    )
    client, _, _ = make_client(tmp_path, body=ESCALATION_BODY + config)
    sign_in(client)
    measured = Measured(9.8, epss=0.4, kev=True, source="nodejs", product="magento")

    page = client.get("/thresholds", params=measured.query()).text

    assert previewed_route(page) == ("default", ["ops"])
    assert "rule 1 (source)" in page and "rule 2 (product)" in page and "rule 4 (source and product)" in page
    assert "rule 3" not in page, "a tag rule can match an escalation, so it is not listed as skipped"
    assert "No rule matches this escalation, so the default notifiers win" in page
    assert "<option value='escalation' selected>Escalation</option>" in page
    # The same facts as a new advisory from that source do reach the source's rule: the message kind is the difference.
    assert previewed_route(client.get("/thresholds", params={**measured.query(), "kind": ""}).text) == (
        "route 1",
        ["phone"],
    )


FALLBACK_SENTENCES = (
    "No rule matches this escalation, so the default notifiers win.",
    "No rule matches this escalation and no default is set, so every enabled notifier gets it.",
    "No routes are configured, so every enabled notifier gets it.",
)


@pytest.mark.parametrize(
    ("config", "route", "sentence"),
    [
        pytest.param(
            routed(("{source: nodejs}", "phone"), default="ops"),
            ("default", ["ops"]),
            FALLBACK_SENTENCES[0],
            id="the default wins when no rule can match",
        ),
        pytest.param(
            routed(("{source: nodejs}", "phone")),
            ("all", ["ops", "phone"]),
            FALLBACK_SENTENCES[1],
            id="every enabled notifier wins when there is no default either",
        ),
        pytest.param(
            "",
            ("all", ["ops", "phone"]),
            FALLBACK_SENTENCES[2],
            id="every enabled notifier gets it when no route is configured",
        ),
        pytest.param(
            routed(("{source: nodejs}", "phone"), ("{tag: critical}", "ops"), default="phone"),
            ("route 2", ["ops"]),
            None,
            id="no fallback applies when a rule matches",
        ),
    ],
)
def test_the_escalation_preview_names_the_fallback_that_wins(tmp_path, config, route, sentence):
    client, _, _ = make_client(tmp_path, body=ESCALATION_BODY + config)
    sign_in(client)

    page = client.get("/thresholds", params=KEV_HIT.query()).text

    assert previewed_route(page) == route
    assert [text for text in FALLBACK_SENTENCES if text in page] == ([sentence] if sentence else [])


def test_the_escalation_preview_says_it_does_not_know_whether_the_cve_escalates(tmp_path):
    client, _, _ = make_client(tmp_path, body=ESCALATION_BODY + routed(("{tag: critical}", "phone"), default="ops"))
    sign_in(client)
    page = client.get("/thresholds", params=KEV_HIT.query()).text
    assert "depends on what its first message told" in page


def test_the_escalation_preview_shows_the_note_an_escalation_carries(tmp_path):
    client, _, _ = make_client(tmp_path, body=ESCALATION_BODY + routed(("{tag: critical}", "phone"), default="ops"))
    sign_in(client)
    escalation = client.get("/thresholds", params=KEV_HIT.query()).text
    assert core.change_note("kev") in escalation, "an escalation says what changed, not why the CVE is critical"
    advisory = client.get("/thresholds", params={**KEV_HIT.query(), "kind": ""}).text
    assert core.change_note("kev") not in advisory


@pytest.mark.parametrize(
    "measured",
    [
        pytest.param(Measured(2.0, told="suppressed"), id="a CVE measured LOW is recorded, not escalated"),
        pytest.param(
            Measured(2.0, told="suppressed", kev_known=False),
            id="a scored CVE below the floor with the catalogue unknown is not escalated either",
        ),
        pytest.param(Measured(None, told="suppressed"), id="a CVE with no score is not escalated"),
    ],
)
def test_the_escalation_preview_routes_nothing_for_facts_that_never_escalate(tmp_path, measured):
    client, _, runtime = make_client(
        tmp_path, body=ESCALATION_BODY + routed(("{tag: warning}", "phone"), default="ops")
    )
    sign_in(client)
    assert evaluate(runtime, measured)["pending"] == [], "the premise: the daily pass queues nothing for these facts"

    page = client.get("/thresholds", params=measured.query()).text

    assert "Routing:" not in page, "no escalation is queued, so nothing is routed"
    assert "No escalation is queued for these facts" in page


def test_the_escalation_preview_needs_exactly_one_cve_id(tmp_path):
    client, _, _ = make_client(tmp_path, body=ESCALATION_BODY + routed(("{ids: 'GHSA-*'}", "phone"), default="ops"))
    sign_in(client)
    query = KEV_HIT.query()

    for ids in ("", "GHSA-aaaa-bbbb-cccc", "CVE-2026-1234 CVE-2026-5678"):
        page = client.get("/thresholds", params={**query, "ids": ids}).text
        assert "Routing:" not in page, ids
        assert "exactly one CVE" in page.split("<h2>Result</h2>")[1], ids

    # One CVE id decides. It may be written in either case or twice, and another id typed beside it never reaches
    # an escalation: a new advisory with the same ids would match the GHSA rule, an escalation does not.
    expected = ("default", ["ops"])
    for ids in ("CVE-2026-1234", "cve-2026-1234 GHSA-aaaa-bbbb-cccc", "CVE-2026-1234, cve-2026-1234"):
        assert previewed_route(client.get("/thresholds", params={**query, "ids": ids}).text) == expected, ids
    advisory = client.get("/thresholds", params={**query, "kind": "", "ids": "CVE-2026-1234 GHSA-aaaa-bbbb-cccc"})
    assert previewed_route(advisory.text) == ("route 1", ["phone"])


def test_the_escalation_preview_will_not_predict_a_kev_rule_against_an_unknown_catalogue(tmp_path):
    client, _, _ = make_client(tmp_path, body=ESCALATION_BODY + routed(("{kev: true}", "phone"), default="ops"))
    sign_in(client)
    page = client.get("/thresholds", params=Measured(9.8, epss=0.4, kev_known=False).query()).text
    assert "Routing:" not in page
    assert "matches on KEV membership" in page and "cannot be predicted" in page


@pytest.mark.parametrize(
    "query",
    [
        {"cvss": "9.8", "kev": "yes", "source": "nodejs"},
        {"cvss": "5.0", "source": "nodejs"},
        {"cvss": "2.0"},
        {"cvss": "9.8", "epss": "0.4", "kev": "yes", "ids": ESCALATED_CVE, "product": "magento"},
        {"cvss": "7.5", "remote": "1", "source": "nodejs", "ids": "GHSA-aaaa-bbbb-cccc"},
        {},
    ],
)
def test_the_default_message_kind_previews_a_new_advisory_as_before(tmp_path, query):
    config = routed(("{source: nodejs, tag: critical}", "phone"), ("{product: magento}", "phone"), default="ops")
    client, _, _ = make_client(tmp_path, body=ESCALATION_BODY + config)
    sign_in(client)

    plain = client.get("/thresholds", params={"preview": "1", **query}).text
    explicit = client.get("/thresholds", params={"preview": "1", "kind": "", **query}).text

    assert plain == explicit, "an absent kind and an empty one are both a new advisory"
    assert "<option value='' selected>New advisory</option>" in plain
    result = plain.split("<h2>Result</h2>")[1].split("</main>")[0]
    assert "escalation" not in result.lower(), "nothing about an escalation leaks into a new advisory's answer"


def test_the_preview_form_offers_the_message_kind_and_keeps_it_without_a_preview(tmp_path):
    client, _, _ = make_client(tmp_path)
    sign_in(client)

    page = client.get("/thresholds", params={"kind": "escalation"})

    assert page.status_code == 200
    assert "<select name='kind'>" in page.text
    assert "<option value='escalation' selected>Escalation</option>" in page.text
    assert "<h2>Result</h2>" not in page.text, "no preview was asked for"
    assert "carries no source and no product" in page.text, "the form says what an escalation lacks"


def test_the_preview_refuses_an_unknown_message_kind(tmp_path):
    client, _, _ = make_client(tmp_path)
    sign_in(client)
    for kind in ("digest", "new", "ESCALATION"):
        response = client.get("/thresholds", params={"preview": "1", "kind": kind})
        assert response.status_code == 400, kind
        assert "kind must be empty or escalation" in response.text, kind


def test_the_routes_section_says_source_and_product_rules_do_not_apply_to_escalations(tmp_path):
    client, _, _ = make_client(tmp_path)
    sign_in(client)

    routes = client.get("/config").text.split("<span class='sec-num'>05</span>Routes</h2>")[1]

    assert "carries no source and no product" in routes
    assert "never matches it" in routes
    assert "then the default notifiers, then every enabled notifier" in routes
    assert "href='/thresholds?kind=escalation'" in routes, "the preview that shows it for these rules"
