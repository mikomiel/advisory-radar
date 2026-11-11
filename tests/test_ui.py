"""The list pages, the advisory page, per-entry queue actions and the routes form.

Behaviour, not markup: the filters are requested through the URL a browser would send, pagination is
followed through the links the page renders, and the mutations are asserted against the state file.
"""

from __future__ import annotations

import html
import importlib.util
import json
import logging
import re
import sys
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from advisory_radar import core
from advisory_radar.config import ConfigError, load_config
from advisory_radar.delivery import QuietHours
from advisory_radar.http import RedactFilter
from advisory_radar.runtime import Runtime
from advisory_radar.settings import load_settings, settings_path
from advisory_radar.state import load_state_document, save_state, serialize_json, state_lock
from advisory_radar.storage import JsonStore
from advisory_radar.web import _advisory_token, create_app

LOG = logging.getLogger("advisory_radar")
NOW = 1792600000  # 2026-10-21 16:26:40 UTC
DAY = 86400
#: 2026-10-21 00:00:00 UTC and the two midnights around it, for the inclusive day-range tests.
DAY_START = NOW - (16 * 3600 + 26 * 60 + 40)
TOKEN = "secret-token"
CSRF_RE = re.compile(r'name="csrf" value="([0-9a-f]{64})"')
FINGERPRINT_RE = re.compile(r"name='fingerprint' value='([0-9a-f]{64})'")
ADVISORY_LINK_RE = re.compile(r"<td><a href='/advisories/[^']*'>([^<]+)</a></td>")
PAGER_RE = re.compile(r"href='(/alerts\?[^']*)'")
ROUTES_CONFIG = """\
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
  - match: {tag: critical}
    notifiers: [phone]
default: [ops]
"""
CHANNEL_ENV = {
    "OPS_HOOK": "https://ntfy.example.net/OPS-SECRET",
    "PHONE_HOOK": "https://ntfy.example.net/PHONE-SECRET",
}


@pytest.fixture(autouse=True)
def _detach_log_redaction():
    """A runtime installs a log filter; one test's secrets must not redact the next test's output."""
    yield
    for installed in list(LOG.filters):
        if isinstance(installed, RedactFilter):
            LOG.removeFilter(installed)


# --- helpers -----------------------------------------------------------------------------------


def make_client(
    tmp_path: Path,
    *,
    body: str = "sources: []\nnotifiers: []\n",
    state: dict | None = None,
    environment: dict[str, str] | None = None,
    clock: int = NOW,
    storage: str = "",
):
    """A signed-out client over a real Runtime, the token, and the runtime itself."""
    cfg_path = tmp_path / "config.yml"
    config = f"{body}\nstate_path: {tmp_path / 'state.json'}\n"
    if storage:
        config += f"storage: {storage}\n"
    cfg_path.write_text(config)
    env = {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN, **(environment or {})}
    runtime = Runtime.build(cfg_path, env, clock=lambda: float(clock))
    runtime.cfg.store().save(state if state is not None else core.new_state())
    client = TestClient(create_app(runtime, env, clock=lambda: float(clock)))
    return client, TOKEN, runtime


def sign_in(client: TestClient, token: str = TOKEN) -> str:
    """Log in and return the CSRF token every authenticated page carries."""
    response = client.post("/login", data={"token": token}, follow_redirects=False)
    assert response.status_code == 303
    client.cookies.set("advisory_radar_session", response.cookies.get("advisory_radar_session"))
    page = client.get("/")
    match = CSRF_RE.search(page.text)
    assert match, "an authenticated page must carry a form token"
    return match.group(1)


def config_form(client: TestClient, token: str = TOKEN) -> tuple[str, str]:
    """Log in and return the form token and the configuration fingerprint /config rendered."""
    csrf = sign_in(client, token)
    page = client.get("/config").text
    match = FINGERPRINT_RE.search(page)
    assert match, "every settings form must carry the configuration fingerprint"
    return csrf, match.group(1)


def advisory_token(identifier: str) -> str:
    """The path segment the pages use for an identifier, which may contain slashes itself."""
    import base64

    return base64.urlsafe_b64encode(identifier.encode("utf-8")).decode("ascii").rstrip("=")


def page_ids(text: str) -> list[str]:
    """The identifiers in the order the alert table renders them."""
    return ADVISORY_LINK_RE.findall(text)


def pager_urls(text: str) -> dict[str, str]:
    """The ``cursor`` (older) and ``before`` (newer) links the page rendered, as real request paths."""
    found = {}
    for raw in PAGER_RE.findall(text):
        url = html.unescape(raw)
        found["next" if "cursor=" in url else "previous"] = url
    return found


def seen(at: int, outcome: str = "delivered", **extra) -> dict:
    return {"at": at, "outcome": outcome, **extra}


def snapshot(at: int, tag: str, source: str, title: str, cve: str, level: str, score: float, accepted):
    return {
        "at": at,
        "outcome": "delivered",
        "tag": tag,
        "source": source,
        "title": title,
        "link": f"https://vendor.example.net/advisories/{cve}",
        "kind": "new",
        "levels": {cve: level},
        "scores": {cve: score},
        "delivered_to": list(accepted),
    }


def pending_entry(cve: str = "CVE-2026-50111", **extra) -> dict:
    entry = {
        "kind": "new",
        "tag": "warning",
        "title": f"WARNING: {cve} in nginx",
        "body": "BODY-MARKER: the rendered message is not retained",
        "ids": [cve],
        "cves": [cve],
        "levels": {cve: "warning"},
        "scores": {cve: 7.5},
        "kev_only": [],
        "source": "Vendor Feed",
        "link": f"https://vendor.example.net/advisories/{cve}",
        "attempts": 2,
        "first_attempt_at": NOW - 300,
        "last_status": 500,
        "sent_to": ["ops"],
    }
    entry.update(extra)
    return entry


def parked_entry(cve: str = "CVE-2026-4000", tag: str = "critical", **extra) -> dict:
    entry = pending_entry(cve, tag=tag, title=f"{tag.upper()}: {cve} in libxml2", attempts=3)
    entry.update({"first_attempt_at": NOW - 900, "parked_at": NOW - 600, "sent_to": []})
    entry.update(extra)
    return entry


class RecordingNotifier:
    """Accepts everything and remembers the messages it was given, with no network."""

    def __init__(self, notifier_id: str, status: int = 200) -> None:
        self.id = notifier_id
        self.status = status
        self.sent: list[dict] = []

    def send(self, entry, http) -> int:
        self.sent.append(entry)
        return self.status


def no_http(*args):
    raise AssertionError("the stub notifiers must not make a request")


# --- /alerts: URL filters ----------------------------------------------------------------------


def filter_state() -> dict:
    state = core.new_state()
    state["seen"]["CVE-2026-1000"] = snapshot(
        NOW, "critical", "Vendor A", "Remote code execution in widget", "CVE-2026-1000", "critical", 9.8, ["ops"]
    )
    state["seen"]["CVE-2026-2000"] = snapshot(
        NOW - 3600, "warning", "Vendor B", "Denial of service in parser", "CVE-2026-2000", "warning", 5.3, ["ops"]
    )
    state["seen"]["GHSA-abcd-efgh"] = seen(NOW - 7200, "suppressed")
    state["seen"]["CVE-2026-LEGACY"] = seen(NOW - 10800, "delivered")
    state["seen"]["APSB26-97"] = snapshot(
        NOW - 14400, "warning", "Vendor A", "Commerce bulletin", "APSB26-97", "warning", 7.2, ["ops"]
    )
    return state


def test_each_alert_filter_narrows_the_list_and_survives_a_reload(tmp_path):
    client, token, _ = make_client(tmp_path, state=filter_state())
    sign_in(client, token)
    cases = (
        ({"tag": "critical"}, ["CVE-2026-1000"]),
        ({"source": "Vendor B"}, ["CVE-2026-2000"]),
        ({"outcome": "suppressed"}, ["GHSA-abcd-efgh"]),
        ({"q": "widget"}, ["CVE-2026-1000"]),
        ({"q": "cve-2026-2000"}, ["CVE-2026-2000"]),  # the identifier itself, case-insensitively
        ({"tag": "critical", "source": "Vendor A", "q": "execution"}, ["CVE-2026-1000"]),
    )
    for params, expected in cases:
        first = client.get("/alerts", params=params)
        assert first.status_code == 200
        assert page_ids(first.text) == expected, params
        # A reload or a shared link sends the same URL: the filter is state in the URL, not in a session.
        again = client.get("/alerts", params=params)
        assert page_ids(again.text) == expected, params
        assert "Filter" in again.text
    # one filter narrows another out entirely
    assert page_ids(client.get("/alerts", params={"tag": "warning", "q": "execution"}).text) == []
    # every row links to its advisory page
    assert f"href='/advisories/{advisory_token('CVE-2026-1000')}'" in client.get("/alerts").text


def test_a_legacy_record_is_excluded_by_snapshot_filters_but_found_by_identifier(tmp_path):
    client, token, _ = make_client(tmp_path, state=filter_state())
    sign_in(client, token)
    for params in ({"tag": "critical"}, {"tag": "warning"}, {"source": "Vendor A"}, {"source": "Vendor B"}):
        assert "CVE-2026-LEGACY" not in page_ids(client.get("/alerts", params=params).text), params
    # Its identifier, its outcome and its date still filter: the record is not hidden, only its missing fields.
    assert page_ids(client.get("/alerts", params={"q": "CVE-2026-LEGACY"}).text) == ["CVE-2026-LEGACY"]
    assert "CVE-2026-LEGACY" in page_ids(client.get("/alerts", params={"outcome": "delivered"}).text)
    assert "CVE-2026-LEGACY" in page_ids(
        client.get("/alerts", params={"since": "2026-10-21", "until": "2026-10-21"}).text
    )
    alerts = client.get("/alerts").text
    assert "A dash means the record predates the delivery snapshot" in alerts


def test_since_and_until_include_the_whole_day_at_both_ends(tmp_path):
    state = core.new_state()
    records = {
        # exactly one second before the window, then both of its edges, then one second after
        "CVE-2026-PREV": DAY_START - 1,
        "CVE-2026-MIDNIGHT": DAY_START,
        "CVE-2026-LAST": DAY_START + DAY - 1,
        "CVE-2026-NEXT": DAY_START + DAY,
    }
    for identifier, at in records.items():
        state["seen"][identifier] = seen(at, "delivered")
    client, token, _ = make_client(tmp_path, state=state)
    sign_in(client, token)
    one_day = client.get("/alerts", params={"since": "2026-10-21", "until": "2026-10-21"})
    assert page_ids(one_day.text) == ["CVE-2026-LAST", "CVE-2026-MIDNIGHT"]
    # The bounds are independent: each one alone keeps its own side and drops nothing on the other.
    assert "CVE-2026-PREV" not in page_ids(client.get("/alerts", params={"since": "2026-10-21"}).text)
    assert "CVE-2026-NEXT" not in page_ids(client.get("/alerts", params={"until": "2026-10-21"}).text)
    assert "CVE-2026-PREV" in page_ids(client.get("/alerts", params={"until": "2026-10-21"}).text)


def test_a_malformed_date_is_refused_rather_than_ignored(tmp_path):
    client, token, _ = make_client(tmp_path, state=filter_state())
    sign_in(client, token)
    response = client.get("/alerts", params={"since": "yesterday"}, headers={"accept": "text/html"})
    assert response.status_code == 400
    assert "must be a date like" in response.text


# --- /alerts: keyset pagination ----------------------------------------------------------------


def pagination_state() -> dict:
    """62 records: 60 sharing one timestamp, one newer and one older, so both order keys are exercised."""
    state = core.new_state()
    for index in range(10, 70):
        identifier = f"CVE-2026-{index:03d}"
        state["seen"][identifier] = snapshot(
            NOW, "warning", "Vendor Feed", f"WARNING: {identifier} in widget", identifier, "warning", 5.0, ["ops"]
        )
    state["seen"]["CVE-2026-999"] = snapshot(
        NOW + 100, "warning", "Vendor Feed", "WARNING: CVE-2026-999 in widget", "CVE-2026-999", "warning", 5.0, ["ops"]
    )
    state["seen"]["CVE-2026-000"] = snapshot(
        NOW - 100, "warning", "Vendor Feed", "WARNING: CVE-2026-000 in widget", "CVE-2026-000", "warning", 5.0, ["ops"]
    )
    return state


def test_the_alert_list_pages_by_keyset_with_no_overlap_and_no_gap(tmp_path):
    client, token, _ = make_client(tmp_path, state=pagination_state())
    sign_in(client, token)
    first = client.get("/alerts", params={"tag": "warning"})
    assert first.status_code == 200
    first_ids = page_ids(first.text)
    assert len(first_ids) == 50
    # Newest first by (at desc, identifier asc): the newer record, then the timestamp tie in identifier order.
    assert first_ids[:2] == ["CVE-2026-999", "CVE-2026-010"]
    assert "CVE-2026-000" not in first_ids
    pager = pager_urls(first.text)
    assert "next" in pager and "previous" not in pager
    assert "tag=warning" in pager["next"], "a pagination link must keep every filter"

    second = client.get(pager["next"])
    second_ids = page_ids(second.text)
    assert second_ids == [*(f"CVE-2026-{index:03d}" for index in range(59, 70)), "CVE-2026-000"]
    assert len(second_ids) == 12
    assert not set(first_ids) & set(second_ids), "no record may appear on two pages"
    assert set(first_ids) | set(second_ids) == set(pagination_state()["seen"]), "no record may be skipped"
    page_two_pager = pager_urls(second.text)
    assert "previous" in page_two_pager and "next" not in page_two_pager

    back = client.get(page_two_pager["previous"])
    assert page_ids(back.text) == first_ids, "the previous link returns to the page before"


def test_a_malformed_cursor_is_a_400_page_not_a_crash(tmp_path):
    client, token, _ = make_client(tmp_path, state=pagination_state())
    sign_in(client, token)
    for cursor in ("not-base64!", "eA", "MTIzNDU2Nzg5MA", "MTIzOmlk!"):  # not base64 / no colon / stray char
        response = client.get("/alerts", params={"cursor": cursor}, headers={"accept": "text/html"})
        assert response.status_code == 400, cursor
        assert "malformed page cursor" in response.text
    # An empty value is not a cursor: the page renders the newest records rather than refusing.
    assert client.get("/alerts", params={"cursor": ""}).status_code == 200


# --- /runs -------------------------------------------------------------------------------------


def runs_state() -> dict:
    state = core.new_state()
    runs = []
    for index in range(200):
        runs.append(
            {
                "at": DAY_START - (199 - index) * 900,
                "sent": index % 3,
                "parked": 0,
                "pending": 0,
                "code": 7 if index == 0 else (1 if index % 40 == 0 else 0),
            }
        )
    state["runs"] = runs
    return state


def test_the_outcome_filter_offers_the_filtered_outcome(tmp_path):
    client, token, _ = make_client(tmp_path, state=pagination_state())
    sign_in(client, token)
    assert "value='filtered'" in client.get("/alerts").text


def test_the_runs_page_filters_by_exit_code_and_day_and_states_the_cap(tmp_path):
    client, token, _ = make_client(tmp_path, state=runs_state())
    sign_in(client, token)
    page = client.get("/runs")
    assert page.status_code == 200
    assert page.text.count("<tr>") - 1 == 200, "no pagination: every retained pass is one row"
    assert "keeps only the last 200 passes" in page.text

    failed = client.get("/runs", params={"code": "7"})
    assert failed.text.count("<tr>") - 1 == 1
    # The oldest retained pass is the failing one, so the filter reaches the far end of the history.
    oldest = datetime.fromtimestamp(DAY_START - 199 * 900, tz=UTC).strftime("%Y-%m-%d %H:%M")
    assert oldest in failed.text

    one_day = client.get("/runs", params={"since": "2026-10-20", "until": "2026-10-20"})
    assert 0 < one_day.text.count("<tr>") - 1 < 200

    assert client.get("/runs", params={"code": "banana"}, headers={"accept": "text/html"}).status_code == 400


# --- the delivery record on a seen advisory ----------------------------------------------------


def test_a_delivered_message_records_the_snapshot_and_keeps_the_first_record():
    state = core.new_state()
    entry = pending_entry("CVE-2026-1")
    entry.update({"tag": "critical", "title": "CRITICAL: CVE-2026-1 in widget", "levels": {"CVE-2026-1": "critical"}})
    state["pending"].append(entry)
    ops, phone = RecordingNotifier("ops"), RecordingNotifier("phone")
    assert core.deliver(state, [ops, phone], no_http, NOW) is True
    record = state["seen"]["CVE-2026-1"]
    assert set(record) == {"at", "outcome", "delivery"}, "a seen record points at its snapshot, not a copy"
    assert record["at"] == NOW and record["outcome"] == "delivered"
    delivery = state["deliveries"][record["delivery"]]
    assert delivery == {
        "tag": "critical",
        "source": "Vendor Feed",
        "title": "CRITICAL: CVE-2026-1 in widget",
        "link": "https://vendor.example.net/advisories/CVE-2026-1",
        "kind": "new",
        "ids": ["CVE-2026-1"],
        "cves": ["CVE-2026-1"],
        "kev_only": [],
        "products": [],
        "levels": {"CVE-2026-1": "critical"},
        "scores": {"CVE-2026-1": 7.5},
        "delivered_to": ["ops", "phone"],
    }
    assert "body" not in delivery, "the rendered message body is not stored"

    # A later message about the same identifier is delivered too, but the first record is what the page keeps.
    again = pending_entry("CVE-2026-1", tag="warning", title="WARNING: CVE-2026-1 elsewhere")
    state["pending"].append(again)
    assert core.deliver(state, [ops], no_http, NOW) is True
    assert state["seen"]["CVE-2026-1"] == record
    assert state["deliveries"][record["delivery"]]["delivered_to"] == ["ops", "phone"]


def test_a_message_delivered_by_this_version_appears_and_filters_in_the_list(tmp_path):
    state = core.new_state()
    entry = pending_entry("CVE-2026-1234")
    entry.update({"tag": "critical", "title": "CRITICAL: CVE-2026-1234 in widget", "source": "Vendor Feed"})
    state["pending"].append(entry)
    assert core.deliver(state, [RecordingNotifier("ops")], no_http, NOW) is True
    save_state(tmp_path / "state.json", state)
    stored = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    client, token, _ = make_client(tmp_path, state=stored)
    sign_in(client, token)
    page = client.get("/alerts").text
    assert "CVE-2026-1234" in page and "CRITICAL: CVE-2026-1234 in widget" in page
    assert "Vendor Feed" in page and "critical" in page
    assert client.get("/alerts", params={"tag": "critical"}).text.count("/advisories/") >= 1
    assert "/advisories/" not in client.get("/alerts", params={"tag": "warning"}).text
    assert client.get("/alerts", params={"source": "Vendor Feed"}).text.count("/advisories/") >= 1
    assert client.get("/alerts", params={"q": "widget"}).text.count("/advisories/") >= 1
    # The detail page resolves the same snapshot.
    detail = client.get(f"/advisories/{advisory_token('CVE-2026-1234')}").text
    assert "CRITICAL: CVE-2026-1234 in widget" in detail and "7.5" in detail
    # A record whose snapshot is gone degrades to what the record itself holds, not a crash.
    stored["deliveries"].clear()
    save_state(tmp_path / "state.json", stored)
    degraded = client.get("/alerts").text
    assert "CVE-2026-1234" in degraded
    # Without the snapshot the identifier, outcome and date still filter; the snapshot's fields no longer do.
    assert "/advisories/" not in client.get("/alerts", params={"tag": "critical"}).text
    assert "/advisories/" not in client.get("/alerts", params={"q": "widget"}).text
    assert "/advisories/" in client.get("/alerts", params={"outcome": "delivered"}).text

    # A hand-edited delivery reference of the wrong type degrades instead of taking the page down.
    stored["seen"]["CVE-2026-1234"]["delivery"] = []
    save_state(tmp_path / "state.json", stored)
    assert client.get("/alerts").status_code == 200
    assert client.get(f"/advisories/{advisory_token('CVE-2026-1234')}").status_code == 200


def test_a_dropped_message_with_no_acceptor_says_so_on_the_page(tmp_path):
    state = core.new_state()
    state["parked"] = [parked_entry("CVE-2026-8888")]
    save_state(tmp_path / "state.json", state)
    assert core.manage_parked_entry(JsonStore(tmp_path / "state.json"), 0, release=False, now=NOW) is True
    stored = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    client, token, _ = make_client(tmp_path, state=stored)
    sign_in(client, token)
    page = client.get(f"/advisories/{advisory_token('CVE-2026-8888')}").text
    assert "dropped before any channel accepted it" in page


def test_a_message_naming_thousands_of_identifiers_does_not_multiply_its_snapshot():
    state = core.new_state()
    entry = pending_entry("CVE-2026-1")
    identifiers = [f"CVE-2026-{number}" for number in range(2000)]
    entry["ids"] = identifiers
    entry["cves"] = identifiers
    state["pending"].append(entry)
    assert core.deliver(state, [RecordingNotifier("ops")], no_http, NOW) is True
    assert len(state["seen"]) == 2000
    assert len(state["deliveries"]) == 1, "one snapshot for one message"
    assert all(set(record) == {"at", "outcome", "delivery"} for record in state["seen"].values())
    serialized = serialize_json(state)
    # The identifiers appear once (the snapshot) plus their keys; a per-identifier copy would be far larger.
    assert len(serialized) < 700_000, f"the persisted state grew to {len(serialized)} bytes"


def test_a_dropped_message_is_recorded_with_no_accepted_notifier(tmp_path):
    state = core.new_state()
    state["parked"] = [parked_entry("CVE-2026-7777")]
    save_state(tmp_path / "state.json", state)
    assert core.manage_parked_entry(JsonStore(tmp_path / "state.json"), 0, release=False, now=NOW) is True
    stored = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    record = stored["seen"]["CVE-2026-7777"]
    assert record["outcome"] == "dropped"
    delivery = stored["deliveries"][record["delivery"]]
    assert delivery["delivered_to"] == []
    assert delivery["tag"] == "critical"


def test_an_identifier_with_slashes_round_trips_through_the_alert_link(tmp_path):
    identifier = "src:https://vendor.example.net/advisory/42"
    state = core.new_state()
    state["seen"][identifier] = seen(NOW, tag="critical", title="A vendor advisory")
    client, token, _ = make_client(tmp_path, state=state)
    sign_in(client, token)
    page = client.get("/alerts").text
    links = re.findall(r"href='(/advisories/[^']+)'", page)
    assert len(links) == 1, "the row must link to the advisory page"
    detail = client.get(html.unescape(links[0]))
    assert detail.status_code == 200
    assert identifier in detail.text
    # A segment the list never produced is a 400 page, not a crash.
    assert client.get("/advisories/!!!!").status_code == 400
    assert client.get("/advisories/").status_code == 404


def test_two_stored_identities_that_would_share_a_replacement_get_their_own_links(tmp_path):
    """Replacing the unpaired surrogate gave both identities one token, so one row opened the other's record."""
    surrogate = "src:wh:wh:a\ud800b"
    question = "src:wh:wh:a?b"
    state = core.new_state()
    state["seen"][surrogate] = seen(NOW, title="Surrogate advisory")
    state["seen"][question] = seen(NOW, title="Question advisory")
    client, token, _ = make_client(tmp_path, state=state)
    sign_in(client, token)

    surrogate_token = _advisory_token(surrogate)
    question_token = _advisory_token(question)
    assert surrogate_token != question_token, "two identities must never share one advisory token"
    alerts = client.get("/alerts").text
    assert f"/advisories/{surrogate_token}" in alerts
    assert f"/advisories/{question_token}" in alerts

    surrogate_page = client.get(f"/advisories/{surrogate_token}")
    assert surrogate_page.status_code == 200
    assert "Surrogate advisory" in surrogate_page.text
    assert "Question advisory" not in surrogate_page.text, "the link must open its own record"
    question_page = client.get(f"/advisories/{question_token}")
    assert question_page.status_code == 200
    assert "Question advisory" in question_page.text
    assert "Surrogate advisory" not in question_page.text, "the link must open its own record"


def test_a_malformed_stored_link_renders_as_text_not_a_crash(tmp_path):
    state = core.new_state()
    entry = pending_entry("CVE-2026-7000")
    entry["link"] = "https://[broken"
    state["pending"].append(entry)
    state["seen"]["CVE-2026-7001"] = seen(NOW, tag="critical", title="Seen", link="https://[broken")
    client, token, _ = make_client(tmp_path, state=state)
    sign_in(client, token)
    for identifier in ("CVE-2026-7000", "CVE-2026-7001"):
        page = client.get(f"/advisories/{advisory_token(identifier)}")
        assert page.status_code == 200
        assert "href='https://[broken'" not in page.text, "a broken URL is not offered as a link"


def test_the_pending_page_shows_the_matched_products(tmp_path):
    entry = pending_entry("CVE-2026-6000", products=["magento", "php"])
    state = core.new_state()
    state["pending"].append(entry)
    client, token, _ = make_client(tmp_path, state=state)
    sign_in(client, token)
    page = client.get(f"/advisories/{advisory_token('CVE-2026-6000')}").text
    assert "Matched products" in page
    assert "magento" in page and "php" in page


def test_a_dropped_message_keeps_the_channel_that_already_accepted_it(tmp_path):
    entry = parked_entry("CVE-2026-9000")
    entry["sent_to"] = ["ops"]
    state = core.new_state()
    state["parked"] = [entry]
    state_path = tmp_path / "state.json"
    save_state(state_path, state)
    assert core.manage_parked_entry(JsonStore(state_path), 0, release=False, now=NOW) is True
    stored = load_state_document(state_path, core.STATE_SCHEMA, "advisory state")
    record = stored["seen"]["CVE-2026-9000"]
    assert record["outcome"] == "dropped"
    assert stored["deliveries"][record["delivery"]]["delivered_to"] == ["ops"], "the channel that accepted it"
    client, token, _ = make_client(tmp_path, state=stored)
    sign_in(client, token)
    page = client.get(f"/advisories/{advisory_token('CVE-2026-9000')}").text
    assert "ops" in page and "dropped before any channel accepted it" not in page


def test_a_stale_parked_row_does_not_act_on_the_message_that_moved_into_its_place(tmp_path):
    state = core.new_state()
    state["parked"] = [parked_entry("CVE-2026-1"), parked_entry("CVE-2026-2"), parked_entry("CVE-2026-3")]
    client, token, runtime = make_client(tmp_path, state=state)
    csrf = sign_in(client, token)
    page = client.get("/parked").text
    tokens = re.findall(r"name='token' value='([0-9a-f]{16})'", page)
    assert len(tokens) == 6, "each row offers a release and a drop, both carrying the row token"
    released = client.post("/parked/0/release", data={"csrf": csrf, "token": tokens[0]}, follow_redirects=False)
    assert released.status_code == 303
    # The page's second row now sits at position 1 but is not the message the old form named.
    stale = client.post("/parked/1/release", data={"csrf": csrf, "token": tokens[2]}, follow_redirects=False)
    assert stale.status_code == 404
    stored = load_state_document(runtime.cfg.state_path, core.STATE_SCHEMA, "advisory state")
    assert [entry["ids"][0] for entry in stored["parked"]] == ["CVE-2026-2", "CVE-2026-3"]


def test_a_notifier_reference_in_a_rule_round_trips_through_the_form(tmp_path):
    body = ROUTES_CONFIG.replace("notifiers: [phone]", 'notifiers: [phone, "${SECOND_CHANNEL}"]').replace(
        "default: [ops]", 'default: [ops, "${SECOND_CHANNEL}"]'
    )
    client, token, runtime = make_client(tmp_path, body=body, environment={**CHANNEL_ENV, "SECOND_CHANNEL": "phone"})
    csrf, fingerprint = config_form(client, token)
    page = client.get("/config").text
    assert page.count("value='${SECOND_CHANNEL}' selected") == 2, "both selects must offer the reference"
    saved = client.post(
        "/config/routes",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "route:1:tag": "critical",
            "route:1:notifiers": ["phone", "${SECOND_CHANNEL}"],
            "default": ["ops", "${SECOND_CHANNEL}"],
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    overlay = load_settings(settings_path(runtime.cfg.state_path))
    assert overlay["routes"] == [{"match": {"tag": "critical"}, "notifiers": ["phone", "${SECOND_CHANNEL}"]}]
    assert overlay["default"] == ["ops", "${SECOND_CHANNEL}"], "a configured reference must survive a save"


def test_a_default_without_a_rule_is_refused_not_silently_discarded(tmp_path):
    client, token, _ = make_client(tmp_path, body="sources: []\nnotifiers: []\n")
    csrf, fingerprint = config_form(client, token)
    response = client.post(
        "/config/routes",
        data={"csrf": csrf, "fingerprint": fingerprint, "default": ["ops"]},
        headers={"accept": "text/html"},
    )
    assert response.status_code == 400
    assert "needs at least one rule" in response.text


def test_more_than_three_rules_round_trip_through_the_form(tmp_path):
    body = ROUTES_CONFIG.replace(
        "default: [ops]",
        "  - match: {product: magento}\n"
        "    notifiers: [ops]\n"
        "  - match: {ids: 'GHSA-*'}\n"
        "    notifiers: [ops, phone]\n"
        "  - match: {source: debian}\n"
        "    notifiers: [ops]\n"
        "default: [ops]",
    )
    client, token, runtime = make_client(tmp_path, body=body, environment=CHANNEL_ENV)
    csrf, fingerprint = config_form(client, token)
    saved = client.post(
        "/config/routes",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "route:1:tag": "critical",
            "route:1:notifiers": ["phone"],
            "route:2:product": "magento",
            "route:2:notifiers": ["ops"],
            "route:3:ids": "GHSA-*",
            "route:3:notifiers": ["ops", "phone"],
            "route:4:source": "debian",
            "route:4:notifiers": ["ops"],
            "default": ["ops"],
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    overlay = load_settings(settings_path(runtime.cfg.state_path))
    assert len(overlay["routes"]) == 4, "a rule beyond the fixed rows must survive the save"
    assert overlay["routes"][3] == {"match": {"source": "debian"}, "notifiers": ["ops"]}


def test_clearing_the_default_with_rules_kept_means_no_fallback(tmp_path):
    client, token, runtime = make_client(tmp_path, body=ROUTES_CONFIG, environment=CHANNEL_ENV)
    assert runtime.cfg.default_notifiers == ("ops",)
    csrf, fingerprint = config_form(client, token)
    saved = client.post(
        "/config/routes",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "route:1:tag": "critical",
            "route:1:notifiers": ["phone"],
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    overlay = load_settings(settings_path(runtime.cfg.state_path))
    assert overlay["routes"] == [{"match": {"tag": "critical"}, "notifiers": ["phone"]}]
    assert overlay["default"] == [], "an explicit empty default must be stored, not removed"
    assert runtime.cfg.default_notifiers == (), "removing the key would have restored the YAML default"


def test_a_route_reference_round_trips_through_the_form(tmp_path):
    body = ROUTES_CONFIG.replace("match: {tag: critical}", 'match: {source: nodejs, tag: "${ROUTE_TAG}"}')
    client, token, runtime = make_client(tmp_path, body=body, environment={**CHANNEL_ENV, "ROUTE_TAG": "critical"})
    csrf, fingerprint = config_form(client, token)
    page = client.get("/config").text
    assert "value='${ROUTE_TAG}'" in page, "the configured reference must be offered, not silently dropped"
    saved = client.post(
        "/config/routes",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "route:1:source": "nodejs",
            "route:1:tag": "${ROUTE_TAG}",
            "route:1:notifiers": ["phone"],
            "default": ["ops"],
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    overlay = load_settings(settings_path(runtime.cfg.state_path))
    assert overlay["routes"] == [{"match": {"source": "nodejs", "tag": "${ROUTE_TAG}"}, "notifiers": ["phone"]}]


# --- the delivery policy and a signed-webhook secret in the forms ------------------------------


def test_digest_and_quiet_hours_round_trip_through_the_settings_form(tmp_path):
    client, token, runtime = make_client(tmp_path, body="sources: []\nnotifiers: []\n")
    csrf, fingerprint = config_form(client, token)
    page = client.get("/config").text
    assert "name='digest'" in page and "name='quiet_hours'" in page
    saved = client.post(
        "/config/settings",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "poll_interval": "15m",
            "hidden_source_hosts": "",
            "digest": "1",
            "quiet_hours": "22:00-07:00",
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303, saved.text
    overlay = load_settings(settings_path(runtime.cfg.state_path))
    assert overlay["digest"] is True and overlay["quiet_hours"] == "22:00-07:00"
    assert runtime.cfg.digest is True
    assert runtime.cfg.quiet_hours == QuietHours(22 * 60, 7 * 60)
    rendered = client.get("/config").text
    assert "name='digest' value='1' checked" in rendered
    assert "name='quiet_hours' value='22:00-07:00'" in rendered

    # Unticking the box and emptying the field turns both off, overriding the values the overlay holds.
    csrf, fingerprint = config_form(client, token)
    cleared = client.post(
        "/config/settings",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "poll_interval": "15m",
            "hidden_source_hosts": "",
            "quiet_hours": "",
        },
        follow_redirects=False,
    )
    assert cleared.status_code == 303, cleared.text
    assert runtime.cfg.digest is False and runtime.cfg.quiet_hours is None
    assert load_settings(settings_path(runtime.cfg.state_path))["quiet_hours"] == ""


def test_a_bad_quiet_hours_window_is_refused_by_the_form_without_echoing_it(tmp_path):
    client, token, runtime = make_client(tmp_path, body="sources: []\nnotifiers: []\n")
    csrf, fingerprint = config_form(client, token)
    response = client.post(
        "/config/settings",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "poll_interval": "15m",
            "hidden_source_hosts": "",
            "quiet_hours": "night-shift",
        },
    )
    assert response.status_code == 400
    assert "22:00-07:00" in response.text
    assert "night-shift" not in response.text
    assert not settings_path(runtime.cfg.state_path).exists(), "a refused window writes nothing"


def test_a_yaml_webhook_secret_survives_a_notifier_form_save(tmp_path):
    body = "sources: []\nnotifiers:\n  - id: hooks\n    type: webhook\n    url: ${HOOK}\n    secret: ${SIGNING}\n"
    environment = {"HOOK": "https://hooks.example.net/x", "SIGNING": "s3cret-value"}
    client, token, runtime = make_client(tmp_path, body=body, environment=environment)
    assert runtime.notifiers[0].secret == "s3cret-value"
    csrf, fingerprint = config_form(client, token)
    page = client.get("/config").text
    assert "name='field:hooks:secret'" in page, "the secret can be edited as a reference"
    assert "value='${SIGNING}'" in page
    assert "s3cret-value" not in page, "the credential value never reaches the page"
    # A submission without the secret field (an older page, a partial POST) must not unsign the webhook.
    saved = client.post(
        "/config/notifiers",
        data={"csrf": csrf, "fingerprint": fingerprint, "enabled:hooks": "1"},
        follow_redirects=False,
    )
    assert saved.status_code == 303, saved.text
    assert "secret" not in load_settings(settings_path(runtime.cfg.state_path))["notifiers"][0], (
        "the credential stays in the YAML and is carried over by id"
    )
    assert runtime.cfg.notifiers[0]["secret"] == "s3cret-value"
    assert runtime.notifiers[0].secret == "s3cret-value"
    assert "s3cret-value" not in settings_path(runtime.cfg.state_path).read_text()


def test_a_new_webhook_secret_is_entered_and_stored_as_a_reference(tmp_path):
    environment = {"HOOK": "https://hooks.example.net/x", "SIGNING": "s3cret-value"}
    client, token, runtime = make_client(tmp_path, body="sources: []\nnotifiers: []\n", environment=environment)
    csrf, fingerprint = config_form(client, token)
    saved = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:id": "hooks",
            "new:type": "webhook",
            "new:reference": "${HOOK}",
            "new:secret": "${SIGNING}",
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303, saved.text
    overlay = load_settings(settings_path(runtime.cfg.state_path))
    assert overlay["notifiers"][0]["secret"] == "${SIGNING}"
    assert runtime.notifiers[0].secret == "s3cret-value"
    assert "s3cret-value" not in settings_path(runtime.cfg.state_path).read_text()


def test_a_literal_webhook_secret_is_refused_by_the_form(tmp_path):
    environment = {"HOOK": "https://hooks.example.net/x"}
    client, token, runtime = make_client(tmp_path, body="sources: []\nnotifiers: []\n", environment=environment)
    csrf, fingerprint = config_form(client, token)
    response = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:id": "hooks",
            "new:type": "webhook",
            "new:reference": "${HOOK}",
            "new:secret": "s3cret-value",
        },
    )
    assert response.status_code == 400
    assert "reference" in response.text
    assert "s3cret-value" not in response.text
    assert not settings_path(runtime.cfg.state_path).exists()


# --- /advisories/{identifier} ------------------------------------------------------------------


def advisory_state() -> dict:
    state = core.new_state()
    record = snapshot(
        NOW,
        "critical",
        "Vendor Feed",
        "CRITICAL: CVE-2026-1000 in widget",
        "CVE-2026-1000",
        "critical",
        9.8,
        ["discord", "phone"],
    )
    record["levels"]["CVE-2026-1001"] = "warning"
    record["scores"]["CVE-2026-1001"] = 5.0
    state["seen"]["CVE-2026-1000"] = record
    state["seen"]["CVE-2026-LEGACY"] = seen(NOW - 100, "delivered")
    state["pending"] = [pending_entry("CVE-2026-3000", kev_only=["CVE-2026-3001"])]
    # A pending message wins over a parked one that claims the same identifier.
    state["parked"] = [parked_entry("CVE-2026-4000"), parked_entry("CVE-2026-3000", title="PARKED-DUPLICATE")]
    # The seen record wins over a pending message that also claims the identifier.
    state["seen"]["CVE-2026-DUP"] = snapshot(
        NOW, "warning", "Seen source", "Seen title", "CVE-2026-DUP", "warning", 4.0, ["ops"]
    )
    state["pending"].append(pending_entry("CVE-2026-DUP", title="Pending title", tag="critical"))
    return state


def test_the_advisory_page_shows_the_delivery_snapshot(tmp_path):
    client, token, _ = make_client(tmp_path, state=advisory_state())
    sign_in(client, token)
    page = client.get(f"/advisories/{advisory_token('CVE-2026-1000')}")
    assert page.status_code == 200
    assert "CRITICAL: CVE-2026-1000 in widget" in page.text
    assert "Vendor Feed" in page.text and "critical" in page.text
    assert "href='https://vendor.example.net/advisories/CVE-2026-1000'" in page.text
    # The per-CVE levels and the scores the message was classified with, plus the notifiers that accepted it.
    assert "CVE-2026-1001" in page.text
    assert "<td>9.8</td>" in page.text and "<td>5</td>" in page.text
    assert "discord" in page.text and "phone" in page.text
    assert "2026-10-21 16:26" in page.text


def test_the_advisory_page_finds_a_pending_and_a_parked_message(tmp_path):
    client, token, _ = make_client(tmp_path, state=advisory_state())
    sign_in(client, token)
    pending = client.get(f"/advisories/{advisory_token('CVE-2026-3000')}")
    assert pending.status_code == 200
    assert "pending" in pending.text
    assert "2 (last HTTP 500)" in pending.text
    assert "ops" in pending.text, "a pending message shows the notifiers that already accepted it"
    assert "KEV-only" in pending.text and "CVE-2026-3001" in pending.text
    assert "PARKED-DUPLICATE" not in pending.text, "a pending message is found before a parked one"
    parked = client.get(f"/advisories/{advisory_token('CVE-2026-4000')}")
    assert parked.status_code == 200
    assert "parked" in parked.text
    assert "Parked (UTC)" in parked.text
    assert "2026-10-21 16:16" in parked.text  # parked_at, rendered as UTC


def test_an_unknown_identifier_is_a_404_page(tmp_path):
    client, token, _ = make_client(tmp_path, state=advisory_state())
    sign_in(client, token)
    response = client.get(f"/advisories/{advisory_token('CVE-2026-NOPE')}", headers={"accept": "text/html"})
    assert response.status_code == 404
    assert "no advisory" in response.text


def test_a_legacy_record_says_the_details_were_not_recorded(tmp_path):
    client, token, _ = make_client(tmp_path, state=advisory_state())
    sign_in(client, token)
    page = client.get(f"/advisories/{advisory_token('CVE-2026-LEGACY')}")
    assert page.status_code == 200
    assert "not recorded" in page.text
    assert "older version" in page.text
    # Neither a score nor a level is invented for a record that never held one.
    assert "9.8" not in page.text and "CVEs and levels" not in page.text
    assert "delivered" in page.text


def test_the_seen_record_wins_and_no_message_body_is_rendered(tmp_path):
    client, token, _ = make_client(tmp_path, state=advisory_state())
    sign_in(client, token)
    duplicate = client.get(f"/advisories/{advisory_token('CVE-2026-DUP')}")
    assert "Seen title" in duplicate.text and "Pending title" not in duplicate.text
    for identifier in ("CVE-2026-3000", "CVE-2026-4000"):
        assert "BODY-MARKER" not in client.get(f"/advisories/{advisory_token(identifier)}").text
    assert "BODY-MARKER" not in client.get("/alerts").text


# --- per-entry queue actions -------------------------------------------------------------------


def test_core_releases_one_parked_message_by_position(tmp_path):
    state = core.new_state()
    state["parked"] = [parked_entry("CVE-2026-1"), parked_entry("CVE-2026-2", "warning")]
    save_state(tmp_path / "state.json", state)
    assert core.manage_parked_entry(JsonStore(tmp_path / "state.json"), 1, release=True, now=NOW) is True
    stored = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    assert [entry["ids"][0] for entry in stored["parked"]] == ["CVE-2026-1"]
    assert [entry["ids"][0] for entry in stored["pending"]] == ["CVE-2026-2"]
    released = stored["pending"][0]
    for gone in ("attempts", "first_attempt_at", "parked_at"):
        assert gone not in released, f"a released message must start its retry history again ({gone})"


def test_core_drops_one_parked_message_and_refuses_a_stale_position(tmp_path):
    state = core.new_state()
    state["parked"] = [parked_entry("CVE-2026-1"), parked_entry("CVE-2026-2", "warning")]
    save_state(tmp_path / "state.json", state)
    before = (tmp_path / "state.json").read_bytes()
    assert core.manage_parked_entry(JsonStore(tmp_path / "state.json"), 5, release=False, now=NOW) is False
    assert core.manage_parked_entry(JsonStore(tmp_path / "state.json"), -1, release=False, now=NOW) is False
    assert (tmp_path / "state.json").read_bytes() == before, "a stale position must not write the state"
    assert core.manage_parked_entry(JsonStore(tmp_path / "state.json"), 0, release=False, now=NOW) is True
    stored = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    assert [entry["ids"][0] for entry in stored["parked"]] == ["CVE-2026-2"]
    assert stored["seen"]["CVE-2026-1"]["outcome"] == "dropped"
    assert stored["pending"] == []


def test_the_parked_page_offers_one_action_per_row(tmp_path):
    state = core.new_state()
    state["parked"] = [parked_entry("CVE-2026-1"), parked_entry("CVE-2026-2", "warning")]
    client, token, _ = make_client(tmp_path, state=state)
    sign_in(client, token)
    page = client.get("/parked").text
    assert "action='/parked/0/release'" in page and "action='/parked/1/drop'" in page
    assert 'action="/parked/release"' in page and 'action="/parked/drop"' in page, "the bulk forms stay"


def test_a_per_entry_release_or_drop_changes_exactly_one_message(tmp_path):
    first, second = parked_entry("CVE-2026-1"), parked_entry("CVE-2026-2", "warning")
    state = core.new_state()
    state["parked"] = [first, second]
    client, token, _ = make_client(tmp_path, state=state)
    csrf = sign_in(client, token)
    released = client.post(
        "/parked/0/release", data={"csrf": csrf, "token": core.parked_token(first)}, follow_redirects=False
    )
    assert released.status_code == 303
    stored = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    assert [entry["ids"][0] for entry in stored["pending"]] == ["CVE-2026-1"]
    assert [entry["ids"][0] for entry in stored["parked"]] == ["CVE-2026-2"]

    dropped = client.post(
        "/parked/0/drop", data={"csrf": csrf, "token": core.parked_token(second)}, follow_redirects=False
    )
    assert dropped.status_code == 303
    stored = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    assert stored["parked"] == []
    assert stored["seen"]["CVE-2026-2"]["outcome"] == "dropped"
    assert "CVE-2026-1" not in stored["seen"], "a released message was never delivered, so it is not seen"
    assert [entry["ids"][0] for entry in stored["pending"]] == ["CVE-2026-1"]


def test_the_per_entry_queue_action_works_on_a_sqlite_store(tmp_path):
    """The queue action must read and write the configured store, not the file it used to live in."""
    first, second = parked_entry("CVE-2026-1"), parked_entry("CVE-2026-2", "warning")
    state = core.new_state()
    state["parked"] = [first, second]
    client, token, runtime = make_client(tmp_path, state=state, storage=f"sqlite:///{tmp_path}/state.db")
    assert not (tmp_path / "state.json").exists(), "a SQLite instance must not touch the JSON file"
    csrf = sign_in(client, token)
    assert "CVE-2026-2" in client.get("/parked").text, "the page reads the same store"

    released = client.post(
        "/parked/0/release", data={"csrf": csrf, "token": core.parked_token(first)}, follow_redirects=False
    )
    assert released.status_code == 303
    stored = runtime.cfg.store().load()
    assert [entry["ids"][0] for entry in stored["pending"]] == ["CVE-2026-1"]
    assert [entry["ids"][0] for entry in stored["parked"]] == ["CVE-2026-2"]

    dropped = client.post(
        "/parked/0/drop", data={"csrf": csrf, "token": core.parked_token(second)}, follow_redirects=False
    )
    assert dropped.status_code == 303
    stored = runtime.cfg.store().load()
    assert stored["parked"] == []
    assert stored["seen"]["CVE-2026-2"]["outcome"] == "dropped"


def test_a_stale_parked_index_is_a_404(tmp_path):
    state = core.new_state()
    state["parked"] = [parked_entry("CVE-2026-1")]
    client, token, _ = make_client(tmp_path, state=state)
    csrf = sign_in(client, token)
    before = (tmp_path / "state.json").read_bytes()
    response = client.post("/parked/7/release", data={"csrf": csrf, "token": "0" * 16}, headers={"accept": "text/html"})
    assert response.status_code == 404
    assert "no parked message at position 7" in response.text
    assert (tmp_path / "state.json").read_bytes() == before


def test_a_per_entry_parked_post_without_the_row_token_is_refused(tmp_path):
    state = core.new_state()
    state["parked"] = [parked_entry("CVE-2026-1")]
    client, token, _ = make_client(tmp_path, state=state)
    csrf = sign_in(client, token)
    before = (tmp_path / "state.json").read_bytes()
    for data in (
        {"csrf": csrf},
        {"csrf": csrf, "token": ""},
        {"csrf": csrf, "token": "not-a-token"},
        {"csrf": csrf, "token": "é" * 16},
    ):
        response = client.post("/parked/0/release", data=data, headers={"accept": "text/html"})
        assert response.status_code == 400, data
        assert "row token" in response.text
    assert (tmp_path / "state.json").read_bytes() == before


def test_a_per_entry_parked_post_needs_the_form_token(tmp_path):
    state = core.new_state()
    state["parked"] = [parked_entry("CVE-2026-1")]
    client, token, _ = make_client(tmp_path, state=state)
    sign_in(client, token)
    assert client.post("/parked/0/release", follow_redirects=False).status_code == 403
    assert client.post("/parked/0/drop", follow_redirects=False).status_code == 403
    stored = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    assert len(stored["parked"]) == 1 and stored["seen"] == {}


def test_a_per_entry_parked_post_answers_409_while_a_pass_holds_the_lock(tmp_path):
    state = core.new_state()
    state["parked"] = [parked_entry("CVE-2026-1")]
    client, token, runtime = make_client(tmp_path, state=state)
    csrf = sign_in(client, token)
    with state_lock(runtime.cfg.state_path):
        response = client.post(
            "/parked/0/release",
            data={"csrf": csrf, "token": core.parked_token(state["parked"][0])},
            headers={"accept": "text/html"},
        )
    assert response.status_code == 409
    assert "holds the state lock" in response.text
    stored = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    assert len(stored["parked"]) == 1


def test_the_bulk_parked_actions_still_release_and_drop(tmp_path):
    state = core.new_state()
    state["parked"] = [parked_entry("CVE-2026-1"), parked_entry("CVE-2026-2", "warning")]
    client, token, _ = make_client(tmp_path, state=state)
    csrf = sign_in(client, token)
    assert client.post("/parked/release", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    stored = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    assert stored["parked"] == [] and [entry["ids"][0] for entry in stored["pending"]] == ["CVE-2026-1", "CVE-2026-2"]

    state["parked"] = [parked_entry("CVE-2026-3")]
    save_state(runtime_state_path(tmp_path), state)
    assert client.post("/parked/drop", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    stored = load_state_document(tmp_path / "state.json", core.STATE_SCHEMA, "state")
    assert stored["parked"] == [] and stored["seen"]["CVE-2026-3"]["outcome"] == "dropped"


def runtime_state_path(tmp_path: Path) -> Path:
    return tmp_path / "state.json"


# --- the routes form ---------------------------------------------------------------------------


def routes_page(client: TestClient, token: str = TOKEN) -> tuple[str, str, str]:
    """The login token, the form fingerprint and the /config page text."""
    csrf, fingerprint = config_form(client, token)
    return csrf, fingerprint, client.get("/config").text


def test_an_empty_routes_form_keeps_the_yaml_rules(tmp_path):
    client, token, runtime = make_client(tmp_path, body=ROUTES_CONFIG, environment=CHANNEL_ENV)
    csrf, fingerprint, page = routes_page(client, token)
    assert "route:1:source" in page and "route:2:source" in page and "route:3:source" in page
    assert "value='critical' selected" in page and "value='phone' selected" in page, "the form is prefilled"
    saved = client.post("/config/routes", data={"csrf": csrf, "fingerprint": fingerprint}, follow_redirects=False)
    assert saved.status_code == 303
    assert runtime.cfg.routes == ({"match": {"tag": "critical"}, "notifiers": ("phone",)},)
    assert runtime.cfg.default_notifiers == ("ops",)
    overlay = load_settings(settings_path(runtime.cfg.state_path))
    assert "routes" not in overlay and "default" not in overlay, "an empty form leaves the YAML in force"


def test_a_route_added_on_the_form_is_used_by_the_next_pass(tmp_path):
    client, token, runtime = make_client(tmp_path, body=ROUTES_CONFIG, environment=CHANNEL_ENV)
    csrf, fingerprint, _ = routes_page(client, token)
    saved = client.post(
        "/config/routes",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            # The browser submits the rows it rendered: the critical rule stays, a nodejs rule is added.
            "route:1:tag": "critical",
            "route:1:notifiers": ["phone"],
            "route:2:source": "nodejs",
            "route:2:notifiers": ["ops"],
            "default": ["ops"],
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    assert runtime.cfg.routes == (
        {"match": {"tag": "critical"}, "notifiers": ("phone",)},
        {"match": {"source": "nodejs"}, "notifiers": ("ops",)},
    )
    # The next render is prefilled from the saved overlay, not from the YAML it replaced.
    rendered = client.get("/config").text
    assert "value='nodejs'" in rendered and "value='critical' selected" in rendered

    # The delivery step of the next pass, with the configuration the save made live.
    state = core.new_state()
    state["pending"].append(pending_entry("CVE-2026-1", source_id="nodejs", sent_to=[]))
    ops, phone = RecordingNotifier("ops"), RecordingNotifier("phone")
    assert core.deliver(
        state, [ops, phone], no_http, NOW, routes=runtime.cfg.routes, default=runtime.cfg.default_notifiers
    )
    assert [len(notifier.sent) for notifier in (ops, phone)] == [1, 0], "the nodejs rule selects ops only"

    state["pending"].append(pending_entry("CVE-2026-2", tag="critical", source_id="nodejs", sent_to=[]))
    assert core.deliver(
        state, [ops, phone], no_http, NOW, routes=runtime.cfg.routes, default=runtime.cfg.default_notifiers
    )
    assert [len(notifier.sent) for notifier in (ops, phone)] == [1, 1], "the first matching rule wins"


def test_a_route_may_select_a_notifier_the_overlay_added(tmp_path):
    body = "sources: []\nnotifiers:\n  - id: phone\n    type: ntfy\n    url: ${PHONE_HOOK}\n    topic: alerts\n"
    client, token, runtime = make_client(tmp_path, body=body, environment=CHANNEL_ENV)
    csrf, fingerprint, _ = routes_page(client, token)
    added = client.post(
        "/config/notifiers",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:id": "ops",
            "new:type": "ntfy",
            "new:reference": "${OPS_HOOK}",
            "new:topic": "advisories",
        },
        follow_redirects=False,
    )
    assert added.status_code == 303
    csrf, fingerprint, _ = routes_page(client, token)
    selected = client.post(
        "/config/routes",
        data={"csrf": csrf, "fingerprint": fingerprint, "route:1:source": "nodejs", "route:1:notifiers": ["ops"]},
        follow_redirects=False,
    )
    assert selected.status_code == 303, selected.text
    assert runtime.cfg.routes == ({"match": {"source": "nodejs"}, "notifiers": ("ops",)},)


def test_an_invalid_route_renders_the_validator_error_and_writes_nothing(tmp_path):
    client, token, runtime = make_client(tmp_path, body=ROUTES_CONFIG, environment=CHANNEL_ENV)
    csrf, fingerprint, _ = routes_page(client, token)
    response = client.post(
        "/config/routes",
        data={"csrf": csrf, "fingerprint": fingerprint, "route:1:tag": "critical"},
    )
    assert response.status_code == 400
    assert "routes[1]: notifiers must be a non-empty list of notifier ids" in response.text
    assert not settings_path(runtime.cfg.state_path).exists(), "nothing is written when the validator refuses"
    assert runtime.cfg.routes == ({"match": {"tag": "critical"}, "notifiers": ("phone",)},)


def test_a_stale_routes_form_is_refused(tmp_path):
    client, token, runtime = make_client(tmp_path, body=ROUTES_CONFIG, environment=CHANNEL_ENV)
    csrf, stale_fingerprint, _ = routes_page(client, token)
    first = client.post(
        "/config/routes",
        data={"csrf": csrf, "fingerprint": stale_fingerprint, "route:1:source": "nodejs", "route:1:notifiers": ["ops"]},
        follow_redirects=False,
    )
    assert first.status_code == 303
    stale = client.post(
        "/config/routes",
        data={
            "csrf": csrf,
            "fingerprint": stale_fingerprint,
            "route:1:source": "other",
            "route:1:notifiers": ["phone"],
        },
        follow_redirects=False,
    )
    assert stale.status_code == 409
    assert runtime.cfg.routes == ({"match": {"source": "nodejs"}, "notifiers": ("ops",)},)


def test_the_routes_overlay_stores_ids_and_never_a_channel_secret(tmp_path):
    client, token, runtime = make_client(tmp_path, body=ROUTES_CONFIG, environment=CHANNEL_ENV)
    csrf, fingerprint, _ = routes_page(client, token)
    saved = client.post(
        "/config/routes",
        data={"csrf": csrf, "fingerprint": fingerprint, "route:1:source": "nodejs", "route:1:notifiers": ["ops"]},
        follow_redirects=False,
    )
    assert saved.status_code == 303
    overlay = settings_path(runtime.cfg.state_path).read_text()
    assert "ops" in overlay
    for secret in CHANNEL_ENV.values():
        assert secret not in overlay
        assert "url" not in overlay


# --- scripts/capture_screenshots.py ------------------------------------------------------------


def load_capture_module():
    path = Path(__file__).resolve().parent.parent / "scripts" / "capture_screenshots.py"
    spec = importlib.util.spec_from_file_location("capture_screenshots_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_screenshot_demo_data_names_no_estate_identifier():
    capture = load_capture_module()
    document = yaml.safe_load(capture.demo_config(Path("data/state.json")))
    hosts = {urllib.parse.urlsplit(source["url"]).hostname for source in document["sources"]}
    hosts |= {
        urllib.parse.urlsplit(notifier["url"]).hostname
        for notifier in document["notifiers"]
        if not notifier["url"].startswith("${")
    }
    assert hosts <= {"nodejs.org", "www.debian.org", "rss.example.net", "changes.example.net"}
    for notifier in document["notifiers"]:
        assert notifier["url"].startswith("${"), "a channel credential is only ever a reference"
    state = capture.demo_state(now=NOW)
    identifiers = set(state["seen"])
    for queue in ("pending", "parked"):
        for entry in state[queue]:
            identifiers |= set(entry["ids"])
    assert identifiers == set(capture.DEMO_ADVISORIES) | {capture.DEMO_LEGACY}
    assert all(
        re.fullmatch(r"(CVE|GHSA|DSA|PSA|APSB)[A-Za-z0-9]*[-:][A-Za-z0-9.: -]+", identifier)
        for identifier in identifiers
    ), "every demo identifier is a synthetic advisory id"
    json.dumps(state)  # the demo state is what save_state writes


def test_the_capture_script_refuses_a_missing_playwright_with_the_documented_message(monkeypatch):
    capture = load_capture_module()
    monkeypatch.setitem(sys.modules, "playwright", None)
    with pytest.raises(SystemExit) as refused:
        capture.load_playwright()
    message = str(refused.value)
    assert "uv run --with playwright python scripts/capture_screenshots.py" in message
    assert "playwright install chromium" in message


def test_the_overlay_routes_replace_the_yaml_block_and_one_validator_checks_membership(tmp_path):
    path = tmp_path / "config.yml"
    path.write_text(
        "sources: []\n"
        "notifiers:\n"
        "  - id: ops\n    type: ntfy\n    url: https://ntfy.example.net/ops\n    topic: advisories\n"
        "  - id: phone\n    type: ntfy\n    url: https://ntfy.example.net/phone\n    topic: alerts\n"
        "routes:\n"
        "  - match: {tag: critical}\n    notifiers: [phone]\n"
        "default: [ops]\n"
        f"state_path: {tmp_path}/state.json\n"
    )
    overlay = {"routes": [{"match": {"source": "nodejs"}, "notifiers": ["ops"]}], "default": ["phone"]}
    cfg = load_config(path, {}, settings=overlay)
    assert cfg.routes == ({"match": {"source": "nodejs"}, "notifiers": ("ops",)},)
    assert cfg.default_notifiers == ("phone",)
    # Membership is judged after the merge by the configuration validator, not by the overlay's own check.
    with pytest.raises(ConfigError, match="not an enabled notifier"):
        load_config(
            path,
            {},
            settings={"routes": [{"match": {"tag": "critical"}, "notifiers": ["ghost"]}]},
        )


#: The exact policy every page carries. Pinned here so a change to it is a deliberate change, not drift.
EXPECTED_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)


def _assert_shell(response, *, active: str, status: int) -> None:
    """The contract every page shares, whatever its status code, body or session."""
    assert response.status_code == status
    assert response.headers["content-security-policy"] == EXPECTED_CSP
    text = response.text
    assert "<html lang='en'>" in text
    assert "<meta name='viewport'" in text
    title = re.search(r"<title>(.*?)</title>", text)
    assert text.count("<title>") == 1 and text.count("</title>") == 1
    assert title is not None
    heading = re.search(r"<h1>(.*?)</h1>", text)
    assert text.count("<h1>") == 1 and heading is not None
    assert title.group(1) == f"{heading.group(1)} · advisory-radar", "the tab names the page it shows"
    assert text.count("<style>") == 1 and text.count("</style>") == 1, "one inline stylesheet"
    assert text.count("<main") == 1 and "<main id='main'>" in text
    assert "<a class='skip' href='#main'>Skip to content</a>" in text
    assert "<script" not in text and " onclick=" not in text and " style=" not in text
    # The stylesheet names the selector too, so the attribute is counted with its leading space.
    assert text.count(" aria-current='page'") == (1 if active else 0)
    if active:
        assert f"<a href='{active}' aria-current='page'>" in text


def test_every_page_carries_the_same_shell(tmp_path):
    """One shell on every page: a language, a viewport, one title, one h1, one current section.

    A rendered page cannot be unit-tested for its look, but the contract the stylesheet, the navigation and
    the security headers depend on can: an error page and a signed-out page included, so a page added later
    cannot quietly lose its landmarks, its per-page title or its session chrome.
    """
    state = core.new_state()
    state["seen"]["CVE-2026-1"] = {"at": NOW, "outcome": "delivered", "tag": "critical", "title": "Seen"}
    client, token, _ = make_client(tmp_path, state=state)
    csrf = sign_in(client, token)
    assert csrf
    pages = {
        "/": "/",
        "/alerts": "/alerts",
        "/parked": "/parked",
        "/config": "/config",
        "/sources": "/sources",
        "/runs": "/runs",
        "/thresholds": "/config",
        f"/advisories/{advisory_token('CVE-2026-1')}": "/alerts",
    }
    # A page route added later must join this test instead of silently going unchecked.
    served = {
        route.path
        for route in client.app.routes
        if "GET" in (getattr(route, "methods", None) or set()) and "{" not in getattr(route, "path", "")
    }
    assert served - set(pages) == {"/login", "/healthz", "/readyz", "/metrics", "/api/state", "/openapi.json"}
    for path, active in pages.items():
        response = client.get(path, headers={"accept": "text/html"})
        _assert_shell(response, active=active, status=200)
        assert 'action="/logout"' in response.text, f"{path} must offer sign out"

    # An unknown identifier is a 404 of the section it was reached from, chrome included.
    missing = client.get(f"/advisories/{advisory_token('CVE-2026-404')}", headers={"accept": "text/html"})
    _assert_shell(missing, active="/alerts", status=404)
    assert 'action="/logout"' in missing.text

    # A refused save is an authenticated configuration page, not a bare error.
    stale = client.post(
        "/config/settings",
        data={"csrf": csrf, "fingerprint": "0" * 64},
        headers={"accept": "text/html"},
    )
    _assert_shell(stale, active="/config", status=409)
    assert 'action="/logout"' in stale.text

    # A refused form token still renders the section the action came from.
    for path, active in (("/run", "/"), ("/reload", "/config"), ("/logout", "")):
        refused = client.post(path, data={"csrf": "0" * 64}, headers={"accept": "text/html"})
        _assert_shell(refused, active=active, status=403)

    # Signed out: the brand alone, the login page still signs in, and the throttle has a page too.
    client.cookies.clear()
    login = client.get("/login", headers={"accept": "text/html"})
    _assert_shell(login, active="", status=200)
    assert "<nav class='links'" not in login.text
    for _ in range(6):
        throttled = client.post("/login", data={"token": "nope"}, headers={"accept": "text/html"})
        if throttled.status_code == 429:
            break
    else:
        raise AssertionError("six wrong tokens must be refused by the login throttle")
    _assert_shell(throttled, active="", status=429)


def test_a_stored_value_is_data_not_a_lookup_key(tmp_path):
    """A malformed stored value is shown as the absence it is; it used to raise or render a Python repr.

    The state loader validates the document's shape, not each field's type, so a hand-edited record can hold a
    list where a string or an integer belongs. Nothing rendered may hash that value or show its repr: the
    alert list, the advisory page, the parked queue, the dashboard and the run history are all checked.
    """
    state = core.new_state()
    state["seen"]["CVE-2026-1"] = {
        "at": NOW,
        "outcome": ["delivered"],
        "tag": ["critical"],
        "title": {"unexpected": "mapping"},
        "link": ["https://vendor.example.net/advisory"],
        "ids": ["CVE-2026-1", {"nested": "mapping"}],
        "levels": {"CVE-2026-1": ["critical"]},
        "scores": {"CVE-2026-1": {"unexpected": "mapping"}},
    }
    state["parked"] = [{"tag": ["critical"], "title": {"unexpected": "mapping"}, "ids": ["CVE-2026-2"]}]
    state["runs"] = [{"at": NOW, "code": ["0"], "sent": 0, "parked": 0, "pending": 0}]
    save_state(tmp_path / "state.json", state)
    client, token, _ = make_client(tmp_path, state=state)
    sign_in(client, token)
    pages = ("/", "/alerts", "/parked", "/runs", f"/advisories/{advisory_token('CVE-2026-1')}")
    for path in pages:
        response = client.get(path)
        assert response.status_code == 200, path
        shown = html.unescape(response.text)
        for rendered in ("['delivered']", "['critical']", "{'unexpected'", "['0']"):
            assert rendered not in shown, f"{path} must not render {rendered}"
    # An unusable exit code is unknown, not a recorded failure.
    assert "<span class='badge badge-neutral'>?</span>" in client.get("/runs").text
    assert "<span class='badge badge-neutral'>?</span>" in client.get("/").text
