"""The /config forms are rendered from the source and notifier catalogues (U05, #103).

Driven through HTTP only: the page a browser gets, the form it posts back, and the files and the live runtime
that result. Markup is asserted where the form *is* the contract (field names, anchors, links) and behaviour
everywhere else.
"""

from __future__ import annotations

import html
import json
import logging
import re
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from advisory_radar import core, messages
from advisory_radar.catalogue import NOTIFIER_SPECS, SOURCE_SPECS
from advisory_radar.runtime import Runtime
from advisory_radar.state import state_lock
from advisory_radar.web import create_app

TOKEN = "secret-token-0123456789abcdef"
CSRF_RE = re.compile(r'name="csrf" value="([0-9a-f]{64})"')
FINGERPRINT_RE = re.compile(r"name='fingerprint' value='([0-9a-f]{64})'")
REVISION_RE = re.compile(r"name='revision' value='(\d+)'")
NOW = 1792600000

#: Three configured notifiers (one each of ntfy, smtp and webhook) and the variables a form may name.
CONFIG = """\
sources: []
notifiers:
  - id: ops
    type: ntfy
    url: ${OPS_HOOK}
    topic: advisories
  - id: mail
    type: smtp
    host: smtp.example.net
    from: radar@example.net
    to: ops@example.net
    password: ${SMTP_PASSWORD}
  - id: hook
    type: webhook
    url: ${HOOK_URL}
    headers:
      X-Api-Key: ${HOOK_KEY}
overlay_references: [NEW_URL, NEW_PASSWORD, NEW_TOKEN, NEW_KEY, NEW_SECRET]
"""
REFERENCES = "overlay_references: [NEW_URL, NEW_PASSWORD, NEW_TOKEN, NEW_KEY, NEW_SECRET]\n"
#: No notifier at all, and exactly one: the smallest documents a save can be judged against.
EMPTY = "sources: []\nnotifiers: []\n" + REFERENCES
ONE = "sources: []\nnotifiers:\n  - id: ops\n    type: ntfy\n    url: ${OPS_HOOK}\n    topic: advisories\n" + REFERENCES
ENV = {
    "OPS_HOOK": "https://ntfy.example.net/OPS-HOOK-VALUE",
    "SMTP_PASSWORD": "SMTP-PASSWORD-VALUE",
    "HOOK_URL": "https://hooks.example.net/HOOK-URL-VALUE",
    "HOOK_KEY": "HOOK-KEY-VALUE",
    "NEW_URL": "https://new.example.net/NEW-URL-VALUE",
    "NEW_PASSWORD": "NEW-PASSWORD-VALUE",
    "NEW_TOKEN": "NEW-TOKEN-VALUE",
    "NEW_KEY": "NEW-KEY-VALUE",
    "NEW_SECRET": "NEW-SECRET-VALUE",
    "UNLISTED": "UNLISTED-VALUE",
}


class Page:
    """A signed-in client over a real runtime, with the form state every /config form carries."""

    def __init__(
        self, tmp_path: Path, *, body: str = CONFIG, http=None, clock: int = NOW, extra_env: dict | None = None
    ) -> None:
        # Every host answers as a public address, so a source the page adds or probes is judged on its URL alone.
        self.tmp_path = tmp_path
        self.config_path = tmp_path / "config.yml"
        self.config_path.write_text(f"{body}\nstate_path: {tmp_path / 'state.json'}\n")
        self.env = {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN, **ENV, **(extra_env or {})}
        self.runtime = Runtime.build(self.config_path, self.env, clock=lambda: float(clock))
        self.runtime.cfg.store().save(core.new_state())
        self.sent: list[dict] = []
        self.http = http if http is not None else self.record
        self.app = create_app(
            self.runtime, self.env, clock=lambda: float(clock), http=self.http, resolve=lambda host: ["93.184.216.34"]
        )
        self.client = TestClient(self.app)
        response = self.client.post("/login", data={"token": TOKEN}, follow_redirects=False)
        assert response.status_code == 303
        self.client.cookies.set("advisory_radar_session", response.cookies.get("advisory_radar_session"))

    def record(self, method, url, headers, body):
        """The default transport: answers 200 and remembers what was posted."""
        self.sent.append({"method": method, "url": url, "body": body})
        return 200, {}, b""

    def get(self, path: str = "/config"):
        return self.client.get(path)

    def state(self, path: str = "/config") -> dict[str, str]:
        """The csrf token, fingerprint and revision a form on this page carries."""
        text = self.get(path).text
        csrf, fingerprint, revision = CSRF_RE.search(text), FINGERPRINT_RE.search(text), REVISION_RE.search(text)
        assert csrf and fingerprint and revision
        return {"csrf": csrf.group(1), "fingerprint": fingerprint.group(1), "revision": revision.group(1)}

    def post(self, path: str, **fields: str):
        return self.client.post(path, data={**self.state(), **fields}, follow_redirects=False)

    @property
    def overlay_file(self) -> Path:
        return self.tmp_path / "settings.json"

    def overlay(self) -> dict:
        return json.loads(self.overlay_file.read_text())["settings"]


def block(text: str, start: str, end: str) -> str:
    """The part of a page from the first ``start`` to the next ``end``; both have to be there."""
    head = text.index(start)
    return text[head : text.index(end, head)]


def notifier_rows(text: str) -> dict[str, str]:
    """The markup of every configured notifier row, by notifier id."""
    rows = {}
    for chunk in text.split("<div class='notifier'>")[1:]:
        identifier = re.search(r"<b>([^<]+)</b>", chunk)
        assert identifier
        rows[html.unescape(identifier.group(1))] = chunk.split("<h3", 1)[0]
    return rows


# --- anchored sections ---------------------------------------------------------------------------


def test_the_page_is_one_page_with_an_anchor_for_every_section(tmp_path):
    text = Page(tmp_path).get().text
    for anchor in ("settings", "thresholds", "sources", "notifiers", "routes"):
        assert re.search(rf"<h2 id='{anchor}'>", text), f"section {anchor} has no anchor"
        assert f"href='#{anchor}'" in text, f"nothing links to section {anchor}"


# --- the catalogue is on the page before anything is submitted --------------------------------------


def test_every_notifier_type_is_listed_with_what_it_needs_before_submission(tmp_path):
    text = Page(tmp_path).get().text
    section = block(text, "id='notifiers'", "id='routes'")
    for kind, spec in NOTIFIER_SPECS.items():
        assert f"<b>{kind}</b>" in section, kind
        assert html.escape(spec.summary) in section, kind
        assert f"<td>{', '.join(spec.required) or '(none)'}</td>" in section, kind
        assert f"<td>{', '.join(spec.secret_keys) or '(none)'}</td>" in section, kind
        assert f"<td>{', '.join(spec.yaml_only) or '(none)'}</td>" in section, kind
        assert f"href='/config?add_notifier={kind}#new-notifier'" in section, kind
    assert "overlay_references" in section, "the page says which variables a reference may name"
    assert "set when the notifier is added" in section, "the page says what a configured row cannot change"


NEW_FIELDS = {
    "apprise": {"new:reference", "new:password", "new:key"},
    "discord_webhook": {"new:reference"},
    "webhook": {"new:reference", "new:secret"},
    "matrix_webhook": {"new:reference"},
    "ntfy": {"new:reference", "new:topic", "new:priority"},
    "gotify": {"new:reference", "new:token", "new:priority"},
    "smtp": {
        "new:reference",
        "new:host",
        "new:port",
        "new:from",
        "new:to",
        "new:username",
        "new:use_tls",
        "new:implicit_tls",
    },
    "log": set(),
}


def test_the_table_of_new_fields_covers_every_catalogue_type():
    assert set(NEW_FIELDS) == set(NOTIFIER_SPECS)


@pytest.mark.parametrize("kind", sorted(NOTIFIER_SPECS))
def test_choosing_a_type_shows_that_types_fields_and_no_others(tmp_path, kind):
    spec = NOTIFIER_SPECS[kind]
    text = Page(tmp_path).get(f"/config?add_notifier={kind}").text
    form = block(text, "id='new-notifier'", "id='routes'")
    names = set(re.findall(r"name='(new:[^']+)'", form))
    assert names == {"new:type", "new:id", *NEW_FIELDS[kind]}
    assert f"name='new:type' value='{kind}'" in form, "the form says which type it adds"
    assert html.escape(spec.summary) in form
    assert html.escape(yaml.safe_dump(spec.example, sort_keys=False)) in form, "the example is on the page"
    for key in spec.yaml_only:
        assert f"name='new:{key}'" not in form
        assert f"{key}</code> is set in the YAML" in form, f"{key} is marked YAML-only before submission"
    for key in spec.required:
        assert re.search(rf"{key}[^<]*<span class='muted small'>\(required", form), f"{key} is not marked required"
    if spec.secret_keys:
        assert "overlay_references" in form and "environment variable" in form
    assert f"href='/config?add_notifier={kind}#new-notifier'" in text


def test_an_unknown_type_in_the_url_opens_nothing_and_is_not_echoed(tmp_path):
    response = Page(tmp_path).get("/config?add_notifier=nope%3Cscript%3E")
    assert response.status_code == 200
    assert "id='new-notifier'" not in response.text
    assert "nope" not in response.text and "<script>" not in response.text


# --- the existing rows show only the keys their type reads --------------------------------------------


def test_each_configured_row_renders_only_the_keys_of_its_type(tmp_path):
    rows = notifier_rows(Page(tmp_path).get().text)
    assert set(rows) == {"ops", "mail", "hook"}
    assert {*re.findall(r"name='field:ops:([a-z_]+)'", rows["ops"])} == {"topic", "priority"}
    assert {*re.findall(r"name='field:mail:([a-z_]+)'", rows["mail"])} == {
        "host",
        "port",
        "from",
        "to",
        "username",
        "use_tls",
        "implicit_tls",
    }
    assert {*re.findall(r"name='field:hook:([a-z_]+)'", rows["hook"])} == {"secret"}
    assert "headers" in rows["hook"] and "YAML" in rows["hook"], "a YAML-only key is named on the row"
    assert "name='enabled:ops'" in rows["ops"]


def test_saving_a_row_leaves_keys_it_did_not_render_alone(tmp_path):
    """A key the type does not read stays as the file wrote it: only rendered fields are the form's to change."""
    legacy = ONE.replace("    topic: advisories\n", "    topic: advisories\n    host: legacy.example.net\n")
    page = Page(tmp_path, body=legacy)
    response = page.post("/config/notifiers", **{"enabled:ops": "1", "field:ops:topic": "alerts"})
    assert response.status_code == 303
    saved = {entry["id"]: entry for entry in page.overlay()["notifiers"]}
    assert saved["ops"]["topic"] == "alerts"
    assert saved["ops"]["host"] == "legacy.example.net"


# --- every type can be added from the page --------------------------------------------------------------

ADD = {
    "apprise": {"new:reference": "${NEW_URL}", "new:password": "${NEW_PASSWORD}", "new:key": "${NEW_KEY}"},
    "discord_webhook": {"new:reference": "${NEW_URL}"},
    "webhook": {"new:reference": "${NEW_URL}", "new:secret": "${NEW_SECRET}"},
    "matrix_webhook": {"new:reference": "${NEW_URL}"},
    "ntfy": {"new:reference": "${NEW_URL}", "new:topic": "alerts", "new:priority": "4"},
    "gotify": {"new:reference": "${NEW_URL}", "new:token": "${NEW_TOKEN}", "new:priority": "6"},
    "smtp": {
        "new:reference": "${NEW_PASSWORD}",
        "new:host": "relay.example.net",
        "new:port": "2525",
        "new:from": "radar@example.net",
        "new:to": "oncall@example.net",
        "new:username": "radar",
        "new:use_tls": "true",
    },
    "log": {},
}
STORED = {
    "apprise": {"url": "${NEW_URL}", "password": "${NEW_PASSWORD}", "key": "${NEW_KEY}"},
    "discord_webhook": {"url": "${NEW_URL}"},
    "webhook": {"url": "${NEW_URL}", "secret": "${NEW_SECRET}"},
    "matrix_webhook": {"url": "${NEW_URL}"},
    "ntfy": {"url": "${NEW_URL}", "topic": "alerts", "priority": "4"},
    "gotify": {"url": "${NEW_URL}", "token": "${NEW_TOKEN}", "priority": "6"},
    "smtp": {
        "password": "${NEW_PASSWORD}",
        "host": "relay.example.net",
        "port": "2525",
        "from": "radar@example.net",
        "to": "oncall@example.net",
        "username": "radar",
        "use_tls": "true",
    },
    "log": {},
}


def test_the_add_tables_cover_every_catalogue_type():
    assert set(ADD) == set(STORED) == set(NOTIFIER_SPECS)


@pytest.mark.parametrize("kind", sorted(NOTIFIER_SPECS))
def test_every_type_can_be_added_with_the_fields_its_form_shows(tmp_path, kind):
    page = Page(tmp_path, body=EMPTY)
    response = page.post("/config/notifiers", **{"new:id": f"n-{kind}", "new:type": kind, **ADD[kind]})
    assert response.status_code == 303, response.text
    added = {entry["id"]: entry for entry in page.overlay()["notifiers"]}[f"n-{kind}"]
    assert added == {"id": f"n-{kind}", "type": kind, **STORED[kind]}
    live = {notifier.id: notifier for notifier in page.runtime.notifiers}[f"n-{kind}"]
    assert type(live).__name__.lower().startswith(kind.split("_")[0]), "the live notifier is of the chosen type"


@pytest.mark.parametrize(
    ("kind", "given", "message"),
    [
        ("apprise", {"new:reference": "${NEW_URL}"}, "apprise needs password"),
        ("gotify", {"new:reference": "${NEW_URL}"}, "gotify needs token"),
        ("ntfy", {"new:reference": "${NEW_URL}"}, "ntfy needs topic"),
        ("ntfy", {"new:topic": "alerts"}, "ntfy needs url"),
        ("smtp", {"new:host": "relay.example.net"}, "smtp needs from, to"),
        ("discord_webhook", {}, "discord_webhook needs url"),
    ],
)
def test_a_missing_required_key_is_named_in_words_and_nothing_is_written(tmp_path, kind, given, message):
    page = Page(tmp_path, body=EMPTY)
    response = page.post("/config/notifiers", **{"new:id": "n", "new:type": kind, **given})
    assert response.status_code == 400
    assert message in response.text
    assert "KeyError" not in response.text
    assert not page.overlay_file.exists(), "a refused save writes nothing"


def test_a_filled_block_without_an_id_is_refused_not_dropped(tmp_path):
    page = Page(tmp_path, body=EMPTY)
    response = page.post("/config/notifiers", **{"new:type": "ntfy", "new:topic": "alerts"})
    assert response.status_code == 400
    assert "needs an id" in response.text
    assert not page.overlay_file.exists()


def test_an_untouched_block_is_not_a_notifier(tmp_path):
    page = Page(tmp_path, body=ONE)
    response = page.post(
        "/config/notifiers", **{"new:type": "ntfy", "enabled:ops": "1", "field:ops:topic": "advisories"}
    )
    assert response.status_code == 303
    assert [entry["id"] for entry in page.overlay()["notifiers"]] == ["ops"]


def test_clearing_a_required_key_of_an_enabled_row_is_refused_in_words(tmp_path):
    page = Page(tmp_path, body=ONE)
    response = page.post("/config/notifiers", **{"enabled:ops": "1", "field:ops:topic": ""})
    assert response.status_code == 400
    assert "ops (ntfy) needs topic" in response.text
    assert not page.overlay_file.exists()


def test_a_disabled_row_is_never_built_so_it_may_lack_a_required_key(tmp_path):
    page = Page(tmp_path, body=ONE)
    assert page.post("/config/notifiers", **{"field:ops:topic": ""}).status_code == 303
    assert page.overlay()["notifiers"][0]["enabled"] is False


# --- an explicit test message: confirm first, then one real message through the running notifier ------------

OPS = "  - id: ops\n    type: ntfy\n    url: ${OPS_HOOK}\n    topic: advisories\n"
OFF = "  - id: standby\n    type: log\n    enabled: false\n"
WITH_OFF = "sources: []\nnotifiers:\n" + OPS + OFF + REFERENCES
TEST_TITLE = messages.level_title("en", "warning", messages.text("en", "test.title"))
TEST_BODY = messages.text("en", "test.body")
CONFIRM_FORM = 'action="/config/notifiers/test/confirm"'


def confirmation_form(text: str) -> dict[str, str]:
    """The fields the confirmation page's form posts back, as a browser would send them."""
    form = block(text, CONFIRM_FORM, "</form>")
    return {
        html.unescape(name): html.unescape(value)
        for name, value in re.findall(r"name=['\"]([^'\"]+)['\"] value=['\"]([^'\"]*)['\"]", form)
    }


def confirm(page: Page, identifier: str):
    """Send the test message the way a browser does: ask, then post the form the confirmation page returned.

    The form carries the binding to the notifier it was shown for, so a send is only ever made from a page that was
    asked for; the binding is read from the page, never computed here.
    """
    ask = page.post("/config/notifiers/test", id=identifier)
    assert ask.status_code == 200, "the confirmation page is offered"
    return page.client.post("/config/notifiers/test/confirm", data=confirmation_form(ask.text))


def test_a_row_offers_a_test_message_only_while_it_is_enabled(tmp_path):
    rows = notifier_rows(Page(tmp_path, body=WITH_OFF).get().text)
    assert "formaction='/config/notifiers/test'" in rows["ops"]
    assert "name='id' value='ops'" in rows["ops"]
    assert "formaction='/config/notifiers/test'" not in rows["standby"]


def test_the_first_click_shows_what_would_be_sent_and_sends_nothing(tmp_path):
    page = Page(tmp_path)
    response = page.post("/config/notifiers/test", id="ops")
    assert response.status_code == 200
    assert html.escape(TEST_TITLE) in response.text and html.escape(TEST_BODY) in response.text
    assert 'action="/config/notifiers/test/confirm"' in response.text
    assert "name='id' value='ops'" in response.text
    assert page.sent == []


def test_the_confirmation_form_is_what_actually_sends(tmp_path):
    page = Page(tmp_path)
    ask = page.post("/config/notifiers/test", id="ops")
    csrf = CSRF_RE.search(ask.text)
    assert csrf, "the confirmation page carries its own form token"
    live = confirmation_form(ask.text)["live"]  # the binding the page carries, read the way a browser reads it
    sent = page.client.post("/config/notifiers/test/confirm", data={"csrf": csrf.group(1), "id": "ops", "live": live})
    assert sent.status_code == 200
    assert len(page.sent) == 1


def test_confirming_sends_one_real_message_through_the_running_notifier_and_shows_the_status(tmp_path):
    page = Page(tmp_path)
    response = confirm(page, "ops")
    assert response.status_code == 200
    assert [item["url"] for item in page.sent] == [ENV["OPS_HOOK"]]
    payload = json.loads(page.sent[0]["body"])
    assert payload["topic"] == "advisories" and payload["title"] == TEST_TITLE
    assert TEST_BODY in payload["message"]
    assert "200" in response.text and "Accepted" in response.text
    assert "OPS-HOOK-VALUE" not in response.text, "the expanded destination is never shown"


def test_a_notifier_takes_three_test_messages_a_minute_and_the_others_are_not_affected(tmp_path):
    page = Page(tmp_path)
    for _ in range(3):
        assert confirm(page, "ops").status_code == 200
    refused = confirm(page, "ops")
    assert refused.status_code == 429
    assert int(refused.headers["retry-after"]) >= 1
    assert [item["url"] for item in page.sent] == [ENV["OPS_HOOK"]] * 3, "the refused one sent nothing"
    assert confirm(page, "hook").status_code == 200
    assert page.sent[-1]["url"] == ENV["HOOK_URL"]


def test_a_notifier_that_is_not_running_is_not_tested(tmp_path):
    page = Page(tmp_path, body=WITH_OFF)
    for path in ("/config/notifiers/test", "/config/notifiers/test/confirm"):
        disabled = page.post(path, id="standby")
        assert disabled.status_code == 409
        assert "not running" in disabled.text
        assert page.post(path, id="nope").status_code == 404
    assert page.sent == []


def test_a_notifier_saved_while_a_pass_holds_the_lock_is_not_tested_until_it_is_live(tmp_path):
    page = Page(tmp_path, body=EMPTY)
    with state_lock(page.runtime.cfg.state_path):
        assert page.post("/config/notifiers", **{"new:id": "n", "new:type": "ntfy", **ADD["ntfy"]}).status_code == 303
        row = notifier_rows(page.get().text)["n"]
        assert "not live yet" in row, "the row says that a test would not reach it"
        assert page.post("/config/notifiers/test/confirm", id="n").status_code == 409
    assert page.sent == []


# A test goes through the notifier that is running, so the row, the confirmation and the send have to agree on it: an
# id that is running as something else than the saved row says is not tested, and a confirmation is only good for
# the notifier it was shown for.

DISCORD_OPS = "sources: []\nnotifiers:\n  - id: ops\n    type: discord_webhook\n    url: ${OPS_HOOK}\n" + REFERENCES
SMTP_OPS = (
    "sources: []\nnotifiers:\n  - id: ops\n    type: smtp\n    host: smtp.example.net\n    from: radar@example.net\n"
    "    to: ops@example.net\n    password: ${SMTP_PASSWORD}\n" + REFERENCES
)


def edit_yaml(page: Page, body: str) -> None:
    """Replace the YAML file the way an operator does by hand: the running process has not read it."""
    page.config_path.write_text(f"{body}\nstate_path: {page.tmp_path / 'state.json'}\n")


def test_a_notifier_whose_type_was_edited_in_the_yaml_is_not_tested_before_the_reload(tmp_path):
    page = Page(tmp_path, body=DISCORD_OPS)
    edit_yaml(page, SMTP_OPS)  # the notifier that is running is still the Discord webhook
    assert "not live yet" in notifier_rows(page.get().text)["ops"], "the row says that a test would not reach it"
    for path in ("/config/notifiers/test", "/config/notifiers/test/confirm"):
        refused = page.post(path, id="ops")
        assert refused.status_code == 409
        assert "not running" in refused.text and "Nothing was sent" in refused.text
        assert CONFIRM_FORM not in refused.text, "there is nothing to confirm"
    assert page.sent == []


def test_a_notifier_whose_topic_was_saved_while_a_pass_holds_the_lock_is_not_tested_until_it_is_live(tmp_path):
    page = Page(tmp_path, body=ONE)
    with state_lock(page.runtime.cfg.state_path):
        assert page.post("/config/notifiers", **{"enabled:ops": "1", "field:ops:topic": "elsewhere"}).status_code == 303
        assert page.overlay()["notifiers"][0]["topic"] == "elsewhere"
        assert "not live yet" in notifier_rows(page.get().text)["ops"], "the saved row is not what is running"
        for path in ("/config/notifiers/test", "/config/notifiers/test/confirm"):
            refused = page.post(path, id="ops")
            assert refused.status_code == 409
            assert "not running" in refused.text and CONFIRM_FORM not in refused.text
    assert page.sent == []
    # Once the reload has applied it, the same row is live and a test goes to the topic it shows.
    assert page.post("/reload").status_code == 303
    assert "not live yet" not in notifier_rows(page.get().text)["ops"]
    assert confirm(page, "ops").status_code == 200
    assert json.loads(page.sent[0]["body"])["topic"] == "elsewhere"


def test_the_whole_confirmation_form_sends_when_nothing_changed_in_between(tmp_path):
    page = Page(tmp_path, body=ONE)
    assert "not live yet" not in notifier_rows(page.get().text)["ops"], "a row that is running as saved is not marked"
    ask = page.post("/config/notifiers/test", id="ops")
    assert ask.status_code == 200 and "<span class='muted'>ntfy</span>" in ask.text
    form = confirmation_form(ask.text)
    assert set(form) == {"csrf", "id", "live"}
    assert re.fullmatch(r"[0-9a-f]{64}", form["live"]), "the form is bound to the notifier it was shown for"
    sent = page.client.post("/config/notifiers/test/confirm", data=form)
    assert sent.status_code == 200 and "Accepted" in sent.text
    assert [item["url"] for item in page.sent] == [ENV["OPS_HOOK"]]


@pytest.mark.parametrize("kind", NOTIFIER_SPECS)
def test_a_notifier_that_runs_as_saved_is_not_marked_and_is_bound_whatever_its_type(tmp_path, kind):
    example = NOTIFIER_SPECS[kind].example
    env = {name: "dummy-value" for name in re.findall(r"\$\{([A-Z_][A-Z0-9_]*)\}", yaml.safe_dump(example))}
    page = Page(tmp_path, body=yaml.safe_dump({"sources": [], "notifiers": [example]}), extra_env=env)
    assert "not live yet" not in notifier_rows(page.get().text)[example["id"]]
    # Asked and never confirmed: an smtp notifier does not go through the recording transport.
    ask = page.post("/config/notifiers/test", id=example["id"])
    assert ask.status_code == 200
    assert re.fullmatch(r"[0-9a-f]{64}", confirmation_form(ask.text)["live"])


def test_a_secret_file_replaced_after_the_last_reload_is_not_tested_until_it_is_reloaded(tmp_path):
    secret = tmp_path / "ops-url"
    secret.write_text("https://ntfy.example.net/OLD-SECRET\n")
    body = "sources: []\nnotifiers:\n  - id: ops\n    type: ntfy\n    url: ${OPS_URL_FILE}\n    topic: advisories\n"
    page = Page(tmp_path, body=body, extra_env={"OPS_URL_FILE": str(secret)})
    secret.write_text("https://ntfy.example.net/NEW-SECRET\n")  # the notifier that is running still holds the old one
    assert "not live yet" in notifier_rows(page.get().text)["ops"]
    assert page.post("/config/notifiers/test/confirm", id="ops").status_code == 409
    assert page.sent == []
    assert page.post("/reload").status_code == 303
    assert confirm(page, "ops").status_code == 200
    assert [item["url"] for item in page.sent] == ["https://ntfy.example.net/NEW-SECRET"]


@pytest.mark.parametrize(
    ("written", "rewritten"),
    [("topic: advisories", "topic: elsewhere"), ("url: ${OPS_HOOK}", "url: ${HOOK_URL}")],
    ids=["another topic", "another variable for the url"],
)
def test_a_reload_between_the_confirmation_and_the_send_refuses_the_send(tmp_path, written, rewritten):
    page = Page(tmp_path, body=ONE)
    ask = page.post("/config/notifiers/test", id="ops")
    assert ask.status_code == 200
    form = confirmation_form(ask.text)
    page.config_path.write_text(page.config_path.read_text().replace(written, rewritten))
    assert page.post("/reload").status_code == 303
    assert "not live yet" not in notifier_rows(page.get().text)["ops"], "the edit is live: row and notifier agree"
    refused = page.client.post("/config/notifiers/test/confirm", data=form)
    assert refused.status_code == 409
    assert "changed after this confirmation" in refused.text and "Nothing was sent" in refused.text
    assert page.sent == []
    # Asking again confirms what is running now, and that form sends.
    again = page.post("/config/notifiers/test", id="ops")
    assert page.client.post("/config/notifiers/test/confirm", data=confirmation_form(again.text)).status_code == 200
    assert len(page.sent) == 1


def test_a_secret_file_replaced_and_reloaded_between_the_confirmation_and_the_send_refuses_the_send(tmp_path):
    secret = tmp_path / "ops-url"
    secret.write_text("https://ntfy.example.net/OLD-SECRET\n")
    body = "sources: []\nnotifiers:\n  - id: ops\n    type: ntfy\n    url: ${OPS_URL_FILE}\n    topic: advisories\n"
    page = Page(tmp_path, body=body, extra_env={"OPS_URL_FILE": str(secret)})
    form = confirmation_form(page.post("/config/notifiers/test", id="ops").text)
    secret.write_text("https://ntfy.example.net/NEW-SECRET\n")  # the entry reads the same, the destination does not
    assert page.post("/reload").status_code == 303
    assert "not live yet" not in notifier_rows(page.get().text)["ops"], "the new secret is live: row and notifier agree"
    refused = page.client.post("/config/notifiers/test/confirm", data=form)
    assert refused.status_code == 409 and "changed after this confirmation" in refused.text
    assert page.sent == []


def test_a_literal_url_edited_and_reloaded_between_the_confirmation_and_the_send_refuses_the_send(tmp_path):
    page = Page(tmp_path, body=ONE.replace("url: ${OPS_HOOK}", "url: https://ntfy.example.net/first"))
    form = confirmation_form(page.post("/config/notifiers/test", id="ops").text)
    page.config_path.write_text(page.config_path.read_text().replace("/first", "/second"))
    assert page.post("/reload").status_code == 303
    refused = page.client.post("/config/notifiers/test/confirm", data=form)
    assert refused.status_code == 409 and "changed after this confirmation" in refused.text
    assert page.sent == []


def test_the_binding_of_a_confirmation_cannot_be_recomputed_from_the_notifier_it_names(tmp_path):
    bound = []
    for name in ("one", "other"):  # one configuration, two apps: a digest of the entry alone would agree
        (tmp_path / name).mkdir()
        bound.append(confirmation_form(Page(tmp_path / name).post("/config/notifiers/test", id="ops").text)["live"])
    assert bound[0] != bound[1], "anyone holding the entry's text could check a guess at its credential against it"


@pytest.mark.parametrize(
    "bound", ["", "0" * 64, "not-a-digest", "café"], ids=["empty", "another notifier", "not a digest", "not ASCII"]
)
def test_a_confirmation_bound_to_something_else_than_the_running_notifier_sends_nothing(tmp_path, bound):
    page = Page(tmp_path)
    refused = page.post("/config/notifiers/test/confirm", id="ops", live=bound)
    assert refused.status_code == 409
    assert "changed after this confirmation" in refused.text
    assert page.sent == []


def test_a_refused_confirmation_does_not_use_up_the_test_quota(tmp_path):
    page = Page(tmp_path)
    for _ in range(4):  # a notifier takes three test messages a minute: counted, the fourth would be a 429
        assert page.post("/config/notifiers/test/confirm", id="ops", live="0" * 64).status_code == 409
    assert confirm(page, "ops").status_code == 200
    assert len(page.sent) == 1


def test_a_confirmation_without_the_binding_sends_nothing_and_uses_no_quota(tmp_path):
    page = Page(tmp_path)
    for _ in range(4):  # no `live` field at all, as in a request that never came from the confirmation page
        refused = page.post("/config/notifiers/test/confirm", id="ops")
        assert refused.status_code == 409
        assert "changed after this confirmation" in refused.text and "Nothing was sent" in refused.text
    assert page.sent == []
    for _ in range(3):  # a notifier takes three test messages a minute, and none of them went to the refusals
        assert confirm(page, "ops").status_code == 200
    assert confirm(page, "ops").status_code == 429
    assert len(page.sent) == 3


def test_the_confirmation_page_carries_no_value_a_reference_names(tmp_path):
    ask = Page(tmp_path).post("/config/notifiers/test", id="ops")
    assert ask.status_code == 200
    assert not [name for name, value in ENV.items() if value in ask.text], "a value a reference names is on the page"


def test_both_test_routes_need_the_session_and_the_form_token(tmp_path):
    page = Page(tmp_path)
    anonymous = TestClient(page.app)
    for path in ("/config/notifiers/test", "/config/notifiers/test/confirm"):
        assert page.client.post(path, data={"id": "ops"}).status_code == 403
        assert anonymous.post(path, data={"id": "ops"}, follow_redirects=False).status_code in {303, 403}
    assert page.sent == []


def test_a_destination_that_refuses_is_reported_as_not_delivered(tmp_path):
    page = Page(tmp_path, http=lambda method, url, headers, body: (500, {}, b""))
    response = confirm(page, "ops")
    assert response.status_code == 200
    assert "Not delivered" in response.text and "500" in response.text


def test_an_error_while_sending_is_reported_without_the_destination(tmp_path):
    def broken(method, url, headers, body):
        raise RuntimeError(f"cannot reach {url}")

    page = Page(tmp_path, http=broken)
    response = confirm(page, "ops")
    assert response.status_code == 200
    assert "Not delivered" in response.text and "RuntimeError" in response.text
    assert "OPS-HOOK-VALUE" not in response.text


def test_a_test_message_writes_neither_state_nor_overlay(tmp_path):
    page = Page(tmp_path)
    state_file = tmp_path / "state.json"
    before = state_file.read_bytes()
    assert confirm(page, "ops").status_code == 200  # asks first, then confirms: neither writes anything
    assert len(page.sent) == 1
    assert state_file.read_bytes() == before
    assert not page.overlay_file.exists()


def test_a_sent_test_message_is_logged_once_without_the_destination(tmp_path, caplog):
    page = Page(tmp_path)
    with caplog.at_level(logging.INFO, logger="advisory_radar"):
        confirm(page, "ops")
    lines = [record.getMessage() for record in caplog.records if "test message" in record.getMessage()]
    assert lines == ["test message sent through ops: status 200"]


# --- a refused save gives the page back with what was typed ------------------------------------------------------

LITERAL = "https://literal.example.net/LITERAL-TOKEN-VALUE"


def typed(text: str, name: str) -> str | None:
    """The value of the text input ``name`` on a page, unescaped; None when the page has no such input."""
    match = re.search(rf"name='{re.escape(name)}' value='([^']*)'", text)
    return html.unescape(match.group(1)) if match else None


def test_a_refused_new_notifier_comes_back_with_what_was_typed_but_not_the_literal(tmp_path):
    page = Page(tmp_path, body=EMPTY)
    response = page.post(
        "/config/notifiers",
        **{"new:id": "n", "new:type": "ntfy", "new:reference": LITERAL, "new:topic": "alerts", "new:priority": "4"},
    )
    assert response.status_code == 400
    assert "Not saved" in response.text and "reference" in response.text
    assert "id='new-notifier'" in response.text, "the form for the chosen type is open again"
    assert [typed(response.text, name) for name in ("new:id", "new:topic", "new:priority")] == ["n", "alerts", "4"]
    assert typed(response.text, "new:reference") == "", "a literal in a credential position is never sent back"
    assert "LITERAL-TOKEN-VALUE" not in response.text
    assert not page.overlay_file.exists()


def test_a_whole_reference_is_given_back_when_something_else_was_wrong(tmp_path):
    page = Page(tmp_path, body=EMPTY)
    response = page.post("/config/notifiers", **{"new:id": "n", "new:type": "ntfy", "new:reference": "${NEW_URL}"})
    assert response.status_code == 400 and "ntfy needs topic" in response.text
    assert typed(response.text, "new:reference") == "${NEW_URL}"
    assert ENV["NEW_URL"] not in response.text, "the reference is shown, never what it expands to"


def test_a_refusal_keeps_the_edits_made_to_the_rows_too(tmp_path):
    page = Page(tmp_path, body=ONE)
    response = page.post(
        "/config/notifiers",
        **{"field:ops:topic": "changed", "field:ops:priority": "5", "new:id": "x", "new:type": "ntfy"},
    )
    assert response.status_code == 400 and "ntfy needs url, topic" in response.text
    row = notifier_rows(response.text)["ops"]
    assert [typed(row, "field:ops:topic"), typed(row, "field:ops:priority")] == ["changed", "5"]
    assert "name='enabled:ops' value='1' checked" not in row, "the box that was left unchecked stays unchecked"
    assert not page.overlay_file.exists()


def test_a_reference_in_a_plain_field_comes_back_as_typed_never_as_what_it_expands_to(tmp_path):
    page = Page(tmp_path, body=EMPTY)
    response = page.post(
        "/config/notifiers",
        **{"new:id": "n", "new:type": "ntfy", "new:reference": "${NEW_URL}", "new:topic": "${UNLISTED}"},
    )
    assert response.status_code == 400 and "overlay_references" in response.text
    assert typed(response.text, "new:topic") == "${UNLISTED}"
    assert "UNLISTED-VALUE" not in response.text and "NEW-URL-VALUE" not in response.text
    assert not page.overlay_file.exists()


def test_the_redrawn_page_carries_fresh_form_state_and_the_corrected_form_saves(tmp_path):
    page = Page(tmp_path, body=EMPTY)
    refused = page.post("/config/notifiers", **{"new:id": "n", "new:type": "ntfy", "new:reference": "${NEW_URL}"})
    assert refused.status_code == 400
    state = {
        "csrf": CSRF_RE.search(refused.text).group(1),
        "fingerprint": FINGERPRINT_RE.search(refused.text).group(1),
        "revision": REVISION_RE.search(refused.text).group(1),
    }
    fields = {"new:id": "n", "new:type": "ntfy", "new:reference": "${NEW_URL}", "new:topic": "alerts"}
    saved = page.client.post("/config/notifiers", data={**state, **fields}, follow_redirects=False)
    assert saved.status_code == 303
    assert [entry["id"] for entry in page.overlay()["notifiers"]] == ["n"]


# --- sources: the same catalogue-driven form ----------------------------------------------------------------------

#: The four built-in types spelled out, so a catalogue edit that changes what a form asks for is a visible diff
#: here. The generic tests below read the catalogue instead and so cover a type added later without an edit.
KNOWN_SOURCE_FIELDS = {
    "rss": {"new:url", "new:interval"},
    "freshrss": {"new:url", "new:token", "new:user", "new:interval"},
    "changedetection": {"new:url", "new:api_key", "new:interval"},
    "webhook": {"new:interval"},
}


def source_field_names(spec) -> set[str]:
    """The fields the form for one source type posts: its keys, minus the ones a row owns, and the shared ones."""
    keys = {key for key in (*spec.required, *spec.optional) if key not in {"id", "type", "enabled", "tag"}}
    return {"new:type", "new:id", "new:interval", *(f"new:{key}" for key in keys)}


FEED = "https://feeds.example.net/security.xml"
SOURCE_BODY = "sources: []\nnotifiers: []\n" + REFERENCES


@pytest.mark.parametrize("kind", sorted(KNOWN_SOURCE_FIELDS))
def test_the_four_built_in_source_types_ask_for_exactly_these_fields(tmp_path, kind):
    form = block(Page(tmp_path).get(f"/config?add_source={kind}").text, "id='new-source'", "id='notifiers'")
    assert set(re.findall(r"name='(new:[^']+)'", form)) == {"new:type", "new:id", *KNOWN_SOURCE_FIELDS[kind]}


def test_every_source_type_is_listed_with_what_it_needs_before_submission(tmp_path):
    text = Page(tmp_path).get().text
    section = block(text, "id='sources'", "id='notifiers'")
    for kind, spec in SOURCE_SPECS.items():
        assert f"<b>{kind}</b>" in section, kind
        assert html.escape(spec.summary) in section, kind
        assert f"<td>{', '.join(spec.required) or '(none)'}</td>" in section, kind
        assert f"<td>{', '.join(spec.secret_keys) or '(none)'}</td>" in section, kind
        assert f"href='/config?add_source={kind}#new-source'" in section, kind
    assert "overlay_references" in section


@pytest.mark.parametrize("kind", sorted(SOURCE_SPECS))
def test_choosing_a_source_type_shows_that_types_fields_and_no_others(tmp_path, kind):
    spec = SOURCE_SPECS[kind]
    text = Page(tmp_path).get(f"/config?add_source={kind}").text
    form = block(text, "id='new-source'", "id='notifiers'")
    assert set(re.findall(r"name='(new:[^']+)'", form)) == source_field_names(spec)
    assert f"name='new:type' value='{kind}'" in form, "the form says which type it adds"
    assert html.escape(spec.summary) in form
    assert html.escape(yaml.safe_dump(spec.example, sort_keys=False)) in form, "the example is on the page"
    for key in spec.required:
        assert re.search(rf"{key}[^<]*<span class='muted small'>\(required", form), f"{key} is not marked required"
    if spec.secret_keys:
        assert "overlay_references" in form and "environment variable" in form
    assert "formaction='/config/sources/probe'" in form, "the type's form can be tested before it is saved"
    assert f"href='/config?add_source={kind}#new-source'" in text


def test_a_source_type_is_needed_to_see_the_source_form_and_an_unknown_one_opens_nothing(tmp_path):
    page = Page(tmp_path)
    assert "id='new-source'" not in page.get().text
    response = page.get("/config?add_source=nope%3Cscript%3E")
    assert response.status_code == 200
    assert "id='new-source'" not in response.text
    assert "nope" not in response.text and "<script>" not in response.text


def test_a_refused_new_source_comes_back_with_what_was_typed_but_not_the_literal(tmp_path):
    page = Page(tmp_path, body=SOURCE_BODY)
    response = page.post(
        "/config/sources",
        **{
            "new:type": "freshrss",
            "new:id": "reader",
            "new:url": "https://rss.example.net",
            "new:token": "LITERAL-TOKEN-VALUE",
            "new:user": "radar",
            "new:interval": "30m",
        },
    )
    assert response.status_code == 400
    assert "Not saved" in response.text and "id='new-source'" in response.text
    for name, value in (
        ("new:id", "reader"),
        ("new:url", "https://rss.example.net"),
        ("new:user", "radar"),
        ("new:interval", "30m"),
    ):
        assert typed(response.text, name) == value, name
    assert typed(response.text, "new:token") == "", "a literal in a credential position is never sent back"
    assert "LITERAL-TOKEN-VALUE" not in response.text
    assert not page.overlay_file.exists()


def test_a_new_source_that_needs_an_id_keeps_the_rest_of_the_block(tmp_path):
    page = Page(tmp_path, body=SOURCE_BODY)
    response = page.post("/config/sources", **{"new:type": "webhook", "new:interval": "30m"})
    assert response.status_code == 400 and "needs an id" in response.text
    assert "name='new:type' value='webhook'" in response.text
    assert typed(response.text, "new:interval") == "30m"


def test_a_failed_probe_of_an_unsaved_source_gives_the_form_back_to_be_corrected(tmp_path):
    page = Page(tmp_path, body=SOURCE_BODY, http=lambda method, url, headers, body: (503, {}, b""))
    response = page.post("/config/sources/probe", **{"new:type": "rss", "new:id": "vendor", "new:url": FEED})
    assert response.status_code == 200, "a probe that fails is an answer, as it always was"
    assert "503" in response.text, "what the probe met is still shown"
    assert "id='new-source'" in response.text and "id='settings'" in response.text, "the whole page, form open"
    assert [typed(response.text, name) for name in ("new:id", "new:url")] == ["vendor", FEED]
    assert not page.overlay_file.exists(), "a probe stores nothing"


def test_a_probe_that_cannot_start_for_a_missing_field_gives_the_form_back_too(tmp_path):
    page = Page(tmp_path, body=SOURCE_BODY)
    response = page.post("/config/sources/probe", **{"new:type": "freshrss", "new:url": "https://rss.example.net"})
    assert response.status_code == 400 and "freshrss needs token" in response.text
    assert typed(response.text, "new:url") == "https://rss.example.net"


INPUT_RE = re.compile(r"<input\b([^>]*)>")
ATTRIBUTE_RE = re.compile(r"""([\w:-]+)(?:=(?:'([^']*)'|"([^"]*)"))?""")


def submitted(text: str, action: str) -> dict[str, str]:
    """What a browser posts when the default button of the form with this ``action`` is pressed.

    Hidden and text inputs with their value, and only the checkboxes that are ticked; no button, because the
    default one has no name. It reads the page as rendered, so a replay sends exactly what the page offered.
    """
    start = re.search(rf"""<form method=["']post["'] action=["']{re.escape(action)}["']>""", text)
    assert start, f"no form posts to {action}"
    form = text[start.end() : text.index("</form>", start.end())]
    data: dict[str, str] = {}
    for tag in INPUT_RE.findall(form):
        attributes = {
            found.group(1): html.unescape(found.group(2) if found.group(2) is not None else found.group(3) or "")
            for found in ATTRIBUTE_RE.finditer(tag)
        }
        if "name" not in attributes or (attributes.get("type") == "checkbox" and "checked" not in attributes):
            continue
        data[attributes["name"]] = attributes.get("value", "")
    return data


@pytest.mark.parametrize(
    ("new_block", "status"),
    [
        pytest.param({"new:type": "rss", "new:id": "second", "new:url": FEED}, 200, id="the probe fails"),
        pytest.param(
            {"new:type": "freshrss", "new:id": "second", "new:url": "https://rss.example.net"},
            400,
            id="the probe cannot start",
        ),
    ],
)
def test_a_probe_from_a_page_that_a_save_has_overtaken_gives_back_the_saved_rows(tmp_path, new_block, status):
    """The answer carries the form state of now, so its rows must be the rows of now and not those of the old page."""
    page = Page(tmp_path, body=SOURCE_BODY, http=lambda method, url, headers, body: (503, {}, b""))
    assert page.post("/config/sources", **{"new:type": "rss", "new:id": "vendor", "new:url": FEED}).status_code == 303
    old_tab = submitted(page.get().text, "/config/sources")
    other_tab = submitted(page.get().text, "/config/sources")
    overtaken = page.client.post("/config/sources", data={**other_tab, "tag:vendor": "newer"}, follow_redirects=False)
    assert overtaken.status_code == 303
    assert page.overlay()["sources_added"][0]["tag"] == "newer"

    probe = page.client.post("/config/sources/probe", data={**old_tab, **new_block}, follow_redirects=False)

    assert probe.status_code == status, probe.text
    assert typed(probe.text, "new:id") == "second", "what the probe was asked about comes back"
    assert typed(probe.text, "tag:vendor") == "newer", "the row is drawn from what is saved, not from the old tab"
    rows_only = {name: value for name, value in submitted(probe.text, "/config/sources").items() if name[:4] != "new:"}
    assert page.client.post("/config/sources", data=rows_only, follow_redirects=False).status_code == 303
    assert page.overlay()["sources_added"][0].get("tag") == "newer", "the form given back must not undo the save"


def test_a_refused_edit_of_an_added_source_comes_back_as_typed(tmp_path):
    page = Page(tmp_path, body=SOURCE_BODY)
    assert page.post("/config/sources", **{"new:type": "rss", "new:id": "vendor", "new:url": FEED}).status_code == 303
    response = page.post(
        "/config/sources",
        **{"enabled:vendor": "1", "tag:vendor": "typed-tag", "interval:vendor": "45m", "added_url:vendor": ""},
    )
    assert response.status_code == 400 and "vendor: rss needs url" in response.text
    assert [typed(response.text, name) for name in ("tag:vendor", "interval:vendor", "added_url:vendor")] == [
        "typed-tag",
        "45m",
        "",
    ]


def example_references(spec) -> list[str]:
    """The variables a type's example names, which a config has to list before the page accepts them."""
    return sorted(set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)\}", yaml.safe_dump(spec.example))))


@pytest.mark.parametrize("kind", sorted(SOURCE_SPECS))
def test_the_form_the_page_draws_for_a_type_saves_that_type(tmp_path, kind):
    """What the page renders is what the handler reads: fill each rendered field from the type's own example."""
    spec = SOURCE_SPECS[kind]
    names = example_references(spec)
    body = "sources: []\nnotifiers: []\n" + f"overlay_references: [{', '.join(names)}]\n"
    page = Page(tmp_path, body=body, extra_env={name: "dummy-value" for name in names})
    form = block(page.get(f"/config?add_source={kind}").text, "id='new-source'", "id='notifiers'")
    rendered = set(re.findall(r"name='(new:[^']+)'", form))
    fields = {name: str(spec.example[name[4:]]) for name in rendered if name[4:] in spec.example}
    assert fields["new:type"] == kind
    response = page.post("/config/sources", **fields)
    assert response.status_code == 303, response.text
    (stored,) = page.overlay()["sources_added"]
    expected = {key: value for key, value in spec.example.items() if key not in {"tag", "enabled"}}
    assert {key: stored[key] for key in expected} == expected
    assert stored["type"] == kind


def test_a_new_source_keeps_the_interval_the_form_asked_for(tmp_path):
    page = Page(tmp_path, body=SOURCE_BODY)
    page.post("/config/sources", **{"new:type": "rss", "new:id": "vendor", "new:url": FEED, "new:interval": "30m"})
    (stored,) = page.overlay()["sources_added"]
    assert stored["interval"] == "30m"


def test_an_unticked_row_stays_unticked_when_the_form_is_given_back(tmp_path):
    page = Page(tmp_path, body=SOURCE_BODY)
    assert page.post("/config/sources", **{"new:type": "rss", "new:id": "vendor", "new:url": FEED}).status_code == 303
    response = page.post("/config/sources", **{"tag:vendor": "x", "new:type": "webhook", "new:interval": "30m"})
    assert response.status_code == 400 and "needs an id" in response.text
    assert re.search(r"name='enabled:vendor' value='1' aria-label", response.text), "typed unticked, shown unticked"
    assert typed(response.text, "tag:vendor") == "x"


def test_a_form_that_carried_no_row_does_not_redraw_the_rows_from_it(tmp_path):
    # The probe page's "Add this source" form posts the new block alone: an absent row is not an unticked one.
    page = Page(tmp_path, body=SOURCE_BODY)
    fields = {"new:type": "rss", "new:id": "vendor", "new:url": FEED}
    assert page.post("/config/sources", **fields).status_code == 303
    response = page.post("/config/sources", **fields)
    assert response.status_code == 400 and "already configured" in response.text
    assert re.search(r"name='enabled:vendor' value='1' checked", response.text), "the stored state is shown"


def test_a_literal_typed_into_a_rows_credential_is_refused_and_never_given_back(tmp_path):
    page = Page(tmp_path, body=SOURCE_BODY)
    added = {
        "new:type": "freshrss",
        "new:id": "reader",
        "new:url": "https://rss.example.net",
        "new:token": "${NEW_TOKEN}",
    }
    assert page.post("/config/sources", **added).status_code == 303
    response = page.post("/config/sources", **{"enabled:reader": "1", "added_token:reader": "LITERAL-TOKEN-VALUE"})
    assert response.status_code == 400
    assert "LITERAL-TOKEN-VALUE" not in response.text
    assert typed(response.text, "added_token:reader") == ""
    assert page.overlay()["sources_added"][0]["token"] == "${NEW_TOKEN}", "the refused edit changed nothing"


def test_a_reference_typed_into_a_credential_field_is_given_back_as_the_reference(tmp_path):
    page = Page(tmp_path, body=SOURCE_BODY)
    response = page.post(
        "/config/sources",
        **{"new:type": "freshrss", "new:url": "https://rss.example.net", "new:token": "${NEW_TOKEN}", "new:user": ""},
    )
    assert response.status_code == 303, "a listed reference and a derived id are a valid source"
    unlisted = page.post(
        "/config/sources",
        **{"new:type": "freshrss", "new:url": "https://rss.example.net", "new:token": "${UNLISTED}"},
    )
    assert unlisted.status_code == 400 and "overlay_references" in unlisted.text
    assert typed(unlisted.text, "new:token") == "${UNLISTED}", "a reference is a name, and the person typed it"
    assert ENV["UNLISTED"] not in unlisted.text, "the value it names is never expanded into the page"


def test_an_open_but_empty_block_does_not_get_in_the_way_of_saving_rows(tmp_path):
    page = Page(tmp_path, body=SOURCE_BODY)
    assert page.post("/config/sources", **{"new:type": "rss", "new:id": "vendor", "new:url": FEED}).status_code == 303
    row = {"enabled:vendor": "1", "tag:vendor": "", "interval:vendor": "", "added_url:vendor": FEED}
    empty_block = {"new:type": "rss", "new:id": "", "new:url": "", "new:interval": ""}
    response = page.post("/config/sources", **row, **empty_block)
    assert response.status_code == 303, response.text


def test_the_form_given_back_can_be_corrected_and_saved(tmp_path):
    page = Page(tmp_path, body=SOURCE_BODY)
    refused = page.post(
        "/config/sources", **{"new:type": "freshrss", "new:id": "reader", "new:url": "https://rss.example.net"}
    )
    assert refused.status_code == 400 and "freshrss needs token" in refused.text
    state = {
        "csrf": CSRF_RE.search(refused.text).group(1),
        "fingerprint": FINGERPRINT_RE.search(refused.text).group(1),
        "revision": REVISION_RE.search(refused.text).group(1),
    }
    fixed = {name: typed(refused.text, name) for name in ("new:type", "new:id", "new:url")}
    saved = page.client.post(
        "/config/sources", data={**state, **fixed, "new:token": "${NEW_TOKEN}"}, follow_redirects=False
    )
    assert saved.status_code == 303, saved.text
    assert page.overlay()["sources_added"][0]["token"] == "${NEW_TOKEN}"
