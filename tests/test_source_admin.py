"""Adding, editing, testing and watching a source from the browser.

Four owners meet here: the catalogue says which keys a kind declares, the settings overlay may add a source
the YAML does not define, the probe performs the same fetch a pass performs, and the state records one health
line per source. Every test below is about one of those boundaries, because a source the operator cannot
configure or cannot see failing is the same failure.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml
from fastapi.testclient import TestClient

from advisory_radar import core, pipeline
from advisory_radar.config import ConfigError, load_config, load_document
from advisory_radar.http import urllib_http
from advisory_radar.runtime import Runtime
from advisory_radar.settings import validate_settings
from advisory_radar.state import save_state
from advisory_radar.web import create_app

#: Two entries, so a probe has something to count and a title to show.
RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Vendor</title>
<link>https://vendor.example.net/</link>
<item><title>CVE-2026-1111 fixed in libfoo</title><link>https://vendor.example.net/adv/1</link>
<guid>adv-1</guid><description>Fixes CVE-2026-1111.</description></item>
<item><title>CVE-2026-2222 fixed in libbar</title><link>https://vendor.example.net/adv/2</link>
<guid>adv-2</guid><description>Fixes CVE-2026-2222.</description></item>
</channel></rss>"""

CSRF_RE = re.compile(r'name="csrf" value="([0-9a-f]{64})"')
FINGERPRINT_RE = re.compile(r"name='fingerprint' value='([0-9a-f]{64})'")
TOKEN = "secret"


def fake_http(method: str, url: str, headers, body) -> tuple[int, dict[str, str], bytes]:
    if "bad.example.net" in url:
        return 404, {}, b"no such feed"
    return 200, {"ETag": '"v1"'}, RSS


def write_config(tmp_path: Path, sources: list[dict] | None = None, extra: str = "") -> Path:
    path = tmp_path / "config.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "sources": sources
                if sources is not None
                else [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"}],
                "notifiers": [{"id": "chat", "type": "webhook", "url": "https://hooks.example.net/x"}],
                "state_path": str(tmp_path / "data" / "state.json"),
            }
        )
        + extra
    )
    return path


def make_client(tmp_path: Path, sources: list[dict] | None = None, environment: dict[str, str] | None = None):
    """A signed-out client, the runtime it serves and the config file behind it."""
    path = write_config(tmp_path, sources)
    env = {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN, **(environment or {})}
    runtime = Runtime.build(path, env)
    return TestClient(create_app(runtime, env, http=fake_http)), runtime, path


def signed_in(client: TestClient) -> tuple[str, str]:
    """Log in and return the config page's form token and the fingerprint it rendered."""
    response = client.post("/login", data={"token": TOKEN}, follow_redirects=False)
    assert response.status_code == 303
    client.cookies.set("advisory_radar_session", response.cookies.get("advisory_radar_session"))
    page = client.get("/config").text
    csrf = CSRF_RE.search(page)
    fingerprint = FINGERPRINT_RE.search(page)
    assert csrf and fingerprint
    return csrf.group(1), fingerprint.group(1)


def overlay(tmp_path: Path) -> dict:
    """The settings overlay as it is stored on the volume."""
    return json.loads((tmp_path / "data" / "settings.json").read_text())["settings"]


def new_source(client: TestClient, **fields: str):
    """Post the "new source" block of the config page and return the response."""
    csrf, fingerprint = signed_in(client)
    return client.post(
        "/config/sources",
        data={"csrf": csrf, "fingerprint": fingerprint, "enabled:vendor": "1", **fields},
        follow_redirects=False,
    )


# --- the overlay: adding, editing and removing one source ----------------------------------------


def test_a_source_added_on_the_config_page_is_stored_whole(tmp_path):
    client, runtime, _ = make_client(tmp_path)
    response = new_source(client, **{"new:type": "rss", "new:url": "https://nodejs.org/feed/vulnerability.xml"})
    assert response.status_code == 303
    # The id is derived from the host, because the field was left empty.
    assert overlay(tmp_path)["sources_added"] == [
        {"id": "nodejs-org", "type": "rss", "url": "https://nodejs.org/feed/vulnerability.xml"}
    ]
    runtime.reload(blocking=True)
    assert [source.id for source in runtime.sources] == ["vendor", "nodejs-org"]


def test_the_second_source_from_one_host_gets_its_own_id(tmp_path):
    client, runtime, _ = make_client(tmp_path)
    assert new_source(client, **{"new:type": "rss", "new:url": "https://nodejs.org/feed/a.xml"}).status_code == 303
    assert new_source(client, **{"new:type": "rss", "new:url": "https://nodejs.org/feed/b.xml"}).status_code == 303
    added = [entry["id"] for entry in overlay(tmp_path)["sources_added"]]
    assert added == ["nodejs-org", "nodejs-org-2"]


def test_an_id_the_yaml_already_defines_is_refused(tmp_path):
    client, _, _ = make_client(tmp_path)
    response = new_source(
        client, **{"new:id": "vendor", "new:type": "rss", "new:url": "https://other.example.net/security.xml"}
    )
    assert response.status_code == 400
    assert "already configured" in response.text
    assert not (tmp_path / "data" / "settings.json").exists(), "a refused save writes nothing"


def test_an_added_source_is_edited_in_place(tmp_path):
    client, runtime, _ = make_client(tmp_path)
    new_source(client, **{"new:type": "rss", "new:url": "https://nodejs.org/feed/vulnerability.xml"})
    csrf, fingerprint = signed_in(client)
    response = client.post(
        "/config/sources",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "enabled:vendor": "1",
            "enabled:nodejs-org": "1",
            "added_url:nodejs-org": "https://nodejs.org/feed/vulnerability-2.xml",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert overlay(tmp_path)["sources_added"][0]["url"] == "https://nodejs.org/feed/vulnerability-2.xml"


def test_removing_an_added_source_leaves_the_yaml_source_alone(tmp_path):
    client, runtime, _ = make_client(tmp_path)
    new_source(client, **{"new:type": "rss", "new:url": "https://nodejs.org/feed/vulnerability.xml"})
    csrf, fingerprint = signed_in(client)
    response = client.post(
        "/config/sources",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "enabled:vendor": "1",
            "remove:nodejs-org": "1",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "sources_added" not in overlay(tmp_path)
    runtime.reload(blocking=True)
    assert [source.id for source in runtime.sources] == ["vendor"]


def test_a_literal_secret_is_refused_for_an_added_source(tmp_path):
    client, _, _ = make_client(tmp_path)
    response = new_source(
        client,
        **{
            "new:type": "freshrss",
            "new:url": "https://rss.example.net",
            "new:token": "a-real-token",
        },
    )
    assert response.status_code == 400
    assert "reference" in response.text
    assert not (tmp_path / "data" / "settings.json").exists()


def test_a_reference_is_accepted_and_stored_as_written(tmp_path):
    client, _, _ = make_client(tmp_path, environment={"FRESHRSS_TOKEN": "s3cret"})
    response = new_source(
        client,
        **{"new:type": "freshrss", "new:url": "https://rss.example.net", "new:token": "${FRESHRSS_TOKEN}"},
    )
    assert response.status_code == 303
    assert overlay(tmp_path)["sources_added"][0]["token"] == "${FRESHRSS_TOKEN}"


def test_an_edit_that_drops_a_required_key_is_refused_readably(tmp_path):
    client, _, _ = make_client(tmp_path)
    new_source(client, **{"new:type": "rss", "new:url": "https://nodejs.org/feed/vulnerability.xml"})
    csrf, fingerprint = signed_in(client)
    response = client.post(
        "/config/sources",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "enabled:vendor": "1",
            "added_url:nodejs-org": "",  # the field was cleared
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "rss needs url" in response.text


# --- the overlay's shape rules, without HTTP -----------------------------------------------------


@pytest.mark.parametrize(
    ("added", "message"),
    [
        ("not a list", "must be a list"),
        ([{"type": "rss", "url": "https://a.example.net"}], "needs a string id"),
        ([{"id": "a", "type": "nope"}], "has no built-in type"),
        ([{"id": "a", "type": "rss"}, {"id": "a", "type": "rss"}], "defined twice"),
        ([{"id": "a", "type": "changedetection", "url": "https://c.example.net", "api_key": "literal"}], "reference"),
    ],
)
def test_the_overlay_refuses_a_source_it_could_not_run(added, message):
    with pytest.raises(ConfigError, match=message):
        validate_settings({"sources_added": added})


def test_the_overlay_cannot_duplicate_a_yaml_source(tmp_path):
    path = write_config(tmp_path)
    with pytest.raises(ConfigError, match="already defined in the YAML"):
        load_document(
            path,
            settings={"sources_added": [{"id": "vendor", "type": "rss", "url": "https://other.example.net/x"}]},
        )


def test_a_match_tag_outside_the_closed_set_is_refused(tmp_path):
    path = write_config(
        tmp_path,
        extra="routes:\n  - match: {tag: vendor}\n    notifiers: [chat]\n",
    )
    with pytest.raises(ConfigError, match="match.tag"):
        load_config(path, {})


# --- the probe: the same fetch a pass performs, and no write -------------------------------------


def test_the_probe_fetches_a_configured_source_and_writes_nothing(tmp_path):
    client, _, _ = make_client(tmp_path)
    csrf, fingerprint = signed_in(client)
    response = client.post("/config/sources/probe", data={"csrf": csrf, "fingerprint": fingerprint, "id": "vendor"})
    assert response.status_code == 200
    assert "Answered with 2 entries." in response.text
    assert "CVE-2026-1111 fixed in libfoo" in response.text
    assert not (tmp_path / "data" / "state.json").exists(), "a probe is not a pass: it saves no state"


def test_the_probe_reports_the_fault_a_pass_would_meet(tmp_path):
    client, _, _ = make_client(
        tmp_path, sources=[{"id": "broken", "type": "rss", "url": "https://bad.example.net/feed.xml"}]
    )
    csrf, fingerprint = signed_in(client)
    response = client.post("/config/sources/probe", data={"csrf": csrf, "fingerprint": fingerprint, "id": "broken"})
    assert response.status_code == 200
    assert "RssError" in response.text
    assert "404" in response.text


def test_an_unsaved_probe_carries_the_values_into_a_save(tmp_path):
    client, runtime, _ = make_client(tmp_path)
    csrf, fingerprint = signed_in(client)
    probed = client.post(
        "/config/sources/probe",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:type": "rss",
            "new:url": "https://nodejs.org/feed/vulnerability.xml",
        },
    )
    assert probed.status_code == 200
    assert "Add this source" in probed.text
    # The page re-emits the probed fields, so saving is a click on that second form.
    saved = client.post(
        "/config/sources",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:type": "rss",
            "new:url": "https://nodejs.org/feed/vulnerability.xml",
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    runtime.reload(blocking=True)
    assert "nodejs-org" in [source.id for source in runtime.sources]


def test_the_probe_names_an_unset_reference_and_never_its_value(tmp_path):
    client, _, _ = make_client(tmp_path)
    csrf, fingerprint = signed_in(client)
    response = client.post(
        "/config/sources/probe",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:type": "freshrss",
            "new:url": "https://rss.example.net",
            "new:token": "${FRESHRSS_TOKEN_NOT_SET}",
        },
    )
    assert response.status_code == 200
    assert "FRESHRSS_TOKEN_NOT_SET" in response.text
    assert "is not set in the environment" in response.text


def test_the_probe_refuses_a_url_it_could_not_fetch(tmp_path):
    client, _, _ = make_client(tmp_path)
    csrf, fingerprint = signed_in(client)
    response = client.post(
        "/config/sources/probe",
        data={"csrf": csrf, "fingerprint": fingerprint, "new:type": "rss", "new:url": "file:///etc/hostname"},
    )
    assert response.status_code == 200
    assert "Only http and https URLs can be fetched." in response.text


def test_the_transport_refuses_any_scheme_but_http():
    # ``urllib`` would open ``file://`` itself: the guard is what keeps a probe from reading a local file.
    assert urllib_http("GET", "file:///etc/hostname", {}, None) == (0, {}, b"")
    assert urlsplit("file:///etc/hostname").scheme == "file"


def test_the_transport_survives_a_url_it_cannot_parse():
    # A URL a person typed can be malformed: an unclosed bracket must stay a failed request, not a 500.
    assert urllib_http("GET", "http://[oops/feed.xml", {}, None) == (0, {}, b"")


def test_an_unknown_source_id_is_a_404_and_not_a_crash(tmp_path):
    client, _, _ = make_client(tmp_path)
    csrf, fingerprint = signed_in(client)
    response = client.post("/config/sources/probe", data={"csrf": csrf, "fingerprint": fingerprint, "id": "ghost"})
    assert response.status_code == 404
    assert "No configured source has id ghost." in response.text


@pytest.mark.parametrize("path", ["/config/sources/probe", "/sources/probe"])
def test_the_probe_endpoints_require_a_session(tmp_path, path):
    client, _, _ = make_client(tmp_path)
    response = client.post(path, data={"csrf": "0" * 64}, follow_redirects=False)
    assert response.status_code in {303, 403}


# --- health: the state's record of one fetch, and where it is shown ------------------------------


def test_a_pass_records_health_for_every_source(tmp_path):
    client, runtime, _ = make_client(
        tmp_path,
        sources=[
            {"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"},
            {"id": "broken", "type": "rss", "url": "https://bad.example.net/feed.xml"},
        ],
    )
    code = pipeline.run_pass(runtime.cfg, runtime.sources, runtime.notifiers, http=fake_http)
    assert code == 1, "a failed source fails the pass, which is what the dashboard reports"
    health = json.loads((tmp_path / "data" / "state.json").read_text())["source_health"]
    assert health["vendor"]["ok"] is True
    assert health["vendor"]["items"] == 2
    assert health["vendor"]["error"] == ""
    assert health["broken"]["ok"] is False
    assert health["broken"]["ok_at"] == 0
    assert "answered HTTP 404" in health["broken"]["error"]


def test_a_health_record_never_outlives_its_source(tmp_path):
    _, runtime, _ = make_client(tmp_path)
    state = core.new_state()
    state["source_health"] = {
        "vendor": {"at": 1, "ok": True, "ok_at": 1, "items": 1, "error": ""},
        "gone": {"at": 1, "ok": False, "ok_at": 0, "items": 0, "error": "old"},
    }
    save_state(runtime.cfg.state_path, state)
    pipeline.run_pass(runtime.cfg, runtime.sources, runtime.notifiers, http=fake_http)
    health = json.loads((tmp_path / "data" / "state.json").read_text())["source_health"]
    assert set(health) == {"vendor"}


def test_the_sources_page_shows_health_and_offers_a_probe(tmp_path):
    client, runtime, _ = make_client(
        tmp_path,
        sources=[
            {"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"},
            {"id": "broken", "type": "rss", "url": "https://bad.example.net/feed.xml"},
        ],
    )
    pipeline.run_pass(runtime.cfg, runtime.sources, runtime.notifiers, http=fake_http)
    signed_in(client)
    page = client.get("/sources").text
    assert "badge-ok" in page, "the working source is marked healthy"
    assert "badge-critical" in page, "the failing one is not"
    assert "answered HTTP 404" in page
    assert "action='/sources/probe'" in page, "every row can be probed"


def test_metrics_carry_one_series_per_source(tmp_path):
    client, runtime, _ = make_client(
        tmp_path,
        sources=[
            {"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"},
            {"id": "broken", "type": "rss", "url": "https://bad.example.net/feed.xml"},
        ],
    )
    pipeline.run_pass(runtime.cfg, runtime.sources, runtime.notifiers, http=fake_http)
    metrics = client.get("/metrics").text
    assert 'advisory_radar_source_up{source="vendor"} 1' in metrics
    assert 'advisory_radar_source_up{source="broken"} 0' in metrics
    assert 'advisory_radar_source_items{source="vendor"} 2' in metrics


def test_a_route_for_an_unconfigured_source_is_reported_on_the_config_page(tmp_path):
    client, _, _ = make_client(tmp_path)
    cfg_path = tmp_path / "config.yml"
    document = yaml.safe_load(cfg_path.read_text())
    document["routes"] = [{"match": {"source": "ghost", "tag": "critical"}, "notifiers": ["chat"]}]
    cfg_path.write_text(yaml.safe_dump(document))
    signed_in(client)
    page = client.get("/config").text
    assert "no configured source" in page
    assert "ghost" in page


def test_adding_from_a_probe_keeps_the_sources_already_added(tmp_path):
    """The probe page's save form carries only the new block, never the rows above it."""
    client, runtime, _ = make_client(tmp_path)
    new_source(client, **{"new:type": "rss", "new:url": "https://nodejs.org/feed/a.xml"})
    csrf, fingerprint = signed_in(client)
    response = client.post(
        "/config/sources",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:type": "rss",
            "new:url": "https://nodejs.org/feed/b.xml",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    added = overlay(tmp_path)["sources_added"]
    assert [entry["id"] for entry in added] == ["nodejs-org", "nodejs-org-2"]
    # The first source is untouched: no row was rendered, so nothing about it was decided by this request.
    assert added[0] == {"id": "nodejs-org", "type": "rss", "url": "https://nodejs.org/feed/a.xml"}
