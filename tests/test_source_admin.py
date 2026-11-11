"""Adding, editing, testing and watching a source from the browser.

Four owners meet here: the catalogue says which keys a kind declares, the settings overlay may add a source
the YAML does not define, the probe performs the same fetch a pass performs, and the state records one health
line per source. Every test below is about one of those boundaries, because a source the operator cannot
configure or cannot see failing is the same failure.
"""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml
from fastapi.testclient import TestClient

from advisory_radar import core, pipeline
from advisory_radar.config import ConfigError, Thresholds, load_config, load_document
from advisory_radar.http import _host_of, private_destination, resolve_host, urllib_http
from advisory_radar.runtime import Runtime
from advisory_radar.settings import save_settings, settings_path, validate_settings
from advisory_radar.state import save_state, state_lock
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


#: A public unicast address: what a name resolves to when a test does not care where it points.
PUBLIC_ADDRESS = "93.184.216.34"


def public_resolver(host: str) -> tuple[str, ...]:
    """The default resolver for a test: every name answers one public address, and no DNS is consulted."""
    return (PUBLIC_ADDRESS,)


def make_client(
    tmp_path: Path,
    sources: list[dict] | None = None,
    environment: dict[str, str] | None = None,
    transport=None,
    resolve=public_resolver,
    extra: str = "",
):
    """A signed-out client, the runtime it serves and the config file behind it.

    The resolver is injected so no test depends on DNS. A test that needs an internal destination passes
    ``lambda host: ("172.16.0.9",)``; one that needs the *name* to decide passes its own function.
    """
    path = write_config(tmp_path, sources, extra)
    env = {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN, **(environment or {})}
    runtime = Runtime.build(path, env)
    app = create_app(runtime, env, http=transport or fake_http, resolve=resolve)
    return TestClient(app), runtime, path


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
            "enabled:nodejs-org": "1",
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
        (
            [
                {"id": "a", "type": "rss", "url": "https://a.example.net/feed.xml"},
                {"id": "a", "type": "rss", "url": "https://b.example.net/feed.xml"},
            ],
            "defined twice",
        ),
        ([{"id": "${SOURCE_ID}", "type": "webhook"}], "literal"),
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
    # The page re-emits the probed fields: replay exactly the form it returned, so this pins "saves what it
    # probed" rather than restating the values the test already knew.
    fields = dict(re.findall(r"""name=['"]([^'"]+)['"] value=['"]([^'"]*)['"]""", probed.text))
    assert {"csrf", "fingerprint", "new:type", "new:url"} <= set(fields)
    saved = client.post("/config/sources", data=fields, follow_redirects=False)
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


# --- destinations: the page may not aim the fetcher at a private network --------------------------


def test_a_source_that_points_into_a_private_network_is_refused(tmp_path):
    client, _, _ = make_client(tmp_path, resolve=lambda host: ("172.16.0.9",))
    response = new_source(client, **{"new:type": "rss", "new:url": "https://nas.example.net/feed.xml"})
    assert response.status_code == 400
    assert "private network" in response.text
    assert not (tmp_path / "data" / "settings.json").exists()


def test_a_private_destination_is_allowed_when_the_yaml_allows_it(tmp_path):
    client, runtime, _ = make_client(
        tmp_path, resolve=lambda host: ("172.16.0.9",), extra="allow_private_sources: true\n"
    )
    response = new_source(client, **{"new:type": "rss", "new:url": "https://nas.example.net/feed.xml"})
    assert response.status_code == 303
    runtime.reload(blocking=True)
    assert "nas-example-net" in [source.id for source in runtime.sources]


def test_a_probe_of_a_new_source_refuses_a_private_destination(tmp_path):
    client, _, _ = make_client(tmp_path, resolve=lambda host: ("172.20.5.7",))
    csrf, fingerprint = signed_in(client)
    response = client.post(
        "/config/sources/probe",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "new:type": "rss",
            "new:url": "http://printer.example.net/feed.xml",
        },
    )
    assert response.status_code == 200
    assert "private network" in response.text


def test_a_configured_source_may_still_point_into_a_private_network(tmp_path):
    # The YAML is written by whoever runs the host, so an existing source is not subject to that rule.
    client, _, _ = make_client(
        tmp_path,
        sources=[{"id": "freshrss", "type": "rss", "url": "https://rss.example.net/feed.xml"}],
        resolve=lambda host: ("172.16.0.9",),
    )
    csrf, fingerprint = signed_in(client)
    response = client.post("/config/sources/probe", data={"csrf": csrf, "fingerprint": fingerprint, "id": "freshrss"})
    assert response.status_code == 200
    assert "Answered with 2 entries." in response.text


def test_a_probe_reports_a_url_that_is_not_http(tmp_path):
    client, _, _ = make_client(tmp_path)
    csrf, fingerprint = signed_in(client)
    response = client.post(
        "/config/sources/probe",
        data={"csrf": csrf, "fingerprint": fingerprint, "new:type": "rss", "new:url": "ftp://example.net/feed.xml"},
    )
    assert response.status_code == 200
    assert "Only http and https URLs can be fetched." in response.text


# --- references and the values they resolve ------------------------------------------------------


def test_a_whole_url_reference_is_probed_after_expansion(tmp_path):
    client, _, _ = make_client(tmp_path, environment={"FEED_URL": "https://feeds.example.net/feed.xml"})
    csrf, fingerprint = signed_in(client)
    response = client.post(
        "/config/sources/probe",
        data={"csrf": csrf, "fingerprint": fingerprint, "new:type": "rss", "new:url": "${FEED_URL}"},
    )
    assert response.status_code == 200
    assert "Answered with 2 entries." in response.text


def test_a_credential_echoed_by_the_source_is_redacted(tmp_path):
    """A title is the source's text: a server can reflect a request token back in one."""
    watches = json.dumps(
        {
            "abc": {
                "last_changed": 1792600000,
                "title": "watch named s3cret-token",
                "link": "https://changes.example.net/w/abc",
            }
        }
    ).encode()

    def echoing(method, url, headers, body):
        if "changes.example.net" in url:
            return 200, {}, watches
        return 200, {}, RSS

    client, _, _ = make_client(
        tmp_path,
        sources=[
            {
                "id": "changes",
                "type": "changedetection",
                "url": "https://changes.example.net",
                "api_key": "${CHANGEDETECTION_API_KEY}",
            }
        ],
        environment={"CHANGEDETECTION_API_KEY": "s3cret-token"},
        transport=echoing,
    )
    csrf, fingerprint = signed_in(client)
    response = client.post("/config/sources/probe", data={"csrf": csrf, "fingerprint": fingerprint, "id": "changes"})
    assert response.status_code == 200
    assert "s3cret-token" not in response.text, "a resolved credential must never reach the page"
    assert "[redacted]" in response.text


def test_an_unparseable_url_is_refused_without_a_crash(tmp_path):
    client, _, _ = make_client(tmp_path)
    # An explicit id skips derivation, so the save path has to refuse the address itself.
    with_id = new_source(client, **{"new:id": "broken", "new:type": "rss", "new:url": "http://[oops/feed.xml"})
    assert with_id.status_code == 400
    assert "not an http or https url" in with_id.text
    # Without one, the id is derived from a URL nobody can parse; the pass must still answer.
    csrf, fingerprint = signed_in(client)
    derived = client.post(
        "/config/sources/probe",
        data={"csrf": csrf, "fingerprint": fingerprint, "new:type": "rss", "new:url": "http://[oops/feed.xml"},
    )
    assert derived.status_code == 200
    assert "cannot be read as a URL" in derived.text


# --- durability of the health record -------------------------------------------------------------


def test_a_pass_that_dies_before_classifying_records_no_health(tmp_path, monkeypatch):
    _, runtime, _ = make_client(tmp_path)

    def boom(*args, **kwargs):
        raise RuntimeError("classification failed")

    monkeypatch.setattr(pipeline.core, "classify_new", boom)
    with pytest.raises(RuntimeError):
        pipeline.run_pass(runtime.cfg, runtime.sources, runtime.notifiers, http=fake_http)
    assert not runtime.cfg.state_path.exists(), "health is written only after this window's work is durable"


def test_the_destination_check_reads_the_host_the_transport_reads(tmp_path):
    # ``urllib.request.Request`` unquotes the authority before it dials, so ``%31%32%37.0.0.1`` reaches
    # 127.0.0.1. A resolver that only knows the decoded name is what proves the check normalises the same way.
    def resolver(host: str) -> tuple[str, ...]:
        return ("127.0.0.1",) if host == "127.0.0.1" else (PUBLIC_ADDRESS,)

    client, _, _ = make_client(tmp_path, resolve=resolver)
    assert private_destination("http://%31%32%37.0.0.1/feed.xml", resolve=resolver)
    response = new_source(client, **{"new:type": "rss", "new:url": "http://%31%32%37.0.0.1/feed.xml"})
    assert response.status_code == 400
    assert "private network" in response.text


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",  # loopback
        "::1",  # loopback, IPv6
        "172.16.0.9",  # private, IPv4
        "fd00::1",  # unique local, IPv6
        "169.254.169.254",  # link-local, the metadata service
        "100.64.0.1",  # shared address space: neither private nor global
        "fec0::1",  # site-local, deprecated, and it reports is_global
        "224.0.0.1",  # multicast, which also reports is_global
    ],
)
def test_internal_address_classes_are_refused(address):
    assert private_destination("https://internal.example/feed.xml", resolve=lambda host: (address,))


def test_a_public_address_is_allowed():
    assert not private_destination("https://feeds.example.net/feed.xml", resolve=lambda host: (PUBLIC_ADDRESS,))


def test_a_reference_cannot_smuggle_a_private_destination_past_the_check(tmp_path):
    def resolver(host: str) -> tuple[str, ...]:
        return ("127.0.0.1",) if host == "127.0.0.1" else (PUBLIC_ADDRESS,)

    client, _, _ = make_client(tmp_path, environment={"INTERNAL_HOST": "127.0.0.1"}, resolve=resolver)
    response = new_source(client, **{"new:type": "rss", "new:url": "http://${INTERNAL_HOST}/feed.xml"})
    assert response.status_code == 400
    assert "private network" in response.text
    assert not (tmp_path / "data" / "settings.json").exists()


def test_a_whole_url_reference_can_be_saved(tmp_path):
    client, runtime, _ = make_client(tmp_path, environment={"FEED_URL": "https://feeds.example.net/feed.xml"})
    response = new_source(client, **{"new:type": "rss", "new:url": "${FEED_URL}"})
    assert response.status_code == 303
    assert overlay(tmp_path)["sources_added"][0]["url"] == "${FEED_URL}"
    runtime.reload(blocking=True)
    assert "rss" in [source.id for source in runtime.sources]


def test_a_webhook_source_can_be_added_without_a_url(tmp_path):
    client, runtime, _ = make_client(tmp_path)
    response = new_source(client, **{"new:id": "vendor-hook", "new:type": "webhook"})
    assert response.status_code == 303
    runtime.reload(blocking=True)
    assert "vendor-hook" in [source.id for source in runtime.sources]


def test_a_credential_echoed_in_a_link_is_redacted(tmp_path):
    # Upper case on purpose: extracting the origin lowercases a hostname, so the redactor has to see both forms.
    watches = json.dumps(
        {
            "abc": {
                "last_changed": 1792600000,
                "title": "a watch",
                "link": "https://AbCdEf123456.example.net/w/abc",
            }
        }
    ).encode()

    def echoing(method, url, headers, body):
        if "changes.example.net" in url:
            return 200, {}, watches
        return 200, {}, RSS

    client, _, _ = make_client(
        tmp_path,
        sources=[
            {
                "id": "changes",
                "type": "changedetection",
                "url": "https://changes.example.net",
                "api_key": "${CHANGEDETECTION_API_KEY}",
            }
        ],
        environment={"CHANGEDETECTION_API_KEY": "AbCdEf123456"},
        transport=echoing,
    )
    csrf, fingerprint = signed_in(client)
    response = client.post("/config/sources/probe", data={"csrf": csrf, "fingerprint": fingerprint, "id": "changes"})
    assert response.status_code == 200
    assert "abcdef123456" not in response.text.lower(), "the origin is source-supplied text, in every case form"
    assert "[redacted]" in response.text


def test_a_failed_first_pass_still_bootstraps_when_a_source_answers(tmp_path):
    failing = {"on": True}

    def toggling(method, url, headers, body):
        if failing["on"]:
            return 0, {}, b""
        return 200, {"ETag": '"v1"'}, RSS

    _, runtime, _ = make_client(tmp_path, transport=toggling)
    assert pipeline.run_pass(runtime.cfg, runtime.sources, runtime.notifiers, http=toggling) == 1
    assert json.loads((tmp_path / "data" / "state.json").read_text())["source_health"]["vendor"]["ok"] is False
    failing["on"] = False
    assert pipeline.run_pass(runtime.cfg, runtime.sources, runtime.notifiers, http=toggling) == 0
    state = json.loads((tmp_path / "data" / "state.json").read_text())
    assert state["source_health"]["vendor"]["ok"] is True
    # The failed first pass marked nothing as seeded, so the first answer bootstraps instead of alerting history.
    assert state["seen"], "the first successful pass seeds the feed's history"
    assert state["pending"] == []


def test_a_dry_run_writes_nothing_even_when_every_source_fails(tmp_path):
    _, runtime, _ = make_client(tmp_path, transport=lambda *args: (0, {}, b""))
    code = pipeline.run_pass(
        runtime.cfg, runtime.sources, runtime.notifiers, http=lambda *args: (0, {}, b""), dry_run=True
    )
    assert code == 1
    assert not (tmp_path / "data" / "state.json").exists()


def test_an_encoded_port_cannot_hide_a_loopback_destination(tmp_path):
    # The real resolver, no stub: 127.0.0.1 is answered locally. ``%3A8080`` is a *port* to the transport,
    # which unquotes the whole authority before it splits host from port, so it must be a port here too.
    client, _, _ = make_client(tmp_path, resolve=resolve_host)
    response = new_source(client, **{"new:type": "rss", "new:url": "http://127.0.0.1%3A8080/feed.xml"})
    assert response.status_code == 400
    assert "private network" in response.text


def test_a_source_whose_host_becomes_internal_can_still_be_disabled(tmp_path):
    addresses = {"value": PUBLIC_ADDRESS}

    def resolver(host: str) -> tuple[str, ...]:
        return (addresses["value"],)

    client, _, _ = make_client(tmp_path, resolve=resolver)
    added = new_source(client, **{"new:type": "rss", "new:url": "https://nas.example.net/feed.xml"})
    assert added.status_code == 303
    # The name now resolves into a private network. Switching the source off is what the operator needs, so
    # the destination rule judges only what would actually be fetched.
    addresses["value"] = "172.16.0.9"
    csrf, fingerprint = signed_in(client)
    saved = client.post(
        "/config/sources",
        data={"csrf": csrf, "fingerprint": fingerprint, "enabled:vendor": "1", "tag:vendor": ""},
        follow_redirects=False,
    )
    assert saved.status_code == 303
    assert overlay(tmp_path)["sources_added"][0]["enabled"] is False
    # Turning it back on is judged again, and refused while the destination is internal.
    csrf, fingerprint = signed_in(client)
    refused = client.post(
        "/config/sources",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "enabled:vendor": "1",
            "enabled:nas-example-net": "1",
            "added_url:nas-example-net": "https://nas.example.net/feed.xml",
        },
        follow_redirects=False,
    )
    assert refused.status_code == 400
    assert "private network" in refused.text


def test_a_probe_of_a_disabled_overlay_source_is_still_judged(tmp_path):
    """Disabling a source the page added must not become the way to aim its probe at an internal address."""
    addresses = {"value": PUBLIC_ADDRESS}

    def resolver(host: str) -> tuple[str, ...]:
        return (addresses["value"],)

    client, _, _ = make_client(tmp_path, resolve=resolver)
    assert new_source(client, **{"new:type": "rss", "new:url": "https://nas.example.net/feed.xml"}).status_code == 303
    addresses["value"] = "172.16.0.9"
    csrf, fingerprint = signed_in(client)
    # Switching it off while pointing it at loopback is allowed: a disabled source is not fetched.
    saved = client.post(
        "/config/sources",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "enabled:vendor": "1",
            "tag:vendor": "",
            "added_url:nas-example-net": "http://127.0.0.1:8080/feed.xml",
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    # A disabled source has no row on ``/sources`` (that page lists what will run); ``/config`` renders it, and
    # probing from there is judged by ownership all the same.
    csrf, fingerprint = signed_in(client)
    probed = client.post("/config/sources/probe", data={"csrf": csrf, "id": "nas-example-net"})
    assert probed.status_code == 200
    assert "private network" in probed.text


def test_the_sources_page_redacts_a_secret_in_a_configured_url(tmp_path):
    client, _, _ = make_client(
        tmp_path,
        sources=[{"id": "vendor", "type": "rss", "url": "https://${FEED_TOKEN}.feeds.example.net/security.xml"}],
        environment={"FEED_TOKEN": "AbCdEf123456"},
    )
    signed_in(client)
    page = client.get("/sources").text
    assert "abcdef123456" not in page.lower(), "the table shows an expanded configuration, so it must redact it"
    assert "redacted" in page.lower()


def test_a_percent_encoded_credential_in_a_link_is_redacted(tmp_path):
    # The redaction covers the encoded form of a secret, which is how it reaches a hostname.
    watches = json.dumps(
        {
            "abc": {
                "last_changed": 1792600000,
                "title": "a watch",
                "link": "https://Ab%2FCd.example.net/w/abc",
            }
        }
    ).encode()

    def echoing(method, url, headers, body):
        if "changes.example.net" in url:
            return 200, {}, watches
        return 200, {}, RSS

    client, _, _ = make_client(
        tmp_path,
        sources=[
            {
                "id": "changes",
                "type": "changedetection",
                "url": "https://changes.example.net",
                "api_key": "${CHANGEDETECTION_API_KEY}",
            }
        ],
        environment={"CHANGEDETECTION_API_KEY": "Ab/Cd"},
        transport=echoing,
    )
    csrf, fingerprint = signed_in(client)
    response = client.post("/config/sources/probe", data={"csrf": csrf, "fingerprint": fingerprint, "id": "changes"})
    assert response.status_code == 200
    assert "ab%2fcd" not in response.text.lower()
    assert "ab/cd" not in response.text.lower()
    assert "[redacted]" in response.text


@pytest.mark.parametrize(
    "address",
    [
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:100.64.0.1",  # IPv4-mapped shared space
        "::ffff:224.0.0.1",  # IPv4-mapped multicast
        "64:ff9b::7f00:1",  # NAT64 wrapper around 127.0.0.1
        "2002:7f00:1::1",  # 6to4 wrapper around 127.0.0.1
        "64:ff9b:1::7f00:1",  # local-use NAT64 wrapper
        "2001:0:7f00:1::1",  # Teredo
        "fe80::1%eth0",  # link-local with a zone id
    ],
)
def test_a_wrapped_or_zoned_literal_is_refused(address):
    assert private_destination("https://internal.example/feed.xml", resolve=lambda host: (address,))


def test_a_public_ipv6_address_is_allowed():
    assert not private_destination("https://feeds.example.net/", resolve=lambda host: ("2001:4860:4860::8888",))


def test_an_added_source_id_must_be_literal(tmp_path):
    """An id is a page value and a metric label on an unauthenticated endpoint: a reference would publish it."""
    client, _, _ = make_client(tmp_path, environment={"SOURCE_ID_SECRET": "abcdef1234567890"})
    response = new_source(client, **{"new:id": "${SOURCE_ID_SECRET}", "new:type": "webhook"})
    assert response.status_code == 400
    assert "literal" in response.text
    assert "abcdef1234567890" not in response.text, "the refusal names the reference, never the value it holds"
    assert not (tmp_path / "data" / "settings.json").exists()


def test_the_sources_page_redacts_a_stored_error_at_render_time(tmp_path):
    client, runtime, _ = make_client(
        tmp_path,
        sources=[
            {
                "id": "vendor",
                "type": "freshrss",
                "url": "https://rss.example.net",
                "token": "${FRESHRSS_TOKEN}",
            }
        ],
        environment={"FRESHRSS_TOKEN": "s3cret-token"},
    )
    state = core.new_state()
    # As an older binary, or a hand edit, could have left it: the page is a redaction boundary of its own.
    state["source_health"] = {"vendor": {"at": 1, "ok": False, "ok_at": 0, "items": 0, "error": "boom s3cret-token"}}
    save_state(runtime.cfg.state_path, state)
    signed_in(client)
    page = client.get("/sources").text
    assert "s3cret-token" not in page
    assert "boom" in page


def test_a_bare_config_app_redacts_a_row_origin(tmp_path):
    # ``create_app`` accepts a validated Config, and that runtime keeps the *expanded* document.
    path = write_config(
        tmp_path,
        sources=[{"id": "vendor", "type": "rss", "url": "https://${FEED_TOKEN}.feeds.example.net/x.xml"}],
    )
    env = {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN, "FEED_TOKEN": "AbCdEf123456"}
    client = TestClient(create_app(load_config(path, env), env, http=fake_http, resolve=public_resolver))
    signed_in(client)
    page = client.get("/config").text
    assert "abcdef123456" not in page.lower()


def test_a_probe_finds_a_yaml_source_by_the_id_the_page_shows(tmp_path):
    """``/sources`` renders the expanded configuration, so its button submits the value, not the reference."""
    client, runtime, _ = make_client(
        tmp_path,
        sources=[{"id": "${PREFIX}dor", "type": "rss", "url": "https://feeds.example.net/feed.xml"}],
        environment={"PREFIX": "ven"},
    )
    assert [source.id for source in runtime.sources] == ["vendor"]
    csrf, _ = signed_in(client)
    from_sources_page = client.post("/sources/probe", data={"csrf": csrf, "id": "vendor"})
    assert from_sources_page.status_code == 200
    assert "Answered with 2 entries." in from_sources_page.text
    from_config_page = client.post("/config/sources/probe", data={"csrf": csrf, "id": "${PREFIX}dor"})
    assert from_config_page.status_code == 200
    assert "Answered with 2 entries." in from_config_page.text


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1%3A8080/x",
        "http://[::1]:8080/x",
        "http://%5B::1%5D/x",
        "http://user:pw@127.0.0.1/x",
    ],
)
def test_the_check_normalises_the_authority_the_way_the_request_object_does(url):
    """No network, and no claim about how the connection splits host from port.

    This pins the normalisation the check reproduces -- unquote the authority, drop userinfo and port -- against
    the object that performs it. The userinfo case is why ``_host_of`` strips it: ``Request.host`` keeps it and
    the connection refuses the URL outright.
    """
    transport_host = urllib.request.Request(url).host
    assert _host_of(url) == urllib.parse.urlsplit("//" + transport_host).hostname


def test_a_disabled_source_cannot_shadow_the_row_that_was_probed(tmp_path):
    """Uniqueness is checked on the entries that load, so a disabled reference may expand to a live id."""

    def distinct(method, url, headers, body):
        if "old.example.net" in url:
            return (
                200,
                {},
                b"<rss version='2.0'><channel><title>old</title>"
                b"<item><title>OLD FEED ITEM</title><guid>o1</guid></item></channel></rss>",
            )
        return (
            200,
            {},
            b"<rss version='2.0'><channel><title>new</title>"
            b"<item><title>NEW FEED ITEM</title><guid>n1</guid></item></channel></rss>",
        )

    client, _, _ = make_client(
        tmp_path,
        sources=[
            {
                "id": "${PREFIX}dor",
                "type": "rss",
                "enabled": False,
                "url": "https://old.example.net/feed.xml",
            }
        ],
        environment={"PREFIX": "ven"},
        transport=distinct,
    )
    added = new_source(client, **{"new:id": "vendor", "new:type": "rss", "new:url": "https://new.example.net/x.xml"})
    assert added.status_code == 303
    csrf, _ = signed_in(client)
    # ``/sources`` lists the enabled source, which is the added one; the disabled row shares its effective id.
    probed = client.post("/sources/probe", data={"csrf": csrf, "id": "vendor"})
    assert probed.status_code == 200
    assert "NEW FEED ITEM" in probed.text
    assert "OLD FEED ITEM" not in probed.text


def test_a_derived_id_reserves_the_ids_in_use(tmp_path):
    client, _, _ = make_client(
        tmp_path,
        sources=[{"id": "nodejs-${SUFFIX}", "type": "rss", "url": "https://feeds.example.net/feed.xml"}],
        environment={"SUFFIX": "org"},
    )
    assert new_source(client, **{"new:type": "rss", "new:url": "https://nodejs.org/feed/x.xml"}).status_code == 303
    assert overlay(tmp_path)["sources_added"][0]["id"] == "nodejs-org-2"


def test_a_derived_id_does_not_take_a_notifier_id(tmp_path):
    path = tmp_path / "config.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "sources": [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/feed.xml"}],
                "notifiers": [{"id": "nodejs-org", "type": "webhook", "url": "https://hooks.example.net/x"}],
                "state_path": str(tmp_path / "data" / "state.json"),
            }
        )
    )
    env = {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN}
    runtime = Runtime.build(path, env)
    client = TestClient(create_app(runtime, env, http=fake_http, resolve=public_resolver))
    assert new_source(client, **{"new:type": "rss", "new:url": "https://nodejs.org/feed/x.xml"}).status_code == 303
    assert overlay(tmp_path)["sources_added"][0]["id"] == "nodejs-org-2"


def test_the_sources_page_probes_what_it_shows_when_a_save_is_not_live(tmp_path):
    """A pass holding the lock leaves a saved overlay unapplied; the row must still fetch the row's URL."""

    def distinct(method, url, headers, body):
        title = b"OLD ITEM" if "old.example.net" in url else b"NEW ITEM"
        return (
            200,
            {},
            b"<rss version='2.0'><channel><title>t</title><item><title>"
            + title
            + (b"</title><guid>g</guid></item></channel></rss>"),
        )

    client, runtime, _ = make_client(tmp_path, transport=distinct)
    assert new_source(client, **{"new:type": "rss", "new:url": "https://old.example.net/feed.xml"}).status_code == 303
    assert [source.id for source in runtime.sources] == ["vendor", "old-example-net"]
    with state_lock(runtime.cfg.state_path):  # the pass holds the lock, so the edit cannot be applied
        csrf, fingerprint = signed_in(client)
        edited = client.post(
            "/config/sources",
            data={
                "csrf": csrf,
                "fingerprint": fingerprint,
                "enabled:vendor": "1",
                "enabled:old-example-net": "1",
                "added_url:old-example-net": "https://new.example.net/feed.xml",
            },
            follow_redirects=False,
        )
        assert edited.status_code == 303
        csrf, _ = signed_in(client)
        probed = client.post("/sources/probe", data={"csrf": csrf, "id": "old-example-net"})
    assert probed.status_code == 200
    assert "OLD ITEM" in probed.text, "the page renders the live configuration, so its probe reads that one"
    assert "NEW ITEM" not in probed.text


@pytest.mark.parametrize("path", ["/sources/probe", "/config/sources/probe"])
def test_a_source_whose_type_is_a_reference_can_be_probed(tmp_path, path):
    client, runtime, _ = make_client(
        tmp_path,
        sources=[{"id": "vendor", "type": "${SOURCE_KIND}", "url": "https://feeds.example.net/feed.xml"}],
        environment={"SOURCE_KIND": "rss"},
    )
    assert [source.id for source in runtime.sources] == ["vendor"]
    csrf, _ = signed_in(client)
    response = client.post(path, data={"csrf": csrf, "id": "vendor"})
    assert response.status_code == 200
    assert "Answered with 2 entries." in response.text


def test_the_route_warning_compares_the_values_routing_uses(tmp_path):
    client, _, _ = make_client(
        tmp_path,
        sources=[{"id": "${PREFIX}dor", "type": "rss", "url": "https://feeds.example.net/feed.xml"}],
        environment={"PREFIX": "ven"},
        extra="routes:\n  - match: {source: vendor}\n    notifiers: [chat]\n",
    )
    signed_in(client)
    page = client.get("/config").text
    assert "no configured source" not in page, "the rule matches the expanded id, so it is not inert"


def test_a_derived_id_reserves_a_disabled_reference(tmp_path):
    client, _, _ = make_client(
        tmp_path,
        sources=[
            {
                "id": "nodejs-${SUFFIX}",
                "type": "rss",
                "enabled": False,
                "url": "https://feeds.example.net/feed.xml",
            }
        ],
        environment={"SUFFIX": "org"},
    )
    assert new_source(client, **{"new:type": "rss", "new:url": "https://nodejs.org/feed/x.xml"}).status_code == 303
    assert overlay(tmp_path)["sources_added"][0]["id"] == "nodejs-org-2", "reserved conservatively by design"


def test_a_derived_id_reserves_a_disabled_notifier_id(tmp_path):
    path = tmp_path / "config.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "sources": [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/feed.xml"}],
                "notifiers": [
                    {"id": "nodejs-org", "type": "webhook", "url": "https://hooks.example.net/x", "enabled": False}
                ],
                "state_path": str(tmp_path / "data" / "state.json"),
            }
        )
    )
    env = {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN}
    runtime = Runtime.build(path, env)
    client = TestClient(create_app(runtime, env, http=fake_http, resolve=public_resolver))
    assert new_source(client, **{"new:type": "rss", "new:url": "https://nodejs.org/feed/x.xml"}).status_code == 303
    assert overlay(tmp_path)["sources_added"][0]["id"] == "nodejs-org-2"


def test_the_route_warning_shows_what_was_written_not_the_resolved_value(tmp_path):
    client, _, _ = make_client(
        tmp_path,
        environment={"FRESHRSS_TOKEN": "s3cret-token"},
        extra='routes:\n  - match: {source: "${FRESHRSS_TOKEN}"}\n    notifiers: [chat]\n',
    )
    signed_in(client)
    page = client.get("/config").text
    assert "s3cret-token" not in page, "the comparison may resolve a reference; the message may not print it"
    assert "FRESHRSS_TOKEN" in page, "the reference itself is what the operator has to see"


def test_a_disabled_source_with_a_referenced_type_does_not_print_its_value(tmp_path):
    # A disabled entry is never expanded by a configuration load, so its type may hold any reference.
    client, _, _ = make_client(
        tmp_path,
        sources=[
            {
                "id": "vendor",
                "type": "${SOME_SECRET}",
                "enabled": False,
                "url": "https://feeds.example.net/feed.xml",
            }
        ],
        environment={"SOME_SECRET": "s3cret-token"},
    )
    csrf, _ = signed_in(client)
    response = client.post("/config/sources/probe", data={"csrf": csrf, "id": "vendor"})
    assert response.status_code == 200
    assert "s3cret-token" not in response.text
    assert "SOME_SECRET" in response.text


def test_every_path_fetches_the_url_the_pass_fetches(tmp_path):
    """Expansion is not recursive, so a probe must expand a raw entry once and a live one not at all."""
    seen: list[str] = []

    def recording(method, url, headers, body):
        seen.append(url)
        return 200, {"ETag": '"v"'}, RSS

    # FEED_URL's value itself contains a reference: the pass fetches the literal text, and so must a probe.
    client, runtime, _ = make_client(
        tmp_path,
        sources=[{"id": "vendor", "type": "rss", "url": "${FEED_URL}"}],
        environment={
            "FEED_URL": "https://feeds.example.net/feed.xml?template=${CHANNEL}",
            "CHANNEL": "security",
        },
        transport=recording,
    )

    def feed_urls() -> list[str]:
        return [url for url in seen if "feeds.example.net" in url]

    csrf, _ = signed_in(client)
    pipeline.run_pass(runtime.cfg, runtime.sources, runtime.notifiers, http=recording)
    assert feed_urls(), "the pass must have fetched the feed"
    pass_url = feed_urls()[-1]
    seen.clear()
    assert client.post("/sources/probe", data={"csrf": csrf, "id": "vendor"}).status_code == 200
    sources_url = feed_urls()[-1]
    seen.clear()
    assert client.post("/config/sources/probe", data={"csrf": csrf, "id": "vendor"}).status_code == 200
    config_url = feed_urls()[-1]
    assert sources_url == pass_url, "the live row was expanded once already; a second pass would change the URL"
    assert config_url == pass_url, "a raw row expands once, exactly as the loader does"


def test_a_disabled_webhook_is_probeable_and_names_its_endpoint(tmp_path):
    # A whole ``${NAME}`` id is refused by the validator now, so the fixture composes one -- which is the only
    # way an id may carry a reference at all.
    client, _, _ = make_client(
        tmp_path,
        sources=[{"id": "hook-${SUFFIX}", "type": "webhook", "enabled": False}],
        environment={"SUFFIX": "vendor"},
    )
    csrf, _ = signed_in(client)
    response = client.post("/config/sources/probe", data={"csrf": csrf, "id": "hook-${SUFFIX}"})
    assert response.status_code == 200
    assert "no remote side" in response.text
    # The endpoint is named from the effective id, redacted like every other place an id is rendered.
    assert "/webhooks/hook-[redacted]" in response.text


def test_a_bare_config_app_does_not_print_a_route_secret(tmp_path):
    path = write_config(tmp_path, extra='routes:\n  - match: {source: "${SOME_SECRET}"}\n    notifiers: [chat]\n')
    env = {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN, "SOME_SECRET": "s3cret-token"}
    client = TestClient(create_app(load_config(path, env), env, http=fake_http, resolve=public_resolver))
    signed_in(client)
    page = client.get("/config").text
    assert "s3cret-token" not in page
    # That runtime's document *is* the resolved configuration, so the reference is gone with it: the page shows
    # a redaction rather than a reference it no longer has.
    assert "[redacted]" in page


def test_a_bare_config_app_probes_the_url_the_pass_fetches(tmp_path):
    """A bare ``Config`` runtime keeps the expanded document, so its rows must not be expanded again."""
    seen: list[str] = []

    def recording(method, url, headers, body):
        seen.append(url)
        return 200, {"ETag": '"v"'}, RSS

    path = write_config(tmp_path, sources=[{"id": "vendor", "type": "rss", "url": "${FEED_URL}"}])
    env = {
        "ADVISORY_RADAR_AUTH_TOKEN": TOKEN,
        "FEED_URL": "https://feeds.example.net/feed.xml?template=${CHANNEL}",
        "CHANNEL": "security",
    }
    cfg = load_config(path, env)
    client = TestClient(create_app(cfg, env, http=recording, resolve=public_resolver))
    csrf, _ = signed_in(client)
    assert client.post("/config/sources/probe", data={"csrf": csrf, "id": "vendor"}).status_code == 200
    probed = [url for url in seen if "feeds.example.net" in url][-1]
    assert probed == cfg.sources[0]["url"], "the loader expanded this once; the probe must not do it again"
    assert "${CHANNEL}" in probed


def test_the_probe_page_title_redacts_a_resolved_id(tmp_path):
    """The title is part of the response: on the live path the id submitted *is* the expanded value."""
    path = write_config(
        tmp_path,
        sources=[{"id": "probe-${SOURCE_ID}", "type": "rss", "url": "https://feeds.example.net/feed.xml"}],
    )
    env = {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN, "SOURCE_ID": "s3cret-token"}
    runtime = Runtime.build(path, env)
    assert [source.id for source in runtime.sources] == ["probe-s3cret-token"]
    # A file-backed runtime's /config renders the reference and looks up a raw id; a bare Config keeps the
    # expanded document, so the same page looks up the value.
    cases = (
        (TestClient(create_app(runtime, env, http=fake_http, resolve=public_resolver)), "probe-${SOURCE_ID}"),
        (
            TestClient(create_app(load_config(path, env), env, http=fake_http, resolve=public_resolver)),
            "probe-s3cret-token",
        ),
    )
    for client, config_id in cases:
        csrf, _ = signed_in(client)
        for endpoint, identifier in (
            ("/sources/probe", "probe-s3cret-token"),
            ("/config/sources/probe", config_id),
        ):
            response = client.post(endpoint, data={"csrf": csrf, "id": identifier})
            assert response.status_code == 200, endpoint
            assert "s3cret-token" not in response.text, f"{endpoint} printed the resolved id"
    # the live path submits the value itself, so its title is where the redaction has to show
    csrf, _ = signed_in(cases[0][0])
    live = cases[0][0].post("/sources/probe", data={"csrf": csrf, "id": "probe-s3cret-token"})
    assert "<title>probe-[redacted] probe" in live.text


def test_a_whole_reference_id_is_refused_by_the_validator(tmp_path):
    """An id appears in routes, logs and a metric label: a whole reference there would publish its value."""
    path = write_config(tmp_path, sources=[{"id": "${SOURCE_ID}", "type": "rss", "url": "https://a.example.net"}])
    with pytest.raises(ConfigError, match="a plugin id is a name"):
        load_config(path, {"SOURCE_ID": "s3cret-token"})
    # A composed id stays allowed: it is a naming scheme, and its author sees it in routes and logs anyway.
    composed = write_config(tmp_path, sources=[{"id": "${PREFIX}dor", "type": "rss", "url": "https://a.example.net"}])
    assert load_config(composed, {"PREFIX": "ven"}).sources[0]["id"] == "vendor"


def test_the_metrics_label_is_the_configured_source_id(tmp_path):
    client, runtime, _ = make_client(
        tmp_path,
        sources=[{"id": "nodejs-${SUFFIX}", "type": "rss", "url": "https://feeds.example.net/x.xml"}],
        environment={"SUFFIX": "org"},
    )
    pipeline.run_pass(runtime.cfg, runtime.sources, runtime.notifiers, http=fake_http)
    metrics = client.get("/metrics").text
    assert 'advisory_radar_source_up{source="nodejs-org"} 1' in metrics


def test_an_id_may_not_borrow_a_credential_variable(tmp_path):
    """The case the whole-reference rule alone missed: the same variable names the source and supplies its key."""
    path = write_config(
        tmp_path,
        sources=[
            {
                "id": "feed-${CD_TOKEN}",
                "type": "changedetection",
                "url": "https://changes.example.net",
                "api_key": "${CD_TOKEN}",
            }
        ],
    )
    with pytest.raises(ConfigError, match="may not be composed from a variable that supplies a credential"):
        load_config(path, {"CD_TOKEN": "AbCdEf123456"})
    # the same source with a name for the id and the credential only in api_key is exactly how it should look
    literal = write_config(
        tmp_path,
        sources=[
            {"id": "changes", "type": "changedetection", "url": "https://changes.example.net", "api_key": "${CD_TOKEN}"}
        ],
    )
    cfg = load_config(literal, {"CD_TOKEN": "AbCdEf123456"})
    assert cfg.sources[0]["id"] == "changes"
    assert "AbCdEf123456" in cfg.secret_values


def test_a_notifier_id_may_not_borrow_a_credential_variable(tmp_path):
    path = write_config(
        tmp_path,
        extra="",  # the helper writes one notifier; this one is written whole, below
    )
    document = yaml.safe_load(path.read_text())
    document["notifiers"] = [
        {"id": "hook-${HOOK}", "type": "webhook", "url": "${HOOK}"},
    ]
    path.write_text(yaml.safe_dump(document))
    with pytest.raises(ConfigError, match="may not be composed from a variable that supplies a credential"):
        load_config(path, {"HOOK": "https://hooks.example.net/secret"})


@pytest.mark.parametrize(
    "document",
    [
        # the kind is itself a reference, so the collector must not depend on it
        {
            "sources": [
                {
                    "id": "feed-${CD_TOKEN}",
                    "type": "${SOURCE_KIND}",
                    "url": "https://changes.example.net",
                    "api_key": "${CD_TOKEN}",
                }
            ]
        },
        # a top-level credential is a credential
        {
            "nvd_api_key": "${NVD_KEY}",
            "sources": [{"id": "feed-${NVD_KEY}", "type": "rss", "url": "https://feeds.example.net/x.xml"}],
        },
        # a disabled entry can supply the value an enabled id borrows
        {
            "sources": [
                {"id": "changes", "type": "changedetection", "url": "https://c.example.net", "api_key": "${CD_TOKEN}"}
            ]
        },
    ],
)
def test_the_credential_inventory_does_not_depend_on_the_kind_or_the_enabled_flag(tmp_path, document):
    path = tmp_path / "config.yml"
    document = {**document, "notifiers": [], "state_path": str(tmp_path / "state.json")}
    if document["sources"][-1].get("api_key") == "${CD_TOKEN}" and document["sources"][-1]["id"] == "changes":
        document["sources"].append({"id": "feed-${CD_TOKEN}", "type": "rss", "url": "https://feeds.example.net/x.xml"})
    path.write_text(yaml.safe_dump(document))
    with pytest.raises(ConfigError, match="may not be composed from a variable that supplies a credential"):
        load_config(
            path,
            {"CD_TOKEN": "AbCdEf123456", "SOURCE_KIND": "changedetection", "NVD_KEY": "AbCdEf123456"},
        )


def test_both_reference_spellings_are_the_same_variable(tmp_path):
    path = write_config(
        tmp_path,
        sources=[
            {
                "id": "feed-${CD_TOKEN}",
                "type": "changedetection",
                "url": "https://changes.example.net",
                "api_key": "${CD_TOKEN_FILE}",
            }
        ],
    )
    with pytest.raises(ConfigError, match="may not be composed from a variable that supplies a credential"):
        load_config(path, {})


def test_a_repeated_file_suffix_cannot_dodge_the_inventory(tmp_path):
    """``${X_FILE}``, ``${X_FILE_FILE}`` and ``${X}`` all read through one chain, so they are one variable."""
    path = write_config(
        tmp_path,
        sources=[
            {
                "id": "feed-${CD_TOKEN_FILE}",
                "type": "changedetection",
                "url": "https://changes.example.net",
                "api_key": "${CD_TOKEN_FILE_FILE}",
            }
        ],
    )
    with pytest.raises(ConfigError, match="may not be composed from a variable that supplies a credential") as raised:
        load_config(path, {})
    # The message names the id as written; no value exists yet, and none is printed.
    assert "feed-${CD_TOKEN_FILE}" in str(raised.value)


def test_a_non_scalar_credential_position_is_inventoried(tmp_path):
    # ``_expand`` resolves the strings inside a list, so a shape the scanner skipped would still supply the value.
    path = write_config(
        tmp_path,
        sources=[
            {
                "id": "feed-${TOKEN}",
                "type": "rss",
                "url": "https://feeds.example.net/security.xml",
                "token": ["${TOKEN}"],
            }
        ],
    )
    with pytest.raises(ConfigError, match="may not be composed from a variable that supplies a credential"):
        load_config(path, {})


def test_a_genuinely_disabled_carrier_is_inventoried(tmp_path):
    path = write_config(
        tmp_path,
        sources=[
            {
                "id": "changes",
                "type": "changedetection",
                "enabled": False,
                "url": "https://changes.example.net",
                "api_key": "${CD_TOKEN}",
            },
            {"id": "feed-${CD_TOKEN}", "type": "rss", "url": "https://feeds.example.net/x.xml"},
        ],
    )
    with pytest.raises(ConfigError, match="may not be composed from a variable that supplies a credential"):
        load_config(path, {"CD_TOKEN": "AbCdEf123456"})


def test_a_notifier_header_credential_is_inventoried(tmp_path):
    path = write_config(tmp_path, sources=[{"id": "feed-${HOOK_TOKEN}", "type": "rss", "url": "https://a.example.net"}])
    document = yaml.safe_load(path.read_text())
    document["notifiers"] = [
        {
            "id": "chat",
            "type": "webhook",
            "url": "${HOOK}",
            "headers": {"Authorization": "Bearer ${HOOK_TOKEN}"},
        }
    ]
    path.write_text(yaml.safe_dump(document))
    with pytest.raises(ConfigError, match="may not be composed from a variable that supplies a credential"):
        load_config(path, {"HOOK": "https://hooks.example.net/x", "HOOK_TOKEN": "AbCdEf123456"})


def test_a_storage_url_cannot_lend_its_variable_to_an_id(tmp_path):
    """``storage:`` can embed a password, so it is a credential position like a notifier's url."""
    path = write_config(
        tmp_path,
        sources=[{"id": "feed-${DB_PASSWORD}", "type": "rss", "url": "https://feeds.example.net/security.xml"}],
        extra="storage: postgresql://radar:${DB_PASSWORD}@db.example/radar\n",
    )
    with pytest.raises(ConfigError, match="may not be composed from a variable that supplies a credential"):
        load_config(path, {"DB_PASSWORD": "AbCdEf123456"})
    # A variable that supplies no credential anywhere stays usable in an id.
    path = write_config(
        tmp_path,
        sources=[{"id": "feed-${TENANT}", "type": "rss", "url": "https://feeds.example.net/security.xml"}],
        extra=f"storage: sqlite:///{tmp_path}/state.db\n",
    )
    cfg = load_config(path, {"TENANT": "acme"})
    assert cfg.sources[0]["id"] == "feed-acme"


def test_a_token_bearing_url_cannot_lend_its_variable_to_an_id(tmp_path):
    """``?token=${FEED_TOKEN}`` is a documented shape for a private feed, so it is a credential position."""
    path = write_config(
        tmp_path,
        sources=[
            {
                "id": "feed-${FEED_TOKEN}",
                "type": "rss",
                "url": "https://feeds.example.net/security.xml?token=${FEED_TOKEN}",
            }
        ],
    )
    with pytest.raises(ConfigError, match="may not be composed from a variable that supplies a credential"):
        load_config(path, {"FEED_TOKEN": "AbCdEf123456"})
    # The path, the userinfo, and a query with no path at all are credential positions too.
    for url in (
        "https://feeds.example.net/${FEED_TOKEN}/security.xml",
        "https://${FEED_TOKEN}@feeds.example.net/security.xml",
        "https://feeds.example.net?token=${FEED_TOKEN}",
        "https://feeds.example.net#${FEED_TOKEN}",
    ):
        path = write_config(tmp_path, sources=[{"id": "feed-${FEED_TOKEN}", "type": "rss", "url": url}])
        with pytest.raises(ConfigError, match="may not be composed from a variable that supplies a credential"):
            load_config(path, {})


def test_a_host_label_reference_is_a_name_and_may_compose_an_id(tmp_path):
    path = write_config(
        tmp_path,
        sources=[{"id": "feed-${TENANT}", "type": "rss", "url": "https://${TENANT}.feeds.example.net/security.xml"}],
    )
    cfg = load_config(path, {"TENANT": "acme"})
    assert cfg.sources[0]["id"] == "feed-acme"


def test_a_nested_mapping_credential_position_is_inventoried(tmp_path):
    path = write_config(
        tmp_path,
        sources=[
            {
                "id": "feed-${TOKEN}",
                "type": "rss",
                "url": "https://feeds.example.net/security.xml",
                "token": {"outer": [{"inner": "${TOKEN}"}]},
            }
        ],
    )
    with pytest.raises(ConfigError, match="may not be composed from a variable that supplies a credential"):
        load_config(path, {})


def test_a_failed_attempt_keeps_the_last_success(tmp_path):
    failing = {"on": False}

    def toggling(method, url, headers, body):
        return (0, {}, b"") if failing["on"] else (200, {"ETag": '"v1"'}, RSS)

    _, runtime, _ = make_client(tmp_path, transport=toggling)
    assert pipeline.run_pass(runtime.cfg, runtime.sources, runtime.notifiers, http=toggling) == 0
    first = json.loads((tmp_path / "data" / "state.json").read_text())["source_health"]["vendor"]
    assert first["ok"] is True and first["ok_at"] == first["at"]
    failing["on"] = True
    assert pipeline.run_pass(runtime.cfg, runtime.sources, runtime.notifiers, http=toggling) == 1
    after = json.loads((tmp_path / "data" / "state.json").read_text())["source_health"]["vendor"]
    assert after["ok"] is False
    assert after["items"] == 0
    assert "unreachable" in after["error"]
    assert after["ok_at"] == first["ok_at"], "the last success survives a later failure"
    assert after["at"] >= first["at"]


# --- a source's own threshold block ------------------------------------------------------------


def test_the_overlay_may_edit_a_yaml_sources_threshold_block(tmp_path):
    """A YAML source keeps its keys in the file, but the overlay may override its numbers."""
    merged = load_config(
        write_config(tmp_path),
        {},
        settings={"sources": {"vendor": {"thresholds": {"critical_cvss": 7.5}}}},
    )
    assert merged.thresholds_for("vendor") == Thresholds(7.5, 0.1, 4.0)
    assert merged.thresholds_for(None) == Thresholds()


def test_a_source_edit_threshold_must_be_a_mapping():
    with pytest.raises(ConfigError) as caught:
        validate_settings({"sources": {"vendor": {"thresholds": ["critical_cvss"]}}})
    assert str(caught.value) == ("settings: source 'vendor': thresholds must be a mapping of threshold name to number")


def test_an_added_source_carries_its_own_threshold_block(tmp_path):
    entry = {
        "id": "added",
        "type": "rss",
        "url": "https://feeds.example.net/added.xml",
        "thresholds": {"critical_epss": 0.4},
    }
    validate_settings({"sources_added": [entry]})
    merged = load_config(write_config(tmp_path), {}, settings={"sources_added": [entry]})
    assert merged.thresholds_for("added") == Thresholds(9.0, 0.4, 4.0)
    assert merged.thresholds_for("vendor") == Thresholds(), "the YAML source is untouched"


def test_an_added_source_threshold_must_be_a_mapping():
    with pytest.raises(ConfigError) as caught:
        validate_settings(
            {
                "sources_added": [
                    {"id": "added", "type": "rss", "url": "https://feeds.example.net/a.xml", "thresholds": "high"}
                ]
            }
        )
    assert str(caught.value) == (
        "settings: added source 'added': thresholds must be a mapping of threshold name to number"
    )


def test_an_added_source_block_is_judged_by_the_config_validator(tmp_path):
    entry = {
        "id": "added",
        "type": "rss",
        "url": "https://feeds.example.net/added.xml",
        "thresholds": {"critical_cvss": 0},
    }
    with pytest.raises(ConfigError) as caught:
        load_config(write_config(tmp_path), {}, settings={"sources_added": [entry]})
    assert str(caught.value) == "added: thresholds.critical_cvss must be above 0 and at most 10"


def test_editing_an_added_source_keeps_its_threshold_block(tmp_path):
    """The sources form rewrites an added entry whole, so the block it does not edit must survive."""
    stored = {
        "sources_added": [
            {
                "id": "added",
                "type": "rss",
                "url": "https://feeds.example.net/a.xml",
                "thresholds": {"critical_cvss": 7.5},
            }
        ]
    }
    save_settings(settings_path(tmp_path / "data" / "state.json"), stored, now=0)
    client, runtime, _ = make_client(tmp_path)
    assert runtime.cfg.thresholds_for("added") == Thresholds(7.5, 0.1, 4.0)

    csrf, fingerprint = signed_in(client)
    saved = client.post(
        "/config/sources",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "enabled:vendor": "1",
            "enabled:added": "1",
            "added_url:added": "https://feeds.example.net/b.xml",
        },
        follow_redirects=False,
    )

    assert saved.status_code == 303
    assert overlay(tmp_path)["sources_added"][0]["thresholds"] == {"critical_cvss": 7.5}
    runtime.reload(blocking=True)
    assert runtime.cfg.thresholds_for("added") == Thresholds(7.5, 0.1, 4.0)


def test_the_sources_form_keeps_a_source_threshold_override(tmp_path):
    """Editing enablement or the watch tag must not drop the numbers the thresholds form saved."""
    save_settings(
        settings_path(tmp_path / "data" / "state.json"),
        {"sources": {"vendor": {"thresholds": {"critical_cvss": 7.5}}}},
        now=0,
    )
    client, runtime, _ = make_client(tmp_path)
    assert runtime.cfg.thresholds_for("vendor") == Thresholds(7.5, 0.1, 4.0)

    csrf, fingerprint = signed_in(client)
    saved = client.post(
        "/config/sources",
        data={"csrf": csrf, "fingerprint": fingerprint, "enabled:vendor": "1", "tag:vendor": "security"},
        follow_redirects=False,
    )

    assert saved.status_code == 303
    stored = overlay(tmp_path)["sources"]["vendor"]
    assert stored["thresholds"] == {"critical_cvss": 7.5}
    assert stored["enabled"] is True and stored["tag"] == "security"


# --- a per-source poll interval, edited on the same page -----------------------------------------


def test_a_source_interval_is_saved_from_the_config_page(tmp_path):
    client, runtime, _ = make_client(tmp_path)
    csrf, fingerprint = signed_in(client)
    response = client.post(
        "/config/sources",
        data={
            "csrf": csrf,
            "fingerprint": fingerprint,
            "enabled:vendor": "1",
            "tag:vendor": "",
            "interval:vendor": "30m",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert overlay(tmp_path)["sources"] == {"vendor": {"enabled": True, "tag": "", "interval": "30m"}}
    runtime.reload(blocking=True)
    assert runtime.cfg.source_intervals == {"vendor": 1800}


def test_an_added_source_can_carry_an_interval(tmp_path):
    client, runtime, _ = make_client(tmp_path)
    response = new_source(
        client,
        **{"new:type": "rss", "new:url": "https://nodejs.org/feed/vulnerability.xml", "new:interval": "1h"},
    )
    assert response.status_code == 303
    assert overlay(tmp_path)["sources_added"][0]["interval"] == "1h"
    runtime.reload(blocking=True)
    assert runtime.cfg.source_intervals == {"nodejs-org": 3600}


# --- importing an OPML subscription list ---------------------------------------------------------


def opml(*urls: str) -> str:
    """An OPML 2.0 document with one folder holding one outline per URL."""
    outlines = "".join(f'<outline text="{urlsplit(url).hostname or "feed"}" xmlUrl="{url}"/>' for url in urls)
    return f'<?xml version="1.0"?><opml version="2.0"><body><outline text="Vendors">{outlines}</outline></body></opml>'


def import_opml(client: TestClient, document: str):
    csrf, fingerprint = signed_in(client)
    return client.post(
        "/config/sources/opml",
        data={"csrf": csrf, "fingerprint": fingerprint, "opml": document},
        follow_redirects=False,
    )


def test_opml_import_adds_every_feed_as_an_rss_source(tmp_path):
    client, runtime, _ = make_client(tmp_path)
    response = import_opml(client, opml("https://a.example.net/feed.xml", "https://b.example.net/security.xml"))
    assert response.status_code == 200
    assert "added 2, skipped 0" in response.text
    added = overlay(tmp_path)["sources_added"]
    assert added == [
        {"id": "a-example-net", "type": "rss", "url": "https://a.example.net/feed.xml"},
        {"id": "b-example-net", "type": "rss", "url": "https://b.example.net/security.xml"},
    ]
    # The outline title is a label, not a watch tag: the tag column is meaningful for changedetection only.
    assert all("tag" not in entry for entry in added)
    runtime.reload(blocking=True)
    assert [source.id for source in runtime.sources] == ["vendor", "a-example-net", "b-example-net"]


def test_opml_import_skips_a_feed_already_configured(tmp_path):
    client, _, _ = make_client(tmp_path)
    response = import_opml(
        client,
        opml("https://feeds.example.net/security.xml", "https://a.example.net/feed.xml"),
    )
    assert response.status_code == 200
    assert "added 1, skipped 1" in response.text
    assert "already configured" in response.text
    assert [entry["id"] for entry in overlay(tmp_path)["sources_added"]] == ["a-example-net"]


def test_opml_import_skips_a_feed_repeated_in_the_document(tmp_path):
    client, _, _ = make_client(tmp_path)
    response = import_opml(
        client,
        opml(
            "https://a.example.net/feed.xml",
            "https://a.example.net/feed.xml",
            "https://b.example.net/security.xml",
        ),
    )
    assert response.status_code == 200
    assert "added 2, skipped 1" in response.text
    assert [entry["id"] for entry in overlay(tmp_path)["sources_added"]] == [
        "a-example-net",
        "b-example-net",
    ]


def test_opml_import_of_the_same_document_again_adds_nothing(tmp_path):
    client, _, _ = make_client(tmp_path)
    assert import_opml(client, opml("https://a.example.net/feed.xml")).status_code == 200
    response = import_opml(client, opml("https://a.example.net/feed.xml"))
    assert response.status_code == 200
    assert "added 0, skipped 1" in response.text
    assert [entry["id"] for entry in overlay(tmp_path)["sources_added"]] == ["a-example-net"]


def test_opml_import_refuses_a_document_with_no_feed(tmp_path):
    client, _, _ = make_client(tmp_path)
    response = import_opml(
        client,
        '<?xml version="1.0"?><opml version="2.0"><body><outline text="Empty folder"/></body></opml>',
    )
    assert response.status_code == 400
    assert "contains no feed" in response.text
    assert not (tmp_path / "data" / "settings.json").exists()


def test_opml_import_refuses_a_document_that_does_not_parse(tmp_path):
    client, _, _ = make_client(tmp_path)
    response = import_opml(client, "not an OPML document")
    assert response.status_code == 400
    assert "could not be read" in response.text
    assert not (tmp_path / "data" / "settings.json").exists()


def test_opml_import_checks_every_url_before_writing(tmp_path):
    client, _, _ = make_client(tmp_path)
    response = import_opml(
        client,
        opml("https://a.example.net/feed.xml", "ftp://b.example.net/security.xml"),
    )
    assert response.status_code == 400
    assert "not an http or https url" in response.text
    assert not (tmp_path / "data" / "settings.json").exists(), "one unusable feed refuses the whole batch"


def test_opml_import_refuses_a_private_destination(tmp_path):
    client, _, _ = make_client(tmp_path, resolve=lambda host: ("172.16.0.9",))
    response = import_opml(client, opml("https://nas.example.net/feed.xml"))
    assert response.status_code == 400
    assert "private network" in response.text
    assert not (tmp_path / "data" / "settings.json").exists()


def test_opml_import_expands_an_imported_reference_when_skipping_a_configured_feed(tmp_path):
    client, _, _ = make_client(
        tmp_path,
        sources=[{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"}],
        environment={"FEED_URL": "https://feeds.example.net/security.xml"},
    )
    response = import_opml(client, opml("${FEED_URL}"))
    assert response.status_code == 200
    assert "added 0, skipped 1" in response.text
    assert not (tmp_path / "data" / "settings.json").exists(), "an already-configured feed writes nothing"


def test_opml_import_treats_a_reference_and_its_literal_as_one_subscription(tmp_path):
    client, _, _ = make_client(tmp_path, environment={"FEED_URL": "https://a.example.net/feed.xml"})
    response = import_opml(client, opml("https://a.example.net/feed.xml", "${FEED_URL}"))
    assert response.status_code == 200
    assert "added 1, skipped 1" in response.text
    assert [entry["url"] for entry in overlay(tmp_path)["sources_added"]] == ["https://a.example.net/feed.xml"]


def test_opml_import_stores_an_imported_reference_as_written(tmp_path):
    client, runtime, _ = make_client(tmp_path, environment={"FEED_URL": "https://b.example.net/feed.xml"})
    response = import_opml(client, opml("${FEED_URL}"))
    assert response.status_code == 200
    assert "added 1, skipped 0" in response.text
    assert overlay(tmp_path)["sources_added"][0]["url"] == "${FEED_URL}"
    runtime.reload(blocking=True)
    assert "https://b.example.net/feed.xml" in [source.url for source in runtime.sources]
