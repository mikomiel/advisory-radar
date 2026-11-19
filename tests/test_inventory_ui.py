"""The inventory as an operator meets it: the page, the upload, the evidence on an advisory, the /alerts filter,
and what a real pass does (and does not do) about an inventory.

Behaviour, not markup: documents arrive as bytes through the routes a browser would use, and the assertions
read the stored sidecar, the facts of the pages and the messages a pass delivered.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import urllib.parse

import pytest

from advisory_radar import applicability, core, inventory, pipeline, settings
from advisory_radar.config import ConfigError, load_config
from advisory_radar.web import UploadRefused, _advisory_token, parse_upload
from inventory_fixtures import (
    AFFECTED_NPM,
    PACKAGE,
    cyclonedx,
    multipart,
    osv_facts,
    osv_scanner,
    sbom_component,
    scan_finding,
    scan_with_ranges,
)
from test_pipeline import WindowSource
from test_producer_to_ui import CHANNEL, CONFIG, CVE_A, FEED, FEED_URL, GHSA_A, SOURCE_ID, Channel, Upstream, read_feed
from test_ui import DAY, NOW, make_client, sign_in

FACT = re.compile(r"<div><dt>([^<]*)</dt><dd>(.*?)</dd></div>", re.S)
TAGS = re.compile(r"<[^>]*>")
CSRF = re.compile(r'name="csrf" value="([0-9a-f]{64})"')


def words(markup: str) -> str:
    import html

    return " ".join(html.unescape(TAGS.sub(" ", markup)).split())


def facts(page: str) -> dict[str, str]:
    return {name: words(value) for name, value in FACT.findall(page)}


def stored(runtime, document: bytes, *, name: str = "sbom.cdx.json", at: int = NOW) -> None:
    """Put an inventory where an upload would have put it, without going through the page."""
    path = inventory.inventory_path(runtime.cfg.state_path)
    inventory.save(path, inventory.parse(document, name=name, now=at, origin="upload"))


def advisory_state(*records: tuple[str, list[str]]) -> dict:
    """A state with one delivered advisory per ``(identifier, ids)``, and the affected data of the GHSA below."""
    state = core.new_state()
    state["deliveries"] = {}
    for number, (identifier, ids) in enumerate(records):
        state["seen"][identifier] = {"at": NOW - number, "outcome": "delivered", "delivery": f"d{number}"}
        state["deliveries"][f"d{number}"] = {
            "at": NOW - number,
            "outcome": "delivered",
            "tag": "warning",
            "source_id": "vendor-feed",
            "source": f"Heading for {identifier}",
            "title": f"WARNING: {identifier}",
            "link": "https://vendor.example.net/advisory",
            "kind": "new",
            "ids": ids,
            "cves": [item for item in ids if item.startswith("CVE-")],
            "levels": {},
            "scores": {},
            "delivered_to": ["ops"],
        }
    applicability.record_facts(state, {GHSA_A: osv_facts(AFFECTED_NPM, CVE_A)}, NOW)
    return state


def evidence(client, identifier: str = GHSA_A) -> str:
    page = client.get(f"/advisories/{_advisory_token(identifier)}")
    assert page.status_code == 200
    return facts(page.text).get("Inventory evidence", "")


def listed(client, value: str) -> list[str]:
    """The identifiers /alerts lists under one value of its Inventory filter ("" is no filter)."""
    page = client.get("/alerts", params={"inventory": value}).text
    return re.findall(r"<td><a href='/advisories/[^']*'>([^<]+)</a></td>", page)


# --- the page and the upload --------------------------------------------------------------------


def test_the_inventory_page_is_a_section_that_explains_the_empty_state(tmp_path):
    client, token, _ = make_client(tmp_path)
    sign_in(client, token)
    response = client.get("/inventory")
    assert response.status_code == 200
    assert "<a href='/inventory'" in response.text, "the page is part of the navigation"
    assert "No inventory has been imported" in response.text
    assert 'enctype="multipart/form-data"' in response.text and 'action="/inventory/upload"' in response.text
    assert response.headers["cache-control"] == "no-store"


def test_an_upload_is_stored_with_its_provenance_and_shown_on_the_page(tmp_path):
    document = cyclonedx(sbom_component(PACKAGE, "2.3.0"), sbom_component("other-lib", "1.0.0"))
    client, token, runtime = make_client(tmp_path)
    csrf = sign_in(client, token)
    body, content_type = multipart({"csrf": (None, csrf), "file": ("../ci/sbom.cdx.json", document)})
    response = client.post(
        "/inventory/upload", content=body, headers={"content-type": content_type}, follow_redirects=False
    )
    assert response.status_code == 303 and response.headers["location"].startswith("/inventory")
    stored_document = json.loads(inventory.inventory_path(runtime.cfg.state_path).read_text())
    # The digest is the digest of the exact bytes that were uploaded, and the name is the base name only.
    assert stored_document["sha256"] == hashlib.sha256(document).hexdigest()
    assert (stored_document["format"], stored_document["name"], stored_document["origin"]) == (
        "cyclonedx",
        "sbom.cdx.json",
        "upload",
    )
    assert stored_document["imported_at"] > 0 and len(stored_document["components"]) == 2
    shown = facts(client.get(response.headers["location"]).text)
    assert shown["Format"] == "cyclonedx" and shown["File name"] == "sbom.cdx.json"
    assert shown["SHA-256"] == hashlib.sha256(document).hexdigest()
    assert shown["Components"] == "2"


def test_an_upload_framed_by_the_clients_own_encoder_is_stored_byte_for_byte(tmp_path):
    """The ``multipart`` fixture was written beside the parser; this body is framed by an independent encoder."""
    document = json.dumps(json.loads(cyclonedx(sbom_component(PACKAGE, "2.3.0"))), indent=2).encode()
    assert document.count(b"\n") > 5, "the content carries real line breaks"
    client, token, runtime = make_client(tmp_path)
    csrf = sign_in(client, token)
    response = client.post(
        "/inventory/upload",
        data={"csrf": csrf},
        files={"file": ("sbom.cdx.json", document, "application/json")},
        follow_redirects=False,
    )
    assert response.status_code == 303 and response.headers["location"].startswith("/inventory")
    stored_document = json.loads(inventory.inventory_path(runtime.cfg.state_path).read_text())
    assert (stored_document["sha256"], stored_document["name"], stored_document["size"]) == (
        hashlib.sha256(document).hexdigest(),
        "sbom.cdx.json",
        len(document),
    )
    wrong = client.post(
        "/inventory/upload", data={"csrf": "0" * 64}, files={"file": ("sbom.cdx.json", document, "application/json")}
    )
    assert wrong.status_code == 403, "the token is read from the same encoder's form field"


def test_a_second_upload_replaces_the_first_and_a_refused_one_keeps_it(tmp_path):
    client, token, runtime = make_client(tmp_path)
    csrf = sign_in(client, token)
    path = inventory.inventory_path(runtime.cfg.state_path)

    def upload(content: bytes, filename: str = "sbom.json"):
        body, content_type = multipart({"csrf": (None, csrf), "file": (filename, content)})
        return client.post(
            "/inventory/upload",
            content=body,
            headers={"content-type": content_type, "accept": "text/html"},
            follow_redirects=False,
        )

    assert upload(cyclonedx(sbom_component(PACKAGE, "2.3.0"))).status_code == 303
    first = path.read_text()
    refused = upload(b'{"not": "an inventory"}', "evil.json")
    assert refused.status_code == 400 and "not an OSV-Scanner result" in refused.text
    assert path.read_text() == first, "a refused import never changes the stored inventory"
    assert upload(cyclonedx(sbom_component("another-lib", "9.9.9"))).status_code == 303
    assert json.loads(path.read_text())["components"] == [
        {"ecosystem": "npm", "name": "another-lib", "version": "9.9.9"}
    ]


def test_an_upload_needs_a_session_and_the_form_token(tmp_path):
    client, token, runtime = make_client(tmp_path)
    document = cyclonedx(sbom_component(PACKAGE, "2.3.0"))
    path = inventory.inventory_path(runtime.cfg.state_path)
    body, content_type = multipart({"csrf": (None, "0" * 64), "file": ("sbom.json", document)})
    anonymous = client.post(
        "/inventory/upload", content=body, headers={"content-type": content_type}, follow_redirects=False
    )
    assert anonymous.status_code == 303 and anonymous.headers["location"] == "/login"
    sign_in(client, token)
    forged = client.post("/inventory/upload", content=body, headers={"content-type": content_type})
    assert forged.status_code == 403
    assert not path.exists()
    # The token may also travel in the header, as for every other state-changing request.
    csrf = CSRF.search(client.get("/").text).group(1)
    headerless, content_type = multipart({"file": ("sbom.json", document)})
    accepted = client.post(
        "/inventory/upload",
        content=headerless,
        headers={"content-type": content_type, "x-csrf-token": csrf},
        follow_redirects=False,
    )
    assert accepted.status_code == 303 and path.exists()


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param({"file": ("a.json", "x"), "extra": (None, "y")}, id="unknown-part"),
        pytest.param({"file": ("a.json", "x"), "file ": ("b.json", "y")}, id="unknown-name"),
        pytest.param({}, id="no-file"),
        pytest.param({"file": (None, "x")}, id="file-without-filename"),
    ],
)
def test_a_malformed_multipart_body_is_refused_without_a_stored_inventory(tmp_path, fields):
    client, token, runtime = make_client(tmp_path)
    csrf = sign_in(client, token)
    body, content_type = multipart({"csrf": (None, csrf), **fields})
    response = client.post("/inventory/upload", content=body, headers={"content-type": content_type})
    assert response.status_code == 400
    assert not inventory.inventory_path(runtime.cfg.state_path).exists()


def test_the_inventory_page_needs_a_session(tmp_path):
    client, _, _ = make_client(tmp_path)
    anonymous = client.get("/inventory", follow_redirects=False)
    assert anonymous.status_code == 303 and anonymous.headers["location"] == "/login"


BOUNDARY_TYPE = "multipart/form-data; boundary=B"
TOKEN_PART = b'Content-Disposition: form-data; name="csrf"\r\n\r\nabc'
FILE_PART = b'Content-Disposition: form-data; name="file"; filename="a.json"\r\n\r\n{}'


def form(*parts: bytes, before: bytes = b"", after: bytes = b"") -> bytes:
    return before + b"".join(b"--B\r\n" + part + b"\r\n" for part in parts) + b"--B--\r\n" + after


def test_the_upload_parser_reads_the_token_the_file_name_and_the_exact_bytes():
    assert parse_upload(form(TOKEN_PART, FILE_PART), BOUNDARY_TYPE) == (b"abc", "a.json", b"{}")
    assert parse_upload(form(FILE_PART, TOKEN_PART), BOUNDARY_TYPE) == (b"abc", "a.json", b"{}")
    assert parse_upload(form(FILE_PART), BOUNDARY_TYPE) == (b"", "a.json", b"{}"), "the missing token is refused later"
    raw = b'Content-Disposition: form-data; name="file"; filename="a.json"\r\n\r\n'
    content = b"\r\n\r\nline\r\n--Z\x00\xff\r\n"
    assert parse_upload(form(raw + content), BOUNDARY_TYPE)[2] == content, "the content is returned byte for byte"
    quoted = 'Content-Disposition: form-data; name="file"; filename="zażółć.json"\r\n\r\n{}'.encode()
    assert parse_upload(form(quoted), BOUNDARY_TYPE)[1] == "zażółć.json"
    with_quotes = 'multipart/form-data; boundary="B"'
    assert parse_upload(form(FILE_PART), with_quotes)[1] == "a.json"


@pytest.mark.parametrize(
    ("body", "content_type", "message"),
    [
        pytest.param(form(FILE_PART), "application/x-www-form-urlencoded", "not a multipart form", id="not-multipart"),
        pytest.param(form(FILE_PART), "multipart/form-data", "not a multipart form", id="no-boundary"),
        pytest.param(form(FILE_PART), "multipart/mixed; boundary=B", "not a multipart form", id="not-form-data"),
        pytest.param(form(FILE_PART), 'multipart/form-data; boundary="B B"', "not a multipart form", id="bad-boundary"),
        pytest.param(form(FILE_PART), "", "not a multipart form", id="no-content-type"),
        pytest.param(form(FILE_PART, before=b"junk\r\n"), BOUNDARY_TYPE, "malformed", id="text-before-the-first-part"),
        pytest.param(form(FILE_PART, after=b"junk"), BOUNDARY_TYPE, "malformed", id="text-after-the-last-part"),
        pytest.param(b"--B\r\n" + FILE_PART + b"\r\n", BOUNDARY_TYPE, "malformed", id="no-closing-delimiter"),
        pytest.param(b"", BOUNDARY_TYPE, "malformed", id="empty"),
        pytest.param(b"--B--\r\n", BOUNDARY_TYPE, "malformed", id="no-parts"),
        pytest.param(
            form(b'Content-Disposition: form-data; name="file"'), BOUNDARY_TYPE, "malformed", id="no-blank-line"
        ),
        pytest.param(form(b"X-Pad: " + b"a" * 3000 + b"\r\n\r\n{}"), BOUNDARY_TYPE, "malformed", id="header-too-long"),
        pytest.param(form(FILE_PART, FILE_PART), BOUNDARY_TYPE, "does not offer", id="file-twice"),
        pytest.param(form(TOKEN_PART, TOKEN_PART, FILE_PART), BOUNDARY_TYPE, "does not offer", id="token-twice"),
        pytest.param(
            form(FILE_PART, b'Content-Disposition: form-data; name="x"\r\n\r\n1'),
            BOUNDARY_TYPE,
            "does not offer",
            id="extra",
        ),
        pytest.param(form(FILE_PART, b"X-Other: 1\r\n\r\n1"), BOUNDARY_TYPE, "does not offer", id="no-disposition"),
        pytest.param(
            form(b'Content-Disposition: attachment; name="file"; filename="a"\r\n\r\n1'),
            BOUNDARY_TYPE,
            "does not offer",
            id="attachment",
        ),
        pytest.param(form(TOKEN_PART), BOUNDARY_TYPE, "no file", id="no-file"),
        pytest.param(
            form(b'Content-Disposition: form-data; name="file"\r\n\r\n{}'),
            BOUNDARY_TYPE,
            "no file",
            id="file-without-filename",
        ),
    ],
)
def test_the_upload_parser_refuses_anything_but_the_one_form_the_page_offers(body, content_type, message):
    with pytest.raises(UploadRefused, match=message):
        parse_upload(body, content_type)


def test_an_upload_that_is_not_multipart_or_is_too_large_is_refused(tmp_path):
    client, token, runtime = make_client(tmp_path)
    csrf = sign_in(client, token)
    not_multipart = client.post("/inventory/upload", data={"csrf": csrf})
    assert not_multipart.status_code == 400
    body, content_type = multipart(
        {"csrf": (None, csrf), "file": ("big.json", b"x" * (inventory.MAX_INVENTORY_BYTES + 128 * 1024))}
    )
    too_large = client.post("/inventory/upload", content=body, headers={"content-type": content_type})
    assert too_large.status_code == 413
    assert not inventory.inventory_path(runtime.cfg.state_path).exists()


def test_a_hostile_file_name_and_error_are_escaped_never_reflected(tmp_path):
    client, token, _ = make_client(tmp_path)
    csrf = sign_in(client, token)
    name = "<img src=x onerror=alert(1)>.json"
    body, content_type = multipart({"csrf": (None, csrf), "file": (name, cyclonedx(sbom_component(PACKAGE, "1.0.0")))})
    done = client.post(
        "/inventory/upload", content=body, headers={"content-type": content_type}, follow_redirects=False
    )
    page = client.get(done.headers["location"]).text
    assert "<img src=x" not in page and "&lt;img src=x onerror=alert(1)&gt;.json" in page
    # A refused document echoes the limit or the field that failed, never the offending value.
    hostile = json.dumps({"bomFormat": "CycloneDX", "specVersion": "<script>alert(2)</script>"}).encode()
    body, content_type = multipart({"csrf": (None, csrf), "file": ("x.json", hostile)})
    refused = client.post("/inventory/upload", content=body, headers={"content-type": content_type})
    assert refused.status_code == 400 and "<script>" not in refused.text
    assert refused.headers["cache-control"] == "no-store"


def test_a_refusal_message_is_escaped_whatever_it_says(tmp_path, monkeypatch):
    client, token, _ = make_client(tmp_path)
    csrf = sign_in(client, token)

    def refuse(data, **kwargs):
        raise inventory.InventoryError("<b>bold</b> & more")

    monkeypatch.setattr(inventory, "parse", refuse)
    body, content_type = multipart({"csrf": (None, csrf), "file": ("x.json", b"{}")})
    refused = client.post("/inventory/upload", content=body, headers={"content-type": content_type})
    assert refused.status_code == 400 and "<b>bold</b>" not in refused.text
    assert "&lt;b&gt;bold&lt;/b&gt; &amp; more" in refused.text


def test_an_inventory_that_cannot_be_stored_is_reported_and_nothing_is_kept(tmp_path, monkeypatch):
    client, token, runtime = make_client(tmp_path)
    csrf = sign_in(client, token)

    def full_disk(path, document):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(inventory, "save", full_disk)
    body, content_type = multipart(
        {"csrf": (None, csrf), "file": ("s.json", cyclonedx(sbom_component(PACKAGE, "1.0.0")))}
    )
    failed = client.post("/inventory/upload", content=body, headers={"content-type": content_type})
    assert failed.status_code == 500 and "could not be stored" in failed.text
    assert "No space left" not in failed.text, "an operating-system message is not shown to the browser"
    assert not inventory.inventory_path(runtime.cfg.state_path).exists()


def test_uploading_a_scan_with_unreadable_ranges_in_a_record_imports_it_and_names_no_fix(tmp_path):
    """Reproduces the reported fault: this upload raised a TypeError out of the importer and imported nothing."""
    client, token, runtime = make_client(tmp_path)
    csrf = sign_in(client, token)
    body, content_type = multipart({"csrf": (None, csrf), "file": ("scan.json", scan_with_ranges(1, GHSA_A))})
    response = client.post(
        "/inventory/upload", content=body, headers={"content-type": content_type}, follow_redirects=False
    )
    assert response.status_code == 303
    stored_document = json.loads(inventory.inventory_path(runtime.cfg.state_path).read_text())
    assert [(item["ids"], item["fixed"]) for item in stored_document["findings"]] == [([GHSA_A], "")]


def test_an_upload_that_trips_a_reader_is_refused_with_a_400_and_the_inventory_stays(tmp_path, monkeypatch):
    client, token, runtime = make_client(tmp_path)
    csrf = sign_in(client, token)
    stored(runtime, cyclonedx(sbom_component("kept-lib", "1.0.0")), name="kept.json")
    path = inventory.inventory_path(runtime.cfg.state_path)
    kept = path.read_bytes()

    def broken(document):
        raise RuntimeError("secret-<b>value</b>")

    monkeypatch.setattr(inventory, "_osv_scanner", broken)
    scan = osv_scanner(scan_finding("npm", PACKAGE, "2.3.0", GHSA_A))
    body, content_type = multipart({"csrf": (None, csrf), "file": ("scan.json", scan)})
    refused = client.post("/inventory/upload", content=body, headers={"content-type": content_type})
    assert refused.status_code == 400 and "unexpected RuntimeError" in refused.text
    assert "current inventory is unchanged" in refused.text and "secret" not in refused.text
    assert refused.headers["cache-control"] == "no-store"
    assert path.read_bytes() == kept


# --- the evidence on an advisory ----------------------------------------------------------------


def test_an_advisory_page_shows_installed_applicability_apart_from_text_relevance(tmp_path):
    state = advisory_state((GHSA_A, [GHSA_A, CVE_A]))
    client, token, runtime = make_client(tmp_path, state=state)
    sign_in(client, token)
    page = client.get(f"/advisories/{_advisory_token(GHSA_A)}").text
    assert "Inventory evidence" not in page, "an installation without an inventory shows no evidence"
    stored(runtime, cyclonedx(sbom_component(PACKAGE, "2.3.0")))
    shown = facts(client.get(f"/advisories/{_advisory_token(GHSA_A)}").text)
    assert "applies" in shown["Inventory evidence"]
    assert "installed 2.3.0, fixed in 2.3.1" in shown["Inventory evidence"]
    assert "cyclonedx" in shown["Inventory evidence"] and "sbom.cdx.json" in shown["Inventory evidence"]
    assert "Matched products" in shown, "text relevance keeps its own row"


def test_a_stale_inventory_that_still_says_applies_notes_its_age(tmp_path):
    client, token, runtime = make_client(tmp_path, state=advisory_state((GHSA_A, [GHSA_A, CVE_A])))
    sign_in(client, token)
    stored(runtime, cyclonedx(sbom_component(PACKAGE, "2.3.0")), at=NOW - 45 * DAY)
    shown = evidence(client)
    assert shown.startswith("applies") and "installed 2.3.0, fixed in 2.3.1" in shown
    assert "45 days old (limit 30)" in shown


@pytest.mark.parametrize(
    ("sbom", "stored_at", "expected"),
    [
        pytest.param(cyclonedx(sbom_component(PACKAGE, "2.3.0")), NOW, "applies", id="affected"),
        pytest.param(cyclonedx(sbom_component(PACKAGE, "2.3.1")), NOW, "not affected", id="fixed"),
        pytest.param(cyclonedx(sbom_component(PACKAGE, None)), NOW, "without a version", id="unknown-version"),
        pytest.param(cyclonedx(sbom_component("other-lib", "1.0.0")), NOW, "no matching component", id="missing"),
        pytest.param(cyclonedx(sbom_component(PACKAGE, "2.3.1")), NOW - 45 * DAY, "45 days old", id="stale"),
    ],
)
def test_the_five_results_read_differently_on_the_page(tmp_path, sbom, stored_at, expected):
    client, token, runtime = make_client(tmp_path, state=advisory_state((GHSA_A, [GHSA_A, CVE_A])))
    sign_in(client, token)
    stored(runtime, sbom, at=stored_at)
    assert expected in evidence(client)


def test_a_scan_that_lists_a_fixed_version_reads_unknown_and_never_not_affected(tmp_path):
    client, token, runtime = make_client(tmp_path, state=advisory_state((GHSA_A, [GHSA_A, CVE_A])))
    sign_in(client, token)
    fixed_for_another_advisory = scan_finding("npm", PACKAGE, "2.3.1", "GHSA-gggg-hhhh-iiii")
    stored(runtime, osv_scanner(fixed_for_another_advisory), name="scan.json")
    shown = evidence(client)
    assert shown.startswith("unknown")
    assert "lists only the packages it found something in" in shown and "another installed version" in shown
    assert "no comparable affected-version data" not in shown, "the sentence of another reason would be false here"
    assert listed(client, "not_affected") == []
    assert listed(client, "unknown") == [GHSA_A]
    stored(runtime, cyclonedx(sbom_component(PACKAGE, "2.3.1")))
    assert evidence(client).startswith("not affected"), "the same facts clear it from an SBOM"


def test_an_advisory_with_no_stored_affected_data_is_unknown_not_safe(tmp_path):
    state = advisory_state((CVE_A, [CVE_A]))
    client, token, runtime = make_client(tmp_path, state=state)
    sign_in(client, token)
    stored(runtime, cyclonedx(sbom_component(PACKAGE, "2.3.1")))
    shown = evidence(client, CVE_A)
    assert shown.startswith("unknown") and "no comparable affected-version data" in shown


def test_an_advisory_naming_an_id_nothing_covers_is_not_cleared_by_its_sibling(tmp_path):
    """Facts exist for GHSA_A only: a message that also names another advisory cannot be called not affected."""
    uncovered = "GHSA-dddd-eeee-ffff"
    state = advisory_state(
        (GHSA_A, [GHSA_A, CVE_A]), (uncovered, [GHSA_A, uncovered]), ("GHSA-gggg-hhhh-iiii", [CVE_A])
    )
    client, token, runtime = make_client(tmp_path, state=state)
    sign_in(client, token)
    stored(runtime, cyclonedx(sbom_component(PACKAGE, "2.3.1")))
    assert evidence(client, GHSA_A).startswith("not affected"), "covered by the record and its alias"
    unknown = evidence(client, uncovered)
    assert unknown.startswith("unknown") and "not for every vulnerability it names" in unknown
    assert evidence(client, "GHSA-gggg-hhhh-iiii").startswith("unknown"), "a CVE alone finds no stored record"
    assert listed(client, "not_affected") == [GHSA_A]
    assert sorted(listed(client, "unknown")) == sorted([uncovered, "GHSA-gggg-hhhh-iiii"])
    # The same uncovered advisory still reads "applies" when the installed version is affected.
    stored(runtime, cyclonedx(sbom_component(PACKAGE, "2.3.0")))
    assert evidence(client, uncovered).startswith("applies")


def test_an_unreadable_stored_inventory_is_named_not_mistaken_for_none(tmp_path):
    client, token, runtime = make_client(tmp_path, state=advisory_state((GHSA_A, [GHSA_A])))
    sign_in(client, token)
    inventory.inventory_path(runtime.cfg.state_path).write_text("{not json")
    assert "cannot be read" in evidence(client)
    page = client.get("/inventory")
    assert page.status_code == 200 and "cannot be read" in page.text
    # The filter agrees with the advisory page: what cannot be judged is unknown, and nothing else.
    assert listed(client, "unknown") == [GHSA_A]
    assert listed(client, "applies") == listed(client, "not_affected") == []


def test_a_stored_inventory_that_fails_unexpectedly_reads_as_unreadable_not_as_a_server_error(tmp_path, monkeypatch):
    client, token, runtime = make_client(tmp_path, state=advisory_state((GHSA_A, [GHSA_A, CVE_A])))
    sign_in(client, token)
    stored(runtime, cyclonedx(sbom_component(PACKAGE, "2.3.0")))

    def broken(document):
        raise RuntimeError("secret-<b>value</b>")

    monkeypatch.setattr(inventory, "Inventory", broken)
    page = client.get("/inventory")
    assert page.status_code == 200 and "cannot be read" in page.text and "unexpected RuntimeError" in page.text
    assert "secret" not in page.text
    assert "cannot be read" in evidence(client)
    assert listed(client, "unknown") == [GHSA_A]


def test_a_scan_result_reports_the_installed_version_and_reachability_as_extra_evidence(tmp_path):
    state = advisory_state((CVE_A, [CVE_A]))
    client, token, runtime = make_client(tmp_path, state=state)
    sign_in(client, token)
    document = osv_scanner(
        scan_finding("npm", PACKAGE, "2.3.0", GHSA_A, aliases=(CVE_A,), fixed="2.3.1", called=False),
    )
    stored(runtime, document, name="scan.json")
    shown = evidence(client, CVE_A)
    assert shown.startswith("applies") and "installed 2.3.0, fixed in 2.3.1" in shown
    assert "Reachability (scanner call analysis): not called, extra evidence only" in shown
    assert "not affected" not in shown, "reachability never turns an applies into a clearance"


@pytest.mark.parametrize("called", [True, False, None])
def test_reachability_reads_called_not_called_or_unknown_beside_an_applies(tmp_path, called):
    client, token, runtime = make_client(tmp_path, state=advisory_state((CVE_A, [CVE_A])))
    sign_in(client, token)
    finding = scan_finding("npm", PACKAGE, "2.3.0", GHSA_A, aliases=(CVE_A,), fixed="2.3.1", called=called)
    stored(runtime, osv_scanner(finding), name="scan.json")
    shown = evidence(client, CVE_A)
    expected = {True: "called", False: "not called", None: "unknown"}[called]
    assert shown.startswith("applies")
    assert f"Reachability (scanner call analysis): {expected}, extra evidence only" in shown


def test_an_sbom_has_no_reachability_to_show(tmp_path):
    client, token, runtime = make_client(tmp_path, state=advisory_state((GHSA_A, [GHSA_A, CVE_A])))
    sign_in(client, token)
    stored(runtime, cyclonedx(sbom_component(PACKAGE, "2.3.0")))
    shown = evidence(client)
    assert shown.startswith("applies") and "Reachability" not in shown


# --- /alerts ------------------------------------------------------------------------------------


def test_the_alerts_filter_selects_by_evidence_and_appears_only_with_an_inventory(tmp_path):
    other = "GHSA-aaaa-bbbb-cccc"
    state = advisory_state((GHSA_A, [GHSA_A, CVE_A]), (other, [other]))
    client, token, runtime = make_client(tmp_path, state=state)
    sign_in(client, token)
    assert "name='inventory'" not in client.get("/alerts").text
    stored(runtime, cyclonedx(sbom_component(PACKAGE, "2.3.0")))
    assert "name='inventory'" in client.get("/alerts").text
    assert listed(client, "applies") == [GHSA_A]
    assert listed(client, "unknown") == [other]
    assert listed(client, "not_affected") == []
    assert sorted(listed(client, "")) == sorted([GHSA_A, other])


# --- a real pass ----------------------------------------------------------------------------------


class OsvUpstream(Upstream):
    """The enrichment stub, with an OSV record that carries the advisory's affected package."""

    def __call__(self, method, url, headers, payload):
        if urllib.parse.urlsplit(url).hostname == "api.osv.dev":
            document = {
                "id": GHSA_A,
                "aliases": [CVE_A],
                "database_specific": {"severity": "MODERATE"},
                "affected": AFFECTED_NPM,
            }
            return 200, {}, json.dumps(document).encode()
        return super().__call__(method, url, headers, payload)


def run_pass(
    tmp_path,
    *,
    drop: str = "",
    at: int = NOW,
    channel: Channel | None = None,
    window=None,
    dry_run: bool = False,
    kev: tuple[str, ...] = (),
):
    config = tmp_path / "config.yml"
    config.write_text(
        CONFIG.format(source=SOURCE_ID, url=FEED_URL, channel=CHANNEL, state=tmp_path / "state.json")
        + (f"inventory:\n  dir: {drop}\n" if drop else "")
    )
    cfg = load_config(config, {})
    channel = channel or Channel(CHANNEL, refuse=[])
    source = WindowSource(SOURCE_ID, read_feed(FEED) if window is None else window, host="feeds.example.com")
    upstream = OsvUpstream()
    upstream.kev.update(kev)
    code = pipeline.run_pass(
        cfg,
        [source],
        [channel],
        http=upstream,
        clock=lambda: float(at),
        sleep=lambda seconds: None,
        dry_run=dry_run,
    )
    assert code == 0
    return cfg, channel, json.loads((tmp_path / "state.json").read_text())


def test_an_inventory_changes_no_notification_and_a_pass_without_one_writes_nothing_extra(tmp_path):
    plain = tmp_path / "plain"
    with_inventory = tmp_path / "with"
    plain.mkdir()
    with_inventory.mkdir()
    _, channel_a, state_a = run_pass(plain)
    assert not (plain / "inventory.json").exists() and "affected" not in state_a
    assert "inventory_drop" not in state_a
    path = with_inventory / "inventory.json"
    inventory.save(
        path, inventory.parse(cyclonedx(sbom_component(PACKAGE, "2.3.0")), name="s.json", now=NOW, origin="upload")
    )
    _, channel_b, state_b = run_pass(with_inventory)
    assert channel_a.sent == channel_b.sent and channel_a.sent, "the same messages, in the same order"
    assert GHSA_A in state_b["affected"], "the affected data of the OSV record is kept for the evidence"
    assert state_b["affected"][GHSA_A]["cves"] == [CVE_A], "and the CVE ids the record aliases, which cover them"
    del state_b["affected"]
    assert state_a == state_b, "nothing else in the state differs"


def test_a_scan_that_says_not_called_neither_hides_nor_downgrades_a_kev_listed_advisory(tmp_path):
    plain, scanned, ui = tmp_path / "plain", tmp_path / "scanned", tmp_path / "ui"
    for directory in (plain, scanned, ui):
        directory.mkdir()
    _, channel_a, _ = run_pass(plain, kev=(CVE_A,))
    scan = osv_scanner(scan_finding("npm", PACKAGE, "2.3.0", GHSA_A, aliases=(CVE_A,), fixed="2.3.1", called=False))
    inventory.save(scanned / "inventory.json", inventory.parse(scan, name="scan.json", now=NOW, origin="upload"))
    _, channel_b, state = run_pass(scanned, kev=(CVE_A,))
    assert channel_a.sent == channel_b.sent, "the scan changes no message"
    kev_alerts = [message for message in channel_b.sent if CVE_A in message["ids"]]
    assert [(message["kind"], message["tag"]) for message in kev_alerts] == [("new", "critical")]
    # The advisory is still recorded as delivered and is still listed, with the reachability beside it.
    client, token, runtime = make_client(ui, state=state)
    sign_in(client, token)
    stored(runtime, scan, name="scan.json")
    assert CVE_A in listed(client, "") and CVE_A in listed(client, "applies")
    assert "Reachability (scanner call analysis): not called" in evidence(client, CVE_A)


def test_the_drop_directory_is_imported_once_and_never_undoes_an_upload(tmp_path, caplog):
    drop = tmp_path / "drop"
    drop.mkdir()
    (drop / "sbom.cdx.json").write_bytes(cyclonedx(sbom_component(PACKAGE, "2.3.0")))
    cfg, _, state = run_pass(tmp_path, drop=str(drop))
    path = inventory.inventory_path(cfg.state_path)
    first = json.loads(path.read_text())
    assert (first["origin"], first["name"], first["imported_at"]) == ("drop", "sbom.cdx.json", NOW)
    assert state["inventory_drop"]["outcome"] == "imported" and GHSA_A in state["affected"]
    # The same file again: not re-imported, so its import time does not move.
    run_pass(tmp_path, drop=str(drop), at=NOW + 60, window=[])
    assert json.loads(path.read_text())["imported_at"] == NOW
    # An upload since replaces it, and the unchanged drop file does not take it back.
    inventory.save(
        path,
        inventory.parse(cyclonedx(sbom_component("up-lib", "1.0.0")), name="u.json", now=NOW + 90, origin="upload"),
    )
    run_pass(tmp_path, drop=str(drop), at=NOW + 120, window=[])
    assert json.loads(path.read_text())["name"] == "u.json"
    # A changed file replaces the upload; a refused file is refused once, keeps the inventory and fails no pass.
    (drop / "sbom.cdx.json").write_bytes(cyclonedx(sbom_component("drop-lib", "3.0.0")))
    run_pass(tmp_path, drop=str(drop), at=NOW + 180, window=[])
    assert json.loads(path.read_text())["origin"] == "drop"
    kept = path.read_text()
    (drop / "sbom.cdx.json").write_bytes(b"{broken")
    with caplog.at_level(logging.WARNING, logger="advisory_radar"):
        for offset in (240, 300):
            run_pass(tmp_path, drop=str(drop), at=NOW + offset, window=[])
    assert path.read_text() == kept
    refusals = [record for record in caplog.records if "was refused" in record.getMessage()]
    assert len(refusals) == 1, "a refused drop file is logged once, not on every pass"
    assert json.loads((tmp_path / "state.json").read_text())["inventory_drop"]["outcome"] == "refused"


def test_a_dry_run_does_not_look_at_the_drop_directory(tmp_path):
    drop = tmp_path / "drop"
    drop.mkdir()
    (drop / "sbom.cdx.json").write_bytes(cyclonedx(sbom_component(PACKAGE, "2.3.0")))
    run_pass(tmp_path, drop=str(drop))
    stored_before = (tmp_path / "inventory.json").read_bytes()
    (drop / "sbom.cdx.json").write_bytes(cyclonedx(sbom_component("later-lib", "1.0.0")))
    _, channel, _ = run_pass(tmp_path, drop=str(drop), at=NOW + 60, window=[], dry_run=True)
    assert (tmp_path / "inventory.json").read_bytes() == stored_before and not channel.sent
    run_pass(tmp_path, drop=str(drop), at=NOW + 120, window=[])
    assert (tmp_path / "inventory.json").read_bytes() != stored_before


def test_the_drop_directory_ignores_links_directories_and_oversized_files(tmp_path):
    drop = tmp_path / "drop"
    drop.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(cyclonedx(sbom_component(PACKAGE, "2.3.0")))
    (drop / "link.json").symlink_to(outside)
    (drop / "nested.json").mkdir()
    (drop / "notes.txt").write_text("not json")
    cfg, _, state = run_pass(tmp_path, drop=str(drop))
    assert not inventory.inventory_path(cfg.state_path).exists() and "inventory_drop" not in state
    (drop / "huge.json").write_bytes(b" " * (inventory.MAX_INVENTORY_BYTES + 1))
    _, _, state = run_pass(tmp_path, drop=str(drop), at=NOW + 60, window=[])
    assert not inventory.inventory_path(cfg.state_path).exists()
    assert state["inventory_drop"]["outcome"] == "refused" and "larger than" in state["inventory_drop"]["error"]


def two_installations(tmp_path):
    """A plain installation, and one with a drop directory: ``(plain, watched, drop)`` as empty directories."""
    plain, watched = tmp_path / "plain", tmp_path / "watched"
    drop = watched / "drop"
    plain.mkdir()
    drop.mkdir(parents=True)
    return plain, watched, drop


def test_a_scan_with_unreadable_ranges_in_a_record_fails_no_pass_and_changes_no_notification(tmp_path):
    """Reproduces the reported fault: the pass raised before it polled a source, so it delivered nothing."""
    plain, watched, drop = two_installations(tmp_path)
    _, channel_a, _ = run_pass(plain)
    (drop / "scan.json").write_bytes(scan_with_ranges(1, GHSA_A))
    cfg, channel_b, state = run_pass(watched, drop=str(drop))
    assert channel_a.sent == channel_b.sent and channel_b.sent, "the same messages, in the same order"
    assert state["inventory_drop"]["outcome"] == "imported"
    stored_document = json.loads(inventory.inventory_path(cfg.state_path).read_text())
    assert [item["fixed"] for item in stored_document["findings"]] == [""]


def test_a_drop_file_that_trips_a_reader_is_refused_once_and_fails_no_pass(tmp_path, monkeypatch, caplog):
    plain, watched, drop = two_installations(tmp_path)
    _, channel_a, _ = run_pass(plain)
    path = watched / "inventory.json"
    inventory.save(
        path, inventory.parse(cyclonedx(sbom_component(PACKAGE, "2.3.0")), name="kept.json", now=NOW, origin="upload")
    )
    kept = path.read_bytes()
    (drop / "scan.json").write_bytes(osv_scanner(scan_finding("npm", PACKAGE, "2.3.0", GHSA_A)))

    def broken(document):
        raise RuntimeError("secret-<b>value</b>")

    monkeypatch.setattr(inventory, "_osv_scanner", broken)
    with caplog.at_level(logging.WARNING, logger="advisory_radar"):
        _, channel_b, state = run_pass(watched, drop=str(drop))
        run_pass(watched, drop=str(drop), at=NOW + 60, window=[])
    assert channel_a.sent == channel_b.sent and channel_b.sent, "the same messages, in the same order"
    look = state["inventory_drop"]
    assert look["outcome"] == "refused" and "unexpected RuntimeError" in look["error"] and "secret" not in str(look)
    assert path.read_bytes() == kept, "a refused file never changes the stored inventory"
    refusals = [record for record in caplog.records if "was refused" in record.getMessage()]
    assert len(refusals) == 1, "a refused drop file is logged once, not on every pass"


def test_a_stored_inventory_that_fails_unexpectedly_fails_no_pass_and_records_no_evidence(tmp_path, monkeypatch):
    plain, watched, _ = two_installations(tmp_path)
    _, channel_a, _ = run_pass(plain)
    stored_document = inventory.parse(
        cyclonedx(sbom_component(PACKAGE, "2.3.0")), name="s.json", now=NOW, origin="upload"
    )
    inventory.save(watched / "inventory.json", stored_document)

    def broken(document):
        raise RuntimeError("secret-<b>value</b>")

    monkeypatch.setattr(inventory, "Inventory", broken)
    _, channel_b, state = run_pass(watched)
    assert channel_a.sent == channel_b.sent and channel_b.sent, "the same messages, in the same order"
    assert "affected" not in state, "an inventory that cannot be read adds no evidence to the state"


def write_config(tmp_path, extra: str, *, state: str = "state.json"):
    config = tmp_path / "config.yml"
    config.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path / state}\n{extra}")
    return config


@pytest.mark.parametrize("bad", ["/etc", "PARENT", "STATE_DIRECTORY", "../escape"])
def test_the_drop_directory_must_sit_under_the_state_or_config_directory(tmp_path, bad):
    directory = {"PARENT": str(tmp_path.parent), "STATE_DIRECTORY": str(tmp_path)}.get(bad, bad)
    with pytest.raises(ConfigError, match="inventory.dir"):
        load_config(write_config(tmp_path, f"inventory:\n  dir: {directory}\n"), {})


def test_a_relative_drop_directory_is_read_from_the_state_directory(tmp_path):
    cfg = load_config(write_config(tmp_path, "inventory:\n  dir: inbox\n  max_age_days: 7\n"), {})
    assert cfg.inventory_dir == (tmp_path / "inbox").resolve() and cfg.inventory_max_age_days == 7
    assert load_config(write_config(tmp_path, ""), {}).inventory_dir is None


@pytest.mark.parametrize(
    ("block", "message"),
    [
        ("inventory: yes\n", "inventory must be a mapping"),
        ("inventory:\n  folder: inbox\n", "unknown inventory keys"),
        ("inventory:\n  max_age_days: 0\n", "max_age_days"),
        ("inventory:\n  max_age_days: 3651\n", "max_age_days"),
        ("inventory:\n  max_age_days: 1.5\n", "max_age_days"),
        ("inventory:\n  max_age_days: true\n", "max_age_days"),
        ("inventory:\n  dir: ''\n", "inventory.dir must be a directory path"),
    ],
)
def test_the_inventory_block_refuses_what_it_does_not_read(tmp_path, block, message):
    with pytest.raises(ConfigError, match=message):
        load_config(write_config(tmp_path, block), {})


def test_the_state_file_cannot_be_named_like_the_stored_inventory(tmp_path):
    with pytest.raises(ConfigError, match="inventory.json"):
        load_config(write_config(tmp_path, "", state="inventory.json"), {})


def test_the_settings_overlay_cannot_move_the_drop_directory():
    assert "inventory" not in settings.OVERLAY_KEYS, "a browser session must never choose a directory to read"
