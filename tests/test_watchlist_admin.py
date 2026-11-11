"""The watchlist page: reading the scope, changing it, and refusing a change it must not make.

The page meets three owners. The document owns its shape and its path (``tests/test_watchlist.py``). The
digest the form carries is what stops a second tab from replacing an edit it never saw, and the refusal is
the interesting half: it must keep what was typed, write nothing, and say why. ``core`` owns the match, so
the preview is checked against the decision the pass makes rather than against its own copy of the rules.
"""

from __future__ import annotations

import html
import json
import re
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from advisory_radar import core, pipeline, watchlist
from advisory_radar.runtime import Runtime
from advisory_radar.sources import RssSource
from advisory_radar.web import create_app

TOKEN = "secret"
CSRF_RE = re.compile(r'name="csrf" value="([0-9a-f]{64})"')
FINGERPRINT_RE = re.compile(r"name='fingerprint' value='([0-9a-f]*)'")
FEED_URL = "https://feeds.example.net/security.xml"
#: One item the scope is about to keep and one it must drop, so a pass proves the document it read.
FEED = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Vendor</title>
<link>https://feeds.example.net/</link>
<item><title>node.js advisory</title><link>https://nodejs.org/en/blog/a1</link>
<guid>adv-1</guid><description>Fixed in 22.1.0.</description>
<pubDate>Fri, 15 Jan 2027 07:00:00 +0000</pubDate></item>
<item><title>ghost advisory</title><link>https://other.example.net/a2</link>
<guid>adv-2</guid><description>Fixed elsewhere.</description>
<pubDate>Fri, 15 Jan 2027 07:00:00 +0000</pubDate></item>
</channel></rss>"""
#: One hour after the feed's items, so the first-run baseline does not treat them as history.
NOW = 1_800_000_000


class Notifier:
    """Records what a pass would send; the pass's own delivery loop is not what these tests are about."""

    id = "fake"

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send(self, entry, http):
        self.sent.append(entry)
        return 200


def feed_http(method, url, headers, body):
    if url == FEED_URL:
        return 200, {}, FEED
    if "cisa.gov" in url:
        return 200, {}, json.dumps({"catalogVersion": "1", "vulnerabilities": []}).encode()
    return 404, {}, b"{}"


def scope_document(**overrides) -> dict:
    """A valid scope with one product, so each test states only the part it is about."""
    return {
        "schema": watchlist.SCHEMA,
        "debian_source_packages": ["*"],
        "excluded_products": [],
        "products": [{"id": "nodejs", "aliases": ["node.js"], "domains": ["nodejs.org"]}],
        **overrides,
    }


def write_scope(path: Path, **overrides) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scope_document(**overrides)))
    return path


def write_config(tmp_path: Path, watch: Path | None = None) -> Path:
    body = (
        "sources:\n  - id: vendor\n    type: rss\n"
        f"    url: {FEED_URL}\n"
        "notifiers:\n  - id: fake\n    type: webhook\n    url: https://hooks.example.net/x\n"
        f"state_path: {tmp_path}/data/state.json\n"
    )
    if watch is not None:
        body += f"watchlist: {watch}\n"
    path = tmp_path / "config.yml"
    path.write_text(body)
    return path


def make_client(tmp_path: Path, watch: Path | None = None) -> tuple[TestClient, Runtime]:
    path = write_config(tmp_path, watch)
    env = {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN}
    runtime = Runtime.build(path, env)
    return TestClient(create_app(runtime, env)), runtime


def sign_in(client: TestClient) -> None:
    """Log in the way every page test does: the cookie, not a redirect-following jar."""
    response = client.post("/login", data={"token": TOKEN}, follow_redirects=False)
    assert response.status_code == 303
    client.cookies.set("advisory_radar_session", response.cookies.get("advisory_radar_session"))


def scope_form(client: TestClient) -> tuple[str, str, str]:
    """The form token, the document digest the page carries, and the page itself."""
    page = client.get("/watchlist")
    assert page.status_code == 200
    csrf = CSRF_RE.search(page.text)
    assert csrf, "the scope form carries a form token"
    fingerprint = FINGERPRINT_RE.search(page.text)
    assert fingerprint, "the scope form carries the digest of the document it was rendered from"
    return csrf.group(1), fingerprint.group(1), page.text


def submit(client: TestClient, csrf: str, fingerprint: str, **fields) -> object:
    """Post the scope form as the page renders it: the envelope, both lists and the pending new row."""
    data = {
        "csrf": csrf,
        "fingerprint": fingerprint,
        "debian_packages": "*",
        "excluded_products": "",
        "new:id": "",
        "new:aliases": "",
        "new:domains": "",
    }
    data.update(fields)
    # ``None`` drops a default: a field the page renders read-only does not submit its visible counterpart at all.
    data = {key: value for key, value in data.items() if value is not None}
    return client.post("/watchlist", data=data, follow_redirects=False)


def test_the_page_shows_the_scope_it_would_save(tmp_path):
    watch = write_scope(tmp_path / "scope.json", debian_source_packages=["curl"], excluded_products=["legacy"])
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    _, fingerprint, text = scope_form(client)
    assert "<a href='/watchlist' aria-current='page'>Watchlist</a>" in text
    assert "name='product:nodejs:aliases' value='node.js'" in text
    assert "name='product:nodejs:domains' value='nodejs.org'" in text
    assert "<textarea name='debian_packages'" in text and "curl" in text
    assert "legacy" in text
    assert f"<code>{watch}</code>" in text, "the page names the document it edits"
    assert fingerprint == watchlist.digest(json.loads(watch.read_text()))
    # The configuration page points at it, because the scope is not one of the overlay's ten keys.
    assert "href='/watchlist'" in client.get("/config").text


def test_a_saved_scope_creates_the_document_beside_the_state(tmp_path):
    """With no ``watchlist:`` in the YAML the writable volume is the owner, not the packaged default."""
    client, _ = make_client(tmp_path)
    sign_in(client)
    csrf, fingerprint, text = scope_form(client)
    assert fingerprint == "", "a page with no document carries no digest"
    assert "No scope is saved" in text
    response = submit(
        client,
        csrf,
        fingerprint,
        **{"new:id": "nodejs", "new:aliases": "node.js, nodejs", "new:domains": "nodejs.org", "debian_packages": "*"},
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/watchlist?saved=")
    target = tmp_path / "data" / "watchlist.json"
    assert json.loads(target.read_text()) == scope_document(
        products=[{"id": "nodejs", "aliases": ["node.js", "nodejs"], "domains": ["nodejs.org"], "metadata_only": False}]
    )


def test_a_product_can_be_added_edited_and_removed(tmp_path):
    watch = write_scope(tmp_path / "scope.json")
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "product:nodejs:aliases": "node.js, nodejs",
            "product:nodejs:domains": "nodejs.org",
            "debian_packages": "*",
            "excluded_products": "",
            "new:id": "php",
            "new:aliases": "php",
            "new:domains": "php.net",
        },
    )
    assert response.status_code == 303
    saved = json.loads(watch.read_text())
    assert [product["id"] for product in saved["products"]] == ["nodejs", "php"]
    assert saved["products"][0]["aliases"] == ["node.js", "nodejs"]
    assert saved["products"][1]["domains"] == ["php.net"]

    csrf, fingerprint, _ = scope_form(client)
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "product:nodejs:aliases": "node.js",
            "product:nodejs:domains": "nodejs.org",
            "product:php:aliases": "php",
            "product:php:domains": "php.net",
            "remove:php": "1",
            "debian_packages": "curl",
            "excluded_products": "legacy",
        },
    )
    assert response.status_code == 303
    saved = json.loads(watch.read_text())
    assert [product["id"] for product in saved["products"]] == ["nodejs"]
    assert saved["products"][0]["aliases"] == ["node.js"]
    assert saved["products"][0]["domains"] == ["nodejs.org"]
    assert saved["debian_source_packages"] == ["curl"]
    assert saved["excluded_products"] == ["legacy"]


def test_a_refused_save_keeps_the_edit_and_writes_nothing(tmp_path):
    watch = write_scope(tmp_path / "scope.json")
    before = watch.read_text()
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "product:nodejs:aliases": "node.js",
            "product:nodejs:domains": "not a domain",
            "debian_packages": "*",
            "new:id": "php",
            "new:aliases": "php",
        },
    )
    assert response.status_code == 200
    assert "Not saved:" in response.text and "domain is invalid" in response.text
    assert "value='not a domain'" in response.text, "a refusal re-renders the rows as they were submitted"
    assert "value='php'" in response.text
    assert watch.read_text() == before


def test_a_stale_page_cannot_replace_a_newer_edit(tmp_path):
    watch = write_scope(tmp_path / "scope.json")
    before = watch.read_text()
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, _, _ = scope_form(client)
    response = submit(
        client,
        csrf,
        "0" * 64,
        **{
            "product:nodejs:aliases": "changed",
            "product:nodejs:domains": "nodejs.org",
            "debian_packages": "*",
        },
    )
    assert response.status_code == 409
    assert "changed since this page was loaded" in response.text
    assert watch.read_text() == before


def test_adding_a_product_that_already_has_a_row_is_named_as_such(tmp_path):
    """Refused before the document is built: "invalid identity" would hide the actual mistake."""
    watch = write_scope(tmp_path / "scope.json")
    before = watch.read_text()
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "product:nodejs:aliases": "node.js",
            "product:nodejs:domains": "nodejs.org",
            "debian_packages": "*",
            "new:id": "nodejs",
            "new:aliases": "node.js",
        },
    )
    assert response.status_code == 200
    assert "already exists" in response.text
    assert watch.read_text() == before


def test_the_page_needs_a_session_and_a_form_token(tmp_path):
    client, _ = make_client(tmp_path)
    assert client.get("/watchlist", follow_redirects=False).status_code == 303
    sign_in(client)
    refused = client.post("/watchlist", data={"csrf": "0" * 64}, follow_redirects=False)
    assert refused.status_code == 403, "a state-changing form needs the token tied to the session"


def test_a_configured_document_that_does_not_exist_is_named_and_created_on_save(tmp_path):
    """A configured path is never judged by a fallback: a typo would otherwise mean "no scope"."""
    watch = tmp_path / "missing" / "scope.json"
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, text = scope_form(client)
    assert not watch.exists()
    assert "does not exist yet" in text and "every pass fails" in text
    assert fingerprint == ""
    response = submit(client, csrf, fingerprint, **{"new:id": "php", "new:aliases": "php", "debian_packages": "*"})
    assert response.status_code == 303
    assert [product["id"] for product in json.loads(watch.read_text())["products"]] == ["php"]


def test_a_document_that_does_not_read_is_reported_and_not_edited(tmp_path):
    watch = tmp_path / "scope.json"
    watch.write_text(json.dumps({"schema": "something-else"}))
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    page = client.get("/watchlist")
    assert page.status_code == 200
    assert "cannot be read" in page.text and "schema is invalid" in page.text
    assert "name='fingerprint'" not in page.text, "there is nothing safe to edit against"
    assert "action='/watchlist'" not in page.text


def test_a_target_that_cannot_be_written_is_reported_without_losing_the_edit(tmp_path, monkeypatch):
    watch = tmp_path / "missing" / "scope.json"
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)

    def refuse(path: Path, document: dict) -> None:
        raise OSError("read-only file system")

    monkeypatch.setattr(watchlist, "save_json", refuse)
    response = submit(client, csrf, fingerprint, **{"new:id": "php", "new:aliases": "php", "debian_packages": "*"})
    assert response.status_code == 200
    assert "cannot be written" in response.text
    assert "value='php'" in response.text
    assert "watchlist:" in response.text, "the refusal says what to change"
    assert not watch.exists()


def test_the_preview_answers_with_the_rule_the_pass_applies(tmp_path):
    watch = write_scope(tmp_path / "scope.json")
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    kept = client.get(
        "/watchlist", params={"preview": "1", "title": "node.js advisory", "link": "https://nodejs.org/en/blog/a"}
    )
    assert "In scope" in kept.text and "matched <code>nodejs</code>" in kept.text
    dropped = client.get(
        "/watchlist", params={"preview": "1", "title": "ghost advisory", "link": "https://other.example.net/a"}
    )
    assert "Out of scope" in dropped.text and "matches none of the configured products" in dropped.text
    exclusions = write_scope(tmp_path / "excluding.json", excluded_products=["nodejs"])
    client, _ = make_client(tmp_path, exclusions)
    sign_in(client)
    excluded = client.get(
        "/watchlist", params={"preview": "1", "title": "node.js advisory", "link": "https://nodejs.org/a"}
    )
    assert "Out of scope" in excluded.text and "matches an excluded product" in excluded.text
    assert "Give the advisory a title or a link" in client.get("/watchlist", params={"preview": "1"}).text


def test_the_preview_says_what_an_empty_scope_means(tmp_path):
    watch = write_scope(tmp_path / "scope.json", products=[])
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    page = client.get("/watchlist", params={"preview": "1", "title": "anything at all"})
    assert "In scope" in page.text and "no products are configured" in page.text


def test_the_scope_a_browser_saved_is_the_scope_the_next_pass_uses(tmp_path):
    """The one end-to-end claim: no reload, no YAML edit, and the document is what filtered the pass."""
    client, runtime = make_client(tmp_path)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    assert (
        submit(
            client,
            csrf,
            fingerprint,
            **{
                "new:id": "nodejs",
                "new:aliases": "node.js, nodejs",
                "new:domains": "nodejs.org",
                "debian_packages": "*",
            },
        ).status_code
        == 303
    )
    notifier = Notifier()
    code = pipeline.run_pass(
        runtime.cfg,
        [RssSource("vendor", FEED_URL)],
        [notifier],
        http=feed_http,
        clock=lambda: float(NOW),
        sleep=lambda seconds: None,
    )
    assert code == 0
    # One message: the item the scope matched. The other feed entry was dropped before classification, which is
    # why the pass says nothing about it.
    assert len(notifier.sent) == 1
    assert "node.js advisory" in notifier.sent[0]["title"]
    assert notifier.sent[0]["products"] == ["nodejs"], "the message records the scope that judged it"


def test_an_id_being_removed_in_the_same_save_can_be_added_again(tmp_path):
    """Removing a row frees its id: a rename is a remove and an add, and both happen in one save."""
    watch = write_scope(tmp_path / "scope.json")
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "product:nodejs:aliases": "node.js",
            "product:nodejs:domains": "nodejs.org",
            "remove:nodejs": "1",
            "debian_packages": "*",
            "new:id": "nodejs",
            "new:aliases": "node js, nodejs",
            "new:domains": "nodejs.org",
        },
    )
    assert response.status_code == 303
    saved = json.loads(watch.read_text())
    assert len(saved["products"]) == 1
    assert saved["products"][0]["aliases"] == ["node js", "nodejs"]


LOSSY_ALIASES = (
    "Example, Inc.",  # the field's own separator
    "Example\nServer",  # a browser drops it from a single-line input
    "Example\rServer",
    "Example\x00Server",  # a control character does not survive a form
    "Example\ud800Server",  # not renderable at all: esc() would replace it
)


@pytest.mark.parametrize("alias", LOSSY_ALIASES)
def test_an_alias_its_field_cannot_hold_is_kept_exactly(tmp_path, alias):
    """The row is read-only and the rendered hidden value is what round-trips, not a field that would alter it."""
    watch = write_scope(
        tmp_path / "scope.json",
        products=[{"id": "acme", "aliases": [alias], "domains": []}],
    )
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, text = scope_form(client)
    assert "readonly" in text and "kept exactly" in text
    assert "name='product:acme:aliases'" not in text, "the lossy field is not submitted at all"
    rendered = re.search(r"name='product:acme:aliases_json' value='([^']*)'", text)
    assert rendered, "the exact list is carried in the form"
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "product:acme:aliases_json": html.unescape(rendered.group(1)),
            "product:acme:domains": "",
            "debian_packages": "*",
        },
    )
    assert response.status_code == 303
    assert json.loads(watch.read_text())["products"][0]["aliases"] == [alias]


@pytest.mark.parametrize("entry", ["Example\nServer", "Example\x00Server"])
def test_an_exclusion_its_field_cannot_hold_is_kept_exactly(tmp_path, entry):
    """An exclusion is a matching rule: splitting one into two broader names widens what is dropped."""
    watch = write_scope(tmp_path / "scope.json", excluded_products=[entry])
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, text = scope_form(client)
    assert "readonly" in text and "kept exactly" in text
    assert "name='excluded_products'" not in text, "the lossy field is not submitted at all"
    rendered = re.search(r"name='excluded_products_json' value='([^']*)'", text)
    assert rendered, "the exact list is carried in the form"
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "excluded_products": None,
            "excluded_products_json": html.unescape(rendered.group(1)),
            "product:nodejs:aliases": "node.js",
            "product:nodejs:domains": "nodejs.org",
            "debian_packages": "*",
        },
    )
    assert response.status_code == 303
    assert json.loads(watch.read_text())["excluded_products"] == [entry]


def test_a_new_row_without_an_id_is_refused_and_kept(tmp_path):
    """Saving it away as a success would leave an installation that thinks it has a scope with none."""
    watch = write_scope(tmp_path / "scope.json")
    before = watch.read_text()
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "product:nodejs:aliases": "node.js",
            "product:nodejs:domains": "nodejs.org",
            "debian_packages": "*",
            "new:aliases": "php",
            "new:domains": "php.net",
        },
    )
    assert response.status_code == 200
    assert "needs an id" in response.text
    assert "value='php'" in response.text and "value='php.net'" in response.text
    assert watch.read_text() == before


def test_a_broken_link_to_the_document_is_reported_and_not_replaced(tmp_path):
    watch = tmp_path / "scope.json"
    watch.symlink_to(tmp_path / "gone.json")
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    page = client.get("/watchlist")
    assert page.status_code == 200
    assert "cannot be read" in page.text
    assert "name='fingerprint'" not in page.text, "there is nothing to edit against"
    assert watch.is_symlink(), "the page never replaces the operator's link"


def test_a_document_value_is_escaped_everywhere_it_is_rendered(tmp_path):
    nasty = '"><script>alert(1)</script>'
    watch = write_scope(
        tmp_path / "scope.json",
        products=[{"id": "acme", "aliases": [nasty], "domains": []}],
        excluded_products=[nasty],
    )
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    page = client.get("/watchlist")
    assert "<script>" not in page.text
    assert "&lt;script&gt;" in page.text
    preview = client.get("/watchlist", params={"preview": "1", "title": "<img src=x onerror=alert(1)>"})
    assert "<img" not in preview.text


def test_a_metadata_only_flag_survives_an_unchanged_save(tmp_path):
    """The flag has no consumer and no control here; it is not part of the form at all, so a save keeps it."""
    watch = write_scope(
        tmp_path / "scope.json",
        products=[{"id": "nodejs", "aliases": ["node.js"], "domains": [], "metadata_only": True}],
    )
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, text = scope_form(client)
    assert "metadata_only:" not in text, "the page offers no control for it, and submits no field for it"
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "product:nodejs:aliases": "node.js",
            "product:nodejs:domains": "",
            "debian_packages": "*",
        },
    )
    assert response.status_code == 303
    assert json.loads(watch.read_text())["products"][0]["metadata_only"] is True


def test_a_path_that_cannot_be_inspected_is_reported_by_the_page(tmp_path, monkeypatch):
    """The page must not show the permissive default while the pass fails on the same unreadable path."""
    client, _ = make_client(tmp_path)
    sign_in(client)

    def denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(watchlist, "os", types.SimpleNamespace(lstat=denied))
    page = client.get("/watchlist")
    assert page.status_code == 200
    assert "cannot be inspected" in page.text
    assert "name='fingerprint'" not in page.text, "there is nothing safe to edit against"


def test_a_missing_configured_document_has_no_verdict_to_show(tmp_path):
    """The page must not answer for the built-in default while the pass reads the configured, missing path."""
    watch = tmp_path / "missing" / "scope.json"
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    page = client.get("/watchlist", params={"preview": "1", "title": "anything at all"})
    assert "In scope" not in page.text and "Out of scope" not in page.text
    assert "nothing to check an advisory against" in page.text
    assert "name='preview'" not in page.text, "the check form is absent, not just its answer"


def test_a_symlinked_document_is_saved_through_its_link(tmp_path):
    """A save must replace the file the link names, not the link: otherwise the operator's file is orphaned."""
    real = write_scope(tmp_path / "scope.json")
    link = tmp_path / "watchlist.json"
    link.symlink_to(real)
    client, _ = make_client(tmp_path, link)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "product:nodejs:aliases": "node.js, nodejs",
            "product:nodejs:domains": "nodejs.org",
            "debian_packages": "*",
        },
    )
    assert response.status_code == 303
    assert link.is_symlink(), "the operator's link is untouched"
    assert json.loads(real.read_text())["products"][0]["aliases"] == ["node.js", "nodejs"]


def test_the_configuration_page_survives_an_uninspectable_scope(tmp_path, monkeypatch):
    """The scope path is one line of /config: failing to name it must not hide every other setting."""
    client, _ = make_client(tmp_path)
    sign_in(client)

    def denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(watchlist, "os", types.SimpleNamespace(lstat=denied))
    page = client.get("/config")
    assert page.status_code == 200
    assert "scope <a href='/watchlist'>unavailable</a>" in page.text
    assert "cannot be inspected" in page.text


def test_a_save_to_an_uninspectable_path_is_refused(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path)
    sign_in(client)
    csrf = CSRF_RE.search(client.get("/").text).group(1)

    def denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(watchlist, "os", types.SimpleNamespace(lstat=denied))
    response = client.post(
        "/watchlist",
        data={
            "csrf": csrf,
            "fingerprint": "",
            "new:id": "php",
            "new:aliases": "php",
            "new:domains": "",
            "debian_packages": "*",
            "excluded_products": "",
        },
    )
    assert response.status_code == 200
    assert "cannot be inspected" in response.text
    assert "value='php'" in response.text, "the row is re-rendered, nothing is written"


BROKEN_EXACT = (
    {"excluded_products": None, "excluded_products_json": "null"},  # readable JSON, not a list
    {"excluded_products": None, "excluded_products_json": "[7]"},  # a list, but not of entries
    {"debian_packages": None, "debian_packages_json": '[["curl"]]'},  # nested
    {"product:nodejs:aliases": None, "product:nodejs:aliases_json": "[7]"},  # a row's exact list
    {"excluded_products": "legacy", "excluded_products_json": '["legacy"]'},  # two representations at once
    {"excluded_products": None, "excluded_products_json": ""},  # the page never renders an empty exact field
    {"excluded_products": None, "excluded_products_json": "[" * 10_000 + "]" * 10_000},  # decoder recursion
)


def _valid_payload(csrf: str, fingerprint: str) -> dict:
    """The form as the page renders it, so a test can break exactly one part of it."""
    return {
        "csrf": csrf,
        "fingerprint": fingerprint,
        "debian_packages": "*",
        "excluded_products": "",
        "product:nodejs:aliases": "node.js",
        "product:nodejs:domains": "nodejs.org",
        "new:id": "",
        "new:aliases": "",
        "new:domains": "",
    }


@pytest.mark.parametrize("fields", BROKEN_EXACT)
def test_a_malformed_exact_field_is_refused(tmp_path, fields):
    """Falling back to the visible field would let a malformed payload silently clear a list."""
    watch = write_scope(tmp_path / "scope.json")
    before = watch.read_text()
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    data = _valid_payload(csrf, fingerprint)
    data.update(fields)
    response = client.post("/watchlist", data={k: v for k, v in data.items() if v is not None})
    assert response.status_code == 400, "a payload this page never emits is refused, not guessed at"
    assert "reload" in response.text
    assert watch.read_text() == before, "nothing is written"


@pytest.mark.parametrize(
    "fields",
    [
        {"excluded_products": ["legacy", "other"]},  # one field, two values
        {"excluded_products_json": ['["legacy"]', "null"]},
        {"new:id": ["php", "perl"]},
    ],
)
def test_a_repeated_field_is_refused(tmp_path, fields):
    """The first value would be used and the second ignored: a form says one thing per field."""
    watch = write_scope(tmp_path / "scope.json")
    before = watch.read_text()
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    data = _valid_payload(csrf, fingerprint)
    data.update(fields)
    response = client.post("/watchlist", data={k: v for k, v in data.items() if v is not None})
    assert response.status_code == 400
    assert "was submitted" in response.text
    assert watch.read_text() == before


@pytest.mark.parametrize(
    "fields",
    [
        {"product:nodejs:aliases": None},  # a row with no aliases: it would vanish and leave no scope
        {"product:nodejs:domains": None},
        {"product:nodejs:bogus": "x"},  # not a field of this form
        {"unexpected": "x"},
        {"product:Bad_Id:aliases": "x", "product:Bad_Id:domains": ""},
        {"remove:nodejs": "false"},  # the page sends 1 or nothing
        {"metadata_only:nodejs": "true"},  # not a control this page offers
    ],
)
def test_a_shape_the_page_never_sends_is_refused(tmp_path, fields):
    """Silently dropping a field is how a malformed row becomes an unrestricted scope."""
    watch = write_scope(tmp_path / "scope.json")
    before = watch.read_text()
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    data = _valid_payload(csrf, fingerprint)
    data.update(fields)
    response = client.post("/watchlist", data={k: v for k, v in data.items() if v is not None})
    assert response.status_code == 400
    assert watch.read_text() == before


def test_omitting_a_row_is_refused(tmp_path):
    """A row the page rendered is a row the submission must speak about: omitting it would delete a product."""
    watch = write_scope(
        tmp_path / "scope.json",
        products=[
            {"id": "nodejs", "aliases": ["node.js"], "domains": []},
            {"id": "php", "aliases": ["php"], "domains": []},
        ],
    )
    before = watch.read_text()
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "product:nodejs:aliases": "node.js",
            "product:nodejs:domains": "",
            "debian_packages": "*",
        },
    )
    assert response.status_code == 400
    assert "missing php" in response.text
    assert watch.read_text() == before


def test_an_invented_row_is_refused(tmp_path):
    """Additions belong in the new row: a row for an id the page never rendered is not an edit."""
    watch = write_scope(tmp_path / "scope.json")
    before = watch.read_text()
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "product:nodejs:aliases": "node.js",
            "product:nodejs:domains": "nodejs.org",
            "product:php:aliases": "php",
            "product:php:domains": "php.net",
            "debian_packages": "*",
        },
    )
    assert response.status_code == 400
    assert "unknown php" in response.text
    assert watch.read_text() == before


def test_a_read_only_alias_list_cannot_be_replaced_through_its_hidden_field(tmp_path):
    """The page shows that row read-only, so a hidden field that disagrees with the document changes nothing."""
    watch = write_scope(
        tmp_path / "scope.json",
        products=[{"id": "acme", "aliases": ["Example, Inc."], "domains": []}],
    )
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "product:acme:aliases": None,
            "product:acme:aliases_json": json.dumps(["something else"]),
            "product:acme:domains": "",
            "debian_packages": "*",
        },
    )
    assert response.status_code == 303
    assert json.loads(watch.read_text())["products"][0]["aliases"] == ["Example, Inc."]


def test_a_read_only_exclusion_list_cannot_be_replaced_through_its_hidden_field(tmp_path):
    """Same rule for a whole field: the document keeps a list its control cannot carry."""
    watch = write_scope(tmp_path / "scope.json", excluded_products=["Example\nServer"])
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    csrf, fingerprint, _ = scope_form(client)
    response = submit(
        client,
        csrf,
        fingerprint,
        **{
            "excluded_products": None,
            "excluded_products_json": json.dumps([]),
            "product:nodejs:aliases": "node.js",
            "product:nodejs:domains": "nodejs.org",
            "debian_packages": "*",
        },
    )
    assert response.status_code == 303
    assert json.loads(watch.read_text())["excluded_products"] == ["Example\nServer"]


def test_a_document_nested_too_deeply_is_reported_and_not_saved_over(tmp_path):
    """A hand edit can leave a document the decoder gives up on: the page and a save must say so, not crash."""
    watch = tmp_path / "scope.json"
    watch.write_text("[" * 10_000 + "]" * 10_000)
    before = watch.read_text()
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    page = client.get("/watchlist")
    assert page.status_code == 200
    assert "cannot be read" in page.text and "name='fingerprint'" not in page.text
    csrf = CSRF_RE.search(client.get("/").text).group(1)
    response = client.post(
        "/watchlist",
        data={
            "csrf": csrf,
            "fingerprint": "",
            "debian_packages": "*",
            "excluded_products": "",
            "new:id": "",
            "new:aliases": "",
            "new:domains": "",
        },
    )
    assert response.status_code == 200
    assert "cannot be read" in response.text
    assert watch.read_text() == before


def test_a_scope_path_that_is_a_directory_root_is_refused_not_a_crash(tmp_path):
    """`watchlist: /` has no name for the sidecar lock, so a save must refuse before it locks."""
    client, _ = make_client(tmp_path, Path("/"))
    sign_in(client)
    page = client.get("/watchlist")
    assert page.status_code == 200
    assert "cannot be read" in page.text
    csrf = CSRF_RE.search(client.get("/").text).group(1)
    response = client.post(
        "/watchlist",
        data={
            "csrf": csrf,
            "fingerprint": "",
            "debian_packages": "*",
            "excluded_products": "",
            "new:id": "",
            "new:aliases": "",
            "new:domains": "",
        },
    )
    assert response.status_code == 200, "the refusal is a page, not a 500"
    assert "does not name a document" in response.text


def test_the_preview_judges_the_text_it_was_given(tmp_path):
    """The pass reads an advisory's title as published; trimming it would answer for a different advisory."""
    watch = write_scope(tmp_path / "scope.json", products=[], debian_source_packages=["openssl"])
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    spaced = client.get(
        "/watchlist",
        params={"preview": "1", "title": " DSA-6104-1 openssl - security update", "link": "https://lists.debian.org/x"},
    )
    assert "Out of scope" in spaced.text, "the anchored DSA title no longer matches once the space is removed"
    assert "debian_source_packages" in spaced.text
    clean = client.get(
        "/watchlist",
        params={"preview": "1", "title": "DSA-6104-1 openssl - security update", "link": "https://lists.debian.org/x"},
    )
    assert "In scope" in clean.text


def test_a_save_creates_the_file_the_pass_will_read(tmp_path):
    """``missing/../scope.json`` resolves to a real file: a save must leave the pass able to read that file."""
    configured = tmp_path / "missing" / ".." / "scope.json"
    client, runtime = make_client(tmp_path, configured)
    sign_in(client)
    csrf, fingerprint, text = scope_form(client)
    assert "not created yet" in text
    response = submit(client, csrf, fingerprint, **{"new:id": "php", "new:aliases": "php", "debian_packages": "*"})
    assert response.status_code == 303
    assert (tmp_path / "scope.json").exists()
    policy = watchlist.load_policy(watchlist.active_path(runtime.cfg.watchlist_path, runtime.cfg.state_path))
    assert [product.id for product in policy.products] == ["php"], "the pass reads what the save created"
    assert "not created yet" not in client.get("/watchlist").text


def test_the_preview_matches_what_a_webhook_entry_is_judged_on(tmp_path):
    """A webhook entry keeps its text, so the preview and that ingestion path must reach the same verdict."""
    from advisory_radar.sources import webhook_item_from_payload

    watch = write_scope(tmp_path / "scope.json", products=[], debian_source_packages=["openssl"])
    client, _ = make_client(tmp_path, watch)
    sign_in(client)
    title = " DSA-6104-1 openssl - security update"
    entry = webhook_item_from_payload({"title": title, "link": "https://lists.debian.org/x", "guid": "g"})
    assert entry is not None
    item = core.Item(
        entry["guid"], entry["title"], entry["link"], entry["summary"], None, (), source_title=entry["source_title"]
    )
    policy = watchlist.load_policy(watch)
    page = client.get("/watchlist", params={"preview": "1", "title": title, "link": item.link})
    reason = core.filter_reason(item, policy)
    assert ("Out of scope" in page.text) is bool(reason), "the page and the entry agree on the verdict"
    assert "judged exactly as typed" in page.text, "the page says what its input stands for"
