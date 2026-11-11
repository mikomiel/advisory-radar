"""The watchlist page: reading the scope, changing it, and refusing a change it must not make.

The page meets three owners. The document owns its shape and its path (``tests/test_watchlist.py``). The
digest the form carries is what stops a second tab from replacing an edit it never saw, and the refusal is
the interesting half: it must keep what was typed, write nothing, and say why. ``core`` owns the match, so
the preview is checked against the decision the pass makes rather than against its own copy of the rules.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

from advisory_radar import pipeline, watchlist
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
    data = {"csrf": csrf, "fingerprint": fingerprint}
    data.update(fields)
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
            "metadata_only:nodejs": "0",
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
            "metadata_only:nodejs": "0",
            "product:php:aliases": "php",
            "product:php:domains": "php.net",
            "metadata_only:php": "0",
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
            "metadata_only:nodejs": "0",
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
            "metadata_only:nodejs": "0",
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
            "metadata_only:nodejs": "0",
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
            "metadata_only:nodejs": "0",
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
