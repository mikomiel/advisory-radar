"""Conditional GET for feeds: an unchanged publisher must cost one round trip, not the whole feed.

A feed polled every 15 minutes is read 96 times a day; without validators every one of those transfers the
whole document from a publisher who owes us nothing. The risky half is the other side:

* a 304 to a conditional request must be an empty window, never an error, and must not forget the
  validators -- while a 304 to an unconditional request is a source error, not a healthy empty feed;
* the validators belong to the URL that issued them, because an ETag is unique per resource -- repointing a
  source id at another feed must not send the old one and earn a legitimate 304 for a feed never read;
* they are stored by ``commit``, after the pipeline captured the candidates, so a window whose advisories were
  never queued is read in full again (the same rule the changedetection cursor follows).
"""

from __future__ import annotations

import hashlib
import json

import pytest

from advisory_radar import feeds, pipeline
from advisory_radar.sources import RssSource
from advisory_radar.watchlist import Policy, Product

FEED = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Vendor</title><link>https://vendor.example.com/</link>
<item><title>DSA-6558-1 curl - security update</title><link>https://lists.debian.org/dsa-6558</link>
<guid>https://lists.debian.org/dsa-6558</guid><description>Fixes CVE-2026-1111.</description>
<pubDate>Wed, 21 Oct 2026 10:00:00 +0000</pubDate></item>
</channel></rss>"""

ETAG = '"v1"'
MODIFIED = "Wed, 21 Oct 2026 10:00:00 GMT"
URL = "https://vendor.example.com/feed.xml"

JSON_FEED = b"""{
  "version": "https://jsonfeed.org/version/1.1",
  "title": "Vendor",
  "home_page_url": "https://vendor.example.com/",
  "items": [
    {"id": "adv-1", "url": "https://vendor.example.com/adv/1",
     "title": "DSA-6558-1 curl - security update",
     "content_text": "Fixes CVE-2026-1111.",
     "date_published": "2026-10-21T10:00:00Z"}
  ]
}"""

PAGE_URL = "https://vendor.example.com/security"
PAGE = b"""<!DOCTYPE html><html><head>
<link rel="alternate" type="application/rss+xml" href="/feed.xml">
</head><body>vendor security</body></html>"""


def http_with(calls: list[dict[str, str]], statuses: list[int]):
    def http(method, request_url, headers, body):
        calls.append(dict(headers))
        if statuses[min(len(calls), len(statuses)) - 1] == 304:
            return 304, {}, b""
        return 200, {"ETag": ETAG, "Last-Modified": MODIFIED}, FEED

    return http


def test_an_unchanged_feed_answers_304_and_keeps_its_validators():
    calls: list[dict[str, str]] = []
    source = RssSource("nodejs", URL)
    state: dict = {}
    first = source.fetch(http_with(calls, [200, 304]), state)
    assert [item.guid for item in first.items] == ["https://lists.debian.org/dsa-6558"]
    source.commit(state)
    assert state["feeds"]["nodejs"] == {
        "url_digest": hashlib.sha256(URL.encode()).hexdigest(),
        "etag": ETAG,
        "last_modified": MODIFIED,
    }
    second = source.fetch(http_with(calls, [200, 304]), state)
    assert second.items == ()  # not an error: the publisher says nothing changed
    assert calls[1]["If-None-Match"] == ETAG
    assert calls[1]["If-Modified-Since"] == MODIFIED
    # a 304 carries no validators, and the stored ones must survive it: forgetting them refetches the body
    source.commit(state)
    assert state["feeds"]["nodejs"]["etag"] == ETAG


def test_fetch_alone_does_not_advance_the_validators():
    """A window whose candidates never reached pending or carry must be read in full again."""
    calls: list[dict[str, str]] = []
    source = RssSource("nodejs", URL)
    state: dict = {}
    source.fetch(http_with(calls, [200]), state)
    assert "feeds" not in state  # fetched, not committed
    source.fetch(http_with(calls, [200]), state)
    assert "If-None-Match" not in calls[1]  # still unconditional: nothing was captured


def test_a_changed_url_does_not_inherit_the_previous_urls_validators():
    """An ETag belongs to one resource: a repointed source id must not send it to a different feed."""
    calls: list[tuple[str, dict[str, str]]] = []

    def http(method, url, headers, body):
        calls.append((url, dict(headers)))
        return 200, {"ETag": ETAG}, FEED  # both servers happen to use the same ETag value

    state: dict = {}
    first = RssSource("vendor", "https://a.example.com/feed.xml")
    first.fetch(http, state)
    first.commit(state)
    second = RssSource("vendor", "https://b.example.com/feed.xml")
    second.fetch(http, state)
    second.commit(state)
    assert calls[1][0] == "https://b.example.com/feed.xml"
    assert "If-None-Match" not in calls[1][1]  # not this resource's validator, so it must not be sent
    assert state["feeds"]["vendor"]["url_digest"] == hashlib.sha256(b"https://b.example.com/feed.xml").hexdigest()


def test_a_200_without_validators_forgets_the_stored_ones():
    statuses = [(200, {"ETag": ETAG}), (200, {})]
    calls: list[dict[str, str]] = []

    def http(method, url, headers, body):
        index = min(len(calls), len(statuses) - 1)
        calls.append(dict(headers))
        status, extra = statuses[index]
        return status, extra, FEED

    source = RssSource("vendor", URL)
    state: dict = {}
    source.fetch(http, state)
    source.commit(state)
    assert state["feeds"]["vendor"]["etag"] == ETAG
    source.fetch(http, state)
    source.commit(state)
    # a 200 that offers no validator replaces the stored ones with nothing: keeping them would send a stale
    # If-None-Match for a feed that stopped offering one
    assert "vendor" not in state.get("feeds", {})


def test_a_feed_with_no_validators_is_always_fetched_in_full():
    calls: list[dict[str, str]] = []

    def http(method, url, headers, body):
        calls.append(dict(headers))
        return 200, {}, FEED

    source = RssSource("vendor", URL)
    state: dict = {}
    source.fetch(http, state)
    source.commit(state)
    source.fetch(http, state)
    source.commit(state)
    assert "If-None-Match" not in calls[0]
    assert "If-None-Match" not in calls[1]
    assert "feeds" not in state  # nothing to remember


def test_a_stored_validator_that_is_not_a_string_is_ignored():
    calls: list[dict[str, str]] = []
    source = RssSource("nodejs", URL)
    # a hand-edited state: the URL matches, so the type checks are what reject each validator
    stored = {"url_digest": hashlib.sha256(URL.encode()).hexdigest(), "etag": 7, "last_modified": None}
    state = {"feeds": {"nodejs": stored}}
    source.fetch(http_with(calls, [200]), state)
    assert "If-None-Match" not in calls[0]
    assert "If-Modified-Since" not in calls[0]


def test_fetch_rss_returns_the_validators_and_refuses_an_error_status():
    def not_modified(method, url, headers, body):
        assert headers["Accept"].startswith("application/rss+xml")
        assert headers["If-None-Match"] == '"abc"'  # a 304 only answers a conditional request
        return 304, {}, b""

    export, stored = feeds.fetch_rss(not_modified, URL, {"If-None-Match": '"abc"'})
    assert export.items == () and not export.truncated
    assert stored is None  # 304: keep the validators already stored, do not forget them

    def unsolicited(method, url, headers, body):
        return 304, {}, b""

    with pytest.raises(feeds.RssError):
        feeds.fetch_rss(unsolicited, URL)

    def unavailable(method, url, headers, body):
        return 503, {}, b""

    with pytest.raises(feeds.RssError):
        feeds.fetch_rss(unavailable, URL)


def test_the_stored_validators_never_contain_the_feed_url():
    # a subscription URL can carry a credential: ?token=${FEED_TOKEN} is expanded before the source is built
    secret_url = "https://feeds.example.com/rss?token=super-secret-token"
    source = RssSource("paid", secret_url)
    state: dict = {}
    source.fetch(http_with([], [200]), state)
    source.commit(state)
    persisted = json.dumps(state)
    assert "super-secret-token" not in persisted
    assert secret_url not in persisted
    assert state["feeds"]["paid"]["url_digest"] == hashlib.sha256(secret_url.encode()).hexdigest()


def test_an_rss_source_reads_a_json_feed():
    """The format is sniffed, not configured: an existing ``rss`` source gains JSON Feed without a new key."""

    def http(method, url, headers, body):
        assert headers["Accept"].startswith("application/rss+xml")
        return 200, {"ETag": ETAG}, JSON_FEED

    source = RssSource("vendor", URL)
    state: dict = {}
    window = source.fetch(http, state)
    (item,) = window.items
    assert item.guid == "adv-1"
    assert item.title.startswith("DSA-6558-1")
    source.commit(state)
    assert state["feeds"]["vendor"]["etag"] == ETAG


def test_an_rss_source_follows_a_page_to_the_feed_it_advertises(monkeypatch):
    # The guard is exercised in tests/test_source_admin.py; stubbing its resolver keeps this test off real DNS.
    monkeypatch.setattr(feeds, "private_destination", lambda url: False)
    calls: list[tuple[str, dict[str, str]]] = []

    def http(method, url, headers, body):
        calls.append((url, dict(headers)))
        if url == PAGE_URL:
            return 200, {"ETag": '"page"'}, PAGE
        assert url == URL
        return 200, {"ETag": '"feed"'}, FEED

    source = RssSource("vendor", PAGE_URL)
    state: dict = {}
    window = source.fetch(http, state)
    assert [item.guid for item in window.items] == ["https://lists.debian.org/dsa-6558"]
    assert [url for url, _ in calls] == [PAGE_URL, URL]
    source.commit(state)
    # A page's ETag says nothing about the feed it advertises, so no validator is armed for the next poll.
    assert "feeds" not in state


def test_an_autodiscovered_page_clears_the_validator_of_the_feed_it_replaced(monkeypatch):
    """The URL used to answer the feed directly and now answers a page.

    Keeping the stored ETag would send ``If-None-Match`` to the page: a 304 would then hide every change behind
    the autodiscovery hop for as long as the page stayed unchanged, which is exactly the silence this source
    exists to break.
    """
    # The guard is exercised in tests/test_source_admin.py; stubbing its resolver keeps this test off real DNS.
    monkeypatch.setattr(feeds, "private_destination", lambda url: False)
    calls: list[dict[str, str]] = []
    state = {"feeds": {"vendor": {"url_digest": hashlib.sha256(PAGE_URL.encode()).hexdigest(), "etag": '"old"'}}}

    def http(method, url, headers, body):
        calls.append(dict(headers))
        if url == PAGE_URL:
            return 200, {"ETag": '"page"'}, PAGE
        return 200, {}, FEED

    source = RssSource("vendor", PAGE_URL)
    source.fetch(http, state)
    assert calls[0]["If-None-Match"] == '"old"', "the stored validator belongs to this URL and is sent"
    source.commit(state)
    assert "vendor" not in state["feeds"], "a page answer must clear it before it hides the feed"


def _policy(product: str) -> Policy:
    return Policy(
        debian_source_packages=(),
        excluded_products=(),
        products=(Product(id=product, aliases=(), domains=(), metadata_only=False),),
    )


def test_a_policy_change_drops_the_conditional_request_state():
    # a 304 says the feed is unchanged, not that nothing in it became in scope
    state: dict = {"feeds": {"nodejs": {"url_digest": "x", "etag": "e"}}}
    pipeline._reset_validators_on_policy_change(state, _policy("nodejs"))
    assert state["feeds"] == {}
    state["feeds"] = {"nodejs": {"url_digest": "x", "etag": "e"}}
    pipeline._reset_validators_on_policy_change(state, _policy("nodejs"))
    assert state["feeds"] == {"nodejs": {"url_digest": "x", "etag": "e"}}
    pipeline._reset_validators_on_policy_change(state, _policy("postgresql"))
    assert state["feeds"] == {}


def test_removing_a_source_drops_its_validators_with_its_carry():
    # keeping the validators would let a re-added, unchanged feed answer 304 for work just discarded
    state = {
        "carry": {"feed": [{"guid": "g"}], "other": [{"guid": "h"}]},
        "feeds": {"feed": {"url_digest": "d", "etag": "e"}, "other": {"url_digest": "x"}},
    }
    # ``feed`` is no longer declared at all, while ``other`` is both declared and enabled.
    pipeline._drop_removed_sources(state, {"other"}, {"other"}, complete=True)
    assert state["carry"] == {"other": [{"guid": "h"}]}
    assert state["feeds"] == {"other": {"url_digest": "x"}}
