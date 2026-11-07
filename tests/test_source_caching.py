"""Conditional GET for feeds: an unchanged publisher must cost one round trip, not the whole feed.

A feed polled every 15 minutes is read 96 times a day; without validators every one of those transfers the
whole document from a publisher who owes us nothing. The risky half is the other side:

* a 304 must be an empty window, never an error, and must not forget the validators;
* the validators belong to the URL that issued them, because an ETag is unique per resource -- repointing a
  source id at another feed must not send the old one and earn a legitimate 304 for a feed never read;
* they are stored by ``commit``, after the pipeline captured the candidates, so a window whose advisories were
  never queued is read in full again (the same rule the changedetection cursor follows).
"""

from __future__ import annotations

import pytest

from advisory_radar import feeds
from advisory_radar.sources import RssSource

FEED = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Vendor</title><link>https://vendor.example.com/</link>
<item><title>DSA-6558-1 curl - security update</title><link>https://lists.debian.org/dsa-6558</link>
<guid>https://lists.debian.org/dsa-6558</guid><description>Fixes CVE-2026-1111.</description>
<pubDate>Wed, 21 Oct 2026 10:00:00 +0000</pubDate></item>
</channel></rss>"""

ETAG = '"v1"'
MODIFIED = "Wed, 21 Oct 2026 10:00:00 GMT"
URL = "https://vendor.example.com/feed.xml"


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
    assert state["feeds"]["nodejs"] == {"url": URL, "etag": ETAG, "last_modified": MODIFIED}
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
    assert state["feeds"]["vendor"]["url"] == "https://b.example.com/feed.xml"


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
    state = {"feeds": {"nodejs": {"url": URL, "etag": 7, "last_modified": None}}}
    source.fetch(http_with(calls, [200]), state)
    assert "If-None-Match" not in calls[0]
    assert "If-Modified-Since" not in calls[0]


def test_fetch_rss_returns_the_validators_and_refuses_an_error_status():
    def not_modified(method, url, headers, body):
        assert headers["Accept"].startswith("application/rss+xml")
        return 304, {}, b""

    export, stored = feeds.fetch_rss(not_modified, URL)
    assert export.items == () and not export.truncated
    assert stored is None  # 304: keep the validators already stored, do not forget them

    def unavailable(method, url, headers, body):
        return 503, {}, b""

    with pytest.raises(feeds.RssError):
        feeds.fetch_rss(unavailable, URL)
