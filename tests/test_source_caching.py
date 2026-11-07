"""Conditional GET for feeds: an unchanged publisher must cost one round trip, not the whole feed.

A feed polled every 15 minutes is read 96 times a day; without validators every one of those transfers the
whole document from a publisher who owes us nothing. The risky half is the other side: a 304 must be an empty
window, never an error and never a reason to drop the validators, or the next poll fetches the body again.
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


def http_with(calls: list[dict[str, str]], statuses: list[int]):
    def http(method, url, headers, body):
        calls.append(dict(headers))
        if statuses[min(len(calls), len(statuses)) - 1] == 304:
            return 304, {}, b""
        return 200, {"ETag": ETAG, "Last-Modified": MODIFIED}, FEED

    return http


def test_an_unchanged_feed_answers_304_and_stores_no_new_validators():
    calls: list[dict[str, str]] = []
    source = RssSource("nodejs", "https://vendor.example.com/feed.xml")
    state: dict = {}
    first = source.fetch(http_with(calls, [200, 304]), state)
    assert [item.guid for item in first.items] == ["https://lists.debian.org/dsa-6558"]
    assert state["feeds"]["nodejs"] == {"etag": ETAG, "last_modified": MODIFIED}
    second = source.fetch(http_with(calls, [200, 304]), state)
    assert second.items == ()  # not an error: the publisher says nothing changed
    assert calls[1]["If-None-Match"] == ETAG
    assert calls[1]["If-Modified-Since"] == MODIFIED
    # a 304 carries no validators, and the stored ones must survive it: forgetting them refetches the body
    assert state["feeds"]["nodejs"] == {"etag": ETAG, "last_modified": MODIFIED}


def test_a_feed_with_no_validators_is_always_fetched_in_full():
    calls: list[dict[str, str]] = []

    def http(method, url, headers, body):
        calls.append(dict(headers))
        return 200, {}, FEED

    source = RssSource("nodejs", "https://vendor.example.com/feed.xml")
    state: dict = {}
    source.fetch(http, state)
    source.fetch(http, state)
    assert "If-None-Match" not in calls[0]
    assert "If-None-Match" not in calls[1]
    assert "feeds" not in state  # nothing to remember


def test_fetch_rss_returns_the_validators_and_refuses_an_error_status():
    def not_modified(method, url, headers, body):
        assert headers["Accept"].startswith("application/rss+xml")
        return 304, {}, b""

    export, stored = feeds.fetch_rss(not_modified, "https://vendor.example.com/feed.xml")
    assert export.items == () and not export.truncated
    assert stored == {}

    def unavailable(method, url, headers, body):
        return 503, {}, b""

    with pytest.raises(feeds.RssError):
        feeds.fetch_rss(unavailable, "https://vendor.example.com/feed.xml")


def test_a_stored_validator_that_is_not_a_string_is_ignored():
    calls: list[dict[str, str]] = []
    source = RssSource("nodejs", "https://vendor.example.com/feed.xml")
    state = {"feeds": {"nodejs": {"etag": 7, "last_modified": None}}}  # a hand-edited state
    source.fetch(http_with(calls, [200]), state)
    assert "If-None-Match" not in calls[0]
    assert "If-Modified-Since" not in calls[0]
