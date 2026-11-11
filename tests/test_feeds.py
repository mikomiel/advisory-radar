"""Feed reader tests: the GReader export, JSON Feed, RSS/Atom/RDF, OPML and autodiscovery."""

from __future__ import annotations

import pytest

from advisory_radar import feeds

GREADER = b"""{
  "items": [
    {"id": "tag:google.com,2005:reader/item/0000000000000001",
     "title": "DSA-6558-1 curl - security update",
     "canonical": [{"href": "https://lists.debian.org/dsa-6558"}],
     "summary": {"content": "<p>curl fixed CVE-2026-1111.</p>"},
     "published": 1760000000,
     "origin": {"title": "Debian Security", "htmlUrl": "https://lists.debian.org/"}}
  ],
  "continuation": "abc"
}"""

RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Vendor News</title><link>https://vendor.example.com/news</link>
<item><title>APSB26-1 Adobe Commerce security update</title><link>https://vendor.example.com/apsb26-1</link>
<guid>https://vendor.example.com/apsb26-1</guid><description>Fixes CVE-2026-2222.</description>
<pubDate>Wed, 21 Oct 2026 10:00:00 +0000</pubDate></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Vendor</title>
<link href="https://vendor.example.com/atom"/>
<entry><id>urn:uuid:1</id><title>Security advisory GHSA-aaaa-bbbb-cccc</title>
<link rel="alternate" href="https://vendor.example.com/a1"/>
<summary>Fixes GHSA-aaaa-bbbb-cccc.</summary><published>2026-10-21T10:00:00Z</published></entry>
</feed>"""

JSON_FEED = b"""{
  "version": "https://jsonfeed.org/version/1.1",
  "title": "Vendor Security",
  "home_page_url": "https://vendor.example.com/security",
  "items": [
    {"id": "apsb26-2",
     "url": "https://vendor.example.com/apsb26-2",
     "title": "APSB26-2 Adobe Commerce security update",
     "content_text": "Fixes CVE-2026-3333.",
     "content_html": "<p>Fixes CVE-2026-3333.</p>",
     "date_published": "2026-10-21T10:00:00Z"},
    {"id": "apsb26-3",
     "external_url": "https://vendor.example.com/apsb26-3",
     "title": "APSB26-3 Adobe Commerce security update",
     "content_html": "<p>Fixes CVE-2026-4444.</p>",
     "date_modified": "2026-10-22T10:00:00+00:00"}
  ]
}"""

RDF = b"""<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel rdf:about="https://vendor.example.com/rdf">
<title>Vendor RDF</title><link>https://vendor.example.com/</link>
</channel>
<item rdf:about="https://vendor.example.com/apsb26-1">
<title>APSB26-1 Adobe Commerce security update</title>
<link>https://vendor.example.com/apsb26-1</link>
<description>Fixes CVE-2026-2222.</description>
<dc:date>2026-10-21T10:00:00Z</dc:date>
</item>
</rdf:RDF>"""

RDF_NO_ITEMS = b"""<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/">
<channel rdf:about="https://vendor.example.com/rdf">
<title>Vendor RDF</title><link>https://vendor.example.com/</link>
</channel>
</rdf:RDF>"""

PAGE_URL = "https://vendor.example.com/security"

PAGE = b"""<!DOCTYPE html>
<html><head>
<title>Security advisories</title>
<link rel="stylesheet" type="text/css" href="/site.css">
<link rel="alternate" type="text/html" href="/security">
<link rel="alternate" type="application/rss+xml; charset=utf-8" href="/feeds/security.xml">
<link rel="alternate" type="application/atom+xml" href="https://vendor.example.com/feeds/security.atom">
</head><body><h1>Security</h1></body></html>"""

OPML = b"""<?xml version="1.0"?>
<opml version="2.0"><head><title>Subscriptions</title></head><body>
  <outline text="Vendors">
    <outline type="rss" text="Vendor Security" title="Vendor Security Advisory"
             xmlUrl="https://vendor.example.com/rss" htmlUrl="https://vendor.example.com/"/>
    <outline type="rss" text="Debian Security" xmlUrl="https://lists.example.org/dsa.rdf"/>
  </outline>
  <outline type="rss" text="Adobe" xmlUrl="https://adobe.example.com/rss" htmlUrl="https://adobe.example.com/"/>
</body></opml>"""


def test_parse_greader_export():
    export = feeds.parse_feed(GREADER)
    assert export.truncated is True  # continuation token present
    (entry,) = export.items
    assert entry.guid == "1"
    assert entry.title.startswith("DSA-6558-1")
    assert entry.summary == "curl fixed CVE-2026-1111."
    assert entry.published == 1760000000
    assert entry.source_title == "Debian Security"


def test_parse_rss():
    export = feeds.parse_rss(RSS)
    assert export.truncated is False
    (entry,) = export.items
    assert entry.title.startswith("APSB26-1")
    assert "CVE-2026-2222" in entry.summary
    assert entry.published == 1792576800
    assert entry.source_url == "https://vendor.example.com/news"


def test_parse_atom():
    export = feeds.parse_rss(ATOM)
    (entry,) = export.items
    assert entry.guid == "urn:uuid:1"
    assert entry.link == "https://vendor.example.com/a1"
    assert entry.published is not None


def test_parse_rss_rejects_garbage():
    with pytest.raises(feeds.RssError):
        feeds.parse_rss(b"<html>not a feed</html>")


def test_parse_json_feed():
    export = feeds.parse_json_feed(JSON_FEED)
    assert export.truncated is False
    first, second = export.items
    assert first.guid == "apsb26-2"
    assert first.link == "https://vendor.example.com/apsb26-2"
    # Both content fields are the same advisory in two renderings, so it is said once.
    assert first.summary == "Fixes CVE-2026-3333."
    assert first.published == 1792576800
    assert first.source_title == "Vendor Security"
    assert first.source_url == "https://vendor.example.com/security"
    assert second.guid == "apsb26-3"
    assert second.link == "https://vendor.example.com/apsb26-3"  # external_url when url is absent
    assert second.published == 1792663200  # date_modified when date_published is absent


def test_parse_rdf_feed():
    export = feeds.parse_rss(RDF)
    (entry,) = export.items
    assert entry.guid == "https://vendor.example.com/apsb26-1"
    assert entry.link == "https://vendor.example.com/apsb26-1"
    assert entry.summary == "Fixes CVE-2026-2222."
    assert entry.published == 1792576800
    assert entry.source_title == "Vendor RDF"
    assert entry.source_url == "https://vendor.example.com/"


def test_discover_feed_ignores_links_that_are_not_feeds():
    assert feeds.discover_feed(PAGE, PAGE_URL) == "https://vendor.example.com/feeds/security.xml"
    page_with_json_feed = b"""<html><head>
    <link rel="alternate" type="application/feed+json" href="feed.json">
    </head></html>"""
    assert feeds.discover_feed(page_with_json_feed, PAGE_URL) == "https://vendor.example.com/feed.json"
    assert feeds.discover_feed(b"<html><head></head><body>no feeds</body></html>", PAGE_URL) is None


def test_parse_opml_flattens_nested_outlines():
    assert feeds.parse_opml(OPML) == (
        ("Vendor Security Advisory", "https://vendor.example.com/rss", "https://vendor.example.com/"),
        ("Debian Security", "https://lists.example.org/dsa.rdf", ""),
        ("Adobe", "https://adobe.example.com/rss", "https://adobe.example.com/"),
    )


def test_parse_any_dispatches_by_version_and_root():
    assert feeds.parse_any(GREADER).items[0].guid == "1"
    assert feeds.parse_any(JSON_FEED).items[0].guid == "apsb26-2"
    assert feeds.parse_any(RSS).items[0].title.startswith("APSB26-1")
    assert feeds.parse_any(RDF).items[0].guid == "https://vendor.example.com/apsb26-1"
    with pytest.raises(feeds.FeedError):
        # A version, not an items list, tells the two JSON exports apart.
        feeds.parse_feed(JSON_FEED)


def test_parse_any_rejects_a_json_feed_without_items():
    with pytest.raises(feeds.FeedError):
        feeds.parse_any(b'{"version": "https://jsonfeed.org/version/1.1", "title": "Nothing to read"}')


def test_parse_rss_rejects_an_rdf_feed_without_items():
    with pytest.raises(feeds.RssError):
        feeds.parse_rss(RDF_NO_ITEMS)


def test_parse_any_refuses_an_html_page():
    with pytest.raises(feeds.FeedError):
        feeds.parse_any(PAGE)  # autodiscovery needs the page URL, which a parser does not have


def test_fetch_any_follows_one_autodiscovery_hop():
    calls = []

    def http(method, url, headers, body):
        calls.append((url, dict(headers)))
        if url == PAGE_URL:
            return 200, {"ETag": '"page"'}, PAGE
        if url == "https://vendor.example.com/feeds/security.xml":
            return 200, {"ETag": '"feed"'}, RSS
        raise AssertionError(f"unexpected fetch: {url}")

    export, stored = feeds.fetch_any(http, PAGE_URL)
    (entry,) = export.items
    assert entry.title.startswith("APSB26-1")
    assert [url for url, _ in calls] == [PAGE_URL, "https://vendor.example.com/feeds/security.xml"]
    assert "text/html" in calls[0][1]["Accept"]
    assert "text/html" not in calls[1][1]["Accept"]
    # A page's validators describe the page, not the feed it advertises, so none are stored.
    assert stored == {}


def test_fetch_any_reads_a_json_feed_and_keeps_its_validators():
    def http(method, url, headers, body):
        return 200, {"ETag": '"v1"'}, JSON_FEED

    export, stored = feeds.fetch_any(http, "https://vendor.example.com/feed.json")
    assert export.items[0].guid == "apsb26-2"
    assert stored == {"etag": '"v1"'}


def test_fetch_any_refuses_a_304_to_an_unconditional_request():
    def not_modified(method, url, headers, body):
        return 304, {}, b""

    with pytest.raises(feeds.RssError):
        feeds.fetch_any(not_modified, PAGE_URL)
    export, stored = feeds.fetch_any(not_modified, PAGE_URL, {"If-None-Match": '"abc"'})
    assert export.items == () and not export.truncated
    assert stored is None  # a 304 keeps the validators already stored


def test_an_html_page_without_a_feed_link_is_refused():
    def no_link(method, url, headers, body):
        return 200, {}, b"<!DOCTYPE html><html><head><title>No feed</title></head></html>"

    with pytest.raises(feeds.FeedError):
        feeds.fetch_any(no_link, PAGE_URL)
