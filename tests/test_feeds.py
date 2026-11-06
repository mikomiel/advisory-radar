"""Feed reader tests: GReader export and generic RSS/Atom."""

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
