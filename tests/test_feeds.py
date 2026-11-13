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


def test_atom_honours_the_declared_text_type():
    """Atom ``type`` defaults to ``text``: an undeclared or text-typed construct is not markup."""
    atom = (
        b'<feed xmlns="http://www.w3.org/2005/Atom">'
        b"<title>Vendor &lt;security&gt;</title>"
        b"<entry><id>urn:uuid:1</id>"
        b"<title>Security update for &lt;libfoo&gt; 2.0</title>"
        b'<summary type="text">Fixes &lt;libfoo&gt; 2.0.</summary>'
        b'<content type="html">&lt;p&gt;Fixes &lt;b&gt;CVE-2026-2222&lt;/b&gt;.&lt;/p&gt;</content>'
        b"</entry></feed>"
    )
    (entry,) = feeds.parse_rss(atom).items
    assert entry.source_title == "Vendor <security>"
    assert entry.title == "Security update for <libfoo> 2.0"
    assert entry.summary == "Fixes <libfoo> 2.0. Fixes CVE-2026-2222."


def test_an_atom_text_title_still_matches_the_watchlist():
    """The product name sits inside a literal tag-like run that the HTML parser would drop."""
    from advisory_radar import core, watchlist

    policy = watchlist.Policy((), (), (watchlist.Product("libfoo", (), (), False),))
    atom = (
        b'<feed xmlns="http://www.w3.org/2005/Atom"><link rel="alternate" href="https://vendor.example.com/"/>'
        b"<entry><id>urn:uuid:1</id><title>Security update for &lt;libfoo&gt; 2.0</title>"
        b'<summary type="text">No package name here.</summary></entry></feed>'
    )
    (entry,) = feeds.parse_rss(atom).items
    assert core.matched_products(entry, policy) == ("libfoo",)


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


def test_json_feed_titles_are_plain_text_and_keep_literal_angle_brackets():
    """JSON Feed ``title`` and ``summary`` are specification-defined plain text, not markup."""
    body = b"""{
      "version": "https://jsonfeed.org/version/1.1",
      "title": "Vendor <security> advisories",
      "items": [
        {"id": "a1", "title": "Security update for <libfoo> 2.0", "summary": "Fixes <libfoo> 2.0."},
        {"id": "a2", "title": "fixed in <2.0", "content_text": "Security update."}
      ]
    }"""
    first, second = feeds.parse_json_feed(body).items
    assert first.source_title == "Vendor <security> advisories"
    assert first.title == "Security update for <libfoo> 2.0"
    assert first.summary == "Fixes <libfoo> 2.0."
    assert second.title == "fixed in <2.0"


def test_a_json_feed_plain_text_title_still_matches_the_watchlist():
    """A product name that only occurs inside a literal tag-like run is still evidence, not markup."""
    from advisory_radar import core, watchlist

    policy = watchlist.Policy((), (), (watchlist.Product("libfoo", (), (), False),))
    body = (
        b'{"version": "https://jsonfeed.org/version/1.1", "items": ['
        b'{"id": "a1", "title": "Security update for <libfoo> 2.0", "content_text": "No package name here."}]}'
    )
    (entry,) = feeds.parse_json_feed(body).items
    assert entry.title == "Security update for <libfoo> 2.0"
    assert core.matched_products(entry, policy) == ("libfoo",)


def test_a_json_feed_content_html_is_still_normalised():
    body = (
        b'{"version": "https://jsonfeed.org/version/1.1", "items": ['
        b'{"id": "a1", "title": "t", "content_html": "<p>Fixes CVE-2026-1111 in <b>libfoo</b>.</p>"}]}'
    )
    assert feeds.parse_json_feed(body).items[0].summary == "Fixes CVE-2026-1111 in libfoo."


def test_a_json_feed_item_without_a_title_derives_a_usable_one():
    """``title`` is optional in JSON Feed: one untitled entry must not make the document unreadable."""
    body = b"""{
      "version": "https://jsonfeed.org/version/1.1",
      "items": [
        {"id": "first", "content_text": "APSB26-9 fixes CVE-2026-5555.\\nSecond line."},
        {"id": "second", "content_html": "<p>APSB26-10 fixes CVE-2026-6666.</p>"},
        {"id": "third", "summary": "APSB26-11 summary line"},
        {"id": "fourth"}
      ]
    }"""
    first, second, third, fourth = feeds.parse_json_feed(body).items
    assert first.title == "APSB26-9 fixes CVE-2026-5555."  # the content's first line
    assert second.title == "APSB26-10 fixes CVE-2026-6666."  # the text of the HTML content
    assert third.title == "APSB26-11 summary line"  # the summary when no content is present
    assert fourth.title == "fourth"  # the id as the last resort


def test_a_derived_json_feed_title_is_capped():
    content = b"x" * (feeds.DERIVED_TITLE_CHARS + 50)
    export = feeds.parse_json_feed(
        b'{"version": "https://jsonfeed.org/version/1.1", "items": [{"id": "long", "content_text": "'
        + content
        + b'"}]}'
    )
    assert export.items[0].title == "x" * feeds.DERIVED_TITLE_CHARS


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


def test_parse_any_requires_positive_evidence_for_each_json_shape():
    """An ``items`` list is not evidence: an unrelated JSON API must not look like an unchanged source."""
    with pytest.raises(feeds.FeedError, match="neither JSON Feed nor a GReader export"):
        feeds.parse_any(b'{"items": []}')
    with pytest.raises(feeds.FeedError, match="neither JSON Feed nor a GReader export"):
        feeds.parse_any(b'{"items": [{"id": "plain", "title": "not a GReader item"}]}')
    # An empty-but-real stream carries its stream marker, so it is still recognised.
    empty_stream = b'{"id": "user/-/state/com.google/reading-list", "updated": 1792600000, "items": []}'
    assert feeds.parse_any(empty_stream).items == ()
    # The explicit FreshRSS reader keeps its permissive contract; only the sniffing path is strict.
    assert feeds.parse_feed(b'{"items": []}').items == ()


def test_parse_any_rejects_a_json_feed_without_items():
    with pytest.raises(feeds.FeedError):
        feeds.parse_any(b'{"version": "https://jsonfeed.org/version/1.1", "title": "Nothing to read"}')


def test_parse_rss_rejects_an_rdf_feed_without_items():
    with pytest.raises(feeds.RssError):
        feeds.parse_rss(RDF_NO_ITEMS)


def test_parse_any_refuses_an_html_page():
    with pytest.raises(feeds.FeedError):
        feeds.parse_any(PAGE)  # autodiscovery needs the page URL, which a parser does not have


def test_fetch_any_follows_one_autodiscovery_hop(monkeypatch):
    # The private-destination guard itself is exercised in tests/test_source_admin.py; stubbing it here keeps
    # this test off real DNS. The recorder proves it still saw the discovered target.
    guarded = []
    monkeypatch.setattr(feeds, "private_destination", lambda url: guarded.append(url) or False)
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
    assert guarded == ["https://vendor.example.com/feeds/security.xml"]
    assert "text/html" in calls[0][1]["Accept"]
    assert "text/html" not in calls[1][1]["Accept"]
    # A page's validators describe the page, not the feed it advertises, so none are stored.
    assert stored == {}


def test_fetch_any_refuses_a_discovered_private_feed_before_fetching_it():
    """The page is remote-authored: its link must not aim this poll at loopback or a metadata service."""
    calls = []

    def http(method, url, headers, body):
        calls.append(url)
        return (
            200,
            {},
            b"""<html><head>
        <link rel="alternate" type="application/rss+xml" href="http://127.0.0.1:8080/feed.xml">
        </head></html>""",
        )

    with pytest.raises(feeds.FeedError):
        feeds.fetch_any(http, "https://vendor.example.com/security")
    assert calls == ["https://vendor.example.com/security"], "the internal GET must never be issued"


@pytest.mark.parametrize(
    "href",
    [
        "https://cdn.example.net/feeds/security.xml",  # another host
        "http://vendor.example.com/feeds/security.xml",  # another scheme
        "https://vendor.example.com:8443/feeds/security.xml",  # another port
    ],
)
def test_fetch_any_refuses_a_feed_on_another_origin_before_fetching_it(href):
    """The page's own host is the one the operator chose; discovery may not redirect the reader elsewhere."""
    calls = []

    def http(method, url, headers, body):
        calls.append(url)
        page = f'<html><head><link rel="alternate" type="application/rss+xml" href="{href}"></head></html>'
        return 200, {}, page.encode()

    with pytest.raises(feeds.FeedError, match="another origin"):
        feeds.fetch_any(http, PAGE_URL)
    assert calls == [PAGE_URL], "the other-origin GET must never be issued"


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


def test_a_control_character_in_a_feed_identity_is_kept_exactly():
    """An identity is compared, never rewritten: the log and display boundaries escape it instead."""
    rdf = RDF.replace(
        b'rdf:about="https://vendor.example.com/apsb26-1"',
        b'rdf:about="apsb26-1&#10;2026-10-22 INFO forged&#127;"',
    )
    entry = feeds.parse_rss(rdf).items[0]
    assert entry.guid == "apsb26-1\n2026-10-22 INFO forged\x7f"


def test_an_identity_of_only_control_characters_is_kept_verbatim():
    """An odd-looking id is still the publisher's identity; replacing it can reach a different advisory."""
    document = (
        b'{"version": "https://jsonfeed.org/version/1.1", "items": ['
        b'{"id": "\\u2028", "content_text": "Security update"}]}'
    )
    assert feeds.parse_json_feed(document).items[0].guid == "\u2028"
    # The id wins over a perfectly usable url, because falling back would silently rename the advisory.
    with_url = (
        b'{"version": "https://jsonfeed.org/version/1.1", "items": ['
        b'{"id": "\\u2028", "url": "https://vendor.example.com/a", "content_text": "Security update"}]}'
    )
    assert feeds.parse_json_feed(with_url).items[0].guid == "\u2028"
    rss = b"<rss><channel><item><title>t</title><guid>\x7f</guid></item></channel></rss>"
    assert feeds.parse_rss(rss).items[0].guid == "\x7f"


def test_an_identity_utf8_cannot_encode_is_kept_verbatim():
    """A guid that is not a Unicode scalar value is legal in state now, so the reader accepts it raw.

    The log and display boundaries escape it: this reader no longer refuses, nor falls back to a different
    value, because either would change which advisory the identity names.
    """
    document = (
        b'{"version": "https://jsonfeed.org/version/1.1", "items": ['
        b'{"id": "\\ud800", "content_text": "Security update"}]}'
    )
    assert feeds.parse_json_feed(document).items[0].guid == "\ud800"
    with_url = (
        b'{"version": "https://jsonfeed.org/version/1.1", "items": ['
        b'{"id": "\\ud800", "url": "https://vendor.example.com/a", "content_text": "Security update"}]}'
    )
    assert feeds.parse_json_feed(with_url).items[0].guid == "\ud800"


def test_a_feed_body_that_is_not_valid_utf8_is_refused():
    """Raw ``ED A0 80 ED B0 80`` is accepted by ``json.loads`` as two surrogates, which stop being the same
    identity after ``ensure_ascii`` spells them like the scalar ``U+10000`` and the decoder recombines them."""
    pair = b"\xed\xa0\x80\xed\xb0\x80"
    malformed = (
        b'{"version": "https://jsonfeed.org/version/1.1", "items": [{"id": "'
        + pair
        + b'", "content_text": "Security update"}]}'
    )
    for reader in (feeds.parse_json_feed, feeds.parse_feed, feeds.parse_any):
        with pytest.raises(feeds.FeedError, match="not valid UTF-8"):
            reader(malformed)
    # The valid UTF-8 encoding of the same scalar is one code point and is read as itself, unchanged.
    scalar = "\U00010000"
    valid = (
        b'{"version": "https://jsonfeed.org/version/1.1", "items": [{"id": "'
        + scalar.encode()
        + b'", "content_text": "Security update"}]}'
    )
    assert feeds.parse_json_feed(valid).items[0].guid == scalar
    assert feeds.parse_any(valid).items[0].guid == scalar


def test_feed_text_utf8_cannot_encode_is_replaced_rather_than_raised():
    """A log record and an HTTP response both encode; neither may fail because a publisher sent a surrogate."""
    document = (
        b'{"version": "https://jsonfeed.org/version/1.1", "title": "\\ud800 feed", "items": ['
        b'{"id": "a1", "title": "\\ud800 advisory", "content_text": "Security update"}]}'
    )
    export = feeds.parse_json_feed(document)
    export.items[0].title.encode("utf-8")
    assert "advisory" in export.items[0].title
