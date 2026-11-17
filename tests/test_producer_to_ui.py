"""What a pass records is what an operator reads.

``test_ui`` and ``test_web`` start from a state document built by hand, so a producer that stops writing a field
the pages read breaks none of them. These tests start from the producer instead: the real pass runs over a fake
feed (items parsed by the real RSS reader), stubbed enrichment services and a channel that refuses one message,
and then the signed-in web client reads the pages an operator reads.

Each test pins one link between what the pass wrote and what a page shows, and reads a row, a cell or a fact. A
word anywhere in the page proves nothing: the filter forms echo the query back, so a source id or an alias would
"appear" on a result that is empty.
"""

from __future__ import annotations

import html
import json
import re
import urllib.parse
from collections import defaultdict
from collections.abc import Iterable
from email.utils import formatdate

import pytest
from fastapi.testclient import TestClient

from advisory_radar import pipeline
from advisory_radar.config import load_config
from advisory_radar.sources import RssSource
from advisory_radar.web import create_app
from test_pipeline import WindowSource
from test_ui import DAY, INBOX_ROW_RE, NOW, TOKEN, RecordingNotifier, page_ids, sign_in

SOURCE_ID = "vendor-feed"
CHANNEL = "ops"
FEED_URL = "https://feeds.example.com/advisories.xml"
#: The advisory the channel accepts as a warning and, a day later, as an escalation.
CVE_A = "CVE-2026-31001"
#: Its alias. Only the item's description names it: the title does not, so the recorded identifiers are the one
#: route to it, and a text search that finds it has found the record the pass wrote.
GHSA_A = "GHSA-q3x7-9mwv-p2hc"
HEADING_A = "Parser library security update"
#: The advisory the channel keeps refusing until the pass parks it.
CVE_B = "CVE-2026-31002"
HEADING_B = "Network daemon security update"
#: The dash the pages print in a cell that has no value. Written as an escape so this file holds no dash.
NO_VALUE = "\u2014"

CONFIG = """\
sources:
  - id: {source}
    type: rss
    url: {url}
notifiers:
  - id: {channel}
    type: webhook
    url: https://hooks.example.com/advisories
state_path: {state}
"""

FEED = f"""<?xml version="1.0"?><rss version="2.0"><channel><title>Vendor advisories</title>
<link>https://feeds.example.com/</link>
<item><title>{HEADING_A}</title><link>https://vendor.example.com/advisories/parser</link>
<guid>parser-1</guid><description>Fixes {CVE_A}, which GitHub tracks as {GHSA_A}.</description>
<pubDate>{formatdate(NOW - 7200, usegmt=True)}</pubDate></item>
<item><title>{HEADING_B}</title><link>https://vendor.example.com/advisories/daemon</link>
<guid>daemon-1</guid><description>Fixes {CVE_B}.</description>
<pubDate>{formatdate(NOW - 3600, usegmt=True)}</pubDate></item>
</channel></rss>""".encode()


class Upstream:
    """The enrichment services a pass calls, answered from fixed documents: CVE.org, EPSS, OSV and CISA KEV.

    Every CVE is a medium score with a low EPSS, so a message is a warning until the catalogue lists its CVE. The
    catalogue always lists a decoy, because an empty one is refused as unusable.
    """

    def __init__(self) -> None:
        self.kev = {"CVE-2020-0001"}

    def __call__(self, method, url, headers, payload):
        parts = urllib.parse.urlsplit(url)
        if parts.hostname == "cveawg.mitre.org":
            cve = parts.path.rsplit("/", 1)[-1]
            metric = {"baseScore": 6.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}
            document = {
                "cveMetadata": {"cveId": cve, "state": "PUBLISHED"},
                "containers": {"cna": {"metrics": [{"cvssV3_1": metric}]}},
            }
        elif parts.hostname == "api.first.org":
            requested = urllib.parse.parse_qs(parts.query)["cve"][0].split(",")
            document = {"data": [{"cve": cve, "epss": "0.01", "percentile": "0.40"} for cve in requested]}
        elif parts.hostname == "api.osv.dev":
            document = {"id": GHSA_A, "aliases": [CVE_A], "database_specific": {"severity": "MODERATE"}}
        elif parts.hostname == "www.cisa.gov":
            document = {"catalogVersion": "1", "vulnerabilities": [{"cveID": cve} for cve in sorted(self.kev)]}
        else:
            raise AssertionError(f"unexpected request {method} {url}")
        return 200, {}, json.dumps(document).encode()


class Channel(RecordingNotifier):
    """A channel that answers 503 to a message naming a refused identifier and 200 to every other."""

    def __init__(self, notifier_id: str, refuse: Iterable[str]) -> None:
        super().__init__(notifier_id)
        self.refuse = frozenset(refuse)

    def send(self, entry, http) -> int:
        self.status = 503 if self.refuse.intersection(entry["ids"]) else 200
        return super().send(entry, http)


def read_feed(body: bytes):
    """The items the real RSS source reads from ``body``: parsed from a feed, not built by hand."""
    source = RssSource(SOURCE_ID, FEED_URL)
    return source.fetch(lambda method, url, headers, payload: (200, {}, body), {}).items


@pytest.fixture
def operator(tmp_path):
    """A signed-in web client over the state four real passes left behind.

    1. ``NOW``: the feed carries two advisories. The channel takes the first, a warning that names a CVE and its
       GHSA alias, and refuses the second.
    2. and 3. Ten and twenty minutes on: the refused message is offered again and refused again. The third
       refusal parks it.
    4. A day later: CISA lists the first CVE, so the daily re-score escalates it and the channel takes the
       escalation.

    The feed lists neither advisory after the first pass, as a feed that rotates its items does. Everything
    later comes from the queue and the re-score, so a page can show an identifier only if the first pass
    recorded it: a second read of the feed cannot repair what the first pass lost.
    """
    config = tmp_path / "config.yml"
    config.write_text(
        CONFIG.format(source=SOURCE_ID, url=FEED_URL, channel=CHANNEL, state=tmp_path / "state.json"),
    )
    cfg = load_config(config, {})
    channel = Channel(CHANNEL, refuse=[CVE_B])
    upstream = Upstream()

    def run(at: int, window=()) -> None:
        source = WindowSource(SOURCE_ID, window, host="feeds.example.com")
        pipeline.run_pass(cfg, [source], [channel], http=upstream, clock=lambda: float(at), sleep=lambda seconds: None)

    run(NOW, read_feed(FEED))
    run(NOW + 600)
    run(NOW + 1200)
    upstream.kev.add(CVE_A)
    later = NOW + DAY + 3600
    run(later)
    # The scenario is the producer's to keep; a change that breaks it should fail here and not at a page.
    assert [(message["kind"], message["tag"], tuple(sorted(message["ids"]))) for message in channel.sent] == [
        ("new", "warning", (CVE_A, GHSA_A)),
        ("new", "warning", (CVE_B,)),
        ("new", "warning", (CVE_B,)),
        ("new", "warning", (CVE_B,)),
        ("escalation", "critical", (CVE_A,)),
    ]
    client = TestClient(create_app(cfg, {"ADVISORY_RADAR_AUTH_TOKEN": TOKEN}, clock=lambda: float(later)))
    sign_in(client)
    return client


# --- reading a page ----------------------------------------------------------------------------

TAGS = re.compile(r"<[^>]*>")
ROW = re.compile(r"<tr>(.*?)</tr>", re.S)
CELL = re.compile(r"<td[^>]*>(.*?)</td>", re.S)
FACT = re.compile(r"<div><dt>([^<]*)</dt><dd>(.*?)</dd></div>", re.S)


def words(markup: str) -> str:
    """What a reader sees in a piece of markup: the tags gone, the entities decoded, the spaces collapsed."""
    return " ".join(html.unescape(TAGS.sub(" ", markup)).split())


def body_rows(markup: str) -> list[list[str]]:
    """The cells of every table row in ``markup`` that has cells, as words. A header row has none."""
    return [[words(cell) for cell in CELL.findall(row)] for row in ROW.findall(markup) if "<td" in row]


def facts(page: str) -> defaultdict[str, str]:
    """The name and value of each fact on an advisory page, as words. A fact the page lacks reads as empty."""
    return defaultdict(str, {name: words(value) for name, value in FACT.findall(page)})


def section(page: str, heading: str) -> str:
    """The markup after ``<h2>heading</h2>``, or nothing when the page has no such section."""
    return page.partition(f"<h2>{heading}</h2>")[2]


def alert_table(page: str) -> str:
    """The seen identifiers of /alerts. "Recent notifications" below them is a second table of the same markup."""
    return page.partition("<h2>Recent notifications</h2>")[0]


def events(markup: str) -> list[list[str]]:
    """The delivery events a section lists: kind, outcome, tag, identifiers, accepted by and source id."""
    return [row[1:] for row in body_rows(markup)]


def link_to(page: str, identifier: str) -> str:
    """The link the page renders for ``identifier``: what an operator clicks, not a token the test computes."""
    found = re.findall(rf"<a href='(/advisories/[^']*)'>{re.escape(identifier)}</a>", page)
    assert found, f"the page links no advisory for {identifier}"
    return found[0]


# --- the configured source id ------------------------------------------------------------------


def test_the_configured_source_id_filters_the_delivered_alerts(operator):
    page = operator.get("/alerts", params={"source": SOURCE_ID}).text
    assert sorted(page_ids(alert_table(page))) == [CVE_A, GHSA_A]
    # The id is what the filter addresses: another id, or the advisory heading the pass also recorded, selects nothing.
    for wrong in ("other-feed", HEADING_A):
        selected = page_ids(alert_table(operator.get("/alerts", params={"source": wrong}).text))
        assert selected == [], f"source={wrong!r} selected {selected}"


def test_a_parked_message_keeps_the_configured_source_id(operator):
    page = operator.get("/inbox", params={"state": "parked", "source": SOURCE_ID}).text
    assert INBOX_ROW_RE.findall(page) == [CVE_B]
    # The advisory carries the id too: it is on the record, not only in the filter. The link comes from the
    # unfiltered list, so this check does not depend on the one above.
    parked = operator.get("/inbox", params={"state": "parked"}).text
    assert facts(operator.get(link_to(parked, CVE_B)).text)["Source id"] == SOURCE_ID


# --- the alias ---------------------------------------------------------------------------------


def test_an_alias_recorded_by_the_pass_is_found_by_text(operator):
    page = operator.get("/alerts", params={"q": GHSA_A}).text
    assert page_ids(alert_table(page)) == [GHSA_A]


def test_the_alias_opens_an_advisory_that_names_both_identifiers(operator):
    page = operator.get("/alerts", params={"q": GHSA_A}).text
    advisory = operator.get(link_to(page, GHSA_A))
    assert advisory.status_code == 200
    assert sorted(facts(advisory.text)["Identifiers"].split(", ")) == [CVE_A, GHSA_A]


# --- a warning, then its escalation ------------------------------------------------------------


def test_an_escalation_is_kept_beside_the_first_event(operator):
    escalation = ["escalation", "delivered", "critical", CVE_A, CHANNEL, NO_VALUE]
    page = operator.get("/alerts", params={"q": CVE_A}).text
    advisory = operator.get(link_to(page, CVE_A)).text
    # The first event is still what the advisory's own record says: the escalation did not overwrite it.
    first = facts(advisory)
    assert (first["Tag"], first["Message kind"], first["Source id"]) == ("warning", "new", SOURCE_ID)
    # The escalation is a second event, listed beside it on the advisory page and in the general history.
    assert events(section(advisory, "Notifications")) == [escalation]
    assert events(section(page, "Recent notifications")) == [escalation]
    # The inbox row carries the new level and still remembers the warning.
    inbox = body_rows(operator.get("/inbox", params={"q": CVE_A}).text)
    assert [(row[1].split()[0], row[2]) for row in inbox] == [("delivered", "critical")]
    assert "Also: delivered warning" in inbox[0][0]


# --- delivered and parked ----------------------------------------------------------------------


def test_a_delivered_advisory_renders_as_delivered(operator):
    alerts = operator.get("/alerts", params={"outcome": "delivered"}).text
    assert sorted(page_ids(alert_table(alerts))) == [CVE_A, GHSA_A]
    inbox = body_rows(operator.get("/inbox", params={"state": "delivered"}).text)
    states = {row[0].split()[0]: row[1].split()[0] for row in inbox}
    assert states == {CVE_A: "delivered", GHSA_A: "delivered"}


def test_a_message_the_channel_kept_refusing_is_parked(operator):
    parked = body_rows(operator.get("/parked").text)
    assert [(row[0], row[2]) for row in parked] == [("warning", CVE_B)]
    assert HEADING_B in parked[0][1]
    inbox = operator.get("/inbox", params={"state": "parked"}).text
    assert [(row[0].split()[0], row[1].split()[0]) for row in body_rows(inbox)] == [(CVE_B, "parked")]
    shown = facts(operator.get(link_to(inbox, CVE_B)).text)
    assert (shown["State"], shown["Delivery attempts"]) == ("parked", "3 (last HTTP 503)")
    # A refused message is owed, not delivered: it is no alert yet.
    assert CVE_B not in page_ids(alert_table(operator.get("/alerts").text))
