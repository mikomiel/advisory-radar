"""The CSAF source: a bounded, resumable read of one provider directory, and what it reports when it cannot read.

The provider is a fake HTTP server over a dict, so every assertion is about the requests made and the items
returned. The documents are the synthetic ones of ``test_csaf``. Their dates are relative to one clock, the
pass clock, so the first-run rule of the pipeline (history is not news) never decides a test by accident.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from advisory_radar import core, csaf, pipeline
from advisory_radar.config import load_config
from advisory_radar.plugins import SourceWindow
from advisory_radar.sources import CsafSource, RssSource, build_source
from test_csaf import PUBLISHER, advisory, body, epoch, index, redhat_style, vulnerability
from test_pipeline import FEED, FakeNotifier, fake_http, make_policy

CLOCK = 1792600000
HOUR = 3600
DAY = 24 * HOUR
YEAR = 365 * DAY
BASE = "https://vendor.example.net/csaf/advisories/"


class Clock:
    """A clock the test moves: the wall clock of a source, or the monotonic clock it times a pass with."""

    def __init__(self, now: float = float(CLOCK)) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def stamp(age: int) -> str:
    """The instant ``age`` seconds before the clock, spelled the way a provider spells it."""
    return datetime.fromtimestamp(CLOCK - age, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def path_of(number: int) -> str:
    return f"2026/example-2026_{number:04d}.json"


def ident_of(number: int) -> str:
    return f"EXAMPLE-2026:{number:04d}"


def guid_of(number: int, **statuses: list[str]) -> str:
    """The identity of document ``number``: its id, and the revision, a digest of the statements it carries.

    With no argument the statements are the ones ``Provider.publish`` writes by default.
    """
    statuses = statuses or {"fixed": ["WIDGET-2:widget-lib-1.2"]}
    document = advisory(ident_of(number), vulnerabilities=[vulnerability("CVE-2026-0001", **statuses)])
    return f"{ident_of(number)}@{csaf.parse_document(body(document)).revision}"


class Provider:
    """A CSAF directory behind the HTTP seam: ``changes.csv``, the documents it lists, and a log of requests."""

    def __init__(self, base: str = BASE, *, stopwatch: Clock | None = None, latency: float = 0.0) -> None:
        self.base = base
        #: Every request takes ``latency`` seconds of the stopwatch, the time a slow provider costs a pass.
        self.stopwatch = stopwatch
        self.latency = latency
        #: path -> the instant the index lists it at; the index keeps one row per path, as the real ones do.
        self.rows: dict[str, str] = {}
        #: path -> the body served, or an HTTP status (0 is a network error) to answer instead.
        self.files: dict[str, bytes | int] = {}
        #: Replaces the whole index answer when set.
        self.index_answer: bytes | int | None = None
        self.requests: list[str] = []

    def publish(
        self,
        number: int,
        age: int,
        *,
        version: str = "1",
        url: str | None = None,
        vulnerabilities: list[dict] | None = None,
        cve: str = "CVE-2026-0001",
        **statuses: list[str],
    ) -> str:
        """Write document ``number`` (a new revision when it exists) and list it at ``age`` seconds ago."""
        if vulnerabilities is None:
            vulnerabilities = [vulnerability(cve, **(statuses or {"fixed": ["WIDGET-2:widget-lib-1.2"]}))]
        document = advisory(
            ident_of(number), version=version, released=stamp(age), vulnerabilities=vulnerabilities, url=url
        )
        self.files[path_of(number)] = body(document)
        self.rows[path_of(number)] = stamp(age)
        return path_of(number)

    def publish_regenerated(
        self,
        number: int,
        *,
        initial: int,
        updated: int,
        generated: int,
        middle: str = "Last updated version",
        vulnerabilities: list[dict] | None = None,
        cve: str = "CVE-2026-0001",
        **statuses: list[str],
    ) -> str:
        """Write document ``number`` the way the first provider does: dated by content, listed when regenerated.

        The three ages are seconds before the clock: when the advisory was first published, when its content last
        changed, and when the provider regenerated the file, which is the instant the index lists it at. Writing the
        same statements again with a later ``generated`` is a regeneration; a later ``updated`` is a real revision.
        """
        if vulnerabilities is None:
            vulnerabilities = [vulnerability(cve, **(statuses or {"fixed": ["WIDGET-2:widget-lib-1.2"]}))]
        document = advisory(ident_of(number), vulnerabilities=vulnerabilities)
        redhat_style(
            document, initial=stamp(initial), updated=stamp(updated), generated=stamp(generated), middle=middle
        )
        self.files[path_of(number)] = body(document)
        self.rows[path_of(number)] = stamp(generated)
        return path_of(number)

    def documents_read(self) -> list[str]:
        """The documents requested since the log was last cleared, as the index names them."""
        return [url.removeprefix(self.base) for url in self.requests if not url.endswith("/changes.csv")]

    def __call__(self, method, url, headers, payload):
        assert method == "GET", "a provider directory is only ever read"
        self.requests.append(url)
        if self.stopwatch is not None:
            self.stopwatch.advance(self.latency)
        if url == self.base + "changes.csv":
            answer = self.index_answer
            if answer is None:
                answer = index(*sorted(self.rows.items(), key=lambda row: row[1], reverse=True))
        elif url.startswith(self.base):
            answer = self.files.get(url.removeprefix(self.base), 404)
        else:
            raise AssertionError(f"the source asked for {url}, which is outside its directory")
        if isinstance(answer, int):
            return answer, {}, b""
        return 200, {}, answer


def break_title(provider: Provider, number: int) -> None:
    """Make a document fail the schema: the first thing a provider's own change would do."""
    document = json.loads(provider.files[path_of(number)])
    del document["document"]["title"]
    provider.files[path_of(number)] = body(document)


def make_source(provider: Provider | None = None, **kwargs) -> CsafSource:
    return CsafSource("vendor", provider.base if provider else BASE, clock=lambda: float(CLOCK), **kwargs)


def read(source: CsafSource, provider: Provider, state: dict) -> SourceWindow:
    """One pass as the pipeline runs it: fetch, then commit once the window is classified."""
    provider.requests.clear()
    window = source.fetch(provider, state)
    source.commit(state)
    return window


def guids(window: SourceWindow) -> list[str]:
    return [item.guid for item in window.items]


# --------------------------------------------------------------------------
# Bounded, resumable reads


def test_a_new_source_reads_only_the_newest_documents_and_then_resumes(monkeypatch):
    monkeypatch.setattr(csaf, "START_DOCUMENTS", 3)
    provider, source, state = Provider(), make_source(), {}
    for number, age in enumerate((500, 400, 300, 200, 100), start=1):
        provider.publish(number, age)
    first = read(source, provider, state)
    assert provider.documents_read() == [path_of(3), path_of(4), path_of(5)], "the newest three, oldest first"
    assert guids(first) == [guid_of(3), guid_of(4), guid_of(5)]
    assert first.host == "vendor.example.net"
    assert first.truncated is False, "the cursor catches up; a window that claims truncation would be a gap alarm"
    assert first.problems == ()
    json.dumps(state)  # what the source keeps is part of the state document
    assert BASE not in json.dumps(state), "the directory URL is configuration and may be private"

    again = read(source, provider, state)
    assert provider.requests == [BASE + "changes.csv"], "a source with nothing new reads the index and nothing else"
    assert again.items == ()


def test_a_revision_that_changes_a_statement_is_a_new_item_and_one_that_does_not_is_the_same_item():
    provider, source, state = Provider(), make_source(), {}
    provider.publish(1, 300)
    first = read(source, provider, state)
    provider.publish(1, 200, version="2")  # a new revision of the document that says the same
    same = read(source, provider, state)
    provider.publish(1, 100, version="3", known_affected=["WIDGET-2"])  # one that says something else
    changed = read(source, provider, state)
    assert provider.documents_read() == [path_of(1)], "a revised document is listed again, and read again"
    assert guids(first) == guids(same) == [guid_of(1)]
    assert guids(changed) == [guid_of(1, known_affected=["WIDGET-2"])]
    assert guids(changed) != guids(first)
    (item,) = changed.items
    assert dict(item.text_fields)["id"] == ident_of(1), "the identity is the document's; a revision is a version of it"
    assert "revision 3 of EXAMPLE-2026:0001" in item.summary, "the version is the vendor's word and is shown as written"
    assert read(source, provider, state).items == (), "a revision is read once"


def test_an_old_advisory_the_provider_regenerates_is_the_same_item_dated_by_its_content():
    # The first provider rewrites a document, and lists it again, whenever its generator runs. Nothing in the file
    # that the generator touches says the content changed: the version stays 3 and the release date is the run.
    provider, source, state = Provider(), make_source(), {}
    old = {"initial": 5 * YEAR, "updated": 5 * YEAR}
    provider.publish_regenerated(1, generated=7200, **old)
    first = read(source, provider, state)
    provider.publish_regenerated(1, generated=60, **old)
    again = read(source, provider, state)
    assert provider.documents_read() == [path_of(1)], "a regenerated document is read: only its content says it is old"
    assert guids(first) == guids(again) == [guid_of(1)], "the same statements are the same item"
    assert first.items[0].published == again.items[0].published == CLOCK - 5 * YEAR
    assert again.items[0].published != CLOCK - 60, "the regeneration is not the date of the advisory"


def test_a_real_revision_of_a_regenerated_document_is_a_new_item_dated_by_the_revision():
    provider, source, state = Provider(), make_source(), {}
    provider.publish_regenerated(1, initial=5 * YEAR, updated=5 * YEAR, generated=7200)
    (first,) = read(source, provider, state).items
    provider.publish_regenerated(
        1, initial=5 * YEAR, updated=1800, generated=60, cve="CVE-2026-0002", known_affected=["GIZMO-1"]
    )
    (revised,) = read(source, provider, state).items
    assert revised.guid != first.guid
    assert revised.published == CLOCK - 1800, "the date the vendor changed it, not the date the file was written"
    assert revised.explicit == ("CVE-2026-0002",)


def test_catching_up_is_bounded_per_pass_and_never_skips_a_document(monkeypatch):
    monkeypatch.setattr(csaf, "MAX_DOCUMENTS", 3)
    provider, source, state = Provider(), make_source(), {}
    provider.publish(0, 1000)
    read(source, provider, state)  # the source starts here
    for number in range(1, 8):
        provider.publish(number, 1000 - number * 100)
    delivered: list[str] = []
    for expected in ([1, 2, 3], [4, 5, 6], [7], []):
        window = read(source, provider, state)
        assert provider.documents_read() == [path_of(number) for number in expected]
        delivered += guids(window)
    assert delivered == [guid_of(number) for number in range(1, 8)]


def test_a_source_that_is_behind_by_more_than_the_limit_says_so_until_it_has_caught_up(monkeypatch):
    # A pass reads a bounded number of documents, so a source can be behind. What it has not reached is not lost,
    # but a source whose news is hours late is not a healthy one, and the operator is told while it is.
    monkeypatch.setattr(csaf, "MAX_DOCUMENTS", 2)
    provider, source, state = Provider(), make_source(), {}
    for number in range(1, 7):  # six documents, all listed 13 hours ago
        provider.publish(number, 13 * HOUR + 7 - number)
    delivered: list[str] = []
    for read_now, unread in (([1, 2], 4), ([3, 4], 2), ([5, 6], 0)):
        window = read(source, provider, state)
        assert provider.documents_read() == [path_of(number) for number in read_now]
        delivered += guids(window)
        if unread:
            assert window.problems == (f"behind: {unread} listed document(s) not read yet, the oldest listed 13 h ago",)
        else:
            assert window.problems == (), "a source that has caught up reports nothing"
    assert delivered == [guid_of(number) for number in range(1, 7)], "being behind skips nothing"


def test_a_source_that_is_behind_by_less_than_the_limit_is_not_a_problem(monkeypatch):
    monkeypatch.setattr(csaf, "MAX_DOCUMENTS", 2)
    provider, source, state = Provider(), make_source(), {}
    for number in range(1, 7):
        provider.publish(number, HOUR + 7 - number)
    window = read(source, provider, state)
    assert len(window.items) == 2 and window.problems == (), "two pass intervals are not a fault"


def test_the_lag_is_counted_from_the_oldest_row_that_is_still_unread(monkeypatch):
    # The newest rows may be minutes old while the oldest unread one is days old: the age that matters is the oldest.
    monkeypatch.setattr(csaf, "MAX_DOCUMENTS", 1)
    provider, source, state = Provider(), make_source(), {}
    provider.publish(1, 3 * DAY + 10)
    provider.publish(2, 3 * DAY + 9)
    provider.publish(3, 60)
    (problem,) = read(source, provider, state).problems
    assert problem == "behind: 2 listed document(s) not read yet, the oldest listed 3 d ago"


def test_a_document_that_is_being_retried_is_not_hidden_by_the_lag_report():
    provider, source, state = Provider(), make_source(), {}
    provider.publish(1, 13 * HOUR)
    break_title(provider, 1)
    window = read(source, provider, state)
    assert len(window.problems) == 2
    assert window.problems[0].startswith("behind: 1 listed document(s) not read yet")
    assert path_of(1) in window.problems[1] and "attempt 1 of 3" in window.problems[1]


def test_the_lag_limit_keeps_what_a_late_pass_reads_out_of_history():
    # A source that is red keeps the instant of its last success, and ``core`` counts an item as news when it was
    # dated after that instant less BACKLOG_OUTAGE_SLACK. The oldest unread row was listed at most LAG_LIMIT before
    # the last green pass, and the vendor dated the document a little before it listed it: the two must fit in the
    # slack, so the limit may not be more than half of it. Lengthen one and the other has to be reconsidered.
    assert csaf.LAG_LIMIT * 2 <= core.BACKLOG_OUTAGE_SLACK


def test_a_pass_that_runs_out_of_time_stops_and_the_next_pass_resumes(monkeypatch):
    # The budget is the time of the whole pass, the index request included, so a slow provider cannot hold the
    # pass for a minute per document. What is not reached is read by the next pass, in order.
    monkeypatch.setattr(csaf, "PASS_SECONDS", 120)
    watch = Clock(1000.0)
    provider, state = Provider(stopwatch=watch, latency=50), {}
    source = make_source(monotonic=watch)
    for number in range(1, 6):
        provider.publish(number, HOUR - number)
    delivered: list[str] = []
    for expected in ([1, 2], [3, 4], [5], []):  # index 50 s, then 50 s a document: the check after 150 s stops it
        window = read(source, provider, state)
        assert provider.documents_read() == [path_of(number) for number in expected]
        delivered += guids(window)
    assert delivered == [guid_of(number) for number in range(1, 6)]


def test_a_pass_reads_at_least_one_document_however_slow_the_provider_is(monkeypatch):
    # An answer may take longer than a whole pass is allowed to (the transport allows two minutes for one). A pass
    # that gave up before the first document would make no progress, ever.
    monkeypatch.setattr(csaf, "PASS_SECONDS", 120)
    watch = Clock(1000.0)
    provider, state = Provider(stopwatch=watch, latency=300), {}
    source = make_source(monotonic=watch)
    for number in range(1, 4):
        provider.publish(number, HOUR - number)
    for number in range(1, 4):
        window = read(source, provider, state)
        assert provider.documents_read() == [path_of(number)]
        assert guids(window) == [guid_of(number)]


def test_rows_that_share_one_second_are_neither_skipped_nor_repeated(monkeypatch):
    monkeypatch.setattr(csaf, "MAX_DOCUMENTS", 1)
    provider, source, state = Provider(), make_source(), {}
    provider.publish(0, 1000)
    read(source, provider, state)
    provider.publish(1, 500)
    provider.publish(2, 500)
    provider.publish(3, 400)
    order: list[str] = []
    for _ in range(4):
        read(source, provider, state)
        order += provider.documents_read()
    assert order == [path_of(1), path_of(2), path_of(3)]


def test_a_row_that_arrives_late_in_a_second_already_read_is_still_read(monkeypatch):
    provider, source, state = Provider(), make_source(), {}
    provider.publish(5, 500)
    read(source, provider, state)
    provider.publish(4, 500)  # the same second, and it sorts before the document already read
    window = read(source, provider, state)
    assert guids(window) == [guid_of(4)]
    assert read(source, provider, state).items == ()


def listed_at(provider: Provider, number: int, age: int, fraction: str) -> None:
    """List document ``number`` at ``age`` seconds ago and ``fraction`` of the next: an index that times rows finer."""
    provider.rows[path_of(number)] = stamp(age).replace("Z", f".{fraction}Z")


@pytest.mark.parametrize(
    ("first", "second"), [("100", "900"), ("123456788", "123456789")], ids=["milliseconds", "ninth-digit"]
)
def test_a_revision_listed_within_the_second_its_predecessor_was_read_in_is_read_again(first, second):
    # An index may time its rows to a fraction of a second, and the vendor can revise a document within one. The
    # revision is listed under the same whole second, so a cursor that kept whole seconds would find the path read
    # already and never fetch it. The nanosecond is the finest a date-time of the index can say.
    provider, source, state = Provider(), make_source(), {}
    provider.publish(1, 300)
    listed_at(provider, 1, 300, first)
    assert guids(read(source, provider, state)) == [guid_of(1)]
    provider.publish(1, 300, version="2", known_affected=["WIDGET-2"])  # a revision that says something else
    listed_at(provider, 1, 300, second)
    revised = read(source, provider, state)
    assert provider.documents_read() == [path_of(1)], "the revision is fetched"
    assert guids(revised) == [guid_of(1, known_affected=["WIDGET-2"])]
    assert read(source, provider, state).items == (), "and once"
    assert provider.documents_read() == []


def test_a_row_that_arrives_late_in_a_second_already_read_is_read_whatever_its_fraction():
    # The guarantee of a second already read holds for an index finer than a second: the late row is listed within
    # the second, at an earlier fraction than the document the cursor passed.
    provider, source, state = Provider(), make_source(), {}
    provider.publish(5, 500)
    listed_at(provider, 5, 500, "900")
    read(source, provider, state)
    provider.publish(4, 500)
    listed_at(provider, 4, 500, "100")
    assert guids(read(source, provider, state)) == [guid_of(4)]
    assert read(source, provider, state).items == ()


def test_rows_that_differ_only_in_their_fraction_are_read_in_the_order_they_were_listed(monkeypatch):
    monkeypatch.setattr(csaf, "MAX_DOCUMENTS", 1)
    provider, source, state = Provider(), make_source(), {}
    provider.publish(0, 1000)
    read(source, provider, state)
    for number, fraction in ((1, "300"), (2, "100"), (3, "200")):  # paths sort the other way round
        provider.publish(number, 500)
        listed_at(provider, number, 500, fraction)
    order: list[str] = []
    for _ in range(4):
        read(source, provider, state)
        order += provider.documents_read()
    assert order == [path_of(2), path_of(3), path_of(1)]


def test_a_revision_in_the_same_second_as_a_failing_one_has_its_attempts_to_itself():
    # What identifies a failing document is the revision the index lists, not the path and the whole second.
    provider, source, state = Provider(), make_source(), {}
    provider.publish(1, 300)
    break_title(provider, 1)
    listed_at(provider, 1, 300, "100")
    for attempt in (1, 2):
        (problem,) = read(source, provider, state).problems
        assert f"attempt {attempt} of 3" in problem
    listed_at(provider, 1, 300, "900")  # the vendor lists it again, and it still fails
    (problem,) = read(source, provider, state).problems
    assert "attempt 1 of 3" in problem, "a document listed anew is a new revision, not a third read of the old one"
    assert "@" not in problem, "what the operator reads names the document, not how the cursor remembers it"


def test_a_fractional_row_that_keeps_failing_is_given_up_and_its_relisting_in_that_second_is_read():
    # The attempts, the cursor and the report of a failing document reach the next pass through the state file
    # whatever fraction its row was listed at; a document listed again within that second is a revision to read.
    provider, state = Provider(), {}
    provider.publish(1, 300)
    break_title(provider, 1)
    listed_at(provider, 1, 300, "100")
    for attempt in range(1, csaf.MAX_ATTEMPTS):
        window = read(make_source(), provider, state)
        assert provider.documents_read() == [path_of(1)]
        assert f"attempt {attempt} of 3" in window.problems[0]
        state = json.loads(json.dumps(state))
    given_up = read(make_source(), provider, state)
    assert provider.documents_read() == [path_of(1)]
    assert "given up" in given_up.problems[0]
    state = json.loads(json.dumps(state))
    assert read(make_source(), provider, state).problems == given_up.problems, "a document given up on stays reported"
    assert provider.documents_read() == [], "and is not read again"
    provider.publish(1, 300, version="2")  # the vendor corrects it, and the index lists it within the same second
    listed_at(provider, 1, 300, "900")
    corrected = read(make_source(), provider, state)
    assert provider.documents_read() == [path_of(1)]
    assert guids(corrected) == [guid_of(1)]
    assert corrected.problems == ()


def test_a_cursor_stored_before_fractions_were_kept_still_loads():
    # What an index in whole seconds leaves in the state is what it has always been: whole seconds and bare paths.
    provider, state = Provider(), {}
    provider.publish(1, 300)
    provider.publish(2, 200)
    read(make_source(), provider, state)
    digest = state["csaf"]["vendor"]["dir"]
    stored = {"csaf": {"vendor": {"dir": digest, "release": CLOCK - 200, "at": [path_of(2)]}}}
    assert state == stored
    provider.publish(3, 100)
    window = read(make_source(), provider, json.loads(json.dumps(stored)))
    assert provider.documents_read() == [path_of(3)], "what the old cursor passed is not read again"
    assert guids(window) == [guid_of(3)]


def test_a_stored_bare_path_cannot_vouch_for_a_listing_with_a_fraction():
    # A cursor stored by an earlier version holds paths without the fraction their row was listed at. When the index
    # lists such a document at the cursor's second with a fraction, the stored path does not say which listing it
    # was: the document is read once more rather than skipped, and the cursor then remembers the listing.
    provider, state = Provider(), {}
    provider.publish(1, 100)
    read(make_source(), provider, state)
    digest = state["csaf"]["vendor"]["dir"]
    stored = {"csaf": {"vendor": {"dir": digest, "release": CLOCK - 100, "at": [path_of(1)]}}}
    listed_at(provider, 1, 100, "500")
    assert guids(read(make_source(), provider, stored)) == [guid_of(1)]
    assert read(make_source(), provider, stored).items == ()
    assert provider.documents_read() == []


def test_the_directory_url_may_omit_its_trailing_slash():
    provider = Provider()
    provider.publish(1, 300)
    window = read(CsafSource("vendor", BASE.rstrip("/"), clock=lambda: float(CLOCK)), provider, {})
    assert guids(window) == [guid_of(1)]


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pw@vendor.example.net/csaf/",
        "https://vendor.example.net/csaf/?token=abc",
        "https://vendor.example.net/csaf/#frag",
        "ftp://vendor.example.net/csaf/",
        "vendor.example.net/csaf/",
        "",
    ],
)
def test_a_directory_url_that_could_leak_or_cannot_be_fetched_is_refused(url):
    # The document URL is shown to the reader as the provenance of an alert, so the directory URL may not carry a
    # credential, and a scheme the transport refuses would only ever fail later and less clearly.
    with pytest.raises(ValueError, match="csaf"):
        CsafSource("vendor", url)


def test_the_source_is_built_from_its_catalogue_entry():
    source = build_source({"id": "vendor", "type": "csaf", "url": BASE}, {})
    assert isinstance(source, CsafSource)
    assert (source.id, source.kind) == ("vendor", "csaf")


def test_a_cursor_belongs_to_the_directory_that_issued_it():
    first, second = Provider(), Provider("https://other.example.net/csaf/")
    first.publish(1, 300)
    second.publish(1, 300)
    state: dict = {}
    read(make_source(first), first, state)
    window = read(make_source(second), second, state)
    assert second.documents_read() == [path_of(1)], "repointing a source id at another directory starts it over"
    assert guids(window) == [guid_of(1)]


# --------------------------------------------------------------------------
# What is emitted: vendor statements, not matches


def test_a_document_that_only_says_not_affected_makes_no_item_and_is_not_read_again():
    provider, source, state = Provider(), make_source(), {}
    provider.publish(1, 300, known_not_affected=["GIZMO-1"])
    window = read(source, provider, state)
    assert window.items == () and window.problems == ()
    assert provider.documents_read() == [path_of(1)]
    read(source, provider, state)
    assert provider.documents_read() == []


def test_only_the_vulnerabilities_a_document_concerns_are_claimed():
    provider, source = Provider(), make_source()
    provider.publish(
        1,
        300,
        vulnerabilities=[
            vulnerability("CVE-2026-0001", known_not_affected=["GIZMO-1"]),
            vulnerability("CVE-2026-0002", known_affected=["GIZMO-1"], known_not_affected=["WIDGET-2"]),
        ],
    )
    (item,) = read(source, provider, {}).items
    assert item.explicit == ("CVE-2026-0002",), "a not-affected statement must not claim its vulnerability"


def test_an_item_keeps_its_provenance_and_says_the_words_are_the_vendors():
    provider, source = Provider(), make_source()
    provider.publish(1, 300, fixed=["WIDGET-2:widget-lib-1.2"], known_not_affected=["GIZMO-1"])
    (item,) = read(source, provider, {}).items
    assert item.guid == guid_of(1, fixed=["WIDGET-2:widget-lib-1.2"], known_not_affected=["GIZMO-1"])
    assert item.title == "Example Vendor Security Advisory: widget update"
    assert item.source_title == PUBLISHER
    assert item.source_url == BASE + path_of(1), "the exact document read"
    assert item.link == BASE + path_of(1), "a document that names no page of its own is linked as itself"
    assert item.published == epoch(stamp(300))
    assert item.explicit == ("CVE-2026-0001",)
    statements = "CVE-2026-0001: fixed: Widget 2.0 (1); known_not_affected (1)"
    assert item.summary_key == "item.summary.csaf"
    assert dict(item.text_fields) == {"version": "1", "id": ident_of(1), "statements": statements}
    assert item.summary == (
        "Vendor statements, revision 1 of EXAMPLE-2026:0001; not a check of your installed versions. " + statements
    )
    assert "Gizmo" not in item.title + item.summary, "a product the vendor says is not affected is never named"


def test_the_link_is_the_documents_own_page_when_it_names_one():
    provider, source = Provider(), make_source()
    page = "https://vendor.example.net/advisories/EXAMPLE-2026-0001"
    provider.publish(1, 300, url=page)
    (item,) = read(source, provider, {}).items
    assert item.link == page
    assert item.source_url == BASE + path_of(1), "the provenance stays the document that was read"


# --------------------------------------------------------------------------
# Failures are visible, never a silent empty window


@pytest.mark.parametrize(("answer", "message"), [(0, "unreachable"), (404, "HTTP 404"), (500, "HTTP 500")])
def test_an_index_that_cannot_be_read_is_a_failure_and_commits_nothing(answer, message):
    provider, source, state = Provider(), make_source(), {}
    provider.publish(1, 300)
    provider.index_answer = answer
    with pytest.raises(csaf.CsafError, match=message):
        source.fetch(provider, state)
    source.commit(state)  # the pipeline commits a failed unit too
    assert state == {}


@pytest.mark.parametrize(
    "answer", [b"", b'"2026/a.json"\n', b"<html>maintenance</html>"], ids=["empty", "one-column", "html"]
)
def test_an_empty_or_malformed_index_is_a_failure_and_not_an_empty_window(answer):
    provider = Provider()
    provider.index_answer = answer
    with pytest.raises(csaf.CsafError, match="changes.csv"):
        make_source().fetch(provider, {})


def test_a_window_that_was_never_committed_is_not_committed_by_a_later_failure():
    provider, source, state = Provider(), make_source(), {}
    provider.publish(1, 300)
    source.fetch(provider, state)  # fetched, never classified: no commit
    provider.index_answer = 500
    with pytest.raises(csaf.CsafError):
        source.fetch(provider, state)
    source.commit(state)
    assert state == {}


def test_a_document_that_fails_is_retried_then_given_up_and_stays_visible():
    provider, source, state = Provider(), make_source(), {}
    provider.publish(1, 300)
    provider.publish(2, 200)
    break_title(provider, 2)
    provider.publish(3, 100)

    first = read(source, provider, state)
    assert guids(first) == [guid_of(1)], "the good document before the bad one is delivered"
    assert provider.documents_read() == [path_of(1), path_of(2)], "the pass stops at the bad document"
    (problem,) = first.problems
    assert path_of(2) in problem and "schema" in problem and "attempt 1 of 3" in problem

    second = read(source, provider, state)
    assert provider.documents_read() == [path_of(2)]
    assert second.items == () and "attempt 2 of 3" in second.problems[0]

    third = read(source, provider, state)
    assert provider.documents_read() == [path_of(2), path_of(3)], "the third failure gives up and the pass goes on"
    assert guids(third) == [guid_of(3)]
    (given_up,) = third.problems
    assert path_of(2) in given_up and "given up" in given_up

    later = read(source, provider, state)
    assert provider.documents_read() == [] and later.items == ()
    assert later.problems == third.problems, "a document given up on stays reported until it is replaced"

    provider.publish(2, 50, version="2")  # the vendor corrects it: a new revision of the same document
    corrected = read(source, provider, state)
    assert guids(corrected) == [guid_of(2)]
    assert corrected.problems == ()
    assert read(source, provider, state).problems == ()


def test_a_given_up_problem_is_forgotten_after_its_retention():
    now = [float(CLOCK)]
    provider, state = Provider(), {}
    source = CsafSource("vendor", BASE, clock=lambda: now[0])
    provider.publish(1, 300)
    break_title(provider, 1)
    for _ in range(csaf.MAX_ATTEMPTS):
        window = read(source, provider, state)
    assert "given up" in window.problems[0]
    now[0] += csaf.PROBLEM_RETENTION - 1
    assert read(source, provider, state).problems, "still reported just before the retention ends"
    now[0] += 2
    assert read(source, provider, state).problems == ()


@pytest.mark.parametrize(("answer", "message"), [(404, "HTTP 404"), (500, "HTTP 500"), (0, "unreachable")])
def test_a_document_that_cannot_be_downloaded_is_a_problem_and_not_a_gap(answer, message):
    provider, source = Provider(), make_source()
    provider.publish(1, 300)
    provider.files[path_of(1)] = answer
    window = read(source, provider, {})
    assert window.items == ()
    (problem,) = window.problems
    assert path_of(1) in problem and message in problem and "attempt 1 of 3" in problem


def test_a_document_that_fails_once_is_delivered_when_it_recovers():
    provider, source, state = Provider(), make_source(), {}
    provider.publish(1, 300)
    good = provider.files[path_of(1)]
    provider.files[path_of(1)] = 500
    assert read(source, provider, state).problems
    provider.files[path_of(1)] = good
    recovered = read(source, provider, state)
    assert guids(recovered) == [guid_of(1)] and recovered.problems == ()
    assert read(source, provider, state).items == ()


def test_a_document_larger_than_the_cap_is_a_problem(monkeypatch):
    monkeypatch.setattr(csaf, "MAX_DOCUMENT_BYTES", 100)
    provider = Provider()
    provider.publish(1, 300)
    (problem,) = read(make_source(), provider, {}).problems
    assert "larger than" in problem


def test_more_given_up_documents_than_are_listed_are_counted(monkeypatch):
    monkeypatch.setattr(csaf, "MAX_ATTEMPTS", 1)
    provider, source, state = Provider(), make_source(), {}
    for number in range(1, 9):
        provider.publish(number, 900 - number)
        break_title(provider, number)
    window = read(source, provider, state)
    assert len(window.problems) == csaf.MAX_LISTED_PROBLEMS + 1
    assert window.problems[-1] == f"{8 - csaf.MAX_LISTED_PROBLEMS} more document(s) given up"


JUNK = [None, "x", 7, -1, True, 2.5, [], {}, ["a", 1], {"a": 1}]


@pytest.mark.parametrize("junk", JUNK, ids=repr)
def test_a_damaged_record_never_stops_the_source(junk):
    provider, state = Provider(), {}
    provider.publish(1, 300)
    provider.publish(2, 200)
    break_title(provider, 2)
    read(make_source(), provider, state)  # leaves a cursor and a pending retry
    record = state["csaf"]["vendor"]
    assert record
    for key in list(record):
        damaged = json.loads(json.dumps(state))
        damaged["csaf"]["vendor"][key] = junk
        window = read(make_source(), provider, damaged)
        assert isinstance(window.items, tuple) and isinstance(window.problems, tuple)
        json.dumps(damaged)
    for damaged in ({"csaf": junk}, {"csaf": {"vendor": junk}}):
        assert isinstance(read(make_source(), provider, damaged).items, tuple)


# --------------------------------------------------------------------------
# State ownership


def test_removing_a_csaf_source_drops_its_cursor_and_disabling_it_keeps_it():
    provider, state = Provider(), {}
    provider.publish(1, 300)
    read(make_source(), provider, state)
    kept = json.loads(json.dumps(state))
    pipeline._drop_removed_sources(kept, {"vendor"}, set(), complete=True)  # declared, but not enabled
    assert "vendor" in kept["csaf"]
    pipeline._drop_removed_sources(state, set(), set(), complete=True)  # no longer declared at all
    assert "vendor" not in state["csaf"]


# --------------------------------------------------------------------------
# Through a pass


def csaf_config(tmp_path: Path, *, with_feed: bool = False):
    """A configuration that declares the CSAF source (and the RSS one), so a pass keeps their stored work."""
    make_policy(tmp_path)
    declared = "  - id: vendor-csaf\n    type: csaf\n    url: https://vendor.example.net/csaf/advisories/\n"
    if with_feed:
        declared += "  - id: test\n    type: rss\n    url: https://feeds.example.com/rss\n"
    path = tmp_path / "config.yml"
    path.write_text(
        f"sources:\n{declared}"
        "notifiers:\n  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
        f"state_path: {tmp_path}/state.json\n"
        f"watchlist: {tmp_path}/watchlist.json\n"
    )
    return load_config(path, {})


def csaf_source(clock: Clock | None = None) -> CsafSource:
    return CsafSource("vendor-csaf", BASE, clock=clock or (lambda: float(CLOCK)))


def run_pass(cfg, sources, provider: Provider, notifier: FakeNotifier, clock: Clock | None = None) -> int:
    def http(method, url, headers, payload):
        if url.startswith(provider.base):
            return provider(method, url, headers, payload)
        if url == "https://feeds.example.com/rss":
            return 200, {}, FEED
        return fake_http(method, url, headers, payload)

    return pipeline.run_pass(
        cfg, sources, [notifier], http=http, clock=clock or (lambda: float(CLOCK)), sleep=lambda s: None
    )


def test_a_vendor_statement_is_delivered_and_says_it_is_not_a_local_match(tmp_path):
    cfg, provider, notifier = csaf_config(tmp_path), Provider(), FakeNotifier(200)
    provider.publish(1, 3600, cve="CVE-2026-4242", fixed=["WIDGET-2:widget-lib-1.2"], known_not_affected=["GIZMO-1"])
    assert run_pass(cfg, [csaf_source()], provider, notifier) == 0
    (entry,) = notifier.sent
    text = f"{entry['title']}\n{entry['body']}"
    assert "CVE-2026-4242" in text
    assert "not a check of your installed versions" in text, "the reader is told this is the vendor's statement"
    assert PUBLISHER in text and BASE + path_of(1) in text, "the provenance reaches the reader"
    assert "Widget 2.0" in text
    assert "Gizmo" not in text, "a product the vendor says is not affected is never named"
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["seen"]["CVE-2026-4242"]["outcome"] == "delivered"
    assert state["source_health"]["vendor-csaf"]["ok"] is True


def test_a_not_affected_statement_does_not_suppress_another_sources_alert(tmp_path):
    cfg, provider, notifier = csaf_config(tmp_path, with_feed=True), Provider(), FakeNotifier(200)
    provider.publish(1, 3600, cve="CVE-2026-4242", known_not_affected=["GIZMO-1"])
    # The CSAF source runs first, so a claim it made on CVE-2026-4242 would drop the feed's own alert.
    sources = [csaf_source(), RssSource("test", "https://feeds.example.com/rss")]
    assert run_pass(cfg, sources, provider, notifier) == 0
    (entry,) = notifier.sent
    assert "vendor.example.com/a1" in entry["body"], "the alert is the feed's, which says the vulnerability is real"
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["seen"]["CVE-2026-4242"]["outcome"] == "delivered"


def test_a_bad_document_turns_the_source_red_while_the_good_ones_are_delivered(tmp_path):
    cfg, provider, notifier = csaf_config(tmp_path), Provider(), FakeNotifier(200)
    provider.publish(1, 3600, cve="CVE-2026-4242", fixed=["WIDGET-2:widget-lib-1.2"])
    provider.publish(2, 1800)
    break_title(provider, 2)
    source = csaf_source()

    assert run_pass(cfg, [source], provider, notifier) == 1, "a source that could not read a document fails the pass"
    assert len(notifier.sent) == 1, "the document that could be read is still delivered"
    health = json.loads((tmp_path / "state.json").read_text())["source_health"]["vendor-csaf"]
    assert health["ok"] is False and health["items"] == 1
    assert path_of(2) in health["error"] and "schema" in health["error"] and "attempt 1 of 3" in health["error"]

    assert run_pass(cfg, [source], provider, notifier) == 1
    assert run_pass(cfg, [source], provider, notifier) == 1
    health = json.loads((tmp_path / "state.json").read_text())["source_health"]["vendor-csaf"]
    assert "given up" in health["error"], "an incomplete recovery stays visible after the retries end"

    provider.publish(2, 60, version="2", cve="CVE-2026-4343", fixed=["WIDGET-2:widget-lib-1.2"])
    assert run_pass(cfg, [source], provider, notifier) == 0
    health = json.loads((tmp_path / "state.json").read_text())["source_health"]["vendor-csaf"]
    assert health["ok"] is True and health["error"] == "", "a corrected revision clears the report"
    assert len(notifier.sent) == 2


def state_of(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "state.json").read_text())


def test_a_source_that_falls_behind_for_days_is_red_and_still_delivers_what_it_reads_late(tmp_path, monkeypatch):
    # Five advisories are listed within a minute and a pass reads one. Passes three days apart leave the source a week
    # and more behind, which an item's age at first sight would turn into history: dated before the last pass that
    # was green less a day, it is news; dated after, it is old. A source that is red does not move that instant.
    monkeypatch.setattr(csaf, "MAX_DOCUMENTS", 1)
    clock, cfg, provider, notifier = Clock(), csaf_config(tmp_path), Provider(), FakeNotifier(200)
    for number in range(1, 6):
        provider.publish(number, 600 - number, cve=f"CVE-2026-{number:04d}")
    source = csaf_source(clock)
    exits, errors = [], []
    for _ in range(5):
        exits.append(run_pass(cfg, [source], provider, notifier, clock))
        errors.append(state_of(tmp_path)["source_health"]["vendor-csaf"]["error"])
        clock.advance(3 * DAY)
    assert exits == [0, 1, 1, 1, 0], (
        "red from the first pass that ends more than half a day behind, green once caught up"
    )
    assert errors[1].startswith("behind: 3 listed document(s) not read yet, the oldest listed 3 d ago")
    assert errors[3].startswith("behind: 1 listed document(s) not read yet, the oldest listed 9 d ago"), (
        "the report does not stop at the age after which an item counts as history"
    )
    assert errors[4] == ""
    state = state_of(tmp_path)
    assert [state["seen"][f"CVE-2026-{number:04d}"]["outcome"] for number in range(1, 6)] == ["delivered"] * 5
    assert len(notifier.sent) == 5, "the advisory read twelve days after it was listed is still delivered"
    assert state["source_health"]["vendor-csaf"]["ok_at"] == CLOCK + 12 * DAY


def test_a_source_that_is_red_from_its_first_pass_still_delivers_what_it_reads_late(tmp_path, monkeypatch):
    # A document the source cannot read keeps it red for a month, and a red source records no last success, so a
    # source that starts with one never has an instant to measure an outage from. It is measured from its first pass
    # instead: what was listed after that is news however late it is read, and what the vendor dated more than a day
    # before it is history, as it is for every new source.
    monkeypatch.setattr(csaf, "MAX_DOCUMENTS", 1)
    clock, cfg, provider, notifier = Clock(), csaf_config(tmp_path), Provider(), FakeNotifier(200)
    provider.publish(1, 60)
    break_title(provider, 1)  # unreadable from the first pass on, and never replaced
    source = csaf_source(clock)
    exits = [run_pass(cfg, [source], provider, notifier, clock)]
    for number in range(2, 6):  # listed after the source began, within a minute
        provider.publish(number, -number, cve=f"CVE-2026-{number:04d}")
    # Listed after the source began as well, but the vendor wrote it a month before.
    provider.publish_regenerated(6, initial=60 * DAY, updated=30 * DAY, generated=-6, cve="CVE-2026-0006")
    for _ in range(8):  # the first document is given up on, then a pass reads one a time, three days apart
        clock.advance(3 * DAY)
        exits.append(run_pass(cfg, [source], provider, notifier, clock))
    assert exits == [1] * 9, "the source is never green"
    state = state_of(tmp_path)
    assert state["source_health"]["vendor-csaf"]["ok_at"] == 0
    assert "given up" in state["source_health"]["vendor-csaf"]["error"]
    outcomes = {cve: entry["outcome"] for cve, entry in state["seen"].items()}
    assert outcomes == {
        **{f"CVE-2026-{number:04d}": "delivered" for number in range(2, 6)},
        "CVE-2026-0006": "backlog",
    }, "read 9 to 18 days after it was listed, news is delivered; what was dated before the source began is history"
    assert len(notifier.sent) == 4


def test_an_old_advisory_the_provider_writes_again_is_history_and_a_revision_of_it_is_news(tmp_path):
    cfg, provider, notifier = csaf_config(tmp_path), Provider(), FakeNotifier(200)
    source = csaf_source()
    provider.publish(1, 3600, cve="CVE-2026-1111")  # a recent advisory: the source is up, and delivering
    assert run_pass(cfg, [source], provider, notifier) == 0
    assert len(notifier.sent) == 1

    # The generator of the provider writes an advisory from five years ago again and lists it as changed a minute ago.
    old = {"initial": 5 * YEAR, "updated": 5 * YEAR}
    provider.publish_regenerated(2, generated=60, cve="CVE-2026-2222", **old)
    assert run_pass(cfg, [source], provider, notifier) == 0
    assert len(notifier.sent) == 1, "an advisory the vendor wrote five years ago is not news because a file was written"
    assert state_of(tmp_path)["seen"]["CVE-2026-2222"]["outcome"] == "backlog"

    # The same file once more: nothing new has been said.
    provider.publish_regenerated(2, generated=30, cve="CVE-2026-2222", **old)
    assert run_pass(cfg, [source], provider, notifier) == 0
    assert len(notifier.sent) == 1

    # The vendor then revises it to cover another vulnerability, and that is news, dated by the revision.
    revised = [
        vulnerability("CVE-2026-2222", fixed=["WIDGET-2:widget-lib-1.2"]),
        vulnerability("CVE-2026-3333", known_affected=["GIZMO-1"]),
    ]
    provider.publish_regenerated(2, initial=5 * YEAR, updated=20, generated=10, vulnerabilities=revised)
    assert run_pass(cfg, [source], provider, notifier) == 0
    (entry,) = notifier.sent[1:]
    assert "CVE-2026-3333" in f"{entry['title']}\n{entry['body']}"
    assert state_of(tmp_path)["seen"]["CVE-2026-3333"]["outcome"] == "delivered"
