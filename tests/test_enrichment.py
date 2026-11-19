"""Capped CVEs: the remaining enrichment work is durable, fair across sources and drained inside the pass budget.

An advisory that names more CVEs than one item may look up (``core.MAX_ITEM_CVE_LOOKUPS``) leaves the rest watched for
KEV only. These tests run whole passes against the fake network of ``test_pass_budget``, with one fake clock for the
wall clock, the pass budget and ``sleep``. Every pass loads the state document from disk, so each one is also a restart.
"""

from __future__ import annotations

import email.utils
import json
from pathlib import Path

import pytest

from advisory_radar import core, enrichment
from advisory_radar.config import DEFAULT_THRESHOLDS
from advisory_radar.state import save_state
from test_pass_budget import NOW, Clock, Net, config, prepare, run, signed_in, stored
from test_web import make_app_client

DAY = 86400


def rss(*entries: tuple[str, list[str], int]) -> bytes:
    """An RSS document with one entry per ``(guid, CVE ids it names, hours old)``."""
    items = "".join(
        f"<item><title>Vendor advisory {guid}</title><link>https://vendor.example.com/{guid}</link>"
        f"<guid>{guid}</guid><description>Fixes {', '.join(cves)}.</description>"
        f"<pubDate>{email.utils.formatdate(NOW - hours * 3600, usegmt=True)}</pubDate></item>"
        for guid, cves, hours in entries
    )
    return (
        '<?xml version="1.0"?><rss version="2.0"><channel><title>T</title><link>https://feeds.example.com/</link>'
        f"{items}</channel></rss>"
    ).encode()


def advisory(guid: str, cves: list[str], hours: int = 3) -> bytes:
    return rss((guid, cves, hours))


class Scored(Net):
    """The fake internet with chosen answers: ``critical`` CVEs are remote and unauthenticated, ``down`` ones fail."""

    def __init__(self, clock: Clock) -> None:
        super().__init__(clock)
        self.critical: set[str] = set()
        self.down: set[str] = set()

    def __call__(self, method, url, headers, body):
        if not url.startswith(core.CVE_ORG_URL):
            return super().__call__(method, url, headers, body)
        cve = url.rsplit("/", 1)[1]
        status, headers_, payload = super().__call__(method, url, headers, body)
        if cve in self.down:
            return 500, {}, b""
        if cve in self.critical and status == 200:
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            record = {
                "cveMetadata": {"cveId": cve, "state": "PUBLISHED"},
                "containers": {"cna": {"metrics": [{"cvssV3_1": {"baseScore": 9.8, "vectorString": vector}}]}},
            }
            return 200, {}, json.dumps(record).encode()
        return status, headers_, payload


class Bare(Scored):
    """``Scored`` whose CVE.org, once ``bare`` is set, knows every CVE but scores none, so each lookup falls to NVD."""

    bare = False

    def __call__(self, method, url, headers, body):
        status, headers_, payload = super().__call__(method, url, headers, body)
        if self.bare and url.startswith(core.CVE_ORG_URL) and status == 200:
            record = {"cveMetadata": {"cveId": url.rsplit("/", 1)[1], "state": "PUBLISHED"}, "containers": {"cna": {}}}
            return 200, {}, json.dumps(record).encode()
        return status, headers_, payload


def looked_up(net: Net, start: int = 0) -> list[str]:
    """The CVEs asked of CVE.org since call number ``start``, in order."""
    return [url.rsplit("/", 1)[1] for url in net.calls[start:] if url.startswith(core.CVE_ORG_URL)]


def capped(state: dict, source: str | None = None) -> set[str]:
    """The watched CVEs that were never measured, of one source or of all."""
    return {
        cve
        for cve, entry in state["watch"].items()
        if entry["kev_only"] and (source is None or entry["source_id"] == source)
    }


def delivered_advisories(tmp_path: Path, big: int = 35, small: int = 12, net_class: type[Scored] = Scored):
    """Pass one: source ``a`` delivers one advisory naming ``big`` CVEs and source ``b`` one naming ``small``."""
    prepare(tmp_path)
    clock = Clock()
    net = net_class(clock)
    net.feeds["https://a.example.com/feed"] = advisory("big", [f"CVE-2026-{3000 + n}" for n in range(big)])
    net.feeds["https://b.example.com/feed"] = advisory("small", [f"CVE-2026-{4000 + n}" for n in range(small)])
    cfg = config(tmp_path, ids=("a", "b"))
    assert run(cfg, net, clock) == 0
    return cfg, net, clock


def test_a_large_advisory_is_measured_in_full_without_starving_another_source(tmp_path):
    cfg, net, clock = delivered_advisories(tmp_path)
    state = stored(tmp_path)
    assert (len(capped(state, "a")), len(capped(state, "b"))) == (25, 2), "each advisory is measured up to the item cap"
    target = sorted(capped(state, "a"))[7]
    net.critical.add(target)
    sent = len(net.posts)
    assert run(cfg, net, clock) == 0
    state = stored(tmp_path)
    assert capped(state, "b") == set(), "the small advisory is not queued behind the large one"
    assert len(capped(state, "a")) == 25 - (enrichment.PER_PASS - 2), "the rest of the pass went to the large one"
    escalations = [post for post in net.posts[sent:] if post["kind"] == "escalation"]
    assert [(post["ids"], post["tag"]) for post in escalations] == [([target], "critical")]
    for left in (7, 0):
        assert run(cfg, net, clock) == 0
        assert len(capped(stored(tmp_path))) == left
    state = stored(tmp_path)
    assert all(entry["kev_only"] is False and "enrich" not in entry for entry in state["watch"].values())
    assert len(state["watch"]) == 47 and set(state["watch"]) <= set(state["cache"]), "every CVE has complete facts"
    assert "enrich_cursor" not in state, "nothing is left to rotate over"
    assert enrichment.coverage(state["watch"], NOW) == enrichment.Coverage(47, 0, 0, 0, None)


def test_the_drain_looks_up_no_more_than_its_cap_in_one_pass(tmp_path):
    cfg, net, clock = delivered_advisories(tmp_path)
    before = capped(stored(tmp_path))
    start = len(net.calls)
    assert run(cfg, net, clock) == 0
    asked = looked_up(net, start)
    assert len(asked) == enrichment.PER_PASS and set(asked) <= before and len(set(asked)) == len(asked)


def test_the_drain_cannot_spend_the_nvd_allowance_the_new_items_share(tmp_path):
    cfg, net, clock = delivered_advisories(tmp_path, net_class=Bare)
    net.bare = True  # from here on every CVE needs NVD for its score
    net.feeds["https://b.example.com/feed"] = advisory("fresh", ["CVE-2026-5001"], hours=1)
    before = capped(stored(tmp_path))
    start = len(net.calls)
    assert run(cfg, net, clock) == 0
    asked = [url for url in net.calls[start:] if url.startswith(core.NVD_URL)]
    assert len(asked) == enrichment.NVD_PER_PASS + 1, "the drain stops at its share and the new item still asks"
    state = stored(tmp_path)
    assert "CVE-2026-5001" in state["cache"], "the new item was measured in full"
    assert len(before - capped(state)) == enrichment.NVD_PER_PASS
    waiting = {cve for cve in capped(state) if enrichment.outstanding(state["watch"][cve]) == enrichment.DEFERRED}
    assert len(waiting) == enrichment.PER_PASS - enrichment.NVD_PER_PASS, "the rest wait, and are not counted as tried"
    assert all(state["watch"][cve]["enrich"]["tries"] == 0 for cve in waiting)
    assert {"outcome", "deferred"}.isdisjoint(state["runs"][-1]), "the allowance is no time budget: not incomplete"


def test_a_new_item_is_still_classified_in_a_pass_that_drains_a_large_advisory(tmp_path):
    cfg, net, clock = delivered_advisories(tmp_path)
    net.feeds["https://b.example.com/feed"] = advisory("fresh", ["CVE-2026-5001"], hours=1)
    sent = len(net.posts)
    assert run(cfg, net, clock) == 0
    assert [post["ids"] for post in net.posts[sent:]] == [["CVE-2026-5001"]], "the new item is sent in that pass"
    assert len(capped(stored(tmp_path))) == 27 - enrichment.PER_PASS


def test_the_drain_is_held_to_the_refresh_share_of_the_pass_budget_and_keeps_what_it_did_not_reach(tmp_path):
    cfg, net, clock = delivered_advisories(tmp_path)
    before = capped(stored(tmp_path))
    net.cost["cveawg.mitre.org"] = 30  # the refresh share of the default budget is 120 s
    net.feeds["https://b.example.com/feed"] = advisory("fresh", ["CVE-2026-5001"], hours=1)
    sent, start, began = len(net.posts), len(net.calls), clock.now
    assert run(cfg, net, clock) == 0
    asked = [cve for cve in looked_up(net, start) if cve in before]
    assert len(asked) == 4, "four lookups of 30 s fill the refresh share, and the other six are not started"
    assert [post["ids"] for post in net.posts[sent:]] == [["CVE-2026-5001"]], "new-item work keeps its own share"
    assert clock.now - began <= 600
    state = stored(tmp_path)
    deferred = {cve for cve in capped(state) if enrichment.outstanding(state["watch"][cve]) == enrichment.DEFERRED}
    assert len(deferred) == 6 and not deferred & set(asked)
    assert {"outcome", "deferred"}.isdisjoint(state["runs"][-1]), "outstanding enrichment is not an incomplete pass"
    coverage = enrichment.coverage(state["watch"], int(clock.now))
    assert (coverage.deferred, coverage.failed) == (6, 0), "the budget is not a failure of the provider"
    net.cost.clear()
    start = len(net.calls)
    assert run(cfg, net, clock) == 0
    again = looked_up(net, start)
    assert set(again[:6]) == deferred, "what the budget deferred is looked up first next time"


def test_a_lookup_the_budget_cut_takes_its_turn_and_cannot_starve_the_other_sources(tmp_path):
    """One CVE whose lookup outlasts the refresh share must not be picked first for ever.

    Its request spends the whole share on every pass, so nothing behind it can start. A lookup that began and was cut
    has had its turn: the next pass starts after its source and tries it last inside that source.
    """
    cfg, net, clock = delivered_advisories(tmp_path, big=13, small=11)
    state = stored(tmp_path)
    slow = min(capped(state, "a"))  # the one the drain picks first
    assert len(capped(state)) == 4 and slow in capped(state, "a")
    net.cost[f"{core.CVE_ORG_URL}{slow}"] = 500  # longer than the whole refresh share
    for _ in range(2):
        assert run(cfg, net, clock) == 0
    state = stored(tmp_path)
    assert capped(state) == {slow}, "every other waiting CVE, of both sources, was measured within two passes"
    marker = state["watch"][slow]["enrich"]
    assert (marker["state"], marker["tries"]) == (enrichment.DEFERRED, 0), "a cut lookup is no failure of a provider"
    start = len(net.calls)
    assert run(cfg, net, clock) == 0
    assert looked_up(net, start) == [slow], "it is asked again on the next pass, not after a day as a failed one is"
    assert enrichment.coverage(stored(tmp_path)["watch"], int(clock.now)).failed == 0


def test_a_daily_re_score_the_budget_cut_does_not_hold_the_drain_back_either(tmp_path):
    """The re-scores go first in the same stage, so one whose lookup never finishes would starve the drain as well."""
    due, waiting = "CVE-2026-6001", "CVE-2026-6002"
    prepare(
        tmp_path,
        watch={
            due: aged(3),
            waiting: aged(3, kev_only=True, source_id="b", last_eval=NOW - 60),
        },
    )
    clock = Clock()
    net = Scored(clock)
    net.cost[f"{core.CVE_ORG_URL}{due}"] = 500
    cfg = config(tmp_path, ids=("a", "b"))
    for _ in range(2):
        assert run(cfg, net, clock) == 0
    state = stored(tmp_path)
    assert state["watch"][waiting]["kev_only"] is False, "the waiting CVE was measured on the second pass"
    entry = state["watch"][due]
    assert entry["last_eval"] == NOW, "the cut re-score had its turn: it is due again after the next interval"
    assert (entry["enrich"]["state"], entry["enrich"]["tries"]) == (enrichment.DEFERRED, 0)


@pytest.mark.parametrize("seconds", [12, 13], ids=["answers_with_nothing_left", "is_cut"])
def test_a_daily_re_score_whose_epss_request_spends_the_budget_takes_its_turn_and_frees_the_drain(tmp_path, seconds):
    """The EPSS request is made before any CVE.org lookup, so it can be what uses up the refresh share (12 s of a one
    minute budget). The due CVE was named in it: without a turn it is due, and first, in every pass."""
    due, waiting = "CVE-2026-6001", "CVE-2026-6002"
    prepare(
        tmp_path,
        watch={
            due: aged(3),
            waiting: aged(3, kev_only=True, source_id="b", last_eval=NOW - 60),
        },
    )
    clock = Clock()
    net = Scored(clock)
    net.cost[f"{core.EPSS_URL}{due}"] = seconds
    cfg = config(tmp_path, ids=("a", "b"), pass_budget="1m")
    start = len(net.calls)
    assert run(cfg, net, clock) == 0
    assert looked_up(net, start) == [], "the request spent the refresh share: no CVE.org lookup began"
    state = stored(tmp_path)
    entry = state["watch"][due]
    assert entry["last_eval"] == NOW, "the due CVE had its turn: it is due again after the next interval"
    assert (entry["enrich"]["state"], entry["enrich"]["tries"]) == (enrichment.DEFERRED, 0)
    assert state["watch"][waiting]["kev_only"] is True and state["watch"][waiting]["enrich"]["at"] == 0
    assert "enrich_cursor" not in state, "the drain never began, so it took no turn"
    start = len(net.calls)
    assert run(cfg, net, clock) == 0
    assert looked_up(net, start) == [waiting], "the drain has the refresh share to itself"
    assert stored(tmp_path)["watch"][waiting]["kev_only"] is False


def test_a_drain_batch_whose_epss_request_spends_the_budget_takes_its_turn_and_the_cves_behind_it_are_reached(tmp_path):
    """One EPSS request names the ten CVEs of a drain. When it uses up the refresh share, none of them could begin; left
    where they were they would be the first ten in every pass, and the seven behind them would never be asked."""
    cfg, net, clock = delivered_advisories(tmp_path, big=25, small=12)
    state = stored(tmp_path)
    assert (len(capped(state, "a")), len(capped(state, "b"))) == (15, 2)
    now = int(clock.now)
    picks = enrichment.select(state, now)
    behind = capped(state) - set(picks)
    assert len(picks) == enrichment.PER_PASS and len(behind) == 7
    net.cost[f"{core.EPSS_URL}{picks[0]}"] = 500  # longer than the refresh share, and only the request that names these
    start = len(net.calls)
    assert run(cfg, net, clock) == 0
    assert looked_up(net, start) == [], "the request spent the refresh share: no lookup began"
    state = stored(tmp_path)
    assert capped(state) == set(picks) | behind, "nothing was measured"
    for cve in picks:
        marker = state["watch"][cve]["enrich"]
        assert (marker["state"], marker["tries"], marker["at"]) == (enrichment.DEFERRED, 0, now)
    assert all("enrich" not in state["watch"][cve] for cve in behind), "the CVEs behind it never began"
    assert state["enrich_cursor"] == state["watch"][picks[-1]]["source_id"], "the batch took its turn"
    assert run(cfg, net, clock) == 0
    assert not capped(stored(tmp_path)) & behind, "the CVEs that waited behind the batch are measured next"


def test_a_failed_lookup_is_recorded_waits_a_day_and_does_not_hold_the_others_back(tmp_path):
    cfg, net, clock = delivered_advisories(tmp_path)
    target = sorted(capped(stored(tmp_path), "a"))[3]
    net.down.add(target)
    assert run(cfg, net, clock) == 0
    state = stored(tmp_path)
    marker = state["watch"][target]["enrich"]
    assert (marker["state"], marker["tries"]) == (enrichment.FAILED, 1)
    assert state["watch"][target]["kev_only"] is True, "a failed lookup measured nothing"
    assert len(capped(state)) == 27 - (enrichment.PER_PASS - 1), "the other nine were measured"
    start = len(net.calls)
    assert run(cfg, net, clock) == 0
    assert target not in looked_up(net, start), "a failed lookup is not repeated on every pass"
    net.down.clear()
    clock.advance(DAY)
    for _ in range(3):
        assert run(cfg, net, clock) == 0
    state = stored(tmp_path)
    assert state["watch"][target]["kev_only"] is False and "enrich" not in state["watch"][target]
    assert capped(state) == set()


def test_a_kev_listed_capped_cve_escalates_on_the_pass_that_sees_it_not_on_its_daily_clock():
    cve = "CVE-2026-9001"
    state = core.new_state()
    state["watch"][cve] = {
        "since": NOW - 3600,
        "last_eval": NOW - 60,
        "level": "warning",
        "kev_only": True,
        "title": "big advisory",
        "link": "https://vendor.example.com/big",
    }

    class Intel:
        def cves(self, cves, force=False, deferred=None):
            raise AssertionError("positive KEV evidence needs no lookup")

    core.reevaluate(state, Intel(), frozenset({cve}), True, NOW, "", thresholds=DEFAULT_THRESHOLDS)
    assert [(entry["cves"], entry["tag"]) for entry in state["pending"]] == [([cve], "critical")]
    core.reevaluate(state, Intel(), frozenset(), True, NOW, "", thresholds=DEFAULT_THRESHOLDS)
    assert len(state["pending"]) == 1, "a catalogue that does not list it escalates nothing"


def test_kev_evidence_is_acted_on_in_the_pass_even_when_every_lookup_is_deferred(tmp_path):
    cve = "CVE-2020-0001"  # the one CVE the fake catalogue lists
    prepare(
        tmp_path,
        watch={
            cve: {
                "since": NOW - 3600,
                "last_eval": NOW - 60,
                "level": "warning",
                "judged": "warning",
                "kev_only": True,
                "title": "big advisory",
                "link": "https://vendor.example.com/big",
                "source_id": "a",
            }
        },
    )
    clock = Clock()
    net = Scored(clock)
    net.cost["cveawg.mitre.org"] = 500  # no lookup fits the refresh share
    assert run(config(tmp_path, ids=("a",)), net, clock) == 0
    assert [(post["ids"], post["tag"]) for post in net.posts if post["kind"] == "escalation"] == [([cve], "critical")]
    entry = stored(tmp_path)["watch"][cve]
    assert entry["level"] == "critical" and entry["kev_only"] is True, "the lookups are still owed"
    assert enrichment.outstanding(entry) == enrichment.DEFERRED


def test_an_item_naming_a_kev_cve_is_sent_critical_after_the_budget_is_spent(tmp_path):
    prepare(tmp_path)
    clock = Clock()
    net = Scored(clock)
    # The plain item is the older one, so it is reached first and spends the whole budget.
    net.feeds["https://a.example.com/feed"] = rss(
        ("plain", ["CVE-2026-1001"], 3), ("exploited", ["CVE-2020-0001", "CVE-2026-1002", "CVE-2026-1003"], 2)
    )
    net.cost["cveawg.mitre.org"] = 700
    assert run(config(tmp_path, ids=("a",)), net, clock) == 0
    state = stored(tmp_path)
    assert [(post["ids"][0], post["tag"]) for post in net.posts] == [("CVE-2020-0001", "critical")]
    assert [row["guid"] for row in state["carry"]["a"]] == ["a:plain"], "the plain item still waits for a lookup"
    assert state["runs"][-1]["outcome"] == "incomplete"
    entry = state["watch"]["CVE-2020-0001"]
    assert entry["level"] == "critical" and entry["kev_only"] is True, "its CVEs are watched and measured later"
    assert state["watch"]["CVE-2026-1002"]["kev_only"] is True and state["watch"]["CVE-2026-1003"]["kev_only"] is True
    net.cost.clear()
    start = len(net.calls)
    assert run(config(tmp_path, ids=("a",)), net, clock) == 0
    assert {"CVE-2020-0001", "CVE-2026-1002", "CVE-2026-1003"} <= set(looked_up(net, start))
    assert capped(stored(tmp_path)) == set()


def test_the_cursor_gives_every_source_its_turn_and_survives_a_restart():
    state = core.new_state()
    names = [f"s{n:02d}" for n in range(12)]
    for index, name in enumerate(names):
        for second in range(3):  # three turns of ``PER_PASS`` need 30 waiting CVEs, so every turn is a full one
            state["watch"][f"CVE-2026-{index:02d}{second}"] = {
                "since": NOW - DAY,
                "last_eval": NOW - 60,
                "level": "warning",
                "kev_only": True,
                "source_id": name,
                "title": "t",
                "link": "https://vendor.example.com/x",
            }
    first_turn: dict[str, int] = {}
    for number in (1, 2, 3):
        state = json.loads(json.dumps(state))  # a restart: the document is all that is kept
        picks = enrichment.select(state, NOW)
        assert len(picks) == enrichment.PER_PASS and len(set(picks)) == len(picks)
        for cve in picks:
            first_turn.setdefault(state["watch"][cve]["source_id"], number)
            enrichment.record(state["watch"][cve], enrichment.MEASURED, NOW)
        enrichment.served(state, picks, {cve: enrichment.MEASURED for cve in picks})
    assert set(first_turn) == set(names), "no source is left out"
    assert max(first_turn.values()) == 2, "with more sources than the cap, the cursor serves the unserved ones first"


def test_a_pass_the_budget_ended_does_not_move_the_cursor_past_a_source_it_never_served():
    state = core.new_state()
    for name in ("a", "b", "c"):
        state["watch"][f"CVE-2026-0{name}"] = {"since": NOW, "last_eval": NOW, "kev_only": True, "source_id": name}
    picks = enrichment.select(state, NOW)
    assert picks == ["CVE-2026-0a", "CVE-2026-0b", "CVE-2026-0c"]
    enrichment.served(state, picks, {picks[0]: enrichment.MEASURED, picks[1]: enrichment.DEFERRED})
    assert state["enrich_cursor"] == "a", "only the lookup that was made counts as a turn"
    enrichment.served(state, picks, {pick: enrichment.DEFERRED for pick in picks})
    assert state["enrich_cursor"] == "a", "a pass that made no lookup moves nothing"


def test_an_interrupted_lookup_takes_a_turn_and_goes_behind_the_rest_without_counting_a_try():
    state = core.new_state()
    for name, cve in (("a", "CVE-2026-0001"), ("a", "CVE-2026-0002"), ("b", "CVE-2026-0003")):
        state["watch"][cve] = {"since": NOW - DAY, "last_eval": NOW, "kev_only": True, "source_id": name}
    picks = enrichment.select(state, NOW)
    assert picks == ["CVE-2026-0001", "CVE-2026-0003", "CVE-2026-0002"]
    outcomes = {"CVE-2026-0001": enrichment.INTERRUPTED, "CVE-2026-0003": enrichment.DEFERRED}
    enrichment.record(state["watch"]["CVE-2026-0001"], enrichment.INTERRUPTED, NOW)
    enrichment.served(state, picks, outcomes)
    assert state["enrich_cursor"] == "a", "the lookup that began is a turn, though it did not finish"
    marker = state["watch"]["CVE-2026-0001"]["enrich"]
    assert marker == {"state": enrichment.DEFERRED, "since": NOW - DAY, "tries": 0, "at": NOW}
    assert enrichment.outstanding(state["watch"]["CVE-2026-0001"]) == enrichment.DEFERRED
    assert enrichment.select(state, NOW + 1) == ["CVE-2026-0003", "CVE-2026-0002", "CVE-2026-0001"]
    enrichment.record(state["watch"]["CVE-2026-0001"], enrichment.DEFERRED, NOW + 2)
    assert state["watch"]["CVE-2026-0001"]["enrich"]["at"] == NOW, "a later deferral does not give the turn back"


def test_intel_tells_a_lookup_the_budget_cut_from_one_it_never_started():
    spent = False

    def http(method, url, headers, body):
        nonlocal spent
        if url.startswith(core.CVE_ORG_URL):
            spent = True  # this request is the one that outlasts the budget
            return 0, {}, b""
        rows = [{"cve": cve, "epss": "0.01", "percentile": "0.40"} for cve in url.split("cve=", 1)[1].split(",")]
        return 200, {}, json.dumps({"data": rows}).encode()

    intel = core.Intel(http, {}, lambda: 0.0, lambda seconds: None, remaining=lambda: -1.0 if spent else 100.0)
    deferred: set[str] = set()
    facts = intel.cves(["CVE-2026-4001", "CVE-2026-4002"], deferred=deferred)
    assert deferred == {"CVE-2026-4001", "CVE-2026-4002"} and not any(fact.complete for fact in facts.values())
    assert {cve for cve, fact in facts.items() if fact.interrupted} == {"CVE-2026-4001"}, (
        "the second was never asked, so it is deferred and no more"
    )


@pytest.mark.parametrize("answers", [True, False], ids=["answers_with_nothing_left", "is_cut"])
def test_intel_marks_every_cve_of_an_epss_request_that_spends_the_budget_interrupted(answers):
    spent = False
    asked: list[str] = []

    def http(method, url, headers, body):
        nonlocal spent
        asked.append(url)
        assert url.startswith(core.EPSS_URL), "no CVE.org lookup can begin once the budget is spent"
        spent = True  # this request is the one that uses up what is left
        if not answers:
            return 0, {}, b""
        rows = [{"cve": cve, "epss": "0.01", "percentile": "0.40"} for cve in url.split("cve=", 1)[1].split(",")]
        return 200, {}, json.dumps({"data": rows}).encode()

    intel = core.Intel(http, {}, lambda: 0.0, lambda seconds: None, remaining=lambda: -1.0 if spent else 100.0)
    named = ["CVE-2026-4001", "CVE-2026-4002"]
    deferred: set[str] = set()
    facts = intel.cves(named, deferred=deferred)
    assert len(asked) == 1 and deferred == set(named) and not any(fact.complete for fact in facts.values())
    assert {cve for cve, fact in facts.items() if fact.interrupted} == set(named), "the one request named both"
    later: set[str] = set()
    facts = intel.cves(["CVE-2026-4003"], deferred=later)
    assert len(asked) == 1 and later == {"CVE-2026-4003"}, "a call that finds the budget spent asks nothing"
    assert not facts["CVE-2026-4003"].interrupted, "and what never began is only deferred"


def test_intel_does_not_call_a_failed_epss_request_interrupted_while_time_is_left():
    def http(method, url, headers, body):
        if url.startswith(core.EPSS_URL):
            return 500, {}, b""  # the provider failed; the budget is not what ended it
        metric = {"cvssV3_1": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N"}}
        record = {"cveMetadata": {"cveId": url.rsplit("/", 1)[1], "state": "PUBLISHED"}}
        record["containers"] = {"cna": {"metrics": [metric]}}
        return 200, {}, json.dumps(record).encode()

    intel = core.Intel(http, {}, lambda: 0.0, lambda seconds: None, remaining=lambda: 100.0)
    deferred: set[str] = set()
    fact = intel.cves(["CVE-2026-4001"], deferred=deferred)["CVE-2026-4001"]
    assert not fact.complete and not fact.interrupted and deferred == set(), "a provider failure is not a budget cut"


def test_the_window_stretches_to_thirty_days_only_for_entries_with_outstanding_enrichment():
    def watched(age: int, **extra) -> dict:
        return {
            "since": NOW - age * DAY,
            "last_eval": NOW,
            "level": "warning",
            "title": "t",
            "link": "https://vendor.example.com/x",
            **extra,
        }

    failing = {"state": "failed", "since": NOW - 5 * DAY, "tries": 3, "at": NOW - DAY}
    waiting = {"state": "deferred", "since": NOW - DAY, "tries": 0, "at": 0}
    state = core.new_state()
    state["watch"] = {
        "CVE-2026-0001": watched(20, kev_only=True),
        "CVE-2026-0002": watched(20, kev_only=False),
        "CVE-2026-0003": watched(31, kev_only=True),
        "CVE-2026-0004": watched(29, kev_only=False, enrich=failing),
        "CVE-2026-0005": watched(13, kev_only=False),
        "CVE-2026-0006": watched(15, enrich=waiting),
        "CVE-2026-0007": watched(15, enrich="damaged"),
    }
    core._prune(state, NOW)
    assert set(state["watch"]) == {"CVE-2026-0001", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006"}
    assert enrichment.EXTENDED_WINDOW == 30 * DAY and core.REEVAL_WINDOW == 14 * DAY


def test_coverage_counts_each_state_and_the_oldest_wait_and_ignores_damaged_entries():
    def watched(age: int, **extra) -> dict:
        return {"since": NOW - age * DAY, "kev_only": False, **extra}

    watch = {
        "CVE-2026-0001": watched(1),
        "CVE-2026-0002": watched(2),
        "CVE-2026-0003": watched(3, kev_only=True),
        "CVE-2026-0004": watched(6, kev_only=True),
        "CVE-2026-0005": watched(9, kev_only=True, enrich={"state": "deferred", "since": NOW - 2 * DAY}),
        "CVE-2026-0006": watched(4, enrich={"state": "failed", "since": NOW - 3 * DAY, "tries": 2, "at": NOW}),
        "CVE-2026-0007": "damaged",
    }
    coverage = enrichment.coverage(watch, NOW)
    assert coverage == enrichment.Coverage(measured=2, kev_only=2, deferred=1, failed=1, oldest_age=6 * DAY)
    assert coverage.outstanding == 4
    assert enrichment.coverage(None, NOW) == enrichment.Coverage(0, 0, 0, 0, None)


def test_a_state_written_before_the_drain_existed_still_loads_and_is_drained(tmp_path):
    cve = "CVE-2026-7001"
    prepare(
        tmp_path,
        watch={
            cve: {
                "since": NOW - 5 * DAY,
                "last_eval": NOW - 3600,
                "level": "warning",
                "judged": "warning",
                "kev_only": True,
                "cvss": None,
                "title": "an advisory delivered by an older version",
                "link": "https://vendor.example.com/old",
                "thresholds": list(DEFAULT_THRESHOLDS.snapshot()),
            }
        },
    )
    clock = Clock()
    net = Scored(clock)
    assert run(config(tmp_path, ids=("a",)), net, clock) == 0
    entry = stored(tmp_path)["watch"][cve]
    assert entry["kev_only"] is False and "enrich" not in entry
    assert cve in looked_up(net)


def aged(age_days: int, **extra) -> dict:
    """A watch entry whose message is ``age_days`` old, as an earlier pass would have left it on disk."""
    return {
        "since": NOW - age_days * DAY,
        "last_eval": NOW - age_days * DAY,
        "level": "warning",
        "judged": "warning",
        "kev_only": False,
        "cvss": None,
        "title": "an advisory",
        "link": "https://vendor.example.com/old",
        "thresholds": list(DEFAULT_THRESHOLDS.snapshot()),
        "source_id": "a",
        **extra,
    }


def test_a_capped_entry_is_kept_and_drained_past_fourteen_days_then_follows_the_ordinary_window(tmp_path):
    capped_cve, measured_cve = "CVE-2026-8001", "CVE-2026-8002"
    prepare(tmp_path, watch={capped_cve: aged(20, kev_only=True), measured_cve: aged(20)})
    clock = Clock()
    net = Scored(clock)
    cfg = config(tmp_path, ids=("a",))
    assert run(cfg, net, clock) == 0  # each pass loads the document from disk: this is a restart
    state = stored(tmp_path)
    assert set(state["watch"]) == {capped_cve}, "20 days is past the window, and only the capped entry owes enrichment"
    assert capped_cve in looked_up(net) and measured_cve not in looked_up(net)
    assert state["watch"][capped_cve]["kev_only"] is False and "enrich" not in state["watch"][capped_cve]
    assert run(cfg, net, clock) == 0
    assert stored(tmp_path)["watch"] == {}, "once measured, the entry is held to the ordinary 14 days again"


def test_an_entry_whose_lookups_keep_failing_is_dropped_at_thirty_days(tmp_path):
    cve = "CVE-2026-8003"
    prepare(tmp_path, watch={cve: aged(29, kev_only=True)})
    clock = Clock()
    net = Scored(clock)
    net.down.add(cve)
    cfg = config(tmp_path, ids=("a",))
    assert run(cfg, net, clock) == 0
    marker = stored(tmp_path)["watch"][cve]["enrich"]
    assert (marker["state"], marker["tries"]) == (enrichment.FAILED, 1), "29 days old and still owed: kept, and tried"
    clock.advance(2 * DAY)
    assert run(cfg, net, clock) == 0
    assert stored(tmp_path)["watch"] == {}, "past 30 days nothing is kept, whatever is outstanding"


def test_the_coverage_is_on_the_dashboard_and_in_the_metrics_after_a_restart(tmp_path):
    delivered_advisories(tmp_path)
    state = stored(tmp_path)
    client, token, runtime = make_app_client(tmp_path, clock=NOW + 7200)
    save_state(runtime.cfg.state_path, state)
    signed_in(client, token)
    page = client.get("/").text
    assert "20 measured · 0 deferred · 0 failed · 27 KEV-only" in page
    assert "Oldest outstanding enrichment" in page and "2h" in page
    assert "30 days" in page and "14 days" in page, "the window policy is stated where the counts are"
    metrics = client.get("/metrics").text
    for state_name, count in (("measured", 20), ("kev_only", 27), ("deferred", 0), ("failed", 0)):
        assert f'advisory_radar_enrichment_cves{{state="{state_name}"}} {count}' in metrics
    assert "advisory_radar_enrichment_oldest_age_seconds 7200" in metrics


def test_the_metrics_report_no_wait_when_nothing_is_outstanding(tmp_path):
    client, token, _ = make_app_client(tmp_path, clock=NOW + 60)
    signed_in(client, token)
    metrics = client.get("/metrics").text
    assert 'advisory_radar_enrichment_cves{state="kev_only"} 0' in metrics
    assert "advisory_radar_enrichment_oldest_age_seconds 0" in metrics
    assert "none outstanding" in client.get("/").text


def test_the_docs_describe_the_drain_the_window_and_the_gauges():
    docs = Path(__file__).parent.parent / "docs"
    configuration = (docs / "configuration.md").read_text()
    deployment = (docs / "deployment.md").read_text()
    assert "## Capped CVEs" in configuration
    for phrase in ("30 days", "14 days", "one source in turn", "KEV"):
        assert phrase in configuration
    for name in ("advisory_radar_enrichment_cves", "advisory_radar_enrichment_oldest_age_seconds"):
        assert name in deployment
