"""The pass budget: a pass spends a bounded wall-clock budget on other people's servers and defers the rest.

One fake clock drives the pass, its budget and ``sleep``. The fake network charges every request in fake seconds and
cuts a request at the ceiling the pass sets, as the real opener does, so the pass is tested end to end without
waiting for anything.
"""

from __future__ import annotations

import email.utils
import json
import time
import urllib.error
from pathlib import Path

import pytest

from advisory_radar import adobe, core, pipeline
from advisory_radar import http as http_module
from advisory_radar.config import ConfigError, load_config
from advisory_radar.plugins import SourceWindow
from advisory_radar.state import save_state
from test_pipeline import make_policy, queued_message
from test_web import make_app_client

NOW = 1792600000


class Clock:
    """The wall clock, the budget's monotonic clock and ``sleep`` in one: time moves only when a test says so."""

    def __init__(self, now: float = NOW) -> None:
        self.now = float(now)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def sleep(self, seconds: float) -> None:
        self.advance(seconds)


def feed(*entries: tuple[str, str, int]) -> bytes:
    """An RSS document with one entry per ``(guid, CVE id, hours old)``."""
    items = "".join(
        f"<item><title>Vendor advisory {cve}</title><link>https://vendor.example.com/{guid}</link>"
        f"<guid>{guid}</guid><description>Fixes {cve}.</description>"
        f"<pubDate>{email.utils.formatdate(NOW - hours * 3600, usegmt=True)}</pubDate></item>"
        for guid, cve, hours in entries
    )
    return (
        '<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>'
        f"<link>https://feeds.example.com/</link>{items}</channel></rss>"
    ).encode()


class Net:
    """The fake internet. ``cost`` maps a URL fragment to the seconds one matching request takes."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.calls: list[str] = []
        self.posts: list[dict] = []
        self.feeds: dict[str, bytes] = {}
        self.cost: dict[str, float] = {}

    def fetched(self) -> list[str]:
        return [url for url in self.calls if url.endswith("/feed")]

    def __call__(self, method, url, headers, body):
        self.calls.append(url)
        seconds = sum(cost for fragment, cost in self.cost.items() if fragment in url)
        # The ceiling the pass sets is part of the contract: a request cannot outlive it, it times out there.
        left = getattr(http_module, "ceiling_left", lambda: None)()
        if left is not None and seconds > left:
            self.clock.advance(max(left, 0.0))
            return 0, {}, b""
        self.clock.advance(seconds)
        if method == "POST":
            self.posts.append(json.loads(body))
            return 200, {}, b"ok"
        if url == core.KEV_URL:
            catalogue = {"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-2020-0001"}]}
            return 200, {"ETag": "k"}, json.dumps(catalogue).encode()
        if url.startswith(core.CVE_ORG_URL):
            cve = url.rsplit("/", 1)[1]
            metric = {"cvssV3_1": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N"}}
            record = {"cveMetadata": {"cveId": cve, "state": "PUBLISHED"}, "containers": {"cna": {"metrics": [metric]}}}
            return 200, {}, json.dumps(record).encode()
        if url.startswith(core.EPSS_URL):
            ids = url.split("cve=", 1)[1].split(",")
            rows = [{"cve": cve, "epss": "0.01", "percentile": "0.40"} for cve in ids]
            return 200, {}, json.dumps({"data": rows}).encode()
        if url.endswith("/feed"):
            return 200, {}, self.feeds.get(url, feed())
        return 404, {}, b""


def config(tmp_path: Path, ids=("a", "b", "c"), **overrides):
    sources = "".join(f"  - id: {i}\n    type: rss\n    url: https://{i}.example.com/feed\n" for i in ids)
    path = tmp_path / "config.yml"
    path.write_text(
        f"sources:\n{sources}"
        "notifiers:\n  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
        f"state_path: {tmp_path}/state.json\n"
        f"watchlist: {tmp_path}/watchlist.json\n" + "".join(f"{key}: {value}\n" for key, value in overrides.items())
    )
    return load_config(path, {})


def prepare(tmp_path: Path, **state) -> None:
    """A watchlist, and a state that has already had its first pass (the first pass seeds and is a case of its own)."""
    make_policy(tmp_path)
    document = core.new_state()
    document.update(state)
    save_state(tmp_path / "state.json", document)


def run(cfg, net: Net, clock: Clock, sources=None) -> int:
    built, notifiers = pipeline.build_plugins(cfg, {})
    return pipeline.run_pass(
        cfg,
        built if sources is None else sources,
        notifiers,
        http=net,
        clock=clock,
        sleep=clock.sleep,
        monotonic=clock,
    )


def stored(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "state.json").read_text())


def test_a_slow_provider_cannot_hold_a_pass_past_its_budget(tmp_path):
    prepare(tmp_path)
    clock = Clock()
    net = Net(clock)
    net.cost["a.example.com"] = 500
    assert run(config(tmp_path), net, clock) == 0, "a pass that ran out of budget is incomplete, not failed"
    assert net.fetched() == ["https://a.example.com/feed"], "the sources behind the slow one are deferred, not read"
    assert clock.now - NOW <= 600, "the default budget is ten minutes"
    state = stored(tmp_path)
    assert state["fetch_deferred"] == ["b", "c"]
    assert state["source_health"]["a"]["ok"] is False, "a source the budget cut short is not recorded as healthy"
    assert state["source_health"]["a"]["error"] == pipeline.BUDGET_CUT_ERROR, "and the budget is named as the reason"
    assert "b" not in state["source_health"], "a deferred source was never tried, so it has no health to record"
    record = state["runs"][-1]
    assert (record["code"], record["outcome"], record["deferred"]) == (0, "incomplete", 3)


def test_the_next_pass_starts_with_the_sources_the_budget_deferred(tmp_path):
    prepare(tmp_path)
    clock = Clock()
    net = Net(clock)
    net.cost["a.example.com"] = 500
    cfg = config(tmp_path)
    run(cfg, net, clock)
    net.calls.clear()
    assert run(cfg, net, clock) == 0
    assert net.fetched() == [f"https://{name}.example.com/feed" for name in "bca"], "deferred sources come first"
    assert "fetch_deferred" not in stored(tmp_path), "nothing is deferred once every source had its turn"


def test_a_candidate_the_budget_could_not_classify_is_carried_not_acknowledged(tmp_path):
    prepare(tmp_path)
    clock = Clock()
    net = Net(clock)
    net.feeds["https://a.example.com/feed"] = feed(("g1", "CVE-2026-1001", 3), ("g2", "CVE-2026-1002", 2))
    net.cost["cveawg.mitre.org"] = 350  # the first lookup fits in the budget, the second does not
    cfg = config(tmp_path, ids=("a",))
    assert run(cfg, net, clock) == 0
    assert [post["ids"] for post in net.posts] == [["CVE-2026-1001"]], "only the measured advisory was sent"
    state = stored(tmp_path)
    assert [row["guid"] for row in state["carry"]["a"]] == ["a:g2"], "the unmeasured candidate is carried"
    assert "CVE-2026-1002" not in state["seen"], "and it is not acknowledged"
    assert "a:g2" not in state.get("enrich_retry", {}), "nor does the budget start a retry clock for it"
    assert state["runs"][-1]["outcome"] == "incomplete"
    net.cost.clear()
    assert run(cfg, net, clock) == 0
    assert [post["ids"] for post in net.posts] == [["CVE-2026-1001"], ["CVE-2026-1002"]], "the next pass sends it"
    state = stored(tmp_path)
    assert "carry" not in state and "outcome" not in state["runs"][-1]


class TwoPages:
    """A plugin that makes two requests and carelessly ignores the failure of the second."""

    kind = "feed"

    def __init__(self, source_id: str) -> None:
        self.id = source_id

    def fetch(self, http, state):
        http("GET", f"https://{self.id}.example.com/page1", {}, None)
        http("GET", f"https://{self.id}.example.com/page2", {}, None)
        return SourceWindow(self.id, (), False, "")

    def commit(self, state):
        state["cursor"] = {self.id: "moved"}


def test_a_source_the_budget_cut_short_does_not_advance_its_cursor(tmp_path):
    prepare(tmp_path)
    clock = Clock()
    net = Net(clock)
    net.cost["a.example.com/page1"] = 440  # the fetch stage ends at 450 s of the default budget
    net.cost["a.example.com/page2"] = 20
    assert run(config(tmp_path, ids=("a",)), net, clock, sources=[TwoPages("a")]) == 0
    state = stored(tmp_path)
    assert "cursor" not in state, "a window a refused request cut short is dropped, so its cursor stays put"
    assert state["source_health"]["a"]["ok"] is False
    assert state["runs"][-1]["outcome"] == "incomplete"


def test_queued_critical_work_is_delivered_after_the_budget_is_spent(tmp_path):
    prepare(tmp_path, pending=[queued_message("CVE-2026-2001", "critical")])
    clock = Clock()
    net = Net(clock)
    net.cost["a.example.com"] = 500
    assert run(config(tmp_path), net, clock) == 0
    assert [post["ids"] for post in net.posts] == [["CVE-2026-2001"]], "delivery runs outside the budget"
    assert stored(tmp_path)["pending"] == []


class LocalSource:
    """A source that reads no network, as the webhook source reads its inbox."""

    kind = "webhook"

    def __init__(self, source_id: str) -> None:
        self.id = source_id
        self.reads = 0

    def fetch(self, http, state):
        self.reads += 1
        return SourceWindow(self.id, (), False, "")


def test_a_source_that_reads_no_network_is_not_deferred_by_the_budget(tmp_path):
    prepare(tmp_path)
    clock = Clock()
    net = Net(clock)
    net.cost["a.example.com"] = 500
    local = LocalSource("b")
    run(
        config(tmp_path, ids=("a", "b")),
        net,
        clock,
        sources=[pipeline.build_plugins(config(tmp_path), {})[0][0], local],
    )
    assert local.reads == 1
    assert "fetch_deferred" not in stored(tmp_path)


def test_a_slow_catalogue_download_cannot_spend_more_than_the_refresh_share(tmp_path):
    day = 86400
    watch = {
        "since": NOW - 10 * day,
        "last_eval": NOW - 2 * day,
        "level": "warning",
        "title": "t",
        "link": "https://vendor.example.com/x",
        "judged": "warning",
    }
    prepare(tmp_path, watch={"CVE-2026-3001": watch})
    clock = Clock()
    net = Net(clock)
    net.cost["cisa.gov"] = 300
    assert run(config(tmp_path, ids=("a",)), net, clock) == 0
    assert net.fetched() == ["https://a.example.com/feed"], "the sources are still read after a slow catalogue"
    state = stored(tmp_path)
    assert state["watch"]["CVE-2026-3001"]["last_eval"] == NOW - 2 * day, "a lookup the budget refused is not tried"
    assert clock.now - NOW < 300, "the catalogue was cut at the refresh share, not waited for"


def test_a_first_pass_that_could_read_nothing_for_lack_of_budget_still_rotates(tmp_path):
    make_policy(tmp_path)
    clock = Clock()
    net = Net(clock)
    net.cost["a.example.com"] = 500
    assert run(config(tmp_path), net, clock) == 0, "nothing was read, but only the budget is to blame"
    state = stored(tmp_path)
    assert state["fetch_deferred"] == ["b", "c"]
    assert "seeded" not in state, "no source is marked seeded before it was read"


class Failing(Net):
    """The internet, except that one host answers with a server error at once."""

    def __init__(self, clock: Clock, host: str) -> None:
        super().__init__(clock)
        self.host = host

    def __call__(self, method, url, headers, body):
        if self.host in url:
            self.calls.append(url)
            return 500, {}, b""
        return super().__call__(method, url, headers, body)


def test_a_source_that_fails_inside_the_budget_still_fails_the_pass(tmp_path):
    prepare(tmp_path)
    clock = Clock()
    net = Failing(clock, "a.example.com")
    assert run(config(tmp_path), net, clock) == 1, "a fault that is not the budget's stays a failure"
    state = stored(tmp_path)
    assert "fetch_deferred" not in state and "outcome" not in state["runs"][-1]
    assert state["source_health"]["a"]["error"] != pipeline.BUDGET_CUT_ERROR
    assert len(net.fetched()) == 3, "the sources after the failing one were still read"


def test_the_retry_clocks_of_sources_the_budget_never_reached_survive(tmp_path):
    clocks = {"b:g8": NOW - 200, "c:g7": NOW - 100}
    prepare(tmp_path, enrich_retry=dict(clocks))
    clock = Clock()
    net = Net(clock)
    net.cost["a.example.com"] = 500
    assert run(config(tmp_path), net, clock) == 0
    assert stored(tmp_path)["enrich_retry"] == clocks, "no window was read, so no clock may be pruned or restarted"


def test_the_deferred_adobe_pass_goes_first_next_time(tmp_path, monkeypatch):
    prepare(tmp_path)
    clock = Clock()
    net = Net(clock)
    net.feeds["https://a.example.com/feed"] = feed(("g1", "CVE-2026-1001", 3))
    net.cost["cveawg.mitre.org"] = 700  # the one lookup spends the whole budget the fetches left

    def adobe_pass(*args, **kwargs):
        net.calls.append("adobe")
        return True

    monkeypatch.setattr(core, "adobe_pass", adobe_pass)
    cfg = config(tmp_path, adobe_commerce="true")
    assert run(cfg, net, clock) == 0
    assert "adobe" not in net.calls, "no time was left for the Adobe pass"
    assert stored(tmp_path)["fetch_deferred"] == ["@adobe"]
    net.cost.clear()
    net.calls.clear()
    assert run(cfg, net, clock) == 0
    assert [call for call in net.calls if call == "adobe" or call.endswith("/feed")] == [
        "adobe",
        "https://a.example.com/feed",
        "https://b.example.com/feed",
        "https://c.example.com/feed",
    ], "the deferred pass runs before the sources instead of after them"
    assert "fetch_deferred" not in stored(tmp_path)


def test_an_adobe_pass_the_budget_cut_short_is_incomplete_not_failed(tmp_path, monkeypatch):
    prepare(tmp_path)
    clock = Clock()
    net = Net(clock)
    net.cost["adobe.example.com"] = 900

    def adobe_pass(state, http, *args, **kwargs):
        """The real pass fails when it cannot read its bulletin list, and records nothing."""
        return http("GET", "https://adobe.example.com/list", {}, None)[0] == 200

    monkeypatch.setattr(core, "adobe_pass", adobe_pass)
    assert run(config(tmp_path, ids=("a",), adobe_commerce="true"), net, clock) == 0
    record = stored(tmp_path)["runs"][-1]
    assert (record["code"], record["outcome"], record["deferred"]) == (0, "incomplete", 1)
    assert "fetch_deferred" not in stored(tmp_path), "it was started, so it keeps its place and is not deferred"


APSB = "APSB26-02"
#: A state that has seen one bulletin already, so ``APSB`` is the new one (a first Adobe pass queues nothing).
ADOBE_SEEN = {
    "window": ["APSB26-01"],
    "seen": {"APSB26-01": {"cves": [], "at": NOW - 86400, "exploited": False}},
}
BULLETIN_PAGE = (
    b'<div class="table"><div><div>Product</div><div>Version</div></div>'
    b"<div><div>Adobe Commerce</div><div>2.4.8-p9</div></div></div>"
)


class AdobeNet(Net):
    """The fake internet with the Adobe Commerce list and the page of ``APSB`` on it; ``page`` is that page's status."""

    def __init__(self, clock: Clock) -> None:
        super().__init__(clock)
        self.page = 200

    def __call__(self, method, url, headers, body):
        status, answer_headers, answer = super().__call__(method, url, headers, body)
        if status != 404:  # the parent charged the request and answered it, or cut it at the ceiling
            return status, answer_headers, answer
        if url == adobe.CAAS_URL:
            cards = [
                {
                    "contentArea": {
                        "detailText": adobe.COMMERCE_MNEMONIC,
                        "title": apsb,
                        "description": "Priority 2",
                        "url": f"https://helpx.example.com/{apsb.lower()}.html",
                    },
                    "search": {"search": "CVE-2026-2002"},
                }
                for apsb in ("APSB26-01", APSB)
            ]
            return 200, {}, json.dumps({"cards": cards}).encode()
        if url == adobe.detail_url(APSB):
            return self.page, {}, BULLETIN_PAGE if self.page == 200 else b""
        return status, answer_headers, answer


def test_a_bulletin_detail_the_budget_cut_is_asked_again_and_never_sent_without_its_details(tmp_path):
    prepare(tmp_path, adobe=ADOBE_SEEN)
    clock = Clock()
    net = AdobeNet(clock)
    net.cost[adobe.detail_url(APSB)] = 700  # longer than the whole budget: every read of the page is cut at the ceiling
    cfg = config(tmp_path, ids=("a",), adobe_commerce="true")
    for _ in range(4):  # an hour apart, so the passes together outlast the window of the retry clock
        assert run(cfg, net, clock) == 0, "a pass the budget cut is incomplete, not failed"
        clock.advance(3600)
        assert APSB not in stored(tmp_path)["adobe"]["seen"], "no message was sent for a page nobody asked Adobe for"
        assert net.posts == []
    assert clock.now - NOW > core.ADOBE_DETAIL_RETRY_SECONDS
    net.cost.clear()
    assert run(cfg, net, clock) == 0
    state = stored(tmp_path)["adobe"]
    assert APSB in state["seen"] and "retry" not in state and "backlog" not in state
    (message,) = net.posts
    assert "2.4.8-p9" in json.dumps(message), "the page was read on the first pass that had time, and its details sent"


def test_the_retry_clock_of_a_bulletin_detail_starts_when_adobe_is_asked_and_does_not_answer(tmp_path):
    prepare(tmp_path, adobe=ADOBE_SEEN)
    clock = Clock()
    net = AdobeNet(clock)
    net.cost[adobe.detail_url(APSB)] = 700
    cfg = config(tmp_path, ids=("a",), adobe_commerce="true")
    assert run(cfg, net, clock) == 0
    assert "retry" not in stored(tmp_path)["adobe"], "a read the budget cut is not a failure of Adobe's page"
    clock.advance(3600)
    net.cost.clear()
    net.page = 500  # Adobe is asked now, and does not answer
    asked = int(clock.now)
    assert run(cfg, net, clock) == 0
    assert stored(tmp_path)["adobe"]["retry"] == {APSB: asked}, "the clock starts with the first real failure"
    clock.advance(core.ADOBE_DETAIL_RETRY_SECONDS - 60)
    assert run(cfg, net, clock) == 0
    assert net.posts == [], "the window is not over yet"
    clock.advance(120)
    assert run(cfg, net, clock) == 0
    assert APSB in stored(tmp_path)["adobe"]["seen"], (
        "a page that keeps failing still ends in the message without details"
    )
    (message,) = net.posts
    assert "2.4.8-p9" not in json.dumps(message)


def test_a_state_written_before_the_budget_existed_still_runs(tmp_path):
    prepare(
        tmp_path, runs=[{"at": NOW - 900, "finished_at": NOW - 890, "sent": 0, "parked": 0, "pending": 0, "code": 0}]
    )
    clock = Clock()
    net = Net(clock)
    assert run(config(tmp_path), net, clock) == 0
    state = stored(tmp_path)
    assert "fetch_deferred" not in state
    assert "outcome" not in state["runs"][-1] and "deferred" not in state["runs"][-1]
    assert len(net.fetched()) == 3


def test_the_budget_is_a_validated_config_key(tmp_path):
    prepare(tmp_path)
    assert config(tmp_path).pass_budget_seconds == 600
    assert config(tmp_path, pass_budget="5m").pass_budget_seconds == 300
    assert config(tmp_path, pass_budget="1h").pass_budget_seconds == 3600
    for bad in ("30s", "2h", "0m", "ten minutes", "-5m"):
        with pytest.raises(ConfigError, match="pass_budget"):
            config(tmp_path, pass_budget=bad)


def signed_in(client, token):
    response = client.post("/login", data={"token": token}, follow_redirects=False)
    client.cookies.set("advisory_radar_session", response.cookies.get("advisory_radar_session"))


def test_runs_and_metrics_show_an_incomplete_pass(tmp_path):
    client, token, runtime = make_app_client(tmp_path, clock=1792600060)
    state = json.loads(runtime.cfg.state_path.read_text())
    state["runs"].append(
        {
            "at": 1792600000,
            "finished_at": 1792600050,
            "sent": 0,
            "parked": 0,
            "pending": 1,
            "code": 0,
            "outcome": "incomplete",
            "deferred": 2,
        }
    )
    save_state(runtime.cfg.state_path, state)
    signed_in(client, token)
    runs = client.get("/runs").text
    assert "incomplete" in runs and "2 deferred" in runs
    metrics = client.get("/metrics").text
    assert "advisory_radar_last_pass_exit 0" in metrics
    assert "advisory_radar_last_pass_incomplete 1" in metrics
    assert "advisory_radar_last_pass_deferred 2" in metrics


def test_a_run_record_without_an_outcome_is_not_incomplete(tmp_path):
    client, token, _ = make_app_client(tmp_path, clock=1792600060)
    signed_in(client, token)
    assert "incomplete" not in client.get("/runs").text
    metrics = client.get("/metrics").text
    assert "advisory_radar_last_pass_incomplete 0" in metrics
    assert "advisory_radar_last_pass_deferred 0" in metrics


def test_the_request_ceiling_caps_the_timeout_and_the_deadline(monkeypatch):
    seen: list[tuple[float, float]] = []

    class Opener:
        def open(self, request, timeout):
            seen.append((timeout, request.deadline - time.monotonic()))
            raise urllib.error.URLError("stop here")

    monkeypatch.setattr(http_module, "_OPENER", Opener())
    assert http_module.urllib_http("GET", "https://x.example.com/", {}, None) == (0, {}, b"")
    with http_module.request_ceiling(lambda: 7.0):
        assert http_module.urllib_http("GET", "https://x.example.com/", {}, None) == (0, {}, b"")
        with http_module.request_ceiling(lambda: 0.0):
            assert http_module.urllib_http("GET", "https://x.example.com/", {}, None) == (0, {}, b"")
    assert http_module.ceiling_left() is None, "the ceiling ends with its block"
    (plain_timeout, plain_window), (capped_timeout, capped_window) = seen
    assert plain_timeout == http_module.HTTP_TIMEOUT and plain_window > http_module.HTTP_DEADLINE - 1
    assert capped_timeout == 7.0 and 6 < capped_window <= 7
    assert len(seen) == 2, "no request is started once nothing is left"


def test_nvd_pacing_never_sleeps_past_the_budget():
    slept: list[float] = []

    def http(method, url, headers, body):
        if url.startswith(core.CVE_ORG_URL):
            record = {"cveMetadata": {"cveId": url.rsplit("/", 1)[1], "state": "PUBLISHED"}, "containers": {"cna": {}}}
            return 200, {}, json.dumps(record).encode()
        if url.startswith(core.EPSS_URL):
            row = {"cve": url.split("cve=", 1)[1], "epss": "0.01", "percentile": "0.40"}
            return 200, {}, json.dumps({"data": [row]}).encode()
        return 404, {}, b""

    intel = core.Intel(http, {}, lambda: 0.0, slept.append, remaining=lambda: core.NVD_PACE_SECONDS - 1)
    deferred: set[str] = set()
    facts = intel.cves(["CVE-2026-4001"], deferred=deferred)
    assert slept == [], "the pacing sleep would end after the budget"
    assert deferred == {"CVE-2026-4001"} and not facts["CVE-2026-4001"].complete


def test_the_docs_name_the_budget_key_the_gauges_and_the_lock_and_shutdown_behaviour():
    docs = Path(__file__).parent.parent / "docs"
    configuration = (docs / "configuration.md").read_text()
    deployment = (docs / "deployment.md").read_text()
    assert "pass_budget" in configuration and "pass_budget" in (docs.parent / "examples" / "config.yml").read_text()
    for name in ("advisory_radar_last_pass_incomplete", "_deferred"):
        assert name in deployment
    assert "## Passes, the state lock and shutdown" in deployment
    assert "Nothing cancels a running pass" in deployment
