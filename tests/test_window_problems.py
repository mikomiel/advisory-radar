"""A window that read only part of what it owed says so: ``SourceWindow.problems`` is health, exit code and probe.

A source that raises fails as a whole and its cursor stays. A source that can read most of its input (a provider
directory with one bad document among twenty) must not be forced to choose between delivering the good items and
reporting the bad one, so its window carries both: the items are classified and delivered, and the problems turn
the source red for the operator in the health record, the exit code, ``sources test`` and the probe.
"""

from __future__ import annotations

import json

from advisory_radar import cli, core, pipeline
from advisory_radar.config import load_config
from advisory_radar.plugins import SourceWindow
from test_catalogue import config_file
from test_csaf import body
from test_csaf_source import BASE, Provider, break_title, path_of
from test_pipeline import FakeNotifier, fake_http, make_config, make_policy
from test_source_admin import make_client, signed_in

CLOCK = 1792600000
#: The warning block as the page renders it. The stylesheet names the class on every page, so a bare
#: ``notice-warning`` would match a page with no warning at all.
WARNING = "class='notice notice-warning'"


class ProblemSource:
    """A source that answers with items and also says what it could not read."""

    kind = "feed"

    def __init__(self, source_id: str, items, problems) -> None:
        self.id = source_id
        self.items = tuple(items)
        self.problems = tuple(problems)
        self.commits = 0

    def fetch(self, http, state=None):
        return SourceWindow(self.id, self.items, False, "", self.problems)

    def commit(self, state):
        self.commits += 1


def advisory_item(guid: str = "g1") -> core.Item:
    return core.Item(
        guid,
        "Vendor advisory CVE-2026-4242",
        "https://vendor.example.com/a1",
        "Fixes CVE-2026-4242.",
        CLOCK - 3600,
        ("CVE-2026-4242",),
    )


def run(cfg, source, *, notifier=None, dry_run: bool = False) -> int:
    return pipeline.run_pass(
        cfg,
        [source],
        [notifier or FakeNotifier(200)],
        http=fake_http,
        clock=lambda: float(CLOCK),
        sleep=lambda seconds: None,
        dry_run=dry_run,
    )


def health_of(tmp_path, source_id: str = "test") -> dict:
    return json.loads((tmp_path / "state.json").read_text())["source_health"][source_id]


def test_a_window_built_without_problems_has_none():
    assert SourceWindow("s", (), False, "example.net").problems == ()


def test_a_window_with_problems_still_delivers_its_items_and_reports_the_source_down(tmp_path):
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    source = ProblemSource("test", [advisory_item()], ["doc-7.json: schema: bad (attempt 1 of 3)", "doc-9.json: gone"])
    notifier = FakeNotifier(200)
    assert run(cfg, source, notifier=notifier) == 1
    assert len(notifier.sent) == 1, "what the window did read is classified and delivered"
    assert source.commits == 1, "the cursor moves for what was read: the problems are about the rest"
    health = health_of(tmp_path)
    assert health["ok"] is False
    assert health["items"] == 1
    assert health["ok_at"] == 0, "a source that never read cleanly has no last success"
    assert health["error"] == "doc-7.json: schema: bad (attempt 1 of 3); doc-9.json: gone"


def test_a_source_that_stops_reporting_problems_is_healthy_again(tmp_path):
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    source = ProblemSource("test", [], ["doc-7.json: gone"])
    assert run(cfg, source) == 1
    source.problems = ()
    assert run(cfg, source) == 0
    health = health_of(tmp_path)
    assert health["ok"] is True and health["error"] == "" and health["ok_at"] == CLOCK


def test_a_window_without_problems_is_unchanged(tmp_path):
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    notifier = FakeNotifier(200)
    assert run(cfg, ProblemSource("test", [advisory_item()], []), notifier=notifier) == 0
    assert len(notifier.sent) == 1
    health = health_of(tmp_path)
    assert health["ok"] is True and health["error"] == "" and health["items"] == 1


def test_a_dry_run_with_problems_exits_one_and_writes_nothing(tmp_path, capsys):
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    assert run(cfg, ProblemSource("test", [advisory_item()], ["doc-7.json: gone"]), dry_run=True) == 1
    assert "CVE-2026-4242" in capsys.readouterr().out, "the dry run still classified what the window did read"
    assert not (tmp_path / "state.json").exists()


def test_problem_text_is_redacted_and_bounded_before_it_is_stored(tmp_path):
    make_policy(tmp_path)
    path = tmp_path / "secret.yml"
    path.write_text(
        "sources:\n  - id: test\n    type: rss\n    url: https://feeds.example.com/rss\n"
        "notifiers:\n  - id: fake\n    type: webhook\n    url: https://hooks.example.com/${HOOK_TOKEN}\n"
        f"state_path: {tmp_path}/state.json\nwatchlist: {tmp_path}/watchlist.json\n"
    )
    cfg = load_config(path, {"HOOK_TOKEN": "dummy-hook-token"})
    source = ProblemSource("test", [], ["echoed dummy-hook-token back", "x" * 5000])
    assert run(cfg, source) == 1
    error = health_of(tmp_path)["error"]
    assert "dummy-hook-token" not in error
    assert "echoed [redacted] back" in error
    assert len(error) <= 1000


def test_sources_test_prints_the_problems_and_exits_one(tmp_path, capsys):
    provider = Provider()
    provider.publish(1, 300)
    provider.publish(2, 200)
    break_title(provider, 2)
    path = config_file(tmp_path, [{"id": "vendor", "type": "csaf", "url": BASE}])
    assert cli.main(["--config", str(path), "sources", "test", "vendor"], env={}, http=provider) == 1
    lines = capsys.readouterr().out.splitlines()
    assert any(line.startswith("problem: ") and path_of(2) in line and "schema" in line for line in lines)
    assert "vendor: 1 item(s); truncated: no" in lines


def test_sources_test_without_problems_prints_none_and_exits_zero(tmp_path, capsys):
    provider = Provider()
    provider.publish(1, 300)
    path = config_file(tmp_path, [{"id": "vendor", "type": "csaf", "url": BASE}])
    assert cli.main(["--config", str(path), "sources", "test", "vendor"], env={}, http=provider) == 0
    printed = capsys.readouterr().out
    assert "problem:" not in printed
    assert "vendor: 1 item(s); truncated: no" in printed


def test_a_problem_cannot_drive_the_terminal(tmp_path, capsys, monkeypatch):
    hostile = "doc.json: bad\x1b]0;pwned\x07\nforged: line"
    monkeypatch.setattr(
        "advisory_radar.sources.build_source", lambda entry, env: ProblemSource("vendor", [], [hostile])
    )
    path = config_file(tmp_path, [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"}])
    assert cli.main(["--config", str(path), "sources", "test", "vendor"], env={}, http=lambda *a: (200, {}, b"")) == 1
    printed = capsys.readouterr().out
    assert "\x1b" not in printed and "\x07" not in printed, "an escape sequence must not reach the terminal"
    assert "doc.json: bad\\x1b]0;pwned\\x07\\nforged: line" in printed
    assert printed.count("\n") == 2, "one problem line and one summary line, whatever the problem contains"


def probe(tmp_path, provider: Provider):
    client, _, _ = make_client(tmp_path, sources=[{"id": "vendor", "type": "csaf", "url": BASE}], transport=provider)
    csrf, fingerprint = signed_in(client)
    return client.post("/config/sources/probe", data={"csrf": csrf, "fingerprint": fingerprint, "id": "vendor"})


def test_the_probe_shows_the_problems_as_a_warning_and_writes_nothing(tmp_path):
    provider = Provider()
    provider.publish(1, 300)
    provider.publish(2, 200)
    break_title(provider, 2)
    response = probe(tmp_path, provider)
    assert response.status_code == 200
    assert "Answered with 1 entry." in response.text
    assert WARNING in response.text
    assert path_of(2) in response.text and "attempt 1 of 3" in response.text
    assert not (tmp_path / "data" / "state.json").exists(), "a probe is not a pass: it saves no state"


def test_the_probe_without_problems_shows_no_warning(tmp_path):
    provider = Provider()
    provider.publish(1, 300)
    response = probe(tmp_path, provider)
    assert "Answered with 1 entry." in response.text
    assert WARNING not in response.text


def test_a_problem_a_document_supplied_is_escaped_in_the_probe(tmp_path):
    provider = Provider()
    provider.publish(1, 300)
    document = json.loads(provider.files[path_of(1)])
    document["vulnerabilities"][0]["cve"] = "<script>alert(1)</script>"
    provider.files[path_of(1)] = body(document)
    response = probe(tmp_path, provider)
    assert "<script>alert(1)" not in response.text
    assert "&lt;script&gt;alert(1)" in response.text


# --------------------------------------------------------------------------
# A source that never reads cleanly: its outage baseline is its first answer

DAY = 86400


class Down:
    """A source that cannot be read at all: its fetch raises, so it never answers a window."""

    kind = "feed"

    def __init__(self, source_id: str) -> None:
        self.id = source_id

    def fetch(self, http, state=None):
        raise OSError("unreachable")


def item_at(guid: str, cve: str, published: int) -> core.Item:
    return core.Item(guid, f"Vendor advisory {cve}", "https://vendor.example.com/a", f"Fixes {cve}.", published, (cve,))


def run_at(cfg, source, now: int, notifier=None) -> int:
    """One pass at ``now``, for a test that lets days go by between passes."""
    return pipeline.run_pass(
        cfg,
        [source],
        [notifier or FakeNotifier(200)],
        http=fake_http,
        clock=lambda: float(now),
        sleep=lambda seconds: None,
    )


def outcome(tmp_path, cve: str) -> str:
    return json.loads((tmp_path / "state.json").read_text())["seen"][cve]["outcome"]


def test_a_source_that_never_read_cleanly_is_measured_from_its_first_answer(tmp_path):
    # A source with a document it cannot read is red, so it records no last success; without a baseline an outage
    # of more than seven days would file everything it reads late as history. It keeps the pass it first answered at.
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    source = ProblemSource("test", [], ["doc-7.json: gone"])
    assert run_at(cfg, source, CLOCK) == 1
    assert health_of(tmp_path)["ok_at"] == 0, "red is not a success"

    source.items = (
        item_at("news", "CVE-2026-4343", CLOCK + 3600),  # published after the source began, read 9 days later
        item_at("old", "CVE-2026-4444", CLOCK - 30 * DAY),  # published a month before the source began
    )
    assert run_at(cfg, source, CLOCK + 9 * DAY) == 1
    assert outcome(tmp_path, "CVE-2026-4343") == "delivered"
    assert outcome(tmp_path, "CVE-2026-4444") == "backlog"
    health = health_of(tmp_path)
    assert health["ok_at"] == 0, "the source never read cleanly"
    assert health["first_at"] == CLOCK, "and the baseline stays where its first answer put it"


def test_the_first_answer_is_not_the_first_attempt(tmp_path):
    # A source that was unreachable has read nothing, so nothing was seen from which to measure an outage; it is
    # bootstrapped when it first answers, as it always was.
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    assert run_at(cfg, Down("test"), CLOCK) == 1
    assert health_of(tmp_path)["first_at"] == 0
    assert run_at(cfg, ProblemSource("test", [], ["doc-7.json: gone"]), CLOCK + 10 * DAY) == 1
    assert health_of(tmp_path)["first_at"] == CLOCK + 10 * DAY
    assert run_at(cfg, Down("test"), CLOCK + 11 * DAY) == 1
    assert health_of(tmp_path)["first_at"] == CLOCK + 10 * DAY, "a later failure keeps it"


def test_the_last_success_outranks_the_first_answer_once_there_is_one(tmp_path):
    make_policy(tmp_path)
    cfg = make_config(tmp_path)
    source = ProblemSource("test", [], ["doc-7.json: gone"])
    assert run_at(cfg, source, CLOCK) == 1
    source.problems = ()
    clean = CLOCK + 20 * DAY
    assert run_at(cfg, source, clean) == 0
    health = health_of(tmp_path)
    assert health["ok_at"] == clean and health["first_at"] == CLOCK
    source.problems = ("doc-7.json: gone",)
    # Published five days after the source began: news to a baseline of its first answer, but more than a day before
    # the last clean pass, which is the instant the source has been measured from since.
    source.items = (item_at("mid", "CVE-2026-4545", CLOCK + 5 * DAY),)
    assert run_at(cfg, source, CLOCK + 40 * DAY) == 1
    assert outcome(tmp_path, "CVE-2026-4545") == "backlog"
