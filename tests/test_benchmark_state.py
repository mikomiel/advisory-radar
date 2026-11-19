"""scripts/benchmark_state.py builds the histories whose cost the deployment guide quotes.

The script is the evidence behind the supported scale, so these tests pin what would quietly make it wrong: a
generator whose documents drift from what a pass writes, a pass measurement that stops counting saves or credits a
message with a save that is not its acknowledgement, a save timing that measures a save which writes nothing, a
budget check that cannot fail. They run on a history of a few dozen records. The full-size run is the operator's to
repeat, with ``uv run python scripts/benchmark_state.py``.
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import statistics
from pathlib import Path

import pytest

from advisory_radar import core
from advisory_radar import state as state_module

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "benchmark_state.py"
#: A history of 60 identifiers and 12 deliveries, spread over four years: half of the deliveries are past the two-year
#: retention line, so the first pass has something to archive.
TINY = ["--seen", "60", "--deliveries", "12", "--span-days", str(4 * 365), "--repeat", "1"]


def load_benchmark():
    spec = importlib.util.spec_from_file_location("benchmark_state_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bench = load_benchmark()


def run_main(arguments: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = bench.main(arguments)
    return code, out.getvalue()


@pytest.fixture(scope="module")
def tiny_report(tmp_path_factory) -> dict:
    """One measurement of the tiny history in both stores, shared by the tests that read its numbers."""
    with pytest.MonkeyPatch.context() as patch:
        # The two syncs are what a save costs on a real disk, and no test here can observe them.
        patch.setattr(state_module, "_sync_directory", lambda directory: None)
        patch.setattr(bench, "_fsync_ms", lambda directory, samples=20: 1.0)
        code, text = run_main([*TINY, "--json", "--workdir", str(tmp_path_factory.mktemp("bench"))])
    assert code == 0
    return json.loads(text)


def stores(report: dict) -> list[dict]:
    return [row for profile in report["profiles"] for row in profile["stores"]]


# --- the synthetic history -------------------------------------------------------------------------------------


def test_the_generator_builds_exactly_the_counts_it_is_asked_for():
    state = bench.build_state(120, 24, span_days=100, seed=1)

    assert state["schema"] == core.STATE_SCHEMA
    assert len(state["seen"]) == 120
    assert len(state["deliveries"]) == 24
    pointers = [record["delivery"] for record in state["seen"].values() if "delivery" in record]
    assert set(pointers) == set(state["deliveries"]), "every delivery is pointed at, and every pointer lands"
    assert len(pointers) == sum(len(snapshot["ids"]) for snapshot in state["deliveries"].values())
    times = [record["at"] for record in state["seen"].values()]
    assert times == sorted(times), "records are added oldest first, as a real document grows"
    assert times[0] >= bench.NOW - 100 * core.DAY
    assert times[-1] <= bench.NOW


def test_the_same_seed_builds_the_same_history_and_another_seed_a_different_one():
    first = bench.build_state(80, 16, span_days=50, seed=7)

    assert bench.build_state(80, 16, span_days=50, seed=7) == first
    assert bench.build_state(80, 16, span_days=50, seed=8) != first


@pytest.mark.parametrize(("seen", "deliveries"), [(5, 6), (5, -1)])
def test_a_history_cannot_deliver_more_than_it_has_seen(seen, deliveries):
    with pytest.raises(ValueError, match="seen"):
        bench.build_state(seen, deliveries, span_days=10, seed=1)


def test_a_generated_delivery_has_the_keys_a_real_delivery_writes():
    """A key a pass writes and the generator leaves out would make every measured document too small."""
    generated = next(iter(bench.build_state(20, 4, span_days=10, seed=1)["deliveries"].values()))
    queued = {
        "kind": "new",
        "tag": "warning",
        "title": "WARNING: CVE-2026-1 in widget",
        "ids": ["CVE-2026-1"],
        "cves": ["CVE-2026-1"],
        "queued_at": 100,
    }

    real = core._delivery_snapshot(queued, ["hook"], at=200, outcome="delivered")

    assert set(generated) == set(real)


def test_the_advisories_a_full_pass_delivers_are_not_in_the_history_of_the_target():
    """The first version gave a pass `CVE-2026-90000` and up, which a history of 100,000 identifiers already holds."""
    target = bench.PROFILES["target"]
    history = bench.build_state(target.seen, target.deliveries, span_days=target.span_days, seed=1)

    news = {identifier for item in bench._news(core.DELIVERY_CAP, bench.NOW) for identifier in item.explicit}

    assert len(news) == core.DELIVERY_CAP
    assert not news & set(history["seen"])


# --- what is measured -------------------------------------------------------------------------------------------


def test_a_pass_saves_the_document_once_per_stage_and_once_per_acknowledgement(tiny_report):
    """The deployment guide states ``sources + 3 + delivered messages``: this is the pass it was counted from."""
    for row in stores(tiny_report):
        idle, full = row["passes"]["idle"], row["passes"]["full"]

        assert (idle["delivered"], idle["saves"], idle["acknowledgements"]) == (0, 1 + 3, 0)
        assert full["delivered"] == core.DELIVERY_CAP
        assert full["saves"] == 1 + 3 + core.DELIVERY_CAP
        assert full["acknowledgements"] == core.DELIVERY_CAP, "one save follows each message that went out"
        assert 0 < idle["saving_seconds"] <= idle["seconds"]
        assert 0 < full["saving_seconds"] <= full["seconds"]


def test_every_save_of_the_json_store_writes_the_whole_document(tiny_report):
    if not tiny_report["environment"]["bytes_written_known"]:
        pytest.skip("this kernel does not count the bytes a process writes")
    [row] = [row for row in stores(tiny_report) if row["store"] == "json"]

    for kind in ("idle", "full"):
        run = row["passes"][kind]
        assert len(run["x_document"]) == run["saves"]
        # The multiples are of the document as the pass found it, and a history of a few dozen records grows by a
        # fifth while a pass delivers five messages into it: the upper bound allows for that, and still says "once".
        assert all(0.9 <= multiple <= 1.3 for multiple in run["x_document"]), "a save is the whole text, once"
        assert run["written_bytes"] == sum(run["save_bytes"])


def test_an_acknowledgement_of_either_store_writes_at_least_the_whole_document(tiny_report):
    """What one message costs is measured on the saves that acknowledge it, not taken from the totals of two passes."""
    if not tiny_report["environment"]["bytes_written_known"]:
        pytest.skip("this kernel does not count the bytes a process writes")

    for row in stores(tiny_report):
        passes = row["passes"]
        acknowledged = passes["full"]["acknowledgement_bytes"]

        assert len(acknowledged) == core.DELIVERY_CAP
        assert passes["idle"]["acknowledgement_bytes"] == []
        assert passes["per_acknowledgement_bytes"] == pytest.approx(statistics.fmean(acknowledged))
        assert passes["per_acknowledgement_bytes"] >= 0.9 * row["document_bytes"], row["store"]
    assert "one acknowledgement wrote" in bench.render(tiny_report)


class FakeKernel:
    """A store that writes as many bytes as a document says, and the count of messages a pass has sent.

    The test sets ``sent`` as a pass would, and reads the written bytes through ``bench._written_bytes``.
    """

    def __init__(self) -> None:
        self.written = 0
        self.sent = 0

    def save(self, document: dict) -> None:
        self.written += document["bytes"]

    def load(self) -> None:
        return None

    def counting_store(self):
        return bench._CountingStore(self, lambda: self.sent)


def test_the_first_save_after_a_message_went_out_is_its_acknowledgement(monkeypatch):
    kernel = FakeKernel()
    monkeypatch.setattr(bench, "_written_bytes", lambda: kernel.written)
    counting = kernel.counting_store()

    counting.save({"bytes": 10})  # before any message
    kernel.sent = 1
    counting.save({"bytes": 20})  # the acknowledgement of the first message
    kernel.sent = 3
    counting.save({"bytes": 30})  # two messages went out before this save, and it is one save
    counting.save({"bytes": 40})  # after delivery: no message went out since the last save

    assert counting.bytes_per_save == [10, 20, 30, 40]
    assert counting.acknowledgements == [20, 30]


def test_a_byte_count_the_kernel_does_not_give_is_left_unknown_rather_than_guessed(monkeypatch):
    kernel = FakeKernel()
    monkeypatch.setattr(bench, "_written_bytes", lambda: None)
    counting = kernel.counting_store()

    kernel.sent = 1
    counting.save({"bytes": 10})

    assert counting.bytes_per_save == [None]
    assert counting.acknowledgements == [None]
    assert bench._known(counting.bytes_per_save) is None
    assert bench._known([3, 4]) == [3, 4]


def test_the_pages_answer_and_are_timed(tiny_report):
    for row in stores(tiny_report):
        for page in ("alerts", "alerts_filtered", "advisory"):
            assert row["pages"][page]["median"] > 0, page
        assert row["pages"]["alerts_peak_mib"] >= 0


def test_the_first_pass_archives_what_is_past_the_line_and_the_stores_measure_what_is_left(tiny_report):
    [profile] = tiny_report["profiles"]
    retention = profile["retention"]

    assert retention["retired"] > 0
    assert retention["retired"] + retention["live_deliveries"] == 12
    assert retention["archive_bytes"] > 0
    assert retention["state_bytes_after"] < retention["state_bytes_before"]
    assert {row["store"] for row in profile["stores"]} == {"json", "sqlite"}
    assert {row["live_deliveries"] for row in profile["stores"]} == {retention["live_deliveries"]}


class RecordingStore:
    """Remembers the text of each document it is asked to save."""

    def __init__(self) -> None:
        self.texts: list[str] = []

    def save(self, document: dict) -> None:
        self.texts.append(json.dumps(document, sort_keys=True))

    def load(self) -> None:
        return None


def test_the_timed_saves_are_of_documents_that_differ_and_the_history_is_put_back():
    """SQLite writes nothing for a row whose new text is the old: timing the same text would time a no-op."""
    kept = RecordingStore()
    history = bench.build_state(60, 12, span_days=100, seed=1)
    original = json.dumps(history, sort_keys=True)

    timings = bench.time_load_and_save(kept, history, repeat=2, now=bench.NOW)

    # Two saves are timed, one is measured for memory, and the last puts the history back.
    assert len(kept.texts) == 4
    assert len(set(kept.texts[:3])) == 3, "no two measured saves write the same text"
    assert original not in kept.texts[:3]
    assert kept.texts[3] == original, "the store holds the history as it was built when the timing is done"
    assert json.dumps(history, sort_keys=True) == original, "the history that was handed in is what it was"
    assert timings["save"]["runs"] == 2 and timings["load"]["runs"] == 2


def test_the_fsync_probe_reports_a_time_and_leaves_nothing_behind(tmp_path):
    assert bench._fsync_ms(tmp_path, samples=2) > 0
    assert list(tmp_path.iterdir()) == []


# --- the report and the exit code -------------------------------------------------------------------------------


def test_the_report_names_each_table_and_each_store(tiny_report):
    text = bench.render(tiny_report)

    for heading in (
        "State size and latency",
        "Python memory above the baseline",
        "What a pass writes",
        "per save, x document",
        "What the first pass archives",
        "Budget: /alerts under 1.0 s, a save under 2.0 s.",
    ):
        assert heading in text
    assert "| json |" in text and "| sqlite |" in text


def test_the_report_still_renders_where_the_kernel_does_not_count_bytes(tiny_report):
    report = copy.deepcopy(tiny_report)
    for row in stores(report):
        for kind in ("idle", "full"):
            row["passes"][kind].update(written_bytes=None, save_bytes=None, acknowledgement_bytes=None, x_document=None)
        row["passes"]["per_acknowledgement_bytes"] = None

    text = bench.render(report)

    assert "n/a" in text
    assert "one acknowledgement wrote" not in text


def test_the_budget_check_passes_inside_the_budgets_and_fails_outside_them():
    def profile(alerts: float, save: float) -> list[dict]:
        row = {"store": "json", "pages": {"alerts": {"median": alerts}}, "save": {"median": save}}
        return [{"profile": "p", "stores": [row]}]

    assert bench._budget(profile(0.5, 1.0), 1.0, 2.0)["rows"][0]["ok"] is True
    assert bench._budget(profile(1.5, 1.0), 1.0, 2.0)["rows"][0]["ok"] is False, "/alerts is too slow"
    assert bench._budget(profile(0.5, 2.5), 1.0, 2.0)["rows"][0]["ok"] is False, "the save is too slow"


def test_check_exits_1_when_a_row_misses_a_budget_and_0_when_it_does_not(tmp_path, monkeypatch, tiny_report):
    measured = tiny_report["profiles"][0]
    monkeypatch.setattr(bench, "measure_profile", lambda *args, **kwargs: measured)
    monkeypatch.setattr(bench, "_fsync_ms", lambda directory, samples=20: 1.0)
    arguments = [*TINY, "--check", "--workdir", str(tmp_path)]

    code, text = run_main([*arguments, "--alerts-budget", "0"])
    assert code == 1
    assert "FAIL" in text

    code, text = run_main([*arguments, "--alerts-budget", "60", "--save-budget", "60"])
    assert code == 0
    assert "PASS" in text
    assert list(tmp_path.iterdir()) == [], "the stores it wrote are removed"


@pytest.mark.parametrize(
    "arguments",
    [
        ["--stores", "oracle"],
        ["--stores", ""],
        ["--profiles", "huge"],
        ["--repeat", "0"],
        ["--seen", "5", "--deliveries", "6"],
    ],
)
def test_arguments_that_cannot_be_measured_exit_2_before_anything_is_written(arguments, tmp_path, capsys):
    assert bench.main([*arguments, "--workdir", str(tmp_path)]) == 2
    assert capsys.readouterr().err.strip()
    assert list(tmp_path.iterdir()) == []
