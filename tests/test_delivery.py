"""Delivery tests: the pure planning rules and the delivery step that consumes them.

The planning half of the module under test is pure, so those tests are plain dicts and an explicit epoch: no
state file, no notifier and no HTTP. The delivery tests below drive ``core.deliver`` with recording notifiers.
"""

from __future__ import annotations

import datetime

import pytest

from advisory_radar import core, delivery
from advisory_radar.config import DEFAULT_THRESHOLDS


def entry(
    title: str = "WARNING: an advisory",
    ids: object = ("CVE-2026-1",),
    tag: str = "warning",
    **extra: object,
) -> dict:
    """One queue entry, shaped like ``core.classify_new`` writes it."""
    return {
        "title": title,
        "body": "\n- **Severity:** CVSS 7.5",
        "tag": tag,
        "kind": "new",
        "ids": list(ids) if isinstance(ids, (list, tuple)) else ids,
        "link": "https://vendor.example/advisory",
        "source": "vendor.example",
        **extra,
    }


def at(hour: int, minute: int = 0) -> int:
    """An epoch on a fixed UTC day, so a window test never depends on the machine's zone."""
    return int(datetime.datetime(2026, 11, 11, hour, minute, tzinfo=datetime.UTC).timestamp())


def bullet_lines(body: str) -> list[str]:
    return [line for line in body.splitlines() if line.startswith("- ")]


class TestDigest:
    def test_one_message_covers_every_entry(self):
        entries = [
            entry("WARNING: first advisory", ("CVE-2026-1",)),
            entry("CRITICAL: second advisory", ("CVE-2026-2", "CVE-2026-3"), tag="critical"),
        ]
        message = delivery.digest_message(entries)
        assert message["title"] == "CRITICAL: digest of 2 advisories"
        assert message["kind"] == "digest"
        assert message["tag"] == "critical"
        assert message["ids"] == ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"]
        assert message["link"] == "" and message["source"] == "digest"
        assert len(bullet_lines(message["body"])) == 2
        assert "first advisory" in message["body"] and "second advisory" in message["body"]

    def test_a_digest_of_warnings_stays_a_warning(self):
        message = delivery.digest_message([entry(), entry("WARNING: another")])
        assert message["tag"] == "warning"
        assert message["title"] == "WARNING: digest of 2 advisories"

    def test_the_line_cap_holds_and_the_rest_are_counted(self):
        message = delivery.digest_message([entry(f"WARNING: advisory {index}", ()) for index in range(25)])
        lines = bullet_lines(message["body"])
        assert len(lines) == delivery.DIGEST_MAX_LINES == 20
        assert "(+5 more not listed)" in message["body"]
        assert "advisory 19" in message["body"] and "advisory 20" not in message["body"]

    def test_the_character_budget_holds_and_trims_from_the_end(self):
        # A title long enough to be capped still leaves the budget finite; each of these lines is ~155 chars, so
        # the 1900-character Discord message cannot hold all twenty.
        entries = [entry("WARNING: " + "x" * 300, ("CVE-2026-1",)) for _ in range(20)]
        message = delivery.digest_message(entries)
        assert len(message["body"]) <= delivery.DIGEST_BODY_LIMIT - len(message["title"])
        lines = bullet_lines(message["body"])
        omitted = int(message["body"].rsplit("(+", 1)[1].split(" ", 1)[0])
        assert 0 < len(lines) < 20
        assert len(lines) + omitted == 20, "every covered advisory is either listed or counted"
        assert len(lines[0]) < 200, "one pathological title cannot fill the message"

    def test_ids_are_the_union_in_first_seen_order(self):
        entries = [
            entry(ids=("CVE-2026-2", "src:vendor")),
            entry(ids=("CVE-2026-1", "CVE-2026-2")),
        ]
        message = delivery.digest_message(entries)
        assert message["ids"] == ["CVE-2026-2", "src:vendor", "CVE-2026-1"]
        # The internal de-duplication marker is not an advisory name, so the line does not show it.
        assert "src:vendor" not in message["body"]

    def test_a_single_entry_still_makes_a_valid_digest(self):
        message = delivery.digest_message([entry("CRITICAL: one advisory", ("CVE-2026-9",), tag="critical")])
        assert message["title"] == "CRITICAL: digest of 1 advisory"
        assert message["tag"] == "critical" and message["kind"] == "digest"
        assert message["ids"] == ["CVE-2026-9"]
        assert len(bullet_lines(message["body"])) == 1
        assert "one advisory" in message["body"]

    def test_a_title_cannot_forge_an_extra_line(self):
        message = delivery.digest_message([entry("WARNING: first\n- **forged**"), entry("WARNING: second")])
        lines = bullet_lines(message["body"])
        assert len(lines) == 2
        assert "forged" in lines[0] and "forged" not in lines[1]

    def test_a_damaged_entry_does_not_break_the_digest(self):
        message = delivery.digest_message([{"title": None, "ids": "CVE-2026-1"}, {"ids": None, "tag": 7}])
        assert message["tag"] == "warning"
        assert message["ids"] == []
        assert len(bullet_lines(message["body"])) == 2
        assert "(untitled advisory)" in message["body"]

    def test_a_digest_needs_at_least_one_entry(self):
        with pytest.raises(ValueError):
            delivery.digest_message([])


class TestQuietHoursParser:
    def test_a_window_that_wraps_midnight(self):
        window = delivery.parse_quiet_hours("22:00-07:00")
        assert window == delivery.QuietHours(22 * 60, 7 * 60)
        assert window.contains(23 * 60) and window.contains(0) and window.contains(6 * 60 + 59)
        assert not window.contains(7 * 60) and not window.contains(21 * 60 + 59)

    def test_a_window_inside_one_day(self):
        window = delivery.parse_quiet_hours("09:00-17:00")
        assert window == delivery.QuietHours(9 * 60, 17 * 60)
        assert window.contains(12 * 60) and not window.contains(17 * 60) and not window.contains(8 * 60 + 59)

    def test_equal_bounds_are_an_empty_window(self):
        window = delivery.parse_quiet_hours("00:00-00:00")
        assert window == delivery.QuietHours(0, 0)
        assert not any(window.contains(minute) for minute in (0, 12 * 60, 23 * 60))

    def test_surrounding_space_is_tolerated(self):
        assert delivery.parse_quiet_hours(" 22:00-07:00 ") == delivery.QuietHours(22 * 60, 7 * 60)

    @pytest.mark.parametrize(
        "value",
        [
            "22:00",
            "22:00-",
            "22:00-07:00-01:00",
            "24:00-07:00",
            "22:60-07:00",
            "7:00-22:00",
            "2200-0700",
            "",
            None,
            2200,
            ["22:00-07:00"],
        ],
    )
    def test_a_bad_shape_is_refused_with_the_expected_form(self, value):
        with pytest.raises(ValueError) as caught:
            delivery.parse_quiet_hours(value)
        assert "22:00-07:00" in str(caught.value)
        assert "HH:MM" in str(caught.value)

    def test_a_refusal_never_repeats_the_value(self):
        for value in ("night-shift", "22:00-07:00-window", 2200):
            with pytest.raises(ValueError) as caught:
                delivery.parse_quiet_hours(value)
            assert str(value) not in str(caught.value)


class TestIsHeld:
    window = delivery.parse_quiet_hours("22:00-07:00")

    def test_a_warning_inside_the_window_waits(self):
        for hour, minute in ((22, 0), (23, 30), (0, 0), (6, 59)):
            assert delivery.is_held(at(hour, minute), entry(), self.window, datetime.UTC), (hour, minute)

    def test_a_warning_outside_the_window_goes(self):
        for hour, minute in ((7, 0), (12, 0), (21, 59)):
            assert not delivery.is_held(at(hour, minute), entry(), self.window, datetime.UTC), (hour, minute)

    def test_a_critical_is_never_held(self):
        critical = entry("CRITICAL: an exploited advisory", tag="critical")
        assert not delivery.is_held(at(23, 30), critical, self.window, datetime.UTC)
        assert not delivery.is_held(at(3, 0), critical, self.window, datetime.UTC)

    def test_no_window_holds_nothing(self):
        assert not delivery.is_held(at(23, 30), entry(), None, datetime.UTC)

    def test_a_window_inside_one_day_holds_only_its_own_hours(self):
        window = delivery.parse_quiet_hours("09:00-17:00")
        assert delivery.is_held(at(9, 0), entry(), window, datetime.UTC)
        assert delivery.is_held(at(16, 59), entry(), window, datetime.UTC)
        assert not delivery.is_held(at(17, 0), entry(), window, datetime.UTC)
        assert not delivery.is_held(at(8, 59), entry(), window, datetime.UTC)
        assert not delivery.is_held(at(23, 0), entry(), window, datetime.UTC)

    def test_an_empty_window_holds_nothing(self):
        window = delivery.parse_quiet_hours("00:00-00:00")
        assert not delivery.is_held(at(23, 0), entry(), window, datetime.UTC)

    def test_an_entry_with_no_readable_tag_waits(self):
        # The tag is a closed set, so a damaged entry is no evidence of severity; the wait still ends with the
        # window, which is safer than treating unreadable state as an alarm.
        assert delivery.is_held(at(23, 0), {"title": "t"}, self.window, datetime.UTC)


class TestPlan:
    window = delivery.parse_quiet_hours("22:00-07:00")

    def test_without_digest_each_sent_entry_is_its_own_batch_in_order(self):
        entries = [entry(f"WARNING: {index}", (f"CVE-2026-{index}",)) for index in range(3)]
        batches = delivery.plan(entries, at(12), digest=False)
        assert [batch.entries[0]["title"] for batch in batches] == [item["title"] for item in entries]
        assert all(batch.message is None for batch in batches)
        assert [len(batch.entries) for batch in batches] == [1, 1, 1]

    def test_digest_turns_the_whole_pass_into_one_batch(self):
        entries = [entry(f"WARNING: {index}", (f"CVE-2026-{index}",)) for index in range(3)]
        batches = delivery.plan(entries, at(12), digest=True)
        assert len(batches) == 1
        assert batches[0].entries == tuple(entries)
        message = batches[0].message
        assert message is not None and message["kind"] == "digest"
        assert [line for line in message["body"].splitlines() if line.startswith("- ")] == [
            f"- **WARNING: {index}** (CVE-2026-{index})" for index in range(3)
        ]

    def test_held_entries_stay_out_of_every_batch(self):
        critical = entry("CRITICAL: exploited", ("CVE-2026-9",), tag="critical")
        warning = entry("WARNING: routine", ("CVE-2026-1",))
        batches = delivery.plan([warning, critical], at(23), digest=False, quiet=self.window, tz=datetime.UTC)
        assert [batch.entries[0]["title"] for batch in batches] == ["CRITICAL: exploited"]

    def test_digest_and_quiet_hours_still_hold_warnings(self):
        entries = [
            entry("WARNING: held one", ("CVE-2026-1",)),
            entry("CRITICAL: sent", ("CVE-2026-2",), tag="critical"),
            entry("WARNING: held two", ("CVE-2026-3",)),
        ]
        batches = delivery.plan(entries, at(23), digest=True, quiet=self.window, tz=datetime.UTC)
        assert len(batches) == 1
        assert [item["title"] for item in batches[0].entries] == ["CRITICAL: sent"]
        message = batches[0].message
        assert message is not None
        assert message["tag"] == "critical"
        assert message["title"] == "CRITICAL: digest of 1 advisory"
        assert message["ids"] == ["CVE-2026-2"]
        assert "held one" not in message["body"] and "held two" not in message["body"]

    def test_quiet_hours_hold_a_warning_but_not_a_critical_at_night(self):
        entries = [entry(), entry("CRITICAL: sent", tag="critical")]
        batches = delivery.plan(entries, at(23), quiet=self.window, tz=datetime.UTC)
        assert [batch.entries[0]["tag"] for batch in batches] == ["critical"]

    def test_daytime_releases_everything(self):
        entries = [entry(), entry("CRITICAL: sent", tag="critical")]
        batches = delivery.plan(entries, at(12), quiet=self.window, tz=datetime.UTC)
        assert [batch.entries[0]["tag"] for batch in batches] == ["warning", "critical"]

    def test_everything_held_is_an_empty_plan(self):
        assert delivery.plan([entry(), entry()], at(23), quiet=self.window, tz=datetime.UTC) == []
        assert delivery.plan([entry()], at(23), digest=True, quiet=self.window, tz=datetime.UTC) == []

    def test_an_empty_queue_is_an_empty_plan(self):
        assert delivery.plan([], at(12)) == []

    def test_the_same_inputs_always_produce_the_same_plan(self):
        entries = [entry(f"WARNING: {index}") for index in range(4)]
        first = delivery.plan(entries, at(12), digest=True)
        second = delivery.plan(entries, at(12), digest=True)
        assert first == second
        assert first[0].message == delivery.digest_message(entries)


# --- the delivery step -------------------------------------------------------------------------


NOW = 1_792_600_000


class Recorder:
    """Accepts or refuses everything and remembers the messages it was given, with no network."""

    def __init__(self, notifier_id: str = "ops", status: int = 200) -> None:
        self.id = notifier_id
        self.status = status
        self.sent: list[dict] = []

    def send(self, entry: dict, http) -> int:
        self.sent.append(entry)
        return self.status


def no_http(*args):
    return 404, {}, b""


def queued(cve: str, tag: str = "warning", source_id: str = "vendor") -> dict:
    """A queue entry shaped like ``core.classify_new`` writes it, complete enough for ``_delivered``."""
    return {
        "kind": "new",
        "tag": tag,
        "title": f"{tag.upper()}: {cve} in widget",
        "body": f"\n- **IDs:** {cve}",
        "ids": [cve],
        "cves": [cve],
        "levels": {cve: tag},
        "kev_only": [],
        "scores": {cve: 7.5},
        "thresholds": [9.0, 0.10, 4.0],
        "source": "Vendor",
        "link": f"https://vendor.example/{cve}",
        "source_id": source_id,
    }


def local_at(hour: int, minute: int = 0) -> int:
    """An epoch whose *local* wall clock is this time: the quiet window is local-time by definition."""
    return int(datetime.datetime(2026, 11, 11, hour, minute).timestamp())


def test_the_features_off_send_one_message_per_entry():
    """The default path is the message-by-message loop, so an untouched installation is unchanged."""
    state = core.new_state()
    state["pending"] = [queued("CVE-2026-1"), queued("CVE-2026-2", "critical"), queued("CVE-2026-3")]
    ops = Recorder()
    assert core.deliver(state, [ops], no_http, NOW) is True
    assert [message["kind"] for message in ops.sent] == ["new", "new", "new"]
    assert state["pending"] == []


def test_three_queued_advisories_become_one_digest_post():
    state = core.new_state()
    state["pending"] = [queued("CVE-2026-1"), queued("CVE-2026-2", "critical"), queued("CVE-2026-3")]
    ops = Recorder()
    assert core.deliver(state, [ops], no_http, NOW, digest=True) is True
    assert len(ops.sent) == 1, "one POST for the whole routing group"
    message = ops.sent[0]
    assert message["kind"] == "digest"
    assert message["tag"] == "critical"
    assert message["title"] == "CRITICAL: digest of 3 advisories"
    assert message["ids"] == ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"]
    assert state["pending"] == []
    assert set(state["seen"]) == {"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"}
    assert all(state["seen"][cve]["outcome"] == "delivered" for cve in state["seen"])
    assert len(state["deliveries"]) == 3, "every covered entry keeps its own delivery record"
    assert all(snapshot["delivered_to"] == ["ops"] for snapshot in state["deliveries"].values())


def test_a_digest_never_mixes_two_routing_groups():
    state = core.new_state()
    state["pending"] = [queued("CVE-2026-1", source_id="one"), queued("CVE-2026-2", source_id="two")]
    routes = [
        {"match": {"source": "one"}, "notifiers": ["ops"]},
        {"match": {"source": "two"}, "notifiers": ["phone"]},
    ]
    ops, phone = Recorder("ops"), Recorder("phone")
    assert core.deliver(state, [ops, phone], no_http, NOW, digest=True, routes=routes) is True
    assert len(ops.sent) == 1 and len(phone.sent) == 1, "two groups are two POSTs"
    assert ops.sent[0]["ids"] == ["CVE-2026-1"]
    assert phone.sent[0]["ids"] == ["CVE-2026-2"]
    assert "CVE-2026-2" not in ops.sent[0]["body"], "an advisory never travels to a channel it did not route to"
    assert state["pending"] == []


def test_quiet_hours_hold_a_warning_while_a_critical_goes_out_then_release_it():
    window = delivery.parse_quiet_hours("22:00-07:00")
    state = core.new_state()
    state["pending"] = [queued("CVE-2026-1"), queued("CVE-2026-2", "critical")]
    ops = Recorder()
    assert core.deliver(state, [ops], no_http, local_at(23), quiet_hours=window) is True
    assert [message["tag"] for message in ops.sent] == ["critical"], "the critical is never held"
    assert [entry["ids"][0] for entry in state["pending"]] == ["CVE-2026-1"]
    held = state["pending"][0]
    assert held.get("attempts", 0) == 0, "a held message is not a failed attempt"
    assert "first_attempt_at" not in held, "a held message was never attempted"
    assert core.deliver(state, [ops], no_http, local_at(12), quiet_hours=window) is True
    assert len(ops.sent) == 2 and ops.sent[1]["tag"] == "warning"
    assert state["pending"] == []


def test_quiet_hours_holding_everything_is_not_a_failed_pass():
    window = delivery.parse_quiet_hours("22:00-07:00")
    state = core.new_state()
    state["pending"] = [queued("CVE-2026-1"), queued("CVE-2026-2")]
    ops = Recorder()
    assert core.deliver(state, [ops], no_http, local_at(23), quiet_hours=window) is True
    assert ops.sent == [] and len(state["pending"]) == 2
    assert all("attempts" not in entry for entry in state["pending"])


def test_a_delivered_message_records_one_event_with_its_time_and_outcome():
    state = core.new_state()
    state["pending"].append(queued("CVE-2026-1"))
    assert core.deliver(state, [Recorder()], no_http, NOW) is True
    record = state["seen"]["CVE-2026-1"]
    event = state["deliveries"][record["delivery"]]
    assert event["at"] == NOW and event["outcome"] == "delivered"
    assert event["delivered_to"] == ["ops"] and event["kind"] == "new"
    assert [stored["kind"] for _, stored in core.delivery_events(state, "CVE-2026-1")] == ["new"]


def test_an_escalation_is_added_beside_the_first_seen_record():
    state = core.new_state()
    state["pending"].append(queued("CVE-2026-1"))
    recorder = Recorder()
    assert core.deliver(state, [recorder], no_http, NOW) is True
    first = dict(state["seen"]["CVE-2026-1"])
    state["pending"].append(
        {
            "kind": "escalation",
            "tag": "critical",
            "title": "CRITICAL: CVE-2026-1 now CRITICAL",
            "body": "\n- **Severity:** CVSS 9.8",
            "ids": ["CVE-2026-1"],
            "cves": ["CVE-2026-1"],
            "levels": {},
            "scores": {"CVE-2026-1": 9.8},
            "thresholds": [9.0, 0.10, 4.0],
            "source": "Vendor",
            "link": "https://vendor.example/CVE-2026-1",
        }
    )
    assert core.deliver(state, [recorder], no_http, NOW + 60) is True
    assert state["seen"]["CVE-2026-1"] == first, "the first-seen record is never rewritten"
    assert state["watch"]["CVE-2026-1"]["level"] == "critical"
    events = core.delivery_events(state, "CVE-2026-1")
    assert [event["kind"] for _, event in events] == ["escalation", "new"]
    assert events[0][1]["at"] == NOW + 60 and events[0][1]["outcome"] == "delivered"
    assert events[0][1]["delivered_to"] == ["ops"]


def test_an_adobe_bulletin_keeps_an_event_without_a_seen_record():
    state = core.new_state()
    state["pending"].append(
        {
            "kind": "adobe",
            "tag": "critical",
            "title": "CRITICAL: APSB26-1 Adobe Commerce",
            "body": "",
            "ids": ["APSB26-1"],
            "cves": [],
            "levels": {},
            "source": "Adobe Commerce APSB26-1",
            "link": "https://helpx.adobe.com/security/products/magento/apsb26-1.html",
        }
    )
    assert core.deliver(state, [Recorder()], no_http, NOW) is True
    assert "APSB26-1" not in state["seen"], "a bulletin never becomes a first-seen record"
    events = core.delivery_events(state, "APSB26-1")
    assert len(events) == 1 and events[0][1]["kind"] == "adobe"
    assert events[0][1]["delivered_to"] == ["ops"]
    assert core.delivery_events(state, "CVE-2026-404") == []


def test_a_dropped_escalation_is_kept_as_a_dropped_event():
    state = core.new_state()
    state["watch"]["CVE-2026-1"] = {
        "since": NOW,
        "last_eval": NOW,
        "level": "warning",
        "judged": "warning",
        "title": "Vendor",
        "link": "https://vendor.example/CVE-2026-1",
        "thresholds": [9.0, 0.10, 4.0],
    }
    core._delivered(
        state,
        {
            "kind": "escalation",
            "tag": "critical",
            "title": "CRITICAL: CVE-2026-1 now CRITICAL",
            "body": "",
            "ids": ["CVE-2026-1"],
            "cves": ["CVE-2026-1"],
            "levels": {},
            "scores": {},
            "source": "Vendor",
            "link": "https://vendor.example/CVE-2026-1",
        },
        NOW,
        outcome="dropped",
    )
    assert state["seen"] == {}, "a dropped escalation was never sent, so no seen record is invented"
    events = core.delivery_events(state, "CVE-2026-1")
    assert events[0][1]["outcome"] == "dropped" and events[0][1]["delivered_to"] == []


def test_a_failed_digest_marks_one_attempt_per_covered_entry_and_retries_only_the_failing_channel():
    state = core.new_state()
    state["pending"] = [queued("CVE-2026-1"), queued("CVE-2026-2")]
    good, bad = Recorder("good"), Recorder("bad", status=500)
    assert core.deliver(state, [good, bad], no_http, NOW, digest=True) is False
    assert [entry["attempts"] for entry in state["pending"]] == [1, 1], "one POST is one attempt for each entry"
    assert [entry["last_status"] for entry in state["pending"]] == [500, 500]
    assert [entry["sent_to"] for entry in state["pending"]] == [["good"], ["good"]]
    assert len(good.sent) == 1 and len(bad.sent) == 1, "the digest was posted once, not once per advisory"
    assert good.sent[0]["ids"] == ["CVE-2026-1", "CVE-2026-2"]

    assert core.deliver(state, [good, bad], no_http, NOW + 1, digest=True) is False
    assert len(good.sent) == 1, "a channel that accepted the digest is not sent it twice"
    assert len(bad.sent) == 2
    assert [entry["attempts"] for entry in state["pending"]] == [2, 2]

    # The third failed attempt parks every covered entry, and the pass then continues rather than stopping.
    assert core.deliver(state, [good, bad], no_http, NOW + 2, digest=True) is True
    assert state["pending"] == [] and len(state["parked"]) == 2


def test_a_critical_escalation_is_selected_ahead_of_five_held_warnings():
    """A full queue of held warnings must not take the delivery window's slots from a critical advisory."""
    window = delivery.parse_quiet_hours("22:00-07:00")
    night = local_at(23)
    state = core.new_state()
    state["pending"] = [queued(f"CVE-2026-{number}") for number in range(1, 6)]
    cve = "CVE-2026-9000"
    state["watch"][cve] = {
        "since": night - 3 * 86400,
        "last_eval": night - 2 * 86400,
        "level": "warning",
        "title": "vendored widget",
        "link": "https://vendor.example/9000",
        "cvss": 7.5,
    }

    class EscalatingIntel:
        """One CVE, measured remote and unauthenticated at CVSS 9.5, with no cache and no network."""

        def cves(self, cves, **ignored):
            return {identifier: core.CveFacts(9.5, None, 0.5, None, True, remote_unauth=True) for identifier in cves}

    core.reevaluate(state, EscalatingIntel(), frozenset(), True, night, "", thresholds=DEFAULT_THRESHOLDS)
    assert [entry["kind"] for entry in state["pending"]] == ["new"] * 5 + ["escalation"]
    assert state["pending"][-1]["tag"] == "critical"

    ops = Recorder()
    assert core.deliver(state, [ops], no_http, night, quiet_hours=window) is True
    assert [message["kind"] for message in ops.sent] == ["escalation"], "the critical behind the held warnings goes"
    assert ops.sent[0]["tag"] == "critical"
    assert [entry["ids"][0] for entry in state["pending"]] == [f"CVE-2026-{number}" for number in range(1, 6)]
    assert all("attempts" not in entry for entry in state["pending"]), "held warnings are not attempts"
    assert state["watch"][cve]["level"] == "critical", "the delivery advanced the watch record"


def test_a_partially_acknowledged_digest_does_not_resend_the_entries_it_already_delivered():
    state = core.new_state()
    state["pending"] = [queued("CVE-2026-1"), queued("CVE-2026-2")]
    good, bad = Recorder("good"), Recorder("bad", status=500)
    assert core.deliver(state, [good, bad], no_http, NOW, digest=True) is False
    assert [message["ids"] for message in good.sent] == [["CVE-2026-1", "CVE-2026-2"]]
    assert [entry["sent_to"] for entry in state["pending"]] == [["good"], ["good"]]

    state["pending"].append(queued("CVE-2026-3"))
    assert core.deliver(state, [good, bad], no_http, NOW + 1, digest=True) is False
    assert [message["ids"] for message in good.sent] == [
        ["CVE-2026-1", "CVE-2026-2"],
        ["CVE-2026-3"],
    ], "good already accepted the first two, so its redelivery carries only the new advisory"
    assert [message["ids"] for message in bad.sent] == [
        ["CVE-2026-1", "CVE-2026-2"],
        ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"],
    ], "bad never accepted anything, so its digest is the whole group"
    assert [entry["sent_to"] for entry in state["pending"]] == [["good"], ["good"], ["good"]]
    assert [entry["attempts"] for entry in state["pending"]] == [2, 2, 1]


def test_equivalent_destination_sets_share_one_digest():
    state = core.new_state()
    state["pending"] = [queued("CVE-2026-1", source_id="one"), queued("CVE-2026-2", source_id="two")]
    routes = [
        {"match": {"source": "one"}, "notifiers": ["ops", "phone"]},
        {"match": {"source": "two"}, "notifiers": ["phone", "ops"]},
    ]
    ops, phone = Recorder("ops"), Recorder("phone")
    assert core.deliver(state, [ops, phone], no_http, NOW, digest=True, routes=routes) is True
    assert len(ops.sent) == 1 and len(phone.sent) == 1, "the same destination set is one group, whatever its order"
    assert ops.sent[0]["ids"] == ["CVE-2026-1", "CVE-2026-2"]
    assert phone.sent[0]["ids"] == ["CVE-2026-1", "CVE-2026-2"]
    assert state["pending"] == []


def test_a_full_parked_queue_still_accounts_for_every_entry_in_the_failed_digest():
    """The failed POST covered every entry, so a refused park must not leave a later entry unaccounted."""
    state = core.new_state()
    first = queued("CVE-2026-1")
    first.update({"attempts": 2, "first_attempt_at": NOW - 600})
    second = queued("CVE-2026-2")
    state["pending"] = [first, second]
    state["parked"] = [
        {"title": f"parked {number}", "ids": [f"CVE-2026-{number}"]} for number in range(core.MAX_PARKED)
    ]
    ops = Recorder(status=500)

    assert core.deliver(state, [ops], no_http, NOW, digest=True) is False
    assert len(ops.sent) == 1, "one digest POST covered both entries"
    assert [entry["attempts"] for entry in state["pending"]] == [3, 1], "both entries take one attempt"
    assert [entry["last_status"] for entry in state["pending"]] == [500, 500]
    assert len(state["parked"]) == core.MAX_PARKED, "parking was blocked, so the entry stays pending"
    assert [entry["ids"][0] for entry in state["pending"]] == ["CVE-2026-1", "CVE-2026-2"]


def test_complementary_acknowledgements_let_one_entry_finish_while_the_other_keeps_its_attempt():
    state = core.new_state()
    first = queued("CVE-2026-1")
    first["sent_to"] = ["good"]
    second = queued("CVE-2026-2")
    second["sent_to"] = ["bad"]
    state["pending"] = [first, second]
    good, bad = Recorder("good"), Recorder("bad", status=500)

    assert core.deliver(state, [good, bad], no_http, NOW, digest=True) is False
    assert [message["ids"] for message in good.sent] == [["CVE-2026-2"]], "good needs only the entry it lacks"
    assert [message["ids"] for message in bad.sent] == [["CVE-2026-1"]], "bad needs only the entry it lacks"
    assert [entry["ids"][0] for entry in state["pending"]] == ["CVE-2026-1"]
    assert state["pending"][0]["attempts"] == 1
    assert state["pending"][0]["last_status"] == 500
    assert state["pending"][0]["sent_to"] == ["good"], "the accepted destination is kept"
    record = state["seen"]["CVE-2026-2"]
    assert record["outcome"] == "delivered", "the entry with every destination accepted left the queue"
    assert state["deliveries"][record["delivery"]]["delivered_to"] == ["bad", "good"]
    assert "CVE-2026-1" not in state["seen"]


def test_a_retry_never_moves_the_time_a_message_was_queued():
    """``queued_at`` is the queue's clock: an attempt, successful or failed, must not rewrite it."""
    state = core.new_state()
    entry = queued("CVE-2026-1")
    entry["queued_at"] = NOW - 3600
    state["pending"] = [entry]
    assert core.deliver(state, [Recorder("bad", status=500)], no_http, NOW) is False
    assert state["pending"][0]["queued_at"] == NOW - 3600
    assert state["pending"][0]["attempts"] == 1


def test_a_legacy_entry_records_its_first_attempt_as_the_claim_clock():
    """A queue entry written before ``queued_at`` still claims at its first attempt, and the snapshot keeps it."""
    state = core.new_state()
    entry = queued("CVE-2026-1")
    entry["first_attempt_at"] = NOW - 7200
    state["pending"] = [entry]
    assert core.deliver(state, [Recorder("ops")], no_http, NOW) is True
    record = state["seen"]["CVE-2026-1"]
    assert state["deliveries"][record["delivery"]]["queued_at"] == NOW - 7200
