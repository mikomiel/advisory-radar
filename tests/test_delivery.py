"""Delivery planning tests: the digest, quiet hours and the plan that combines them.

The whole module under test is pure, so every test here is plain dicts and an explicit epoch: no state file,
no notifier and no HTTP.
"""

from __future__ import annotations

import datetime

import pytest

from advisory_radar import delivery


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
