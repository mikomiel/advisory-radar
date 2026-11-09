"""The review relay: a review must reach the gate, and the merge, without waiting for a schedule.

The behaviour lives in three declarations across workflow files, so this test is structural: it pins the
relay's shape (a no-op that may run from a head), both `workflow_run` lists, and the schedules that remain the
backstop. The failure it guards is silent: drop the relay from either list and everything still works, hours
late, which looks like nothing is wrong.
"""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def document(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text())


def triggers(name: str) -> dict:
    """The ``on:`` mapping. PyYAML reads the bare key ``on`` as the boolean True (YAML 1.1)."""
    loaded = document(name)
    return loaded["on"] if "on" in loaded else loaded[True]


def test_the_relay_is_a_no_op_that_may_run_from_a_head():
    relay = WORKFLOWS / "review-signal.yml"
    assert relay.is_file(), "the review relay is what makes a review reach the default branch"
    loaded = document("review-signal.yml")
    trigger = loaded["on"] if "on" in loaded else loaded[True]

    assert set(trigger) == {"pull_request_review"}, "only a review event may start the relay"
    assert trigger["pull_request_review"]["types"] == ["submitted", "dismissed"]
    # It runs the head's copy of this file, so it must be able to do nothing at all. No permission means the
    # token it receives can act on nothing even if the definition is rewritten.
    assert loaded.get("permissions") == {}
    for job in loaded["jobs"].values():
        assert "uses" not in job, "a reusable workflow would be a second uncontrolled trigger"
        for step in job["steps"]:
            assert set(step) == {"name", "run"}, f"a relay step may only run a command, not {sorted(step)}"


def test_the_gate_wakes_on_the_relay_and_the_merge_wakes_on_the_gate():
    gate = triggers("review-gate.yml")
    assert {"ci", "review-signal"} <= set(gate["workflow_run"]["workflows"])
    assert gate["workflow_run"]["types"] == ["completed"]
    assert gate["schedule"], "the schedule stays the backstop"

    merge = triggers("automerge.yml")
    assert {"ci", "review-gate"} <= set(merge["workflow_run"]["workflows"])
    assert merge["workflow_run"]["types"] == ["completed"]
    assert merge["schedule"], "the schedule stays the backstop"
