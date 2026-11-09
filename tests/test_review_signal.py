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
    # This file runs the head's copy of itself, so its committed shape is the whole of its safety: no
    # permission, no environment, nothing that could read the pull request. A rewritten copy can declare its
    # own permissions -- what it cannot do is decide anything, because the consumers re-derive every answer
    # from the API on the default branch. So this pins the committed configuration, not a sandbox.
    assert loaded.get("permissions") == {}
    assert "env" not in loaded, "a top-level environment could carry a secret into the no-op"
    for job_name, job in loaded["jobs"].items():
        assert set(job) == {"runs-on", "steps"}, f"{job_name} may declare only runs-on and steps, not {sorted(job)}"
        for step in job["steps"]:
            assert set(step) == {"name", "run"}, f"a relay step may only run a command, not {sorted(step)}"
            assert "${{" not in step["run"], "an expression could read the pull request"
            # Startswith would also accept "echo x; id" and "echo \"$(id)\"", so pin the one command exactly.
            assert step["run"] == 'echo "review event relayed to review-gate and automerge"', (
                "the relay may only print its one line"
            )


def test_the_gate_wakes_on_the_relay_and_the_merge_wakes_on_the_gate():
    gate = triggers("review-gate.yml")
    assert {"ci", "review-signal"} <= set(gate["workflow_run"]["workflows"])
    assert gate["workflow_run"]["types"] == ["completed"]
    assert gate["schedule"], "the schedule stays the backstop"

    merge = triggers("automerge.yml")
    assert {"ci", "review-gate"} <= set(merge["workflow_run"]["workflows"])
    assert merge["workflow_run"]["types"] == ["completed"]
    assert merge["schedule"], "the schedule stays the backstop"
