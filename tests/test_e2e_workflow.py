"""Both shipped deployment paths are started end to end, from the image the change under test builds.

``ci.yml`` builds the image and probes ``/healthz``. It does not run what README.md and docs/deployment.md tell a
user to run; ``e2e.yml`` does. These assertions pin the properties that make its result mean something, each of
which is a way such a workflow keeps passing while proving nothing:

* an image that is pulled instead of built, so the run starts the last release and not this change;
* a quadlet that is edited before it is installed, so the file a user copies is never the file that ran;
* a failing check that is swallowed (``continue-on-error``, ``|| true``, a shell that carries on after an error);
* a check that is deleted, that cannot fail (``|| :``, ``[ 1 = 1 ]``) or that compares a value no command produced;
* an action behind a mutable tag, or a job that can hold a runner for the default six hours.

The workflow is read as data, and the properties are pinned rather than the exact shell text. The exception is the
checks themselves (``CHECKS``): each comparison a job makes is pinned by its condition, because a check that quietly
changes is the failure this file exists to catch. Nothing here starts a container: the workflow does that, on
GitHub's runners.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "e2e.yml"
QUADLET = ROOT / "deploy" / "podman" / "advisory-radar.container"
UNIT = "deploy/podman/advisory-radar.container"

JOBS = ["compose", "podman-quadlet"]
MAX_TIMEOUT_MINUTES = 30
# Anchored at the line: "statuses:" also contains "uses:", and a permission key is not an action reference.
USES = re.compile(r"^[ \t]*(?:-[ \t]*)?uses:[ \t]*(\S+)", re.M)
PINNED = re.compile(r"[^@\s]+@[0-9a-f]{40}")


def document() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def steps(name: str) -> list[dict]:
    return document()["jobs"][name]["steps"]


def script(name: str) -> str:
    """The shell of every step of one job, in order."""
    return "\n".join(step["run"] for step in steps(name) if "run" in step)


def step_running(name: str, needle: str) -> dict:
    found = [step for step in steps(name) if needle in step.get("run", "")]
    assert len(found) == 1, f"{name}: exactly one step must run {needle!r}, found {len(found)}"
    return found[0]


def keys(node: object) -> Iterator[object]:
    """Every mapping key of a parsed document, at any depth."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from keys(value)
    elif isinstance(node, list):
        for item in node:
            yield from keys(item)


# --- the workflow as a whole ------------------------------------------------------------------------------------


def test_both_deployment_paths_have_a_job():
    assert set(JOBS) <= set(document()["jobs"])


def test_it_runs_for_pull_requests_pushes_to_main_and_on_demand():
    workflow = document()
    declared = workflow.get("on", workflow.get(True))  # YAML 1.1 reads the key `on` as the boolean True
    assert set(declared) == {"pull_request", "push", "workflow_dispatch"}
    assert declared["push"] == {"branches": ["main"]}


def test_the_workflow_only_reads_the_repository():
    assert document()["permissions"] == {"contents": "read"}
    for name in JOBS:
        # A job-level mapping replaces the workflow-level one instead of merging with it, so it would be the grant.
        assert "permissions" not in document()["jobs"][name], f"{name} replaces the workflow's read-only token"


@pytest.mark.parametrize("name", JOBS)
def test_every_job_is_bounded_and_runs_on_a_pinned_os_release(name: str):
    job = document()["jobs"][name]
    minutes = job.get("timeout-minutes")
    assert isinstance(minutes, int) and not isinstance(minutes, bool), f"{name} has no timeout-minutes"
    assert 1 <= minutes <= MAX_TIMEOUT_MINUTES, f"{name} may run {minutes} minutes"
    assert job["runs-on"] == "ubuntu-24.04"


def test_every_action_is_a_pinned_commit_with_its_version():
    text = WORKFLOW.read_text(encoding="utf-8")
    references = list(USES.finditer(text))
    assert references, "both jobs check out the repository, so the workflow uses at least one action"
    for match in references:
        reference = match.group(1)
        assert PINNED.fullmatch(reference), f"{reference} is a mutable reference"
        line = text[match.start() : text.index("\n", match.start())]
        assert re.search(r"#\s*v\d", line), f"{reference} is pinned without its version comment"


def test_no_failing_check_is_swallowed():
    assert "continue-on-error" not in set(keys(document())), "a failing step must fail the job"
    for name in JOBS:
        for step in steps(name):
            run = step.get("run")
            if run is None:
                continue
            label = f"{name}: {step.get('name', run.splitlines()[0])}"
            assert run.lstrip().startswith("set -euo pipefail"), f"{label} does not stop at its first error"
            assert "|| true" not in run and "set +e" not in run, f"{label} hides a failure"


# --- the image under test ---------------------------------------------------------------------------------------


def test_the_images_are_built_from_the_checkout_and_never_pulled():
    text = WORKFLOW.read_text(encoding="utf-8")
    # The compose file and the unit already name the published image; a second copy here could drift from them.
    assert "ghcr.io" not in text, "the workflow must read the image name from the files it tests"
    for pull in ("docker pull", "docker compose pull", "podman pull"):
        assert pull not in text

    compose = script("compose")
    assert "docker compose config --images" in compose, "the image name must come from the compose file"
    assert re.search(r'^docker build -t "\$image" \.$', compose, re.M), "the image is not built from the checkout"
    starts = [line for line in compose.splitlines() if line.startswith("docker compose up")]
    assert len(starts) == 2, "expected the first start and the wait after the restart"
    for line in starts:
        assert "--pull never" in line, f"{line!r} may pull the last release instead of starting the build"

    quadlet = script("podman-quadlet")
    assert re.search(rf"sed -n 's/\^Image=//p' {re.escape(UNIT)}", quadlet), "the image name must come from the unit"
    assert re.search(r'^podman build --tag "\$image" \.$', quadlet, re.M), "the image is not built from the checkout"


def test_the_unit_names_exactly_one_image():
    # The workflow reads the name with sed: a second Image= line would turn the one name into two.
    assert len(re.findall(r"^Image=", QUADLET.read_text(encoding="utf-8"), re.M)) == 1


# --- the compose job --------------------------------------------------------------------------------------------


def test_the_compose_job_follows_the_quickstart_in_a_scratch_directory():
    quickstart = step_running("compose", "mktemp -d")["run"]
    assert re.search(r'^cp docker-compose\.yml "\$scratch/?"$', quickstart, re.M)
    assert re.search(r'^cp "\$GITHUB_WORKSPACE/examples/config\.yml" config/config\.yml$', quickstart, re.M)
    # A fresh copy starts with the login token alone. The tag only points the compose file at the local build.
    assert set(re.findall(r"ADVISORY_RADAR_[A-Z_]+(?==)", quickstart)) == {
        "ADVISORY_RADAR_AUTH_TOKEN",
        "ADVISORY_RADAR_TAG",
    }
    assert "ADVISORY_RADAR_TAG=e2e" in quickstart
    assert re.search(r"^docker compose up -d --wait\b", script("compose"), re.M)


def test_the_compose_job_removes_the_project_and_its_volume_even_after_a_failure():
    assert step_running("compose", "docker compose down -v").get("if") == "always()"


# --- the quadlet job --------------------------------------------------------------------------------------------


def test_the_quadlet_is_installed_unmodified_and_the_job_is_rootless():
    install = step_running("podman-quadlet", f"cp {UNIT} ")["run"]
    assert re.search(rf"^cp {re.escape(UNIT)} ~/\.config/containers/systemd/$", install, re.M)
    # `cmp` turns "installed unmodified" from a habit of the workflow into a fact of each run.
    installed = r"~/\.config/containers/systemd/advisory-radar\.container"
    assert re.search(rf"^cmp {re.escape(UNIT)} {installed}$", install, re.M)

    shell = script("podman-quadlet")
    assert "sed -i" not in shell
    assert not re.search(r"(>>?|\btee\b[^\n]*)\s*\S*\.container\b", shell), "something writes to a unit file"
    # Podman and systemctl run as the runner user. The one thing that needs root is lingering: no login session
    # exists on a runner, so the user manager that the quadlet needs does not run without it.
    assert re.findall(r"\bsudo\s+(\S+\s+\S+)", shell) == ["loginctl enable-linger"]


def test_the_quadlet_job_reaches_the_user_manager_and_records_the_podman_version():
    # The runner image decides the Podman version and has changed it before, so every run says which one it used.
    printing = [step for step in steps("podman-quadlet") if "podman --version" in step.get("run", "")]
    assert any("if" not in step for step in printing), "the Podman version must be printed on every run"
    linger = step_running("podman-quadlet", "loginctl enable-linger")["run"]
    # systemctl --user and the unit's own Podman must agree on one runtime directory with the steps that follow.
    assert "XDG_RUNTIME_DIR=" in linger and '>> "$GITHUB_ENV"' in linger


def test_the_quadlet_is_asked_what_the_generator_makes_of_it():
    # The failure step prints the generator's reading again for the reader. This one is part of the pass: a Podman
    # that does not know a key of the unit exits non-zero here and names the key.
    dryrun = "/usr/libexec/podman/quadlet -dryrun -user"
    asked = [step for step in steps("podman-quadlet") if dryrun in step.get("run", "") and "if" not in step]
    assert len(asked) == 1, "exactly one unconditional step must run the generator"


# --- what each job asserts, and what it prints when it fails ----------------------------------------------------


@pytest.mark.parametrize(
    ("name", "restart"),
    [("compose", "docker compose restart"), ("podman-quadlet", "systemctl --user restart advisory-radar")],
)
def test_each_deployment_is_checked_where_a_user_depends_on_it(name: str, restart: str):
    shell = script(name)
    assert re.search(r'\[ "\$running" = "\$E2E_IMAGE_ID" \]', shell), "the running image is never compared"
    assert "10001 10001 10001 10001" in shell, "the application's user is never compared"
    exec_user = r"^exec_uid=\$\(\S+( compose)? exec (-T )?advisory-radar id -u\)$"
    assert re.search(exec_user, shell, re.M), "the user that exec runs as is never read"
    assert "/healthz" in shell
    # State written before the restart is read after it, which only holds if the restart sits between the two.
    # The command is matched as a whole line: an error message may quote it too.
    command = re.search(rf"^{re.escape(restart)}$", shell, re.M)
    assert command, f"{name} never runs {restart!r}"
    probe = "/data/e2e-probe"
    assert shell.index(probe) < command.start() < shell.rindex(probe)


def test_the_quadlet_job_checks_who_owns_what_the_container_writes():
    shell = script("podman-quadlet")
    assert re.search(r"stat --format %u", shell), "the host-side owner of the state is never checked"
    assert '"$(id -u)"' in shell


@pytest.mark.parametrize(
    ("name", "needles"),
    [
        ("compose", ["docker compose ps", "docker compose logs"]),
        (
            "podman-quadlet",
            [
                "systemctl --user status",
                "journalctl --user -u advisory-radar",
                "/usr/libexec/podman/quadlet -dryrun -user",
            ],
        ),
    ],
)
def test_a_failed_run_prints_what_a_reader_needs(name: str, needles: list[str]):
    diagnostics = [step for step in steps(name) if step.get("if") == "failure()"]
    assert len(diagnostics) == 1, f"{name} needs exactly one step that runs only after a failure"
    for needle in needles:
        assert needle in diagnostics[0]["run"], f"{name}: the failure output lacks {needle!r}"


# --- every check a job makes, pinned by its condition -----------------------------------------------------------

# A check that is deleted, that cannot fail, or that compares a value no command produced leaves a job that passes on a
# broken deployment: nothing in the run notices. So each check is pinned by its `[ condition ] || fail` guard and by
# the line that sets the value it compares (a short distinguishing fragment of that command, not the whole command or
# its message). A pin covers the half of the job that the restart command splits off: the same condition is checked
# once before the restart and once after it, and a pin on the whole job would stay green when one of the two went
# missing.

RESTART = {"compose": "docker compose restart", "podman-quadlet": "systemctl --user restart advisory-radar"}


def around_restart(name: str) -> dict[str, str]:
    """The shell of one job before its restart command and after it."""
    shell = script(name)
    command = re.search(rf"^{re.escape(RESTART[name])}$", shell, re.M)
    assert command, f"{name} never runs {RESTART[name]!r}"
    return {"before": shell[: command.start()], "after": shell[command.end() :]}


def reads(variable: str, source: str) -> tuple[str, str]:
    """A line that sets ``variable`` from a command whose text contains ``source``."""
    return f"{variable}=$(... {source.strip()} ...)", rf"^[ \t]*{variable}=\$\(.*{re.escape(source)}"


def demands(condition: str) -> tuple[str, str]:
    """The guard that fails the step unless ``condition`` holds. It starts its line: ``if [ ... ]`` is no guard."""
    return f"[ {condition} ] || fail", rf"^[ \t]*\[ {re.escape(condition)} \] \|\| fail\b"


def has(text: str) -> tuple[str, str]:
    """A line that is exactly ``text``, indentation aside."""
    return text, rf"^[ \t]*{re.escape(text)}$"


IMAGE = [reads("running", "{{.Image}}"), demands('"$running" = "$E2E_IMAGE_ID"')]
HEALTHZ = [reads("body", "curl "), demands('"$body" = ok')]
EXEC_USER = [reads("exec_uid", "advisory-radar id -u"), demands('"$exec_uid" = 10001')]
PID_1_USER = [
    reads("uids", "/proc/1/status"),
    has('read -r _ real effective saved filesystem <<< "$uids"'),
    has('expected="10001 10001 10001 10001"'),
    demands('"$real $effective $saved $filesystem" = "$expected"'),
]

CHECKS: dict[tuple[str, str], list[tuple[str, str]]] = {
    ("compose", "before"): [
        *IMAGE,
        *HEALTHZ,
        *PID_1_USER,
        *EXEC_USER,
        reads("type", '"$data_mount"'),
        demands('"$type" = volume'),
        reads("started", "{{.State.StartedAt}}"),
    ],
    ("compose", "after"): [
        reads("restarted", "{{.State.StartedAt}}"),
        demands('"$restarted" != "$started"'),
        reads("health", "{{.State.Health.Status}}"),
        demands('"$health" = healthy'),
        *HEALTHZ,
        reads("probe", "cat /data/e2e-probe"),
        demands('"$probe" = persisted'),
    ],
    ("podman-quadlet", "before"): [
        reads("status", "{{.State.Health.Status}}"),
        demands('"$status" = healthy'),
        *IMAGE,
        *HEALTHZ,
        *PID_1_USER,
        *EXEC_USER,
        reads("pid", "{{.State.Pid}}"),
        reads("host_uids", "/proc/$pid/status"),
        has('read -r _ host_uid _ <<< "$host_uids"'),
        demands('"$host_uid" = "$(id -u)"'),
        # The directory alone proves nothing: the job created it. The file is what the container wrote.
        has('for path in "$state" "$state/e2e-probe"; do'),
        reads("owner", "stat "),
        demands('"$owner" = "$(id -u)"'),
        reads("before", "{{.Id}}"),
    ],
    ("podman-quadlet", "after"): [
        reads("after", "{{.Id}}"),
        demands('"$before" != "$after"'),
        *HEALTHZ,
        reads("on_host", "e2e-probe"),
        demands('"$on_host" = persisted'),
        reads("in_container", "cat /data/e2e-probe"),
        demands('"$in_container" = persisted'),
    ],
}


@pytest.mark.parametrize(("name", "phase"), list(CHECKS), ids=["-".join(key) for key in CHECKS])
def test_each_job_keeps_every_check_it_relies_on(name: str, phase: str):
    shell = around_restart(name)[phase]
    lost = [what for what, pattern in CHECKS[name, phase] if not re.search(pattern, shell, re.M)]
    assert not lost, f"{name}, {phase} its restart, lost: {lost}"


def test_every_compose_start_waits_for_the_container_to_be_healthy():
    # The first start must not return before the container is up, and the one after the restart must wait for the new
    # container's first probe. The words are compared, not a substring: `--wait-timeout` contains `--wait`.
    starts = [line.split() for line in script("compose").splitlines() if line.startswith("docker compose up")]
    assert len(starts) == 2, "expected the first start and the wait after the restart"
    for words in starts:
        line = " ".join(words)
        assert "--wait" in words, f"{line!r} returns before the container is healthy"
        bound = words[words.index("--wait-timeout") + 1 :][:1] if "--wait-timeout" in words else []
        assert bound and bound[0].isdigit(), f"{line!r} does not bound that wait"


@pytest.mark.parametrize("name", JOBS)
def test_a_failed_check_stops_its_step(name: str):
    # Every check ends in `fail`. A `fail` that returned would turn all the checks of its step into no-ops.
    for step in steps(name):
        run = step.get("run", "")
        if re.search(r"\|\| fail\b", run):
            defined = re.search(r"^[ \t]*fail\(\)[^\n]*\bexit 1\b", run, re.M)
            assert defined, f"{name}: {step.get('name')!r} calls fail but defines none that exits 1"
