"""The container files agree with each other and with the application.

Nothing here builds an image: the ``ci`` job does that. These checks pin the properties a build and a smoke start
cannot see, each of which broke a real deployment: a ``/data`` that a fresh named volume copied as root-owned, a
``--config`` baked into the entrypoint so ``ADVISORY_RADAR_CONFIG`` did nothing, and a quoted ``HealthCmd`` that the
Quadlet generator turned into a command that could never succeed. The files are read as data; the Dockerfile and the
unit are parsed with a few lines each rather than a dependency.
"""

from __future__ import annotations

import fnmatch
import json
import re
import shlex
from pathlib import Path

import pytest
import yaml

from advisory_radar import cli

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE = ROOT / "docker-compose.yml"
QUADLET = ROOT / "deploy" / "podman" / "advisory-radar.container"
DOCKERIGNORE = ROOT / ".dockerignore"
README = ROOT / "README.md"
DEPLOYMENT = ROOT / "docs" / "deployment.md"

HEALTHCHECK_COMMAND = ["advisory-radar", "healthcheck"]


# --- Dockerfile -------------------------------------------------------------------------------------------------


def instructions(text: str) -> list[tuple[str, str]]:
    """Each instruction as ``(KEYWORD, arguments)``: continuations joined, comment and blank lines dropped."""
    logical: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#") or (not line and not pending):
            continue  # a comment is dropped even inside a continued instruction
        if line.endswith("\\"):
            pending += line[:-1].rstrip() + " "
            continue
        logical.append((pending + line).strip())
        pending = ""
    if pending:
        logical.append(pending.strip())
    split = [line.split(None, 1) for line in logical]
    return [(parts[0].upper(), parts[1] if len(parts) > 1 else "") for parts in split]


def final_stage() -> list[tuple[str, str]]:
    everything = instructions(DOCKERFILE.read_text(encoding="utf-8"))
    last_from = max(index for index, (keyword, _) in enumerate(everything) if keyword == "FROM")
    return everything[last_from + 1 :]


def position(stage: list[tuple[str, str]], keyword: str, needle: str = "") -> int:
    for index, (candidate, arguments) in enumerate(stage):
        if candidate == keyword and needle in arguments:
            return index
    raise AssertionError(f"the final stage has no {keyword} instruction containing {needle!r}")


def option(words: list[str], flag: str) -> str | None:
    return words[words.index(flag) + 1] if flag in words[:-1] else None


def install_commands(run_arguments: str) -> list[list[str]]:
    """The ``install`` invocations inside one RUN line, split on the shell's command separators."""
    commands = []
    for part in re.split(r"&&|;|\|\|", run_arguments):
        words = shlex.split(part)
        if words and words[0] == "install":
            commands.append(words)
    return commands


def creates_data_for_the_runtime_user(words: list[str]) -> bool:
    return "-d" in words and words[-1] == "/data" and option(words, "-o") == "radar"


def test_data_is_created_for_the_runtime_user_before_it_becomes_a_volume():
    """A fresh named volume copies the owner and mode of the image's mount point.

    ``WORKDIR /data`` alone creates the directory as root, so a volume made from it is unwritable for the
    non-root user the image runs as. The directory therefore has to exist, owned by that user, before the
    ``VOLUME`` instruction freezes it.
    """
    stage = final_stage()
    creating = [
        index
        for index, (keyword, arguments) in enumerate(stage)
        if keyword == "RUN" and any(creates_data_for_the_runtime_user(words) for words in install_commands(arguments))
    ]
    assert creating, "no RUN creates /data owned by radar, so a fresh named volume is root-owned and unwritable"
    created = creating[0]
    assert position(stage, "RUN", "useradd") < created, "the user must exist before it can own a directory"
    assert created < position(stage, "WORKDIR", "/data")
    assert created < position(stage, "VOLUME", "/data"), "ownership set after VOLUME is discarded"
    assert created < position(stage, "USER", "radar"), "install -d -o needs root"

    words = next(w for w in install_commands(stage[created][1]) if creates_data_for_the_runtime_user(w))
    mode = option(words, "-m")
    assert mode, "the directory needs an explicit mode"
    assert int(mode, 8) & 0o007 == 0, "/data holds the state and the settings: no access for other users"


def test_the_image_runs_as_the_non_root_user():
    users = [arguments for keyword, arguments in final_stage() if keyword == "USER"]
    assert users and users[-1] == "radar"


def test_the_entrypoint_leaves_the_config_path_to_the_environment():
    """``--config`` in the entrypoint made ADVISORY_RADAR_CONFIG dead: the flag always wins over the default."""
    stage = final_stage()
    entrypoint = json.loads(stage[position(stage, "ENTRYPOINT")][1])
    command = json.loads(stage[position(stage, "CMD")][1])
    assert entrypoint == ["advisory-radar"]
    assert command == ["run"]
    environment = {}
    for keyword, arguments in stage:
        if keyword == "ENV":
            environment.update(word.split("=", 1) for word in shlex.split(arguments))
    assert environment["ADVISORY_RADAR_CONFIG"] == "/config/config.yml"


def dockerfile_healthcheck() -> list[str]:
    stage = final_stage()
    _, _, command = stage[position(stage, "HEALTHCHECK")][1].partition(" CMD ")
    return json.loads(command)


def test_the_image_healthcheck_is_the_exec_form_subcommand():
    assert dockerfile_healthcheck() == HEALTHCHECK_COMMAND


# --- docker-compose.yml -----------------------------------------------------------------------------------------


def compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def service() -> dict:
    return compose()["services"]["advisory-radar"]


def test_compose_runs_the_image_user_and_keeps_state_on_a_named_volume():
    """A ``user:`` override against a bind mount made the quickstart's chown advice wrong; the volume needs none."""
    assert "user" not in service()
    mounts = dict(entry.split(":", 1) for entry in service()["volumes"])
    assert mounts["advisory-radar-data"] == "/data"
    assert mounts["./config"] == "/config:ro"
    assert "advisory-radar-data" in compose()["volumes"]
    assert not [source for source in mounts if mounts[source].startswith("/data") and "/" in source]


def test_compose_publishes_the_ui_on_the_loopback_address_only():
    assert service()["ports"] == ["127.0.0.1:8080:8080"]


def test_compose_follows_a_tag_the_operator_can_pin():
    assert service()["image"] == "ghcr.io/mikomiel/advisory-radar:${ADVISORY_RADAR_TAG:-latest}"


def test_compose_drops_capabilities_and_privilege_escalation():
    assert service()["cap_drop"] == ["ALL"]
    assert service()["security_opt"] == ["no-new-privileges:true"]


def test_compose_healthcheck_is_the_exec_form_subcommand():
    assert service()["healthcheck"]["test"] == ["CMD", *HEALTHCHECK_COMMAND]


# --- the Podman quadlet -----------------------------------------------------------------------------------------


def quadlet() -> dict[str, list[tuple[str, str]]]:
    """Section -> ``(key, value)`` pairs in file order. Keys repeat (``Volume=``), so this is not a mapping."""
    sections: dict[str, list[tuple[str, str]]] = {}
    current: list[tuple[str, str]] | None = None
    for raw in QUADLET.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], [])
            continue
        assert current is not None, f"a setting before any section: {line}"
        key, _, value = line.partition("=")
        current.append((key, value))
    return sections


def values(section: str, key: str) -> list[str]:
    return [value for candidate, value in quadlet()[section] if candidate == key]


def test_quadlet_healthcheck_needs_no_quoting():
    """The generator turned the quoted ``python -c "..."`` into a ``--health-cmd`` that lost its closing quote.

    A command made of plain words has no quote to lose, which is why the unit calls the subcommand.
    """
    (command,) = values("Container", "HealthCmd")
    assert command.split() == HEALTHCHECK_COMMAND
    assert not set(command) & set("\"'\\"), "a quote or backslash in HealthCmd does not survive the generator"
    assert values("Container", "HealthStartPeriod") == ["10s"]


def test_quadlet_publishes_the_ui_on_the_loopback_address_only():
    assert values("Container", "PublishPort") == ["127.0.0.1:8080:8080"]


def test_quadlet_drops_capabilities_and_privilege_escalation():
    assert values("Container", "NoNewPrivileges") == ["true"]
    assert values("Container", "DropCapability") == ["ALL"]


def test_quadlet_restarts_slowly_and_allows_a_slow_first_pull():
    assert values("Service", "Restart") == ["always"]
    assert values("Service", "RestartSec") == ["10"]
    assert values("Service", "TimeoutStartSec") == ["900"]


def test_quadlet_still_maps_the_image_user_onto_the_host_user():
    assert values("Container", "UserNS") == ["keep-id:uid=10001,gid=10001"]


# --- the three healthchecks call a command that exists ------------------------------------------------------------


HEALTHCHECKS = {
    "Dockerfile": dockerfile_healthcheck,
    "compose": lambda: service()["healthcheck"]["test"][1:],
    "quadlet": lambda: values("Container", "HealthCmd")[0].split(),
}


@pytest.mark.parametrize("name", sorted(HEALTHCHECKS))
def test_every_healthcheck_calls_a_subcommand_the_cli_parses(name):
    command = HEALTHCHECKS[name]()
    assert command[0] == "advisory-radar"
    assert cli._parser().parse_args(command[1:]).command == "healthcheck"


# --- .dockerignore ----------------------------------------------------------------------------------------------


def dockerignore_patterns() -> list[str]:
    lines = DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def test_dockerignore_keeps_local_state_and_secrets_out_of_the_build_context():
    patterns = {pattern.rstrip("/") for pattern in dockerignore_patterns()}
    # ``**/__pycache__``, not the bare name: a bare name only matches at the root of the context.
    for required in (".git", ".venv", "**/__pycache__", ".pytest_cache", "data", "config", ".env"):
        assert required in patterns, f".dockerignore does not exclude {required}"


def test_dockerignore_excludes_nothing_the_build_copies():
    patterns = dockerignore_patterns()
    copied: list[str] = []
    for keyword, arguments in instructions(DOCKERFILE.read_text(encoding="utf-8")):
        words = shlex.split(arguments)
        if keyword == "COPY" and not any(word.startswith("--from") for word in words):
            copied += [word for word in words[:-1] if not word.startswith("--")]
    assert {"pyproject.toml", "uv.lock", "src"} <= set(copied), "the build no longer copies what this test expects"
    for source in copied:
        assert not any(fnmatch.fnmatch(source, pattern.rstrip("/")) for pattern in patterns), (
            f".dockerignore would drop {source}, which the Dockerfile copies"
        )


# --- the guide the files point at -------------------------------------------------------------------------------


def heading_anchors(path: Path) -> set[str]:
    """The anchors GitHub gives the headings of a Markdown file: lower case, punctuation dropped, spaces to hyphens."""
    anchors = set()
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            fenced = not fenced  # a `# comment` in a shell block is not a heading
            continue
        heading = None if fenced else re.match(r"#{1,6}\s+(.+?)\s*$", line)
        if heading:
            title = heading.group(1).replace("`", "").lower()
            anchors.add(re.sub(r"[^\w\- ]", "", title).replace(" ", "-"))
    return anchors


def test_every_link_into_the_deployment_guide_names_a_heading_that_exists():
    """The compose file, the unit and the README send the reader to a section by name; a rename must not strand them."""
    anchors = heading_anchors(DEPLOYMENT)
    links = {
        path: re.findall(r"deployment\.md#([\w-]+)", path.read_text(encoding="utf-8"))
        for path in (README, COMPOSE, QUADLET)
    }
    links[DEPLOYMENT] = re.findall(r"\]\(#([\w-]+)\)", DEPLOYMENT.read_text(encoding="utf-8"))
    assert links[COMPOSE] and links[QUADLET], "the compose file and the unit point at no section of the guide"
    broken = {path.name: sorted(set(found) - anchors) for path, found in links.items() if set(found) - anchors}
    assert not broken, f"links to a heading the guide does not have: {broken}"
