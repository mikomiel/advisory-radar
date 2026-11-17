"""``advisory-radar healthcheck``: the one probe the image, the compose file and the quadlet all run.

The command exists because an inline ``python -c`` probe could not be written the same way in all three places: the
Quadlet generator dropped the closing quote of the one in the unit, so the container was unhealthy for good. These
tests run it against a real socket, because a stubbed transport would not notice a proxy, a timeout or a wrong path.

The probe reads one number, ``web.port``, from the YAML file alone. It does not expand a reference, open a ``*_FILE``
file, merge the settings overlay or validate any other setting: the service does all of that when it starts, and a
probe that repeats it only reports a running service as unhealthy.
"""

from __future__ import annotations

import contextlib
import logging
import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import uvicorn

from advisory_radar import cli, settings
from advisory_radar.config import ConfigError, load_config
from advisory_radar.runtime import Runtime, read_config
from advisory_radar.web import create_app

NO_NOTIFIERS = "notifiers: []\n"


def write_config(directory: Path, port: int, notifiers: str = NO_NOTIFIERS, extra: str = "") -> Path:
    """A configuration whose web UI is on ``port``; ``extra`` is more top-level YAML, as whole lines."""
    path = directory / "config.yml"
    path.write_text(
        f"sources: []\n{notifiers}{extra}state_path: {directory}/state.json\nweb:\n  port: {port}\n",
        encoding="utf-8",
    )
    return path


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@contextlib.contextmanager
def answering(status: int = 200, body: bytes = b"ok") -> Iterator[tuple[int, list[tuple[str, dict[str, str]]]]]:
    """A loopback server that answers every GET with ``status``; yields its port and the requests it saw."""
    seen: list[tuple[str, dict[str, str]]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.append((self.path, dict(self.headers)))
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # keep the test output quiet
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def probe(config: Path) -> int:
    # An empty environment: the probe needs no token and no secret, and must not read either.
    return cli.main(["--config", str(config), "healthcheck"], env={})


def assert_one_plain_error(caplog: pytest.LogCaptureFixture) -> None:
    """One log line that says why, and no traceback: the container runtime shows this text as the health output."""
    assert [record.levelno for record in caplog.records] == [logging.ERROR]
    assert caplog.records[0].exc_info is None


def test_a_200_from_healthz_exits_zero_and_sends_no_credential(tmp_path):
    with answering() as (port, seen):
        config = write_config(tmp_path, port)
        before = sorted(path.name for path in tmp_path.iterdir())
        assert probe(config) == 0
    assert [path for path, _ in seen] == ["/healthz"]
    assert not {name.lower() for name in seen[0][1]} & {"authorization", "cookie"}
    # The probe only reads: no state file, lock or overlay appears beside the configuration.
    assert sorted(path.name for path in tmp_path.iterdir()) == before


def test_the_config_path_comes_from_the_environment_when_no_flag_is_given(tmp_path, monkeypatch):
    """The image sets ADVISORY_RADAR_CONFIG and passes no --config, so the variable has to be live."""
    with answering() as (port, _):
        config = write_config(tmp_path, port)
        monkeypatch.setenv("ADVISORY_RADAR_CONFIG", str(config))
        assert cli._parser().parse_args(["run"]).config == config
        assert cli.main(["healthcheck"], env={}) == 0


@pytest.mark.parametrize("status", [404, 500, 503])
def test_any_answer_other_than_200_is_unhealthy(tmp_path, caplog, status):
    with answering(status) as (port, _):
        assert probe(write_config(tmp_path, port)) == 1
    assert_one_plain_error(caplog)
    assert str(status) in caplog.text


def test_a_refused_connection_is_unhealthy(tmp_path, caplog):
    assert probe(write_config(tmp_path, free_port())) == 1
    assert_one_plain_error(caplog)


def test_a_server_that_never_answers_is_unhealthy_within_the_timeout(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(cli, "HEALTHCHECK_TIMEOUT", 0.3)
    with socket.socket() as silent:
        silent.bind(("127.0.0.1", 0))
        silent.listen(1)  # the kernel completes the handshake; nothing ever reads or answers
        config = write_config(tmp_path, silent.getsockname()[1])
        started = time.monotonic()
        assert probe(config) == 1
    assert time.monotonic() - started < 5
    assert_one_plain_error(caplog)


def test_a_missing_configuration_is_unhealthy_without_a_traceback(tmp_path, caplog):
    assert probe(tmp_path / "absent.yml") == 1
    assert_one_plain_error(caplog)


@pytest.mark.parametrize("port", [0, 70000])
def test_a_port_the_configuration_would_refuse_is_unhealthy(tmp_path, caplog, port):
    assert probe(write_config(tmp_path, port)) == 1
    assert_one_plain_error(caplog)
    assert "web.port" in caplog.text


def test_an_unset_secret_reference_does_not_make_a_running_service_unhealthy(tmp_path):
    """The probe reads web.port only: a ${NAME} a notifier needs is the service's concern, not the probe's."""
    notifiers = "notifiers:\n  - id: discord\n    type: discord_webhook\n    url: ${DISCORD_WEBHOOK_URL}\n"
    with answering() as (port, _):
        assert probe(write_config(tmp_path, port, notifiers)) == 0


def test_a_value_the_overlay_replaces_does_not_need_its_reference_to_be_set(tmp_path):
    """The service merges the settings overlay before it expands, so the probe has to cope with the same two files.

    ``poll_interval: ${POLL_INTERVAL}`` with no such variable is a configuration the service starts with once the
    UI has saved a ``poll_interval``. A probe that read the YAML without the overlay judged the literal reference
    and refused it, so a service that was answering ``/healthz`` was reported unhealthy.
    """
    with answering() as (port, _):
        config = write_config(tmp_path, port, extra="poll_interval: ${POLL_INTERVAL}\n")
        settings.save_settings(settings.settings_path(tmp_path / "state.json"), {"poll_interval": "10m"}, now=1)
        # The premise: the service itself starts from exactly these two files, with nothing in its environment.
        assert read_config(config, {})[0].poll_interval_seconds == 600
        assert probe(config) == 0


def test_the_probe_opens_no_file_the_configuration_names(tmp_path, monkeypatch):
    """A ``${NAME_FILE}`` reference names a secret, and the probe has no use for it."""
    secret = tmp_path / "hook-url"
    secret.write_text("not-a-real-secret\n", encoding="utf-8")
    notifiers = "notifiers:\n  - id: hook\n    type: webhook\n    url: ${HOOK_URL_FILE}\n"
    opened: list[Path] = []
    real_read_text = Path.read_text

    def recording(self: Path, *args: object, **kwargs: object) -> str:
        opened.append(self)
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", recording)
    with answering() as (port, _):
        config = write_config(tmp_path, port, notifiers)
        assert cli.main(["--config", str(config), "healthcheck"], env={"HOOK_URL_FILE": str(secret)}) == 0
    assert secret not in opened


@pytest.mark.parametrize(
    "extra",
    [
        "poll_interval: not-an-interval\n",
        "language: xx\n",
        "storage: 42\n",
        "digest: maybe\n",
        "unknown_setting: 1\n",
    ],
)
def test_the_probe_judges_the_answer_and_not_the_settings_it_does_not_read(tmp_path, extra):
    """The service validates its configuration when it starts, and a service that did not start answers nothing.

    A probe that repeated that validation could only add false alarms, so what it does not read, it does not judge.
    """
    with answering() as (port, _):
        config = write_config(tmp_path, port, extra=extra)
        with pytest.raises(ConfigError):
            load_config(config, {})  # the premise: the service would refuse to start from this file
        assert probe(config) == 0


def write_web(directory: Path, web: str) -> Path:
    """A configuration that holds only the ``web`` block under test: YAML text as whole lines, or nothing."""
    path = directory / "config.yml"
    path.write_text(f"sources: []\nnotifiers: []\nstate_path: {directory}/state.json\n{web}", encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "web",
    [
        "",
        "web:\n",
        "web: {}\n",
        "web: []\n",
        "web:\n  host: 127.0.0.1\n",
        "web:\n  port: 1\n",
        "web:\n  port: 9090\n",
        "web:\n  port: 65535\n",
    ],
)
def test_the_port_the_probe_asks_is_the_port_the_service_binds(tmp_path, web):
    """The probe cannot reuse the validator's reading of ``web.port`` without running all of the validation.

    So it carries the same rule, and this table holds the two together: a missing or empty ``web`` block is the
    default port, and a number is that number.
    """
    path = write_web(tmp_path, web)
    assert cli._web_port(path) == load_config(path, {}).web_port


@pytest.mark.parametrize(
    "web",
    [
        "web:\n  port: 0\n",
        "web:\n  port: 65536\n",
        "web:\n  port: -1\n",
        "web:\n  port: '8080'\n",
        "web:\n  port: 8080.5\n",
        "web:\n  port:\n",
        "web: 3\n",
        "web: [8080]\n",
    ],
)
def test_a_web_block_the_service_would_refuse_is_refused_by_the_probe_too(tmp_path, web):
    path = write_web(tmp_path, web)
    with pytest.raises(ConfigError):
        load_config(path, {})
    with pytest.raises(ConfigError, match="web"):
        cli._web_port(path)


def test_a_port_written_as_a_reference_is_refused_without_being_expanded(tmp_path):
    """An expansion is always a string, which the validator refuses as a port: the probe never has to expand one."""
    path = write_web(tmp_path, "web:\n  port: ${WEB_PORT}\n")
    with pytest.raises(ConfigError):
        load_config(path, {"WEB_PORT": "8080"})
    with pytest.raises(ConfigError, match=r"web\.port"):
        cli._web_port(path)


def test_the_overlay_cannot_carry_the_web_binding_so_the_yaml_is_the_only_place_to_look(tmp_path):
    """The probe never reads the overlay. That is complete only while the overlay cannot set ``web``.

    If this test fails, ``web`` has become an overlay key and ``cli._web_port`` has to learn where the overlay is.
    """
    config = write_config(tmp_path, 9090)
    with pytest.raises(ConfigError, match="unknown overlay keys"):
        load_config(config, {}, settings={"web": {"port": 9091}})


@pytest.mark.parametrize(
    "content", [b"\xff\xfe\x00\xc3(", b"", b"# only a comment\n", b"- not\n- a mapping\n", b"web: [unclosed\n"]
)
def test_a_configuration_that_is_not_a_readable_mapping_is_unhealthy_in_one_line(tmp_path, caplog, content):
    """Not UTF-8, empty, comments only, a list, or YAML that does not parse: one line of health output each.

    The service refuses every one of them as well, on the path it starts by (``read_config``), so none of them can be
    a running service that the probe reports as unhealthy.
    """
    path = tmp_path / "config.yml"
    path.write_bytes(content)
    with pytest.raises((ConfigError, UnicodeDecodeError)):
        read_config(path, {})
    assert probe(path) == 1
    assert_one_plain_error(caplog)
    assert "\n" not in caplog.text.strip()


def test_the_probe_ignores_proxy_settings(tmp_path, monkeypatch):
    """A proxy in the container environment must not carry a loopback request somewhere else."""
    for name in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{free_port()}")
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    with answering() as (port, seen):
        assert probe(write_config(tmp_path, port)) == 0
    assert [path for path, _ in seen] == ["/healthz"]


def test_the_probe_reaches_the_real_healthz_route(tmp_path):
    """The real app, over a real socket: a Host header or a middleware that refused the probe would show here."""
    env = {"ADVISORY_RADAR_AUTH_TOKEN": "probe-token-0123456789abcdef"}
    config = write_config(tmp_path, 8080)  # never bound: the server below takes an ephemeral port
    app = create_app(Runtime.build(config, env), env)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started, "the application server did not start"
        port = server.servers[0].sockets[0].getsockname()[1]
        assert probe(write_config(tmp_path, port)) == 0
    finally:
        server.should_exit = True
        thread.join(timeout=10)
