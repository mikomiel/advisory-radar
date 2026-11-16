"""``advisory-radar healthcheck``: the one probe the image, the compose file and the quadlet all run.

The command exists because an inline ``python -c`` probe could not be written the same way in all three places: the
Quadlet generator dropped the closing quote of the one in the unit, so the container was unhealthy for good. These
tests run it against a real socket, because a stubbed transport would not notice a proxy, a timeout or a wrong path.
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

from advisory_radar import cli
from advisory_radar.runtime import Runtime
from advisory_radar.web import create_app

NO_NOTIFIERS = "notifiers: []\n"


def write_config(directory: Path, port: int, notifiers: str = NO_NOTIFIERS) -> Path:
    path = directory / "config.yml"
    path.write_text(
        f"sources: []\n{notifiers}state_path: {directory}/state.json\nweb:\n  port: {port}\n",
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
