"""The source catalogue is the single owner of a kind's metadata.

Four consumers could drift apart: the builders, the config key allowlist, the README table and the
``/sources`` page. Every test here pins one of them to ``SOURCE_SPECS``, and every example is loaded and
built, so a catalogue snippet is a config a user could actually run.
"""

from __future__ import annotations

import html
import json
import logging
import re
import threading
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from fastapi.testclient import TestClient

from advisory_radar import cli, config
from advisory_radar.catalogue import SOURCE_SPECS
from advisory_radar.config import load_config
from advisory_radar.sources import SOURCE_BUILDERS, build_source
from advisory_radar.state import state_lock
from advisory_radar.web import create_app

README = Path(__file__).parent.parent / "README.md"
ENV_PLACEHOLDER = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")
RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Vendor</title><link>https://vendor.example.net/</link>
<item><title>CVE-2026-1111 fixed in libfoo</title><link>https://vendor.example.net/adv/1</link>
<guid>adv-1</guid><description>Fixes CVE-2026-1111.</description></item>
<item><title>CVE-2026-2222 fixed in libbar</title><link>https://vendor.example.net/adv/2</link>
<guid>adv-2</guid><description>Fixes CVE-2026-2222.</description></item>
</channel></rss>"""


def config_file(tmp_path: Path, sources: list[dict]) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "config.yml"
    path.write_text(yaml.safe_dump({"sources": sources, "notifiers": [], "state_path": str(tmp_path / "state.json")}))
    return path


def test_every_builder_has_exactly_one_spec():
    assert SOURCE_SPECS, "the catalogue must not be empty"
    assert set(SOURCE_BUILDERS) == set(SOURCE_SPECS)


def test_config_allows_the_registry_keys():
    documented = {key for spec in SOURCE_SPECS.values() for key in (*spec.required, *spec.optional)}
    assert {"id", "type", "enabled"} | documented == config._SOURCE_KEYS


def test_every_example_validates_and_builds(tmp_path):
    for kind, spec in SOURCE_SPECS.items():
        assert spec.kind == kind
        assert spec.docs_anchor == "README.md#sources"
        assert set(spec.required) <= set(spec.example), f"{kind}: the example must show every required key"
        assert set(spec.example) <= {"id", "type"} | set(spec.required) | set(spec.optional)
        for credential in ("token", "api_key"):
            if credential in spec.example:
                assert ENV_PLACEHOLDER.fullmatch(spec.example[credential]), (
                    f"{kind}: {credential} must be a ${{NAME}} reference, never a literal secret"
                )
        for value in spec.example.values():
            if isinstance(value, str) and "://" in value:
                assert (urlsplit(value).hostname or "").endswith(".example.net"), f"{kind}: {value} is not a test host"
        env = {name: "dummy-value" for name in ENV_PLACEHOLDER.findall(yaml.safe_dump(spec.example))}
        path = config_file(tmp_path / kind, [spec.example])
        cfg = load_config(path, env)
        assert [entry["type"] for entry in cfg.sources] == [kind]
        source = build_source(dict(cfg.sources[0]), env)
        assert source.id == spec.example["id"]
        assert callable(source.fetch)


def test_sources_list_needs_neither_config_nor_secrets(tmp_path, capsys):
    code = cli.main(["sources", "list"], env={})
    assert code == 0
    printed = capsys.readouterr().out
    for kind, spec in SOURCE_SPECS.items():
        assert f"{kind}: {spec.summary}" in printed
        assert f"  required: {', '.join(spec.required) or '(none)'}" in printed
        assert f"  optional: {', '.join(spec.optional) or '(none)'}" in printed

    code = cli.main(["--config", str(tmp_path / "does-not-exist.yml"), "sources", "list"], env={})
    assert code == 0, "sources list must not read the config path it was given"
    assert capsys.readouterr().out


def test_sources_test_prints_items_and_saves_nothing(tmp_path, capsys):
    path = config_file(tmp_path, [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"}])
    calls: list[dict[str, str]] = []

    def http(method, url, headers, body):
        calls.append(dict(headers))
        return 200, {}, RSS

    code = cli.main(["--config", str(path), "sources", "test", "vendor"], env={}, http=http)
    assert code == 0
    printed = capsys.readouterr().out
    assert "adv-1\tCVE-2026-1111 fixed in libfoo\thttps://vendor.example.net/adv/1" in printed
    assert "2 item(s); truncated: no" in printed
    assert len(calls) == 1
    assert "If-None-Match" not in calls[0], "an empty state must make the fetch unconditional"
    assert not (tmp_path / "state.json").exists(), "sources test must write no state"
    assert not (tmp_path / "state.json.lock").exists(), "sources test must not even take the state lock"

    code = cli.main(["--config", str(path), "sources", "test", "vendor", "--limit", "1"], env={}, http=http)
    assert code == 0
    limited = capsys.readouterr().out
    assert "CVE-2026-1111 fixed in libfoo" in limited
    assert "CVE-2026-2222 fixed in libbar" not in limited
    assert "2 item(s); truncated: no" in limited


def test_a_truncated_window_exits_one(tmp_path, capsys):
    path = config_file(
        tmp_path,
        [{"id": "fresh", "type": "freshrss", "url": "https://rss.example.net", "token": "${FRESHRSS_TOKEN}"}],
    )
    payload = {
        "items": [
            {
                "id": "tag:google.com,2005:reader/item/0000000000000001",
                "title": "Advisory in a full window",
                "canonical": [{"href": "https://vendor.example.net/adv/1"}],
            }
        ],
        "continuation": "next-page",
    }
    code = cli.main(
        ["--config", str(path), "sources", "test", "fresh"],
        env={"FRESHRSS_TOKEN": "dummy-token"},
        http=lambda method, url, headers, body: (200, {}, json.dumps(payload).encode()),
    )
    assert code == 1, "a truncated window proves the source held more than it returned"
    printed = capsys.readouterr().out
    assert "Advisory in a full window" in printed
    assert "truncated: yes" in printed


def test_a_failing_fetch_exits_one(tmp_path):
    path = config_file(tmp_path, [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"}])
    code = cli.main(
        ["--config", str(path), "sources", "test", "vendor"],
        env={},
        http=lambda method, url, headers, body: (503, {}, b""),
    )
    assert code == 1
    assert not (tmp_path / "state.json").exists()


def test_sources_test_loads_the_config_strictly(tmp_path, caplog):
    path = config_file(
        tmp_path, [{"id": "fresh", "type": "freshrss", "url": "https://rss.example.net", "token": "${FRESHRSS_TOKEN}"}]
    )
    with caplog.at_level(logging.ERROR):
        code = cli.main(["--config", str(path), "sources", "test", "fresh"], env={}, http=lambda *a: (200, {}, b"{}"))
    assert code == 1, "a missing secret for an enabled source is a configuration error, not a silent skip"
    assert "FRESHRSS_TOKEN" in caplog.text, "the error must name the missing secret"
    assert not (tmp_path / "state.json").exists()


def test_sources_test_rejects_an_unknown_id(tmp_path):
    path = config_file(tmp_path, [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"}])
    code = cli.main(["--config", str(path), "sources", "test", "typo"], env={}, http=lambda *a: (200, {}, b""))
    assert code == 1


def test_sources_test_leaves_an_existing_state_document_untouched(tmp_path):
    path = config_file(tmp_path, [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"}])
    # A stored ETag would answer 304 if the command read the state; it passes an empty state instead, and the
    # document it did not read must still be byte-identical afterwards.
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "schema": "advisory-radar-state.v1",
                "seen": {"CVE-2026-1": {"at": 1792600000, "outcome": "delivered"}},
                "pending": [],
                "parked": [],
                "watch": {},
                "cache": {},
                "feeds": {"vendor": {"url_digest": "digest", "etag": 'W/"old"'}},
            }
        ),
        encoding="utf-8",
    )
    before = state_path.read_bytes()
    headers: list[dict[str, str]] = []

    def http(method, url, request_headers, body):
        headers.append(dict(request_headers))
        return 200, {}, RSS

    code = cli.main(["--config", str(path), "sources", "test", "vendor"], env={}, http=http)
    assert code == 0
    assert headers and "If-None-Match" not in headers[0]
    assert state_path.read_bytes() == before, "sources test must not rewrite the state it was pointed at"


def test_sources_test_does_not_wait_for_the_state_lock(tmp_path):
    path = config_file(tmp_path, [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"}])
    state_path = tmp_path / "state.json"
    state_path.write_text("{}", encoding="utf-8")
    result: list[int] = []
    with state_lock(state_path):
        worker = threading.Thread(
            target=lambda: result.append(
                cli.main(["--config", str(path), "sources", "test", "vendor"], env={}, http=lambda *a: (200, {}, RSS))
            ),
            daemon=True,
        )
        worker.start()
        worker.join(10)
        assert not worker.is_alive(), "sources test must not take the state lock a pass already holds"
    assert result == [0]


def test_sources_test_loads_a_notifier_secret_strictly(tmp_path, caplog):
    path = tmp_path / "config.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "sources": [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"}],
                "notifiers": [
                    {
                        "id": "phone",
                        "type": "ntfy",
                        "url": "https://ntfy.example.net",
                        "topic": "advisories",
                        "token": "${NTFY_TOKEN}",
                    }
                ],
                "state_path": str(tmp_path / "state.json"),
            }
        ),
        encoding="utf-8",
    )
    with caplog.at_level(logging.ERROR):
        code = cli.main(["--config", str(path), "sources", "test", "vendor"], env={}, http=lambda *a: (200, {}, RSS))
    assert code == 1, "the documented 'any enabled plugin' rule includes the notifiers a pass would build"
    assert "NTFY_TOKEN" in caplog.text


def _keys(cell: str) -> tuple[str, ...]:
    if cell.strip().strip("`") in {"", "-", "—", "none", "(none)"}:
        return ()
    return tuple(part.strip().strip("`") for part in cell.split(","))


def _readme_rows() -> dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]]:
    """Parse the catalogue table into kind -> (summary, required, optional).

    A duplicate kind is a failure, not a silently overwritten row: the table is the only place a user reads a
    summary, and two rows for one kind would make one of them invisible to this check.
    """
    text = README.read_text(encoding="utf-8")
    assert "\n## Sources\n" in text, "README must document the sources in its own section"
    section = text.split("\n## Sources\n", 1)[1].split("\n## ", 1)[0]
    rows: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {}
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not cells or cells[0].lower() == "kind" or set(cells[0]) <= {"-", ":", " "}:
            continue
        kind = cells[0].strip("`")
        assert kind not in rows, f"README has two rows for {kind}"
        rows[kind] = (cells[1], _keys(cells[2]), _keys(cells[3]))
    return rows


def test_the_readme_table_matches_the_registry():
    rows = _readme_rows()
    assert set(rows) == set(SOURCE_SPECS)
    for kind, spec in SOURCE_SPECS.items():
        summary, required, optional = rows[kind]
        # The summary is user-facing prose, not a key list: it has to be the same sentence the catalogue and the
        # /sources page carry, or the README describes a kind differently from the page next to it.
        # The table renders the endpoint path as code, so compare the prose with the markdown removed.
        assert summary.replace("`", "") == spec.summary, f"README summary drifted for {kind}"
        assert required == spec.required, f"README required keys drifted for {kind}"
        assert optional == spec.optional, f"README optional keys drifted for {kind}"


def sources_client(tmp_path: Path) -> TestClient:
    path = config_file(tmp_path, [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"}])
    app = create_app(load_config(path, {}), {"ADVISORY_RADAR_AUTH_TOKEN": "secret"})
    return TestClient(app)


def test_sources_page_lists_the_catalogue_for_a_signed_in_user(tmp_path):
    client = sources_client(tmp_path)
    response = client.post("/login", data={"token": "secret"}, follow_redirects=False)
    assert response.status_code == 303
    client.cookies.set("advisory_radar_session", response.cookies.get("advisory_radar_session"))
    page = client.get("/sources")
    assert page.status_code == 200
    for kind, spec in SOURCE_SPECS.items():
        assert f"<b>{kind}</b>" in page.text
        assert html.escape(spec.summary) in page.text
        assert f"<td>{', '.join(spec.required) or '(none)'}</td>" in page.text
    for spec in SOURCE_SPECS.values():
        example = html.escape(yaml.safe_dump(spec.example, sort_keys=False))
        assert example in page.text, "the page must show each example as YAML"
    assert '<a href="/sources">Sources</a>' in page.text, "the nav must link the page"
    assert "<li><b>vendor</b> (rss)</li>" in page.text, "configured source ids and types are listed"


def test_sources_page_requires_auth(tmp_path):
    client = sources_client(tmp_path)
    response = client.get("/sources", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
