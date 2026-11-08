"""The optional NVD API key: a free credential that raises the anonymous limit from 5 to 50 requests per 30 s.

NVD is the one upstream that rate-limits the anonymous caller hard enough to shape a pass, so the key is both a
throughput and a latency decision. What must not regress: no key means no header at all (an empty ``apiKey``
would be rejected), and the anonymous pace still applies so an installation without a key stays within limits.
"""

from __future__ import annotations

from pathlib import Path

from advisory_radar import core
from advisory_radar.config import load_config


def intel_with(headers: list[dict[str, str]], slept: list[float], *, key: str) -> core.Intel:
    def http(method, url, header_map, body):
        headers.append(dict(header_map))
        return 404, {}, b""  # NVD has no record for this CVE: a complete answer, and it short-circuits parsing

    return core.Intel(http, {}, lambda: 0.0, slept.append, nvd_key=key)


def test_a_key_is_sent_with_the_nvd_request_and_shortens_the_pace():
    headers: list[dict[str, str]] = []
    slept: list[float] = []
    intel = intel_with(headers, slept, key="nvd-key")
    assert intel._nvd("CVE-2026-1234") == (True, None, False)
    assert headers[0]["apiKey"] == "nvd-key"
    assert headers[0]["Accept"] == "application/json"
    assert slept == [core.NVD_KEY_PACE_SECONDS]


def test_without_a_key_no_header_is_sent_and_the_anonymous_pace_applies():
    headers: list[dict[str, str]] = []
    slept: list[float] = []
    intel = intel_with(headers, slept, key="")
    assert intel._nvd("CVE-2026-1234") == (True, None, False)
    assert "apiKey" not in headers[0]
    assert slept == [core.NVD_PACE_SECONDS]


def test_the_key_is_read_from_the_environment_and_redacted_like_any_credential(tmp_path: Path):
    path = tmp_path / "config.yml"
    path.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path}/state.json\nnvd_api_key: ${{NVD_API_KEY}}\n")
    cfg = load_config(path, {"NVD_API_KEY": "secret-key-value"})
    assert cfg.nvd_api_key == "secret-key-value"
    assert "secret-key-value" in cfg.secret_values


def test_the_key_stays_optional(tmp_path: Path):
    path = tmp_path / "config.yml"
    path.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path}/state.json\n")
    assert load_config(path, {}).nvd_api_key == ""


def test_an_unexpanded_key_fails_closed_without_echoing_the_value(tmp_path: Path):
    from advisory_radar.config import ConfigError

    path = tmp_path / "config.yml"
    path.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path}/state.json\nnvd_api_key: ${{NVD_API_KEY}}\n")
    assert load_config(path, {}, lenient=True).nvd_api_key == "${NVD_API_KEY}"  # state-only commands
    try:
        load_config(path, {})
    except ConfigError as exc:
        assert "NVD_API_KEY" in str(exc) and "${NVD_API_KEY} is not set" in str(exc)
    else:  # pragma: no cover - a missing secret must never be tolerated on a real pass
        raise AssertionError("a missing key reference must be a configuration error")
