"""Message language: the catalogue, the ``language`` option and the exact Polish of every kind of notification.

The expected texts below are written out by hand, so they pin the Polish a reader gets and not whatever the code
happens to produce. Each kind of message runs through ``pipeline.run_pass``: that also proves the configured
language reaches every step that writes text (classify, escalate, deliver, Adobe), where a missed call site would
send English to a Polish reader. Every message assertion of those passes includes the routing tag, because a
notifier routes on it and it must stay English.
"""

from __future__ import annotations

import json
import string
from pathlib import Path

import pytest

from advisory_radar import adobe, cli, core, delivery, messages, pipeline
from advisory_radar.config import DEFAULT_THRESHOLDS, ConfigError, load_config
from advisory_radar.runtime import Runtime
from advisory_radar.settings import save_settings, settings_path
from advisory_radar.sources import RssSource
from advisory_radar.state import save_state
from advisory_radar.watchlist import load_policy

NOW = 1792600000  # 2026-10-21 16:26:40 UTC
DAY = 86400
FEED_URL = "https://feeds.example.com/rss"
#: A vector with AV:N, PR:N and UI:N, which makes a CVSS of 9.0 or more critical by the remote rule.
REMOTE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"
LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N"
#: What the fake CVE.org and EPSS answer for a CVE: ``(cvss, vector, epss, percentile)``.
CRITICAL = (9.8, REMOTE, "0.50", "0.99")
WARNING = (6.0, LOCAL, "0.01", "0.30")
ONE_NOTIFIER = "notifiers:\n  - id: fake\n    type: webhook\n    url: https://hooks.example.com/x\n"
ADOBE_PAGE = "https://helpx.adobe.com/security/products/magento/"


# --- helpers ---------------------------------------------------------------------------------


def write_config(tmp_path: Path, extra: str = "", notifiers: str = ONE_NOTIFIER) -> Path:
    """A one-source configuration (and the watchlist it names); ``extra`` is appended as top-level YAML."""
    (tmp_path / "watchlist.json").write_text(
        json.dumps(
            {
                "schema": "security-watchlist.v1",
                "debian_source_packages": ["curl"],
                "excluded_products": [],
                "products": [],
            }
        )
    )
    path = tmp_path / "config.yml"
    path.write_text(
        f"sources:\n  - id: test\n    type: rss\n    url: {FEED_URL}\n{notifiers}"
        f"state_path: {tmp_path}/state.json\nwatchlist: {tmp_path}/watchlist.json\n{extra}"
    )
    return path


def feed(*advisories: tuple[str, str]) -> bytes:
    """An RSS document with one advisory per ``(guid, cve)``, published on 2026-10-21 and fixing its CVE."""
    rows = "".join(
        f"<item><title>Vendor advisory {cve}</title><link>https://vendor.example.com/{guid}</link><guid>{guid}</guid>"
        f"<description>Fixes {cve}.</description><pubDate>Wed, 21 Oct 2026 10:00:00 +0000</pubDate></item>"
        for guid, cve in advisories
    )
    return (
        '<?xml version="1.0"?><rss version="2.0"><channel><title>T</title><link>https://feeds.example.com/</link>'
        f"{rows}</channel></rss>"
    ).encode()


def serve(
    body: bytes, intel: dict[str, tuple[float, str, str, str]] | None = None, kev: tuple[str, ...] = ("CVE-2020-0001",)
):
    """The network of one pass: the feed, CVE.org, EPSS and a KEV catalog that lists ``kev``.

    A catalog with no row is not trusted, so it always lists at least one CVE.
    """
    intel = intel or {}

    def http(method, url, headers, payload):
        if "cveawg.mitre.org" in url:
            cve = url.rsplit("/", 1)[1]
            cvss, vector, _, _ = intel[cve]
            metrics = [{"cvssV3_1": {"baseScore": cvss, "vectorString": vector}}]
            document = {
                "cveMetadata": {"cveId": cve, "state": "PUBLISHED"},
                "containers": {"cna": {"metrics": metrics}},
            }
            return 200, {}, json.dumps(document).encode()
        if "api.first.org" in url:
            rows = [
                {"cve": cve, "epss": epss, "percentile": pct} for cve, (_, _, epss, pct) in intel.items() if cve in url
            ]
            return 200, {}, json.dumps({"data": rows}).encode()
        if "cisa.gov" in url:
            catalog = {"catalogVersion": "1", "vulnerabilities": [{"cveID": cve} for cve in kev]}
            return 200, {"ETag": "k"}, json.dumps(catalog).encode()
        if url == FEED_URL:
            return 200, {}, body
        return 404, {}, b""

    return http


class Notifier:
    """Records what a pass posts, in place of a channel."""

    def __init__(self, notifier_id: str = "fake") -> None:
        self.id = notifier_id
        self.sent: list[dict] = []

    def send(self, entry, http):
        self.sent.append(dict(entry))
        return 200


def run_pass(cfg, http, *notifiers: Notifier, now: int = NOW) -> int:
    return pipeline.run_pass(
        cfg, [RssSource("test", FEED_URL)], list(notifiers), http=http, clock=lambda: float(now), sleep=lambda s: None
    )


def one_message(notifier: Notifier) -> tuple[str, str, str]:
    """``(tag, title, body)`` of the single message a pass posted."""
    [sent] = notifier.sent
    return sent["tag"], sent["title"], sent["body"]


def lines(*parts: str) -> str:
    """A message body: it starts with a newline, which is how every body is rendered."""
    return "\n".join(("", *parts))


CRITICAL_PL = lines(
    "- **Ważność:** CVSS 9.8 · EPSS 0.50 (p99) · SSVC brak",
    "- **Identyfikatory:** CVE-2026-4242",
    "- **Opublikowano:** 2026-10-21",
    "- **Uwaga:** CVSS ≥ 9.0, atak zdalny bez logowania i bez udziału użytkownika (wektor CVSS).",
    "",
    "> Fixes CVE-2026-4242.",
    "",
    "**Działanie:** sprawdź, czy wdrożono podatną wersję.",
    "",
    "- **Biuletyn:** <https://vendor.example.com/a1>",
    "- **Źródło:** T — <https://feeds.example.com/>",
)
CRITICAL_EN = lines(
    "- **Severity:** CVSS 9.8 · EPSS 0.50 (p99) · SSVC none",
    "- **IDs:** CVE-2026-4242",
    "- **Published:** 2026-10-21",
    "- **Note:** CVSS >= 9.0, remote attack, no privileges, no user interaction (CVSS vector).",
    "",
    "> Fixes CVE-2026-4242.",
    "",
    "**Action:** check whether the vulnerable version is deployed.",
    "",
    "- **Advisory:** <https://vendor.example.com/a1>",
    "- **Source:** T — <https://feeds.example.com/>",
)
WARNING_PL = lines(
    "- **Ważność:** CVSS 6.0 · EPSS 0.01 (p30) · SSVC brak",
    "- **Identyfikatory:** CVE-2026-4242",
    "- **Opublikowano:** 2026-10-21",
    "",
    "> Fixes CVE-2026-4242.",
    "",
    "**Działanie:** sprawdź, czy wdrożono podatną wersję.",
    "",
    "- **Biuletyn:** <https://vendor.example.com/a1>",
    "- **Źródło:** T — <https://feeds.example.com/>",
)
ESCALATION_PL = lines(
    "- **Ważność:** CVSS 6.0 · EPSS 0.01 (p30) · SSVC brak · KEV",
    "- **Identyfikatory:** CVE-2026-4242",
    "- **Uwaga:** Zmiana: CVE trafiło do katalogu CISA KEV (wykorzystywane w praktyce).",
    "",
    "> Wcześniej wysłane jako ostrzeżenie \\(2026-10-21\\): Vendor advisory CVE-2026-4242",
    "",
    "**Działanie:** jeśli wersja z biuletynu jest już wdrożona, nic do zrobienia; jeśli nie, załataj priorytetowo.",
    "",
    "- **Biuletyn:** <https://vendor.example.com/a1>",
)
ADOBE_DECISION_PL = "**Do decyzji: sprawdź, czy trzeba powiadomić użytkowników (łatanie może leżeć po ich stronie)**"
ADOBE_NEW_PL = lines(
    "- **Biuletyn Adobe:** APSB26-02",
    "- **Priorytet Adobe:** 1",
    "- **Najwyższy CVSS:** 9.8",
    "- **Uwierzytelnienie wymagane:** nie",
    "- **Wykorzystywana:** nie",
    "- **Wersje dotknięte:** Adobe Commerce → 2.4.7, 2.4.6-p5",
    "- **Wersje naprawione:** Adobe Commerce → 2.4.7-p1, 2.4.6-p6",
    "- **Hotfix:** Apply the hotfix.",
    "",
    ADOBE_DECISION_PL,
    "",
    f"- **Biuletyn:** <{ADOBE_PAGE}apsb26-02.html>",
)
ADOBE_KEV_PL = lines(
    "- **Biuletyn Adobe:** APSB26-01",
    "- **Priorytet Adobe:** 1",
    "- **Wykorzystywana:** tak (CISA KEV)",
    "- **CVE w KEV:** CVE-2026-1001",
    "",
    ADOBE_DECISION_PL,
    "",
    f"- **Biuletyn:** <{ADOBE_PAGE}apsb26-01.html>",
)


# --- the catalogue ---------------------------------------------------------------------------


def placeholders(template: str) -> set[str]:
    """The field names of a template, refusing a literal brace, a positional field or a format spec."""
    names: set[str] = set()
    for literal, name, spec, conversion in string.Formatter().parse(template):
        assert "{" not in literal and "}" not in literal, f"a literal brace in {template!r}"
        if name is not None:
            assert name.isidentifier(), f"{template!r} has the field {name!r}, which is not a plain name"
            assert not spec and conversion is None, f"{template!r} formats the field {name!r}"
            names.add(name)
    return names


def test_the_languages_are_english_and_polish_and_english_is_the_default():
    assert messages.LANGUAGES == ("en", "pl")
    assert set(messages.CATALOGUE) == {"en", "pl"}
    assert messages.DEFAULT_LANGUAGE == "en"


def test_polish_holds_exactly_the_english_keys():
    english, polish = set(messages.CATALOGUE["en"]), set(messages.CATALOGUE["pl"])
    assert not english - polish, f"keys the Polish catalogue lacks: {sorted(english - polish)}"
    assert not polish - english, f"keys only the Polish catalogue has: {sorted(polish - english)}"


@pytest.mark.parametrize("language", messages.LANGUAGES)
def test_every_value_is_a_non_empty_string_with_plain_placeholders(language):
    for key, template in messages.CATALOGUE[language].items():
        assert isinstance(template, str) and template.strip(), f"{language}: {key} is empty"
        placeholders(template)


def test_a_key_has_the_same_placeholders_in_both_languages():
    for key, english in messages.CATALOGUE["en"].items():
        assert placeholders(messages.CATALOGUE["pl"][key]) == placeholders(english), key


# --- the option ------------------------------------------------------------------------------


def test_language_defaults_to_english(tmp_path):
    assert load_config(write_config(tmp_path), {}).language == "en"


@pytest.mark.parametrize("code", ["en", "pl"])
def test_a_supported_language_is_accepted(tmp_path, code):
    assert load_config(write_config(tmp_path, f"language: {code}\n"), {}).language == code


@pytest.mark.parametrize("raw", ["de", "PL", "pl-PL", '" pl"', '""', "1", "true", "[pl]", "null"])
def test_any_other_value_is_refused_and_the_error_names_the_allowed_ones(tmp_path, raw):
    with pytest.raises(ConfigError) as caught:
        load_config(write_config(tmp_path, f"language: {raw}\n"), {})
    assert "language must be one of en, pl" in str(caught.value)


def test_a_refused_value_is_never_echoed(tmp_path):
    """The value may be the expansion of a ``${NAME}`` reference, and the error is logged before redaction."""
    path = write_config(tmp_path, "language: ${PICK}\n")
    assert load_config(path, {"PICK": "pl"}).language == "pl"
    with pytest.raises(ConfigError) as caught:
        load_config(path, {"PICK": "hunter2-not-a-language"})
    assert "hunter2" not in str(caught.value)
    assert "language must be one of en, pl" in str(caught.value)


def test_a_settings_overlay_cannot_carry_language(tmp_path):
    with pytest.raises(ConfigError) as caught:
        load_config(write_config(tmp_path), {}, settings={"language": "pl"})
    assert "unknown overlay keys" in str(caught.value)
    assert "language" in str(caught.value)


def test_a_reload_applies_a_changed_language_without_a_restart(tmp_path):
    path = write_config(tmp_path)
    runtime = Runtime.build(path, {})
    try:
        assert runtime.cfg.language == "en"
        write_config(tmp_path, "language: pl\n")
        runtime.reload(blocking=False)
        assert runtime.cfg.language == "pl"
    finally:
        runtime.detach_redaction()


def test_a_yaml_language_survives_a_saved_overlay_and_a_reload(tmp_path):
    """The usual install: ``language`` in the YAML and something saved on /config. The overlay never carries it."""
    path = write_config(tmp_path, "language: pl\n")
    overlay = settings_path(tmp_path / "state.json")
    save_settings(overlay, {"digest": True}, now=NOW)
    runtime = Runtime.build(path, {})
    try:
        assert (runtime.cfg.language, runtime.cfg.digest) == ("pl", True)
        save_settings(overlay, {"digest": False}, now=NOW + 1)
        runtime.reload(blocking=False)
        assert (runtime.cfg.language, runtime.cfg.digest) == ("pl", False)
    finally:
        runtime.detach_redaction()


# --- English is unchanged --------------------------------------------------------------------


@pytest.mark.parametrize("extra", ["", "language: en\n"])
def test_english_is_the_default_and_its_text_is_unchanged(tmp_path, extra):
    cfg = load_config(write_config(tmp_path, extra), {})
    notifier = Notifier()
    assert run_pass(cfg, serve(feed(("a1", "CVE-2026-4242")), {"CVE-2026-4242": CRITICAL}), notifier) == 0
    assert one_message(notifier) == ("critical", "CRITICAL: Vendor advisory CVE-2026-4242", CRITICAL_EN)


def test_the_helpers_the_routing_preview_calls_stay_english():
    """``web`` previews a verdict through these with no language argument; the setting must never reach it."""
    assert core.metrics_line(9.8, None, None, None, False) == "CVSS 9.8 · EPSS none · SSVC none"
    assert core.reason_note("epss", DEFAULT_THRESHOLDS) == "Likely exploitation (EPSS), unconfirmed."
    assert core.LEVEL_LABEL == {"critical": "CRITICAL", "warning": "WARNING"}


# --- the Polish of each kind of message, through a real pass ---------------------------------


def test_a_critical_advisory_in_polish(tmp_path):
    cfg = load_config(write_config(tmp_path, "language: pl\n"), {})
    notifier = Notifier()
    assert run_pass(cfg, serve(feed(("a1", "CVE-2026-4242")), {"CVE-2026-4242": CRITICAL}), notifier) == 0
    assert one_message(notifier) == ("critical", "KRYTYCZNE: Vendor advisory CVE-2026-4242", CRITICAL_PL)


def test_a_warning_advisory_in_polish(tmp_path):
    cfg = load_config(write_config(tmp_path, "language: pl\n"), {})
    notifier = Notifier()
    assert run_pass(cfg, serve(feed(("a1", "CVE-2026-4242")), {"CVE-2026-4242": WARNING}), notifier) == 0
    assert one_message(notifier) == ("warning", "OSTRZEŻENIE: Vendor advisory CVE-2026-4242", WARNING_PL)


def test_an_escalation_in_polish(tmp_path):
    cfg = load_config(write_config(tmp_path, "language: pl\n"), {})
    advisory, intel = feed(("a1", "CVE-2026-4242")), {"CVE-2026-4242": WARNING}
    notifier = Notifier()
    assert run_pass(cfg, serve(advisory, intel), notifier) == 0
    # Two days later CISA lists the CVE: the reader of the warning is told it is now critical.
    assert run_pass(cfg, serve(advisory, intel, kev=("CVE-2026-4242",)), notifier, now=NOW + 2 * DAY) == 0
    first, escalation = notifier.sent
    assert (first["tag"], first["title"]) == ("warning", "OSTRZEŻENIE: Vendor advisory CVE-2026-4242")
    assert (escalation["tag"], escalation["title"], escalation["body"]) == (
        "critical",
        "KRYTYCZNE: CVE-2026-4242 teraz krytyczne",
        ESCALATION_PL,
    )


def test_a_digest_in_polish(tmp_path):
    cfg = load_config(write_config(tmp_path, "language: pl\ndigest: true\n"), {})
    advisories = feed(("a1", "CVE-2026-4242"), ("a2", "CVE-2026-4243"))
    notifier = Notifier()
    assert run_pass(cfg, serve(advisories, {"CVE-2026-4242": CRITICAL, "CVE-2026-4243": WARNING}), notifier) == 0
    assert one_message(notifier) == (
        "critical",
        "KRYTYCZNE: zestawienie 2 biuletynów",
        lines(
            "- **KRYTYCZNE: Vendor advisory CVE-2026-4242** (CVE-2026-4242)",
            "- **OSTRZEŻENIE: Vendor advisory CVE-2026-4243** (CVE-2026-4243)",
        ),
    )


def test_adobe_bulletins_in_polish(tmp_path, monkeypatch):
    """A new bulletin and the follow-up for one that CISA has since listed as exploited."""
    cfg = load_config(write_config(tmp_path, "language: pl\nadobe_commerce: true\n"), {})
    listed = adobe.Bulletin("APSB26-01", 1, ("CVE-2026-1001",), f"{ADOBE_PAGE}apsb26-01.html")
    fresh = adobe.Bulletin("APSB26-02", 1, ("CVE-2026-1002",), f"{ADOBE_PAGE}apsb26-02.html")
    detail = adobe.Detail(
        (adobe.CveDetail("CVE-2026-1002", "critical", False, 9.8),),
        (("Adobe Commerce", ("2.4.7", "2.4.6-p5")),),
        (("Adobe Commerce", ("2.4.7-p1", "2.4.6-p6")),),
        "Apply the hotfix.",
        False,
    )
    monkeypatch.setattr(core, "_adobe_list", lambda http, stored: (listed, fresh))
    monkeypatch.setattr(core, "_adobe_detail", lambda http, apsb: detail)
    state = core.new_state()
    state["adobe"] = {
        "window": ["APSB26-01"],
        "seen": {"APSB26-01": {"cves": ["CVE-2026-1001"], "at": NOW, "exploited": False}},
    }
    save_state(cfg.state_path, state)
    notifier = Notifier()
    assert run_pass(cfg, serve(feed(), kev=("CVE-2026-1001",)), notifier) == 0
    by_kind = {sent["kind"]: sent for sent in notifier.sent}
    assert set(by_kind) == {"adobe", "adobe-kev"}
    assert (by_kind["adobe"]["tag"], by_kind["adobe"]["title"], by_kind["adobe"]["body"]) == (
        "critical",
        "KRYTYCZNE: Adobe Commerce APSB26-02",
        ADOBE_NEW_PL,
    )
    assert (by_kind["adobe-kev"]["tag"], by_kind["adobe-kev"]["title"], by_kind["adobe-kev"]["body"]) == (
        "critical",
        "KRYTYCZNE: Adobe Commerce APSB26-01",
        ADOBE_KEV_PL,
    )


@pytest.mark.parametrize(
    ("language", "title", "body"),
    [
        (
            "en",
            "WARNING: advisory-radar test notification",
            lines("- **Severity:** test", "- **Note:** if you read this, delivery works."),
        ),
        (
            "pl",
            "OSTRZEŻENIE: powiadomienie testowe advisory-radar",
            lines("- **Ważność:** test", "- **Uwaga:** jeśli to czytasz, dostarczanie działa."),
        ),
    ],
)
def test_test_notify_speaks_the_configured_language(tmp_path, language, title, body):
    path = write_config(tmp_path, f"language: {language}\n")
    posted: list[dict] = []

    def http(method, url, headers, payload):
        posted.append(json.loads(payload))
        return 204, {}, b""

    assert cli.main(["--config", str(path), "test-notify"], env={}, http=http) == 0
    assert [(sent["tag"], sent["title"], sent["body"]) for sent in posted] == [("warning", title, body)]


def test_the_routing_tag_stays_english_so_a_tag_route_still_matches(tmp_path):
    notifiers = (
        "notifiers:\n  - id: urgent\n    type: webhook\n    url: https://hooks.example.com/urgent\n"
        "  - id: calm\n    type: webhook\n    url: https://hooks.example.com/calm\n"
    )
    routes = "routes:\n  - match: {tag: critical}\n    notifiers: [urgent]\ndefault: [calm]\n"
    cfg = load_config(write_config(tmp_path, "language: pl\n" + routes, notifiers), {})
    urgent, calm = Notifier("urgent"), Notifier("calm")
    advisories = feed(("a1", "CVE-2026-4242"), ("a2", "CVE-2026-4243"))
    assert run_pass(cfg, serve(advisories, {"CVE-2026-4242": CRITICAL, "CVE-2026-4243": WARNING}), urgent, calm) == 0
    assert [(sent["tag"], sent["title"]) for sent in urgent.sent] == [
        ("critical", "KRYTYCZNE: Vendor advisory CVE-2026-4242")
    ]
    assert [(sent["tag"], sent["title"]) for sent in calm.sent] == [
        ("warning", "OSTRZEŻENIE: Vendor advisory CVE-2026-4243")
    ]


# --- the rest of the Polish text, one branch at a time ---------------------------------------


def facts(cvss=None, epss=None, *, remote=False, complete=True):
    return core.CveFacts(cvss, None, epss, None, complete, remote_unauth=remote)


def test_a_long_id_list_the_published_day_a_note_and_a_source_in_polish(monkeypatch):
    monkeypatch.setattr(core, "HIDDEN_SOURCE_HOSTS", frozenset())
    ids = [f"CVE-2026-{number:04d}" for number in range(1, 13)]
    title, body = core.render(
        "warning",
        "Some advisory (v1)",
        ids,
        "CVSS 5.0",
        "A note.",
        "https://vendor.example.com/a",
        "Vendor text",
        NOW,
        "feeds.example.com",
        "Feed",
        "https://feeds.example.com/",
        language="pl",
    )
    assert title == "OSTRZEŻENIE: Some advisory \\(v1\\)"
    assert body == lines(
        "- **Ważność:** CVSS 5.0",
        f"- **Identyfikatory:** {', '.join(ids[:10])} (+2 więcej)",
        "- **Opublikowano:** 2026-10-21",
        "- **Uwaga:** A note.",
        "",
        "> Vendor text",
        "",
        "**Działanie:** sprawdź, czy wdrożono podatną wersję.",
        "",
        "- **Biuletyn:** <https://vendor.example.com/a>",
        "- **Źródło:** Feed — <https://feeds.example.com/>",
    )


@pytest.mark.parametrize(
    ("ids", "scores", "osv", "complete", "extra", "expected"),
    [
        (
            [],
            {},
            None,
            True,
            {},
            ("warning", "nieznana (brak identyfikatora CVE i brak oceny w OSV)", ""),
        ),
        (
            [],
            {},
            6.0,
            False,
            {},
            (
                "warning",
                "CVSS 6.0 (etykieta OSV, przybliżone) · EPSS brak · SSVC brak",
                "Niepełne dane o ważności; traktowane jako nieznane.",
            ),
        ),
        (
            ["CVE-2026-1"],
            {"CVE-2026-1": facts(2.0)},
            None,
            True,
            {"independent_ghsa_cvss": 9.5},
            (
                "critical",
                "ważność GHSA wg OSV 9.5 (przybliżona); CVSS 2.0 · EPSS brak · SSVC brak",
                "O ważności decyduje biuletyn w tej pozycji, który nie ma identyfikatora CVE.",
            ),
        ),
        (
            ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"],
            {"CVE-2026-1": facts(5.0), "CVE-2026-2": facts(9.8, remote=True), "CVE-2026-3": facts(4.5)},
            None,
            True,
            {},
            (
                "critical",
                "CVE-2026-2: CVSS 9.8 · EPSS brak · SSVC brak (+2 CVE więcej)",
                "CVSS ≥ 9.0, atak zdalny bez logowania i bez udziału użytkownika (wektor CVSS).",
            ),
        ),
        (
            ["CVE-2026-1", "CVE-2026-2"],
            {"CVE-2026-1": facts(5.0), "CVE-2026-2": facts(complete=False)},
            None,
            True,
            {},
            (
                "warning",
                "CVE-2026-1: CVSS 5.0 · EPSS brak · SSVC brak (+1 CVE więcej) (+1 CVE bez oceny)",
                "Niepełne dane o ważności; traktowane jako nieznane.",
            ),
        ),
        (
            ["CVE-2026-1"],
            {"CVE-2026-1": facts(9.5, 0.5)},
            None,
            True,
            {},
            ("critical", "CVSS 9.5 · EPSS 0.50 · SSVC brak", "Prawdopodobne wykorzystanie (EPSS), niepotwierdzone."),
        ),
    ],
    ids=["no-id", "osv-approximate", "ghsa-decides", "more-cves", "unscored", "epss"],
)
def test_the_verdict_line_and_note_in_polish(ids, scores, osv, complete, extra, expected):
    verdict = core.judge(
        ids, scores, frozenset(), True, osv, complete, thresholds=DEFAULT_THRESHOLDS, language="pl", **extra
    )
    assert (verdict.tag, verdict.line, verdict.note) == expected


def test_the_reason_and_change_notes_in_polish():
    notes = {
        reason: (
            core.reason_note(reason, DEFAULT_THRESHOLDS, language="pl"),
            core.change_note(reason, DEFAULT_THRESHOLDS, language="pl"),
        )
        for reason in ("kev", "ssvc", "remote", "epss")
    }
    assert notes == {
        "kev": ("", "Zmiana: CVE trafiło do katalogu CISA KEV (wykorzystywane w praktyce)."),
        "ssvc": ("", "Zmiana: CISA oznaczyła aktywne wykorzystanie (SSVC)."),
        "remote": (
            "CVSS ≥ 9.0, atak zdalny bez logowania i bez udziału użytkownika (wektor CVSS).",
            "Zmiana: pojawiła się ocena CVSS ≥ 9.0 dla ataku zdalnego bez logowania i bez udziału użytkownika.",
        ),
        "epss": (
            "Prawdopodobne wykorzystanie (EPSS), niepotwierdzone.",
            "Zmiana: ryzyko wykorzystania (EPSS) na poziomie co najmniej 0.1; niepotwierdzone.",
        ),
    }


class Lookups:
    """The lookups ``classify_new`` makes for a release item, answered with fixed data (the real ones read pages)."""

    tracker_left = 5

    def __init__(self, *, php: core.PhpRelease | None = None, node: core.NodejsRelease | None = None) -> None:
        self._php, self._node = php, node

    def announcement_read(self) -> bool:
        return False

    def changelog_read(self, version: str) -> bool:
        return False

    def nodejs_read(self, slug: str) -> bool:
        return False

    def php_cves(self, version: str) -> core.PhpRelease | None:
        return self._php

    def nodejs_page(self, slug: str) -> core.NodejsRelease | None:
        return self._node

    def cves(self, cves, **ignored):
        return {cve: facts(5.0) for cve in cves}


def test_release_excerpts_and_the_unreadable_page_note_in_polish(tmp_path):
    write_config(tmp_path)
    policy = load_policy(tmp_path / "watchlist.json")

    def classify(item: core.Item, lookups: Lookups, state: dict | None = None) -> str:
        state = core.new_state() if state is None else state
        core.classify_new(
            state,
            [item],
            lookups,
            frozenset({"CVE-2020-0001"}),
            True,
            NOW,
            "feeds.example.com",
            policy,
            thresholds=DEFAULT_THRESHOLDS,
            source_id="test",
            language="pl",
        )
        [queued] = state["pending"]
        return queued["body"]

    php = core.Item(
        "g-php", "PHP 8.4.26 released!", "https://www.php.net/releases/8.4.26.php", "Security.", NOW - 3600, ()
    )
    node = core.Item(
        "g-node",
        "Wednesday, October 21, 2026 Security Releases",
        "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
        "Security.",
        NOW - 3600,
        (),
    )
    release = core.PhpRelease(("CVE-2026-1111",), (), ("8.4.26", "8.3.30"))
    assert (
        "> Wydanie bezpieczeństwa PHP; poprawione wersje: 8.4.26, 8.3.30"
        in classify(php, Lookups(php=release)).splitlines()
    )
    page = core.NodejsRelease(("CVE-2026-9999",), ("26.x", "24.x"))
    assert "> Wydanie bezpieczeństwa Node.js; linie: 26.x, 24.x" in classify(node, Lookups(node=page)).splitlines()
    # The page stayed unreadable past the retry clock: the item goes out once, as a warning that says why.
    state = core.new_state()
    state["enrich_retry"] = {"g-php": NOW - core.ENRICH_RETRY_SECONDS - 5}
    unreadable = classify(php, Lookups(php=None), state).splitlines()
    assert "- **Uwaga:** Nie udało się odczytać listy CVE ze źródła; ważność nieznana." in unreadable


def test_adobe_fact_values_in_polish():
    bulletin = adobe.Bulletin("APSB26-03", None, (), f"{ADOBE_PAGE}apsb26-03.html")

    def body(detail: adobe.Detail | None, exploited: str) -> list[str]:
        return core._adobe_new_message(bulletin, detail, exploited, "pl")["body"].splitlines()

    nothing = body(None, "unknown")
    for line in (
        "- **Priorytet Adobe:** nieznany",
        "- **Najwyższy CVSS:** brak szczegółów",
        "- **Uwierzytelnienie wymagane:** brak szczegółów",
        "- **Wykorzystywana:** brak danych",
        "- **Wersje dotknięte:** brak szczegółów",
        "- **Wersje naprawione:** brak szczegółów",
    ):
        assert line in nothing
    only_moderate = adobe.Detail((adobe.CveDetail("CVE-2026-1", "moderate", False, 4.0),), (), (), "", False)
    assert "- **Uwierzytelnienie wymagane:** brak CVE krytycznych" in body(only_moderate, "no")
    login = adobe.Detail((adobe.CveDetail("CVE-2026-1", "critical", True, 9.0),), (), (), "", False)
    assert "- **Uwierzytelnienie wymagane:** tak" in body(login, "yes")
    assert "- **Wykorzystywana:** tak" in body(login, "yes")


def test_digest_words_in_polish():
    def entries(count: int) -> list[dict]:
        return [{"title": f"WARNING: advisory {n}", "ids": [f"CVE-2026-{n}"], "tag": "warning"} for n in range(count)]

    one = delivery.digest_message(entries(1), language="pl")
    assert (one["tag"], one["title"]) == ("warning", "OSTRZEŻENIE: zestawienie 1 biuletynu")
    assert delivery.digest_message(entries(5), language="pl")["title"] == "OSTRZEŻENIE: zestawienie 5 biuletynów"
    many = delivery.digest_message(entries(22), language="pl")
    assert many["title"] == "OSTRZEŻENIE: zestawienie 22 biuletynów"
    assert many["body"].splitlines()[-1] == "(+2 więcej poza listą)"
    untitled = delivery.digest_message([{"title": None, "ids": "x"}], language="pl")
    assert untitled["body"] == lines("- **(biuletyn bez tytułu)**")
    [batch] = delivery.plan(entries(2), NOW, digest=True, language="pl")
    assert batch.message["title"] == "OSTRZEŻENIE: zestawienie 2 biuletynów"


def test_a_polish_digest_that_hits_the_character_budget_still_fits_it():
    """The notice of the advisories left out is longer in Polish; the trim counts it, so the message still fits."""
    crowded = [{"title": "Ż" * 140 + f" {n}", "ids": [f"CVE-2026-{n}"], "tag": "warning"} for n in range(20)]
    message = delivery.digest_message(crowded, language="pl")
    assert len(message["body"]) <= delivery.DIGEST_BODY_LIMIT - len(message["title"])
    listed = [line for line in message["body"].splitlines() if line.startswith("- **")]
    assert 0 < len(listed) < len(crowded)
    assert message["body"].splitlines()[-1] == f"(+{len(crowded) - len(listed)} więcej poza listą)"
