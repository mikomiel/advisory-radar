"""The words a notification is written in: one catalogue per language, and nothing else.

``language`` in ``config.yml`` picks the language of every human-readable string the product writes into a
notification: the level word of a title, the labels of the fact list, the notes that explain a verdict, the
action line, the digest wording, the Adobe bulletin messages, the words the service itself writes for a changed
web page and the ``test-notify`` message. Text that came from a feed or a vendor page is never translated: it
is not in the catalogue and passes through unchanged. The web UI is English whatever the setting.

The routing tag a notifier receives (``critical`` or ``warning``) is not text. ``routing`` matches on it, so it
stays English in every language and only the ``level.*`` words a reader sees are translated.

The catalogue is flat on purpose: a key names one string, a placeholder is a ``str.format`` field, and a
template holds no literal brace. ``tests/test_messages.py`` pins that both languages carry exactly the same
keys and the same placeholders, so a string added to one language and forgotten in the other fails a test
instead of failing a notification. English is the default, and its output is the text the product wrote before
the option existed.

This module imports nothing from the package: ``config`` validates the option with it, ``delivery`` stays free
of ``core``, and ``core`` renders with it.
"""

from __future__ import annotations

#: The language a configuration that states none gets.
DEFAULT_LANGUAGE = "en"

_EN = {
    # The level word of a title, and of an escalation heading. A title shows it in capitals.
    "level.critical": "CRITICAL",
    "level.warning": "WARNING",
    # Labels of the fact list, and the identifier list's overflow.
    "label.severity": "Severity",
    "label.ids": "IDs",
    "label.published": "Published",
    "label.note": "Note",
    "label.advisory": "Advisory",
    "label.source": "Source",
    "ids.more": "{ids} (+{count} more)",
    # The paragraph under the excerpt. An escalation reaches readers who already acted on the first message.
    "action": "**Action:** check whether the vulnerable version is deployed.",
    "action.escalation": (
        "**Action:** if the advisory version is already deployed, nothing to do; otherwise patch promptly."
    ),
    # The severity line. CVSS, EPSS, SSVC and KEV are names and are written as they are.
    "metrics.none": "none",
    "metrics.cvss_approximate": "{score} (OSV label, approximate)",
    "judge.unknown": "unknown (no CVE id and no OSV score)",
    "judge.ghsa_severity": "OSV GHSA severity {score} (approximate); {line}",
    "judge.more_cves": "{cve}: {line} (+{count} more CVEs)",
    "judge.unscored": "{line} (+{count} CVEs unscored)",
    # The note under the severity line.
    "note.epss": "Likely exploitation (EPSS), unconfirmed.",
    "note.remote": "CVSS >= {cvss}, remote attack, no privileges, no user interaction (CVSS vector).",
    "note.incomplete": "Incomplete severity data; treated as unknown.",
    "note.ghsa_decides": "An advisory in this item without a CVE id decides the severity.",
    "note.enrich_failed": "The CVE list could not be read from the source; severity unknown.",
    # An escalation: what changed, and what the first message said.
    "change.kev": "Change: CVE added to the CISA KEV catalog (exploited in the wild).",
    "change.ssvc": "Change: CISA recorded active exploitation (SSVC).",
    "change.epss": "Change: exploitation likelihood (EPSS) at or above {epss}; unconfirmed.",
    "change.remote": "Change: a CVSS >= {cvss} score appeared for a remote, unauthenticated, no-interaction attack.",
    "escalation.heading": "{cve} now {level}",
    "escalation.before.suppressed": "recorded as LOW and not sent",
    "escalation.before.sent": "sent as a warning",
    "escalation.excerpt": "Previously {before} ({day}): {title}",
    # The excerpt of a release item that its source page enriched; the versions or lines follow.
    "excerpt.php": "PHP security release; fixed versions: {versions}",
    "excerpt.nodejs": "Node.js security release; lines: {lines}",
    # The words the service writes for a changed web page, when the page has no text of its own to show: the
    # summary of a changedetection.io watch, and the title and summary of a webhook payload that names no watch
    # or carries no diff. An item stores the key and its fields, so the language is chosen when the message is
    # written, not when the source is read.
    "item.summary.page_changed": "Page changed (last_changed={changed}).",
    "item.summary.no_diff": "page changed",
    "item.title.change": "change",
    # A digest. The title is ``<LEVEL>: <this>``; the count picks the singular or the plural form.
    "digest.title.one": "digest of {count} advisory",
    "digest.title.other": "digest of {count} advisories",
    "digest.untitled": "(untitled advisory)",
    "digest.omitted": "(+{count} more not listed)",
    # An Adobe Commerce bulletin. Its link keeps the label it has always had.
    "adobe.decision": (
        "**Decision needed:** check whether downstream users must be notified (patching may be on their side)"
    ),
    "label.adobe_link": "Biuletyn",
    "adobe.label.bulletin": "Adobe bulletin",
    "adobe.label.priority": "Adobe priority",
    "adobe.label.cvss": "Highest CVSS",
    "adobe.label.auth": "Authentication required",
    "adobe.label.exploited": "Exploited",
    "adobe.label.affected": "Affected versions",
    "adobe.label.fixed": "Fixed versions",
    "adobe.label.hotfix": "Hotfix",
    "adobe.label.kev": "CVEs in KEV",
    "adobe.priority_unknown": "unknown",
    "adobe.no_details": "no details",
    "adobe.auth.none_critical": "no critical CVEs",
    "adobe.auth.yes": "yes",
    "adobe.auth.no": "no",
    "adobe.exploited.yes": "yes",
    "adobe.exploited.no": "no",
    "adobe.exploited.unknown": "unknown",
    "adobe.exploited.kev": "yes (CISA KEV)",
    # ``advisory-radar test-notify``. The title is ``<LEVEL>: <this>``.
    "test.title": "advisory-radar test notification",
    "test.body": "- **Severity:** test\n- **Note:** if you read this, delivery works.",
}

_PL = {
    "level.critical": "krytyczne",
    "level.warning": "ostrzeżenie",
    "label.severity": "Ważność",
    "label.ids": "Identyfikatory",
    "label.published": "Opublikowano",
    "label.note": "Uwaga",
    "label.advisory": "Biuletyn",
    "label.source": "Źródło",
    "ids.more": "{ids} (+{count} więcej)",
    "action": "**Działanie:** sprawdź, czy wdrożono podatną wersję.",
    "action.escalation": (
        "**Działanie:** jeśli wersja z biuletynu jest już wdrożona, nic do zrobienia; jeśli nie, załataj priorytetowo."
    ),
    "metrics.none": "brak",
    "metrics.cvss_approximate": "{score} (etykieta OSV, ocena przybliżona)",
    "judge.unknown": "nieznana (brak identyfikatora CVE i brak oceny w OSV)",
    "judge.ghsa_severity": "ważność GHSA wg OSV {score} (przybliżona); {line}",
    "judge.more_cves": "{cve}: {line} (+{count} CVE więcej)",
    "judge.unscored": "{line} (+{count} CVE bez oceny)",
    "note.epss": "Prawdopodobne wykorzystanie (EPSS), niepotwierdzone.",
    "note.remote": "CVSS ≥ {cvss}, atak zdalny bez logowania i bez udziału użytkownika (wektor CVSS).",
    "note.incomplete": "Niepełne dane o ważności; traktowane jako nieznane.",
    "note.ghsa_decides": "O ważności decyduje biuletyn w tej pozycji, który nie ma identyfikatora CVE.",
    "note.enrich_failed": "Nie udało się odczytać listy CVE ze źródła; ważność nieznana.",
    "change.kev": "Zmiana: CVE trafiło do katalogu CISA KEV (wykorzystywane w praktyce).",
    "change.ssvc": "Zmiana: CISA oznaczyła aktywne wykorzystanie (SSVC).",
    "change.epss": "Zmiana: ryzyko wykorzystania (EPSS) na poziomie co najmniej {epss}; niepotwierdzone.",
    "change.remote": (
        "Zmiana: pojawiła się ocena CVSS ≥ {cvss} dla ataku zdalnego bez logowania i bez udziału użytkownika."
    ),
    "escalation.heading": "{cve} teraz {level}",
    "escalation.before.suppressed": "zapisane z niską ważnością i niewysłane",
    "escalation.before.sent": "wysłane jako ostrzeżenie",
    "escalation.excerpt": "Wcześniej {before} ({day}): {title}",
    "excerpt.php": "Wydanie bezpieczeństwa PHP; poprawione wersje: {versions}",
    "excerpt.nodejs": "Wydanie bezpieczeństwa Node.js; linie: {lines}",
    "item.summary.page_changed": "Strona uległa zmianie (last_changed={changed}).",
    "item.summary.no_diff": "strona uległa zmianie",
    "item.title.change": "zmiana",
    # "zestawienie" takes the genitive: one form for a single advisory, one for every other count.
    "digest.title.one": "zestawienie {count} biuletynu",
    "digest.title.other": "zestawienie {count} biuletynów",
    "digest.untitled": "(biuletyn bez tytułu)",
    "digest.omitted": "(+{count} więcej poza listą)",
    # The line is wrapped in bold when it is rendered, so it carries no bold marker of its own.
    "adobe.decision": "Do decyzji: sprawdź, czy trzeba powiadomić użytkowników (łatanie może leżeć po ich stronie)",
    "label.adobe_link": "Biuletyn",
    "adobe.label.bulletin": "Biuletyn Adobe",
    "adobe.label.priority": "Priorytet Adobe",
    "adobe.label.cvss": "Najwyższy CVSS",
    "adobe.label.auth": "Uwierzytelnienie wymagane",
    "adobe.label.exploited": "Wykorzystywana",
    "adobe.label.affected": "Wersje dotknięte",
    "adobe.label.fixed": "Wersje naprawione",
    "adobe.label.hotfix": "Hotfix",
    "adobe.label.kev": "CVE w KEV",
    "adobe.priority_unknown": "nieznany",
    "adobe.no_details": "brak szczegółów",
    "adobe.auth.none_critical": "brak CVE krytycznych",
    "adobe.auth.yes": "tak",
    "adobe.auth.no": "nie",
    "adobe.exploited.yes": "tak",
    "adobe.exploited.no": "nie",
    "adobe.exploited.unknown": "brak danych",
    "adobe.exploited.kev": "tak (CISA KEV)",
    "test.title": "powiadomienie testowe advisory-radar",
    "test.body": "- **Ważność:** test\n- **Uwaga:** jeśli to czytasz, dostarczanie działa.",
}

#: Language code -> its catalogue. The order is the order the configuration error names the codes in.
CATALOGUE: dict[str, dict[str, str]] = {"en": _EN, "pl": _PL}
LANGUAGES = tuple(CATALOGUE)


def text(language: str, key: str, **fields: object) -> str:
    """The catalogue string ``key`` in ``language``, with ``fields`` filled into its placeholders.

    An unknown language or key is a programming error and raises ``KeyError``: the configuration validates the
    language, and the catalogue test pins the keys, so a lookup that fails here means the code asked for
    something the catalogue does not hold.
    """
    return CATALOGUE[language][key].format(**fields)


def level_title(language: str, tag: str, subject: str) -> str:
    """``CRITICAL: <subject>``: the title every message starts with, its level word in capitals."""
    return f"{text(language, f'level.{tag}').upper()}: {subject}"
