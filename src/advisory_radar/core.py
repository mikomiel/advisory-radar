"""Core pipeline of advisory-radar: feed items -> CVE facts -> verdict -> rendered message -> delivery state.

Ported from a proven single-purpose worker and generalised: sources and
notifiers are plugins (plugins.py / sources.py / notifiers.py), configuration
comes from config.py, secrets come from the environment (never a credential
file baked into the image). The correctness rules are carried over unchanged:

* atomic state writes; an item enters ``pending`` before delivery and leaves it
  only after every notifier answered 2xx, so an unreachable channel keeps it;
* a message that fails MAX_DELIVERY_ATTEMPTS times, or whose first attempt is
  older than PARK_AFTER, is parked, never discarded on its own;
* a full export window that shares no entry with the previous one is a window
  gap and fails the pass (items may have been missed);
* an item older than BACKLOG_AGE at first sight is history, never alerted;
* watched CVEs are re-scored once a day and escalated at most once per level;
* a failed lookup never suppresses and never promotes an item;
* vendor text is Markdown-neutralised before rendering; secrets are redacted
  from logs by a second-line filter.
"""

from __future__ import annotations

import datetime
import fnmatch
import hashlib
import hmac
import json
import logging
import math
import re
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from . import adobe, delivery, routing
from .config import DEFAULT_THRESHOLDS, Thresholds
from .feeds import FeedExport
from .feeds import parse_feed as parse_greader
from .http import MESSAGE_LIMIT, Http, inert, log_safe, parse_json
from .state import SourceError
from .storage import Store, StoreUnavailable
from .watchlist import Policy, Product

LOG = logging.getLogger("advisory_radar")

STATE_SCHEMA = "advisory-radar-state.v1"
DEFAULT_STATE = Path("data/state.json")

HTTP_TIMEOUT = 30
CVE_ORG_URL = "https://cveawg.mitre.org/api/cve/"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
OSV_URL = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/"
#: A tracker page for one DSA is about 2 kB; a response above this is not one.
MAX_TRACKER_BYTES = 1024 * 1024
#: ``<major>.php`` is appended; the major comes from a php.net release title (see ``php_release``) or from
#: ``PHP_CHANGELOG_MAJORS``, never from other feed text.
PHP_CHANGELOG_URL = "https://www.php.net/ChangeLog-"
#: The majors whose ChangeLog is searched for a release date (``php_announcement``). A constant, so that no feed text
#: chooses the URL.
PHP_CHANGELOG_MAJORS = ("8",)
#: The PHP 8 ChangeLog was 726 kB on 2026-10-21 and grows by a few kB per release; a response above this is not one.
MAX_CHANGELOG_BYTES = 4 * 1024 * 1024
#: The slug of a nodejs.org vulnerability post is appended (see ``nodejs_slug``); the slug comes from a feed link that
#: matched ``NODEJS_PATH_RE``, never the link as given.
NODEJS_VULN_URL = "https://nodejs.org/en/blog/vulnerability/"
#: A security release page was 289 kB on 2026-10-22 (most of it a duplicate copy of the post for the page's scripts);
#: a response above this is not one.
MAX_NODEJS_PAGE_BYTES = 2 * 1024 * 1024
#: ``urllib_http`` buffers at most this many bytes plus one, so that no response exhausts the worker's memory. It
#: is no smaller than any source's own cap, the largest being the MSRC document's (``msrc_products.MAX_BODY_BYTES``):
#: a longer body arrives as ``MAX_RESPONSE_BYTES + 1`` bytes and that source's own check rejects it, as it does a
#: shorter one that is still too long.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
#: NVD admits 5 requests per 30 s without a key; the worker waits this long before every call.
NVD_PACE_SECONDS = 6.0
#: With a free API key NVD admits 50 requests per 30 s, so the same wait would waste nine tenths of the budget.
NVD_KEY_PACE_SECONDS = 0.6

DAY = 86400
CACHE_TTL = DAY
REEVAL_INTERVAL = DAY
REEVAL_WINDOW = 14 * DAY
SEED_WINDOW = DAY
#: An item older than this at first sight is recorded as ``backlog``, not alerted (see ``classify_new``).
BACKLOG_AGE = 7 * DAY
DELIVERY_CAP = 5
#: A pending message that fails this many attempts, or whose first attempt is older than PARK_AFTER, is parked.
#: A notifier may answer 4xx when one of its own legs fails while others already posted. This cap is therefore
#: also the bound on duplicate posts of one message: at most MAX_DELIVERY_ATTEMPTS per notifier, then it waits
#: for the operator.
MAX_DELIVERY_ATTEMPTS = 3
PARK_AFTER = 3600
#: The parked list is bounded; when full, a failing message stays pending (see ``_park``), never discarded.
MAX_PARKED = 50
#: Bounds the lookups of one pass; unclassified items stay unseen and are picked up on the next pass.
MAX_CLASSIFY = 15
MAX_REEVAL = 10
#: One advisory can name 50-150 CVEs (a Debian kernel DSA, a GitLab patch release). Only the first few are
#: looked up in CVE.org/NVD; the rest are unscored, so the item can never be suppressed. KEV is a local set and
#: stays complete; EPSS is one cheap batch call per EPSS_BATCH ids.
MAX_ITEM_CVE_LOOKUPS = 10
#: OSV lookups one item may spend. A feed item naming hundreds of GHSAs must not hold the pass (and the
#: state lock) for hours; the rest stay unmeasured, so the item can be a warning but never suppressed.
MAX_ITEM_GHSA_LOOKUPS = 5
#: CVEs one classification call may send to EPSS. An item naming a hundred thousand ids must not turn
#: into a thousand sequential requests while the pass holds the state lock.
MAX_EPSS_IDS = 200
EPSS_BATCH = 100
MAX_SHOWN_IDS = 10
#: A feed name is operator-chosen text; this keeps it from eating the budget the excerpt shrinks into.
MAX_SOURCE_TITLE = 100
#: Feed sites never shown: an RSSHub transform feed reports its own internal, parameterised URL as its site.
#: Feed sites never shown in a message (config ``hidden_source_hosts``).
HIDDEN_SOURCE_HOSTS: frozenset[str] = frozenset()
#: NVD answers one CVE per call at NVD_PACE_SECONDS each; this bounds one pass (classify and re-evaluate
#: share it) well inside TimeoutStartSec. A CVE that needs NVD after the budget is spent is retried later.
MAX_NVD_CALLS = 10
#: Enrichment pages (a DSA's tracker page, a php.net ChangeLog, a nodejs.org post) fetched in one pass; all spend this
#: one budget. An item past the budget is left unseen, like an item past MAX_CLASSIFY, and is read on the next pass:
#: delivery waits at most a few passes and nothing is classified unknown meanwhile. Running out of budget is not a
#: fault.
MAX_TRACKER_FETCHES = 10
#: A DSA, PHP or Node.js release item whose enrichment page fails stays unseen and is retried every pass for this long
#: after its first failure (``state["enrich_retry"]``); then it is sent once as unknown severity with
#: ``ENRICH_FAILED_NOTE``.
ENRICH_RETRY_SECONDS = 2 * 3600
#: A Node.js security release post whose fetched page names no CVE waits this long, counted from the first such page
#: (``state["enrich_pending"]``, apart from the ``enrich_retry`` clock so that a later page fault cannot shorten it),
#: before it is sent as unknown severity: Node.js may publish the post a little before it fills in the CVE list.
NODEJS_PENDING_SECONDS = 24 * 3600
#: A vendor-neutral approximation of OSV's `database_specific.severity` label: the upper edge of the
#: CVSS v3 band. Used only when OSV is the sole source of a score; a CVSS vector is not computed.
OSV_SEVERITY_SCORE = {"LOW": 3.9, "MODERATE": 6.9, "HIGH": 8.9, "CRITICAL": 9.0}

RANK = {"suppressed": 0, "warning": 1, "critical": 2}


def _rank(level: object) -> int:
    """The escalation precedence of a stored level; a damaged or unknown value ranks below every real one."""
    return RANK.get(level, 0) if isinstance(level, str) else 0


#: The level words a message shows. The tag sent to notifiers (``critical``, ``warning``) and the levels kept
#: in state stay English.
LEVEL_LABEL = {"critical": "CRITICAL", "warning": "WARNING"}
EPSS_NOTE = "Likely exploitation (EPSS), unconfirmed."
ENRICH_FAILED_NOTE = "The CVE list could not be read from the source; severity unknown."
ACTION = "**Action:** check whether the vulnerable version is deployed."
#: An escalation reaches readers who already acted on the first message.
ESCALATION_ACTION = "**Action:** if the advisory version is already deployed, nothing to do; otherwise patch promptly."
#: The excerpt of a PHP release item that the ChangeLog enriched; the versions follow, newest first.
PHP_EXCERPT = "PHP security release; fixed versions: "
#: The excerpt of a Node.js security release item whose page names its release lines.
NODEJS_EXCERPT = "Node.js security release; lines: "
ADOBE_DECISION = "**Decision needed:** check whether downstream users must be notified (patching may be on their side)"
NO_DETAILS = "no details"
#: Detail pages fetched (and messages queued) for new bulletins in one pass; the rest stay unseen for the next.
MAX_ADOBE_NEW = 5
#: A new bulletin whose detail page cannot be read waits this long (retried every pass) for it before its message goes
#: out without details. The page carries the "critical CVE needing no login" fact that raises the decision line.
ADOBE_DETAIL_RETRY_SECONDS = 2 * 3600
#: The longest a version list or hotfix note may be in a message before it is cut with an ellipsis.
MAX_ADOBE_FIELD = 700

#: The canonical packaged watchlist preserves the legacy sender's package scope.
NGINX_KEYWORDS = ("cve-", "security", "vulnerab")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)
PSA_RE = re.compile(r"PSA-\d{4}-\d{5}-\d+", re.IGNORECASE)
#: ASCII digits only: ``\d`` would admit other scripts' digits into the tracker URL.
DSA_ID = r"DSA-[0-9]+(?:-[0-9]+)?"
DSA_ID_RE = re.compile(DSA_ID)
#: Group 1 is the advisory id, group 2 the source package. Only the title is trusted to name the id.
DSA_RE = re.compile(rf"^({DSA_ID})\s+(\S+)")
#: A Proxmox forum advisory has no title of its own, so its feed title is the whole post:
#: ``Subject: PSA-…: <subject> Advisory date: … Packages: … Details: …``.
POST_SUBJECT_RE = re.compile(r"^Subject:\s*(PSA-\d{4}-\d{5}-\d+:.+?)\s+(Advisory date:.*)$", re.IGNORECASE)
#: php.net's release feed: ``PHP 8.4.26 released!``. ASCII digits only, as for ``DSA_ID``: the major goes into a URL.
PHP_VERSION = r"[0-9]+\.[0-9]+\.[0-9]+"
PHP_VERSION_RE = re.compile(PHP_VERSION)
PHP_RELEASE_RE = re.compile(rf"^PHP ({PHP_VERSION}) [Rr]eleased")
#: php.net's combined news entry for a security release names no version: ``Critical PHP Security Release``.
#: Title only.
PHP_SECURITY_TITLE_RE = re.compile(r"\bsecurity release\b", re.IGNORECASE)
#: The only link hosts whose release titles are trusted to name a PHP version.
PHP_HOSTS = frozenset({"php.net", "www.php.net"})
#: nodejs.org's vulnerability feed: ``Wednesday, October 21, 2026 Security Releases``. Title only; an "OpenSSL ...
#: Assessment" or a HashDoS post is not a release and keeps the feed's own text.
NODEJS_SECURITY_TITLE_RE = re.compile(r"\bsecurity releases?\b", re.IGNORECASE)
#: The only link host trusted to name a Node.js vulnerability post, and the only path shape (group 1 is the slug). The
#: whole path must match, so a longer path or a traversal never qualifies.
NODEJS_HOST = "nodejs.org"
NODEJS_SLUG = r"[a-z0-9-]+"
NODEJS_SLUG_RE = re.compile(NODEJS_SLUG)
NODEJS_PATH_RE = re.compile(rf"/en/blog/vulnerability/({NODEJS_SLUG})/?")
#: The opening sentence of a release post: ``Updates are now available for the 26.x, 24.x Node.js release lines``.
_NODEJS_LINES_RE = re.compile(r"Updates are now available for the (.{1,100}?) Node\.js release lines")
_NODEJS_LINE_RE = re.compile(r"\b[0-9]{1,3}\.x\b")
#: One ``<section class="version" id="8.4.26">…</section>`` of a ChangeLog page, and the release date inside it.
_PHP_SECTION_RE = re.compile(
    rf"""<section\s+class=["']version["']\s+id=["']({PHP_VERSION})["']\s*>(.*?)</section>""", re.DOTALL
)
_PHP_DATE_RE = re.compile(r"""<time\s+class=["']releasedate["']\s+datetime=["']([0-9]{4}-[0-9]{2}-[0-9]{2})["']""")


# --------------------------------------------------------------------------
# Feed items

# Feed items


@dataclass(frozen=True)
class Item:
    guid: str
    title: str
    link: str
    summary: str
    published: int | None
    #: CVE, GHSA and PSA ids named in the title, summary and link, normalised, then the DSA id the title names.
    explicit: tuple[str, ...]
    #: The feed the entry came from (``origin.title``, ``origin.htmlUrl``). Never the feed URL: it can be private.
    source_title: str = ""
    source_url: str = ""


def _normalise_id(match: str) -> str:
    return "GHSA-" + match[5:].lower() if match.upper().startswith("GHSA-") else match.upper()


def extract_ids(*texts: str) -> tuple[str, ...]:
    found: dict[str, None] = {}
    for text in texts:
        for pattern in (CVE_RE, GHSA_RE, PSA_RE):
            for match in pattern.findall(text):
                found[_normalise_id(match)] = None
    return tuple(found)


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:  # a malformed feed link must never stop a pass
        return ""


def dsa_id(title: str) -> str | None:
    """The Debian advisory id a title starts with (``DSA-6558-1 curl - security update``), else None."""
    match = DSA_RE.match(title)
    return match.group(1) if match else None


def php_release(title: str, link: str) -> str | None:
    """The version a php.net release item announces (``PHP 8.4.26 released!``), else None.

    Only the title names the version, and only an item whose link is on ``PHP_HOSTS`` counts; the summary and the
    link path are never read for it.
    """
    match = PHP_RELEASE_RE.match(title)
    return match.group(1) if match and _host(link) in PHP_HOSTS else None


def php_announcement(title: str, link: str) -> bool:
    """Whether a php.net item announces a security release without a version (``Critical PHP Security Release``).

    Only the title is read, and only an item whose link is on ``PHP_HOSTS`` counts. A title naming a version is a
    ``php_release`` or another item, not this one.
    """
    return (
        _host(link) in PHP_HOSTS
        and PHP_SECURITY_TITLE_RE.search(title) is not None
        and PHP_VERSION_RE.search(title) is None
    )


def nodejs_slug(title: str, link: str) -> str | None:
    """The slug of the nodejs.org post a Node.js security release item links to (``october-2026-security-releases``).

    The link host must be exactly ``nodejs.org`` and its whole path ``/en/blog/vulnerability/<slug>``; the title must
    say ``Security Releases``. The query, the fragment and the scheme are ignored, and the page is fetched from
    ``NODEJS_VULN_URL`` plus the slug, never from the link.
    """
    try:
        parts = urllib.parse.urlsplit(link)
    except ValueError:  # a malformed link is simply not a nodejs.org post
        return None
    match = NODEJS_PATH_RE.fullmatch(parts.path) if (parts.hostname or "").lower() == NODEJS_HOST else None
    return match.group(1) if match and NODEJS_SECURITY_TITLE_RE.search(title) else None


def _items(export: FeedExport) -> list[Item]:
    items = []
    for entry in export.items:
        explicit = extract_ids(entry.title, entry.summary, entry.link)
        dsa = dsa_id(entry.title)
        items.append(
            Item(
                entry.guid,
                entry.title,
                entry.link,
                entry.summary,
                entry.published,
                (*explicit, dsa) if dsa and dsa not in explicit else explicit,
                entry.source_title,
                entry.source_url,
            )
        )
    return items


def parse_feed(body: bytes) -> list[Item]:
    return _items(parse_greader(body))


def headline(title: str, summary: str) -> tuple[str, str]:
    """(heading, excerpt): a whole post used as the title becomes its subject, and the excerpt never repeats it."""
    match = POST_SUBJECT_RE.match(title)
    if match:
        body = POST_SUBJECT_RE.match(summary)
        return match.group(1), body.group(2) if body else summary
    if summary.startswith(title):
        return title, summary[len(title) :].strip()
    return title, summary


def _matches_product(text: str, host: str, product) -> bool:
    """A product matches when the link is on one of its domains or its name appears in the text."""
    if host and any(host == domain or host.endswith("." + domain) for domain in product.domains):
        return True
    lowered = text.lower()
    for alias in (product.id, *product.aliases):
        if re.search(r"(?<![a-z0-9])" + re.escape(alias.lower()) + r"(?![a-z0-9])", lowered):
            return True
    return False


def matched_products(item: Item, policy: Policy) -> tuple[str, ...]:
    """The ids of the configured watchlist products this item matches, sorted.

    The one implementation of a product match: ``passes_filter`` uses it for scope, and ``classify_new``
    records the result on the queued message so routing can match on it later.
    """
    host = _host(item.link)
    text = f"{item.title} {item.summary} {item.source_title}"
    return tuple(sorted(product.id for product in policy.products if _matches_product(text, host, product)))


def filter_reason(item: Item, policy: Policy) -> str:
    """Why this item is outside the configured scope, or ``""`` when it is inside it.

    Debian publishes every package; nginx.org mixes news with security notes. A configured watchlist is a
    scope, not a label: an item that matches no configured product is dropped, and an item that matches an
    excluded product is dropped even without a product list. The one implementation of the decision, so the
    page that explains a scope cannot disagree with the pass that applies it.
    """
    host = _host(item.link)
    text = f"{item.title} {item.summary} {item.source_title}"
    by_id = {product.id: product for product in policy.products}
    for excluded in policy.excluded_products:
        product = by_id.get(excluded)
        if product is None:  # an exclusion may name a product the scope does not define
            product = Product(excluded, (), (), False)
        if _matches_product(text, host, product):
            return "excluded-product"
    if policy.products and not matched_products(item, policy):
        return "no-product-match"
    if host == "lists.debian.org" or item.title.startswith("DSA-"):
        match = DSA_RE.match(item.title)
        if not match:
            return "debian-package"
        package = match.group(2).lower()
        if not any(fnmatch.fnmatchcase(package, pattern) for pattern in policy.debian_source_packages):
            return "debian-package"
        return ""
    if host == "nginx.org" or host.endswith(".nginx.org"):
        text = f"{item.title} {item.summary}".lower()
        if not any(keyword in text for keyword in NGINX_KEYWORDS):
            return "nginx-keyword"
        return ""
    return ""


def passes_filter(item: Item, policy: Policy) -> bool:
    """Whether the item is inside the configured scope; the decision itself is :func:`filter_reason`."""
    return filter_reason(item, policy) == ""


# --------------------------------------------------------------------------
# Severity facts


@dataclass(frozen=True)
class CveFacts:
    cvss: float | None
    ssvc: str | None
    epss: float | None
    percentile: float | None
    #: Every lookup this CVE needed answered. An incomplete record is unknown, never LOW.
    complete: bool
    #: Not looked up in CVE.org/NVD because its item named more CVEs than MAX_ITEM_CVE_LOOKUPS.
    skipped: bool = False
    #: The metric that gave ``cvss`` has a vector with ``AV:N``, ``PR:N`` and ``UI:N`` (see ``remote_unauth``).
    remote_unauth: bool = False


@dataclass(frozen=True)
class OsvFacts:
    cves: tuple[str, ...]
    cvss: float | None
    complete: bool
    #: OSV keeps serving a withdrawn record. The lifecycle is retained, but that record is not evidence of a
    #: current severity: it carries no ``cvss`` and makes no completeness claim.
    withdrawn: bool = False


@dataclass(frozen=True)
class PhpRelease:
    """What php.net's ChangeLog section for one release names (see ``Intel.php_cves``)."""

    #: Newest first (year, then number, descending), so MAX_ITEM_CVE_LOOKUPS drops the old references.
    cves: tuple[str, ...]
    #: In page order; the item uses them only when the section names no CVE.
    ghsas: tuple[str, ...]
    #: Every version released the same day whose section names a CVE or GHSA, newest first.
    versions: tuple[str, ...]


@dataclass(frozen=True)
class NodejsRelease:
    """What a nodejs.org security release post names (see ``Intel.nodejs_page``)."""

    #: Newest first (year, then number, descending), so MAX_ITEM_CVE_LOOKUPS drops the old references.
    cves: tuple[str, ...]
    #: The release lines the opening sentence names (``26.x``), in page order; empty when it is not found.
    lines: tuple[str, ...]


def remote_unauth(vector: object) -> bool:
    """True for a CVSS v3.x or v4.0 vector string holding the tokens ``AV:N``, ``PR:N`` and ``UI:N``.

    The vector is split on ``/`` and compared token by token, so ``AV:N`` never matches inside another token. A v2
    vector has no ``PR`` or ``UI`` token and never qualifies.
    """
    return isinstance(vector, str) and {"AV:N", "PR:N", "UI:N"} <= set(vector.split("/"))


def _best(scores: Sequence[tuple[float, bool]]) -> tuple[float | None, bool]:
    """(highest score, whether any metric giving that score is remote and unauthenticated)."""
    if not scores:
        return None, False
    top = max(score for score, _ in scores)
    return top, any(remote for score, remote in scores if score == top)


def _scores(metrics: object) -> tuple[list[tuple[float, bool]], bool]:
    """(usable scores, whether a supported metric was present but unreadable).

    A malformed supported metric means the severity was not fully measured: the caller must treat the facts as
    incomplete, or a readable LOW beside an unreadable CRITICAL would authorize a suppression.
    """
    found: list[tuple[float, bool]] = []
    malformed = False
    for metric in metrics if isinstance(metrics, list) else []:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if not isinstance(metric, dict) or key not in metric:
                continue
            data = metric.get(key)
            if not isinstance(data, dict):
                malformed = True
                continue
            score = _bounded(data.get("baseScore"), 0.0, 10.0)
            if score is None:
                malformed = True
            else:
                found.append((score, remote_unauth(data.get("vectorString"))))
    return found, malformed


def _ssvc_exploitation(metrics: object) -> str | None:
    for metric in metrics if isinstance(metrics, list) else []:
        other = metric.get("other") if isinstance(metric, dict) else None
        if not isinstance(other, dict) or other.get("type") != "ssvc":
            continue
        content = other.get("content")
        options = content.get("options") if isinstance(content, dict) else None
        for option in options if isinstance(options, list) else []:
            value = option.get("Exploitation") if isinstance(option, dict) else None
            if isinstance(value, str) and value.lower() in {"none", "poc", "active"}:
                return value.lower()
    return None


def cve_org_facts(document: dict) -> tuple[float | None, str | None, bool, bool]:
    """(CVSS, SSVC exploitation, whether the chosen score is remote and unauthenticated, any metric malformed).

    The CNA score wins; CISA-ADP supplies one only when the CNA gave none.
    """
    containers = document.get("containers")
    containers = containers if isinstance(containers, dict) else {}
    cna = containers.get("cna")
    cna_scores, malformed = _scores(cna.get("metrics") if isinstance(cna, dict) else None)
    adp_scores: list[tuple[float, bool]] = []
    ssvc = None
    adps = containers.get("adp")
    for adp in adps if isinstance(adps, list) else []:
        provider = adp.get("providerMetadata") if isinstance(adp, dict) else None
        if not isinstance(provider, dict) or provider.get("shortName") != "CISA-ADP":
            continue
        adp_found, adp_malformed = _scores(adp.get("metrics"))
        adp_scores += adp_found
        malformed = malformed or adp_malformed
        ssvc = ssvc or _ssvc_exploitation(adp.get("metrics"))
    cvss, remote = _best(cna_scores or adp_scores)
    return cvss, ssvc, remote, malformed


def parse_nvd(document: dict) -> float | None:
    """The NVD Primary score, or any score when NVD names no Primary."""
    return nvd_facts(document)[0]


def _nvd_record_matches(document: dict, cve: str) -> bool:
    """The response must describe the requested CVE: an unrelated record would be false evidence."""
    vulnerabilities = document.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return False
    for entry in vulnerabilities:
        record = entry.get("cve") if isinstance(entry, dict) else None
        if not isinstance(record, dict):
            return False
        identifier = record.get("id")
        if not isinstance(identifier, str) or identifier.upper() != cve.upper():
            return False
    return True


def nvd_facts(document: dict) -> tuple[float | None, bool, bool]:
    """``parse_nvd`` plus whether that score is remote/unauthenticated (same source) and whether a supported
    metric was present but unreadable: a partially readable metrics list is not a measurement."""
    vulnerabilities = document.get("vulnerabilities")
    first = vulnerabilities[0] if isinstance(vulnerabilities, list) and vulnerabilities else None
    cve = first.get("cve") if isinstance(first, dict) else None
    metrics = cve.get("metrics") if isinstance(cve, dict) else None
    primary: list[tuple[float, bool]] = []
    other: list[tuple[float, bool]] = []
    malformed = False
    for entries in metrics.values() if isinstance(metrics, dict) else []:
        for entry in entries if isinstance(entries, list) else []:
            data = entry.get("cvssData") if isinstance(entry, dict) else None
            if not isinstance(data, dict):
                malformed = True
                continue
            score = _bounded(data.get("baseScore"), 0.0, 10.0)
            if score is None:
                malformed = True
                continue
            (primary if entry.get("type") == "Primary" else other).append(
                (score, remote_unauth(data.get("vectorString")))
            )
    score, remote = _best(primary or other)
    return score, remote, malformed


def _number(value: object) -> float | None:
    """A finite float, or None: ``NaN``/``Infinity`` from a feed must never reach a decision or a render."""
    if isinstance(value, bool):
        return None
    try:
        number = float(value) if isinstance(value, (int, float, str)) else None
    except (ValueError, OverflowError):
        return None
    return number if number is not None and math.isfinite(number) else None


def _bounded(value: object, low: float, high: float) -> float | None:
    number = _number(value)
    return number if number is not None and low <= number <= high else None


def _cve_age(cve: str) -> tuple[int, int]:
    """(year, number) for ordering; a suffix too long to be an integer is treated as number 0.

    ``CVE_RE`` accepts any number of digits, and ``int()`` refuses absurd lengths: sorting untrusted ids must
    not raise inside classification.
    """
    _, year, number = cve.split("-")
    return int(year), int(number) if len(number) <= 18 else 0


def parse_nodejs_page(text: str) -> NodejsRelease:
    """The CVE ids (newest first) and release lines of a nodejs.org security release post.

    Page text is untrusted: every id is re-read with the module's own pattern, and a release line is kept only as
    ASCII ``N.x`` from the opening sentence.
    """
    cves = sorted({_normalise_id(found) for found in CVE_RE.findall(text)}, key=_cve_age, reverse=True)
    opening = _NODEJS_LINES_RE.search(text)
    lines = tuple(dict.fromkeys(_NODEJS_LINE_RE.findall(opening.group(1)))) if opening else ()
    return NodejsRelease(tuple(cves), lines)


def _newest_version_first(versions: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(versions, key=lambda version: [int(part) for part in version.split(".")], reverse=True))


def parse_php_changelog(text: str) -> dict[str, tuple[str | None, tuple[str, ...], tuple[str, ...]]]:
    """Per version section of a php.net ChangeLog page: (release date, CVE ids newest first, GHSA ids in page order).

    Page text is untrusted: a version is kept only as ASCII ``X.Y.Z`` and a date only as ``YYYY-MM-DD``, and every id
    is re-read with the module's own patterns.
    """
    sections: dict[str, tuple[str | None, tuple[str, ...], tuple[str, ...]]] = {}
    for match in _PHP_SECTION_RE.finditer(text):
        version, body = match.groups()
        date = _PHP_DATE_RE.search(body)
        cves = sorted({_normalise_id(found) for found in CVE_RE.findall(body)}, key=_cve_age, reverse=True)
        ghsas = tuple(dict.fromkeys(_normalise_id(found) for found in GHSA_RE.findall(body)))
        sections.setdefault(version, (date.group(1) if date else None, tuple(cves), ghsas))
    return sections


class Intel:
    """The lookups behind a verdict, cached in the state file for 24 hours."""

    def __init__(
        self,
        http: Http,
        cache: dict[str, dict],
        clock: Callable[[], float],
        sleep: Callable[[float], None],
        *,
        nvd_key: str = "",
    ) -> None:
        self._http = http
        self._cache = cache
        self._clock = clock
        self._sleep = sleep
        #: A free NVD API key raises the limit from 5 to 50 requests per 30 s, so the pace follows the key.
        self._nvd_key = nvd_key
        self._nvd_pace = NVD_KEY_PACE_SECONDS if nvd_key else NVD_PACE_SECONDS
        self._nvd_left = MAX_NVD_CALLS
        #: Enrichment pages this pass may still fetch: tracker pages (``dsa_cves``), ChangeLogs (``php_cves``) and
        #: Node.js posts (``nodejs_page``).
        self.tracker_left = MAX_TRACKER_FETCHES
        #: The ChangeLog sections read in this pass by major version, ``None`` after a fault. Never in the state file.
        self._changelogs: dict[str, dict[str, tuple[str | None, tuple[str, ...], tuple[str, ...]]] | None] = {}
        #: The Node.js posts read in this pass by slug, ``None`` after a fault. Never in the state file.
        self._nodejs: dict[str, NodejsRelease | None] = {}

    def _get(self, url: str, extra_headers: Mapping[str, str] | None = None) -> tuple[int, object]:
        headers = {"Accept": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        status, _, body = self._http("GET", url, headers, None)
        return status, (parse_json(body) if status == 200 else None)

    def _fresh(self, key: str, force: bool) -> dict | None:
        entry = self._cache.get(key)
        if not force and entry is not None and self._clock() - entry["at"] < CACHE_TTL:
            return entry
        return None

    def _cve_org(self, cve: str) -> tuple[bool, float | None, str | None, bool]:
        status, document = self._get(CVE_ORG_URL + cve)
        if status == 404:
            return True, None, None, False
        if not isinstance(document, dict):
            return False, None, None, False
        metadata = document.get("cveMetadata")
        identifier = metadata.get("cveId") if isinstance(metadata, dict) else None
        if not isinstance(identifier, str) or identifier.upper() != cve.upper():
            # A missing or different identity is not evidence about the requested CVE (an error body has none).
            return False, None, None, False
        cvss, ssvc, remote, malformed = cve_org_facts(document)
        # An unreadable supported metric means the severity was not measured in full: fail closed.
        return (not malformed, cvss, ssvc, remote)

    def _nvd(self, cve: str) -> tuple[bool, float | None, bool]:
        self._sleep(self._nvd_pace)
        # Without a key this sends no header at all: NVD then applies its anonymous limit, and the pace above
        # already respects it.
        status, document = (
            self._get(NVD_URL + cve, {"apiKey": self._nvd_key}) if self._nvd_key else self._get(NVD_URL + cve)
        )
        if status == 404:
            return True, None, False
        # A 200 must carry the NVD envelope for *this* CVE: an error body, {} or another CVE's record is a
        # failed lookup, never "no score".
        if not isinstance(document, dict) or not _nvd_record_matches(document, cve):
            return False, None, False
        score, remote, malformed = nvd_facts(document)
        # A supported metric that could not be read means the severity was not measured in full: fail closed.
        return (not malformed, score, remote)

    def _epss(self, cves: Sequence[str]) -> dict[str, tuple[float | None, float | None]] | None:
        scores: dict[str, tuple[float | None, float | None]] = {}
        for start in range(0, len(cves), EPSS_BATCH):
            status, document = self._get(EPSS_URL + ",".join(cves[start : start + EPSS_BATCH]))
            data = document.get("data") if isinstance(document, dict) else None
            if status != 200 or not isinstance(data, list):
                return None
            requested = {cve.upper() for cve in cves[start : start + EPSS_BATCH]}
            if data and any(
                not isinstance(row, dict) or not isinstance(row.get("cve"), str) or row["cve"].upper() not in requested
                for row in data
            ):
                # A batch with an unusable row, or one describing a CVE nobody asked for, is a failed
                # measurement: accepting it would make the requested CVE look like "no score".
                return None
            for row in data:
                if row.get("epss") is None:
                    # A row for the CVE without its exploitation-probability score is malformed: "no score" is
                    # expressed by the CVE being absent from the response, never by a partial row.
                    return None
                score = _bounded(row.get("epss"), 0.0, 1.0)
                percentile = _bounded(row.get("percentile"), 0.0, 1.0)
                if (row.get("epss") is not None and score is None) or (
                    row.get("percentile") is not None and percentile is None
                ):
                    # A row that matched but carries an unusable number is a failed measurement. Caching it as
                    # "no score" would let a LOW CVSS suppress an advisory that was never really measured.
                    return None
                scores[row["cve"].upper()] = (score, percentile)
        return scores

    def cves(
        self,
        cves: Sequence[str],
        *,
        force: bool = False,
        lookup_limit: int | None = None,
        deferred: set[str] | None = None,
    ) -> dict[str, CveFacts]:
        """Facts per CVE. Only the first ``lookup_limit`` uncached CVEs go to CVE.org/NVD; EPSS is capped.

        ``deferred`` collects the CVEs on which the NVD budget ran out before a request: those were not
        measured, so a caller that schedules the next attempt must not count them as tried.
        """
        deferred = set() if deferred is None else deferred
        facts: dict[str, CveFacts] = {}
        missing: list[str] = []
        for cve in cves:
            entry = self._fresh(cve, force)
            if entry is None:
                missing.append(cve)
            else:
                # An entry written before ``remote_unauth`` existed reads False until it is looked up again.
                facts[cve] = CveFacts(
                    entry["cvss"],
                    entry["ssvc"],
                    entry["epss"],
                    entry["percentile"],
                    True,
                    remote_unauth=entry.get("remote_unauth") is True,
                )
        if not missing:
            return facts
        epss = self._epss(missing[:MAX_EPSS_IDS])
        for position, cve in enumerate(missing):
            if position >= MAX_EPSS_IDS:
                # Past the budget this id was not measured at all: unknown, never suppressed.
                facts[cve] = CveFacts(None, None, None, None, False, skipped=True)
                continue
            score, percentile = (None, None) if epss is None else epss.get(cve, (None, None))
            if lookup_limit is not None and position >= lookup_limit:
                facts[cve] = CveFacts(None, None, score, percentile, False, skipped=True)
                continue
            complete, cvss, ssvc, remote = self._cve_org(cve)
            if complete and cvss is None:
                if self._nvd_left > 0:
                    self._nvd_left -= 1
                    complete, cvss, remote = self._nvd(cve)
                else:
                    # No request was made: this is a deferral, not a measurement. Re-evaluation uses it to
                    # avoid advancing its daily clock on a CVE it never actually checked.
                    complete = False
                    deferred.add(cve)
            complete = complete and epss is not None
            facts[cve] = CveFacts(cvss, ssvc, score, percentile, complete, remote_unauth=remote)
            if complete:
                self._cache[cve] = {
                    "at": int(self._clock()),
                    "cvss": cvss,
                    "ssvc": ssvc,
                    "epss": score,
                    "percentile": percentile,
                    "remote_unauth": remote,
                }
        return facts

    def dsa_cves(self, dsa: str) -> tuple[str, ...] | None:
        """The CVE ids Debian's tracker lists for ``dsa``; ``None`` after any fault, which is logged.

        Debian's feed carries only the DSA id, so this is the one lookup that tells the item what it fixes. The URL
        is built from ``dsa`` alone, which must be an id taken from a feed title (never from its link or summary).
        A failed fetch spends the budget too. ``None`` leaves the item unclaimed for retry (for at most
        ``ENRICH_RETRY_SECONDS``); an empty tuple means a successful page names no CVE, so the item follows the
        unknown-severity warning route.
        """
        if not DSA_ID_RE.fullmatch(dsa):
            LOG.warning("debian tracker: %r is not a DSA id; not fetched", dsa)
            return None
        self.tracker_left -= 1
        status, _, body = self._http("GET", DEBIAN_TRACKER_URL + dsa, {"Accept": "text/html"}, None)
        if status != 200:
            LOG.warning("debian tracker: no page for %s (HTTP %s); the item is deferred for retry", dsa, status)
            return None
        if len(body) > MAX_TRACKER_BYTES:
            LOG.warning(
                "debian tracker: the page for %s exceeds %d bytes; the item is deferred for retry",
                dsa,
                MAX_TRACKER_BYTES,
            )
            return None
        cves = tuple(dict.fromkeys(_normalise_id(found) for found in CVE_RE.findall(body.decode("utf-8", "replace"))))
        if not cves:
            LOG.warning("debian tracker: the page for %s names no CVE; the item has unknown severity", dsa)
        return cves

    def changelog_read(self, version: str) -> bool:
        """Whether ``php_cves(version)`` needs no fetch: this pass already read (or failed) its ChangeLog."""
        return version.split(".")[0] in self._changelogs

    def announcement_read(self) -> bool:
        """Whether ``php_cves_on(day)`` needs no fetch: this pass already read (or failed) every ChangeLog it uses."""
        return all(major in self._changelogs for major in PHP_CHANGELOG_MAJORS)

    def _changelog(self, major: str) -> dict[str, tuple[str | None, tuple[str, ...], tuple[str, ...]]] | None:
        """The sections of php.net's ChangeLog for ``major``, fetched once per pass; ``None`` after any fault (logged).

        The fetch spends the tracker budget, a failed one too. A page above ``MAX_CHANGELOG_BYTES`` is not a ChangeLog.
        """
        if major not in self._changelogs:
            self.tracker_left -= 1
            status, _, body = self._http("GET", f"{PHP_CHANGELOG_URL}{major}.php", {"Accept": "text/html"}, None)
            if status != 200:
                LOG.warning(
                    "php changelog: no page for PHP %s (HTTP %s); the item is deferred for retry", major, status
                )
                self._changelogs[major] = None
            elif len(body) > MAX_CHANGELOG_BYTES:
                LOG.warning(
                    "php changelog: the page for PHP %s exceeds %d bytes; the item is deferred for retry",
                    major,
                    MAX_CHANGELOG_BYTES,
                )
                self._changelogs[major] = None
            else:
                self._changelogs[major] = parse_php_changelog(body.decode("utf-8", "replace"))
        return self._changelogs[major]

    def php_cves(self, version: str) -> PhpRelease | None:
        """What php.net's ChangeLog lists for release ``version``; ``None`` after any fault, which is logged.

        php.net's release feed names no CVE, so this is the lookup that tells the item what it fixes. The URL is built
        from the major of ``version`` alone, which must come from a release title (see ``php_release``). One page
        serves every branch of a major, so it is fetched once per pass and kept in memory only. A page that cannot be
        read, is oversize or has no section for ``version`` leaves the item unclaimed for retry. A section naming
        neither a CVE nor a GHSA gives an empty release.
        """
        if not PHP_VERSION_RE.fullmatch(version):
            LOG.warning("php changelog: %r is not a PHP version; not fetched", version)
            return None
        major = version.split(".")[0]
        sections = self._changelog(major)
        if sections is None:
            return None
        if version not in sections:
            LOG.warning(
                "php changelog: the page for PHP %s has no section for %s; the item is deferred for retry",
                major,
                version,
            )
            return None
        date, cves, ghsas = sections[version]
        versions = _newest_version_first(
            other
            for other, (day, *ids) in sections.items()
            if any(ids) and (other == version or (date is not None and day == date))
        )
        return PhpRelease(cves, ghsas, versions)

    def php_cves_on(self, day: str) -> PhpRelease | None:
        """What the ChangeLogs of ``PHP_CHANGELOG_MAJORS`` list for the releases dated ``day`` (``YYYY-MM-DD``).

        For a security announcement whose title names no version (see ``php_announcement``). Every section of that
        date naming a CVE or GHSA counts; the CVEs of all of them are merged, newest first. ``None`` after any fault or
        when no section has that date yet (php.net often updates the ChangeLog after the news); both are logged and
        leave the item unclaimed for retry. The URLs come from the constant, never from the item.
        """
        cves: set[str] = set()
        ghsas: dict[str, None] = {}
        versions: list[str] = []
        for major in PHP_CHANGELOG_MAJORS:
            sections = self._changelog(major)
            if sections is None:
                return None
            for version, (released, section_cves, section_ghsas) in sections.items():
                if released == day and (section_cves or section_ghsas):
                    cves.update(section_cves)
                    ghsas.update(dict.fromkeys(section_ghsas))
                    versions.append(version)
        if not versions:
            LOG.warning("php changelog: no section dated %s names a CVE or GHSA; the item is deferred for retry", day)
            return None
        return PhpRelease(
            tuple(sorted(cves, key=_cve_age, reverse=True)), tuple(ghsas), _newest_version_first(versions)
        )

    def nodejs_read(self, slug: str) -> bool:
        """Whether ``nodejs_page(slug)`` needs no fetch: this pass already read (or failed) that post."""
        return slug in self._nodejs

    def nodejs_page(self, slug: str) -> NodejsRelease | None:
        """What the nodejs.org vulnerability post ``slug`` names; ``None`` after any fault, which is logged.

        The feed carries a title and a link only, so this is the lookup that tells the item what it fixes. The URL is
        ``NODEJS_VULN_URL`` plus ``slug``, which must come from ``nodejs_slug``, never the item's link. One post is
        fetched once per pass and kept in memory only; a fetch spends the budget, a failed one too. An HTTP error or a
        page above ``MAX_NODEJS_PAGE_BYTES`` leaves the item unclaimed for retry (for at most
        ``ENRICH_RETRY_SECONDS``); a successful page naming no CVE gives an empty ``cves``, which the caller also
        leaves unclaimed, but for ``NODEJS_PENDING_SECONDS`` from the first such page, since the post may precede its
        CVE list.
        """
        if not NODEJS_SLUG_RE.fullmatch(slug):
            LOG.warning("nodejs.org: %r is not a vulnerability post slug; not fetched", slug)
            return None
        if slug not in self._nodejs:
            self.tracker_left -= 1
            status, _, body = self._http("GET", NODEJS_VULN_URL + slug, {"Accept": "text/html"}, None)
            if status != 200:
                LOG.warning("nodejs.org: no page for %s (HTTP %s); the item is deferred for retry", slug, status)
                self._nodejs[slug] = None
            elif len(body) > MAX_NODEJS_PAGE_BYTES:
                LOG.warning(
                    "nodejs.org: the page for %s exceeds %d bytes; the item is deferred for retry",
                    slug,
                    MAX_NODEJS_PAGE_BYTES,
                )
                self._nodejs[slug] = None
            else:
                page = parse_nodejs_page(body.decode("utf-8", "replace"))
                if not page.cves:
                    LOG.warning("nodejs.org: the page for %s names no CVE; the item waits for its CVE list", slug)
                self._nodejs[slug] = page
        return self._nodejs[slug]

    def ghsa(self, ghsa: str) -> OsvFacts:
        entry = self._fresh(ghsa, False)
        if entry is not None:
            return OsvFacts(
                tuple(entry["cves"]),
                entry["cvss"],
                bool(entry.get("complete", True)),
                bool(entry.get("withdrawn", False)),
            )
        status, document = self._get(OSV_URL + ghsa)
        if status == 404:
            # OSV does not know this advisory. That is not a measurement of zero severity: a LOW sibling must
            # not suppress an item whose other advisory is unmeasured.
            return OsvFacts((), None, False)
        if not isinstance(document, dict):
            return OsvFacts((), None, False)
        identifier = document.get("id")
        if not isinstance(identifier, str) or identifier.upper() != ghsa.upper():
            return OsvFacts((), None, False)  # another advisory's record is not evidence about this one
        aliases = document.get("aliases")
        cves = tuple(
            dict.fromkeys(
                alias.upper()
                for alias in (aliases if isinstance(aliases, list) else [])
                if isinstance(alias, str) and CVE_RE.fullmatch(alias)
            )
        )
        # A withdrawn record keeps an RFC3339 ``withdrawn`` timestamp; OSV omits the member otherwise. Only a
        # valid timestamp is evidence of a withdrawal: a malformed non-empty value is tolerated and read as
        # active, so it can neither strip this record's severity nor be cached as withdrawn.
        withdrawn = _is_rfc3339(document.get("withdrawn"))
        specific = document.get("database_specific")
        label = specific.get("severity") if isinstance(specific, dict) else None
        cvss = None if withdrawn else (OSV_SEVERITY_SCORE.get(label.upper()) if isinstance(label, str) else None)
        # An advisory with neither a CVE alias nor a usable severity label was not measured: its severity is
        # unknown, and it must not be suppressed by a LOW sibling. A withdrawn record also makes no completeness
        # claim, so an item naming it is never suppressed while its lifecycle is unknown to the verdict.
        complete = not withdrawn and (bool(cves) or cvss is not None)
        self._cache[ghsa] = {
            "at": int(self._clock()),
            "cves": list(cves),
            "cvss": cvss,
            "complete": complete,
            "withdrawn": withdrawn,
        }
        return OsvFacts(cves, cvss, complete, withdrawn)


# --------------------------------------------------------------------------
# Routing


def critical_reason(facts: CveFacts, kev: bool, *, thresholds: Thresholds) -> str | None:
    """``kev`` | ``ssvc`` | ``remote`` | ``epss`` (first match wins), else None."""
    if kev:
        return "kev"
    if facts.ssvc == "active":
        return "ssvc"
    if facts.cvss is not None and facts.cvss >= thresholds.critical_cvss:
        if facts.remote_unauth:
            return "remote"
        if facts.epss is not None and facts.epss >= thresholds.critical_epss:
            return "epss"
    return None


def remote_note(thresholds: Thresholds = DEFAULT_THRESHOLDS) -> str:
    """The note the remote rule carries, naming the CVSS bar actually configured.

    A literal "CVSS >= 9.0" would be a lie the moment the threshold is saved as anything else, and the note is
    the only place a reader learns which rule decided.
    """
    return f"CVSS >= {thresholds.critical_cvss}, remote attack, no privileges, no user interaction (CVSS vector)."


def reason_note(reason: str | None, thresholds: Thresholds = DEFAULT_THRESHOLDS) -> str:
    """The note a critical verdict carries, or the empty string for a reason that needs none.

    ``kev`` and ``ssvc`` are observed exploitation and speak for themselves; ``remote`` and ``epss`` are forecasts
    and name the configured bar, because the same advisory is a warning under a stricter threshold.
    """
    if reason == "remote":
        return remote_note(thresholds)
    if reason == "epss":
        return EPSS_NOTE
    return ""


def change_note(reason: str | None, thresholds: Thresholds = DEFAULT_THRESHOLDS) -> str:
    """The note an escalation carries: what changed since the first message, not why the CVE is critical."""
    if reason == "kev":
        return "Change: CVE added to the CISA KEV catalog (exploited in the wild)."
    if reason == "ssvc":
        return "Change: CISA recorded active exploitation (SSVC)."
    if reason == "epss":
        return f"Change: exploitation likelihood (EPSS) at or above {thresholds.critical_epss}; unconfirmed."
    if reason == "remote":
        return (
            f"Change: a CVSS >= {thresholds.critical_cvss} score appeared for a remote, unauthenticated, "
            "no-interaction attack."
        )
    return ""


def level_of(
    facts: CveFacts,
    kev: bool,
    kev_known: bool,
    fallback_cvss: float | None = None,
    *,
    thresholds: Thresholds,
) -> tuple[str, str | None]:
    """(``critical`` | ``warning`` | ``suppressed``, why critical). Unknown is a warning."""
    reason = critical_reason(facts, kev, thresholds=thresholds)
    if reason:
        return "critical", reason
    cvss = facts.cvss if facts.cvss is not None else fallback_cvss
    if facts.complete and kev_known and cvss is not None and cvss < thresholds.suppress_below_cvss:
        return "suppressed", None
    return "warning", None


def metrics_line(
    cvss: float | None,
    epss: float | None,
    percentile: float | None,
    ssvc: str | None,
    kev: bool,
    *,
    approximate: bool = False,
) -> str:
    parts = [
        "CVSS " + (f"{cvss:.1f}" + (" (OSV label, approximate)" if approximate else "") if cvss is not None else "none")
    ]
    if epss is None:
        parts.append("EPSS none")
    else:
        parts.append(f"EPSS {epss:.2f}" + (f" (p{int(percentile * 100)})" if percentile is not None else ""))
    parts.append(f"SSVC {ssvc or 'none'}")
    if kev:
        parts.append("KEV")
    return " · ".join(parts)


@dataclass(frozen=True)
class Verdict:
    tag: str
    #: Per-CVE level, kept in state for the daily re-evaluation.
    levels: tuple[tuple[str, str], ...]
    line: str
    note: str
    #: CVEs that were never enriched in this pass (past the lookup cap). They are watched for KEV only, which
    #: costs no request, so a later KEV addition still escalates them.
    skipped: tuple[str, ...] = ()


def _cvss_floor(facts: CveFacts) -> float:
    return -1.0 if facts.cvss is None else facts.cvss


def judge(
    cves: Sequence[str],
    facts: Mapping[str, CveFacts],
    kev: frozenset[str],
    kev_known: bool,
    osv_cvss: float | None,
    osv_complete: bool = True,
    osv_fallbacks: Mapping[str, float] | None = None,
    independent_ghsa_cvss: float | None = None,
    osv_scores_are_aliased: bool = False,
    *,
    thresholds: Thresholds,
) -> Verdict:
    """Item verdict from the CVEs it names; the CVE that decides is the one shown.

    ``osv_complete`` is False when an OSV lookup for one of the item's GHSA ids did not answer:
    that advisory was never measured, so the item can be a warning or critical but never suppressed.
    """
    incomplete_note = "Incomplete severity data; treated as unknown."
    if not cves:
        if independent_ghsa_cvss is not None:
            # An alias-free advisory carries its own severity, whatever else the item mentions. Once it
            # exists, the aggregate score is not used: part of it may belong to an already-claimed CVE.
            if independent_ghsa_cvss >= thresholds.critical_cvss:
                return Verdict(
                    "critical", (), metrics_line(independent_ghsa_cvss, None, None, None, False, approximate=True), ""
                )
            if osv_complete and independent_ghsa_cvss < thresholds.suppress_below_cvss:
                return Verdict(
                    "suppressed", (), metrics_line(independent_ghsa_cvss, None, None, None, False, approximate=True), ""
                )
            return Verdict(
                "warning",
                (),
                metrics_line(independent_ghsa_cvss, None, None, None, False, approximate=True),
                "" if osv_complete else incomplete_note,
            )
        if osv_scores_are_aliased:
            # Every scored advisory aliases a CVE that is not being judged here (it was already claimed), so
            # the OSV label is not independent evidence about this item: keep it visible as unknown.
            line = metrics_line(osv_cvss, None, None, None, False, approximate=True)
            return Verdict("warning", (), line, incomplete_note)
        # With no CVE named, every OSV score here belongs to an advisory that has no CVE alias, so its
        # severity decides on its own: a CRITICAL label is critical, not merely a warning.
        if osv_cvss is not None and osv_cvss >= thresholds.critical_cvss:
            return Verdict("critical", (), metrics_line(osv_cvss, None, None, None, False, approximate=True), "")
        if osv_complete and osv_cvss is not None and osv_cvss < thresholds.suppress_below_cvss:
            return Verdict("suppressed", (), metrics_line(osv_cvss, None, None, None, False, approximate=True), "")
        line = (
            "unknown (no CVE id and no OSV score)"
            if osv_cvss is None
            else metrics_line(osv_cvss, None, None, None, False, approximate=True)
        )
        return Verdict("warning", (), line, "" if osv_complete else incomplete_note)
    fallbacks = osv_fallbacks or {}
    judged = {
        cve: level_of(
            facts[cve],
            cve in kev,
            kev_known,
            fallbacks.get(cve),
            thresholds=thresholds,
        )
        for cve in cves
    }
    # An unscored CVE (past the lookup cap) is not watched unless a critical signal names it.
    # Every CVE the advisory names is watched. CVEs past the per-item lookup cap were not enriched here, so
    # they are watched for KEV only (a local set, no request): their identifiers are claimed by this message,
    # and without a watch entry a later KEV addition could never escalate them.
    levels = tuple((cve, level) for cve, (level, _) in judged.items())
    skipped_cves = tuple(cve for cve, fact in facts.items() if fact.skipped)
    critical = [cve for cve in cves if judged[cve][0] == "critical"]
    if critical:
        shown = min(critical, key=lambda cve: ("kev", "ssvc", "remote", "epss").index(judged[cve][1] or "epss"))
        tag = "critical"
    else:
        shown = max(cves, key=lambda cve: _cvss_floor(facts[cve]))
        tag = "suppressed" if all(level == "suppressed" for level, _ in judged.values()) else "warning"
        if tag == "suppressed" and not osv_complete:
            # Sent as a warning, so the watch records it as sent: a later re-score is not a second warning.
            tag = "warning"
            levels = tuple((cve, "warning") for cve, _ in levels)
    ghsa_decides = False
    if independent_ghsa_cvss is not None:
        # An alias-free GHSA carries its own severity: a LOW CVE beside it must not hide it, and an aliased
        # GHSA (whose score is already represented by its CVE) must not override the CVE's own score.
        if independent_ghsa_cvss >= thresholds.critical_cvss:
            tag = "critical"
            ghsa_decides = True
        elif tag == "suppressed" and independent_ghsa_cvss >= thresholds.suppress_below_cvss:
            # Both components are measured and both are LOW: keep the suppression. Only a second advisory
            # above the LOW floor is news.
            tag = "warning"
            ghsa_decides = True
    chosen = facts[shown]
    # The displayed score must belong to the CVE that is shown: the item-wide OSV fallback may be another
    # advisory's measurement.
    shown_fallback = fallbacks.get(shown) if cves else None
    cvss = chosen.cvss if chosen.cvss is not None else shown_fallback
    line = metrics_line(
        cvss,
        chosen.epss,
        chosen.percentile,
        chosen.ssvc,
        shown in kev,
        approximate=chosen.cvss is None and shown_fallback is not None,
    )
    if ghsa_decides:
        # The deciding evidence is the GHSA's OSV label, not the CVE we happen to show beside it.
        line = f"OSV GHSA severity {independent_ghsa_cvss:g} (approximate); {line}"
    if len(cves) > 1:
        line = f"{shown}: {line} (+{len(cves) - 1} more CVEs)"
    unscored = sum(1 for cve in cves if not facts[cve].complete)
    if unscored:
        line += f" (+{unscored} CVEs unscored)"
    note = reason_note(judged[shown][1], thresholds)
    if ghsa_decides:
        note = "An advisory in this item without a CVE id decides the severity."
    if tag == "warning" and (not osv_complete or any(not facts[cve].complete for cve in cves)):
        note = incomplete_note
    return Verdict(tag, levels, line, note, skipped_cves)


# --------------------------------------------------------------------------
# Messages


def _cap(text: str, limit: int) -> str:
    """``text`` cut to ``limit`` characters with an ellipsis; never ends in a lone backslash, which would escape it."""
    if len(text) <= limit:
        return text
    kept = text[: max(limit - 1, 0)]
    if (len(kept) - len(kept.rstrip("\\"))) % 2:
        kept = kept[:-1]
    return kept + "…"


#: Backslash-escaped, so Matrix Hookshot (markdown-it) and Discord show the character and give it no meaning:
#: links, images and masked links (``[ ] ( ) ! < >``), code spans, emphasis, headings, quotes, tables, spoilers and
#: strikethrough (``* _ # > | ~``), character references (``&``) and a backslash that would cancel an escape.
_MARKDOWN_ESCAPES = str.maketrans({char: "\\" + char for char in "\\`*_[]()<>#|~!&"})
#: A line that opens with a bullet or numbered-list marker (``1.``; ``1)`` is escaped above).
_LINE_MARKER = re.compile(r"^( *)(?:([-+])|(\d+)(\.))", re.MULTILINE)


def neutralise(text: str) -> str:
    """Raw feed text made harmless as Markdown: no control or format characters, no live Markdown.

    Drops every Unicode category C character (bidi overrides, zero-width characters, controls) except newline;
    a tab or carriage return becomes a space. Then backslash-escapes every Markdown control character (see
    ``_MARKDOWN_ESCAPES``), a line-leading ``-``, ``+`` or ``1.``, and the ``//`` of a ``scheme://`` so that Discord
    does not turn a bare URL into a link. A vendor string can therefore not make a link, image, heading, list,
    quote, code, table or HTML element on either renderer.
    Apply it to every string that came from a feed, before ``inert`` (which adds the zero-width space this drops).
    ``_md`` also makes the text one line.
    """
    kept = "".join(
        " " if char in "\t\r" else char for char in text if char in "\n\t\r" or unicodedata.category(char)[0] != "C"
    )
    escaped = _LINE_MARKER.sub(
        lambda m: f"{m[1]}\\{m[2]}" if m[2] else f"{m[1]}{m[3]}\\{m[4]}", kept.translate(_MARKDOWN_ESCAPES)
    )
    return escaped.replace("://", "\\://")


#: A vendor summary often is Markdown source (a GitHub advisory). In one blockquote paragraph its heading markers
#: and code fences are only noise, so they are dropped from the excerpt; whatever remains is escaped as usual.
_EXCERPT_NOISE = re.compile(r"(?<!\S)#{1,6}(?=\s)|`+")


def _md(text: str) -> str:
    """One line of feed text, safe as inline Markdown: whitespace is collapsed first, so no line adds a marker."""
    return neutralise(" ".join(text.split()))


#: Characters that would let a printed URL carry markup or hide its target: ``[text](url)`` masked links, code
#: spans, ``<url>``/``<@id>`` forms and spoilers. A URL holding one is not printed rather than escaped, so the line
#: stays a plain, clickable vendor link.
_URL_FORBIDDEN = frozenset("<>`\\|[]()")


def _public_https(url: str) -> bool:
    """True for an https URL with an ASCII host (punycode ``xn--`` passes) and no userinfo, safe to print."""
    if any(unicodedata.category(char)[0] == "C" or char.isspace() or char in _URL_FORBIDDEN for char in url):
        return False
    try:
        parts = urllib.parse.urlsplit(url)
        host, _ = parts.hostname, parts.port
    except ValueError:
        return False
    return parts.scheme == "https" and bool(host) and host.isascii() and "@" not in parts.netloc


def _autolink(url: str) -> str:
    """``<url>``: Discord shows it without an embed and markdown-it makes it a link. Only for a ``_public_https`` URL.

    An ``@`` becomes ``%40``: ``inert`` would put a zero-width space into the address, and a Matrix client would
    read ``@room`` in a path as a mention.
    """
    return f"<{url.replace('@', '%40')}>"


def _fact(label: str, value: str) -> str:
    """One Markdown bullet; ``label`` is our own text, ``value`` is already safe Markdown."""
    return f"- **{label}:** {value}"


def _source_value(source_title: str, source_url: str, feed_host: str) -> str:
    """``<name> — <site>``; the site only when it is a public https URL off a hidden host."""
    title = _cap(_md(source_title), MAX_SOURCE_TITLE)
    public = _public_https(source_url) and _host(source_url) not in HIDDEN_SOURCE_HOSTS
    site = _autolink(source_url) if public else ""
    return f"{title} — {site}" if title and site else title or site


#: RFC3339 date-time grammar, ASCII only: seconds are required, the offset is ``Z`` or a numeric offset whose
#: hours are 00-23 and minutes 00-59, and RFC3339 allows a lower-case ``t``/``z``. The classes are written out
#: rather than ``\d`` because ``\d`` matches non-ASCII digits. The calendar values are checked by constructing a
#: ``datetime``: ``fromisoformat`` would also accept a bare date, an arbitrary single-character separator, a
#: missing seconds field and an out-of-range offset, none of which RFC3339 allows.
_RFC3339 = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?"
    r"(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


def _is_rfc3339(value: object) -> bool:
    """Whether ``value`` is a valid RFC3339 timestamp.

    The grammar is matched ASCII-only and the calendar values are validated by constructing the moment, so a
    malformed spelling cannot be mistaken for the fact. A leap second (``:60``) is deliberately not supported:
    RFC 3339 permits an application to leave leap seconds out, and refusing one can only keep the record active,
    never strip its severity. A caller reads a lifecycle field with this: a value this parser rejects is not
    evidence of a withdrawal, and the caller must keep the record active.
    """
    if not isinstance(value, str):
        return False
    # Validated exactly as sent: RFC3339 has no surrounding whitespace, and a padded value must not be read as
    # the fact either -- the field is evidence, not user input to tidy.
    match = _RFC3339.fullmatch(value)
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    try:
        datetime.datetime(year, month, day, hour, minute, second)
    except ValueError:
        return False
    return True


def _day(epoch: float) -> str:
    """``YYYY-MM-DD`` (UTC) of an epoch, the one date format of a message."""
    return datetime.datetime.fromtimestamp(epoch, datetime.UTC).strftime("%Y-%m-%d")


def render(
    tag: str,
    heading: str,
    ids: Sequence[str],
    line: str,
    note: str,
    link: str,
    summary: str,
    published: int | None,
    feed_host: str,
    source_title: str = "",
    source_url: str = "",
    action: str = ACTION,
) -> tuple[str, str]:
    """(title, body): the body is Markdown for chat channels, in four blocks.

    The body starts with a newline, so the title stays a paragraph of its own on both: chat renderers prefix
    ``**title**: `` to the text or send ``title`` + CRLF + the body. Then a bullet list of
    the labelled facts; the excerpt as one blockquote paragraph; ``action`` (``**Action:**``; an escalation passes
    ``ESCALATION_ACTION``) as a paragraph; and a bullet list with the link (an ``<https://…>`` autolink) and the
    source.

    Labels are English. ``heading``, ``summary`` and ``source_title`` are feed text: they pass through ``_md``
    (control characters dropped, every Markdown character escaped, one line) and then ``inert`` (mentions
    broken); the excerpt first loses its ``#`` heading markers and backticks (``_EXCERPT_NOISE``). The link is
    printed only when it is a public https URL. Message text that the worker wrote itself
    is not escaped. Title and body fit one Discord message.
    """
    title = _cap(inert(f"{LEVEL_LABEL[tag].upper()}: {_md(heading)}").rstrip(), 200)
    facts = [_fact("Severity", line)]
    if ids:  # A kernel advisory can name 100+ CVEs; the full list is on the vendor page.
        facts.append(
            _fact(
                "IDs",
                ", ".join(ids[:MAX_SHOWN_IDS])
                + (f" (+{len(ids) - MAX_SHOWN_IDS} more)" if len(ids) > MAX_SHOWN_IDS else ""),
            )
        )
    if published is not None:
        facts.append(_fact("Published", _day(published)))
    if note:
        facts.append(_fact("Note", note))
    links = []
    if _public_https(link) and _host(link) not in HIDDEN_SOURCE_HOSTS:
        links.append(_fact("Advisory", _autolink(link)))
    if source := _source_value(source_title, source_url, feed_host):
        links.append(_fact("Source", source))
    fixed = ["\n".join(facts), action, *(["\n".join(links)] if links else [])]
    room = MESSAGE_LIMIT - 100 - len(title) - len("\n" + "\n\n".join(fixed)) - len("\n\n> ")
    excerpt = _cap(_md(_EXCERPT_NOISE.sub("", summary)), min(500, room)) if room > 40 else ""
    sections = [fixed[0], *([f"> {excerpt}"] if excerpt else []), *fixed[1:]]
    return title, _cap(inert("\n" + "\n\n".join(sections)), MESSAGE_LIMIT - 100 - len(title))


# --------------------------------------------------------------------------
# State


def new_state() -> dict:
    return {"schema": STATE_SCHEMA, "seen": {}, "pending": [], "parked": [], "watch": {}, "cache": {}}


def _prune(state: dict, now: int) -> None:
    state["watch"] = {cve: entry for cve, entry in state["watch"].items() if now - entry["since"] <= REEVAL_WINDOW}
    state["cache"] = {key: entry for key, entry in state["cache"].items() if now - entry["at"] < CACHE_TTL}


def _stored_list(value: object) -> list[str]:
    """A list of identifier strings off a queue entry; anything else is stored as the empty list.

    The entry came through the state document, where a hand edit can turn a list into a string; splitting that
    into characters would put nonsense on the advisory page.
    """
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, str)]


def _delivery_snapshot(entry: dict, delivered_to: Sequence[str]) -> dict:
    """The compact record of one delivered message, copied off the queue entry so a later edit cannot reach it.

    ``tag``/``source``/``levels``/``scores`` are the classification the message was sent with, which the seen
    record previously dropped, and the identifiers, KEV-only CVEs and matched products answer the rest of the
    advisory page from the record alone. The body is deliberately absent: it is the rendered text, not a fact.
    """
    return {
        "tag": entry.get("tag", ""),
        "source": entry.get("source", ""),
        "title": entry.get("title", ""),
        "link": entry.get("link", ""),
        # Stored too, because the snapshot's meaning depends on which kind of message produced it.
        "kind": entry.get("kind", ""),
        "ids": _stored_list(entry.get("ids")),
        "cves": _stored_list(entry.get("cves")),
        "kev_only": _stored_list(entry.get("kev_only")),
        "products": _stored_list(entry.get("products")),
        "levels": dict(entry.get("levels") or {}),
        "scores": dict(entry.get("scores") or {}),
        "delivered_to": list(delivered_to),
    }


def _snapshot_id(snapshot: dict) -> str:
    """A stable id for one delivery snapshot, so its collections are stored once rather than per identifier."""
    material = json.dumps(snapshot, sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _delivered(
    state: dict, entry: dict, now: int, outcome: str = "delivered", delivered_to: Sequence[str] = ()
) -> None:
    """Advance state for one message the gateway accepted, or (``outcome="dropped"``) the operator discarded.

    ``delivered_to`` names the notifiers that accepted the message; ``deliver`` clears ``sent_to`` from the
    entry before calling this, so the accepted ids are passed in rather than read back off it.

    The snapshot is stored once under ``state["deliveries"]`` and each seen identifier points at it. Copying it
    into every identifier's record would be quadratic: one accepted message can name thousands of identifiers,
    each of which would then carry a copy of the full list.
    """
    if entry["kind"] == "new":
        snapshot = _delivery_snapshot(entry, delivered_to)
        fresh = [identifier for identifier in entry["ids"] if identifier not in state["seen"]]
        if fresh:
            deliveries = state.setdefault("deliveries", {})
            snapshot_id = _snapshot_id(snapshot)
            deliveries[snapshot_id] = snapshot
            for identifier in fresh:
                # The first record wins: an identifier keeps what was sent for it first, even when a later
                # message about the same advisory is dropped or delivered again from another source.
                state["seen"][identifier] = {"at": now, "outcome": outcome, "delivery": snapshot_id}
        kev_only = set(entry.get("kev_only") or ())
        # The rules that judged this message travel with it: a queue entry written before thresholds were
        # configurable carries none, and then the defaults are what judged it.
        judged_by = Thresholds.from_snapshot(entry.get("thresholds")).snapshot()
        source_id = entry.get("source_id")
        for cve, level in entry["levels"].items() if outcome == "delivered" else ():
            # A message the operator dropped was never sent, so no later escalation may refer to it as sent.
            record = {
                "since": now,
                "last_eval": now,
                "level": level,
                "kev_only": cve in kev_only,
                "title": entry["source"],
                "link": entry["link"],
                "thresholds": judged_by,
                "judged": level,
            }
            if isinstance(source_id, str) and source_id:
                # The source that queued the entry, so a later evaluation applies its own numbers rather than
                # the global block. An entry recorded before this key existed keeps judging by the global one.
                record["source_id"] = source_id
            if "scores" in entry:  # A message queued before the key existed has no score on record: legacy.
                record["cvss"] = entry["scores"].get(cve)
            state["watch"][cve] = record
    elif entry["kind"] == "escalation":
        watch = state["watch"].get(entry["cves"][0])
        if watch is not None:
            watch["level"] = entry["tag"]
            watch["judged"] = entry["tag"]
            watch["thresholds"] = Thresholds.from_snapshot(entry.get("thresholds")).snapshot()
    # An Adobe message was recorded in state["adobe"] when it was queued; delivering or dropping it changes nothing.


def _suppressed(
    state: dict,
    ids: Sequence[str],
    verdict: Verdict,
    item: Item,
    scores: Mapping[str, float | None],
    now: int,
    thresholds: Thresholds,
    source_id: str = "",
) -> None:
    for identifier in ids:
        # An identifier that was already notified keeps its history: this message is about the new CVEs.
        state["seen"].setdefault(identifier, {"at": now, "outcome": "suppressed"})
    for cve, level in verdict.levels:
        watch = {
            "since": now,
            "last_eval": now,
            "level": level,
            "judged": level,
            "title": headline(item.title, item.summary)[0],
            "link": item.link,
            "cvss": scores.get(cve),
            "thresholds": thresholds.snapshot(),
        }
        if source_id:
            # A suppressed advisory is watched too, and the source that recorded it is which numbers may judge
            # it later: without this, a re-evaluation would fall back to the global block and re-baseline a
            # CVE whose source never changed its rules.
            watch["source_id"] = source_id
        state["watch"][cve] = watch


def _claimed(state: dict) -> set[str]:
    """Every id the worker already answers for: seen, queued, or parked (a parked message is not lost).

    Compared exactly as stored. An identity is never rewritten, so a document written before this version --
    which already holds the publisher's raw guid -- matches that same raw guid read again, and no claim can
    be moved onto a different advisory by a normalisation that happened to agree.
    """
    stored = set(state["seen"]) | {
        identifier for entry in (*state["pending"], *state.get("parked", ())) for identifier in entry["ids"]
    }
    return {value for value in stored if isinstance(value, str)}


def _log_id(value: str) -> str:
    """An untrusted identifier made safe for one log record without losing a character of it.

    A control character would end the record and let a publisher write what looks like an application log
    line; a string that is not a Unicode scalar value (an escaped unpaired surrogate) cannot be encoded by a
    log handler at all. Both are escaped rather than dropped, because the log may spell an identity
    differently but must not change which advisory it names. Nothing is shortened here either: redaction runs
    on the finished record and replaces a whole configured credential, so shortening first would leave its
    prefix in the log where the redactor could no longer recognise it. The length bound therefore lives in
    ``http.RedactFilter.filter``, after the replacements. The spelling itself is ``http.log_safe``, which the
    redactor also knows, so escaping the argument first cannot hide a credential from it.
    """
    return log_safe(value)


def classify_new(
    state: dict,
    items: Sequence[Item],
    intel: Intel,
    kev: frozenset[str],
    kev_known: bool,
    now: int,
    feed_host: str,
    policy: Policy,
    *,
    share: int | None = None,
    trusted: Collection[str] = (),
    source_id: str = "",
    thresholds: Thresholds,
    quiet_hours: delivery.QuietHours | None = None,
) -> list[Item]:
    """Queue the items nobody has seen, oldest first, until the delivery cap or the lookup budget is reached.

    ``share`` bounds how much of the pending room one source may take, so a busy first source cannot fill the
    queue and leave later sources unclassified pass after pass.

    ``quiet_hours`` is the window in which delivery holds everything but a critical message. Only entries
    delivery would send now count towards the cap: a queue held by the window must not take the room a newly
    arrived critical advisory needs, and a message queued below is counted by the same rule, so a warning
    queued during the window still consumes none of it. ``delivery.is_held`` is the one owner of "held".

    ``source_id`` is the configured ``source.id`` the items came from, and each queued message records it with
    the watchlist products the item matched. Routing reads both; a message queued elsewhere (an escalation, an
    Adobe bulletin) has neither, so it falls through ``source``/``product`` rules to ``tag``, ``ids`` or the
    default.

    Returns the candidates left unclassified. The caller must carry them to the next pass: the feed window
    advances past them, so without that they can rotate out of the export unrecorded.
    """
    seen: dict = state["seen"]
    pending: list[dict] = state["pending"]

    def sendable(entry: dict) -> bool:
        """Whether delivery would offer this entry to a channel now, rather than hold it for the window."""
        return not delivery.is_held(now, entry, quiet_hours)

    # The delivery cap bounds what this pass may send, so only sendable entries fill it; held ones stay durable
    # and keep their attempts. ``room`` is fixed for the pass: entries queued below do not widen it.
    sendable_pending = sum(1 for entry in pending if sendable(entry))
    room = min(DELIVERY_CAP, sendable_pending + share) if share else DELIVERY_CAP
    claimed = _claimed(state)
    # Item guid -> epoch of its first enrichment fault (``_enrichment_wait``); ``_prune_enrich_clock`` keeps it clean.
    retry: dict[str, int] = state.setdefault("enrich_retry", {})
    # Node.js only: guid -> epoch of the first page naming no CVE, a longer clock that a later fault cannot shorten.
    waiting: dict[str, int] = state.setdefault("enrich_pending", {})
    classified = 0
    backlog = 0
    deferred: list[Item] = []
    ordered = sorted(items, key=lambda candidate: candidate.published or 0)
    for position, item in enumerate(ordered):
        if item.published is not None and now - item.published > BACKLOG_AGE and item.guid not in trusted:
            # History is decided before capacity: a full queue must not push an old item into carry, where
            # the next pass would treat it as recent.
            first_sight = item.explicit or (f"src:{item.guid}",)
            unclaimed = [identifier for identifier in first_sight if identifier not in claimed]
            for identifier in unclaimed:
                seen[identifier] = {"at": now, "outcome": "backlog"}
            claimed.update(unclaimed)
            backlog += bool(unclaimed)
            continue
        if sendable_pending >= room or classified >= MAX_CLASSIFY:
            # The tail still gets the history decision: carrying an old item would make the next pass treat
            # it as recent merely because it came from carry.
            carryable: list[Item] = []
            for rest in ordered[position:]:
                first = list(rest.explicit or (f"src:{rest.guid}",))
                if rest.published is not None and now - rest.published > BACKLOG_AGE and rest.guid not in trusted:
                    unclaimed_rest = [identifier for identifier in first if identifier not in claimed]
                    for identifier in unclaimed_rest:
                        seen[identifier] = {"at": now, "outcome": "backlog"}
                    claimed.update(unclaimed_rest)
                    backlog += bool(unclaimed_rest)
                    continue
                carryable.append(rest)
            if carryable:
                LOG.info("%d item(s) left unclassified this pass; carried to the next one", len(carryable))
            return carryable + deferred
        if f"src:{item.guid}" in claimed:
            continue  # Already seen under its own guid, before a PSA/CVE id was read from it.
        explicit = item.explicit
        # A new source subscription brings its whole history into the window as unseen entries, and nothing
        # here tells them apart from news but their age. So an old item at first sight is backlog: recorded,
        # never looked up or queued, and free of the lookup budget. Its ids stay claimed, so the same CVE in a
        # fresh item from another feed is a duplicate. Age alone decides: an old item that also names an
        # already-claimed id is still backlog, and only its unclaimed ids are recorded.
        first_sight = list(explicit or (f"src:{item.guid}",))
        # A carried item was recent when it first arrived, so age must not turn it into history later.
        if item.published is not None and now - item.published > BACKLOG_AGE and item.guid not in trusted:
            unclaimed = [identifier for identifier in first_sight if identifier not in claimed]
            for identifier in unclaimed:
                seen[identifier] = {"at": now, "outcome": "backlog"}
            claimed.update(unclaimed)
            backlog += bool(unclaimed)
            continue
        if explicit and all(identifier in claimed for identifier in explicit):
            continue
        # Debian's, php.net's and nodejs.org's feeds name no CVE: the tracker page, the ChangeLog section or the post
        # does. Running out of fetch budget leaves the item unseen for the next pass, as an item past MAX_CLASSIFY is.
        # A fault leaves it unseen too, and starts its ENRICH_RETRY_SECONDS clock (see ``_enrichment_wait``).
        dsa = dsa_id(item.title)
        php = php_release(item.title, item.link)
        node = None if dsa or php else nodejs_slug(item.title, item.link)
        # A php.net "Critical PHP Security Release" news entry names no id and no version: it is enriched by its day.
        day = (
            _day(item.published)
            if item.published is not None
            and not (dsa or php)
            and not explicit
            and php_announcement(item.title, item.link)
            else None
        )
        source = dsa or php or node
        unenriched = False
        release: PhpRelease | None = None
        page: NodejsRelease | None = None
        own: list[str] = []
        if day or (source and not any(identifier.startswith("CVE-") for identifier in explicit)):
            # An enriched PHP or Node.js item is also recorded under its guid: its own text names no id by which a
            # later pass could skip it (a DSA item has its DSA id), so without it every pass would fetch the page
            # again.
            own = [f"src:{item.guid}"] if php or node or day else []
            read = (
                intel.announcement_read()
                if day
                else bool(php and intel.changelog_read(php)) or bool(node and intel.nodejs_read(node))
            )
            if intel.tracker_left <= 0 and not read:
                deferred.append(item)  # out of fetch budget: retried next pass, so it must be carried
                continue
            clock, limit = retry, ENRICH_RETRY_SECONDS
            if dsa:
                found = intel.dsa_cves(dsa)
            elif node:
                page = intel.nodejs_page(node)
                # A post may precede its CVE list: a page without one starts its own 24 h clock, and a later page
                # fault does not shorten it.
                found = None if page is None else page.cves or None
                if page is not None or item.guid in waiting:
                    clock, limit = waiting, NODEJS_PENDING_SECONDS
                    # One clock per item: the day replaces an earlier fault's 2 h.
                    retry.pop(item.guid, None)
            else:
                release = intel.php_cves_on(day) if day else intel.php_cves(php) if php else None
                found = None if release is None else list(dict.fromkeys([*release.cves, *release.ghsas]))
            if found is None:
                if _enrichment_wait(clock, item.guid, now, limit):
                    deferred.append(item)  # waiting on its retry clock: carried so the feed cannot drop it
                    continue
                retry.pop(item.guid, None)
                waiting.pop(item.guid, None)
                unenriched = True
            else:
                retry.pop(item.guid, None)
                waiting.pop(item.guid, None)
                if release is not None and not found:
                    seen[f"src:{item.guid}"] = {"at": now, "outcome": "not-security"}
                    claimed.add(f"src:{item.guid}")
                    LOG.info("php changelog: %s names no CVE or GHSA; recorded as not-security, not alerted", php)
                    continue
                explicit = (*explicit, *(identifier for identifier in found if identifier not in explicit))
        cves = [identifier for identifier in explicit if identifier.startswith("CVE-")]
        ghsas = [identifier for identifier in explicit if identifier.startswith("GHSA-")]
        osv_cvss: float | None = None
        osv_complete = True
        #: CVE -> the score of the GHSA that aliases it, so one advisory's LOW cannot judge another's CVE.
        osv_fallbacks: dict[str, float] = {}
        independent_ghsa_cvss: float | None = None
        aliased_scored = False
        independent_scored = False
        if len(ghsas) > MAX_ITEM_GHSA_LOOKUPS:
            osv_complete = False  # the rest were not looked up, so nothing here is a complete measurement
        for ghsa in ghsas[:MAX_ITEM_GHSA_LOOKUPS]:
            osv = intel.ghsa(ghsa)
            osv_complete = osv_complete and osv.complete
            cves += [cve for cve in osv.cves if cve not in cves]
            claimed_advisory = not osv.cves and ghsa in claimed
            if osv.cvss is not None and not claimed_advisory:
                # An advisory already delivered is not evidence about the new finding this item carries.
                osv_cvss = max(osv_cvss or 0.0, osv.cvss)
                if osv.cves:
                    aliased_scored = True
                    for alias in osv.cves:
                        osv_fallbacks[alias] = max(osv_fallbacks.get(alias, 0.0), osv.cvss)
                elif not claimed_advisory:
                    # An alias-free advisory is its own severity evidence.
                    independent_scored = True
                    independent_ghsa_cvss = max(independent_ghsa_cvss or 0.0, osv.cvss)
        vendor_ids = [identifier for identifier in explicit if identifier.startswith(("PSA-", "DSA-"))]
        # Every explicit identifier is an identity: an unclaimed GHSA must not be hidden behind a CVE that
        # an earlier message already claimed.
        identity = list(dict.fromkeys([*cves, *ghsas, *vendor_ids])) or [f"src:{item.guid}"]
        ids = list(dict.fromkeys([*explicit, *identity, *own]))
        if all(identifier in claimed for identifier in identity):
            # Remember the alias so the next pass skips the OSV lookup, or the tracker or ChangeLog fetch. Another
            # branch of the same PHP release claimed these CVEs moments ago: this item is that release, not news.
            for alias in (*ghsas, *(identifier for identifier in explicit if identifier.startswith("DSA-")), *own):
                seen.setdefault(alias, {"at": now, "outcome": "alias"})
            continue
        classified += 1
        new_cves = [cve for cve in cves if cve not in claimed]
        facts = intel.cves(new_cves, lookup_limit=MAX_ITEM_CVE_LOOKUPS) if new_cves else {}
        # A source page that stayed unreadable past ENRICH_RETRY_SECONDS: the item was never measured, so it may be
        # a warning but never suppressed (as after a failed OSV lookup), and its note says why it is unknown.
        # An OSV score is evidence about the CVEs that advisory aliases, not about every CVE in the item: a LOW
        # GHSA must not suppress an unrelated, unmeasured CVE.
        verdict = judge(
            new_cves,
            facts,
            kev,
            kev_known,
            osv_cvss,
            osv_complete and not unenriched,
            osv_fallbacks=osv_fallbacks,
            independent_ghsa_cvss=independent_ghsa_cvss,
            osv_scores_are_aliased=aliased_scored and not independent_scored,
            thresholds=thresholds,
        )
        if unenriched and verdict.tag == "warning":
            verdict = replace(verdict, note=ENRICH_FAILED_NOTE)
        # The CVSS each watched CVE had when its message was queued: a later escalation by the remote rule needs it.
        scores = {cve: facts[cve].cvss for cve, _ in verdict.levels}
        # What a route predicate may read, and only that: the EPSS each judged CVE was measured at, and whether
        # any of them is in the KEV catalog. An unreadable catalog measured no membership, so it is recorded
        # as ``None`` rather than as "not in KEV", which would let ``kev: false`` claim a fact nobody observed.
        epss = {cve: facts[cve].epss for cve, _ in verdict.levels}
        kev_membership = None if not kev_known else any(cve in kev for cve, _ in verdict.levels)
        if verdict.tag == "suppressed":
            _suppressed(state, ids, verdict, item, scores, now, thresholds, source_id=source_id)
        else:
            shown_ids = [i for i in ids if i not in claimed and not i.startswith("src:")]
            heading, excerpt = headline(item.title, item.summary)
            if release is not None:
                excerpt = PHP_EXCERPT + ", ".join(release.versions)
            elif page is not None and page.lines:
                excerpt = NODEJS_EXCERPT + ", ".join(page.lines)
            title, body = render(
                verdict.tag,
                heading,
                shown_ids,
                verdict.line,
                verdict.note,
                item.link,
                excerpt,
                item.published,
                feed_host,
                item.source_title,
                item.source_url,
            )
            queued = {
                "kind": "new",
                "tag": verdict.tag,
                "title": title,
                "body": body,
                "ids": ids,
                "cves": new_cves,
                "levels": dict(verdict.levels),
                "kev_only": list(verdict.skipped),
                "scores": scores,
                "epss": epss,
                "kev": kev_membership,
                "thresholds": thresholds.snapshot(),
                "source": heading,
                "link": item.link,
                "source_id": source_id,
                "products": list(matched_products(item, policy)),
            }
            pending.append(queued)
            # Counted by the same rule as the entries already there: a warning queued inside the window is
            # held and leaves the room free, while a critical queued now consumes it.
            if sendable(queued):
                sendable_pending += 1
        claimed.update(ids)
        LOG.info("classified %s as %s", _log_id(item.guid if not item.explicit else item.explicit[0]), verdict.tag)
    if backlog:
        LOG.info("recorded %d item(s) older than %d days as backlog, not alerted", backlog, BACKLOG_AGE // DAY)
    if not retry:
        state.pop("enrich_retry", None)
    if not waiting:
        state.pop("enrich_pending", None)
    return deferred


def _enrichment_wait(retry: dict[str, int], guid: str, now: int, limit: int = ENRICH_RETRY_SECONDS) -> bool:
    """After an enrichment fault: True while item ``guid`` is inside ``limit`` seconds of its first failure.

    The first fault starts the clock. Once it has run out the entry is removed and the item goes out once as unknown
    severity; the claim then keeps it from being fetched or sent again.
    """
    key = guid
    first = retry.setdefault(key, now)
    if now - first < limit:
        LOG.warning(
            "enrichment: item %s waits for its CVE list or source page (first missing %d s ago); retried next pass",
            _log_id(guid),
            now - first,
        )
        return True
    LOG.warning(
        "enrichment: item %s has no CVE list or readable source page after %d s; sent once with unknown severity",
        _log_id(guid),
        now - first,
    )
    del retry[key]
    return False


def _prune_enrich_clock(state: dict, key: str, guids: set[str]) -> None:
    """Keep the ``key`` (``enrich_retry`` or ``enrich_pending``) entries of items still in the export; drop a damaged
    one. State written before the key existed has none, and an empty map is not written."""
    stored = state.get(key)
    kept = {
        guid: first
        for guid, first in (stored.items() if isinstance(stored, dict) else ())
        if guid in guids and type(first) is int
    }
    if kept:
        state[key] = kept
    else:
        state.pop(key, None)


def _score_is_new(entry: dict, thresholds: Thresholds) -> bool:
    """True when the CVSS now on record is news to a reader: the CVE was unscored or below the bar when queued.

    A watch entry without the ``cvss`` key was written before the score was recorded; its score counts as known.
    """
    return "cvss" in entry and (entry["cvss"] is None or entry["cvss"] < thresholds.critical_cvss)


def _entry_thresholds(entry: dict, default: Thresholds, overrides: Mapping[str, Thresholds] | None) -> Thresholds:
    """The numbers that judge one watch entry: those of the source that queued it, or the global block.

    A watch entry written before the source was recorded, a hand-edited ``source_id`` and a source the
    configuration no longer defines all fall back to the global block -- which is what judged them when they
    were written, and the state file is JSON a person can damage without warning.
    """
    source_id = entry.get("source_id")
    if isinstance(source_id, str) and source_id:
        return (overrides or {}).get(source_id, default)
    return default


def reevaluate(
    state: dict,
    intel: Intel,
    kev: frozenset[str],
    kev_known: bool,
    now: int,
    feed_host: str,
    *,
    thresholds: Thresholds,
    source_thresholds: Mapping[str, Thresholds] | None = None,
) -> None:
    """Re-score due CVEs once a day; queue one escalation per level a CVE newly reaches.

    The remote-and-unauthenticated rule alone escalates only a CVE whose score was new (``_score_is_new``): a rule
    that changed since the first message is not a change in the world. KEV, SSVC and EPSS escalate as before.

    Each entry is judged by the numbers of the source that queued it (``source_thresholds``, from
    ``Config.thresholds_for``), so a per-source override behaves exactly like the global block: a *threshold*
    change is the same kind of rule change, so an entry judged under other numbers is re-baselined once
    (``entry["thresholds"]``) instead of being escalated: otherwise lowering the floor would send the whole
    watch list out at once. Observed exploitation is the exception -- a KEV hit or CISA's active flag that a
    reader was never told about is a miss, whatever the thresholds say.
    """
    watch: dict = state["watch"]
    due = sorted(
        (
            cve
            for cve, entry in watch.items()
            if now - entry["last_eval"] >= REEVAL_INTERVAL and not entry.get("kev_only")
        ),
        key=lambda cve: (watch[cve]["last_eval"], cve),
    )[:MAX_REEVAL]
    if not due and not any(entry.get("kev_only") for entry in watch.values()):
        return
    kev_only_due = [
        cve for cve, entry in watch.items() if entry.get("kev_only") and now - entry["last_eval"] >= REEVAL_INTERVAL
    ]
    deferred: set[str] = set()
    facts = intel.cves(due, force=True, deferred=deferred) if due else {}
    for cve in kev_only_due:
        facts.setdefault(cve, CveFacts(None, None, None, None, False))
    due = [*due, *kev_only_due]
    for cve in due:
        current = facts[cve]
        entry = watch[cve]
        entry_thresholds = _entry_thresholds(entry, thresholds, source_thresholds)
        # Membership is positive evidence on its own; kev_known only gates the *absence*-based suppression.
        deciding = critical_reason(current, cve in kev, thresholds=entry_thresholds)
        if cve in deferred and not deciding:
            # No request was made and nothing independently decisive is known: try again next pass rather
            # than waiting a whole day. KEV or SSVC evidence still escalates now.
            continue
        if not current.complete and not deciding:
            # A failed lookup changes nothing unless an independently sufficient signal (KEV, SSVC active,
            # or a remote-unauthenticated CVSS >= 9.0) already decides the level.
            # Retried after the next daily interval rather than on every pass: otherwise a handful of CVEs
            # whose lookups keep failing would hold the whole batch and every later watch would starve.
            # A KEV hit is a local fact and does not need the failed lookups.
            entry["last_eval"] = now
            continue
        entry["last_eval"] = now
        level, reason = level_of(current, cve in kev, kev_known, thresholds=entry_thresholds)
        # Two levels, deliberately kept apart: ``level`` is what the reader was last told, and ``judged`` is what
        # the numbers in force now make of the CVE, whether or not anything was sent. A re-baseline raises only
        # the second, so it stays silent -- while later evidence (KEV, SSVC) can still escalate against the first.
        told = _rank(entry.get("level"))
        judged_by = Thresholds.from_snapshot(entry.get("thresholds"))
        entry["thresholds"] = entry_thresholds.snapshot()
        evidence = reason in ("kev", "ssvc") and _rank(level) > told
        if judged_by != entry_thresholds:
            entry["judged"] = level
            if not evidence:
                # A settings edit is not a change in the world, so it must not look like one.
                LOG.info("reevaluate: %s recorded as %s under changed thresholds; nothing sent", cve, level)
                continue
        held = reason == "remote" and not _score_is_new(entry, entry_thresholds)
        if held:  # Judge again without the remote rule, so EPSS can still escalate.
            level, reason = level_of(
                replace(current, remote_unauth=False), cve in kev, kev_known, thresholds=entry_thresholds
            )
        if level == "warning" and not (
            current.cvss is not None and current.cvss >= entry_thresholds.suppress_below_cvss
        ):
            continue  # Still unscored or LOW: not an escalation.
        if _rank(level) <= max(told, _rank(entry.get("judged"))) and not evidence:
            if held and entry["level"] != "critical":
                LOG.info(
                    "reevaluate: %s already scored %.1f when sent; the remote rule alone does not escalate it",
                    cve,
                    current.cvss,
                )
            continue
        if any(
            queued["kind"] == "escalation" and queued["cves"] == [cve] and RANK[queued["tag"]] >= RANK[level]
            for queued in (*state["pending"], *state.get("parked", ()))
        ):
            continue
        before = "recorded as LOW and not sent" if entry["level"] == "suppressed" else "sent as a warning"
        line = metrics_line(current.cvss, current.epss, current.percentile, current.ssvc, cve in kev)
        note = change_note(reason, entry_thresholds)
        title, body = render(
            level,
            f"{cve} now {LEVEL_LABEL[level]}",
            [cve],
            line,
            note,
            entry["link"],
            f"Previously {before} ({_day(entry['since'])}): {entry['title']}",
            None,
            feed_host,
            action=ESCALATION_ACTION,
        )
        # No source_id and no products: an escalation is not a feed item, so routing falls through a
        # source/product rule to tag, ids or the default. Its measured score travels with it so a numeric
        # predicate judges what the escalation message reports, and its KEV membership is the fact that decided it.
        state["pending"].append(
            {
                "kind": "escalation",
                "tag": level,
                "title": title,
                "body": body,
                "ids": [cve],
                "cves": [cve],
                "levels": {},
                "scores": {cve: current.cvss},
                "epss": {cve: current.epss},
                "kev": None if not kev_known else cve in kev,
                "source": entry["title"],
                "link": entry["link"],
                "thresholds": entry_thresholds.snapshot(),
            }
        )


# --------------------------------------------------------------------------
# Adobe Commerce bulletins

# --------------------------------------------------------------------------
# Adobe Commerce bulletins (--adobe-commerce)


def _versions(rows: Sequence[tuple[str, tuple[str, ...]]]) -> str:
    """``product → v1, v2; product → …``, versions verbatim; the whole is page text and is escaped once."""
    return _md("; ".join(f"{product} → {', '.join(versions)}" for product, versions in rows))


def adobe_exploited(cves: Sequence[str], detail: adobe.Detail | None, kev: frozenset[str], kev_known: bool) -> str:
    """``yes`` | ``no`` | ``unknown``. Adobe's "not aware" sentence never counts: Adobe does not update it.

    Only a KEV hit or Adobe's positive sentence says ``yes``. ``no`` needs both sources to have answered: a
    catalog that is unknown, or a page that was not read, leaves it ``unknown``.
    """
    if any(cve in kev for cve in cves) or (detail is not None and detail.exploited):
        return "yes"
    return "no" if kev_known and detail is not None else "unknown"


def adobe_decision(bulletin: adobe.Bulletin, detail: adobe.Detail | None, exploited: str) -> bool:
    """Whether the message asks for a customer decision: priority 1, exploited, or a critical CVE needing no login."""
    return (
        bulletin.priority == 1
        or exploited == "yes"
        or (
            detail is not None and any(cve.severity == "critical" and cve.auth_required is False for cve in detail.cves)
        )
    )


def render_adobe(
    tag: str, apsb: str, head: Sequence[tuple[str, str]], detail: Sequence[tuple[str, str]], decision: bool, link: str
) -> tuple[str, str]:
    """(title, body) as Markdown in three blocks: the fact bullets, the bold decision line, then the link bullet.

    Like ``render``, the body starts with a newline. ``head`` is (label, value) text the worker wrote. ``detail`` is
    (label, value) page text whose value is already escaped by ``_md``; the values share whatever room the other
    blocks leave (a short value keeps its length), so the link is never the part cut. ``inert`` runs last.
    """
    title = _cap(inert(f"{LEVEL_LABEL[tag].upper()}: Adobe Commerce {apsb}"), 200)
    action = [
        *([f"**{ADOBE_DECISION}**"] if decision else []),
        *([_fact("Biuletyn", _autolink(link))] if _public_https(link) else []),
    ]
    heads = [_fact(label, value) for label, value in head]
    prefixes = sum(len(_fact(label, "")) + 1 for label, _ in detail)
    room = MESSAGE_LIMIT - 100 - len(title) - len("\n".join(heads)) - len("\n\n".join(action)) - prefixes - 6
    shown: dict[int, str] = {}
    for index in sorted(range(len(detail)), key=lambda position: len(detail[position][1])):  # shortest first
        allowance = min(max(room // (len(detail) - len(shown)), 40), MAX_ADOBE_FIELD)
        shown[index] = _cap(detail[index][1], allowance)
        room -= len(shown[index]) + 1
    facts = [*heads, *(_fact(label, shown[index]) for index, (label, _) in enumerate(detail))]
    sections = ["\n".join(facts), *action]
    return title, _cap(inert("\n" + "\n\n".join(sections)), MESSAGE_LIMIT - 100 - len(title))


def _priority(bulletin: adobe.Bulletin) -> tuple[str, str]:
    return "Adobe priority", str(bulletin.priority) if bulletin.priority is not None else "unknown"


def _login_answer(detail: adobe.Detail | None) -> str:
    """Whether the critical CVE with the highest score needs a login; on a tie the unauthenticated one decides."""
    critical = [cve for cve in detail.cves if cve.severity == "critical"] if detail else []
    if not critical:
        return "no critical CVEs" if detail and detail.cves else NO_DETAILS
    worst = max(critical, key=lambda cve: (cve.cvss or 0.0, cve.auth_required is False))
    return NO_DETAILS if worst.auth_required is None else "yes" if worst.auth_required else "no"


def _adobe_new_message(bulletin: adobe.Bulletin, detail: adobe.Detail | None, exploited: str) -> dict:
    decision = adobe_decision(bulletin, detail, exploited)
    scores = [cve.cvss for cve in detail.cves if cve.cvss is not None] if detail else []
    head = [
        ("Adobe bulletin", bulletin.apsb),
        _priority(bulletin),
        ("Highest CVSS", f"{max(scores):.1f}" if scores else NO_DETAILS),
        ("Authentication required", _login_answer(detail)),
        ("Exploited", exploited),
    ]
    lines = [
        ("Affected versions", _versions(detail.affected) if detail and detail.affected else NO_DETAILS),
        ("Fixed versions", _versions(detail.fixed) if detail and detail.fixed else NO_DETAILS),
    ]
    if detail and detail.hotfix_note:
        lines.append(("Hotfix", _md(detail.hotfix_note)))
    tag = "critical" if decision else "warning"
    title, body = render_adobe(tag, bulletin.apsb, head, lines, decision, bulletin.url)
    # No source_id and no products: a bulletin is not a feed item, so routing falls through a source/product
    # rule to tag, ids or the default.
    return {
        "kind": "adobe",
        "tag": tag,
        "title": title,
        "body": body,
        "ids": [bulletin.apsb],
        "cves": [],
        "levels": {},
        "source": f"Adobe Commerce {bulletin.apsb}",
        "link": bulletin.url,
    }


def _adobe_kev_message(bulletin: adobe.Bulletin, listed: Sequence[str]) -> dict:
    shown = ", ".join(listed[:MAX_SHOWN_IDS]) + (
        f" (+{len(listed) - MAX_SHOWN_IDS} more)" if len(listed) > MAX_SHOWN_IDS else ""
    )
    head = [
        ("Adobe bulletin", bulletin.apsb),
        _priority(bulletin),
        ("Exploited", "yes (CISA KEV)"),
        ("CVEs in KEV", shown),
    ]
    title, body = render_adobe("critical", bulletin.apsb, head, [], True, bulletin.url)
    # Same as a new bulletin: no source_id or products, so tag, ids or the default decide.
    return {
        "kind": "adobe-kev",
        "tag": "critical",
        "title": title,
        "body": body,
        "ids": [bulletin.apsb],
        "cves": [],
        "levels": {},
        "source": f"Adobe Commerce {bulletin.apsb}",
        "link": bulletin.url,
    }


def _adobe_detail(http: Http, apsb: str) -> adobe.Detail | None:
    status, _, body = http("GET", adobe.detail_url(apsb), {"Accept": "text/html"}, None)
    detail = adobe.parse_detail(body) if status == 200 else None
    if detail is None:
        LOG.warning("adobe commerce: no details for %s (HTTP %s)", apsb, status)
    return detail


def _adobe_list(http: Http, stored: object) -> tuple[adobe.Bulletin, ...] | str:
    """The Commerce bulletins, or why the response (or the stored state it is compared with) cannot be trusted."""
    status, _, body = http("GET", adobe.CAAS_URL, {"Accept": "application/json"}, None)
    if status != 200:
        return f"HTTP {status}"
    bulletins = adobe.parse_caas(body)
    if bulletins is None:
        return "the response is not a list of cards"
    if not bulletins:
        return "the response holds no Adobe Commerce bulletin"
    if stored is not None and not (
        isinstance(stored, dict)
        and isinstance(stored.get("seen"), dict)
        and all(
            isinstance(record, dict)
            and {"cves", "at", "exploited"} <= record.keys()
            and isinstance(record["cves"], list)
            and all(isinstance(cve, str) for cve in record["cves"])
            and type(record["at"]) is int
            and (record["exploited"] is None or isinstance(record["exploited"], bool))
            for record in stored["seen"].values()
        )
    ):
        return "the stored Adobe state is invalid; not re-seeding"
    # A list that shares nothing with the response seen last pass may be another or a cut-off list; comparing
    # against the lifetime history instead would reject every normally rotating response forever.
    previous = stored.get("window") if isinstance(stored, dict) else None
    current = {bulletin.apsb for bulletin in bulletins}
    if isinstance(previous, list) and previous and not current & set(previous):
        return "the response shares no bulletin with the previous one; it may be cut off"
    return bulletins


def adobe_pass(state: dict, http: Http, kev: frozenset[str], kev_known: bool, now: int) -> bool:
    """Queue the Commerce bulletins nobody has been told about; False after a source fault.

    ``state["adobe"]["seen"]`` maps an APSB id to its CVEs, whether it is already reported exploited (``None``
    when it was seeded while the KEV catalog was unknown; the next pass with a catalog settles it silently, so an
    old bulletin never gets a follow-up), and when it was recorded. A bulletin is recorded when its message
    enters ``pending``, which then owns delivery. The first run (no ``adobe`` key) records everything and queues
    nothing; a failed first run records nothing. A response or stored record that cannot be trusted queues nothing
    at all; invalid stored records are kept rather than re-seeded.

    A new bulletin whose detail page cannot be read is neither queued nor recorded: ``state["adobe"]["retry"]`` maps
    its APSB id to the epoch of the first failure and the page is read again on every pass. A readable page gives
    the one complete message. Once ``ADOBE_DETAIL_RETRY_SECONDS`` have passed, the message goes out once without
    details. A detail fault is not a source fault: the return value stays True. State written before ``retry``
    existed has none.
    """
    stored = state.get("adobe")
    bulletins = _adobe_list(http, stored)
    if isinstance(bulletins, str):
        LOG.error("adobe commerce: source failure: %s; nothing is treated as new", bulletins)
        return False
    if stored is None:
        state["adobe"] = {
            "window": sorted({bulletin.apsb for bulletin in bulletins}),
            "seen": {
                bulletin.apsb: {
                    "cves": list(bulletin.cves),
                    "at": now,
                    "exploited": any(cve in kev for cve in bulletin.cves) if kev_known else None,
                }
                for bulletin in bulletins
            },
        }
        LOG.info("adobe commerce: first run, %d bulletin(s) recorded without a message", len(bulletins))
        return True
    seen: dict = stored["seen"]
    unseen = [bulletin for bulletin in bulletins if bulletin.apsb not in seen]
    # Outstanding work: a bulletin first seen but not yet delivered (detail page failed, or it exceeded the
    # per-pass budget) is remembered here, so a rotation that drops it from the next response cannot lose it.
    stored_backlog = stored.get("backlog")
    backlog: dict[str, dict] = (
        {
            apsb: dict(record)
            for apsb, record in stored_backlog.items()
            if isinstance(record, dict) and isinstance(record.get("cves"), list) and isinstance(record.get("url"), str)
        }
        if isinstance(stored_backlog, dict)
        else {}
    )
    for bulletin in unseen:
        backlog.setdefault(
            bulletin.apsb,
            {"cves": list(bulletin.cves), "url": bulletin.url, "priority": bulletin.priority},
        )
    stored_retry = stored.get("retry")
    previous = stored_retry if isinstance(stored_retry, dict) else {}
    retry: dict[str, int] = {apsb: first for apsb, first in previous.items() if isinstance(first, int)}
    for apsb in backlog:
        backlog[apsb]["first"] = retry.get(apsb, now)
    # Retries come first and share the per-pass budget with the bulletins first seen now.
    fresh = sorted(
        unseen,
        key=lambda bulletin: (
            bulletin.apsb not in retry,
            [int(number) for number in re.findall(r"\d+", bulletin.apsb)],
        ),
    )
    # Record this pass's window, which the next pass compares against for the cut-off check.
    state["adobe"]["window"] = sorted({bulletin.apsb for bulletin in bulletins})
    # The backlog is the work list: this pass's unseen bulletins first, then anything still outstanding from an
    # earlier window. Bounded so a permanently broken bulletin cannot grow the state without limit.
    by_apsb = {bulletin.apsb: bulletin for bulletin in unseen}
    outstanding = [
        by_apsb.get(apsb) or adobe.Bulletin(apsb, record.get("priority"), tuple(record["cves"]), record["url"])
        for apsb, record in sorted(backlog.items(), key=lambda pair: (pair[1].get("first", now), pair[0]))
    ][: MAX_ADOBE_NEW * 4]
    fresh = outstanding[:MAX_ADOBE_NEW]
    followed = 0
    queued = 0
    for bulletin in bulletins:
        record = seen.get(bulletin.apsb)
        if record is None:
            continue
        record["cves"] = list(dict.fromkeys((*record.get("cves", ()), *bulletin.cves)))
        listed = [cve for cve in record["cves"] if cve in kev]
        if record.get("exploited") is None:  # seeded while the catalog was unknown: settle it without a message
            if kev_known:
                record["exploited"] = bool(listed)
            continue
        if listed and not record["exploited"]:
            state["pending"].append(_adobe_kev_message(bulletin, listed))
            record["exploited"] = True
            followed += 1
    for bulletin in fresh:
        detail = _adobe_detail(http, bulletin.apsb)
        if detail is None:
            first = retry.setdefault(bulletin.apsb, now)
            backlog.setdefault(bulletin.apsb, {"cves": list(bulletin.cves), "url": bulletin.url})["first"] = first
            if now - first < ADOBE_DETAIL_RETRY_SECONDS:
                LOG.warning(
                    "adobe commerce: %s waits for its detail page (first failed %d s ago); retried next pass",
                    bulletin.apsb,
                    now - first,
                )
                continue
            LOG.warning(
                "adobe commerce: %s has no detail page after %d s; its message says so", bulletin.apsb, now - first
            )
        retry.pop(bulletin.apsb, None)
        backlog.pop(bulletin.apsb, None)  # delivered: no longer outstanding
        cves = list(dict.fromkeys((*bulletin.cves, *(cve.cve for cve in detail.cves))) if detail else bulletin.cves)
        exploited = adobe_exploited(cves, detail, kev, kev_known)
        state["pending"].append(_adobe_new_message(bulletin, detail, exploited))
        seen[bulletin.apsb] = {"cves": cves, "at": now, "exploited": exploited == "yes"}
        queued += 1
    if retry:
        stored["retry"] = retry
    else:
        stored.pop("retry", None)
    if backlog:
        stored["backlog"] = backlog
    else:
        stored.pop("backlog", None)
    LOG.info(
        "adobe commerce: %d bulletin(s) in the list, %d new queued, %d outstanding, %d KEV follow-up(s) queued",
        len(bulletins),
        queued,
        len(backlog),
        followed,
    )
    return True


def item_to_state(item: Item) -> dict:
    """A candidate carried to the next pass; a rotating feed would otherwise drop it unrecorded."""
    return {
        "guid": item.guid,
        "title": item.title,
        "link": item.link,
        "summary": item.summary,
        "published": item.published,
        "explicit": list(item.explicit),
        "source_title": item.source_title,
        "source_url": item.source_url,
    }


def item_from_state(row: object) -> Item:
    data = row if isinstance(row, dict) else {}
    published = data.get("published")
    explicit = data.get("explicit")
    return Item(
        str(data.get("guid", "")),
        str(data.get("title", "")),
        str(data.get("link", "")),
        str(data.get("summary", "")),
        published if type(published) is int else None,
        tuple(str(value) for value in explicit) if isinstance(explicit, list) else (),
        str(data.get("source_title", "")),
        str(data.get("source_url", "")),
    )


# --------------------------------------------------------------------------
# Delivery


def deliver(
    state: dict,
    notifiers: Sequence,
    http: Http,
    now: int,
    *,
    persist: Callable[[], None] | None = None,
    routes: Sequence[dict] = (),
    default: Sequence[str] = (),
    digest: bool = False,
    quiet_hours: delivery.QuietHours | None = None,
) -> bool:
    """Deliver up to DELIVERY_CAP pending messages; False on a failed pass.

    ``routes`` and ``default`` narrow the channels per message (see :func:`routing.select`); both empty keeps
    the pre-routing behaviour of every enabled notifier. A failed message stays at the head and stops the pass,
    so order is kept. Its MAX_DELIVERY_ATTEMPTS-th failed attempt, or a first attempt older than PARK_AFTER,
    parks it instead (see ``_park``) and the pass goes on with the next message, unless the parked list is full:
    then it stays at the head and stops the pass. A message that already failed MAX_DELIVERY_ATTEMPTS times is
    never posted again, so a full parked list cannot turn into a duplicate post on every pass. A selection that
    names no built notifier is a configuration fault: it logs an error, fails the pass and leaves the message
    queued, never marked delivered.

    With ``digest`` and ``quiet_hours`` both unset this is the message-by-message loop it has always been,
    kept whole in :func:`_deliver_each` so turning the features off changes no request, no state field and no
    log line. When either is set, the routing decision is made per entry and the entries are grouped by the
    set of notifiers it selects, because a digest may only cover advisories that reach the same channels.
    Entries quiet hours hold are skipped while the delivery window is filled, so a queue of held warnings
    cannot take the slot a critical advisory needs; they stay pending and are looked at again on a later pass.
    Each group is planned once (:func:`delivery.plan`): a digest becomes one POST per destination covering the
    entries that still need it, and an entry held by quiet hours is absent from every batch, stays pending
    and does not count as a failed attempt. Success or failure is then recorded per covered entry -- one
    POST that covered several advisories is one attempt for each of them -- so the parking rule and
    ``state["seen"]`` stay honest.
    """
    if not notifiers:  # an empty notifier list must never mark a message delivered
        return not state["pending"]
    enabled_ids = [notifier.id for notifier in notifiers]
    if not digest and quiet_hours is None:
        return _deliver_each(
            state,
            notifiers,
            http,
            now,
            persist=persist,
            routes=routes,
            default=default,
            enabled_ids=enabled_ids,
        )
    return _deliver_grouped(
        state,
        notifiers,
        http,
        now,
        persist=persist,
        routes=routes,
        default=default,
        enabled_ids=enabled_ids,
        digest=digest,
        quiet_hours=quiet_hours,
    )


def _deliver_each(
    state: dict,
    notifiers: Sequence,
    http: Http,
    now: int,
    *,
    persist: Callable[[], None] | None,
    routes: Sequence[dict],
    default: Sequence[str],
    enabled_ids: list[str],
) -> bool:
    """The pre-digest delivery loop, kept whole: one message at a time, each with its own routing and attempts."""
    for entry in list(state["pending"][:DELIVERY_CAP]):
        entry.setdefault("first_attempt_at", now)
        if entry.get("attempts", 0) >= MAX_DELIVERY_ATTEMPTS:  # only a full parked list leaves one here
            if _park(state, entry, entry.get("last_status", 0), now):
                continue
            return False
        already = set(entry.get("sent_to") or ())
        selected, label = routing.select(entry, routes, default, enabled_ids)
        targets = [notifier for notifier in notifiers if notifier.id in set(selected)]
        # One line per decision, before any POST: the notifiers this message is routed to and the rule that
        # chose them. No body and no credential ever reaches it.
        LOG.debug("routing: %s -> %s (%s)", _audit_ids(entry), ",".join(selected) or "none", label)
        if not targets:
            LOG.error(
                "routing: %s selects no enabled notifier (%s, ids %s); the message stays pending",
                _audit_ids(entry),
                label,
                ",".join(selected) or "none",
            )
            return False
        statuses = []
        for notifier in targets:
            if notifier.id in already:  # a retry only re-sends to the channels that have not had it
                statuses.append(200)
                continue
            try:
                status = notifier.send(entry, http)
            except Exception as exc:  # a broken notifier is a failed attempt, never a crash or a duplicate
                LOG.error("notifier %s raised %s: %s", notifier.id, type(exc).__name__, exc)
                status = 0
            if 200 <= status < 300:
                already.add(notifier.id)
                if persist is not None:
                    # Persist the acknowledgement now: a shutdown between channels must not resend it.
                    entry["sent_to"] = sorted(already)
                    persist()
            statuses.append(status)
        if all(200 <= status < 300 for status in statuses):
            accepted = sorted(already)
            entry.pop("sent_to", None)
            state["pending"].remove(entry)
            _delivered(state, entry, now, delivered_to=accepted)
            LOG.info(
                "delivered %s %s %s (HTTP %s): %s",
                entry["tag"],
                entry["kind"],
                _audit_ids(entry),
                "/".join(str(status) for status in statuses),
                " ".join(entry["title"].split()),
            )
            continue
        status = max(statuses)  # 0 is a network error and the worst outcome
        entry["sent_to"] = sorted(already)
        entry["attempts"] = entry.get("attempts", 0) + 1
        entry["last_status"] = status
        if entry["attempts"] >= MAX_DELIVERY_ATTEMPTS or now - entry["first_attempt_at"] > PARK_AFTER:
            if _park(state, entry, status, now):
                continue
            return False
        LOG.error(
            "delivery of %s refused or unreachable (HTTP %s, attempt %d of %d); %d message(s) stay pending",
            _audit_ids(entry),
            status,
            entry["attempts"],
            MAX_DELIVERY_ATTEMPTS,
            len(state["pending"]),
        )
        return False
    return True


def _deliver_grouped(
    state: dict,
    notifiers: Sequence,
    http: Http,
    now: int,
    *,
    persist: Callable[[], None] | None,
    routes: Sequence[dict],
    default: Sequence[str],
    enabled_ids: list[str],
    digest: bool,
    quiet_hours: delivery.QuietHours | None,
) -> bool:
    """Deliver this pass's messages by routing group, batching each group through :func:`delivery.plan`.

    The delivery window is filled from entries this pass may actually send, not from the head of the queue:
    a held entry is skipped and leaves its slot to the next entry, so five held warnings cannot hide a
    critical advisory queued behind them. Held entries stay in ``pending`` and are looked at again on a later
    pass. The walk is done before the first POST so a group is complete when it is planned: a later advisory
    that routes to the same channels belongs in the same digest. Groups are keyed by the set of destination
    ids, so two rules that name the same notifiers in another order share one digest, and the entries keep
    the order in which they first appeared. A selection that names no built notifier therefore fails the pass
    before any of this pass's messages is posted, and every message stays pending.
    """
    window = []
    for entry in state["pending"]:
        if len(window) >= DELIVERY_CAP:
            break
        if delivery.is_held(now, entry, quiet_hours):
            continue  # still queued: the cap counts entries this pass may send, not held ones
        window.append(entry)
    candidates = []
    for entry in window:
        if entry.get("attempts", 0) >= MAX_DELIVERY_ATTEMPTS:  # only a full parked list leaves one here
            entry.setdefault("first_attempt_at", now)
            if not _park(state, entry, entry.get("last_status", 0), now):
                return False
            continue
        candidates.append(entry)
    groups: dict[frozenset[str], list[dict]] = {}
    targets_by_group: dict[frozenset[str], list] = {}
    for entry in candidates:
        selected, label = routing.select(entry, routes, default, enabled_ids)
        targets = [notifier for notifier in notifiers if notifier.id in set(selected)]
        # One line per decision, before any POST: the notifiers this message is routed to and the rule that
        # chose them. No body and no credential ever reaches it.
        LOG.debug("routing: %s -> %s (%s)", _audit_ids(entry), ",".join(selected) or "none", label)
        if not targets:
            LOG.error(
                "routing: %s selects no enabled notifier (%s, ids %s); the message stays pending",
                _audit_ids(entry),
                label,
                ",".join(selected) or "none",
            )
            return False
        key = frozenset(selected)
        if key not in groups:
            groups[key] = []
            targets_by_group[key] = targets
        groups[key].append(entry)
    for key, group in groups.items():
        for batch in delivery.plan(group, now, digest=digest, quiet=quiet_hours):
            if not _deliver_batch(state, http, now, persist, batch, targets_by_group[key], digest=digest):
                return False
    return True


def _deliver_batch(
    state: dict,
    http: Http,
    now: int,
    persist: Callable[[], None] | None,
    batch: delivery.Batch,
    targets: Sequence,
    *,
    digest: bool,
) -> bool:
    """Send one planned batch, destination by destination, and record the outcome per covered entry.

    Each destination receives only the entries that still need it: ``sent_to`` is kept across passes, so a
    digest rebuilt after a partial acknowledgement must not carry an advisory that destination already
    accepted. With digesting on, a destination gets one digest of its own subset; with it off, each of those
    entries is posted as it was rendered. An entry whose destinations have all accepted is delivered even
    when another entry in the batch failed, an entry with a refused destination takes one attempt for the
    pass, and a batch whose entries all park lets the pass continue, exactly as a single parked message does.
    Every refused entry is charged its attempt before any parking is attempted, so a full parked queue cannot
    leave a later covered entry with no attempt or status recorded.
    """
    covered = list(batch.entries)
    for entry in covered:
        entry.setdefault("first_attempt_at", now)
    statuses: list[int] = []
    failure_status: list[int | None] = [None] * len(covered)
    for notifier in targets:
        need = [index for index, entry in enumerate(covered) if notifier.id not in set(entry.get("sent_to") or ())]
        if not need:
            # Every covered entry has already had this destination; a retry may not send it anything.
            statuses.append(200)
            continue
        sends = (
            [(delivery.digest_message([covered[index] for index in need]), need)]
            if digest
            else [(covered[index], [index]) for index in need]
        )
        for payload, indices in sends:
            try:
                status = notifier.send(payload, http)
            except Exception as exc:  # a broken notifier is a failed attempt, never a crash or a duplicate
                LOG.error("notifier %s raised %s: %s", notifier.id, type(exc).__name__, exc)
                status = 0
            statuses.append(status)
            if 200 <= status < 300:
                for index in indices:
                    entry = covered[index]
                    entry["sent_to"] = sorted(set(entry.get("sent_to") or ()) | {notifier.id})
                if persist is not None:
                    # Persist the acknowledgement now: a shutdown between channels must not resend it.
                    persist()
            else:
                for index in indices:
                    # Keep the worst status seen for the entry, as the single-message path always reported.
                    previous = failure_status[index]
                    failure_status[index] = status if previous is None else max(previous, status)
    delivered = {
        index
        for index, entry in enumerate(covered)
        if all(notifier.id in set(entry.get("sent_to") or ()) for notifier in targets)
    }
    if delivered:
        status_text = "/".join(str(status) for status in statuses)
        for index in sorted(delivered):
            entry = covered[index]
            accepted = sorted(entry.get("sent_to") or ())
            entry.pop("sent_to", None)
            state["pending"].remove(entry)
            _delivered(state, entry, now, delivered_to=accepted)
            LOG.info(
                "delivered %s %s %s (HTTP %s): %s",
                entry["tag"],
                entry["kind"],
                _audit_ids(entry),
                status_text,
                " ".join(entry["title"].split()),
            )
    # Account for every covered entry before any parking is attempted. A full parked queue must not leave a
    # later covered entry with no attempt recorded: the failed POST covered it just as much as the first one.
    for index, entry in enumerate(covered):
        if index in delivered:
            continue
        status = failure_status[index]
        if status is None:  # a pending entry always has a destination that refused or failed it
            status = max(statuses)
        entry["attempts"] = entry.get("attempts", 0) + 1
        entry["last_status"] = status
    blocked = False
    remaining = []
    for index, entry in enumerate(covered):
        if index in delivered:
            continue
        status = entry["last_status"]
        if entry["attempts"] >= MAX_DELIVERY_ATTEMPTS or now - entry["first_attempt_at"] > PARK_AFTER:
            if not _park(state, entry, status, now):
                # The entry stays pending exactly as ``_park`` left it; the pass still fails below.
                blocked = True
        else:
            remaining.append((entry, status))
    for entry, status in remaining:
        LOG.error(
            "delivery of %s refused or unreachable (HTTP %s, attempt %d of %d); %d message(s) stay pending",
            _audit_ids(entry),
            status,
            entry["attempts"],
            MAX_DELIVERY_ATTEMPTS,
            len(state["pending"]),
        )
    return not remaining and not blocked


def _park(state: dict, entry: dict, status: int, now: int) -> bool:
    """Move a message that keeps failing out of ``pending``; the operator releases or drops it.

    False when the parked list is full: the message stays pending, so an outage that fails every message can
    never discard an advisory. Only ``--drop-parked`` writes ``dropped``.
    """
    if len(state["parked"]) >= MAX_PARKED:
        LOG.error(
            "delivery: the parked list is full (%d); %s stays pending (HTTP %s); run release-parked or drop-parked",
            MAX_PARKED,
            _audit_ids(entry),
            status,
        )
        return False
    state["pending"].remove(entry)
    entry["parked_at"] = now
    state["parked"].append(entry)
    LOG.error(
        "delivery: parked %s after %d failed attempt(s) since %d (last HTTP %s); run release-parked or drop-parked",
        _audit_ids(entry),
        entry["attempts"],
        entry["first_attempt_at"],
        status,
    )
    return True


#: The fields a released message loses: they describe the failed attempts, not the advisory.
PARKED_ATTEMPT_KEYS = ("attempts", "first_attempt_at", "parked_at")


def _released(entry: dict) -> dict:
    """A parked message as it goes back to the queue: no retry history, so the next pass starts fresh."""
    return {key: value for key, value in entry.items() if key not in PARKED_ATTEMPT_KEYS}


def manage_parked(store: Store, release: bool, now: int) -> int:
    """The operator's decision on the parked messages; sends nothing and needs no secret.

    The caller holds the store's lock, so the read and the write are one transaction. A store that cannot be
    read is logged and reported, never treated as an empty queue: an unreachable database is not a decision.
    """
    try:
        state = store.load()
    except (SourceError, StoreUnavailable) as exc:
        LOG.error("%s", exc)
        return 1
    if state is None:
        LOG.error("no state document in %s; nothing is parked", store)
        return 1
    parked = state.setdefault("parked", [])
    if release:
        state["pending"] = [*map(_released, parked), *state["pending"]]
    else:
        for entry in parked:
            _delivered(state, entry, now, outcome="dropped", delivered_to=entry.get("sent_to") or ())
    state["parked"] = []
    store.save(state)
    LOG.info(
        "%s %d parked message(s): %s",
        "released" if release else "dropped",
        len(parked),
        "; ".join(_audit_ids(entry) for entry in parked) or "none",
    )
    return 0


def parked_token(entry: Mapping) -> str:
    """A stable identity for one parked message, so an old row button cannot act on a different one.

    The position alone is not enough: a page offers "Drop" for the row it rendered, and a release or a second
    tap can move another message into that position before the form is submitted. The token covers the parts
    of the entry an operator saw (its time, identifiers, title and link) and moves with it.
    """
    material = [entry.get("parked_at"), entry.get("ids"), entry.get("title"), entry.get("link")]
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


def manage_parked_entry(store: Store, index: int, release: bool, now: int, *, expected: str | None = None) -> bool:
    """The operator's decision on one parked message, by its position in ``state["parked"]``.

    The same effect as :func:`manage_parked` for one entry. False when the state cannot be read, that
    position no longer exists, or ``expected`` names a different message: the page that offered the button
    may be older than the queue, and a stale row must refuse rather than act on whatever message moved into
    it. The caller holds the store's lock, exactly as for the bulk action.
    """
    try:
        state = store.load()
    except (SourceError, StoreUnavailable) as exc:
        LOG.error("%s", exc)
        return False
    if state is None:
        LOG.error("no state document in %s; nothing is parked", store)
        return False
    parked = state.get("parked")
    if not isinstance(parked, list) or not 0 <= index < len(parked):
        LOG.warning("no parked message at position %d; the queue changed since the page was rendered", index)
        return False
    entry = parked[index]
    # The shape is checked before the compare: ``compare_digest`` raises on non-ASCII input, and a token this
    # page never produced cannot name the row.
    if expected is not None and (
        not re.fullmatch(r"[0-9a-f]{16}", expected) or not hmac.compare_digest(parked_token(entry), expected)
    ):
        LOG.warning(
            "the message at parked position %d is not the one the page offered; the queue was not changed",
            index,
        )
        return False
    parked.pop(index)
    if release:
        state["pending"] = [_released(entry), *state["pending"]]
    else:
        # A partial delivery may already have been accepted by one notifier: the record keeps that fact even
        # though no escalation state may advance for a dropped message.
        _delivered(state, entry, now, outcome="dropped", delivered_to=entry.get("sent_to") or ())
    store.save(state)
    LOG.info(
        "%s parked message at position %d: %s",
        "released" if release else "dropped",
        index,
        _audit_ids(entry),
    )
    return True


def _audit_ids(entry: dict) -> str:
    shown = [_log_id(identifier) for identifier in entry["ids"] if not identifier.startswith("src:")]
    return ",".join(shown[:MAX_SHOWN_IDS]) or "no-id"


def seed(state: dict, items: Sequence[Item], now: int) -> list[Item]:
    """First run: everything older than the seed window is recorded as ``backlog``; the rest is returned to be queued.

    A bootstrap reveals history, it never delivers it, so a fresh record says ``backlog`` -- the same outcome an
    old item seen for the first time gets during classification -- and carries no delivery reference. An
    identifier already recorded keeps its first record, including when another source's history names it: the
    first record wins, as it does for every other write to ``seen``.
    """
    recent = []
    for item in items:
        # An undated item is unknown, not old: a valid RSS feed may omit dates, and consuming its current
        # advisories as history would silently drop them.
        if item.published is None or now - item.published <= SEED_WINDOW:
            recent.append(item)
            continue
        for identifier in item.explicit or (f"src:{item.guid}",):
            state["seen"].setdefault(identifier, {"at": now, "outcome": "backlog"})
    return recent
