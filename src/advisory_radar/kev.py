"""The CISA KEV catalog, cached with ETag/Last-Modified and a fallback copy."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from .http import Http, header, parse_json
from .state import SourceError, load_state_document, save_state

LOG = logging.getLogger("advisory_radar")
#: A CVE id in a KEV row: the year and at least four digits.
KEV_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
KEV_CACHE_SCHEMA = "advisory-radar-kev.v1"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# --------------------------------------------------------------------------
# KEV catalog


def _catalog_is_usable(rows: list) -> bool:
    """Every row must name a CVE: a reshaped response must fail closed, not wipe the cache to empty."""
    if not rows:
        return False
    return all(isinstance(row, dict) and KEV_ID_RE.match(str(row.get("cveID", "")).upper()) for row in rows)


def load_kev(http: Http, cache_path: Path, *, save: bool) -> tuple[frozenset[str], bool]:
    """(CVE ids in the catalog, whether the catalog is known). A failed fetch falls back to the cached copy."""
    try:
        cached = load_state_document(cache_path, KEV_CACHE_SCHEMA, "kev cache") or {}
    except (OSError, SourceError):
        cached = {}  # A cache is rebuilt, never trusted over a fresh fetch.
    cached_cves = cached.get("cves")
    if (
        not isinstance(cached_cves, list)
        or not cached_cves
        or any(not isinstance(cve, str) or not KEV_ID_RE.match(cve.upper()) for cve in cached_cves)
    ):
        cached = {}  # a damaged or empty cache must not masquerade as a known empty catalog
    headers = {"Accept": "application/json"}
    if cached.get("etag"):
        headers["If-None-Match"] = cached["etag"]
    if cached.get("last_modified"):
        headers["If-Modified-Since"] = cached["last_modified"]
    status, response_headers, body = http("GET", KEV_URL, headers, None)
    if status == 304 and cached:
        return frozenset(cached.get("cves", [])), True
    document = parse_json(body) if status == 200 else None
    vulnerabilities = document.get("vulnerabilities") if isinstance(document, dict) else None
    if isinstance(vulnerabilities, list) and _catalog_is_usable(vulnerabilities):
        cves = sorted({row["cveID"].upper() for row in vulnerabilities})
        if save:
            save_state(
                cache_path,
                {
                    "schema": KEV_CACHE_SCHEMA,
                    "etag": header(response_headers, "ETag"),
                    "last_modified": header(response_headers, "Last-Modified"),
                    "catalog_version": document.get("catalogVersion") if isinstance(document, dict) else None,
                    "cves": cves,
                },
            )
        return frozenset(cves), True
    if cached:
        LOG.warning("kev: fetch failed or returned an unusable catalog (HTTP %s); using the cached one", status)
        return frozenset(cached.get("cves", [])), True
    LOG.warning("kev: fetch failed (HTTP %s) and no cached catalog exists; nothing is promoted by KEV", status)
    return frozenset(), False
