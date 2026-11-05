"""The CISA KEV catalog, cached with ETag/Last-Modified and a fallback copy."""

from __future__ import annotations

import logging
from pathlib import Path

from .http import Http, header, parse_json
from .state import SourceError, load_state_document, save_state

LOG = logging.getLogger("advisory_radar")
KEV_CACHE_SCHEMA = "advisory-radar-kev.v1"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# --------------------------------------------------------------------------
# KEV catalog


def load_kev(http: Http, cache_path: Path, *, save: bool) -> tuple[frozenset[str], bool]:
    """(CVE ids in the catalog, whether the catalog is known). A failed fetch falls back to the cached copy."""
    try:
        cached = load_state_document(cache_path, KEV_CACHE_SCHEMA, "kev cache") or {}
    except (OSError, SourceError):
        cached = {}  # A cache is rebuilt, never trusted over a fresh fetch.
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
    if isinstance(vulnerabilities, list):
        cves = sorted(
            {
                row["cveID"].upper()
                for row in vulnerabilities
                if isinstance(row, dict) and isinstance(row.get("cveID"), str)
            }
        )
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
        LOG.warning("kev: fetch failed (HTTP %s); using the cached catalog", status)
        return frozenset(cached.get("cves", [])), True
    LOG.warning("kev: fetch failed (HTTP %s) and no cached catalog exists; nothing is promoted by KEV", status)
    return frozenset(), False
