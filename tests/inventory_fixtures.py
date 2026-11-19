"""Synthetic inventory documents for the inventory tests.

Invented package names and versions only: no real host, scan or software list. Each builder returns the bytes a
scanner or an SBOM tool would write, so a test imports them the way an upload or a dropped file arrives.
"""

from __future__ import annotations

import json

#: The package the advisories in these tests are about, and an affected-entry that fixes it in 2.3.1.
PACKAGE = "parser-lib"
AFFECTED_NPM = [
    {
        "package": {"ecosystem": "npm", "name": PACKAGE},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.3.1"}]}],
    }
]


def osv_facts(affected: list, *cves: str) -> dict:
    """What a pass keeps of one OSV record: the CVE ids it aliases and its raw ``affected`` list."""
    return {"cves": list(cves), "affected": affected}


def sbom_component(name: str, version: str | None, ecosystem: str = "npm") -> dict:
    """One SBOM component: a package URL, and a version field when the tool knew one."""
    entry = {"type": "library", "name": name, "purl": f"pkg:{ecosystem}/{name}" + (f"@{version}" if version else "")}
    if version:
        entry["version"] = version
    return entry


def cyclonedx(*components: dict, timestamp: str = "2026-10-20T10:00:00Z") -> bytes:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"timestamp": timestamp},
        "components": list(components),
    }
    return json.dumps(document).encode()


def spdx(*components: dict) -> bytes:
    """An SPDX 2.3 document with one package per component, each carrying its package URL as an external ref."""
    packages = [
        {
            "SPDXID": f"SPDXRef-{position}",
            "name": entry["name"],
            "versionInfo": entry.get("version", ""),
            "externalRefs": [
                {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": entry["purl"]}
            ],
        }
        for position, entry in enumerate(components)
    ]
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "creationInfo": {"created": "2026-10-20T10:00:00Z"},
        "packages": packages,
    }
    return json.dumps(document).encode()


def scan_finding(
    ecosystem: str,
    name: str,
    version: str,
    identifier: str,
    *,
    aliases: tuple[str, ...] = (),
    fixed: str | None = None,
    called: bool | None = None,
    analysis_key: str = "experimentalAnalysis",
) -> dict:
    """One OSV-Scanner package entry: the installed package, the record that matched it, and its call analysis.

    Written by hand from the layout the reader targets, not captured from a scanner run. ``analysis_key`` is the
    spelling of the call-analysis member; the reader accepts both ``experimentalAnalysis`` and
    ``experimental_analysis``.
    """
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    entry = {
        "package": {"name": name, "version": version, "ecosystem": ecosystem},
        "vulnerabilities": [
            {
                "id": identifier,
                "aliases": list(aliases),
                "affected": [
                    {
                        "package": {"ecosystem": ecosystem, "name": name},
                        "ranges": [{"type": "SEMVER", "events": events}],
                    }
                ],
            }
        ],
        "groups": [{"ids": [identifier, *aliases]}],
    }
    if called is not None:
        entry["groups"][0][analysis_key] = {identifier: {"called": called}}
    return entry


def osv_scanner(*packages: dict) -> bytes:
    """An OSV-Scanner v2 JSON result: one source, the given package entries."""
    document = {"results": [{"source": {"path": "package-lock.json", "type": "lockfile"}, "packages": list(packages)}]}
    return json.dumps(document).encode()


def scan_with_ranges(ranges: object, identifier: str = "GHSA-AAAA-BBBB-CCCC") -> bytes:
    """A scan whose one finding embeds an OSV record with ``ranges`` set to ``ranges``, of whatever type it is."""
    entry = scan_finding("npm", PACKAGE, "2.3.0", identifier, fixed="2.3.1")
    entry["vulnerabilities"][0]["affected"][0]["ranges"] = ranges
    return osv_scanner(entry)


def multipart(
    fields: dict[str, tuple[str | None, bytes | str]], boundary: str = "x-test-boundary"
) -> tuple[bytes, str]:
    """A multipart/form-data body and its Content-Type: ``{name: (filename or None, content)}``."""
    chunks = []
    for name, (filename, content) in fields.items():
        disposition = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename is not None else "")
        data = content.encode() if isinstance(content, str) else content
        chunks.append(f"--{boundary}\r\nContent-Disposition: {disposition}\r\n\r\n".encode() + data + b"\r\n")
    return b"".join(chunks) + f"--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"
