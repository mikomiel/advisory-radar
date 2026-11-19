"""The inventory import: three input formats, hard limits, a stored document that is checked when it is read."""

from __future__ import annotations

import ast
import copy
import json
import logging
import os
import stat
from pathlib import Path

import pytest

from advisory_radar import applicability, core, inventory
from advisory_radar.inventory import Inventory, InventoryError, parse
from inventory_fixtures import (
    AFFECTED_NPM,
    PACKAGE,
    cyclonedx,
    osv_facts,
    osv_scanner,
    sbom_component,
    scan_finding,
    scan_with_ranges,
    spdx,
)

NOW = 1_790_000_000
GHSA = "GHSA-AAAA-BBBB-CCCC"


def document_of(data: bytes, name: str = "sbom.json") -> dict:
    return parse(data, name=name, now=NOW, origin="upload")


def components_of(data: bytes) -> list[tuple[str, str, str]]:
    return [(item["ecosystem"], item["name"], item["version"]) for item in document_of(data)["components"]]


# --- nothing is executed ------------------------------------------------------------------------------


def test_the_modules_that_read_an_imported_file_can_start_no_process_and_open_no_socket():
    """A tripwire for the rule that no scanner runs here: the readers import no way to start a process, open a
    socket (which a container runtime's socket would need) or run text as code."""
    root = Path(inventory.__file__).parent
    modules = {"subprocess", "socket", "pty", "ctypes", "multiprocessing", "pickle", "marshal", "runpy"}
    calls = {"system", "popen", "eval", "exec", "execv", "execve", "spawnl", "spawnv", "fork", "__import__"}
    for name in ("inventory.py", "versions.py", "applicability.py"):
        tree = ast.parse((root / name).read_text())
        imported = {
            alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
        } | {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        called = {
            node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
        }
        assert not imported & modules, (name, imported & modules)
        assert not called & calls, (name, called & calls)


# --- identifiers and names ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "identifier",
    [
        "GHSA-AAAA-BBBB-CCCC",
        "ghsa-aaaa-bbbb-cccc",
        "GhSa-AaAa-bBbB-cCcC",
        "cve-2026-0001",
        "CVE-2026-0001",
        "pysec-2026-1",
    ],
)
def test_identifiers_are_normalised_exactly_as_the_pass_normalises_them(identifier):
    assert inventory.normalise_id(identifier) == core._normalise_id(identifier)


def test_package_names_are_normalised_the_way_each_ecosystem_compares_them():
    assert inventory.normalise_name("PyPI", "Foo_Bar.baz") == "foo-bar-baz"
    assert inventory.normalise_name("npm", "@Scope/Name") == "@scope/name"
    assert inventory.normalise_name("crates.io", "Serde_Json") == "serde-json"
    assert inventory.normalise_name("Go", "github.com/Example/Mod") == "github.com/Example/Mod"


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:npm/left-pad@1.3.0", ("npm", "left-pad", "1.3.0")),
        ("pkg:npm/%40scope/name@1.0.0", ("npm", "@scope/name", "1.0.0")),
        ("pkg:npm/@scope/name@1.0.0", ("npm", "@scope/name", "1.0.0")),
        ("pkg:npm/@scope/name", ("npm", "@scope/name", "")),
        ("pkg:pypi/Django@4.2.1", ("PyPI", "Django", "4.2.1")),
        ("pkg:golang/example.org/mod/v2@v2.1.0", ("Go", "example.org/mod/v2", "v2.1.0")),
        ("pkg:cargo/serde@1.0.0", ("crates.io", "serde", "1.0.0")),
        ("pkg:maven/org.example/lib@1.0", ("Maven", "org.example:lib", "1.0")),
        ("pkg:npm/left-pad@1.3.0?arch=x86#sub/path", ("npm", "left-pad", "1.3.0")),
        ("PKG:NPM/Left-Pad@1.0.0", ("npm", "Left-Pad", "1.0.0")),
        ("pkg:deb/debian/openssl@3.0", None),
        ("pkg:oci/image@sha256%3Aabc", None),
        ("pkg:npm", None),
        ("pkg:npm/", None),
        ("pkg:npm/@1.0.0", None),
        ("left-pad@1.3.0", None),
        ("", None),
        ("pkg:npm/" + "n" * inventory.MAX_PURL_CHARS, None),
        ("pkg:npm/" + "n" * (inventory.MAX_NAME_CHARS + 1) + "@1", None),
    ],
)
def test_a_package_url_names_an_ecosystem_a_package_and_a_version_or_nothing(purl, expected):
    assert inventory.parse_purl(purl) == expected


def test_a_file_name_is_shown_as_its_last_printable_segment():
    assert inventory.display_name("../../etc/passwd") == "passwd"
    assert inventory.display_name("C:\\scans\\sbom.json") == "sbom.json"
    assert inventory.display_name("a\x00b\x1b[31m\u202e.json") == "ab[31m.json"
    assert inventory.display_name("") == inventory.display_name("dir/") == "unnamed"
    assert len(inventory.display_name("n" * 500)) == inventory.MAX_FILENAME_CHARS


# --- SBOMs --------------------------------------------------------------------------------------------


def test_a_cyclonedx_sbom_lists_its_components_including_nested_ones():
    parent = sbom_component("parent-lib", "1.0.0")
    parent["components"] = [sbom_component("child-lib", "2.0.0")]
    document = document_of(cyclonedx(parent, sbom_component("Other_Lib", "3.0.0", "pypi")))
    assert document["format"] == "cyclonedx" and document["complete"] is True
    assert document["created"] == "2026-10-20T10:00:00Z"
    assert components_of(cyclonedx(parent, sbom_component("Other_Lib", "3.0.0", "pypi"))) == [
        ("npm", "parent-lib", "1.0.0"),
        ("npm", "child-lib", "2.0.0"),
        ("PyPI", "Other_Lib", "3.0.0"),
    ]


def test_an_spdx_sbom_reads_the_package_url_of_each_package():
    data = spdx(sbom_component(PACKAGE, "2.3.0"), sbom_component("serde", "1.0.0", "cargo"))
    document = document_of(data)
    assert document["format"] == "spdx" and document["complete"] is True
    assert document["created"] == "2026-10-20T10:00:00Z"
    assert components_of(data) == [("npm", PACKAGE, "2.3.0"), ("crates.io", "serde", "1.0.0")]


def test_components_without_a_readable_package_url_are_counted_not_guessed():
    deb = {"type": "library", "name": "openssl", "purl": "pkg:deb/debian/openssl@3.0", "version": "3.0"}
    bare = {"type": "library", "name": "left-pad", "version": "1.3.0"}
    document = document_of(cyclonedx(sbom_component(PACKAGE, "2.3.0"), deb, bare))
    assert [item["name"] for item in document["components"]] == [PACKAGE]
    assert document["skipped"] == 2


@pytest.mark.parametrize(
    ("purl", "version", "expected"),
    [
        ("pkg:npm/lib@1.0.0", "1.0.0", "1.0.0"),
        ("pkg:npm/lib@1.0.0", None, "1.0.0"),
        ("pkg:npm/lib", "2.0.0", "2.0.0"),
        ("pkg:npm/lib", None, ""),
        ("pkg:npm/lib@1.0.0", "1.0.1", ""),  # the document disagrees with itself: nothing is confirmed
    ],
)
def test_the_version_comes_from_the_document_and_a_contradiction_leaves_it_unknown(purl, version, expected):
    entry = {"type": "library", "name": "lib", "purl": purl}
    if version:
        entry["version"] = version
    assert components_of(cyclonedx(entry)) == [("npm", "lib", expected)]


def test_an_sbom_with_no_usable_component_is_refused_not_stored_as_empty():
    for data in (cyclonedx(), cyclonedx({"name": "x", "purl": "pkg:deb/debian/x@1"}), spdx()):
        with pytest.raises(InventoryError, match="no component with a package URL"):
            document_of(data)


# --- scan results -------------------------------------------------------------------------------------


def test_an_osv_scanner_result_becomes_components_and_findings_with_normalised_ids():
    data = osv_scanner(
        scan_finding("npm", PACKAGE, "2.3.0", GHSA, aliases=("cve-2026-0001",), fixed="2.3.1", called=True),
        scan_finding("PyPI", "other-lib", "1.0", "PYSEC-2026-9"),
        scan_finding("Maven", "org.example:lib", "1.0", "GHSA-DDDD-EEEE-FFFF", fixed="1.0.1"),
    )
    document = document_of(data, "scan.json")
    assert document["format"] == "osv-scanner"
    assert document["complete"] is False, "a scan lists the packages it found something in, not every package"
    assert document["findings"] == [
        {
            "ids": ["GHSA-aaaa-bbbb-cccc", "CVE-2026-0001"],
            "ecosystem": "npm",
            "name": PACKAGE,
            "version": "2.3.0",
            "fixed": "2.3.1",
            "called": True,
        },
        {
            "ids": ["PYSEC-2026-9"],
            "ecosystem": "PyPI",
            "name": "other-lib",
            "version": "1.0",
            "fixed": "",
            "called": None,
        },
        {
            "ids": ["GHSA-dddd-eeee-ffff"],
            "ecosystem": "Maven",
            "name": "org.example:lib",
            "version": "1.0",
            "fixed": "1.0.1",
            "called": None,
        },
    ]
    assert [(item["ecosystem"], item["name"]) for item in document["components"]] == [
        ("npm", PACKAGE),
        ("PyPI", "other-lib"),
        ("Maven", "org.example:lib"),
    ]


@pytest.mark.parametrize(
    ("verdicts", "merged"),
    [
        ((False, False), False),
        ((False, True), True),
        ((True, False), True),
        ((None, True), True),
        ((False, None), None),
        ((None, False), None),
        ((None, None), None),
    ],
)
def test_one_finding_seen_twice_in_a_scan_keeps_reachability_honest(verdicts, merged):
    data = osv_scanner(*(scan_finding("npm", PACKAGE, "2.3.0", GHSA, called=called) for called in verdicts))
    document = document_of(data)
    assert len(document["findings"]) == 1 and len(document["components"]) == 1
    assert document["findings"][0]["called"] is merged


@pytest.mark.parametrize("key", ["experimentalAnalysis", "experimental_analysis"])
@pytest.mark.parametrize("called", [True, False])
def test_call_analysis_is_read_under_either_spelling_of_its_member(key, called):
    data = osv_scanner(scan_finding("npm", PACKAGE, "2.3.0", GHSA, called=called, analysis_key=key))
    assert document_of(data)["findings"][0]["called"] is called


def test_a_group_carrying_both_spellings_is_read_as_one_analysis():
    entry = scan_finding("npm", PACKAGE, "2.3.0", GHSA, called=False)
    entry["groups"][0]["experimental_analysis"] = {GHSA: {"called": True}}
    assert document_of(osv_scanner(entry))["findings"][0]["called"] is True


def test_call_analysis_that_names_another_vulnerability_says_nothing_about_this_finding():
    entry = scan_finding("npm", PACKAGE, "2.3.0", GHSA)
    entry["groups"][0]["experimentalAnalysis"] = {"GHSA-DDDD-EEEE-FFFF": {"called": True}}
    assert document_of(osv_scanner(entry))["findings"][0]["called"] is None


@pytest.mark.parametrize("key", ["experimentalAnalysis", "experimental_analysis"])
def test_a_call_analysis_member_that_is_not_an_object_refuses_the_import(key):
    entry = scan_finding("npm", PACKAGE, "2.3.0", GHSA)
    entry["groups"][0][key] = ["called"]
    with pytest.raises(InventoryError, match=rf"groups\[\]\.{key} must be an object"):
        document_of(osv_scanner(entry))


@pytest.mark.parametrize(
    "detail", [None, True, 1, "called", [], {}, {"called": None}, {"called": "yes"}, {"called": 1}]
)
def test_a_call_analysis_entry_that_does_not_say_true_or_false_reads_as_no_analysis(detail):
    """Documented in ``docs/inventory.md``: an entry that is not a verdict decorates nothing and refuses nothing."""
    entry = scan_finding("npm", PACKAGE, "2.3.0", GHSA)
    entry["groups"][0]["experimentalAnalysis"] = {GHSA: detail}
    assert document_of(osv_scanner(entry))["findings"][0]["called"] is None


def test_a_scan_with_no_findings_is_a_valid_import_that_confirms_nothing():
    document = document_of(json.dumps({"results": []}).encode())
    assert (document["format"], document["components"], document["findings"], document["complete"]) == (
        "osv-scanner",
        [],
        [],
        False,
    )


# --- limits and refusals ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "the file is empty"),
        (b"{not json", "not UTF-8 JSON"),
        (b"\xff\xfe\x00", "not UTF-8 JSON"),
        (b"[]", "top level"),
        (b'"text"', "top level"),
        (b"{" * 20000, "not UTF-8 JSON"),  # nesting deep enough to exhaust the parser's recursion limit
        (json.dumps({"hello": "world"}).encode(), "not an OSV-Scanner result"),
        (json.dumps({"spdxVersion": "SPDX-3.0", "packages": []}).encode(), "only SPDX 2.x"),
        (json.dumps({"bomFormat": "CycloneDX", "components": []}).encode(), "specVersion must be a string"),
        (
            json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": {}}).encode(),
            "components must be a list",
        ),
        (
            json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": ["x"]}).encode(),
            "must be an object",
        ),
        (
            json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"purl": 5}]}).encode(),
            "purl must be",
        ),
        (json.dumps({"results": {}}).encode(), "results must be a list"),
        (json.dumps({"results": [{"packages": [{"package": {"name": "x"}}]}]}).encode(), "ecosystem must be a string"),
    ],
)
def test_a_document_that_is_not_one_of_the_supported_formats_is_refused_whole(data, message):
    with pytest.raises(InventoryError, match=message):
        document_of(data)


def test_a_file_over_the_size_limit_is_refused_before_it_is_parsed():
    with pytest.raises(InventoryError, match="larger than 8 MiB"):
        document_of(b" " * (inventory.MAX_INVENTORY_BYTES + 1))


def test_an_unknown_origin_is_a_programming_error_not_a_refusal():
    with pytest.raises(ValueError, match="origin"):
        parse(cyclonedx(sbom_component(PACKAGE, "1.0.0")), name="x.json", now=NOW, origin="email")


def test_the_component_count_is_bounded_in_every_format_and_nothing_is_truncated(monkeypatch):
    monkeypatch.setattr(inventory, "MAX_ENTRIES", 3)
    many = [sbom_component(f"lib-{number}", "1.0.0") for number in range(4)]
    for data in (cyclonedx(*many), spdx(*many)):
        with pytest.raises(InventoryError, match="more than 3"):
            document_of(data)
    scan = osv_scanner(
        *(scan_finding("npm", f"lib-{number}", "1.0.0", f"GHSA-AAAA-BBBB-{number:04d}") for number in range(4))
    )
    with pytest.raises(InventoryError, match="more than 3"):
        document_of(scan)
    assert len(document_of(cyclonedx(*many[:3]))["components"]) == 3


def test_components_that_are_skipped_still_count_towards_the_bound(monkeypatch):
    monkeypatch.setattr(inventory, "MAX_ENTRIES", 3)
    skipped = [{"name": f"os-{number}", "purl": f"pkg:deb/debian/os-{number}@1"} for number in range(4)]
    with pytest.raises(InventoryError, match="more than 3 components"):
        document_of(cyclonedx(*skipped))


def test_nested_components_are_followed_to_a_fixed_depth_and_no_deeper():
    def chain(levels: int) -> bytes:
        node = sbom_component("leaf", "1.0.0")
        for number in range(levels - 1):
            node = {**sbom_component(f"level-{number}", "1.0.0"), "components": [node]}
        return cyclonedx(node)

    assert len(document_of(chain(inventory.MAX_DEPTH))["components"]) == inventory.MAX_DEPTH
    with pytest.raises(InventoryError, match="nested deeper than 12 levels"):
        document_of(chain(inventory.MAX_DEPTH + 1))


def test_an_alias_list_and_a_field_over_its_limit_are_refused():
    finding = scan_finding("npm", PACKAGE, "2.3.0", GHSA, aliases=tuple(f"CVE-2026-{n:04d}" for n in range(40)))
    with pytest.raises(InventoryError, match="more than 32 identifiers"):
        document_of(osv_scanner(finding))
    long_version = {"type": "library", "name": "x", "purl": "pkg:npm/x", "version": "1" * 500}
    with pytest.raises(InventoryError, match="version is longer than 128"):
        document_of(cyclonedx(long_version))


def test_a_refusal_names_the_limit_or_field_and_never_echoes_the_offending_value():
    secret = "hunter2-<b>value</b>"
    hostile = [
        json.dumps({"bomFormat": "CycloneDX", "specVersion": secret, "components": []}),
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": secret}),
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"purl": [secret]}]}),
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [secret]}),
        json.dumps({"spdxVersion": secret, "packages": []}),
        json.dumps({"results": [{"packages": [{"package": {"ecosystem": secret * 20, "name": "x"}}]}]}),
        json.dumps({"results": secret}),
        json.dumps({secret: secret}),
    ]
    for text in hostile:
        with pytest.raises(InventoryError) as raised:
            document_of(text.encode())
        assert secret not in str(raised.value), text


# --- no member of a file can fail an import any way but a refusal --------------------------------------

#: Stands in for a member that is removed rather than replaced.
MISSING = object()
#: Values of the wrong type or size for almost any member of a document.
JUNK = [None, True, False, 0, 1, -1, 1.5, 2**70, "", "text", [], {}, [1], {"key": 1}, ["text"], [[]], [{}]]
#: The same without ``null`` and the lists: a list-typed member reads ``null`` as "none" and a list as its items.
NOT_A_LIST = [True, False, 0, 1, -1, 1.5, 2**70, "", "text", {}, {"key": 1}]
AT_PACKAGE = ("results", 0, "packages", 0)
AT_RECORD = (*AT_PACKAGE, "vulnerabilities", 0)


def full_documents() -> dict[str, bytes]:
    """One valid document per format that carries every member a reader looks at, so each can be damaged in turn."""
    parent = sbom_component("parent-lib", "1.0.0")
    parent["components"] = [sbom_component("child-lib", "2.0.0")]
    return {
        "cyclonedx": cyclonedx(parent, sbom_component("Other_Lib", "3.0.0", "pypi")),
        "spdx": spdx(sbom_component(PACKAGE, "2.3.0"), sbom_component("serde", "1.0.0", "cargo")),
        "osv-scanner": osv_scanner(
            scan_finding("npm", PACKAGE, "2.3.0", GHSA, aliases=("CVE-2026-0001",), fixed="2.3.1", called=True),
            scan_finding(
                "PyPI",
                "other-lib",
                "1.0",
                "PYSEC-2026-9",
                fixed="1.1",
                called=False,
                analysis_key="experimental_analysis",
            ),
        ),
    }


def positions(node, path=()):
    """Every position in a JSON tree, as the keys and indexes that lead to it; the root comes first."""
    yield path
    if isinstance(node, dict):
        children = node.items()
    elif isinstance(node, list):
        children = enumerate(node)
    else:
        return
    for step, child in children:
        yield from positions(child, (*path, step))


def with_value(tree, path, value):
    """A copy of ``tree`` with the position ``path`` set to ``value``, or removed when ``value`` is ``MISSING``."""
    if not path:
        return value
    clone = copy.deepcopy(tree)
    holder = clone
    for step in path[:-1]:
        holder = holder[step]
    if value is MISSING:
        del holder[path[-1]]
    else:
        holder[path[-1]] = value
    return clone


def mutants(tree):
    """``(path, value, mutant)`` for every single-member change of ``tree``: each position takes each junk value."""
    for path in positions(tree):
        for value in (*JUNK, MISSING):
            if path or value is not MISSING:
                yield path, "<removed>" if value is MISSING else value, with_value(tree, path, value)


def escape_of(data: bytes) -> str | None:
    """How the importer failed to handle ``data`` by itself, or ``None`` when it did.

    By itself means: the file was imported, or refused by a check of its own, an ``InventoryError`` with no cause.
    One that carries a cause was raised by the safety net around the readers, so a reader let something through
    that it should have checked. An import the loader would then refuse is a failure too.
    """
    try:
        document = parse(data, name="mutant.json", now=NOW, origin="upload")
    except InventoryError as refused:
        return None if refused.__cause__ is None else f"the safety net caught a {type(refused.__cause__).__name__}"
    except Exception as escaped:
        return f"{type(escaped).__name__} escaped"
    try:
        Inventory(document)
    except Exception as unreadable:
        return f"imported a document that its own loader refuses ({type(unreadable).__name__})"
    return None


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx", "osv-scanner"])
def test_no_single_member_of_any_format_can_get_past_the_checks_of_its_reader(fmt):
    data = full_documents()[fmt]
    assert document_of(data)["format"] == fmt, "the sweep starts from a valid document"
    checked, failures = 0, []
    for path, value, mutant in mutants(json.loads(data)):
        checked += 1
        found = escape_of(json.dumps(mutant).encode())
        if found:
            failures.append((path, value, found))
    assert checked > 300, "the sweep must reach the members of the document"
    assert not failures, failures


_RANGE = (*AT_RECORD, "affected", 0, "ranges", 0)
SCAN_LISTS = [
    pytest.param(("results",), r"^results must be a list", id="results"),
    pytest.param(("results", 0, "packages"), r"^results\[\]\.packages must be a list", id="packages"),
    pytest.param((*AT_PACKAGE, "groups"), r"^results\[\]\.packages\[\]\.groups must be a list", id="groups"),
    pytest.param((*AT_PACKAGE, "vulnerabilities"), r"vulnerabilities must be a list", id="vulnerabilities"),
    pytest.param((*AT_RECORD, "aliases"), r"vulnerabilities\[\]\.aliases must be a list", id="aliases"),
    # The embedded OSV record only decorates a finding with the version that fixes it. A part of it that cannot be
    # read leaves the finding without a fix; it never refuses a scan whose packages and identifiers are sound.
    pytest.param((*AT_RECORD, "affected"), None, id="affected"),
    pytest.param((*AT_RECORD, "affected", 0, "ranges"), None, id="ranges"),
    pytest.param((*_RANGE, "events"), None, id="events"),
]


@pytest.mark.parametrize("junk", NOT_A_LIST, ids=repr)
@pytest.mark.parametrize(("path", "message"), SCAN_LISTS)
def test_a_list_member_of_a_scan_that_is_not_a_list_is_refused_by_name_or_read_as_absent_by_design(path, message, junk):
    data = json.dumps(with_value(json.loads(full_documents()["osv-scanner"]), path, junk)).encode()
    if message is None:
        assert document_of(data)["format"] == "osv-scanner"
        return
    with pytest.raises(InventoryError, match=message) as refused:
        document_of(data)
    assert refused.value.__cause__ is None, "refused by the check of the reader itself, not by the safety net"


@pytest.mark.parametrize("junk", [*JUNK, *({"type": "SEMVER"}, [{"type": "SEMVER"}, 5])], ids=repr)
def test_a_record_in_a_scan_whose_ranges_cannot_be_read_imports_and_names_no_fix(junk):
    """Reproduces the reported fault: ``ranges`` of ``true``, ``1`` or ``1.5`` raised a TypeError out of the import."""
    document = document_of(scan_with_ranges(junk))
    assert [(item["ids"], item["version"], item["fixed"]) for item in document["findings"]] == [
        (["GHSA-aaaa-bbbb-cccc"], "2.3.0", "")
    ]
    assert document["findings"][0]["called"] is None and len(document["components"]) == 1


def test_readable_ranges_still_name_the_fix():
    """The counterpart of the test above: reading ranges only when they are a list must not stop reading them."""
    assert (
        document_of(scan_with_ranges([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.3.1"}]}]))[
            "findings"
        ][0]["fixed"]
        == "2.3.1"
    )


@pytest.mark.parametrize(
    ("reader", "data"),
    [
        pytest.param("_cyclonedx", cyclonedx(sbom_component(PACKAGE, "1.0.0")), id="cyclonedx"),
        pytest.param("_spdx", spdx(sbom_component(PACKAGE, "1.0.0")), id="spdx"),
        pytest.param("_osv_scanner", osv_scanner(scan_finding("npm", PACKAGE, "1.0.0", GHSA)), id="osv-scanner"),
    ],
)
def test_a_fault_no_check_foresaw_refuses_the_file_and_names_only_the_kind_of_error(monkeypatch, reader, data):
    """The import is optional evidence: whatever a reader does wrong, it refuses one file and nothing else."""

    def broken(document):
        raise RuntimeError("secret-<b>value</b>")

    monkeypatch.setattr(inventory, reader, broken)
    with pytest.raises(InventoryError, match=r"^the file could not be processed: unexpected RuntimeError$") as refused:
        document_of(data)
    assert "secret" not in str(refused.value)
    assert isinstance(refused.value.__cause__, RuntimeError), "the original fault stays attached for a developer"


def test_a_request_to_stop_is_not_taken_for_a_fault_in_a_reader(monkeypatch):
    def interrupted(document):
        raise KeyboardInterrupt

    monkeypatch.setattr(inventory, "_cyclonedx", interrupted)
    with pytest.raises(KeyboardInterrupt):
        document_of(cyclonedx(sbom_component(PACKAGE, "1.0.0")))


# --- the stored document ------------------------------------------------------------------------------


def stored_document() -> dict:
    return document_of(
        cyclonedx(sbom_component(PACKAGE, "2.3.0"), sbom_component("Foo_Bar", "1.0.0", "pypi")), "a.json"
    )


def test_a_stored_inventory_round_trips_and_is_private(tmp_path):
    path = tmp_path / inventory.INVENTORY_NAME
    assert inventory.load(path) is None
    document = stored_document()
    inventory.save(path, document)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    loaded = inventory.load(path)
    assert loaded is not None
    assert (loaded.format, loaded.name, loaded.sha256, loaded.origin) == (
        "cyclonedx",
        "a.json",
        document["sha256"],
        "upload",
    )
    assert (loaded.imported_at, loaded.size, loaded.skipped, loaded.complete) == (NOW, document["size"], 0, True)
    assert loaded.components == document["components"]
    assert inventory.inventory_path(tmp_path / "state.json") == tmp_path / inventory.INVENTORY_NAME


def damaged(**changes: object) -> bytes:
    return json.dumps({**stored_document(), **changes}).encode()


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"{", "not valid JSON"),
        (b"[]", "not a document this version wrote"),
        (b'{"schema": "advisory-radar-inventory.v0"}', "not a document this version wrote"),
        (b"\xff\xfe", "cannot be read"),
        (damaged(format="docx"), "unknown format or origin"),
        (damaged(origin="email"), "unknown format or origin"),
        (damaged(imported_at="yesterday"), "malformed number"),
        (damaged(size=True), "malformed number"),
        (damaged(skipped=-1), "malformed number"),
        (damaged(complete="yes"), "malformed flag"),
        (damaged(components={}), "components must be a list"),
        (damaged(components=[{"ecosystem": "npm"}]), "name must be a string"),
        (damaged(components=["x"]), "must be an object"),
        (
            damaged(findings=[{"ecosystem": "npm", "name": "x", "version": "1", "fixed": "", "ids": "GHSA-x"}]),
            "ids must be",
        ),
        (
            damaged(
                findings=[{"ecosystem": "npm", "name": "x", "version": "1", "fixed": "", "ids": [], "called": "yes"}]
            ),
            "called",
        ),
    ],
)
def test_a_damaged_stored_inventory_is_an_error_never_an_empty_inventory(tmp_path, content, message):
    path = tmp_path / inventory.INVENTORY_NAME
    path.write_bytes(content)
    with pytest.raises(InventoryError, match=message):
        inventory.load(path)


def test_an_inventory_path_that_is_not_a_file_is_unreadable_not_absent(tmp_path):
    (tmp_path / inventory.INVENTORY_NAME).mkdir()
    with pytest.raises(InventoryError, match="cannot be read"):
        inventory.load(tmp_path / inventory.INVENTORY_NAME)


def exercised(stored: Inventory) -> None:
    """Everything the judge and the pages ask of a stored inventory, for everything it lists."""
    state = core.new_state()
    applicability.record_facts(state, {GHSA: osv_facts(AFFECTED_NPM, "CVE-2026-0001")}, NOW)
    ids = [identifier for finding in stored.findings for identifier in finding["ids"]]
    for component in stored.components:
        stored.versions_of(component["ecosystem"], component["name"])
    stored.findings_for(ids)
    applicability.evidence_for(state, stored, [GHSA, "CVE-2026-0001", *ids], NOW, 30)


@pytest.mark.parametrize("fmt", ["cyclonedx", "osv-scanner"])
def test_no_single_member_of_a_stored_inventory_can_get_past_the_checks_of_the_loader(fmt):
    """A stored document that loads must also be one the judge and the pages can use: they index its members."""
    base = document_of(full_documents()[fmt])
    exercised(Inventory(base))  # the sweep starts from a document that works
    checked, failures = 0, []
    for path, value, mutant in mutants(base):
        checked += 1
        try:
            exercised(Inventory(mutant))
        except InventoryError:
            continue  # a damaged document refused by the loader's own check is the intended outcome
        except Exception as escaped:
            failures.append((path, value, type(escaped).__name__))
    assert checked > 100, "the sweep must reach the members of the document"
    assert not failures, failures


def test_a_stored_inventory_that_fails_unexpectedly_is_damaged_never_a_crash(tmp_path, monkeypatch, caplog):
    state_path = tmp_path / "state.json"
    path = inventory.inventory_path(state_path)
    inventory.save(path, stored_document())

    def broken(document):
        raise RuntimeError("secret-<b>value</b>")

    monkeypatch.setattr(inventory, "Inventory", broken)
    with pytest.raises(InventoryError, match=r"^the stored inventory is damaged: unexpected RuntimeError$") as damaged:
        inventory.load(path)
    assert "secret" not in str(damaged.value) and isinstance(damaged.value.__cause__, RuntimeError)
    with caplog.at_level(logging.WARNING, logger="advisory_radar"):
        assert inventory.refresh(state_path, None, {}, NOW) is None
    assert "unexpected RuntimeError" in caplog.text and "secret" not in caplog.text


def test_lookups_use_each_ecosystems_own_name_rules_and_one_finding_is_returned_once():
    data = osv_scanner(scan_finding("PyPI", "Foo_Bar", "1.0", GHSA, aliases=("CVE-2026-0001",)))
    stored = Inventory(document_of(data))
    assert stored.versions_of("PyPI", "foo.bar") == ["1.0"]
    assert stored.versions_of("PyPI", "other") == []
    assert stored.versions_of("npm", "foo-bar") == []
    assert len(stored.findings_for(["ghsa-AAAA-bbbb-CCCC", "cve-2026-0001"])) == 1
    assert stored.findings_for(["CVE-2099-0000"]) == []


def test_every_installed_version_of_a_package_is_listed_once():
    stored = Inventory(
        document_of(
            cyclonedx(
                sbom_component(PACKAGE, "1.0.0"), sbom_component(PACKAGE, "2.0.0"), sbom_component(PACKAGE, "1.0.0")
            )
        )
    )
    assert stored.versions_of("npm", PACKAGE) == ["1.0.0", "2.0.0"]


# --- the drop directory -------------------------------------------------------------------------------


def drop(directory, name: str, data: bytes, *, at: int | None = None) -> None:
    path = directory / name
    path.write_bytes(data)
    if at is not None:
        os.utime(path, (at, at))


def test_the_newest_drop_file_is_imported_and_remembered_by_its_own_digest(tmp_path):
    directory, path, state = tmp_path / "drop", tmp_path / inventory.INVENTORY_NAME, {}
    directory.mkdir()
    drop(directory, "old.json", cyclonedx(sbom_component("old-lib", "1.0.0")), at=1_000)
    drop(directory, "new.json", cyclonedx(sbom_component("new-lib", "1.0.0")), at=2_000)
    inventory.pick_up(directory, state, path, NOW)
    assert state["inventory_drop"]["outcome"] == "imported" and state["inventory_drop"]["name"] == "new.json"
    loaded = inventory.load(path)
    assert loaded is not None and (loaded.name, loaded.origin, loaded.imported_at) == ("new.json", "drop", NOW)
    inventory.pick_up(directory, state, path, NOW + 100)  # the same file again: nothing to do
    assert state["inventory_drop"]["at"] == NOW
    assert inventory.load(path).imported_at == NOW


def test_a_drop_file_that_parses_but_cannot_be_stored_is_tried_again_on_the_next_pass(tmp_path, monkeypatch):
    directory, path, state = tmp_path / "drop", tmp_path / inventory.INVENTORY_NAME, {}
    directory.mkdir()
    drop(directory, "sbom.json", cyclonedx(sbom_component(PACKAGE, "1.0.0")))
    real_save = inventory.save

    def full_disk(target, document):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(inventory, "save", full_disk)
    inventory.pick_up(directory, state, path, NOW)
    assert "inventory_drop" not in state and not path.exists()
    monkeypatch.setattr(inventory, "save", real_save)
    inventory.pick_up(directory, state, path, NOW + 60)
    assert state["inventory_drop"]["outcome"] == "imported"
    assert inventory.load(path).imported_at == NOW + 60


def test_a_refused_drop_file_is_logged_once_keeps_the_stored_inventory_and_is_retried_when_it_changes(tmp_path, caplog):
    directory, path, state = tmp_path / "drop", tmp_path / inventory.INVENTORY_NAME, {}
    directory.mkdir()
    inventory.save(path, stored_document())
    drop(directory, "bad.json", b'{"hello": "world"}')
    with caplog.at_level(logging.WARNING, logger="advisory_radar"):
        inventory.pick_up(directory, state, path, NOW)
        inventory.pick_up(directory, state, path, NOW + 60)
    refusals = [record for record in caplog.records if "was refused" in record.getMessage()]
    assert len(refusals) == 1 and "bad.json" in refusals[0].getMessage()
    assert (
        state["inventory_drop"]["outcome"] == "refused"
        and "not an OSV-Scanner result" in state["inventory_drop"]["error"]
    )
    assert inventory.load(path).name == "a.json"
    drop(directory, "bad.json", cyclonedx(sbom_component(PACKAGE, "1.0.0")))
    inventory.pick_up(directory, state, path, NOW + 120)
    assert state["inventory_drop"]["outcome"] == "imported" and inventory.load(path).name == "bad.json"


def test_a_drop_file_that_trips_a_reader_is_refused_once_and_the_stored_inventory_stays(tmp_path, monkeypatch, caplog):
    directory, path, state = tmp_path / "drop", tmp_path / inventory.INVENTORY_NAME, {}
    directory.mkdir()
    inventory.save(path, stored_document())
    kept = path.read_bytes()
    drop(directory, "scan.json", osv_scanner(scan_finding("npm", PACKAGE, "2.3.0", GHSA)))

    def broken(document):
        raise RuntimeError("secret-<b>value</b>")

    monkeypatch.setattr(inventory, "_osv_scanner", broken)
    with caplog.at_level(logging.WARNING, logger="advisory_radar"):
        inventory.pick_up(directory, state, path, NOW)
        inventory.pick_up(directory, state, path, NOW + 60)  # the same file: remembered by its digest, said once
    assert path.read_bytes() == kept
    look = state["inventory_drop"]
    assert (look["outcome"], look["error"]) == ("refused", "the file could not be processed: unexpected RuntimeError")
    refusals = [record for record in caplog.records if "was refused" in record.getMessage()]
    assert len(refusals) == 1 and "scan.json" in refusals[0].getMessage() and "secret" not in caplog.text


def test_a_link_swapped_in_after_the_directory_was_listed_is_not_followed(tmp_path, monkeypatch):
    directory, path, state = tmp_path / "drop", tmp_path / inventory.INVENTORY_NAME, {}
    directory.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(cyclonedx(sbom_component(PACKAGE, "1.0.0")))
    link = directory / "late.json"
    link.symlink_to(outside)
    monkeypatch.setattr(inventory, "_newest_file", lambda listed: ("late.json", os.lstat(link)))
    inventory.pick_up(directory, state, path, NOW)
    assert state["inventory_drop"]["outcome"] == "refused" and not path.exists()


def test_a_missing_or_empty_drop_directory_changes_nothing(tmp_path):
    path, state = tmp_path / inventory.INVENTORY_NAME, {}
    inventory.pick_up(tmp_path / "absent", state, path, NOW)
    (tmp_path / "empty").mkdir()
    inventory.pick_up(tmp_path / "empty", state, path, NOW)
    assert state == {} and not path.exists()


def test_refresh_returns_the_stored_inventory_and_says_nothing_of_a_damaged_one(tmp_path, caplog):
    state_path = tmp_path / "state.json"
    path = inventory.inventory_path(state_path)
    assert inventory.refresh(state_path, None, {}, NOW) is None
    inventory.save(path, stored_document())
    assert inventory.refresh(state_path, None, {}, NOW).name == "a.json"
    path.write_bytes(b"{")
    with caplog.at_level(logging.WARNING, logger="advisory_radar"):
        assert inventory.refresh(state_path, None, {}, NOW) is None
    assert "no applicability evidence is recorded" in caplog.text
