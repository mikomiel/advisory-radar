"""CSAF 2.0 documents and the directory index: schema, identity, revision, product mapping and failures.

The fixtures are synthetic and small. They follow the layout of the first provider's directory (a quoted
two-column ``changes.csv``, year folders, ``default_component_of`` relationships) without copying a real
document, and the vendor is a made-up one on an ``example.net`` host.
"""

from __future__ import annotations

import hashlib
import json
import socket
import time
from datetime import datetime

import pytest

from advisory_radar import csaf

PUBLISHER = "Example Vendor PSIRT"
#: The instant the index tests pretend to read at: every fixture date is before it.
NOW = datetime.fromisoformat("2026-11-19T00:00:00Z").timestamp()


def epoch(stamp: str) -> int:
    return int(datetime.fromisoformat(stamp).timestamp())


def product_tree() -> dict:
    """Three products, one component and the relationship that makes the component a part of Widget 2.0."""

    def product(name: str, product_id: str, category: str = "product_name", **extra: object) -> dict:
        return {"category": category, "name": name, "product": {"name": name, "product_id": product_id, **extra}}

    return {
        "branches": [
            {
                "category": "vendor",
                "name": "Example",
                "branches": [
                    product("Widget 2.0", "WIDGET-2"),
                    product(
                        "Gizmo 1.0",
                        "GIZMO-1",
                        product_identification_helper={"cpe": "cpe:/a:example:gizmo:1.0"},
                    ),
                    product("Doohickey 3", "DOOHICKEY-3"),
                    product("widget-lib-1.2-1.noarch", "widget-lib-1.2", "product_version"),
                ],
            }
        ],
        "relationships": [
            {
                "category": "default_component_of",
                "full_product_name": {
                    "name": "widget-lib-1.2-1.noarch as a component of Widget 2.0",
                    "product_id": "WIDGET-2:widget-lib-1.2",
                },
                "product_reference": "widget-lib-1.2",
                "relates_to_product_reference": "WIDGET-2",
            }
        ],
    }


def vulnerability(cve: str, **statuses: list[str]) -> dict:
    return {"cve": cve, "product_status": dict(statuses)}


def advisory(
    ident: str = "EXAMPLE-2026:0001",
    *,
    version: str = "1",
    released: str = "2026-03-10T10:00:00Z",
    category: str = "csaf_security_advisory",
    vulnerabilities: list[dict] | None = None,
    title: str = "Example Vendor Security Advisory: widget update",
    url: str | None = None,
) -> dict:
    """A document that is valid under the CSAF 2.0 schema; a test breaks the one thing it is about."""
    document = {
        "category": category,
        "csaf_version": "2.0",
        "publisher": {"category": "vendor", "name": PUBLISHER, "namespace": "https://vendor.example.net"},
        "title": title,
        "tracking": {
            "current_release_date": released,
            "id": ident,
            "initial_release_date": "2026-03-01T10:00:00Z",
            "revision_history": [{"date": released, "number": version, "summary": "Revision"}],
            "status": "final",
            "version": version,
        },
    }
    if url:
        document["references"] = [{"category": "self", "summary": "Canonical URL", "url": url}]
    if vulnerabilities is None:
        vulnerabilities = [
            vulnerability("CVE-2026-0001", fixed=["WIDGET-2:widget-lib-1.2"], known_not_affected=["GIZMO-1"])
        ]
    return {"document": document, "product_tree": product_tree(), "vulnerabilities": vulnerabilities}


def body(document: object) -> bytes:
    return json.dumps(document).encode()


def index(*rows: tuple[str, str]) -> bytes:
    """A changes.csv as the first provider writes it: both fields quoted, newest first."""
    return "".join(f'"{path}","{stamp}"\n' for path, stamp in rows).encode()


def redhat_style(
    document: dict, *, initial: str, updated: str, generated: str, middle: str = "Last updated version"
) -> dict:
    """Rewrite the tracking block the way the first provider writes every document, whatever its age.

    Checked on 2026-11-19 against the provider's own documents: the version is always ``3``, the history always has
    three entries, and the last of them (``Last generated version``), ``current_release_date`` and the generator
    date are all the instant the document was regenerated, which says nothing about when its content last changed.
    The middle entry carries that: ``Last updated version`` in an advisory, ``Current version`` in a VEX.
    """
    document["document"]["tracking"].update(
        version="3",
        initial_release_date=initial,
        current_release_date=generated,
        generator={"date": generated, "engine": {"name": "Example Generator", "version": "1.0"}},
        revision_history=[
            {"date": initial, "number": "1", "summary": "Initial version"},
            {"date": updated, "number": "2", "summary": middle},
            {"date": generated, "number": "3", "summary": "Last generated version"},
        ],
    )
    return document


# --------------------------------------------------------------------------
# The vendored schema


SCHEMA_FILES = {
    "csaf_json_schema.json": (
        "29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262",
        "https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json",
    ),
    "cvss-v2.0.json": (
        "cd1a7c0815b7a47dc12fb7dded10622b96d562841f7bc6d2d8765c5d937a28f2",
        "https://www.first.org/cvss/cvss-v2.0.json",
    ),
    "cvss-v3.0.json": (
        "b2b587e5dfa6d9a4be89e25cb593df04f14e7ffbe8fe5b167ceee17b6097d919",
        "https://www.first.org/cvss/cvss-v3.0.json",
    ),
    "cvss-v3.1.json": (
        "77ff3df106e4588e2bb5c9cf0237f962c62d35c5002443c4bf7cc7ca16ee171f",
        "https://www.first.org/cvss/cvss-v3.1.json",
    ),
}


def test_the_vendored_schema_files_are_the_pinned_ones_and_their_notice_names_them():
    notice = (csaf.SCHEMA_DIR / "NOTICE.md").read_text(encoding="utf-8")
    for name, (digest, url) in SCHEMA_FILES.items():
        data = (csaf.SCHEMA_DIR / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest, f"{name} is not the pinned copy"
        assert digest in notice and url in notice, f"NOTICE.md must record the source and digest of {name}"
    assert "Copyright" in notice and "OASIS" in notice


def test_the_schema_validates_without_the_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the schema must be read from the package, never fetched")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    csaf.schema_validator.cache_clear()
    try:
        # The schema's CVSS references are resolved from the vendored copies, so a document with a score is the
        # proof that nothing was fetched.
        scored = advisory()
        scored["vulnerabilities"][0]["scores"] = [
            {
                "products": ["WIDGET-2"],
                "cvss_v3": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                },
            }
        ]
        assert csaf.parse_document(body(scored)).id == "EXAMPLE-2026:0001"
        scored["vulnerabilities"][0]["scores"][0]["cvss_v3"]["baseScore"] = 11.5
        with pytest.raises(csaf.DocumentRejected, match="schema"):
            csaf.parse_document(body(scored))
    finally:
        csaf.schema_validator.cache_clear()


# --------------------------------------------------------------------------
# Identity, revision and provenance


def test_a_valid_advisory_keeps_identity_revision_and_provenance():
    document = csaf.parse_document(
        body(
            advisory(
                "EXAMPLE-2026:0001",
                version="2",
                released="2026-03-10T10:00:00Z",
                url="https://vendor.example.net/advisories/EXAMPLE-2026-0001",
            )
        )
    )
    assert (document.id, document.version) == ("EXAMPLE-2026:0001", "2")
    assert document.release == epoch("2026-03-10T10:00:00Z")
    assert document.publisher == PUBLISHER
    assert document.category == "csaf_security_advisory"
    assert document.title == "Example Vendor Security Advisory: widget update"
    assert document.url == "https://vendor.example.net/advisories/EXAMPLE-2026-0001"


def test_a_semantic_version_is_kept_as_written():
    document = csaf.parse_document(body(advisory(version="1.2.3")))
    assert document.version == "1.2.3"


def test_a_self_reference_that_is_not_a_web_address_is_not_kept():
    document = csaf.parse_document(body(advisory(url="javascript:alert(1)")))
    assert document.url == ""


@pytest.mark.parametrize("middle", ["Last updated version", "Current version"], ids=["advisory", "vex"])
def test_a_regenerated_document_is_dated_by_its_content_and_not_by_its_regeneration(middle):
    document = redhat_style(
        advisory(category="csaf_vex" if middle == "Current version" else "csaf_security_advisory"),
        initial="2020-07-28T15:54:02+00:00",
        updated="2026-09-04T08:30:00+00:00",
        generated="2026-11-19T03:17:12+00:00",
        middle=middle,
    )
    parsed = csaf.parse_document(body(document))
    assert parsed.version == "3", "the vendor's own word, kept as written"
    assert parsed.release == epoch("2026-09-04T08:30:00Z"), "the date its statements last changed, not the regeneration"


def test_a_regenerated_document_that_was_never_updated_is_dated_by_its_first_release():
    document = redhat_style(
        advisory(),
        initial="2020-07-28T15:54:02+00:00",
        updated="2020-07-28T15:54:02+00:00",
        generated="2026-11-19T03:17:12+00:00",
    )
    assert csaf.parse_document(body(document)).release == epoch("2020-07-28T15:54:02Z")


def test_a_document_without_the_regeneration_entry_is_dated_by_its_release_date():
    # Only the first provider's marker entry is set aside. Another vendor's newest revision is the document's date.
    document = advisory(released="2026-03-10T10:00:00Z")
    document["document"]["tracking"]["revision_history"] = [
        {"date": "2026-03-01T10:00:00Z", "number": "1", "summary": "Initial version"},
        {"date": "2026-03-10T10:00:00Z", "number": "2", "summary": "Current version"},
    ]
    document["document"]["tracking"]["version"] = "2"
    assert csaf.parse_document(body(document)).release == epoch("2026-03-10T10:00:00Z")


def test_a_regenerated_document_with_a_revision_date_that_is_not_a_date_is_rejected():
    document = redhat_style(
        advisory(),
        initial="2020-07-28T15:54:02+00:00",
        updated="yesterday",
        generated="2026-11-19T03:17:12+00:00",
    )
    with pytest.raises(csaf.DocumentRejected, match="schema: .*revision_history.*date-time"):
        csaf.parse_document(body(document))


def test_the_revision_is_the_same_after_a_regeneration_and_changes_with_a_statement():
    old = {"initial": "2020-07-28T15:54:02+00:00", "updated": "2020-07-28T15:54:02+00:00"}
    first = csaf.parse_document(body(redhat_style(advisory(), generated="2026-11-18T03:00:00+00:00", **old)))
    regenerated = csaf.parse_document(body(redhat_style(advisory(), generated="2026-11-19T03:00:00+00:00", **old)))
    assert first.version == regenerated.version == "3", "the version never moves, so it cannot tell revisions apart"
    assert first.revision == regenerated.revision
    changed = csaf.parse_document(
        body(
            redhat_style(
                advisory(vulnerabilities=[vulnerability("CVE-2026-0001", known_affected=["WIDGET-2"])]),
                generated="2026-11-19T03:00:00+00:00",
                **old,
            )
        )
    )
    assert changed.revision != first.revision


def test_the_revision_does_not_depend_on_the_order_the_vendor_lists_things_in():
    forward = advisory(
        vulnerabilities=[
            vulnerability("CVE-2026-0001", fixed=["WIDGET-2", "GIZMO-1"]),
            vulnerability("CVE-2026-0002", known_affected=["DOOHICKEY-3"]),
        ]
    )
    backward = advisory(
        vulnerabilities=[
            vulnerability("CVE-2026-0002", known_affected=["DOOHICKEY-3"]),
            vulnerability("CVE-2026-0001", fixed=["GIZMO-1", "WIDGET-2"]),
        ]
    )
    assert csaf.parse_document(body(forward)).revision == csaf.parse_document(body(backward)).revision


# --------------------------------------------------------------------------
# Product mapping and the statements


def test_product_ids_resolve_through_branches_and_relationships():
    document = csaf.parse_document(
        body(
            advisory(
                vulnerabilities=[
                    vulnerability(
                        "CVE-2026-0001",
                        fixed=["WIDGET-2:widget-lib-1.2", "WIDGET-2"],
                        known_affected=["GIZMO-1"],
                    )
                ]
            )
        )
    )
    # A component is reported as the product it is a component of; both ids of Widget 2.0 are counted together.
    assert document.assertions == (
        csaf.Assertion("CVE-2026-0001", "known_affected", "Gizmo 1.0", 1),
        csaf.Assertion("CVE-2026-0001", "fixed", "Widget 2.0", 2),
    )


def test_a_vex_keeps_every_status_distinct():
    document = csaf.parse_document(
        body(
            advisory(
                category="csaf_vex",
                vulnerabilities=[
                    vulnerability(
                        "CVE-2026-0001",
                        known_not_affected=["DOOHICKEY-3"],
                        fixed=["GIZMO-1"],
                        under_investigation=["WIDGET-2"],
                        known_affected=["WIDGET-2:widget-lib-1.2"],
                    )
                ],
            )
        )
    )
    assert document.category == "csaf_vex"
    assert [(a.status, a.product) for a in document.assertions] == [
        ("known_affected", "Widget 2.0"),
        ("under_investigation", "Widget 2.0"),
        ("fixed", "Gizmo 1.0"),
        ("known_not_affected", "Doohickey 3"),
    ]


def test_not_affected_is_scoped_to_its_own_vulnerability_and_product():
    document = csaf.parse_document(
        body(
            advisory(
                vulnerabilities=[
                    vulnerability("CVE-2026-0001", known_not_affected=["GIZMO-1"]),
                    vulnerability("CVE-2026-0002", known_affected=["GIZMO-1"], known_not_affected=["WIDGET-2"]),
                ]
            )
        )
    )
    assert document.assertions == (
        csaf.Assertion("CVE-2026-0001", "known_not_affected", "Gizmo 1.0", 1),
        csaf.Assertion("CVE-2026-0002", "known_affected", "Gizmo 1.0", 1),
        csaf.Assertion("CVE-2026-0002", "known_not_affected", "Widget 2.0", 1),
    )
    # CVE-2026-0001 is not-affected for Gizmo; that says nothing about Gizmo and CVE-2026-0002.
    assert csaf.concerned_cves(document) == ("CVE-2026-0002",)


def test_a_document_with_only_not_affected_statements_concerns_no_vulnerability():
    document = csaf.parse_document(
        body(advisory(vulnerabilities=[vulnerability("CVE-2026-0001", known_not_affected=["GIZMO-1", "WIDGET-2"])]))
    )
    assert csaf.concerned_cves(document) == ()
    assert len(document.assertions) == 2


def test_a_vulnerability_without_a_cve_makes_no_statement():
    without_cve = {"ids": [{"system_name": "Vendor", "text": "V-1"}], "product_status": {"fixed": ["GIZMO-1"]}}
    document = csaf.parse_document(body(advisory(vulnerabilities=[without_cve])))
    assert document.assertions == ()


def test_not_affected_products_are_counted_and_never_named():
    document = csaf.parse_document(body(advisory()))
    # The sentence is language-neutral: a not-affected statement is a count, so it can never be read as naming a
    # product the watchlist should match.
    assert csaf.statements_text(document) == "CVE-2026-0001: fixed: Widget 2.0 (1); known_not_affected (1)"
    assert "Gizmo" not in csaf.statements_text(document)


def test_the_statement_text_is_bounded():
    tree = product_tree()
    names = [f"Product {number}" for number in range(300)]
    tree["branches"][0]["branches"] = [
        {"category": "product_name", "name": name, "product": {"name": name, "product_id": f"P{number}"}}
        for number, name in enumerate(names)
    ]
    del tree["relationships"]  # the schema refuses an empty list: no relationships is an absent key
    document = advisory(
        vulnerabilities=[vulnerability(f"CVE-2026-{1000 + number}", fixed=[f"P{number}"]) for number in range(300)]
    )
    document["product_tree"] = tree
    text = csaf.statements_text(csaf.parse_document(body(document)))
    assert len(text) <= csaf.MAX_STATEMENTS_CHARS
    assert text.endswith("...")
    assert text.startswith("CVE-2026-1000: fixed: Product 0 (1)")


# --------------------------------------------------------------------------
# A document that must not be used


def remove_title(document: dict) -> None:
    del document["document"]["title"]


def malformed_cve(document: dict) -> None:
    document["vulnerabilities"][0]["cve"] = "CVE-26-1"


def other_version(document: dict) -> None:
    document["document"]["csaf_version"] = "2.1"


def status_is_not_a_list(document: dict) -> None:
    document["vulnerabilities"][0]["product_status"]["fixed"] = "GIZMO-1"


def empty_status(document: dict) -> None:
    document["vulnerabilities"][0]["product_status"]["fixed"] = []


@pytest.mark.parametrize(
    ("break_it", "mentions"),
    [
        (remove_title, "title"),
        (malformed_cve, "CVE-26-1"),
        (other_version, "2.1"),
        (status_is_not_a_list, "array"),
        (empty_status, "non-empty"),
    ],
)
def test_a_document_that_breaks_the_schema_is_rejected_with_its_location(break_it, mentions):
    document = advisory()
    break_it(document)
    with pytest.raises(csaf.DocumentRejected) as rejected:
        csaf.parse_document(body(document))
    reason = str(rejected.value)
    assert reason.startswith("schema: ")
    assert mentions in reason
    assert len(reason) < 400


@pytest.mark.parametrize(
    "raw",
    [b"not json", b"[]", b'"text"', b"null", b"\xff\xfe\x00", b"[" * 5000 + b"]" * 5000, b""],
    ids=["text", "list", "string", "null", "not-utf8", "deeply-nested", "empty"],
)
def test_a_body_that_is_not_a_json_object_is_rejected(raw):
    with pytest.raises(csaf.DocumentRejected, match="JSON object"):
        csaf.parse_document(raw)


def test_a_profile_other_than_the_pinned_two_is_rejected():
    with pytest.raises(csaf.DocumentRejected, match="csaf_base.*profile|profile.*csaf_base"):
        csaf.parse_document(body(advisory(category="csaf_base")))


def test_a_product_id_the_document_never_defines_is_rejected():
    with pytest.raises(csaf.DocumentRejected, match="NOPE.*not defined"):
        csaf.parse_document(body(advisory(vulnerabilities=[vulnerability("CVE-2026-0001", fixed=["NOPE"])])))


def test_a_relationship_that_points_at_an_undefined_product_is_rejected():
    document = advisory()
    document["product_tree"]["relationships"][0]["relates_to_product_reference"] = "MISSING-9"
    with pytest.raises(csaf.DocumentRejected, match="MISSING-9.*not defined"):
        csaf.parse_document(body(document))


def test_one_product_id_defined_with_two_names_is_rejected():
    document = advisory()
    document["product_tree"]["branches"][0]["branches"].append(
        {"category": "product_name", "name": "Impostor", "product": {"name": "Impostor", "product_id": "WIDGET-2"}}
    )
    with pytest.raises(csaf.DocumentRejected, match="WIDGET-2.*twice"):
        csaf.parse_document(body(document))


def test_one_product_defined_twice_with_one_name_is_accepted():
    # A real Red Hat VEX document repeats an identical definition for 32 of its 1,882 product ids. The id still names
    # one product, so refusing the document would lose real statements for nothing.
    document = advisory()
    branches = document["product_tree"]["branches"][0]["branches"]
    branches.append(dict(branches[0]))
    assert csaf.parse_document(body(document)).assertions == csaf.parse_document(body(advisory())).assertions


def test_a_relationship_product_defined_a_second_time_is_rejected_even_with_one_name():
    # A component's id also says which product it belongs to, so unlike a plain repeat it must be defined once.
    document = advisory()
    component = document["product_tree"]["relationships"][0]["full_product_name"]
    component.update(product_id="GIZMO-1", name="Gizmo 1.0")  # the id and the name of a product in the branches
    with pytest.raises(csaf.DocumentRejected, match="GIZMO-1.*twice"):
        csaf.parse_document(body(document))


def test_a_document_larger_than_the_cap_is_rejected_unparsed(monkeypatch):
    monkeypatch.setattr(csaf, "MAX_DOCUMENT_BYTES", 100)
    with pytest.raises(csaf.DocumentRejected, match="larger than"):
        csaf.parse_document(body(advisory()))


# --------------------------------------------------------------------------
# The work a document costs is bounded by its size
#
# The size cap bounds the download and the parse, not the schema check. The schema asks for unique elements in
# several arrays, and a library that compares objects pairwise takes a time that grows with the square of the
# array: a document far below the cap held a few thousand distinct ids and kept one pass busy for minutes. The check
# is linear, so the time is what the size cap implies and no other limit on array lengths is needed (real documents
# list hundreds of product ids per status and a thousand relationships).


def with_ids(count: int) -> dict:
    document = advisory()
    ids = [{"system_name": "Vendor", "text": f"V-{number}"} for number in range(count)]
    document["vulnerabilities"][0]["ids"] = ids
    return document


def timed(raw: bytes) -> tuple[float, str]:
    started = time.perf_counter()
    try:
        csaf.parse_document(raw)
        outcome = "accepted"
    except csaf.DocumentRejected as rejected:
        outcome = str(rejected)
    return time.perf_counter() - started, outcome


def test_a_large_array_of_distinct_objects_is_checked_in_linear_time():
    # 10,000 ids took about 25 s pairwise on a developer machine; linear it is a few hundredths of a second.
    elapsed, outcome = timed(body(with_ids(10_000)))
    assert outcome == "accepted"
    assert elapsed < 5, f"{elapsed:.1f} s: the uniqueness check must not compare every pair"


def test_a_large_array_of_objects_where_ids_belong_is_rejected_in_linear_time():
    # The check runs whatever the elements are, so objects placed where the schema wants product ids cost the same.
    document = advisory()
    document["vulnerabilities"][0]["product_status"]["fixed"] = [{"id": number} for number in range(10_000)]
    elapsed, outcome = timed(body(document))
    assert outcome.startswith("schema: ")
    assert elapsed < 5, f"{elapsed:.1f} s: the uniqueness check must not compare every pair"


@pytest.mark.parametrize(
    ("where", "elements"),
    [
        ("ids", [{"system_name": "Vendor", "text": "V-1"}, {"system_name": "Vendor", "text": "V-1"}]),
        ("ids", [{"system_name": "Vendor", "text": "V-1"}, {"text": "V-1", "system_name": "Vendor"}]),
        ("flags", [{"label": "component_not_present", "product_ids": ["GIZMO-1"]}] * 2),
        ("fixed", ["GIZMO-1", "WIDGET-2", "GIZMO-1"]),
    ],
    ids=["objects", "objects-in-another-key-order", "flags", "strings"],
)
def test_an_array_with_a_repeated_element_is_rejected(where, elements):
    document = advisory()
    vulnerability_ = document["vulnerabilities"][0]
    if where == "fixed":
        vulnerability_["product_status"]["fixed"] = elements
    else:
        vulnerability_[where] = elements
    with pytest.raises(csaf.DocumentRejected, match="non-unique") as rejected:
        csaf.parse_document(body(document))
    assert len(str(rejected.value)) < 400, "the reason names the place, never the whole array"


def test_elements_that_differ_in_any_way_are_distinct():
    # Only an exact repeat is refused: a different text, or the same letters in another case, is another element.
    document = advisory()
    document["vulnerabilities"][0]["ids"] = [
        {"system_name": "Vendor", "text": "V-1"},
        {"system_name": "Vendor", "text": "V-2"},
        {"system_name": "Other", "text": "V-1"},
    ]
    document["document"]["tracking"]["aliases"] = ["EXAMPLE-2026-0001", "example-2026-0001"]
    assert csaf.parse_document(body(document)).id == "EXAMPLE-2026:0001"


# --------------------------------------------------------------------------
# The directory index


def test_the_index_is_read_oldest_first_whatever_its_order():
    rows = csaf.parse_index(
        index(
            ("2026/b.json", "2026-03-02T00:00:00+00:00"),
            ("2026/a.json", "2026-03-02T00:00:00+00:00"),
            ("2025/z.json", "2026-03-01T23:59:59Z"),
        ),
        NOW,
    )
    assert rows == (
        csaf.Row("2025/z.json", epoch("2026-03-01T23:59:59Z")),
        csaf.Row("2026/a.json", epoch("2026-03-02T00:00:00Z")),
        csaf.Row("2026/b.json", epoch("2026-03-02T00:00:00Z")),
    )


def test_an_offset_date_is_read_as_the_instant_it_names():
    (row,) = csaf.parse_index(index(("2026/a.json", "2026-03-02T02:00:00+02:00")), NOW)
    assert row.release == epoch("2026-03-02T00:00:00Z")


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\n\n",
        b'"2026/a.json"\n',
        b'"2026/a.json","2026-03-02T00:00:00Z","extra"\n',
        b'"../secret.json","2026-03-02T00:00:00Z"\n',
        b'"/abs.json","2026-03-02T00:00:00Z"\n',
        b'"https://evil.example.net/a.json","2026-03-02T00:00:00Z"\n',
        b'"//evil.example.net/a.json","2026-03-02T00:00:00Z"\n',
        b'"dir\\\\a.json","2026-03-02T00:00:00Z"\n',
        b'"a//b.json","2026-03-02T00:00:00Z"\n',
        b'"2026/a.txt","2026-03-02T00:00:00Z"\n',
        b'"2026/a.json","yesterday"\n',
        b'"2026/a.json","2026-03-02T00:00:00"\n',
        b'"2026/a.json","2099-01-01T00:00:00Z"\n',
        b'"2026/a.json","2026-03-02T00:00:00Z"\n"2026/a.json","2026-03-03T00:00:00Z"\n',
        b"\xff\xfe\x00",
    ],
    ids=[
        "empty",
        "blank-lines",
        "one-column",
        "three-columns",
        "dot-dot",
        "absolute-path",
        "other-host",
        "scheme-relative",
        "backslash",
        "double-slash",
        "not-json",
        "bad-date",
        "zoneless-date",
        "future-date",
        "path-twice",
        "not-utf8",
    ],
)
def test_an_index_that_cannot_be_trusted_is_refused_whole(raw):
    with pytest.raises(csaf.CsafError, match="changes.csv"):
        csaf.parse_index(raw, NOW)


def test_an_index_larger_than_the_cap_is_refused_unparsed(monkeypatch):
    monkeypatch.setattr(csaf, "MAX_INDEX_BYTES", 10)
    with pytest.raises(csaf.CsafError, match="larger than"):
        csaf.parse_index(index(("2026/a.json", "2026-03-02T00:00:00Z")), NOW)
