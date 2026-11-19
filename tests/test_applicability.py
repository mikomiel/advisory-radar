"""Applicability evidence: distinct results for distinct situations, and never a "not affected" nothing supports."""

from __future__ import annotations

import pytest

from advisory_radar import applicability, core
from advisory_radar.inventory import Inventory, parse
from inventory_fixtures import AFFECTED_NPM, PACKAGE, cyclonedx, osv_facts, osv_scanner, sbom_component, scan_finding

NOW = 1_790_000_000
DAY = 86400
GHSA = "GHSA-AAAA-BBBB-CCCC"
CVE = "CVE-2026-0001"
OTHER_GHSA = "GHSA-DDDD-EEEE-FFFF"
ENTRIES, COMPLETE = applicability.trim_affected(AFFECTED_NPM)


def inventory_of(data: bytes, *, at: int = NOW) -> Inventory:
    return Inventory(parse(data, name="inventory.json", now=at, origin="upload"))


def sbom(*components: dict, at: int = NOW) -> Inventory:
    return inventory_of(cyclonedx(*components), at=at)


def judged(stored: Inventory, *, entries=ENTRIES, complete=COMPLETE, ids=(GHSA,), now=NOW, max_age=30):
    return applicability.judge(stored, list(ids), list(entries), complete, now, max_age)


def summary(found: applicability.Evidence) -> tuple[str, str]:
    return found.status, found.reason


def affected_entry(name: str, *events: dict, ecosystem: str = "npm") -> dict:
    return {"package": {"ecosystem": ecosystem, "name": name}, "ranges": [{"type": "SEMVER", "events": list(events)}]}


# --- the stored form of an advisory's affected data ---------------------------------------------------


def test_trimming_keeps_what_a_verdict_reads_and_drops_the_rest():
    raw = [
        {
            "package": {"ecosystem": "npm", "name": PACKAGE, "purl": "pkg:npm/x"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "repo": "https://example.invalid/r",
                    "events": [{"introduced": "0", "note": "x"}, {"fixed": "2.3.1"}],
                }
            ],
            "versions": ["1.0.0"],
            "database_specific": {"anything": "else"},
        }
    ]
    assert applicability.trim_affected(raw) == (
        [
            {
                "ecosystem": "npm",
                "name": PACKAGE,
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.3.1"}]}],
                "versions": ["1.0.0"],
            }
        ],
        True,
    )


def test_an_empty_affected_list_is_complete_and_a_missing_one_is_not():
    assert applicability.trim_affected([]) == ([], True)
    assert applicability.trim_affected(None) == ([], False)
    assert applicability.trim_affected({"package": {}}) == ([], False)


@pytest.mark.parametrize(
    "entry",
    [
        "not an object",
        {"ranges": []},
        {"package": {"ecosystem": "npm"}, "ranges": []},
        {"package": {"ecosystem": "", "name": "x"}, "ranges": []},
        {"package": {"ecosystem": "npm", "name": "n" * 257}, "ranges": []},
        {"package": {"ecosystem": "npm", "name": "x"}, "ranges": "SEMVER"},
        {"package": {"ecosystem": "npm", "name": "x"}, "ranges": ["SEMVER"]},
        {"package": {"ecosystem": "npm", "name": "x"}, "ranges": [{"events": "x"}]},
        {"package": {"ecosystem": "npm", "name": "x"}, "ranges": [{"events": []}] * (applicability.MAX_RANGES + 1)},
        {
            "package": {"ecosystem": "npm", "name": "x"},
            "ranges": [{"events": [{"introduced": "0"}] * (applicability.MAX_EVENTS + 1)}],
        },
        {"package": {"ecosystem": "npm", "name": "x"}, "versions": "1.0.0"},
    ],
)
def test_an_entry_that_is_malformed_or_over_a_bound_is_dropped_and_marks_the_advisory_incomplete(entry):
    entries, complete = applicability.trim_affected([entry, *AFFECTED_NPM])
    assert complete is False
    assert [item["name"] for item in entries] == [PACKAGE]


def test_the_number_of_affected_entries_is_bounded():
    many = [
        affected_entry(f"lib-{number}", {"introduced": "0"}) for number in range(applicability.MAX_AFFECTED_ENTRIES + 1)
    ]
    entries, complete = applicability.trim_affected(many)
    assert len(entries) == applicability.MAX_AFFECTED_ENTRIES and complete is False


def test_a_listed_version_that_cannot_be_kept_makes_the_advisory_incomplete():
    entry = {"package": {"ecosystem": "npm", "name": "x"}, "ranges": [], "versions": ["1.0.0", 5, "v" * 200]}
    entries, complete = applicability.trim_affected([entry])
    assert entries[0]["versions"] == ["1.0.0"] and complete is False


def test_a_long_list_of_versions_is_cut_and_the_entry_keeps_its_ranges_so_applies_still_works():
    versions = [f"1.{number}.0" for number in range(applicability.MAX_LISTED_VERSIONS * 3)]
    entry = {**AFFECTED_NPM[0], "versions": versions}
    entries, complete = applicability.trim_affected([entry])
    assert complete is False, "a cut list cannot show that a version is outside it"
    assert len(entries) == 1 and entries[0]["ranges"] == [
        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.3.1"}]}
    ]
    assert entries[0]["versions"] == versions[: applicability.MAX_LISTED_VERSIONS]
    affected = judged(sbom(sbom_component(PACKAGE, "2.3.0")), entries=entries, complete=complete)
    assert (summary(affected), affected.fixed) == (("applies", "affected"), "2.3.1")
    cleared = judged(sbom(sbom_component(PACKAGE, "2.3.1")), entries=entries, complete=complete)
    assert summary(cleared) == ("unknown", "no_facts"), "and a fixed version is not called safe from a cut list"


def test_a_list_of_versions_exactly_at_the_bound_is_kept_whole_and_complete():
    versions = [f"1.{number}.0" for number in range(applicability.MAX_LISTED_VERSIONS)]
    entries, complete = applicability.trim_affected([{**AFFECTED_NPM[0], "versions": versions}])
    assert entries[0]["versions"] == versions and complete is True


def test_an_event_with_a_version_that_is_not_text_reads_as_unknown_never_as_an_open_range():
    raw = [affected_entry("x", {"introduced": "0", "fixed": 5}, {"fixed": ["2.0.0"]}, "junk")]
    entries, _ = applicability.trim_affected(raw)
    assert entries[0]["ranges"][0]["events"] == [{}, {}, {}]
    found = judged(sbom(sbom_component("x", "1.0.0")), entries=entries)
    assert summary(found) == ("unknown", "no_facts")


# --- facts kept in the state --------------------------------------------------------------------------


def test_facts_are_stored_under_the_normalised_id_and_nothing_is_written_for_nothing():
    state: dict = {}
    applicability.record_facts(state, {}, NOW)
    assert state == {}
    both = {"GHSA-AAAA-BBBB-CCCC": osv_facts(AFFECTED_NPM, "cve-2026-0001"), "cve-2026-0002": osv_facts(AFFECTED_NPM)}
    applicability.record_facts(state, both, NOW)
    assert sorted(state["affected"]) == ["CVE-2026-0002", "GHSA-aaaa-bbbb-cccc"]
    assert state["affected"]["CVE-2026-0002"] == {"at": NOW, "cves": [], "entries": ENTRIES, "complete": True}
    assert state["affected"]["GHSA-aaaa-bbbb-cccc"]["cves"] == [CVE], "an alias is kept in its normal form"


def test_recording_an_advisory_again_replaces_its_facts_and_refreshes_their_time():
    state: dict = {}
    applicability.record_facts(state, {GHSA: osv_facts(AFFECTED_NPM, CVE)}, NOW)
    applicability.record_facts(state, {GHSA: osv_facts([])}, NOW + 60)
    assert state["affected"]["GHSA-aaaa-bbbb-cccc"] == {"at": NOW + 60, "cves": [], "entries": [], "complete": True}


def test_only_the_newest_advisories_are_kept_up_to_the_cap(monkeypatch):
    monkeypatch.setattr(applicability, "MAX_FACT_ADVISORIES", 3)
    state: dict = {}
    for number in range(5):
        applicability.record_facts(state, {f"GHSA-aaaa-bbbb-{number:04d}": osv_facts(AFFECTED_NPM)}, NOW + number)
    assert sorted(state["affected"]) == [f"GHSA-aaaa-bbbb-{number:04d}" for number in (2, 3, 4)]


def test_facts_of_one_advisory_are_found_by_its_own_id_in_any_case():
    state: dict = {}
    applicability.record_facts(state, {GHSA: osv_facts(AFFECTED_NPM, CVE)}, NOW)
    assert applicability.facts_for(state, ["ghsa-AAAA-bbbb-CCCC"]) == (ENTRIES, True)
    assert applicability.facts_for(state, ["CVE-2099-0000"]) == ([], False), "nothing is stored under a CVE id"
    assert applicability.facts_for({}, [GHSA]) == ([], False)
    assert applicability.facts_for({"affected": "damaged"}, [GHSA]) == ([], False)


def test_facts_are_incomplete_as_soon_as_one_id_says_so():
    state = {"affected": {"CVE-2026-0002": {"at": NOW, "cves": [], "entries": ENTRIES, "complete": False}}}
    applicability.record_facts(state, {GHSA: osv_facts(AFFECTED_NPM)}, NOW)
    assert applicability.facts_for(state, [GHSA, "CVE-2026-0002"])[1] is False
    assert applicability.facts_for(state, [GHSA])[1] is True
    state["affected"][GHSA.replace("AAAA-BBBB-CCCC", "aaaa-bbbb-cccc")]["entries"] = ["junk"]
    assert applicability.facts_for(state, [GHSA]) == ([], True)


@pytest.mark.parametrize(
    "ids",
    [
        pytest.param([GHSA, CVE], id="the advisory and its alias"),
        pytest.param([CVE.lower(), GHSA.lower()], id="in any case"),
        pytest.param(
            [GHSA, CVE, "src:https://feed.example.invalid/post/1", "PSA-2026-00001-1", "DSA-5000-1"],
            id="beside ids that name no vulnerability",
        ),
    ],
)
def test_ids_the_stored_record_covers_leave_its_facts_able_to_clear_the_advisory(ids):
    state: dict = {}
    applicability.record_facts(state, {GHSA: osv_facts(AFFECTED_NPM, CVE)}, NOW)
    assert applicability.facts_for(state, ids) == (ENTRIES, True)


@pytest.mark.parametrize(
    "ids",
    [
        pytest.param([GHSA, OTHER_GHSA], id="a second advisory nothing was stored for"),
        pytest.param([GHSA, "CVE-2026-0002"], id="a CVE the record does not alias"),
        pytest.param([GHSA, CVE, "cve-2026-0002"], id="one covered CVE beside an uncovered one"),
    ],
)
def test_an_id_no_stored_record_covers_keeps_the_facts_of_its_sibling_from_clearing_it(ids):
    state: dict = {}
    applicability.record_facts(state, {GHSA: osv_facts(AFFECTED_NPM, CVE)}, NOW)
    assert applicability.facts_for(state, ids) == (ENTRIES, False)


def test_a_cve_aliased_by_a_record_the_advisory_does_not_name_is_not_covered():
    state: dict = {}
    both = {GHSA: osv_facts(AFFECTED_NPM, CVE), OTHER_GHSA: osv_facts(AFFECTED_NPM, "CVE-2026-0002")}
    applicability.record_facts(state, both, NOW)
    assert applicability.facts_for(state, [GHSA, "CVE-2026-0002"]) == (ENTRIES, False)


def test_aliases_are_bounded_validated_and_one_past_the_bound_is_not_covered():
    cves = [f"CVE-2026-{number:04d}" for number in range(1, applicability.MAX_FACT_CVES + 2)]
    state: dict = {}
    applicability.record_facts(state, {GHSA: osv_facts(AFFECTED_NPM, *cves)}, NOW)
    assert state["affected"]["GHSA-aaaa-bbbb-cccc"]["cves"] == cves[:-1]
    assert applicability.facts_for(state, [GHSA, cves[-2]])[1] is True
    assert applicability.facts_for(state, [GHSA, cves[-1]])[1] is False
    applicability.record_facts(state, {GHSA: osv_facts(AFFECTED_NPM, "not-a-cve", 5, CVE, CVE.lower())}, NOW)
    assert state["affected"]["GHSA-aaaa-bbbb-cccc"]["cves"] == [CVE]
    applicability.record_facts(state, {GHSA: {"cves": CVE, "affected": AFFECTED_NPM}}, NOW)
    assert state["affected"]["GHSA-aaaa-bbbb-cccc"]["cves"] == []


# --- the verdict --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("components", "imported", "expected"),
    [
        ([sbom_component(PACKAGE, "2.3.0")], NOW, ("applies", "affected")),
        ([sbom_component(PACKAGE, "2.3.1")], NOW, ("not_affected", "fixed")),
        ([sbom_component(PACKAGE, "3.0.0")], NOW, ("not_affected", "fixed")),
        ([sbom_component(PACKAGE, None)], NOW, ("unknown", "unknown_version")),
        ([sbom_component(PACKAGE, "main")], NOW, ("unknown", "unknown_version")),
        ([sbom_component("other-lib", "1.0.0")], NOW, ("unknown", "no_component")),
        ([sbom_component(PACKAGE, "2.3.1")], NOW - 40 * DAY, ("unknown", "stale")),
        ([sbom_component(PACKAGE, "2.3.0")], NOW - 40 * DAY, ("applies", "affected")),
    ],
)
def test_affected_fixed_unknown_version_missing_package_and_stale_inventories_read_differently(
    components, imported, expected
):
    assert summary(judged(sbom(*components, at=imported))) == expected


def test_an_affected_result_names_the_installed_version_the_fix_and_the_package():
    found = judged(sbom(sbom_component(PACKAGE, "2.3.0")))
    assert (found.package, found.installed, found.fixed, found.called) == (f"npm {PACKAGE}", "2.3.0", "2.3.1", None)


def test_a_version_before_the_first_affected_one_is_outside_not_fixed():
    entries = [affected_entry(PACKAGE, {"introduced": "1.5.0"}, {"fixed": "2.0.0"})]
    found = judged(sbom(sbom_component(PACKAGE, "1.4.0")), entries=applicability.trim_affected(entries)[0])
    assert (summary(found), found.fixed) == (("not_affected", "outside"), "")


def test_an_ecosystem_without_a_comparator_is_unknown_even_when_the_package_is_listed():
    entries = applicability.trim_affected(
        [affected_entry("org.example:lib", {"introduced": "0"}, {"fixed": "2"}, ecosystem="Maven")]
    )[0]
    found = judged(sbom(sbom_component("org.example/lib", "1.0", "maven")), entries=entries)
    assert summary(found) == ("unknown", "unsupported")


def test_an_advisory_with_no_comparable_facts_is_unknown_never_not_affected():
    stored = sbom(sbom_component(PACKAGE, "2.3.1"))
    assert summary(judged(stored, entries=[])) == ("unknown", "no_facts")
    assert summary(judged(stored, complete=False)) == ("unknown", "no_facts")
    git = [
        {"package": {"ecosystem": "npm", "name": PACKAGE}, "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}
    ]
    assert summary(judged(stored, entries=applicability.trim_affected(git)[0])) == ("unknown", "no_facts")


def test_incomplete_facts_can_still_confirm_that_an_advisory_applies():
    found = judged(sbom(sbom_component(PACKAGE, "2.3.0")), complete=False)
    assert summary(found) == ("applies", "affected")


def test_one_affected_installed_version_decides_when_a_package_is_installed_twice():
    found = judged(sbom(sbom_component(PACKAGE, "2.3.1"), sbom_component(PACKAGE, "2.2.0")))
    assert (summary(found), found.installed) == (("applies", "affected"), "2.2.0")


def test_a_version_that_cannot_be_compared_outweighs_a_fixed_one_beside_it():
    found = judged(sbom(sbom_component(PACKAGE, "2.3.1"), sbom_component(PACKAGE, None)))
    assert summary(found) == ("unknown", "unknown_version")


def test_an_advisory_naming_two_packages_is_judged_by_the_strongest_evidence():
    entries = applicability.trim_affected(
        [
            affected_entry("lib-a", {"introduced": "0"}, {"fixed": "2.0.0"}),
            affected_entry("lib-b", {"introduced": "0"}, {"fixed": "2.0.0"}),
        ]
    )[0]
    fixed_a = sbom_component("lib-a", "2.0.0")
    assert summary(judged(sbom(fixed_a), entries=entries)) == ("not_affected", "fixed"), "a missing sibling is weakest"
    assert summary(judged(sbom(fixed_a, sbom_component("lib-b", "1.0.0")), entries=entries)) == ("applies", "affected")
    assert summary(judged(sbom(fixed_a, sbom_component("lib-b", None)), entries=entries)) == (
        "unknown",
        "unknown_version",
    )
    assert summary(judged(sbom(sbom_component("other", "1.0.0")), entries=entries)) == ("unknown", "no_component")


def test_an_sbom_that_skipped_a_component_cannot_say_a_package_it_lacks_is_not_installed():
    entries = applicability.trim_affected(
        [
            affected_entry("lib-a", {"introduced": "0"}, {"fixed": "2.0.0"}),
            affected_entry("lib-b", {"introduced": "0"}, {"fixed": "2.0.0"}),
        ]
    )[0]
    fixed_a = sbom_component("lib-a", "2.0.0")
    purl_less = {"type": "library", "name": "lib-b", "version": "1.0.0"}
    assert summary(judged(sbom(fixed_a, purl_less), entries=entries)) == ("unknown", "no_component")
    other_type = {"type": "library", "name": "lib-b", "version": "1.0.0", "purl": "pkg:deb/debian/lib-b@1.0.0"}
    assert summary(judged(sbom(fixed_a, other_type), entries=entries)) == ("unknown", "no_component")


def test_an_absent_package_of_an_ecosystem_whose_names_are_not_compared_hides_a_clearance():
    entries = applicability.trim_affected(
        [
            affected_entry("lib-a", {"introduced": "0"}, {"fixed": "2.0.0"}),
            affected_entry("org.example:lib-b", {"introduced": "0"}, {"fixed": "2"}, ecosystem="Maven"),
        ]
    )[0]
    found = judged(sbom(sbom_component("lib-a", "2.0.0")), entries=entries)
    assert summary(found) == ("unknown", "no_component")


def test_package_names_match_by_each_ecosystems_rules():
    entries = applicability.trim_affected(
        [affected_entry("Foo_Bar", {"introduced": "0"}, {"fixed": "2.0"}, ecosystem="PyPI")]
    )[0]
    entries[0]["ranges"][0]["type"] = "ECOSYSTEM"
    found = judged(sbom(sbom_component("foo.bar", "1.5", "pypi")), entries=entries)
    assert summary(found) == ("applies", "affected")


def test_an_inventory_is_stale_only_after_the_configured_age():
    just_inside = sbom(sbom_component(PACKAGE, "2.3.1"), at=NOW - 30 * DAY)
    just_outside = sbom(sbom_component(PACKAGE, "2.3.1"), at=NOW - 30 * DAY - 1)
    assert (summary(judged(just_inside)), judged(just_inside).stale) == (("not_affected", "fixed"), False)
    old = judged(just_outside)
    assert (summary(old), old.stale, old.age_days) == (("unknown", "stale"), True, 30)
    assert summary(judged(just_outside, max_age=31)) == ("not_affected", "fixed")


def test_a_stale_inventory_that_still_says_applies_keeps_saying_so_and_notes_its_age():
    found = judged(sbom(sbom_component(PACKAGE, "2.3.0"), at=NOW - 45 * DAY))
    assert (summary(found), found.stale, found.age_days) == (("applies", "affected"), True, 45)


def test_an_inventory_imported_in_the_future_is_not_stale():
    found = judged(sbom(sbom_component(PACKAGE, "2.3.1"), at=NOW + 3 * DAY))
    assert (summary(found), found.stale, found.age_days) == (("not_affected", "fixed"), False, 0)


# --- scan results -------------------------------------------------------------------------------------


def scanned(*findings: dict, at: int = NOW) -> Inventory:
    return inventory_of(osv_scanner(*findings), at=at)


def test_a_scan_finding_is_applicable_by_any_id_it_names_and_carries_the_installed_version_and_fix():
    stored = scanned(scan_finding("npm", PACKAGE, "2.3.0", GHSA, aliases=("CVE-2026-0001",), fixed="2.3.1"))
    for identifier in (GHSA, "ghsa-aaaa-bbbb-cccc", "cve-2026-0001"):
        found = judged(stored, entries=[], ids=[identifier])
        assert summary(found) == ("applies", "affected")
        assert (found.package, found.installed, found.fixed) == (f"npm {PACKAGE}", "2.3.0", "2.3.1")
    assert summary(judged(stored, entries=[], ids=["CVE-2099-0000"])) == ("unknown", "no_facts")


def test_a_scan_finding_applies_even_when_stored_advisory_data_says_the_version_is_fixed():
    stored = scanned(scan_finding("npm", PACKAGE, "2.3.0", GHSA, fixed="2.3.1"))
    fixed_earlier = applicability.trim_affected([affected_entry(PACKAGE, {"introduced": "0"}, {"fixed": "2.0.0"})])[0]
    assert summary(judged(stored, entries=fixed_earlier)) == ("applies", "affected")


@pytest.mark.parametrize(
    ("reach", "expected"),
    [
        ((True,), True),
        ((False,), False),
        ((None,), None),
        ((False, True), True),
        ((False, False), False),
        ((False, None), None),
        ((None, True), True),
    ],
)
def test_reachability_is_extra_evidence_and_never_changes_the_verdict(reach, expected):
    findings = [
        scan_finding("npm", f"lib-{number}", "1.0.0", GHSA, called=called) for number, called in enumerate(reach)
    ]
    found = judged(scanned(*findings), entries=[])
    assert summary(found) == ("applies", "affected")
    assert found.called is expected


def test_a_scan_that_does_not_list_a_package_cannot_clear_an_advisory():
    stored = scanned(scan_finding("npm", "other-lib", "1.0.0", "GHSA-DDDD-EEEE-FFFF"))
    assert summary(judged(stored)) == ("unknown", "no_component")
    assert stored.complete is False


def test_a_package_a_scan_does_not_list_may_still_be_installed_so_it_blocks_a_clearance():
    entries = applicability.trim_affected(
        [
            affected_entry("lib-a", {"introduced": "0"}, {"fixed": "2.0.0"}),
            affected_entry("lib-b", {"introduced": "0"}, {"fixed": "2.0.0"}),
        ]
    )[0]
    listed_a = scan_finding(
        "npm", "lib-a", "2.0.0", "GHSA-DDDD-EEEE-FFFF", fixed="3.0.0"
    )  # listed for another advisory
    found = judged(scanned(listed_a), entries=entries)
    assert summary(found) == ("unknown", "no_component"), "an SBOM would say not affected here, a scan cannot"
    assert summary(judged(sbom(sbom_component("lib-a", "2.0.0")), entries=entries)) == ("not_affected", "fixed")


def test_a_scan_can_confirm_an_advisory_but_never_clear_it():
    """A scan lists only what it found something in: a clean copy of the package can be missing from it."""
    fixed = scan_finding("npm", PACKAGE, "2.3.1", OTHER_GHSA)  # listed for another advisory
    assert summary(judged(scanned(fixed))) == ("unknown", "partial")
    assert summary(judged(sbom(sbom_component(PACKAGE, "2.3.1")))) == ("not_affected", "fixed"), "the same facts"
    before = applicability.trim_affected([affected_entry(PACKAGE, {"introduced": "3.0.0"}, {"fixed": "3.1.0"})])[0]
    assert summary(judged(scanned(fixed), entries=before)) == ("unknown", "partial"), "outside the range, too"
    affected = scan_finding("npm", PACKAGE, "2.3.0", OTHER_GHSA)
    assert summary(judged(scanned(affected))) == ("applies", "affected"), "a listed version in range still applies"


def test_a_stale_scan_that_lists_a_fixed_version_names_the_scan_not_its_age():
    found = judged(scanned(scan_finding("npm", PACKAGE, "2.3.1", OTHER_GHSA), at=NOW - 40 * DAY))
    assert (summary(found), found.stale, found.age_days) == (("unknown", "partial"), True, 40)


def test_a_stale_scan_still_reports_its_finding_and_says_it_is_old():
    found = judged(scanned(scan_finding("npm", PACKAGE, "2.3.0", GHSA), at=NOW - 60 * DAY), entries=[])
    assert (summary(found), found.stale, found.age_days) == (("applies", "affected"), True, 60)


# --- facts and inventory together ---------------------------------------------------------------------


def test_evidence_for_reads_the_recorded_facts_of_the_ids_it_is_given():
    state: dict = {}
    applicability.record_facts(state, {GHSA: osv_facts(AFFECTED_NPM, CVE)}, NOW)
    stored = sbom(sbom_component(PACKAGE, "2.3.0"))
    assert summary(applicability.evidence_for(state, stored, ["ghsa-aaaa-bbbb-cccc"], NOW, 30)) == (
        "applies",
        "affected",
    )
    assert summary(applicability.evidence_for(state, stored, ["CVE-2099-0000"], NOW, 30)) == ("unknown", "no_facts")
    assert summary(applicability.evidence_for({}, stored, [GHSA], NOW, 30)) == ("unknown", "no_facts")


def test_evidence_for_never_clears_an_advisory_that_names_an_id_nothing_covers():
    state: dict = {}
    applicability.record_facts(state, {GHSA: osv_facts(AFFECTED_NPM, CVE)}, NOW)
    fixed = sbom(sbom_component(PACKAGE, "2.3.1"))
    assert summary(applicability.evidence_for(state, fixed, [GHSA, CVE], NOW, 30)) == ("not_affected", "fixed")
    assert summary(applicability.evidence_for(state, fixed, [GHSA, OTHER_GHSA], NOW, 30)) == ("unknown", "no_facts")
    assert summary(applicability.evidence_for(state, fixed, [OTHER_GHSA, GHSA], NOW, 30)) == ("unknown", "no_facts")
    assert summary(applicability.evidence_for(state, fixed, [GHSA, "CVE-2026-0002"], NOW, 30)) == (
        "unknown",
        "no_facts",
    )
    # An uncovered id can only withhold a clearance: what the stored record shows as affected is still shown.
    affected = sbom(sbom_component(PACKAGE, "2.3.0"))
    assert summary(applicability.evidence_for(state, affected, [GHSA, OTHER_GHSA], NOW, 30)) == (
        "applies",
        "affected",
    )


# --- what the pass captures ---------------------------------------------------------------------------


def intel_answering(document: dict) -> core.Intel:
    class Intel(core.Intel):
        def __init__(self):
            super().__init__(None, {}, lambda: 0.0, lambda s: None)

        def _get(self, url):
            return 200, document

    return Intel()


def test_the_pass_keeps_the_aliases_and_affected_list_of_a_live_osv_record_under_its_normalised_id():
    record = {"id": GHSA, "aliases": ["CVE-2026-0001"], "affected": AFFECTED_NPM}
    intel = intel_answering(record)
    assert intel.ghsa(GHSA).cves == ("CVE-2026-0001",)
    assert intel.affected == {"GHSA-aaaa-bbbb-cccc": {"cves": ["CVE-2026-0001"], "affected": AFFECTED_NPM}}


@pytest.mark.parametrize(
    "extra",
    [
        {"withdrawn": "2026-10-01T00:00:00Z"},  # a withdrawn advisory applies to nothing
        {"affected": []},
        {"affected": "everything"},
        {"affected": None},
    ],
)
def test_the_pass_keeps_nothing_for_a_withdrawn_record_or_one_without_a_usable_affected_list(extra):
    intel = intel_answering({"id": GHSA, "aliases": ["CVE-2026-0001"], "affected": AFFECTED_NPM, **extra})
    intel.ghsa(GHSA)
    assert intel.affected == {}
