"""Version order and OSV range evaluation: a wrong order is a wrong "not affected", so each rule is pinned."""

from __future__ import annotations

import pytest

from advisory_radar.versions import MAX_VERSION_CHARS, evaluate, pep440_key, semver_key, version_key


def in_order(key, *versions: str) -> None:
    keys = [key(version) for version in versions]
    assert None not in keys, versions
    assert keys == sorted(keys), versions
    assert len(set(keys)) == len(keys), f"{versions} contains two equal versions"


def test_semantic_versions_sort_by_number_not_by_text():
    in_order(semver_key, "1.2.3", "1.2.10", "1.10.0", "2.0.0", "10.0.0")


def test_a_semver_pre_release_sorts_before_its_release_in_the_order_the_spec_gives():
    in_order(
        semver_key,
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    )


def test_a_leading_v_and_build_metadata_do_not_change_a_semver_version():
    assert semver_key("v1.2.3") == semver_key("1.2.3")
    assert semver_key("1.0.0+build.1") == semver_key("1.0.0+other")
    assert semver_key("v0.0.0-20210101000000-abcdef123456") < semver_key("v0.0.0")  # a Go pseudo-version


@pytest.mark.parametrize(
    "text", ["", "1", "1.2", "1.2.3.4", "01.2.3", "1.2.3-01", "1.2.3-", "latest", "1.2.x", " 1.2.3"]
)
def test_text_that_is_not_a_semantic_version_has_no_key(text):
    assert semver_key(text) is None


def test_pep440_orders_dev_pre_release_release_and_post_release():
    in_order(
        pep440_key,
        "1.0.dev1",
        "1.0a1.dev1",
        "1.0a1",
        "1.0a2",
        "1.0b1",
        "1.0rc1",
        "1.0",
        "1.0.post1.dev1",
        "1.0.post1",
        "1.0.1",
        "1.1",
        "2.0",
        "1!0.1",
    )


def test_pep440_spellings_of_one_version_are_equal():
    assert pep440_key("1.0") == pep440_key("1.0.0") == pep440_key("v1.0")
    assert pep440_key("1.0a1") == pep440_key("1.0-alpha.1") == pep440_key("1.0.ALPHA1")
    assert pep440_key("1.0rc1") == pep440_key("1.0c1")
    assert pep440_key("1.0.post1") == pep440_key("1.0-1") == pep440_key("1.0r1")


@pytest.mark.parametrize("text", ["", "abc", "1.0.x", "1..0", "1.0+cpu", "1.0.dev1+local", "1.0 beta"])
def test_text_that_is_not_a_public_pep440_version_has_no_key(text):
    assert pep440_key(text) is None


def test_an_ecosystem_without_a_comparator_or_an_oversized_version_has_no_key():
    assert version_key("Maven", "1.0") is None
    assert version_key("npm", "1" * (MAX_VERSION_CHARS + 1)) is None
    assert version_key("npm", "") is None
    assert version_key("npm", "1.2.3") == semver_key("1.2.3")
    assert version_key("Go", "v1.2.3") == semver_key("1.2.3")
    assert version_key("crates.io", "1.2.3") == semver_key("1.2.3")
    assert version_key("PyPI", "1.2.3") == pep440_key("1.2.3")


def semver_range(*events: dict, kind: str = "SEMVER") -> list[dict]:
    return [{"type": kind, "events": list(events)}]


FIXED_IN_231 = semver_range({"introduced": "0"}, {"fixed": "2.3.1"})


@pytest.mark.parametrize(
    ("installed", "affected", "fixed"),
    [
        ("0.0.1", True, "2.3.1"),
        ("2.3.0", True, "2.3.1"),
        ("2.3.1", False, "2.3.1"),
        ("2.3.2", False, "2.3.1"),
        ("3.0.0", False, "2.3.1"),
    ],
)
def test_a_range_from_zero_to_a_fix_splits_installed_versions_at_the_fix(installed, affected, fixed):
    verdict = evaluate("npm", installed, FIXED_IN_231)
    assert (verdict.affected, verdict.fixed) == (affected, fixed)


def test_a_version_before_the_first_affected_one_is_outside_and_names_no_fix():
    ranges = semver_range({"introduced": "1.5.0"}, {"fixed": "2.0.0"})
    assert (evaluate("npm", "1.4.9", ranges).affected, evaluate("npm", "1.4.9", ranges).fixed) == (False, "")
    assert evaluate("npm", "1.5.0", ranges).affected is True
    assert evaluate("npm", "1.9.9", ranges).fixed == "2.0.0"
    assert evaluate("npm", "2.0.0", ranges).affected is False


def test_events_are_read_in_version_order_whatever_order_the_record_lists_them():
    shuffled = semver_range({"fixed": "2.3.1"}, {"introduced": "0"})
    assert evaluate("npm", "2.3.0", shuffled).affected is True
    assert evaluate("npm", "2.3.1", shuffled).affected is False


def test_two_affected_windows_in_one_range_are_both_honoured():
    ranges = semver_range({"introduced": "1.0.0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"fixed": "2.1.0"})
    assert evaluate("npm", "1.1.0", ranges).affected is True
    assert evaluate("npm", "1.5.0", ranges).affected is False
    assert evaluate("npm", "2.0.5", ranges).affected is True
    assert evaluate("npm", "2.0.5", ranges).fixed == "2.1.0"
    assert evaluate("npm", "3.0.0", ranges).affected is False


def test_last_affected_is_itself_affected_and_the_next_version_is_not():
    ranges = semver_range({"introduced": "0"}, {"last_affected": "1.4.0"})
    assert evaluate("npm", "1.4.0", ranges).affected is True
    assert evaluate("npm", "1.4.1", ranges).affected is False
    assert evaluate("npm", "1.4.0", ranges).fixed == ""


def test_a_range_with_no_fix_stays_affected_without_naming_one():
    verdict = evaluate("npm", "9.9.9", semver_range({"introduced": "1.0.0"}))
    assert (verdict.affected, verdict.fixed) == (True, "")


def test_pypi_ranges_use_pep_440_order():
    ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]
    assert evaluate("PyPI", "2.0rc1", ranges).affected is True
    assert evaluate("PyPI", "2.0", ranges).affected is False
    assert evaluate("PyPI", "1.9.post3", ranges).affected is True
    assert evaluate("PyPI", "2.0.0", ranges).affected is False


def test_an_explicitly_listed_version_is_affected_even_beside_an_unreadable_range():
    git = [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "0123abc"}]}]
    assert evaluate("npm", "1.2.3", git, ["1.2.3"]).affected is True
    assert evaluate("npm", "1.2.4", git, ["1.2.3"]).affected is None
    assert evaluate("npm", "1.2.4", (), ["1.2.3"]).affected is False


def test_an_affected_range_wins_over_one_that_cannot_be_read():
    git = {"type": "GIT", "events": [{"introduced": "0"}]}
    verdict = evaluate("npm", "2.3.0", [git, *FIXED_IN_231])
    assert (verdict.affected, verdict.fixed) == (True, "2.3.1")


def test_not_affected_needs_every_range_to_be_readable():
    git = {"type": "GIT", "events": [{"introduced": "0"}]}
    assert evaluate("npm", "2.3.1", [git, *FIXED_IN_231]).affected is None


@pytest.mark.parametrize(
    "ranges",
    [
        semver_range({"introduced": "0"}, {"fixed": "0123abcd"}),  # a commit, not a version
        semver_range({"introduced": "0"}, {"fixed": "2.3.1"}, {"limit": "3.0.0"}),
        semver_range({"introduced": "0"}, {"fixed": "2.3.1", "limit": "3.0.0"}),
        semver_range({"introduced": "0"}, {"fixed": 231}),
        semver_range({"introduced": "0"}, {}),
        semver_range({"introduced": "0"}, {"fixed": "2.3.1"}, kind="GIT"),
        semver_range({"introduced": "0"}, {"fixed": "2.3.1"}, kind=""),
        [{"type": "SEMVER", "events": "not a list"}],
        ["not a mapping"],
        [],
    ],
)
def test_a_range_that_cannot_be_read_never_becomes_a_confident_answer(ranges):
    assert evaluate("npm", "2.3.0", ranges).affected is None


def test_an_installed_version_that_cannot_be_compared_is_unknown():
    for installed in ("", "main", "2.3", "1" * (MAX_VERSION_CHARS + 1)):
        assert evaluate("npm", installed, FIXED_IN_231).affected is None
    assert evaluate("Maven", "2.3.0", FIXED_IN_231).affected is None
    assert evaluate("npm", "2.3.0").affected is None
