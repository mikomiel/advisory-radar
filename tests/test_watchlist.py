"""The watchlist document: the shape it must have, where it lives, and what a save may replace.

Four owners meet here -- the document's schema, the two places a document can live (the path the YAML names
and the one beside the state file), the atomic write that replaces it, and the decision that reads it. Each
test is about one of those boundaries, because a scope that cannot be saved and a scope that silently stops
being read are the same failure: an instance that judges every advisory, or none.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisory_radar import core, watchlist
from advisory_radar.config import ConfigError, load_config
from advisory_radar.state import SourceError
from advisory_radar.watchlist import (
    DEFAULT_DOCUMENT,
    StaleDocument,
    active_path,
    digest,
    editable_path,
    parse_policy,
    read_watchlist,
    save_watchlist,
)

KIND = "security-watchlist.v1"


def document(**overrides) -> dict:
    """A valid document with one product, so a test only states the part it is about."""
    return {
        "schema": KIND,
        "debian_source_packages": ["*"],
        "excluded_products": [],
        "products": [{"id": "nodejs", "aliases": ["node.js", "nodejs"], "domains": ["nodejs.org"]}],
        **overrides,
    }


def write(path: Path, value: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return path


def item(title: str, link: str = "https://vendor.example.com/a", summary: str = "notes", source_title: str = ""):
    return core.Item("g1", title, link, summary, None, (), source_title=source_title)


# ---------------------------------------------------------------------------
# The shape


def test_the_packaged_default_is_a_valid_document():
    """A fresh clone runs with no document configured, so the packaged one must always parse."""
    loaded = read_watchlist(DEFAULT_DOCUMENT)
    assert set(loaded) == watchlist.DOCUMENT_KEYS
    assert parse_policy(loaded).products == ()


def test_the_document_is_read_as_a_policy():
    policy = parse_policy(document(excluded_products=["legacy"], debian_source_packages=["curl", "lib*"]))
    assert [product.id for product in policy.products] == ["nodejs"]
    assert policy.products[0].aliases == ("node.js", "nodejs")
    assert policy.products[0].domains == ("nodejs.org",)
    assert policy.debian_source_packages == ("curl", "lib*")
    assert policy.excluded_products == ("legacy",)


BROKEN: tuple[tuple[dict, str], ...] = (
    ({}, "schema is invalid"),
    (document(schema="security-watchlist.v2"), "schema is invalid"),
    (document(unexpected=[]), "schema is invalid"),
    (document(products="nodejs"), "products are invalid"),
    (document(products=[{"id": "nodejs", "aliases": ["nodejs"]}]), "product fields are invalid"),
    (document(products=[{"id": "nodejs", "aliases": ["nodejs"], "domains": [], "unexpected": 1}]), "fields"),
    (document(products=[{"id": "NodeJS", "aliases": ["nodejs"], "domains": []}]), "identity is invalid"),
    (document(products=[{"id": "a", "aliases": ["a"], "domains": []}]), "identity is invalid"),
    (document(products=[{"id": "node js", "aliases": ["a"], "domains": []}]), "identity is invalid"),
    (
        document(
            products=[
                {"id": "nodejs", "aliases": ["a"], "domains": []},
                {"id": "nodejs", "aliases": ["b"], "domains": []},
            ]
        ),
        "identity is invalid",
    ),
    (document(products=[{"id": "nodejs", "aliases": [], "domains": []}]), "nonempty string arrays"),
    (document(products=[{"id": "nodejs", "aliases": [" x "], "domains": []}]), "nonempty string arrays"),
    (document(products=[{"id": "nodejs", "aliases": ["x", "x"], "domains": []}]), "duplicate values"),
    (document(products=[{"id": "nodejs", "aliases": ["x"], "domains": ["localhost"]}]), "domain is invalid"),
    (document(products=[{"id": "nodejs", "aliases": ["x"], "domains": ["nodejs.org/a"]}]), "domain is invalid"),
    (
        document(products=[{"id": "nodejs", "aliases": ["x"], "domains": [], "metadata_only": "yes"}]),
        "metadata policy is invalid",
    ),
    (document(debian_source_packages=[]), "nonempty string arrays"),
    (document(debian_source_packages=["CURL"]), "package pattern is invalid"),
    (document(excluded_products=[""]), "nonempty string arrays"),
)


@pytest.mark.parametrize("broken, message", BROKEN)
def test_a_malformed_document_is_refused_with_its_reason(broken, message):
    with pytest.raises(SourceError, match=message):
        parse_policy(broken)


def test_an_unreadable_file_is_not_an_empty_scope(tmp_path):
    """Treating a missing or broken document as "no scope" would judge every advisory on a typo."""
    with pytest.raises(SourceError, match="cannot be read"):
        read_watchlist(tmp_path / "absent.json")
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    with pytest.raises(SourceError, match="cannot be read"):
        read_watchlist(broken)


# ---------------------------------------------------------------------------
# Where it lives


def test_the_document_lives_where_the_yaml_names_it_or_beside_the_state(tmp_path):
    state_path = tmp_path / "data" / "state.json"
    configured = tmp_path / "scope.json"
    assert editable_path(configured, state_path) == configured
    assert editable_path(None, state_path) == state_path.with_name("watchlist.json")
    # A save writes the configured path even before it exists: that is how a fresh document is created.
    assert active_path(configured, state_path) == configured
    assert not active_path(configured, state_path).exists()


def test_an_unconfigured_installation_reads_beside_the_state_or_the_packaged_default(tmp_path):
    state_path = tmp_path / "data" / "state.json"
    assert active_path(None, state_path) == DEFAULT_DOCUMENT
    saved = write(state_path.with_name("watchlist.json"), document())
    assert active_path(None, state_path) == saved


# ---------------------------------------------------------------------------
# The digest a page carries


def test_the_digest_covers_values_not_formatting():
    """A hand edit that only reorders keys leaves the page it was rendered from valid."""
    assert digest({"b": 1, "a": [1, 2]}) == digest({"a": [1, 2], "b": 1})
    assert digest({"a": [1, 2]}) != digest({"a": [1, 3]})
    assert digest({}) != "", "no digest is ever the empty string, which means there is no document"


# ---------------------------------------------------------------------------
# What a save may replace


def test_a_save_creates_the_document(tmp_path):
    target = tmp_path / "data" / "watchlist.json"
    written = save_watchlist(target, document(), expected="")
    assert written == digest(document())
    assert read_watchlist(target) == document()
    assert oct(target.stat().st_mode & 0o777) == "0o600", "the scope is a document on the data volume"


def test_a_save_replaces_the_document_it_was_rendered_from(tmp_path):
    target = write(tmp_path / "watchlist.json", document())
    written = save_watchlist(target, document(products=[]), expected=digest(document()))
    assert read_watchlist(target)["products"] == []
    assert written == digest(document(products=[]))


def test_a_stale_page_cannot_replace_a_newer_edit(tmp_path):
    target = write(tmp_path / "watchlist.json", document())
    before = target.read_text()
    with pytest.raises(StaleDocument):
        save_watchlist(target, document(products=[]), expected="0" * 64)
    assert target.read_text() == before, "a refused save writes nothing"


def test_a_page_that_thinks_there_is_no_document_cannot_create_one_over_an_edit(tmp_path):
    target = write(tmp_path / "watchlist.json", document())
    with pytest.raises(StaleDocument):
        save_watchlist(target, document(), expected="")
    assert read_watchlist(target) == document()


def test_an_invalid_document_is_refused_before_the_file_is_touched(tmp_path):
    target = write(tmp_path / "watchlist.json", document())
    before = target.read_text()
    broken = document(products=[{"id": "nodejs", "aliases": ["x"], "domains": ["not a domain"]}])
    with pytest.raises(SourceError, match="domain is invalid"):
        save_watchlist(target, broken, expected=digest(document()))
    assert target.read_text() == before


def test_a_target_that_is_not_a_watchlist_is_not_overwritten(tmp_path):
    """A misconfigured ``watchlist:`` path must fail, not replace the file it happens to name."""
    target = tmp_path / "state.json"
    target.write_text(json.dumps({"schema": "advisory-radar-state.v1", "seen": {}}))
    before = target.read_text()
    with pytest.raises(SourceError, match="schema is invalid"):
        save_watchlist(target, document(), expected="")
    assert target.read_text() == before


def test_a_document_over_the_save_limit_is_refused(tmp_path):
    target = tmp_path / "watchlist.json"
    large = document(products=[{"id": f"p{index}", "aliases": ["x" * 200], "domains": []} for index in range(100)])
    with pytest.raises(SourceError, match="more than the"):
        save_watchlist(target, large, expected="")
    assert not target.exists(), "a document too large to save from the page is refused, never half-written"


def test_the_state_file_may_not_be_named_like_the_default_watchlist(tmp_path):
    """The default document sits beside the state file, so one name for both is two owners for one path."""
    path = tmp_path / "config.yml"
    path.write_text(f"sources: []\nnotifiers: []\nstate_path: {tmp_path}/watchlist.json\n")
    with pytest.raises(ConfigError, match="watchlist.json"):
        load_config(path, {})


# ---------------------------------------------------------------------------
# The decision the document feeds


def test_every_reason_the_scope_refuses_an_item_has_a_name():
    policy = parse_policy(document(excluded_products=["legacy"]))
    assert core.filter_reason(item("node.js advisory"), policy) == ""
    assert core.filter_reason(item("release", link="https://nodejs.org/adv/1"), policy) == ""
    assert core.filter_reason(item("legacy advisory"), policy) == "excluded-product"
    assert core.filter_reason(item("unrelated news"), policy) == "no-product-match"


def test_the_debian_and_nginx_rules_keep_their_own_reason():
    debian = parse_policy(document(products=[], debian_source_packages=["openssl"]))
    assert core.filter_reason(item("DSA-6104-1 openssl - security update", "https://lists.debian.org/x"), debian) == ""
    assert (
        core.filter_reason(item("DSA-6104-1 curl - security update", "https://lists.debian.org/x"), debian)
        == "debian-package"
    )
    nginx = parse_policy(document(products=[]))
    assert core.filter_reason(item("security fix", link="https://nginx.org/x"), nginx) == ""
    assert core.filter_reason(item("new release", link="https://nginx.org/x"), nginx) == "nginx-keyword"


def test_passes_filter_is_the_same_decision_as_its_reason():
    policy = parse_policy(document())
    for probe in (item("node.js advisory"), item("unrelated news"), item("legacy advisory")):
        assert core.passes_filter(probe, policy) is (core.filter_reason(probe, policy) == "")
