"""The watchlist document: the shape it must have, where it lives, and what a save may replace.

Four owners meet here -- the document's schema, the two places a document can live (the path the YAML names
and the one beside the state file), the atomic write that replaces it, and the decision that reads it. Each
test is about one of those boundaries, because a scope that cannot be saved and a scope that silently stops
being read are the same failure: an instance that judges every advisory, or none.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest

from advisory_radar import core, watchlist
from advisory_radar.config import ConfigError, load_config
from advisory_radar.state import SourceError, state_lock
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


def _save(path: Path, document: dict, *, expected: str = "") -> str:
    """Save one document the way the editor does: the build returns it whatever the file holds."""
    return save_watchlist(path, lambda current: document, expected=expected)


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
    written = _save(target, document(), expected="")
    assert written == digest(document())
    assert read_watchlist(target) == document()
    assert oct(target.stat().st_mode & 0o777) == "0o600", "the scope is a document on the data volume"


def test_a_save_replaces_the_document_it_was_rendered_from(tmp_path):
    target = write(tmp_path / "watchlist.json", document())
    written = _save(target, document(products=[]), expected=digest(document()))
    assert read_watchlist(target)["products"] == []
    assert written == digest(document(products=[]))


def test_a_stale_page_cannot_replace_a_newer_edit(tmp_path):
    target = write(tmp_path / "watchlist.json", document())
    before = target.read_text()
    with pytest.raises(StaleDocument):
        _save(target, document(products=[]), expected="0" * 64)
    assert target.read_text() == before, "a refused save writes nothing"


def test_a_page_that_thinks_there_is_no_document_cannot_create_one_over_an_edit(tmp_path):
    target = write(tmp_path / "watchlist.json", document())
    with pytest.raises(StaleDocument):
        _save(target, document(), expected="")
    assert read_watchlist(target) == document()


def test_an_invalid_document_is_refused_before_the_file_is_touched(tmp_path):
    target = write(tmp_path / "watchlist.json", document())
    before = target.read_text()
    broken = document(products=[{"id": "nodejs", "aliases": ["x"], "domains": ["not a domain"]}])
    with pytest.raises(SourceError, match="domain is invalid"):
        _save(target, broken, expected=digest(document()))
    assert target.read_text() == before


def test_a_target_that_is_not_a_watchlist_is_not_overwritten(tmp_path):
    """A misconfigured ``watchlist:`` path must fail, not replace the file it happens to name."""
    target = tmp_path / "state.json"
    target.write_text(json.dumps({"schema": "advisory-radar-state.v1", "seen": {}}))
    before = target.read_text()
    with pytest.raises(SourceError, match="schema is invalid"):
        _save(target, document(), expected="")
    assert target.read_text() == before


def test_a_document_over_the_save_limit_is_refused(tmp_path):
    target = tmp_path / "watchlist.json"
    large = document(products=[{"id": f"p{index}", "aliases": ["x" * 200], "domains": []} for index in range(100)])
    with pytest.raises(SourceError, match="more than the"):
        _save(target, large, expected="")
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


# ---------------------------------------------------------------------------
# Concurrency and a document that is present but unreadable


def _sidecar_is_locked(document: Path) -> bool:
    """Whether another open file description already holds the document's lock.

    ``flock`` locks belong to the open file description, so a second ``open`` in this same process conflicts
    exactly as another process would: that is what makes this probe a real test of the lock.
    """
    descriptor = os.open(document.with_name(document.name + ".lock"), os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    else:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def test_a_save_holds_the_lock_across_the_read_the_check_and_the_write(tmp_path, monkeypatch):
    """A digest check is only a check if no other process can save between reading it and replacing the file."""
    target = write(tmp_path / "watchlist.json", document())
    observed: list[tuple[str, bool]] = []
    read, save = watchlist.read_watchlist, watchlist.save_json

    def probe_read(path):
        observed.append(("read", _sidecar_is_locked(target)))
        return read(path)

    def probe_save(path, value):
        observed.append(("write", _sidecar_is_locked(target)))
        return save(path, value)

    monkeypatch.setattr(watchlist, "read_watchlist", probe_read)
    monkeypatch.setattr(watchlist, "save_json", probe_save)
    _save(target, document(products=[]), expected=digest(document()))
    assert observed == [("read", True), ("write", True)]


def test_the_lock_is_not_held_once_the_save_returns(tmp_path):
    target = write(tmp_path / "watchlist.json", document())
    _save(target, document(), expected=digest(document()))
    assert _sidecar_is_locked(target) is False, "the lock is released, so the next save is not blocked"


def test_a_broken_link_is_a_present_document_not_a_missing_one(tmp_path):
    """Falling back to the packaged default would judge every advisory on a broken link."""
    state_path = tmp_path / "data" / "state.json"
    link = state_path.with_name("watchlist.json")
    link.parent.mkdir(parents=True)
    link.symlink_to(tmp_path / "gone.json")
    # The name resolves to the file it was meant to be; that file is what is missing, and the link still counts as
    # a document rather than as an empty slot the page could create.
    target = (tmp_path / "gone.json").resolve()
    assert active_path(None, state_path) == target
    assert watchlist.resolve_document(link) == (target, True)
    with pytest.raises(SourceError, match="cannot be read"):
        read_watchlist(active_path(None, state_path))


def test_a_save_does_not_replace_a_broken_link_with_a_file(tmp_path):
    """Replacing the link would leave the operator's own document ignored the moment the target came back."""
    target = tmp_path / "watchlist.json"
    target.symlink_to(tmp_path / "gone.json")
    with pytest.raises(SourceError, match="refusing to create it"):
        _save(target, document(), expected="")
    assert target.is_symlink(), "the link is the operator's, not this program's"
    assert not (tmp_path / "gone.json").exists(), "the link's target is not created behind the operator's back"


def test_a_save_through_a_link_updates_the_file_it_names(tmp_path):
    """A readable link stays a link: the document it names is replaced, and the operator's link keeps working."""
    real = write(tmp_path / "scope.json", document())
    link = tmp_path / "watchlist.json"
    link.symlink_to(real)
    _save(link, document(products=[]), expected=digest(document()))
    assert link.is_symlink(), "the link is not replaced by a regular file"
    assert read_watchlist(real)["products"] == []
    assert (tmp_path / "scope.json.lock").exists(), "the lock is taken on the document, not on the link"
    assert not (tmp_path / "watchlist.json.lock").exists(), "one document, one lock, whatever names it"


def test_a_path_that_cannot_be_inspected_is_not_an_absent_document(tmp_path, monkeypatch):
    """``lexists`` answers False for a permission error, and "absent" falls back to judging everything."""

    def denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(watchlist, "os", types.SimpleNamespace(lstat=denied))
    with pytest.raises(SourceError, match="cannot be inspected"):
        watchlist.present(tmp_path / "watchlist.json")
    with pytest.raises(SourceError, match="cannot be inspected"):
        active_path(None, tmp_path / "state.json")
    # A configured document is named outright: the sibling being uninspectable cannot change which one is read.
    assert active_path(tmp_path / "scope.json", tmp_path / "state.json") == tmp_path / "scope.json"


RACE_CHILD = """
import sys, time
from pathlib import Path
from advisory_radar.watchlist import StaleDocument, save_watchlist

target, expected = Path(sys.argv[1]), sys.argv[2]
document = {"schema": "security-watchlist.v1", "debian_source_packages": ["*"], "excluded_products": [],
            "products": []}
print("ready", flush=True)
started = time.monotonic()
try:
    save_watchlist(target, lambda current: document, expected=expected)
except StaleDocument:
    print(f"stale {time.monotonic() - started:.3f}", flush=True)
    raise SystemExit(3)
raise SystemExit(0)
"""


def test_a_second_process_saving_the_same_page_is_refused(tmp_path, monkeypatch):
    """The sidecar lock is what makes the digest check mean something between processes, not only threads.

    The child announces itself after its imports, then blocks: while the first save holds the lock it cannot
    reach its read at all, and the elapsed time it reports is the wait, so this is contention rather than two
    sequential saves.
    """
    target = write(tmp_path / "watchlist.json", document())
    stale = digest(document())
    writing = threading.Event()
    release = threading.Event()
    original = watchlist.save_json

    def slow_save(path, value):
        writing.set()
        assert release.wait(20)
        return original(path, value)

    monkeypatch.setattr(watchlist, "save_json", slow_save)
    first = threading.Thread(target=lambda: _save(target, document(products=[]), expected=stale))
    first.start()
    assert writing.wait(20), "the first save must reach the write while holding the lock"
    child = subprocess.Popen([sys.executable, "-c", RACE_CHILD, str(target), stale], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "ready"
        time.sleep(0.3)
        assert child.poll() is None, "the child is blocked on the lock the first save holds"
    finally:
        release.set()
        first.join(20)
    reported = child.stdout.readline().split()
    child.wait(timeout=30)
    assert child.returncode == 3, "the second process reads the first one's document and refuses"
    assert float(reported[1]) >= 0.2, "the child waited for the lock before it read"
    assert read_watchlist(target)["products"] == []


def test_a_link_retargeted_while_the_save_waits_is_refused(tmp_path, monkeypatch):
    """Resolving before the lock leaves a window: the configured name can move while the save waits for it."""
    first = write(tmp_path / "first.json", document())
    second = write(tmp_path / "second.json", document(products=[]))
    link = tmp_path / "watchlist.json"
    link.symlink_to(first)

    @contextlib.contextmanager
    def retarget_then_lock(path):
        # Exactly the window the save must not close its eyes to: the name moved before the lock was taken, so the
        # path it resolved is no longer the document a pass reads.
        link.unlink()
        link.symlink_to(second)
        with state_lock(path):
            yield

    monkeypatch.setattr(watchlist, "state_lock", retarget_then_lock)
    before_first, before_second = first.read_text(), second.read_text()
    with pytest.raises(StaleDocument, match="now names another document"):
        _save(link, document(products=[]), expected=digest(document()))
    assert first.read_text() == before_first
    assert second.read_text() == before_second


def test_a_document_nested_too_deeply_is_unreadable_not_a_crash(tmp_path):
    """A hand edit can leave a document past the interpreter's decode or validation limit.

    The contract is the class of outcome, not the decoder's message or its exact nesting threshold: 3.13's
    decoder gives up on this depth, a newer one accepts it and the schema check refuses the document. A read
    must refuse either way, and leave the file exactly as it was.
    """
    deep = tmp_path / "deep.json"
    payload = "[" * 10_000 + "]" * 10_000
    deep.write_text(payload)
    with pytest.raises(SourceError):
        read_watchlist(deep)
    assert deep.read_text() == payload


def test_a_path_with_an_embedded_nul_is_refused_not_a_crash(tmp_path):
    """``os.lstat`` raises ValueError for a NUL, which is not the OSError the inspection guard expects."""
    broken = Path("scope\x00.json")
    with pytest.raises(SourceError, match="not a usable path"):
        watchlist.present(broken)
    with pytest.raises(SourceError, match="not a usable path"):
        save_watchlist(broken, lambda current: document(), expected="")


def test_the_configuration_refuses_a_watchlist_path_with_a_nul(tmp_path):
    path = tmp_path / "config.yml"
    path.write_text('sources: []\nnotifiers: []\nstate_path: state.json\nwatchlist: "scope\\u0000.json"\n')
    with pytest.raises(ConfigError, match="NUL"):
        load_config(path, {})


def test_every_way_a_document_cannot_be_read_is_one_answer(tmp_path):
    """The page and the pass report one unreadable document, whatever the filesystem did."""
    directory = tmp_path / "directory"
    directory.mkdir()
    invalid = tmp_path / "invalid.json"
    invalid.write_bytes(b'{"schema": "security-watchlist.v1"}\xff')
    loop = tmp_path / "loop.json"
    loop.symlink_to(loop)
    for broken in (directory, invalid, loop):
        assert watchlist.present(broken) is True, "the entry is there; it just cannot be read"
        with pytest.raises(SourceError, match="cannot be read"):
            read_watchlist(broken)
    component = tmp_path / "file"
    component.write_text("x")
    assert watchlist.present(component / "under.json") is False, "ENOTDIR: nothing can be there"


def test_a_document_root_is_not_a_document(tmp_path):
    """``watchlist: /`` has no name to build the sidecar lock from; it must refuse, not raise."""
    root = Path("/")
    assert watchlist.present(root) is True
    with pytest.raises(SourceError, match="does not name a document"):
        save_watchlist(root, lambda current: document(), expected="")


def test_the_default_document_is_found_beside_a_state_path_the_filesystem_cannot_walk(tmp_path):
    """The sibling is looked for at its resolved entry: otherwise a `..` hides a saved scope behind the default."""
    state_path = tmp_path / "missing" / ".." / "state.json"
    saved = write(tmp_path / "watchlist.json", document())
    assert active_path(None, state_path) == saved.resolve()


def test_a_link_behind_an_unwalkable_spelling_is_still_a_document(tmp_path):
    """The dangling-link rule must survive the spelling the filesystem cannot traverse."""
    link = tmp_path / "scope.json"
    link.symlink_to(tmp_path / "gone.json")
    configured = tmp_path / "missing" / ".." / "scope.json"
    resolved, there = watchlist.resolve_document(configured)
    assert resolved == (tmp_path / "gone.json").resolve()
    assert there is True, "the entry is a link, so it is a document that cannot be read, not an empty slot"
    with pytest.raises(SourceError, match="refusing to create it"):
        save_watchlist(configured, lambda current: document(), expected="")
    assert not (tmp_path / "gone.json").exists()
