"""The settings overlay: merge precedence, secret references, atomic storage and hot reload.

Every behaviour here is the contract of ``settings.json``: it wins over the YAML for exactly four
keys, it is validated by the one configuration validator, no credential is stored in it, and a
reload either installs a wholly built candidate under the state lock or changes nothing.
"""

from __future__ import annotations

import json
import logging
import signal
import stat
import sys
import threading
import time

import pytest
import yaml

from advisory_radar import cli, config, core, delivery, pipeline
from advisory_radar.config import ConfigError, load_config
from advisory_radar.http import RedactFilter
from advisory_radar.runtime import Runtime
from advisory_radar.settings import (
    MAX_SETTINGS_BYTES,
    SETTINGS_SCHEMA,
    load_settings,
    load_settings_document,
    save_settings,
    settings_path,
)
from advisory_radar.state import LockBusy, SourceError, load_state_document, save_state, state_lock

NOW = 1792600000
SECRET = "https://hooks.example.com/SUPERSECRET"
LOG = logging.getLogger("advisory_radar")


@pytest.fixture(autouse=True)
def _detach_log_redaction():
    """A runtime installs a log filter; one test's secrets must not redact the next test's output."""
    yield
    for installed in list(LOG.filters):
        if isinstance(installed, RedactFilter):
            LOG.removeFilter(installed)


def write_config(tmp_path, document: dict, *, name: str = "config.yml"):
    body = {
        "sources": [],
        "notifiers": [],
        "poll_interval": "15m",
        "state_path": str(tmp_path / "state.json"),
        **document,
    }
    path = tmp_path / name
    path.write_text(yaml.safe_dump(body, sort_keys=False))
    return path


def save_overlay(tmp_path, overlay: dict, *, now: int = NOW):
    return save_settings(settings_path(tmp_path / "state.json"), overlay, now=now)


# --- precedence and validation ---------------------------------------------------------------


def test_the_overlay_wins_for_each_writable_key_and_the_yaml_still_supplies_the_rest(tmp_path):
    document = {
        "sources": [
            {"id": "keep", "type": "rss", "url": "https://feeds.example.com/keep.xml", "tag": "news"},
            {"id": "edit", "type": "rss", "url": "https://feeds.example.com/edit.xml"},
        ],
        "notifiers": [{"id": "yaml_notifier", "type": "ntfy", "url": "${YAML_HOOK}", "topic": "yaml"}],
        "poll_interval": "15m",
        "hidden_source_hosts": ["yaml.example.com"],
        "watchlist": str(tmp_path / "watchlist.json"),
    }
    path = write_config(tmp_path, document)
    overlay = {
        "notifiers": [{"id": "overlay_notifier", "type": "ntfy", "url": "${OVERLAY_HOOK}", "topic": "ops"}],
        "sources": {"edit": {"enabled": False, "tag": "security"}},
        "poll_interval": "30s",
        "hidden_source_hosts": ["overlay.example.com"],
    }
    # No YAML_HOOK: the replaced notifier must not need it any more.
    cfg = load_config(path, {"OVERLAY_HOOK": "https://ntfy.example.com/overlay"}, settings=overlay)

    assert cfg.poll_interval_seconds == 30
    assert cfg.hidden_source_hosts == frozenset({"overlay.example.com"})
    assert [source["id"] for source in cfg.sources] == ["keep"]
    assert cfg.sources[0]["tag"] == "news", "a source the overlay does not name keeps its YAML value"
    assert [notifier["id"] for notifier in cfg.notifiers] == ["overlay_notifier"]
    assert cfg.notifiers[0]["url"] == "https://ntfy.example.com/overlay"
    # Everything outside the four keys still comes from the YAML.
    assert cfg.watchlist_path == tmp_path / "watchlist.json"
    assert cfg.state_path == tmp_path / "state.json"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("poll_interval", "banana"),
        ("hidden_source_hosts", "not-a-list"),
        ("notifiers", {"not": "a list"}),
    ],
)
def test_a_bad_overlay_value_fails_with_the_message_the_yaml_gives(tmp_path, key, value):
    yaml_path = write_config(tmp_path, {key: value}, name="bad.yml")
    with pytest.raises(ConfigError) as from_yaml:
        load_config(yaml_path, {})
    overlay_path = write_config(tmp_path, {})
    with pytest.raises(ConfigError) as from_overlay:
        load_config(overlay_path, {}, settings={key: value})
    assert str(from_overlay.value) == str(from_yaml.value)


def test_a_bad_notifier_key_fails_with_the_message_the_yaml_gives(tmp_path):
    entry = {"id": "n", "type": "webhook", "url": "${HOOK}", "bogus": 1}
    yaml_path = write_config(tmp_path, {"notifiers": [entry]}, name="bad.yml")
    with pytest.raises(ConfigError) as from_yaml:
        load_config(yaml_path, {"HOOK": SECRET})
    overlay_path = write_config(tmp_path, {})
    with pytest.raises(ConfigError) as from_overlay:
        load_config(overlay_path, {"HOOK": SECRET}, settings={"notifiers": [entry]})
    assert str(from_overlay.value) == str(from_yaml.value)


def test_the_overlay_cannot_move_the_store(tmp_path):
    # The store locator is YAML-only: a browser save must not be able to point the next pass at another
    # document, exactly as it cannot move state_path.
    path = write_config(tmp_path, {})
    with pytest.raises(ConfigError) as caught:
        load_config(path, {}, settings={"storage": f"sqlite:///{tmp_path}/state.db"})
    assert "unknown overlay keys" in str(caught.value)
    assert "storage" in str(caught.value)


def test_an_overlay_key_outside_the_four_is_refused(tmp_path):
    path = write_config(tmp_path, {})
    with pytest.raises(ConfigError) as caught:
        load_config(path, {}, settings={"watchlist": "other.json"})
    assert "unknown overlay keys" in str(caught.value)
    assert "watchlist" in str(caught.value)


def test_a_null_overlay_section_is_refused_instead_of_crashing(tmp_path):
    path = write_config(tmp_path, {})
    for key in ("notifiers", "sources"):
        with pytest.raises(ConfigError):
            load_config(path, {}, settings={key: None})


def test_an_unknown_source_id_is_refused(tmp_path):
    path = write_config(tmp_path, {"sources": [{"id": "known", "type": "webhook"}]})
    with pytest.raises(ConfigError) as caught:
        load_config(path, {}, settings={"sources": {"missing": {"enabled": False}}})
    assert "missing" in str(caught.value)


def test_a_source_id_is_refused_when_the_yaml_defines_no_sources(tmp_path):
    path = tmp_path / "config.yml"
    path.write_text(f"notifiers: []\nstate_path: {tmp_path}/state.json\n")
    with pytest.raises(ConfigError) as caught:
        load_config(path, {}, settings={"sources": {"missing": {"enabled": False}}})
    assert "missing" in str(caught.value)


def test_a_literal_notifier_secret_is_refused_and_never_stored(tmp_path):
    path = write_config(tmp_path, {})
    overlay = {"notifiers": [{"id": "hook", "type": "discord_webhook", "url": SECRET}]}
    with pytest.raises(ConfigError) as caught:
        load_config(path, {}, settings=overlay)
    assert SECRET not in str(caught.value)
    assert "reference" in str(caught.value)
    overlay_path = settings_path(tmp_path / "state.json")
    with pytest.raises(ConfigError):
        save_settings(overlay_path, overlay, now=1)
    assert not overlay_path.exists(), "a refused overlay is never written"
    # a reference buried inside a URL still stores the rest of a credential-bearing URL
    with pytest.raises(ConfigError):
        save_settings(
            overlay_path,
            {"notifiers": [{"id": "hook", "type": "webhook", "url": "https://hooks.example.com/${HOOK}"}]},
            now=1,
        )
    assert not overlay_path.exists()


def test_headers_cannot_be_written_by_the_overlay(tmp_path):
    overlay_path = settings_path(tmp_path / "state.json")
    overlay = {
        "notifiers": [
            {"id": "hook", "type": "webhook", "url": "${HOOK}", "headers": {"Authorization": "Bearer ${TOKEN}"}}
        ]
    }
    with pytest.raises(ConfigError) as caught:
        save_settings(overlay_path, overlay, now=1)
    assert "headers" in str(caught.value)
    assert not overlay_path.exists()


def test_a_reference_in_the_overlay_is_expanded_and_redacted_like_a_yaml_one(tmp_path, caplog):
    yaml_value = "https://hooks.example.com/YAML-SECRET"
    path = write_config(tmp_path, {"notifiers": [{"id": "yaml", "type": "webhook", "url": "${YAML_HOOK}"}]})
    environment = {"YAML_HOOK": yaml_value, "OVERLAY_HOOK": SECRET}
    by_yaml = load_config(path, environment)
    by_overlay = load_config(
        path,
        environment,
        settings={"notifiers": [{"id": "overlay", "type": "webhook", "url": "${OVERLAY_HOOK}"}]},
    )

    assert [notifier["url"] for notifier in by_overlay.notifiers] == [SECRET]
    assert "OVERLAY_HOOK" in by_overlay.secret_names
    assert "YAML_HOOK" not in by_overlay.secret_names, "the replaced YAML notifier is no longer referenced"
    assert SECRET in by_overlay.secret_values
    assert yaml_value in by_yaml.secret_values

    def redacted(cfg, value: str) -> str:
        caplog.clear()
        redactor = pipeline.attach_redaction(config.secret_values(cfg))
        try:
            with caplog.at_level(logging.INFO, logger="advisory_radar"):
                LOG.info("hook %s", value)
        finally:
            LOG.removeFilter(redactor)
        return caplog.text

    assert "hook [redacted]" in redacted(by_yaml, yaml_value)
    assert "hook [redacted]" in redacted(by_overlay, SECRET)


# --- storage ---------------------------------------------------------------------------------


def test_load_settings_is_empty_until_a_document_exists_and_refuses_a_corrupt_one(tmp_path):
    path = settings_path(tmp_path / "state.json")
    assert load_settings(path) == {}
    path.write_text("{not json")
    with pytest.raises(ConfigError) as caught:
        load_settings(path)
    assert str(path) in str(caught.value)
    path.write_text(json.dumps({"schema": "advisory-radar-settings.v0", "revision": 1, "settings": {}}))
    with pytest.raises(ConfigError) as caught:
        load_settings(path)
    assert str(path) in str(caught.value)
    path.write_bytes(b"{}" + b" " * MAX_SETTINGS_BYTES)
    with pytest.raises(ConfigError) as caught:
        load_settings(path)
    assert str(path) in str(caught.value)


def test_a_deeply_nested_overlay_is_a_config_error_and_a_save_leaves_it_alone(tmp_path):
    """#81: a hand edit can nest past the decoder's limit; the overlay must refuse by name and never be replaced."""
    path = settings_path(tmp_path / "state.json")
    deep = b"[" * 10_000 + b"]" * 10_000
    path.write_bytes(deep)
    with pytest.raises(ConfigError):
        load_settings_document(path)
    assert path.read_bytes() == deep, "a failed read never rewrites the damaged overlay"
    with pytest.raises(ConfigError):
        save_settings(path, {"poll_interval": "30s"}, now=NOW)
    assert path.read_bytes() == deep, "a save refuses an unreadable overlay instead of resetting its revision"


def test_a_deeply_nested_settings_schema_is_a_config_error_and_is_not_rewritten(tmp_path):
    """#81 review: the schema value can be the deep part; the overlay must still refuse without representing it."""
    path = settings_path(tmp_path / "state.json")
    body = b'{"schema": ' + b"[" * 10_000 + b"]" * 10_000 + b', "revision": 1, "settings": {}}'
    path.write_bytes(body)
    with pytest.raises(ConfigError):
        load_settings_document(path)
    assert path.read_bytes() == body, "a failed read never rewrites the damaged overlay"


def test_a_settings_schema_that_is_not_a_string_is_named_by_type(tmp_path):
    """A decoded container schema must not be represented: only a string is safe to ``repr``."""
    path = settings_path(tmp_path / "state.json")
    path.write_text(json.dumps({"schema": ["x"], "revision": 1, "settings": {}}))
    with pytest.raises(ConfigError, match="declares a list schema"):
        load_settings_document(path)


def test_save_settings_writes_0600_and_moves_the_revision_forward(tmp_path):
    path = settings_path(tmp_path / "state.json")
    first = save_settings(path, {"poll_interval": "30s"}, now=100)
    assert first == {
        "schema": SETTINGS_SCHEMA,
        "revision": 1,
        "updated_at": 100,
        "settings": {"poll_interval": "30s"},
    }
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_settings(path) == {"poll_interval": "30s"}
    second = save_settings(path, {"poll_interval": "12h"}, now=200)
    assert second["revision"] == 2
    assert load_settings(path) == {"poll_interval": "12h"}
    assert load_settings_document(path)["updated_at"] == 200


def test_a_failed_replace_leaves_the_previous_overlay(tmp_path, monkeypatch):
    path = settings_path(tmp_path / "state.json")
    save_settings(path, {"poll_interval": "30s"}, now=1)
    before = path.read_bytes()

    def refuse(source, destination):
        raise OSError("disk full")

    monkeypatch.setattr("advisory_radar.state.os.replace", refuse)
    with pytest.raises(OSError):
        save_settings(path, {"poll_interval": "12h"}, now=2)
    assert path.read_bytes() == before
    assert load_settings(path) == {"poll_interval": "30s"}
    assert list(path.parent.glob(".settings-*")) == [], "a failed write leaves no temporary file"


# --- the runtime and reload ------------------------------------------------------------------


def test_a_failed_build_leaves_the_live_runtime_and_the_overlay_untouched(tmp_path):
    path = write_config(tmp_path, {"notifiers": [{"id": "base", "type": "webhook", "url": "${BASE_HOOK}"}]})
    environment = {"BASE_HOOK": SECRET, "OVERLAY_HOOK": "https://hooks.example.com/overlay"}
    runtime = Runtime.build(path, environment)
    overlay = settings_path(runtime.cfg.state_path)
    # A valid shape: the ntfy builder is what needs a `topic` the overlay does not carry.
    save_settings(overlay, {"notifiers": [{"id": "broken", "type": "ntfy", "url": "${OVERLAY_HOOK}"}]}, now=1)
    before = overlay.read_bytes()
    try:
        with pytest.raises(ConfigError):
            runtime.reload(blocking=False)
        assert [notifier.id for notifier in runtime.notifiers] == ["base"]
        assert runtime.overlay["revision"] == 0
        assert overlay.read_bytes() == before
        assert not (tmp_path / "state.json").exists(), "a refused reload writes no state"
    finally:
        runtime.detach_redaction()


def test_reload_under_the_lock_records_the_applied_revision_and_keeps_the_queues(tmp_path):
    path = write_config(tmp_path, {"notifiers": [{"id": "base", "type": "webhook", "url": "${BASE_HOOK}"}]})
    environment = {"BASE_HOOK": SECRET, "EXTRA_HOOK": "https://hooks.example.com/extra"}
    runtime = Runtime.build(path, environment, clock=lambda: NOW)
    state = core.new_state()
    state["seen"] = {"CVE-2026-9": {"at": NOW, "outcome": "delivered"}}
    state["pending"] = [
        {
            "kind": "new",
            "tag": "warning",
            "title": "Pending",
            "body": "b",
            "ids": ["CVE-2026-10"],
            "cves": [],
            "levels": {},
            "source": "s",
            "link": "",
        }
    ]
    state["parked"] = [
        {
            "kind": "new",
            "tag": "critical",
            "title": "Parked",
            "body": "b",
            "ids": ["CVE-2026-11"],
            "cves": [],
            "levels": {},
            "source": "s",
            "link": "",
            "attempts": 3,
            "first_attempt_at": NOW - 3600,
            "parked_at": NOW - 60,
        }
    ]
    save_state(runtime.cfg.state_path, state)
    pending_before = json.dumps(state["pending"], sort_keys=True)
    parked_before = json.dumps(state["parked"], sort_keys=True)
    overlay = settings_path(runtime.cfg.state_path)
    stored = save_settings(
        overlay,
        {
            "notifiers": [
                {"id": "base", "type": "webhook", "url": "${BASE_HOOK}"},
                {"id": "extra", "type": "webhook", "url": "${EXTRA_HOOK}"},
            ]
        },
        now=1,
    )
    try:
        with state_lock(runtime.cfg.state_path):
            with pytest.raises(LockBusy):
                runtime.reload(blocking=False)
            assert [notifier.id for notifier in runtime.notifiers] == ["base"]
            assert runtime.overlay["revision"] == 0
        runtime.reload(blocking=False)
        assert [notifier.id for notifier in runtime.notifiers] == ["base", "extra"]
        after = load_state_document(runtime.cfg.state_path, core.STATE_SCHEMA, "advisory state")
        assert after["settings"]["revision"] == stored["revision"]
        assert after["settings"]["applied_at"] == NOW
        assert len(after["settings"]["fingerprint"]) == 64
        assert json.dumps(after["pending"], sort_keys=True) == pending_before
        assert json.dumps(after["parked"], sort_keys=True) == parked_before
        assert after["seen"] == state["seen"]
    finally:
        runtime.detach_redaction()


def test_a_reload_never_publishes_an_older_revision(tmp_path, monkeypatch):
    # A candidate is built before the lock. If a newer revision was applied while it waited, publishing the
    # older one would roll the configuration back while the file on disk stays newer.
    path = write_config(tmp_path, {})
    runtime = Runtime.build(path, {})
    save_overlay(tmp_path, {"poll_interval": "30s"})
    stale = Runtime.build(path, {})  # a candidate built at revision 1
    save_overlay(tmp_path, {"poll_interval": "12h"})
    runtime.reload(blocking=False)
    assert runtime.cfg.poll_interval_seconds == 12 * 3600
    monkeypatch.setattr("advisory_radar.runtime.Runtime.build", classmethod(lambda cls, *a, **k: stale))
    with pytest.raises(ConfigError) as caught:
        runtime.reload(blocking=False)
    assert "older than the live revision" in str(caught.value)
    assert runtime.cfg.poll_interval_seconds == 12 * 3600, "the stale candidate must not be published"


def test_a_second_nonblocking_reload_answers_instead_of_waiting(tmp_path):
    # A SIGHUP reload holds the reload lock while it waits for a pass; the UI's reload must answer at once,
    # not queue behind it.
    from advisory_radar.runtime import _RELOAD_LOCK

    path = write_config(tmp_path, {})
    runtime = Runtime.build(path, {})
    with _RELOAD_LOCK, pytest.raises(LockBusy):
        runtime.reload(blocking=False)


def test_a_reload_that_would_change_the_web_binding_is_refused(tmp_path):
    path = write_config(tmp_path, {})
    runtime = Runtime.build(path, {})
    write_config(tmp_path, {"web": {"port": 9090}})
    with pytest.raises(ConfigError) as caught:
        runtime.reload(blocking=False)
    assert "restart" in str(caught.value)
    assert (runtime.cfg.web_host, runtime.cfg.web_port) == ("0.0.0.0", 8080)


def test_a_state_file_named_settings_json_is_refused(tmp_path):
    # The overlay is the file beside the state file with that name; a state file there would be read as an
    # overlay and a pass would write a state document there that every later overlay read refuses.
    path = write_config(tmp_path, {"state_path": str(tmp_path / "settings.json")})
    with pytest.raises(ConfigError) as caught:
        load_config(path, {})
    assert "settings.json" in str(caught.value)


def test_a_reload_with_an_unreadable_state_is_refused(tmp_path):
    path = write_config(tmp_path, {})
    runtime = Runtime.build(path, {})
    (tmp_path / "state.json").write_text("{not json")
    try:
        with pytest.raises(SourceError):
            runtime.reload(blocking=False)
        assert runtime.cfg.poll_interval_seconds == 900, "a refused reload leaves the live configuration"
    finally:
        runtime.detach_redaction()


def test_a_reload_cannot_move_the_state_file(tmp_path):
    # A hand-edited YAML can move the state path; reloading would lock one file, read it and write the
    # resulting document to the other path, which is a different instance's state. Refuse and keep running.
    path = write_config(tmp_path, {})
    runtime = Runtime.build(path, {})
    write_config(tmp_path, {"state_path": str(tmp_path / "moved.json")})
    with pytest.raises(ConfigError) as caught:
        runtime.reload(blocking=False)
    assert "state_path" in str(caught.value)
    assert runtime.cfg.state_path == tmp_path / "state.json"
    assert not (tmp_path / "moved.json").exists()


def test_a_reload_cannot_move_the_store(tmp_path):
    # A hand-edited YAML can move the store; a reload records the applied revision through the live store, so
    # publishing the candidate would write the marker into one store and serve another. Refuse and keep running.
    path = write_config(tmp_path, {})
    runtime = Runtime.build(path, {})
    moved = tmp_path / "moved.db"
    write_config(tmp_path, {"storage": f"sqlite:///{moved}"})
    with pytest.raises(ConfigError) as caught:
        runtime.reload(blocking=False)
    assert "storage" in str(caught.value)
    assert runtime.cfg.storage == ""
    assert not moved.exists()


def test_a_reload_refuses_an_unavailable_store_before_changing_anything(tmp_path, monkeypatch):
    # The lock, the load and the applied marker are one publication. An unreachable database at any of them
    # used to escape as StoreUnavailable past the callers that answer ConfigError, so the overlay was saved and
    # the browser saw a 500; it must be a refusal the operator can act on.
    monkeypatch.setitem(sys.modules, "psycopg", None)
    path = write_config(tmp_path, {"storage": "postgresql://radar@db.example/radar"})
    runtime = Runtime.build(path, {})
    save_overlay(tmp_path, {"poll_interval": "30s"})

    with pytest.raises(ConfigError) as caught:
        runtime.reload(blocking=False)
    message = str(caught.value)
    assert "not applied" in message
    assert "psycopg" in message, "the refusal still names the missing piece"
    assert runtime.cfg.poll_interval_seconds == 900, "a refused reload leaves the live configuration"
    assert runtime.overlay["settings"] == {}, "a refused reload leaves the applied overlay"


def test_an_overlay_over_the_reader_limit_is_never_written(tmp_path):
    # JSON escaping can push an accepted value past the limit the reader enforces; writing that file would
    # brick the next start, so the size is checked against the exact text that is about to be written.
    overlay_path = settings_path(tmp_path / "state.json")
    with pytest.raises(ConfigError) as caught:
        save_overlay(tmp_path, {"hidden_source_hosts": ["x" * MAX_SETTINGS_BYTES]})
    assert str(MAX_SETTINGS_BYTES) in str(caught.value)
    assert not overlay_path.exists(), "a refused overlay is never written"


def test_a_reload_whose_state_write_fails_keeps_the_old_configuration(tmp_path, monkeypatch):
    path = write_config(tmp_path, {})
    runtime = Runtime.build(path, {})
    save_overlay(tmp_path, {"poll_interval": "30s"})

    def fails(*args, **kwargs):
        raise OSError("No space left on device")

    monkeypatch.setattr("advisory_radar.storage.save_state", fails)
    with pytest.raises(ConfigError) as caught:
        runtime.reload(blocking=False)
    assert "not applied" in str(caught.value)
    assert runtime.cfg.poll_interval_seconds == 900, "a failed marker write must not publish the candidate"
    assert runtime.overlay["settings"] == {}


def test_an_expanded_state_path_finds_its_overlay(tmp_path):
    # A state_path that uses ${...} must have its overlay read beside the expanded file, not beside a
    # literal "${DATA_DIR}/settings.json"; otherwise the UI saves where the next start does not look.
    path = write_config(tmp_path, {"state_path": "${DATA_DIR}/state.json"})
    environment = {"DATA_DIR": str(tmp_path)}
    runtime = Runtime.build(path, environment)
    assert runtime.overlay_path == tmp_path / "settings.json"
    save_settings(tmp_path / "settings.json", {"poll_interval": "30s"}, now=NOW)
    assert Runtime.build(path, environment).cfg.poll_interval_seconds == 30


def test_headers_stay_in_the_yaml_when_the_overlay_edits_a_notifier(tmp_path):
    # headers is the one field the overlay may not store; an enablement edit must not drop the authentication
    # headers the YAML holds.
    path = write_config(
        tmp_path,
        {
            "notifiers": [
                {
                    "id": "hook",
                    "type": "webhook",
                    "url": "${HOOK}",
                    "headers": {"Authorization": "Bearer ${TOKEN}"},
                }
            ]
        },
    )
    environment = {"HOOK": "https://hooks.example.net/x", "TOKEN": "t"}
    overlay = {"notifiers": [{"id": "hook", "type": "webhook", "url": "${HOOK}"}]}
    cfg = load_config(path, environment, settings=overlay)
    assert cfg.notifiers[0]["headers"] == {"Authorization": "Bearer t"}, "the YAML headers reach the builder"
    disabled = {"notifiers": [{"id": "hook", "type": "webhook", "url": "${HOOK}", "enabled": False}]}
    merged = config.load_document(path, settings=disabled)
    assert merged["notifiers"][0]["headers"] == {"Authorization": "Bearer ${TOKEN}"}


def test_an_overlay_can_reference_a_file_secret(tmp_path):
    secret_file = tmp_path / "hook"
    secret_file.write_text(SECRET)
    path = write_config(tmp_path, {})
    overlay = {"notifiers": [{"id": "hook", "type": "discord_webhook", "url": "${HOOK_FILE}"}]}
    cfg = load_config(path, {"HOOK_FILE": str(secret_file)}, settings=overlay)
    assert cfg.notifiers[0]["url"] == SECRET, "the documented ${NAME_FILE} form must resolve from a file"


def test_concurrent_saves_never_reuse_a_revision(tmp_path, monkeypatch):
    original = load_settings_document

    def slow(path):
        time.sleep(0.01)  # widen the window a missing writer lock would lose a revision in
        return original(path)

    monkeypatch.setattr("advisory_radar.settings.load_settings_document", slow)
    overlay_path = settings_path(tmp_path / "state.json")
    failures: list[Exception] = []

    def save(index: int) -> None:
        try:
            save_settings(overlay_path, {"poll_interval": f"{index + 1}m"}, now=NOW + index)
        except Exception as exc:  # a failure is the test result
            failures.append(exc)

    workers = [threading.Thread(target=save, args=(index,)) for index in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert failures == []
    assert load_settings_document(overlay_path)["revision"] == 4, "every save must advance the revision once"


def test_a_refused_sighup_reload_keeps_the_secret_out_of_its_reason(tmp_path, caplog):
    secret = "https://hooks.example.net/SUPERSECRET-BUILDER-VALUE"
    path = write_config(tmp_path, {})
    runtime = Runtime.build(path, {"HOOK": secret})
    save_settings(
        settings_path(runtime.cfg.state_path),
        {"notifiers": [{"id": "x", "type": "ntfy", "url": "${HOOK}", "topic": "advisories", "priority": "${HOOK}"}]},
        now=NOW,
    )
    try:
        with caplog.at_level(logging.ERROR, logger="advisory_radar"):
            cli._reload_blocking(runtime)
        assert "keeping the running configuration" in caplog.text
        assert "int() argument" in caplog.text or "invalid literal" in caplog.text, "the reason is logged"
        assert "SUPERSECRET-BUILDER-VALUE" not in caplog.text, "the expanded secret never reaches the log"
        assert runtime.cfg.poll_interval_seconds == 900
    finally:
        runtime.detach_redaction()


def test_a_pass_queued_before_a_reload_keeps_its_redaction(tmp_path, caplog):
    # A pass can hold a snapshot of the old configuration while it waits for the state lock, and run after the
    # reload published. Its secrets are only filtered if the filter it was built under is still installed.
    old_only = "OLD-ONLY-SECRET-VALUE"
    path = write_config(
        tmp_path,
        {"sources": [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/${SOURCE_ID}"}]},
    )
    runtime = Runtime.build(path, {"SOURCE_ID": old_only})
    write_config(tmp_path, {})  # the reloaded configuration no longer references the value
    save_overlay(tmp_path, {"poll_interval": "30s"})
    runtime.reload(blocking=False)
    assert runtime.cfg.sources == ()
    with caplog.at_level(logging.ERROR, logger="advisory_radar"):
        LOG.error("source %s failed", old_only)  # the queued pass has not run yet
    assert old_only not in caplog.text, "the old snapshot's secrets are still filtered after the swap"


def test_a_queued_pass_with_an_overlapping_secret_stays_redacted(tmp_path, caplog):
    # The old value is a prefix of the new one. Two filters applied in sequence would let the old one replace
    # "feed" and leave "_private_value" for the new filter to miss; one cumulative filter, longest first,
    # redacts the whole value.
    path = write_config(
        tmp_path,
        {"sources": [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/${OLD_ID}"}]},
    )
    # the same process environment serves both configurations; only the references differ
    runtime = Runtime.build(path, {"OLD_ID": "feed", "NEW_ID": "feed_private_value"})
    write_config(
        tmp_path,
        {"sources": [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/${NEW_ID}"}]},
    )
    save_overlay(tmp_path, {"poll_interval": "30s"})
    runtime.reload(blocking=False)
    with caplog.at_level(logging.ERROR, logger="advisory_radar"):
        LOG.error("source %s failed", "feed_private_value")  # the queued pass, running after the swap
    assert "private_value" not in caplog.text, "a short old secret must not hide the tail of a new one"
    assert "[redacted]" in caplog.text


def test_sighup_reloads_the_running_process(tmp_path, monkeypatch):
    path = write_config(tmp_path, {})
    runtime = Runtime.build(path, {})
    save_overlay(tmp_path, {"poll_interval": "30s"})
    registered = []
    monkeypatch.setattr(cli.signal, "signal", lambda signum, handler: registered.append((signum, handler)))
    try:
        assert cli.install_sighup(runtime) is True
        assert registered and registered[0][0] == signal.SIGHUP
        worker = registered[0][1](signal.SIGHUP, None)
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert runtime.cfg.poll_interval_seconds == 30
    finally:
        runtime.detach_redaction()


def test_a_refused_sighup_reload_keeps_the_running_configuration(tmp_path, caplog):
    path = write_config(tmp_path, {})
    runtime = Runtime.build(path, {})
    settings_path(runtime.cfg.state_path).write_text("{not json")
    try:
        with caplog.at_level(logging.ERROR, logger="advisory_radar"):
            cli._reload_blocking(runtime)
        assert runtime.cfg.poll_interval_seconds == 900
        assert "keeping the running configuration" in caplog.text
        assert "is not JSON" in caplog.text, "the refusal must say why, not only that it happened"
    finally:
        runtime.detach_redaction()


# --- the scheduler ---------------------------------------------------------------------------


class Wake:
    """A wake event whose wait records the timeout; the default answers "the interval elapsed"."""

    def __init__(self) -> None:
        self.waits: list[int] = []
        self.answer = False

    def wait(self, timeout: int) -> bool:
        self.waits.append(timeout)
        return self.answer

    def clear(self) -> None:
        self.answer = False

    def set(self) -> None:
        self.answer = True


def test_the_scheduler_reads_the_reloaded_interval_on_the_next_pass(tmp_path, monkeypatch):
    path = write_config(tmp_path, {})
    runtime = Runtime.build(path, {})
    overlay = settings_path(runtime.cfg.state_path)
    wake = Wake()
    runtime.wake = wake
    stopping = threading.Event()
    passes: list[int] = []

    def fake_pass(cfg, sources, notifiers, **kwargs):
        passes.append(cfg.poll_interval_seconds)
        if len(passes) == 1:
            save_settings(overlay, {"poll_interval": "30s"}, now=1)
            runtime.reload(blocking=False)
        else:
            stopping.set()
        return 0

    monkeypatch.setattr(cli.pipeline, "run_pass", fake_pass)
    try:
        cli.run_scheduler(runtime, stopping)
        assert passes == [900, 30]
        # each pass runs under its own snapshot (900, then 30) and each wait follows the live interval at
        # the time it waits: the reload during the first pass is already in force for the first wait
        assert wake.waits == [30, 30]
    finally:
        runtime.detach_redaction()


def test_a_reload_restarts_the_wait_with_the_new_interval(tmp_path):
    path = write_config(tmp_path, {})
    runtime = Runtime.build(path, {})
    wake = Wake()
    runtime.wake = wake
    waits = wake.waits

    def wait_then_reload(timeout: int) -> bool:
        waits.append(timeout)
        if len(waits) == 1:
            save_overlay(tmp_path, {"poll_interval": "30s"})
            runtime.reload(blocking=False)  # sets the real event; this fake ignores the setter
            return True
        return False

    wake.wait = wait_then_reload  # type: ignore[method-assign]
    try:
        cli._wait_for_next_pass(runtime, threading.Event())
        assert waits == [900, 30], "the outstanding wait is recalculated with the reloaded interval"
        stopping = threading.Event()
        stopping.set()
        waits.clear()
        cli._wait_for_next_pass(runtime, stopping)
        assert waits == [], "a stop is seen before another wait starts"
    finally:
        runtime.detach_redaction()


def test_a_pass_that_started_keeps_the_plugins_it_started_with(tmp_path, monkeypatch):
    path = write_config(tmp_path, {"notifiers": [{"id": "base", "type": "webhook", "url": "${BASE_HOOK}"}]})
    runtime = Runtime.build(path, {"BASE_HOOK": SECRET})
    overlay = settings_path(runtime.cfg.state_path)
    old_sources, old_notifiers = runtime.sources, runtime.notifiers
    runtime.wake = Wake()
    stopping = threading.Event()
    seen = {}

    def fake_pass(cfg, sources, notifiers, **kwargs):
        seen["sources"], seen["notifiers"] = sources, notifiers
        # a reload completes while this pass is "running": its argument list must not change
        save_settings(overlay, {"poll_interval": "30s"}, now=1)
        runtime.reload(blocking=False)
        stopping.set()
        return 0

    monkeypatch.setattr(cli.pipeline, "run_pass", fake_pass)
    try:
        cli.run_scheduler(runtime, stopping)
        assert seen["sources"] is old_sources and seen["notifiers"] is old_notifiers
        assert runtime.sources is not old_sources, "the next pass reads the reloaded plugins"
    finally:
        runtime.detach_redaction()


# --- the one-shot commands keep working ------------------------------------------------------


def test_the_sources_commands_still_work_with_an_overlay(tmp_path, capsys):
    path = write_config(
        tmp_path,
        {"sources": [{"id": "vendor", "type": "rss", "url": "https://feeds.example.net/security.xml"}]},
    )
    save_overlay(tmp_path, {"poll_interval": "30s"})
    assert cli.main(["sources", "list"], env={}) == 0
    assert "rss:" in capsys.readouterr().out

    body = (
        b'<?xml version="1.0"?><rss version="2.0"><channel><title>V</title>'
        b"<link>https://feeds.example.net/</link><item><title>CVE-2026-1 fixed</title>"
        b"<link>https://feeds.example.net/a</link><guid>a1</guid></item></channel></rss>"
    )

    def http(method, url, headers, payload):
        return 200, {}, body

    assert cli.main(["--config", str(path), "sources", "test", "vendor"], env={}, http=http) == 0
    printed = capsys.readouterr().out
    assert "a1\tCVE-2026-1 fixed\thttps://feeds.example.net/a" in printed
    assert not (tmp_path / "state.json").exists(), "sources test still writes no state"


def test_test_notify_sends_through_a_notifier_the_overlay_added(tmp_path):
    path = write_config(tmp_path, {})
    save_overlay(tmp_path, {"notifiers": [{"id": "ops", "type": "webhook", "url": "${OPS_HOOK}"}]})
    calls: list[str] = []

    def http(method, url, headers, payload):
        calls.append(url)
        return 204, {}, b""

    assert cli.main(["--config", str(path), "test-notify"], env={"OPS_HOOK": SECRET}, http=http) == 0
    assert calls == [SECRET]


# --- a per-source poll interval ---------------------------------------------------------------


def test_a_source_may_carry_its_own_poll_interval(tmp_path):
    path = write_config(
        tmp_path,
        {
            "sources": [
                {"id": "slow", "type": "rss", "url": "https://feeds.example.com/slow.xml", "interval": "2h"},
                {"id": "default", "type": "rss", "url": "https://feeds.example.com/default.xml"},
            ]
        },
    )
    cfg = load_config(path, {})
    assert cfg.source_intervals == {"slow": 7200}, "only the source that names one is throttled"
    assert cfg.poll_interval_seconds == 900, "a source interval does not move the global pace"
    assert cfg.sources[0]["interval"] == "2h"


@pytest.mark.parametrize(("interval", "message"), [("banana", "must look like"), ("0m", "greater than zero")])
def test_an_invalid_source_interval_is_refused(tmp_path, interval, message):
    path = write_config(
        tmp_path,
        {"sources": [{"id": "slow", "type": "rss", "url": "https://feeds.example.com/slow.xml", "interval": interval}]},
    )
    with pytest.raises(ConfigError) as exc:
        load_config(path, {})
    assert "slow: interval" in str(exc.value)
    assert message in str(exc.value)


def test_the_overlay_can_set_an_interval_for_a_yaml_source_or_one_it_adds(tmp_path):
    path = write_config(
        tmp_path,
        {"sources": [{"id": "edit", "type": "rss", "url": "https://feeds.example.com/edit.xml"}]},
    )
    cfg = load_config(
        path,
        {},
        settings={
            "sources": {"edit": {"interval": "30m"}},
            "sources_added": [
                {
                    "id": "added",
                    "type": "rss",
                    "url": "https://feeds.example.com/added.xml",
                    "interval": "45m",
                }
            ],
        },
    )
    assert cfg.source_intervals == {"edit": 1800, "added": 2700}
    assert cfg.sources[0]["interval"] == "30m"


def test_a_bad_overlay_interval_fails_with_the_message_the_yaml_gives(tmp_path):
    source = {"id": "edit", "type": "rss", "url": "https://feeds.example.com/edit.xml"}
    yaml_path = write_config(tmp_path, {"sources": [{**source, "interval": "banana"}]}, name="bad.yml")
    with pytest.raises(ConfigError) as from_yaml:
        load_config(yaml_path, {})
    overlay_path = write_config(tmp_path, {"sources": [source]})
    with pytest.raises(ConfigError) as from_overlay:
        load_config(overlay_path, {}, settings={"sources": {"edit": {"interval": "banana"}}})
    assert str(from_overlay.value) == str(from_yaml.value)


def test_a_per_source_edit_still_refuses_a_key_outside_enabled_tag_and_interval(tmp_path):
    path = write_config(
        tmp_path,
        {"sources": [{"id": "edit", "type": "rss", "url": "https://feeds.example.com/edit.xml"}]},
    )
    with pytest.raises(ConfigError, match="unknown keys"):
        load_config(path, {}, settings={"sources": {"edit": {"url": "https://elsewhere.example.net/x"}}})


# --- the delivery policy and the signed-webhook secret -----------------------------------------


def test_digest_and_quiet_hours_are_overlay_writable(tmp_path):
    path = write_config(tmp_path, {})
    cfg = load_config(path, {}, settings={"digest": True, "quiet_hours": "22:00-07:00"})
    assert cfg.digest is True
    assert cfg.quiet_hours == delivery.QuietHours(22 * 60, 7 * 60)
    # The form stores the fields even when cleared, so an unticked box and an empty window override the YAML.
    off = load_config(path, {}, settings={"digest": False, "quiet_hours": ""})
    assert off.digest is False and off.quiet_hours is None


def test_the_yaml_can_set_the_delivery_policy(tmp_path):
    cfg = load_config(write_config(tmp_path, {"digest": True, "quiet_hours": "22:00-07:00"}), {})
    assert cfg.digest is True and cfg.quiet_hours == delivery.QuietHours(22 * 60, 7 * 60)
    assert load_config(write_config(tmp_path, {"digest": False, "quiet_hours": ""}), {}).quiet_hours is None


def test_a_bad_quiet_hours_window_is_refused_without_echoing_it(tmp_path):
    for bad, echo in (("night-shift", "night-shift"), ("24:00-07:00", "24:00"), (2200, "2200")):
        path = write_config(tmp_path, {})
        with pytest.raises(ConfigError) as caught:
            load_config(path, {}, settings={"quiet_hours": bad})
        assert "22:00-07:00" in str(caught.value), bad
        assert echo not in str(caught.value), f"the refusal repeated the value: {caught.value}"


def test_a_notifier_secret_in_the_overlay_must_be_a_reference(tmp_path):
    path = write_config(tmp_path, {})
    with pytest.raises(ConfigError) as caught:
        load_config(
            path,
            {},
            settings={
                "notifiers": [{"id": "hook", "type": "webhook", "url": "${HOOK}", "secret": "s3cret-literal-value"}]
            },
        )
    assert "secret" in str(caught.value) and "reference" in str(caught.value)
    assert "s3cret-literal-value" not in str(caught.value)


def test_a_yaml_notifier_secret_survives_an_overlay_notifier_save(tmp_path):
    path = write_config(
        tmp_path,
        {"notifiers": [{"id": "hook", "type": "webhook", "url": "${HOOK}", "secret": "${SIGNING}"}]},
    )
    environment = {"HOOK": "https://hooks.example.net/x", "SIGNING": "s3cret"}
    # The notifier form rewrites the list; the entry it submits carries only the fields the form edits.
    overlay = {"notifiers": [{"id": "hook", "type": "webhook", "url": "${HOOK}"}]}
    document = config.load_document(path, settings=overlay)
    assert document["notifiers"][0]["secret"] == "${SIGNING}", "the overlay entry inherits the YAML secret by id"
    cfg = load_config(path, environment, settings=overlay)
    assert cfg.notifiers[0]["secret"] == "s3cret", "the builder still sees the signing secret"
    # A reference the overlay states itself wins over the file's, exactly as every other overlay value does.
    own = {"notifiers": [{"id": "hook", "type": "webhook", "url": "${HOOK}", "secret": "${OTHER}"}]}
    assert load_config(path, {**environment, "OTHER": "other"}, settings=own).notifiers[0]["secret"] == "other"
