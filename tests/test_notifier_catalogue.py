"""The notifier catalogue is the single owner of a notifier type's metadata (U05, #103).

It mirrors ``tests/test_catalogue.py``: four consumers could drift apart (the builders, the config key
allowlist, the settings-overlay rules and ``docs/notifiers.md``), and every test here pins one of them to
``NOTIFIER_SPECS``. Every example is loaded and built, so a snippet in the catalogue is a config a user could
actually run, and the form is pinned to what the overlay accepts, so a notifier the page offers can be saved.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from advisory_radar import config
from advisory_radar.config import CREDENTIAL_DESTINATION_KEYS, NOTIFIER_SECRET_KEYS, ConfigError, load_config
from advisory_radar.notifiers import NOTIFIER_BUILDERS, build_notifier
from advisory_radar.settings import validate_settings

NOTIFIERS_DOC = Path(__file__).parent.parent / "docs" / "notifiers.md"
ENV_PLACEHOLDER = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")
#: Keys that are structure, not a property of one type: every entry has them and no form field edits them.
STRUCTURAL = {"id", "type", "enabled"}


def specs() -> dict:
    """The catalogue, imported on use so a missing name fails each test with its own error, not the whole run."""
    from advisory_radar.catalogue import NOTIFIER_SPECS

    return NOTIFIER_SPECS


def keys_of(spec) -> set[str]:
    return {*spec.required, *spec.optional}


def config_file(tmp_path: Path, *, notifiers: list[dict], extra: dict | None = None) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "config.yml"
    document = {"sources": [], "notifiers": notifiers, "state_path": str(tmp_path / "state.json"), **(extra or {})}
    path.write_text(yaml.safe_dump(document))
    return path


def test_every_builder_has_exactly_one_spec():
    assert specs(), "the catalogue must not be empty"
    assert set(NOTIFIER_BUILDERS) == set(specs())
    for kind, spec in specs().items():
        assert spec.kind == kind


def test_config_allows_the_registry_keys():
    documented = {key for spec in specs().values() for key in keys_of(spec)}
    assert {"id", "type"} | documented == config._NOTIFIER_KEYS


def test_secret_keys_are_exactly_the_reference_only_keys_a_type_reads():
    for kind, spec in specs().items():
        assert set(spec.secret_keys) == keys_of(spec) & set(NOTIFIER_SECRET_KEYS), kind
        assert set(spec.secret_keys) <= {*spec.required, *spec.optional}
    assert {key for spec in specs().values() for key in spec.secret_keys} == set(NOTIFIER_SECRET_KEYS), (
        "every reference-only key the overlay knows must belong to some type"
    )


def test_a_credential_destination_the_overlay_pins_is_a_plain_key_of_its_type():
    # ``CREDENTIAL_DESTINATION_KEYS`` names keys the overlay may write as text but pins to the YAML's value, so
    # the form has to be able to render them as ordinary fields of that very type.
    for kind, destination in CREDENTIAL_DESTINATION_KEYS.items():
        spec = specs()[kind]
        for key in destination:
            assert key in keys_of(spec), (kind, key)
            assert key not in spec.secret_keys, (kind, key)


def test_yaml_only_keys_are_never_written_by_the_form():
    from advisory_radar.web import notifier_form_keys

    yaml_only = {key for spec in specs().values() for key in spec.yaml_only}
    assert yaml_only == {"headers"}, "a new YAML-only key is a decision: pin it here and explain it in the docs"
    assert specs()["webhook"].yaml_only == ("headers",)
    for kind, spec in specs().items():
        assert not set(spec.yaml_only) & set(notifier_form_keys(spec)), kind
        assert set(spec.yaml_only) <= keys_of(spec), kind
        assert not set(spec.yaml_only) & set(spec.required), (
            f"{kind}: a required key that only the YAML can write would make the type impossible to add here"
        )
        for key in spec.yaml_only:
            with pytest.raises(ConfigError, match="cannot be written by the overlay"):
                validate_settings({"notifiers": [{"id": "n", "type": kind, key: {"X-Key": "value"}}]})


def test_the_form_keys_are_the_plain_keys_of_the_catalogue():
    from advisory_radar.web import notifier_form_keys

    for kind, spec in specs().items():
        plain = keys_of(spec) - STRUCTURAL - set(spec.secret_keys) - set(spec.yaml_only)
        assert set(notifier_form_keys(spec)) == plain, kind
        assert not plain & set(NOTIFIER_SECRET_KEYS), f"{kind}: a credential position is never a plain text field"
        assert plain <= config._NOTIFIER_KEYS
    every = {key for spec in specs().values() for key in notifier_form_keys(spec)}
    assert every == {"topic", "priority", "host", "port", "from", "to", "username", "use_tls", "implicit_tls"}


def test_every_example_validates_and_builds(tmp_path):
    for kind, spec in specs().items():
        example = spec.example
        assert spec.docs_anchor == f"docs/notifiers.md#{kind}"
        assert example["type"] == kind
        assert set(spec.required) <= set(example), f"{kind}: the example must show every required key"
        assert set(example) <= {"id", "type"} | keys_of(spec)
        for key in spec.secret_keys:
            if key in example:
                assert ENV_PLACEHOLDER.fullmatch(example[key]), f"{kind}: {key} must be a ${{NAME}} reference"
        for value in example.values():
            if isinstance(value, str) and "://" in value:
                assert value.split("://", 1)[1].split("/", 1)[0].endswith(".example.net"), f"{kind}: {value}"
        env = {name: "dummy-value" for name in ENV_PLACEHOLDER.findall(yaml.safe_dump(example))}
        cfg = load_config(config_file(tmp_path / kind, notifiers=[example]), env)
        assert [entry["type"] for entry in cfg.notifiers] == [kind]
        notifier = build_notifier(dict(cfg.notifiers[0]), env)
        assert notifier.id == example["id"]
        assert callable(notifier.send)


def test_a_key_is_required_exactly_when_the_builder_cannot_do_without_it():
    for kind, spec in specs().items():
        minimal = {"id": "n", "type": kind, **{key: spec.example[key] for key in spec.required}}
        assert build_notifier(dict(minimal), {}).id == "n", f"{kind}: the required keys alone must build"
        for key in spec.required:
            without = {name: value for name, value in minimal.items() if name != key}
            with pytest.raises(KeyError):
                build_notifier(without, {})


def test_the_form_can_save_every_type_it_offers(tmp_path):
    """The "in step" pin: what the page can produce for a type is exactly what the overlay accepts.

    The entry is the example minus the YAML-only keys, which is what the form submits when every field is
    filled. It has to load when the YAML lists its variables, and a literal in any reference position has to be
    refused, so a catalogue entry cannot promise a field the overlay would reject or a literal it would store.
    """
    for kind, spec in specs().items():
        entry = {key: value for key, value in spec.example.items() if key not in spec.yaml_only}
        names = sorted(set(ENV_PLACEHOLDER.findall(yaml.safe_dump(entry))))
        env = {name: "dummy-value" for name in names}
        allowed = config_file(tmp_path / kind / "allowed", notifiers=[], extra={"overlay_references": names})
        cfg = load_config(allowed, env, settings={"notifiers": [entry]})
        assert [item["type"] for item in cfg.notifiers] == [kind]
        if names:
            closed = config_file(tmp_path / kind / "closed", notifiers=[])
            with pytest.raises(ConfigError, match="overlay_references"):
                load_config(closed, env, settings={"notifiers": [entry]})
        for key in spec.secret_keys:
            with pytest.raises(ConfigError, match="reference"):
                load_config(allowed, env, settings={"notifiers": [{**entry, key: "a-literal-secret"}]})


def _cell_keys(cell: str) -> tuple[str, ...]:
    if cell.strip().strip("`") in {"", "-", "—", "none", "(none)"}:
        return ()
    return tuple(part.strip().strip("`") for part in cell.split(","))


def _doc_rows() -> dict[str, tuple[str, ...]]:
    """Parse the catalogue table into kind -> (summary, required, optional, references, yaml-only)."""
    text = NOTIFIERS_DOC.read_text(encoding="utf-8")
    assert text.startswith("# Notifiers\n"), "docs/notifiers.md must document the notifiers"
    rows: dict[str, tuple] = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not cells or cells[0].lower() == "kind" or set(cells[0]) <= {"-", ":", " "}:
            continue
        kind = cells[0].strip("`")
        assert kind not in rows, f"docs/notifiers.md has two rows for {kind}"
        rows[kind] = (cells[1], *(_cell_keys(cell) for cell in cells[2:6]))
    return rows


def test_the_notifiers_doc_table_matches_the_registry():
    rows = _doc_rows()
    assert set(rows) == set(specs())
    for kind, spec in specs().items():
        summary, required, optional, references, yaml_only = rows[kind]
        assert summary.replace("`", "") == spec.summary.replace("`", ""), f"notifiers summary drifted for {kind}"
        assert required == spec.required, f"notifiers required keys drifted for {kind}"
        assert optional == spec.optional, f"notifiers optional keys drifted for {kind}"
        assert references == spec.secret_keys, f"notifiers reference keys drifted for {kind}"
        assert yaml_only == spec.yaml_only, f"notifiers YAML-only keys drifted for {kind}"


def test_every_type_has_a_heading_for_its_docs_anchor():
    text = NOTIFIERS_DOC.read_text(encoding="utf-8")
    for kind, spec in specs().items():
        path, _, anchor = spec.docs_anchor.partition("#")
        assert path == "docs/notifiers.md" and anchor == kind
        assert re.search(rf"^#{{2,4}} {re.escape(kind)}\s*$", text, re.M), f"docs/notifiers.md has no heading {kind}"


def test_every_example_is_shown_in_the_docs_exactly_as_the_catalogue_has_it():
    """The YAML a reader copies from docs/notifiers.md is the YAML the test suite loaded and built."""
    text = NOTIFIERS_DOC.read_text(encoding="utf-8")
    for kind, spec in specs().items():
        shown = "notifiers:\n" + "".join(
            f"  {line}\n" for line in yaml.safe_dump([spec.example], sort_keys=False).splitlines()
        )
        section = text.split(f"\n## {kind}\n", 1)[1].split("\n## ", 1)[0]
        assert shown in section, f"the {kind} example in docs/notifiers.md drifted from the catalogue"
