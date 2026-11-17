"""The shipped example config must stay loadable, and a fresh copy must start on the quickstart's one secret.

`examples/config.yml` is the first thing a new user copies; a key that drifts
from the parser breaks the documented quickstart silently. Env placeholders are
filled with dummy values so the file is validated without any real secret.

The quickstart's `.env` holds ``ADVISORY_RADAR_AUTH_TOKEN`` and nothing else. A notifier that needs another variable
and is enabled in the example crash-loops the container on its first start, so the example ships its one notifier
disabled: ``enabled: false`` drops the entry from the configuration, and its ``${NAME}`` is not resolved until an
operator turns it on.
"""

import re
from pathlib import Path

from fastapi.testclient import TestClient

from advisory_radar.config import config_from_document, load_config, load_document
from advisory_radar.runtime import Runtime
from advisory_radar.web import create_app

EXAMPLE = Path(__file__).parent.parent / "examples" / "config.yml"


def _dummy_env() -> dict[str, str]:
    names = set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)(?:_FILE)?\}", EXAMPLE.read_text()))
    return {name: "dummy-value" for name in names}


def test_example_config_parses():
    cfg = load_config(EXAMPLE, _dummy_env())
    assert cfg.sources
    assert all(source["id"] and source["type"] for source in cfg.sources)
    # The shipped notifier is disabled, so the validated configuration omits it: read it from the document.
    notifiers = load_document(EXAMPLE)["notifiers"]
    assert notifiers
    assert all(notifier["id"] and notifier["type"] for notifier in notifiers)


def test_a_fresh_copy_starts_with_only_the_login_token(tmp_path):
    """The file a user copies, with only its state path moved off the container's /data onto a temporary directory."""
    text, moved = re.subn(
        r"(?m)^state_path:.*$", f"state_path: {tmp_path}/state.json", EXAMPLE.read_text(encoding="utf-8")
    )
    assert moved == 1, "the example no longer sets state_path on one line, so this test cannot keep off /data"
    copy = tmp_path / "config.yml"
    copy.write_text(text, encoding="utf-8")
    env = {"ADVISORY_RADAR_AUTH_TOKEN": "quickstart-token-0123456789abcdef"}
    runtime = Runtime.build(copy, env)
    assert not runtime.notifiers  # nothing is sent until the operator enables a channel
    assert TestClient(create_app(runtime, env)).get("/healthz").status_code == 200


def test_the_shipped_notifier_is_valid_once_it_is_enabled():
    document = load_document(EXAMPLE)
    for notifier in document["notifiers"]:
        notifier["enabled"] = True
    cfg = config_from_document(document, EXAMPLE, _dummy_env())
    assert [notifier["id"] for notifier in cfg.notifiers] == [notifier["id"] for notifier in document["notifiers"]]
