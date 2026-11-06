"""The shipped example config must stay loadable.

`examples/config.yml` is the first thing a new user copies; a key that drifts
from the parser breaks the documented quickstart silently. Env placeholders are
filled with dummy values so the file is validated without any real secret.
"""

import re
from pathlib import Path

from advisory_radar.config import load_config

EXAMPLE = Path(__file__).parent.parent / "examples" / "config.yml"


def _dummy_env() -> dict[str, str]:
    names = set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)(?:_FILE)?\}", EXAMPLE.read_text()))
    return {name: "dummy-value" for name in names}


def test_example_config_parses():
    cfg = load_config(EXAMPLE, _dummy_env())
    assert cfg.sources and cfg.notifiers
    assert all(source["id"] and source["type"] for source in cfg.sources)
    assert all(notifier["id"] and notifier["type"] for notifier in cfg.notifiers)
