"""Command line: run | once | dry-run | test-notify | release-parked | drop-parked."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path

from . import core, pipeline
from .config import ConfigError, collect_secrets, load_config
from .http import Http, urllib_http
from .state import state_lock

LOG = logging.getLogger("advisory_radar")
DEFAULT_CONFIG = Path("config/config.yml")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="advisory-radar",
        description="Watch configurable security sources and deliver deduplicated, "
        "severity-scored alerts to configured notifiers.",
    )
    import os

    default_config = Path(os.environ.get("ADVISORY_RADAR_CONFIG", DEFAULT_CONFIG))
    parser.add_argument(
        "--config",
        type=Path,
        default=default_config,
        help="YAML config path (default $ADVISORY_RADAR_CONFIG or config/config.yml)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="poll sources on the configured interval until stopped")
    sub.add_parser("once", help="run one pass")
    sub.add_parser("dry-run", help="run one pass, print what would be sent, write nothing")
    sub.add_parser("test-notify", help="send one test message through every notifier")
    sub.add_parser("release-parked", help="queue the parked messages again and exit")
    sub.add_parser("drop-parked", help="record the parked messages as handled and discard them")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    http: Http = urllib_http,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    import os

    environment = os.environ if env is None else env
    args = _parser().parse_args(argv)
    if not LOG.handlers and not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="advisory-radar: %(message)s", stream=sys.stderr)
    try:
        cfg = load_config(args.config, environment)
    except ConfigError as exc:
        LOG.error("config: %s", exc)
        return 1
    redactor = pipeline.attach_redaction(
        [environment[name] for name in collect_secrets(cfg, environment) if environment.get(name)]
    )
    try:
        sources, notifiers = pipeline.build_plugins(cfg, environment)
        if args.command == "release-parked":
            with state_lock(cfg.state_path):
                return core.manage_parked(cfg.state_path, release=True, now=int(clock()))
        if args.command == "drop-parked":
            with state_lock(cfg.state_path):
                return core.manage_parked(cfg.state_path, release=False, now=int(clock()))
        if args.command == "test-notify":
            entry = {
                "kind": "test",
                "tag": "warning",
                "title": "WARNING: advisory-radar test notification",
                "body": "\n- **Severity:** test\n- **Note:** if you read this, delivery works.",
                "ids": ["TEST"],
                "cves": [],
                "levels": {},
                "source": "advisory-radar",
                "link": "",
            }
            statuses = [notifier.send(entry, http) for notifier in notifiers]
            LOG.info("test-notify: %s", ", ".join(f"{n.id}={s}" for n, s in zip(notifiers, statuses, strict=True)))
            return 0 if notifiers and all(200 <= s < 300 for s in statuses) else 1
        if args.command == "run":
            while True:
                code = pipeline.run_pass(cfg, sources, notifiers, http=http, clock=clock, sleep=sleep)
                sleep(cfg.poll_interval_seconds)
                if code:
                    LOG.warning("pass exited %d; continuing on schedule", code)
        return pipeline.run_pass(
            cfg, sources, notifiers, http=http, clock=clock, sleep=sleep, dry_run=args.command == "dry-run"
        )
    finally:
        LOG.removeFilter(redactor)
