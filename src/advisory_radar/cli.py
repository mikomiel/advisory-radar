"""Command line: run | once | dry-run | test-notify | release-parked | drop-parked | sources."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path

from . import core, pipeline
from .catalogue import SOURCE_SPECS
from .config import Config, ConfigError, load_config, secret_values
from .http import Http, urllib_http
from .state import state_lock

LOG = logging.getLogger("advisory_radar")
DEFAULT_CONFIG = Path("config/config.yml")


def _non_negative(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return value


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
    sources = sub.add_parser("sources", help="inspect the built-in source catalogue, or test one configured source")
    sources_sub = sources.add_subparsers(dest="sources_command", required=True)
    sources_sub.add_parser("list", help="print every built-in kind with its keys (no config file needed)")
    test = sources_sub.add_parser("test", help="fetch one configured source and print its items; nothing is sent")
    test.add_argument("id", help="the id of the configured source")
    test.add_argument("--limit", type=_non_negative, default=10, metavar="N", help="items to print (default 10)")
    return parser


def _terminal(value: object) -> str:
    """One source-controlled field made safe for a tab-separated terminal line.

    A feed's ``guid``, title and link are remote input: an embedded ``ESC`` sequence would drive the
    operator's terminal, and a tab or newline would forge another field or another record. Control
    characters are shown as their escapes rather than dropped, so a surprising source stays visible in
    the output instead of silently changing it.
    """
    out: list[str] = []
    for char in str(value):
        if char == "\t":
            out.append("\\t")
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char.isprintable():
            out.append(char)
        elif ord(char) <= 0xFF:
            out.append(f"\\x{ord(char):02x}")
        else:
            out.append(f"\\u{ord(char):04x}")
    return "".join(out)


def _list_sources() -> int:
    """The catalogue without a config file or any secret, so it is dispatched before ``load_config``."""
    for kind, spec in SOURCE_SPECS.items():
        print(f"{kind}: {spec.summary}")
        print(f"  required: {', '.join(spec.required) or '(none)'}")
        print(f"  optional: {', '.join(spec.optional) or '(none)'}")
        print(f"  docs: {spec.docs_anchor}")
    return 0


def _test_source(cfg: Config, args: argparse.Namespace, http: Http, environment: Mapping[str, str]) -> int:
    """Fetch one source with empty state, print what it returns, and touch nothing else.

    The empty state makes the fetch unconditional (no stored ``ETag``/cursor) and nothing is committed: no
    ``save_state``, no ``source.commit``, not even the state lock. A fault or a truncated window is the exit
    code, because a full window proves the source held more than it returned.
    """
    from .sources import build_source

    entry = next((dict(candidate) for candidate in cfg.sources if candidate["id"] == args.id), None)
    if entry is None:
        LOG.error("sources test: no enabled source has id %r", args.id)
        return 1
    try:
        source = build_source(entry, environment)
    except (ValueError, KeyError) as exc:
        LOG.error("sources test: %s: %s", type(exc).__name__, exc)
        return 1
    try:
        window = source.fetch(http, {})
    except Exception as exc:  # the command reports a source fault as its exit code, not a traceback
        LOG.error("sources test: %s: %s: %s", args.id, type(exc).__name__, exc)
        return 1
    for item in window.items[: args.limit]:
        print(f"{_terminal(item.guid)}\t{_terminal(item.title)}\t{_terminal(item.link)}")
    print(f"{args.id}: {len(window.items)} item(s); truncated: {'yes' if window.truncated else 'no'}")
    return 1 if window.truncated else 0


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
    # The catalogue is static and needs neither the config file nor a secret: listing it must not require
    # either, so it is dispatched before load_config.
    if args.command == "sources" and args.sources_command == "list":
        return _list_sources()
    state_only = args.command in {"release-parked", "drop-parked"}
    try:
        cfg = load_config(args.config, environment, lenient=state_only)
    except ConfigError as exc:
        LOG.error("config: %s", exc)
        return 1
    redactor = pipeline.attach_redaction(secret_values(cfg))
    try:
        if args.command == "sources":
            return _test_source(cfg, args, http, environment)
        # These only touch the state document: no source or notifier is built, so an unrelated plugin with a
        # missing credential cannot block recovery of an existing parked queue.
        if args.command == "release-parked":
            with state_lock(cfg.state_path):
                return core.manage_parked(cfg.state_path, release=True, now=int(clock()))
        if args.command == "drop-parked":
            with state_lock(cfg.state_path):
                return core.manage_parked(cfg.state_path, release=False, now=int(clock()))
        try:
            sources, notifiers = pipeline.build_plugins(cfg, environment)
        except (ValueError, KeyError) as exc:
            # Inside the redacted block: a builder error would otherwise traceback unredacted, and plugin
            # fields are expanded from the environment.
            LOG.error("plugin configuration: %s", exc)
            return 1
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
            import threading

            from .web import create_app

            def one_pass(lock_blocking: bool = True) -> int:
                return pipeline.run_pass(
                    cfg, sources, notifiers, http=http, clock=clock, sleep=sleep, lock_blocking=lock_blocking
                )

            app = create_app(cfg, environment, run_pass=one_pass, sources=sources, notifiers=notifiers)

            stopping = threading.Event()

            def scheduler() -> None:
                while not stopping.is_set():
                    try:
                        code = one_pass()
                        if code:
                            LOG.warning("pass exited %d; continuing on schedule", code)
                    except Exception:  # the schedule must survive any single bad pass
                        LOG.exception("pass raised; continuing on schedule")
                    stopping.wait(cfg.poll_interval_seconds)

            thread = threading.Thread(target=scheduler, daemon=True)
            thread.start()
            import uvicorn

            LOG.info("web UI on http://%s:%d", cfg.web_host, cfg.web_port)
            try:
                uvicorn.run(app, host=cfg.web_host, port=cfg.web_port, log_level="warning")
            finally:
                # Shutdown is not a reason to fetch and notify again: stop the schedule and leave.
                stopping.set()
                thread.join(timeout=5)
            return 0
        return pipeline.run_pass(
            cfg, sources, notifiers, http=http, clock=clock, sleep=sleep, dry_run=args.command == "dry-run"
        )
    finally:
        LOG.removeFilter(redactor)
