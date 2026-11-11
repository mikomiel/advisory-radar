"""Command line: run | once | dry-run | test-notify | release-parked | drop-parked | sources."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path

from . import core, pipeline
from .catalogue import SOURCE_SPECS
from .config import Config, ConfigError, load_config, secret_values
from .http import Http, urllib_http
from .runtime import Runtime, read_config
from .state import SourceError, serialize_json
from .storage import StoreUnavailable, store_for

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
    migrate = sub.add_parser("migrate", help="copy the state document from the configured store to another one")
    # Both spellings of the global option work for this command, and a default here would overwrite a
    # ``--config`` given before the subcommand: SUPPRESS leaves the namespace as the global parser set it.
    migrate.add_argument(
        "--config", type=Path, default=argparse.SUPPRESS, help="YAML config path (default: the global --config)"
    )
    migrate.add_argument(
        "--to",
        required=True,
        help="target store: sqlite:///path/to/state.db or postgresql://host/database",
    )
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


def _reload_blocking(runtime: Runtime) -> None:
    """The SIGHUP action: rebuild off to the side and swap under the lock.

    A refused reload is logged and the process keeps running with the configuration it has: a
    typo in a mounted file must not turn a signal into an outage.
    """
    try:
        runtime.reload(blocking=True)
    except Exception as exc:  # a reload must be able to fail without taking the process down
        # The redaction filter removes exc_info from a record, so the reason is put into the message itself:
        # a refusal the operator cannot diagnose is barely better than a crash.
        reason = pipeline.redact(f"{type(exc).__name__}: {exc}", secret_values(runtime.cfg))
        LOG.error("reload refused; keeping the running configuration: %s", reason)
    else:
        LOG.info("reload applied: overlay revision %s", runtime.overlay["revision"])


def sighup_handler(runtime: Runtime) -> Callable[[int, object], threading.Thread]:
    """The SIGHUP handler: reload in a background thread and return it.

    A signal handler must not run a whole pass, and the thread it starts waits for the state lock.
    Returning the thread is harmless when a signal delivers it and lets a test join the work.
    """

    def handle(signum: int, frame: object) -> threading.Thread:
        LOG.info("SIGHUP: reloading the configuration")
        worker = threading.Thread(target=_reload_blocking, args=(runtime,), daemon=True)
        worker.start()
        return worker

    return handle


def install_sighup(runtime: Runtime) -> bool:
    """Register the reload handler on SIGHUP where the platform has one; returns whether it did."""
    if not hasattr(signal, "SIGHUP"):
        return False
    try:
        signal.signal(signal.SIGHUP, sighup_handler(runtime))
    except ValueError:  # a caller that runs main() off the main thread cannot own signal handlers
        LOG.warning("SIGHUP reload is unavailable outside the main thread")
        return False
    return True


def _migrate(cfg: Config, target_value: str) -> int:
    """Copy the state document from the configured store to ``--to``, refusing to overwrite a document.

    The source is only read, so no lock is taken: every store's save is atomic, which makes one ``load()`` a
    consistent snapshot even while a pass runs. The target is checked before it is written, because a
    migration that replaced a live document would destroy the only record of what had already been sent.
    """
    if target_value == cfg.storage:
        LOG.error("--to is the configured store, so a migration would move nothing")
        return 1
    try:
        target = store_for(target_value, cfg.state_path)
    except ValueError as exc:
        LOG.error("%s", exc)
        return 1
    source = cfg.store()
    try:
        document = source.load()
    except (SourceError, StoreUnavailable) as exc:
        LOG.error("%s", exc)
        return 1
    if document is None:
        LOG.error("%s holds no state document yet; nothing to migrate", source)
        return 1
    try:
        if target.load() is not None:
            LOG.error("%s already holds a state document; refusing to overwrite it", target)
            return 1
        target.save(document)
    except (SourceError, StoreUnavailable, OSError) as exc:
        LOG.error("%s", exc)
        return 1
    # Only the stores' reprs are shown: a PostgreSQL locator carries a password, and this line is output an
    # operator may paste into an issue.
    print(f"migrated the state document ({len(serialize_json(document))} bytes) from {source} to {target}")
    return 0


def run_scheduler(
    runtime: Runtime,
    stopping: threading.Event,
    *,
    http: Http = urllib_http,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """One pass at a time, then wait the interval the live runtime reports.

    The configuration and the plugins are read together at the start of each pass, so a reload
    between two passes applies to the next one; a pass that already started keeps the plugins it
    was given, because swapping mid-pass could deliver one advisory through two configurations.
    """
    while not stopping.is_set():
        cfg, sources, notifiers = runtime.snapshot()
        try:
            code = pipeline.run_pass(cfg, sources, notifiers, http=http, clock=clock, sleep=sleep)
            if code:
                LOG.warning("pass exited %d; continuing on schedule", code)
        except Exception:  # the schedule must survive any single bad pass
            LOG.exception("pass raised; continuing on schedule")
        _wait_for_next_pass(runtime, stopping)


def _wait_for_next_pass(runtime: Runtime, stopping: threading.Event) -> None:
    """Wait for the next pass, restarting the wait when a reload lands.

    The wait follows the *live* interval, not the one the finished pass ran under: shortening the interval
    and then sleeping out the old one would leave the scheduler idle while /readyz judges by the new
    interval and reports a healthy instance unready. The wake event is also what shutdown sets, so a stop is
    seen without waiting for the interval to expire.
    """
    while not stopping.is_set():
        if runtime.wake.wait(runtime.cfg.poll_interval_seconds):
            runtime.wake.clear()
            continue
        return


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
    if args.command == "migrate":
        try:
            cfg = load_config(args.config, environment, lenient=True)
        except ConfigError as exc:
            LOG.error("config: %s", exc)
            return 1
        redactor = pipeline.attach_redaction(secret_values(cfg))
        try:
            return _migrate(cfg, args.to)
        finally:
            LOG.removeFilter(redactor)
    if args.command in {"release-parked", "drop-parked"}:
        # State-only recovery. It needs the state path and nothing else: no source or notifier is built,
        # so an unrelated plugin with a missing credential cannot block recovery; the overlay cannot
        # change the state path, and an unreadable one must not block releasing a queue.
        try:
            cfg = load_config(args.config, environment, lenient=True)
        except ConfigError as exc:
            LOG.error("config: %s", exc)
            return 1
        redactor = pipeline.attach_redaction(secret_values(cfg))
        store = cfg.store()
        try:
            with store.lock():
                return core.manage_parked(store, release=args.command == "release-parked", now=int(clock()))
        except StoreUnavailable as exc:
            LOG.error("%s; the queue was not changed", exc)
            return 1
        finally:
            LOG.removeFilter(redactor)
    if args.command == "sources":
        # `sources test` builds only the source it tests: an unrelated plugin with a missing
        # credential or an unbuildable field must not block inspecting one feed.
        try:
            cfg, _, _ = read_config(args.config, environment)
        except ConfigError as exc:
            LOG.error("config: %s", exc)
            return 1
        redactor = pipeline.attach_redaction(secret_values(cfg))
        try:
            return _test_source(cfg, args, http, environment)
        finally:
            LOG.removeFilter(redactor)
    try:
        runtime = Runtime.build(args.config, environment, clock=clock)
    except ConfigError as exc:
        LOG.error("config: %s", exc)
        return 1
    try:
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
            statuses = [notifier.send(entry, http) for notifier in runtime.notifiers]
            LOG.info(
                "test-notify: %s", ", ".join(f"{n.id}={s}" for n, s in zip(runtime.notifiers, statuses, strict=True))
            )
            return 0 if runtime.notifiers and all(200 <= s < 300 for s in statuses) else 1
        if args.command == "run":
            from .web import create_app

            def one_pass(lock_blocking: bool = True) -> int:
                """The web UI's "run now", from the same live snapshot the schedule uses."""
                cfg, sources, notifiers = runtime.snapshot()
                return pipeline.run_pass(
                    cfg, sources, notifiers, http=http, clock=clock, sleep=sleep, lock_blocking=lock_blocking
                )

            app = create_app(runtime, environment, run_pass=one_pass)
            stopping = threading.Event()
            thread = threading.Thread(
                target=run_scheduler,
                args=(runtime, stopping),
                kwargs={"http": http, "clock": clock, "sleep": sleep},
                daemon=True,
            )
            install_sighup(runtime)
            thread.start()
            import uvicorn

            LOG.info("web UI on http://%s:%d", runtime.cfg.web_host, runtime.cfg.web_port)
            try:
                uvicorn.run(app, host=runtime.cfg.web_host, port=runtime.cfg.web_port, log_level="warning")
            finally:
                # Shutdown is not a reason to fetch and notify again: stop the schedule and leave. The wake
                # event ends the wait between passes so the thread is not joined while asleep.
                stopping.set()
                runtime.wake.set()
                thread.join(timeout=5)
            return 0
        return pipeline.run_pass(
            runtime.cfg,
            runtime.sources,
            runtime.notifiers,
            http=http,
            clock=clock,
            sleep=sleep,
            dry_run=args.command == "dry-run",
        )
    finally:
        runtime.detach_redaction()
