"""The live configuration of one process, and the reload that replaces it.

A pass, an HTTP request and a reload all read the same three objects. A reload builds a candidate
completely off to the side, so a failure (an unreadable overlay, an invalid value, a builder
error) leaves the live objects untouched, then takes the state lock and installs the candidate.
The lock is what keeps a reload from interleaving with a pass, and the state write records which
overlay revision is now live without touching pending or parked messages.

Nothing is read at import time: the module only defines the runtime.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from pathlib import Path

from . import config, core, pipeline, settings
from .config import Config, ConfigError, load_document
from .http import RedactFilter
from .state import load_state_document, save_state, state_lock

LOG = logging.getLogger("advisory_radar")


def _state_path(document: dict, environment: Mapping[str, str]) -> Path:
    """Where the overlay lives is read from the YAML before the overlay can exist.

    ``state_path`` goes through the same ``${NAME}`` expansion the validator applies, or a
    ``state_path: ${DATA_DIR}/state.json`` would have the overlay read beside a literal
    ``${DATA_DIR}/settings.json`` and written beside the expanded one. Only the location is taken here;
    the validator owns the value itself, so a spelling it would refuse falls back to the documented
    default and the validator reports the real error.
    """
    raw = document.get("state_path", core.DEFAULT_STATE)
    if not isinstance(raw, str):
        return core.DEFAULT_STATE
    expanded = config._expand(raw, dict(environment))
    return Path(expanded) if isinstance(expanded, str) else core.DEFAULT_STATE


def read_config(
    config_path: Path, environment: Mapping[str, str], *, lenient: bool = False
) -> tuple[Config, dict, dict]:
    """Load the YAML and the overlay beside its state file, then validate the merge exactly once.

    Returns ``(cfg, merged document, overlay document)``. The merged document is the unexpanded,
    unfiltered one: the web forms need the entries a ``Config`` deliberately drops (disabled
    plugins) and the references a ``Config`` has already resolved. The YAML is read twice: once for
    ``state_path`` -- the overlay's location depends on the file it will be merged into -- and once
    with the overlay, whose values only the validator judges.
    """
    base = load_document(config_path)
    overlay = settings.load_settings_document(settings.settings_path(_state_path(base, environment)))
    document = load_document(config_path, settings=overlay["settings"])
    cfg = config.config_from_document(document, config_path, environment, lenient=lenient)
    return cfg, document, overlay


class Runtime:
    """The live configuration: a validated snapshot, rebuilt and swapped on reload."""

    def __init__(
        self,
        *,
        config_path: Path | None,
        environment: Mapping[str, str],
        overlay_path: Path | None,
        overlay: dict,
        document: dict,
        cfg: Config,
        sources: list,
        notifiers: list,
        clock: Callable[[], float] = time.time,
        redactor: RedactFilter | None = None,
    ) -> None:
        self.config_path = config_path
        self.environment = environment
        self.overlay_path = overlay_path
        self.overlay = overlay
        self.document = document
        #: The three objects a pass must read together, replaced as one tuple so a swap cannot be seen
        #: between two of them. ``cfg``/``sources``/``notifiers`` read through to it.
        self._live: tuple[Config, list, list] = (cfg, sources, notifiers)
        self.clock = clock
        self._redactor = redactor

    @property
    def cfg(self) -> Config:
        return self._live[0]

    @property
    def sources(self) -> list:
        return self._live[1]

    @property
    def notifiers(self) -> list:
        return self._live[2]

    def snapshot(self) -> tuple[Config, list, list]:
        """The live configuration as one value, so a concurrent reload cannot mix two of them."""
        return self._live

    @classmethod
    def build(
        cls, config_path: Path, environment: Mapping[str, str], *, clock: Callable[[], float] = time.time
    ) -> Runtime:
        """Load the YAML and its overlay, then build the plugins from the validated result.

        Redaction is installed before the builders run: a builder error can carry an expanded value
        (``int("...")``), and the CLI logs it. The filter is redacted out of the message as well, so
        the raised ``ConfigError`` is safe to show on a page.
        """
        cfg, document, overlay = read_config(config_path, environment)
        redactor = pipeline.attach_redaction(config.secret_values(cfg))
        try:
            sources, notifiers = pipeline.build_plugins(cfg, environment)
        except (ValueError, KeyError) as exc:
            LOG.removeFilter(redactor)
            raise ConfigError(f"plugin configuration: {pipeline.redact(str(exc), config.secret_values(cfg))}") from None
        except BaseException:
            LOG.removeFilter(redactor)
            raise
        return cls(
            config_path=config_path,
            environment=environment,
            overlay_path=settings.settings_path(cfg.state_path),
            overlay=overlay,
            document=document,
            cfg=cfg,
            sources=sources,
            notifiers=notifiers,
            clock=clock,
            redactor=redactor,
        )

    @classmethod
    def from_config(cls, cfg: Config, *, environment: Mapping[str, str] | None = None) -> Runtime:
        """A runtime for a caller that already holds a validated ``Config`` and never reloads.

        ``create_app`` accepts a bare ``Config`` this way, so a caller that constructs the app from a
        loaded config keeps working. There is no YAML path and no overlay file, so saving and
        reloading are unavailable.
        """
        document = dict(cfg.raw)
        document.setdefault("state_path", str(cfg.state_path))
        return cls(
            config_path=None,
            environment=dict(environment or {}),
            overlay_path=None,
            overlay={"schema": settings.SETTINGS_SCHEMA, "revision": 0, "updated_at": 0, "settings": {}},
            document=document,
            cfg=cfg,
            sources=[],
            notifiers=[],
        )

    def detach_redaction(self) -> None:
        """Remove this runtime's filter, so a stopped or failed configuration stops filtering."""
        if self._redactor is not None:
            LOG.removeFilter(self._redactor)
            self._redactor = None

    def reload(self, *, blocking: bool) -> None:
        """Rebuild off to the side and install under the state lock.

        A candidate that cannot be built raises before the lock is taken and leaves every live object
        untouched. ``blocking=False`` raises ``LockBusy`` when a pass holds the lock. The state document is
        read and the applied marker written before the candidate is published, so an unreadable or
        unwritable state is a refusal rather than a live revision its state does not record; the write
        itself leaves pending and parked exactly as they were.
        """
        if self.config_path is None or self.overlay_path is None:
            raise ConfigError("this runtime has no configuration file; reload is unavailable")
        candidate = type(self).build(self.config_path, self.environment, clock=self.clock)
        try:
            if candidate.cfg.state_path != self.cfg.state_path:
                # The overlay cannot move the state file, but the YAML can, and a reload would then take one
                # file's lock, read that file and write the document to the other path. That is a restart's job.
                raise ConfigError(
                    "state_path is file-only and a reload cannot move it; restart to use a new state file"
                )
            with state_lock(self.cfg.state_path, blocking=blocking):
                state = load_state_document(self.cfg.state_path, core.STATE_SCHEMA, "advisory state")
                if state is None:
                    state = core.new_state()
                # Persist the applied marker *before* publishing the candidate: if the write fails the
                # running configuration is still the old one, and a reader never sees a live revision its
                # state does not record. Everything after the write is an in-memory assignment.
                state["settings"] = {"revision": int(candidate.overlay["revision"]), "applied_at": int(self.clock())}
                try:
                    save_state(self.cfg.state_path, state)
                except OSError as exc:
                    raise ConfigError(f"the overlay was not applied: cannot record it in the state: {exc}") from exc
                self._live = candidate.snapshot()
                self.overlay = candidate.overlay
                self.document = candidate.document
                self.overlay_path = candidate.overlay_path
                # The candidate's filter was installed before its plugins were built; adopting it before
                # removing the live one leaves no log line unfiltered during the swap.
                previous, self._redactor = self._redactor, candidate._redactor
                candidate._redactor = None
                if previous is not None:
                    LOG.removeFilter(previous)
        finally:
            candidate.detach_redaction()


__all__ = ["Runtime", "read_config"]
