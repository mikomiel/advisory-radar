"""Web UI and health/metrics endpoints (FastAPI, server-rendered HTML).

One process serves the UI, the REST-ish actions and the in-process scheduler
(see cli.py ``run``). Auth is a single bearer token from the environment
(``ADVISORY_RADAR_AUTH_TOKEN``); /healthz and /metrics stay unauthenticated for
container probes and scrapers. Pages are plain HTMLResponse renders -- no
frontend build step.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import logging
import os
import time
import urllib.parse
from collections.abc import Callable, Mapping
from datetime import UTC, datetime

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeSerializer

from . import pipeline
from .catalogue import SOURCE_SPECS
from .config import Config, ConfigError, config_from_document, load_document, secret_values
from .notifiers import NOTIFIER_BUILDERS
from .runtime import Runtime
from .settings import SECRET_KEYS, is_reference, load_settings_document, save_settings
from .state import LockBusy, SourceError

LOG = logging.getLogger("advisory_radar")

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>advisory-radar</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;max-width:60rem;color:#1a1a1a}}
nav a{{margin-right:1rem}} table{{border-collapse:collapse}} td,th{{border:1px solid #ccc;padding:.25rem .6rem}}
.tag-critical{{color:#b00020;font-weight:bold}} .tag-warning{{color:#9a6700}} .muted{{color:#666}}
form{{display:inline}} button{{cursor:pointer}}
</style></head><body><nav><a href="/">Dashboard</a><a href="/alerts">Alerts</a>
<a href="/parked">Parked</a><a href="/config">Config</a><a href="/sources">Sources</a><a href="/runs">Runs</a>
<a href="/healthz">healthz</a>{nav_extra}</nav><h1>{title}</h1>{body}</body></html>"""


def esc(value: object) -> str:
    return html.escape(str(value))


def page(
    title: str, body: str, *, nav_extra: str = "", status_code: int = 200, headers: Mapping[str, str] | None = None
) -> HTMLResponse:
    return HTMLResponse(
        PAGE.format(title=esc(title), nav_extra=nav_extra, body=body), status_code=status_code, headers=headers
    )


class Auth:
    def __init__(self, token: str) -> None:
        self._serializer = URLSafeSerializer(token, salt="advisory-radar-session")

    def login_cookie(self) -> str:
        return self._serializer.dumps({"t": time.time()})

    def valid(self, request: Request) -> bool:
        cookie = request.cookies.get("advisory_radar_session")
        if not cookie:
            return False
        try:
            data = self._serializer.loads(cookie)
        except BadSignature:
            return False
        return time.time() - float(data.get("t", 0)) < 7 * 86400


def _public_url(url: str) -> str:
    """The origin only: a source URL can carry a token in its userinfo, query *or path*."""
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme or not parts.hostname:
        return ""
    return f"{parts.scheme}://{parts.hostname}"


def _number(value: object, default: int = 0) -> int:
    """A state value as an integer: a hand-edited or older state must not break a probe or a scrape.

    ``NaN`` and ``inf`` are floats that ``int()`` refuses (and that Python's JSON reader accepts), so the
    conversion is guarded too -- that is the whole point of this helper.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    try:
        return int(value)
    except (ValueError, OverflowError):
        return default


def _length(value: object) -> int:
    """A collection's size, or 0: a malformed document must not raise from a probe or a scrape."""
    return len(value) if isinstance(value, (list, dict, tuple, set)) else 0


def _epoch(value: object) -> int | None:
    """A stored epoch second this process can render, or None when the state holds nothing usable.

    ``_when`` and the dashboard's 24-hour count share this one check, so a value the page cannot print is never
    counted as a time either.
    """
    stamp = _number(value, -1)
    if stamp < 0:
        return None
    try:
        datetime.fromtimestamp(stamp, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return stamp


def _when(value: object) -> str:
    """A stored epoch second as a UTC date and time, or empty when the state holds nothing usable.

    Every page prints state as it was written, and a hand-edited or older state can hold a string, a ``NaN`` or a
    timestamp outside the representable range. A page that raised would take the whole UI down for one bad field.
    """
    stamp = _epoch(value)
    if stamp is None:
        return ""
    return datetime.fromtimestamp(stamp, tz=UTC).strftime("%Y-%m-%d %H:%M")


def last_pass_code(state: dict) -> int:
    """The last pass's exit code, or -1. Normalises ``runs`` the same way ``readiness`` does: a malformed
    document must not raise from a probe or a scrape."""
    runs = state.get("runs")
    if not isinstance(runs, list) or not runs or not isinstance(runs[-1], dict):
        return -1
    return _number(runs[-1].get("code"), -1)


#: A pass may be this many poll intervals late before the instance is not ready. Two skipped runs of slack keeps a
#: slow source from flapping the probe, and a stopped scheduler still surfaces within a few intervals.
READY_AGE_FACTOR = 3
#: Floor for the staleness limit: a 30 s poll interval must not declare itself unready between two passes.
READY_MIN_AGE_SECONDS = 300
#: A run timestamp further ahead than this is a copied state file or a clock that moved, not a fresh pass.
READY_CLOCK_SKEW_SECONDS = 60


def readiness(cfg: Config, state: dict, now: int) -> tuple[bool, str]:
    """Whether a pass finished recently enough to trust, and the sentence a caller shows."""
    runs = state.get("runs") or []
    if not isinstance(runs, list) or not runs:
        return False, "not ready: no pass has completed yet"
    last = runs[-1]
    at = 0
    if isinstance(last, dict):
        # ``at`` is when the pass started; a record written before completion times existed falls back to it.
        at = _number(last.get("finished_at")) or _number(last.get("at"))
    if not at:
        return False, "not ready: the last run record has no timestamp"
    limit = max(READY_AGE_FACTOR * cfg.poll_interval_seconds, READY_MIN_AGE_SECONDS)
    age = now - at
    if age < -READY_CLOCK_SKEW_SECONDS:
        # A future timestamp is not freshness: it would hide a stopped scheduler until that moment, so it is
        # reported rather than trusted.
        return False, f"not ready: the last run is recorded {-age // 60} min in the future (state replaced?)"
    if age > limit:
        return False, f"not ready: the last pass finished {age // 60} min ago (limit {limit // 60} min)"
    return True, "ready"


#: A login form is a handful of bytes; an unauthenticated request must not be able to make us buffer more.
LOGIN_BODY_LIMIT = 8 * 1024
#: The form field and the header that carry the per-session token; a state-changing POST needs one of them.
CSRF_FIELD = "csrf"
CSRF_HEADER = "x-csrf-token"
#: A settings form carries one row per configured plugin; still a bounded read, and the CSRF dependency
#: hands the body to the handler that edits it.
FORM_BODY_LIMIT = 64 * 1024
#: Notifier keys the /config form edits. None of them carries a credential: a secret-bearing key is
#: written only as an environment reference, and ``headers`` is not writable at all.
NOTIFIER_FORM_KEYS = ("topic", "priority", "host", "port", "from", "to", "username", "use_tls", "implicit_tls")
#: The one secret-bearing key the "new notifier" row fills, per type. ``apprise`` (url+password) and
#: ``gotify`` (url+token) need two references each, so they are added by editing the YAML.
NEW_NOTIFIER_REFERENCE = {
    "discord_webhook": "url",
    "matrix_webhook": "url",
    "ntfy": "url",
    "webhook": "url",
    "smtp": "password",
}
#: Every page is server-rendered HTML with one inline stylesheet: no scripts, no fonts, no external origins.
#: A page that needs any of those widens this deliberately, in the same change that adds it.
CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
#: Failed logins one peer may make inside this window before the endpoint refuses; the token is 24 random bytes,
#: so throttling only has to make online guessing pointless, not impossible.
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_FAILURES = 5
#: Peers the throttle remembers. Bounded because a rotating-address attacker must not turn it into unbounded
#: memory; see LoginThrottle for why the oldest peer is evicted rather than a new peer refused.
LOGIN_MAX_PEERS = 1024


class LoginThrottle:
    """Failed sign-in attempts per peer inside a rolling window.

    Two properties the endpoint depends on:

    * :meth:`refusal` reflects every failure recorded *so far*, so the handler can call it again after the
      body arrived and immediately before comparing credentials -- a check made before an attacker-controlled
      wait cannot be the only one.
    * the map is bounded. At the cap the least recently failing peer is evicted rather than a new peer being
      refused: refusing newcomers would let an attacker who fills the map lock the operator out, and the
      secret being guessed is 24 random bytes that no rate of online guessing reaches.
    """

    def __init__(
        self,
        window: float = LOGIN_WINDOW_SECONDS,
        attempts: int = LOGIN_MAX_FAILURES,
        peers: int = LOGIN_MAX_PEERS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._window = window
        self._attempts = attempts
        self._peers = peers
        self._clock = clock
        self._failures: dict[str, list[float]] = {}

    @property
    def tracked(self) -> int:
        """How many peers are being remembered (a test, and an operator reading a debugger, both want this)."""
        return len(self._failures)

    def _prune(self, now: float) -> None:
        """Forget every peer whose newest failure has left the window, not only the caller's."""
        stale = [peer for peer, stamps in self._failures.items() if not stamps or now - stamps[-1] >= self._window]
        for peer in stale:
            self._failures.pop(peer, None)

    def refusal(self, peer: str) -> int | None:
        """Seconds until this peer may try again, or None when it may try now."""
        now = self._clock()
        self._prune(now)
        recent = [stamp for stamp in self._failures.get(peer, ()) if now - stamp < self._window]
        if recent:
            self._failures[peer] = recent
        if len(recent) < self._attempts:
            return None
        return max(1, int(self._window - (now - recent[0])))

    def failed(self, peer: str) -> None:
        now = self._clock()
        self._prune(now)
        self._failures.setdefault(peer, []).append(now)
        while len(self._failures) > self._peers:
            self._failures.pop(min(self._failures, key=lambda name: self._failures[name][-1]), None)

    def succeeded(self, peer: str) -> None:
        self._failures.pop(peer, None)


class BodyTooLarge(Exception):
    """The request body exceeded the endpoint's limit; it is refused before it is fully read."""


async def _body(request: Request, limit: int) -> bytes:
    """Read a request body with a hard limit, streaming, so a chunked request cannot pre-allocate memory."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise BodyTooLarge
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


class InboxFull(Exception):
    """A webhook source's inbox is at capacity; the sender must retry, nothing is discarded."""


def _insecure_cookies(env: Mapping[str, str]) -> bool:
    """Whether the plaintext-cookie opt-out is set (development only; the default is a Secure cookie)."""
    return env.get("ADVISORY_RADAR_INSECURE_COOKIES", "").strip().lower() in {"1", "true", "yes", "on"}


def _public_https(env: Mapping[str, str]) -> bool:
    """Whether TLS terminates in front of this process, so HSTS may be sent (opt-in: a wrong HSTS pins a browser)."""
    return env.get("ADVISORY_RADAR_PUBLIC_HTTPS", "").strip().lower() in {"1", "true", "yes", "on"}


def create_app(
    runtime: Runtime | Config,
    env: Mapping[str, str],
    *,
    run_pass: Callable[..., int] | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    """The web UI over one live configuration.

    ``runtime`` is the process's :class:`~advisory_radar.runtime.Runtime`; pages read ``runtime.cfg``
    and the intake looks the configured sources up per request, so a reload applies without a
    restart. A bare :class:`Config` is wrapped in a runtime that never reloads, for a caller that
    constructs the app from an already-loaded config.
    """
    if not isinstance(runtime, Runtime):
        runtime = Runtime.from_config(runtime)
    app = FastAPI(title="advisory-radar", docs_url=None, redoc_url=None)
    auth = Auth(env.get("ADVISORY_RADAR_AUTH_TOKEN", ""))

    def webhook_source_ids() -> set[str]:
        """Webhooks are open to a configured webhook source id only, read from the live runtime."""
        return {source.id for source in runtime.sources if getattr(source, "kind", "") == "webhook"}

    token = env.get("ADVISORY_RADAR_AUTH_TOKEN", "")
    if not token:
        # The session cookie is signed with this token; an empty key is a public key, so anyone could
        # mint a cookie for a protected endpoint.
        raise ValueError("ADVISORY_RADAR_AUTH_TOKEN must be set to serve the web UI")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        """Headers on every response, including /healthz and /metrics.

        ``default-src 'none'`` is honest today: the pages ship no script and load nothing external. An
        authenticated page lists advisories and run history, so it must not sit in a shared proxy's cache.
        """
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Content-Security-Policy", CSP)
        if _public_https(env):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if response.headers.get("content-type", "").startswith("text/html"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        """A browser gets a page, a script gets JSON; neither leaks why a token was refused."""
        if "text/html" in request.headers.get("accept", ""):
            return page("Error", f"<p>{esc(exc.detail)}</p>", status_code=exc.status_code)
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    def csrf_token(request: Request) -> str:
        """The HMAC of this session's cookie: a token bound to the session, with no extra state to store."""
        session = request.cookies.get("advisory_radar_session") or ""
        return hmac.new(token.encode(), session.encode(), hashlib.sha256).hexdigest()

    def csrf_field(request: Request) -> str:
        return f'<input type="hidden" name="{CSRF_FIELD}" value="{esc(csrf_token(request))}">'

    def sign_out_form(request: Request) -> str:
        """The nav's sign-out button, present on every authenticated page."""
        return (
            f'<form method="post" action="/logout">{csrf_field(request)}<button type="submit">Sign out</button></form>'
        )

    async def require_csrf(request: Request) -> None:
        """Refuse a state-changing POST no page of ours issued.

        SameSite=Lax already keeps the cookie off a cross-site POST; this is the second lock, for a browser or
        proxy that does not apply it. The body is read once and kept on the request: a settings form's handler
        edits the body this dependency has already consumed.
        """
        if not auth.valid(request):  # the endpoint itself redirects an unauthenticated caller
            return
        try:
            raw = await _body(request, FORM_BODY_LIMIT)
        except BodyTooLarge:
            raise HTTPException(status_code=413, detail="payload too large") from None
        request.state.form_body = raw
        supplied = request.headers.get(CSRF_HEADER, "")
        if not supplied:
            form = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
            supplied = (form.get(CSRF_FIELD) or [""])[0]
        # Compared as bytes: hmac.compare_digest raises TypeError on a non-ASCII str, and a form field is
        # attacker-supplied -- "%C3%A9" must be a refused token, not a 500.
        if not supplied or not hmac.compare_digest(
            csrf_token(request).encode(), supplied.encode("utf-8", "surrogatepass")
        ):
            raise HTTPException(status_code=403, detail="invalid form token; reload the page and try again")

    throttle = LoginThrottle()

    def require_auth(request: Request) -> bool:
        return auth.valid(request)

    def load_state() -> dict:
        from . import core
        from .state import load_state_document

        return load_state_document(runtime.cfg.state_path, core.STATE_SCHEMA, "advisory state") or core.new_state()

    @app.get("/login", response_class=HTMLResponse)
    def login_form():
        return page(
            "Login",
            '<form method="post" action="/login"><input type="password" name="token" '
            'placeholder="auth token"><button>Sign in</button></form>',
        )

    @app.post("/login")
    async def login(request: Request):
        peer = request.client.host if request.client else "unknown"

        def throttled(wait: int):
            return page(
                "Too many attempts",
                "<p>Too many failed sign-in attempts. Try again shortly.</p>",
                status_code=429,
                headers={"Retry-After": str(wait)},
            )

        wait = throttle.refusal(peer)
        if wait is not None:
            # Refuse before reading the body: a throttled peer costs this process nothing.
            return throttled(wait)
        # parse the urlencoded body by hand: no python-multipart dependency
        try:
            raw = await _body(request, LOGIN_BODY_LIMIT)
        except BodyTooLarge:
            return PlainTextResponse("payload too large", status_code=413)
        form = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
        supplied = (form.get("token") or [""])[0]
        # Re-check with a fresh timestamp now the body has arrived: the first check happened before a wait the
        # caller controls, so concurrent requests could all have passed it and then guessed.
        wait = throttle.refusal(peer)
        if wait is not None:
            return throttled(wait)
        expected = env.get("ADVISORY_RADAR_AUTH_TOKEN", "")
        # constant-time compare: a byte-by-byte comparison leaks how much of the token matched
        if supplied and expected and hmac.compare_digest(supplied.encode(), expected.encode()):
            throttle.succeeded(peer)
            response = RedirectResponse("/", status_code=303)
            # Secure by default: without it a browser may send a seven-day session over plaintext HTTP to the
            # same host. ADVISORY_RADAR_INSECURE_COOKIES=1 opts out, for a plain-HTTP development instance only.
            response.set_cookie(
                "advisory_radar_session",
                auth.login_cookie(),
                httponly=True,
                samesite="lax",
                secure=not _insecure_cookies(os.environ),
            )
            return response
        throttle.failed(peer)
        return page(
            "Login",
            '<p>Wrong token.</p><form method="post" action="/login">'
            '<input type="password" name="token"><button>Sign in</button></form>',
        )

    @app.post("/logout", dependencies=[Depends(require_csrf)])
    def logout():
        """Clear the session cookie. The token cannot be revoked, but the browser stops sending it."""
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(
            "advisory_radar_session",
            httponly=True,
            samesite="lax",
            secure=not _insecure_cookies(os.environ),
        )
        return response

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        state = load_state()
        pending, parked = state.get("pending", []), state.get("parked", [])
        seen = state.get("seen")
        seen = seen if isinstance(seen, dict) else {}
        runs = state.get("runs")
        runs = runs if isinstance(runs, list) else []
        last = runs[-1] if runs and isinstance(runs[-1], dict) else {}
        today = int(time.time()) - 86400
        # ``seen`` is state as it was written: a record that is not an object, or whose ``at`` is not a time this
        # process can render, is simply not "seen today" -- it must never take the page down or inflate the count.
        today_seen = 0
        for record in seen.values():
            stamp = _epoch(record.get("at")) if isinstance(record, dict) else None
            if stamp is not None and stamp >= today:
                today_seen += 1
        body = (
            f"<p>Pending: <b>{len(pending)}</b> · Parked: <b>{len(parked)}</b> · "
            f"Seen in last 24h: <b>{today_seen}</b> · Total seen: <b>{len(seen)}</b></p>"
            f"<p class='muted'>Last pass: {esc(_when(last.get('at')) or 'never')} — sent {last.get('sent', 0)}, "
            f"parked {last.get('parked', 0)}, exit {last.get('code', '?')}</p>"
            f'<form method="post" action="/run">{csrf_field(request)}<button>Run a pass now</button></form>'
        )
        return page("Dashboard", body, nav_extra=sign_out_form(request))

    @app.post("/run", dependencies=[Depends(require_csrf)])
    def run_now(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        code = run_pass(lock_blocking=False) if run_pass is not None else -1
        return RedirectResponse(f"/?ran={code}", status_code=303)

    @app.get("/alerts", response_class=HTMLResponse)
    def alerts(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        state = load_state()
        seen = state.get("seen")
        seen = seen if isinstance(seen, dict) else {}
        rows = []
        # A record that is not an object, or whose timestamp is not a number, is skipped by the sort key rather
        # than raising: one hand-edited field must not hide every advisory behind a 500.
        ordered = sorted(
            ((identifier, record) for identifier, record in seen.items() if isinstance(record, dict)),
            key=lambda kv: (-_number(kv[1].get("at"), 0), kv[0]),
        )
        for identifier, record in ordered[:200]:
            rows.append(
                f"<tr><td>{esc(identifier)}</td><td>{esc(record.get('outcome', ''))}</td>"
                f"<td class='muted'>{esc(_when(record.get('at')))}</td></tr>"
            )
        body = "<table><tr><th>ID</th><th>Outcome</th><th>First seen (UTC)</th></tr>" + "".join(rows) + "</table>"
        return page("Alerts", body, nav_extra=sign_out_form(request))

    @app.get("/parked", response_class=HTMLResponse)
    def parked_page(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        state = load_state()
        rows = []
        for entry in state.get("parked", []):
            rows.append(
                f"<tr><td class='tag-{esc(entry.get('tag', ''))}'>{esc(entry.get('tag', ''))}</td>"
                f"<td>{esc(entry.get('title', ''))}</td><td>{esc(', '.join(entry.get('ids', []))[:80])}</td></tr>"
            )
        body = (
            "<table><tr><th>Tag</th><th>Title</th><th>IDs</th></tr>" + "".join(rows) + "</table>"
            f'<form method="post" action="/parked/release">{csrf_field(request)}'
            "<button>Release all</button></form> "
            f'<form method="post" action="/parked/drop">{csrf_field(request)}<button>Drop all</button></form>'
        )
        return page("Parked messages", body, nav_extra=sign_out_form(request))

    @app.post("/parked/release", dependencies=[Depends(require_csrf)])
    def parked_release(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        from . import core
        from .state import state_lock

        state_path = runtime.cfg.state_path
        with state_lock(state_path):
            core.manage_parked(state_path, release=True, now=int(time.time()))
        return RedirectResponse("/parked", status_code=303)

    @app.post("/parked/drop", dependencies=[Depends(require_csrf)])
    def parked_drop(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        from . import core
        from .state import state_lock

        state_path = runtime.cfg.state_path
        with state_lock(state_path):
            core.manage_parked(state_path, release=False, now=int(time.time()))
        return RedirectResponse("/parked", status_code=303)

    # --- the settings overlay: /config and the POSTs that write and apply it ---------------------

    def form_body(request: Request) -> dict[str, list[str]]:
        """The urlencoded body the CSRF dependency already read; no python-multipart dependency."""
        raw = getattr(request.state, "form_body", b"")
        return urllib.parse.parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)

    def first(form: dict[str, list[str]], name: str) -> str:
        return (form.get(name) or [""])[0]

    def overlay_on_disk() -> dict:
        """The overlay as saved (not necessarily live), so editing one section keeps the other three."""
        if runtime.overlay_path is None:
            return {}
        try:
            return dict(load_settings_document(runtime.overlay_path)["settings"])
        except ConfigError:
            return dict(runtime.overlay["settings"])

    def applied_settings() -> dict:
        try:
            value = load_state().get("settings")
        except SourceError:
            return {}
        return value if isinstance(value, dict) else {}

    def notifier_notes(entry: dict) -> str:
        """What a notifier carries, for display: a reference by name, never a credential."""
        notes = []
        for key in SECRET_KEYS:
            if key not in entry:
                continue
            notes.append(f"{key}={entry[key]}" if is_reference(entry[key]) else f"{key} set (not shown)")
        if "headers" in entry:
            notes.append("headers set in the YAML (not shown)")
        return esc(", ".join(notes))

    def notifier_form_entries(entries) -> str:
        """One row per configured notifier: enabled, its non-secret keys, and its secret references."""
        rows = []
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                continue
            identifier = entry["id"]
            checked = " checked" if entry.get("enabled", True) is not False else ""
            fields = " ".join(
                f"<label>{key} <input type='text' name='field:{esc(identifier)}:{key}' "
                f"value='{esc(entry[key])}'></label>"
                for key in NOTIFIER_FORM_KEYS
                if key in entry
            )
            rows.append(
                f"<tr><td><b>{esc(identifier)}</b><br><span class='muted'>{esc(entry.get('type', ''))}</span></td>"
                f"<td><input type='checkbox' name='enabled:{esc(identifier)}' value='1'{checked}></td>"
                f"<td>{fields}</td><td class='muted'>{notifier_notes(entry)}</td></tr>"
            )
        return "".join(rows)

    def source_form_entries(entries) -> str:
        """One row per configured source: its id and type, its enabled flag and its tag."""
        rows = []
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                continue
            identifier = entry["id"]
            checked = " checked" if entry.get("enabled", True) is not False else ""
            # The origin only: a source URL can carry a token in its userinfo, query or path.
            public = _public_url(str(entry.get("url", "")))
            rows.append(
                f"<tr><td><b>{esc(identifier)}</b> <span class='muted'>{esc(entry.get('type', ''))}</span>"
                + (f"<br><span class='muted'>{esc(public)}</span>" if public else "")
                + f"</td><td><input type='checkbox' name='enabled:{esc(identifier)}' value='1'{checked}></td>"
                f"<td><input type='text' name='tag:{esc(identifier)}' value='{esc(entry.get('tag', ''))}'></td></tr>"
            )
        return "".join(rows)

    def commit_overlay(overlay: dict):
        """Validate, build, save and apply one overlay; nothing is written when any step refuses.

        Building the plugins here is what makes a saved overlay safe: it is the same build the next
        start and the reload perform, so a value that would fail then is refused now, while the live
        configuration and the file on disk are still untouched.
        """
        if runtime.config_path is None or runtime.overlay_path is None:
            return page("Not saved", "<p>This instance has no configuration file to update.</p>", status_code=400)
        values = list(secret_values(runtime.cfg))
        candidate = None
        try:
            document = load_document(runtime.config_path, settings=overlay)
            candidate = config_from_document(document, runtime.config_path, runtime.environment)
            values += secret_values(candidate)
            pipeline.build_plugins(candidate, runtime.environment)
        except (ConfigError, ValueError, KeyError) as exc:
            # Redacted before rendering: a builder error can carry a value expanded from the environment.
            message = esc(pipeline.redact(str(exc), values))
            return page(
                "Not saved",
                f"<p>{message}</p><p>The live configuration is unchanged and nothing was written.</p>",
                status_code=400,
            )
        try:
            stored = save_settings(runtime.overlay_path, overlay, now=int(clock()))
        except ConfigError as exc:
            return page("Not saved", f"<p>{esc(pipeline.redact(str(exc), values))}</p>", status_code=400)
        try:
            runtime.reload(blocking=False)
        except LockBusy:
            LOG.info("settings revision %d saved; a pass holds the lock, so it is not live yet", stored["revision"])
        except (ConfigError, SourceError) as exc:
            LOG.warning(
                "settings revision %d saved but not applied: %s",
                stored["revision"],
                pipeline.redact(str(exc), values),
            )
        return RedirectResponse(f"/config?saved={stored['revision']}", status_code=303)

    @app.post("/config/settings", dependencies=[Depends(require_csrf)])
    def save_settings_form(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        form = form_body(request)
        overlay = overlay_on_disk()
        poll = first(form, "poll_interval").strip()
        if poll:
            overlay["poll_interval"] = poll
        else:
            overlay.pop("poll_interval", None)  # an empty field means "use the YAML value"
        overlay["hidden_source_hosts"] = [
            line.strip() for line in first(form, "hidden_source_hosts").splitlines() if line.strip()
        ]
        return commit_overlay(overlay)

    @app.post("/config/sources", dependencies=[Depends(require_csrf)])
    def save_sources_form(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        form = form_body(request)
        overlay = overlay_on_disk()
        changes = {}
        for entry in runtime.document.get("sources") or []:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                continue
            identifier = entry["id"]
            changes[identifier] = {
                "enabled": f"enabled:{identifier}" in form,
                "tag": first(form, f"tag:{identifier}").strip(),
            }
        overlay["sources"] = changes
        return commit_overlay(overlay)

    @app.post("/config/notifiers", dependencies=[Depends(require_csrf)])
    def save_notifiers_form(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        form = form_body(request)
        overlay = overlay_on_disk()
        entries = []
        for entry in runtime.document.get("notifiers") or []:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                continue
            identifier = entry["id"]
            updated = dict(entry)
            updated["enabled"] = f"enabled:{identifier}" in form
            for key in NOTIFIER_FORM_KEYS:
                if key not in entry:
                    continue
                value = first(form, f"field:{identifier}:{key}").strip()
                if value:
                    updated[key] = value
                else:
                    updated.pop(key, None)
            entries.append(updated)
        identifier = first(form, "new:id").strip()
        if identifier:
            kind = first(form, "new:type").strip()
            reference = first(form, "new:reference").strip()
            secret_key = NEW_NOTIFIER_REFERENCE.get(kind)
            if kind and secret_key is None and kind in NOTIFIER_BUILDERS:
                return page(
                    "Not saved",
                    f"<p>A {esc(kind)} notifier needs more than one reference; this form collects one. "
                    "Add it by editing the YAML. A secret stays in the environment and is only referenced.</p>",
                    status_code=400,
                )
            new = {"id": identifier, "type": kind}
            if secret_key is not None:
                if not reference:
                    return page(
                        "Not saved",
                        f"<p>A {esc(kind)} needs a reference here: enter ${{NAME}} or ${{NAME}}_FILE. "
                        "The secret itself stays in the environment.</p>",
                        status_code=400,
                    )
                new[secret_key] = reference
            for key in NOTIFIER_FORM_KEYS:
                value = first(form, f"new:{key}").strip()
                if value:
                    new[key] = value
            entries.append(new)
        overlay["notifiers"] = entries
        return commit_overlay(overlay)

    @app.post("/reload", dependencies=[Depends(require_csrf)])
    def reload_configuration(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        if runtime.config_path is None:
            return page("Not reloaded", "<p>This instance has no configuration file to reload.</p>", status_code=400)
        try:
            runtime.reload(blocking=False)
        except LockBusy:
            return page(
                "Reload refused",
                "<p>A pass is running, so the configuration was not reloaded; try again when it finishes.</p>"
                '<p><a href="/config">Back to configuration</a></p>',
                status_code=409,
            )
        except (ConfigError, SourceError) as exc:
            message = esc(pipeline.redact(str(exc), secret_values(runtime.cfg)))
            return page(
                "Reload refused",
                f"<p>{message}</p><p>The running configuration is unchanged.</p>",
                status_code=400,
            )
        return RedirectResponse("/config", status_code=303)

    @app.get("/config", response_class=HTMLResponse)
    def config_page(request: Request, saved: int | None = None):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        cfg = runtime.cfg
        document = runtime.document
        sources = document.get("sources")
        sources = sources if isinstance(sources, list) else []
        notifiers = document.get("notifiers")
        notifiers = notifiers if isinstance(notifiers, list) else []
        try:
            saved_document = (
                load_settings_document(runtime.overlay_path)
                if runtime.overlay_path is not None
                else {"revision": 0, "settings": {}}
            )
            overlay_error = ""
        except ConfigError as exc:
            saved_document, overlay_error = {"revision": 0, "settings": {}}, esc(str(exc))
        saved_revision = int(saved_document["revision"])
        live_revision = int(runtime.overlay.get("revision", 0))
        # "Live" means this process loaded this file: the same revision and the same settings. A
        # hand-edit that kept the revision number is therefore not reported as applied.
        live_now = saved_revision == live_revision and saved_document["settings"] == runtime.overlay["settings"]
        applied = applied_settings()
        applied_at = _when(applied.get("applied_at"))
        if saved_revision == 0 and not saved_document["settings"]:
            status = "no overlay saved; the YAML is the whole configuration"
        else:
            status = f"saved revision <b>{saved_revision}</b> · " + (
                "<b>live</b>" if live_now else f"NOT live (live revision <b>{live_revision}</b>)"
            )
            if applied_at:
                status += f" · last applied {esc(applied_at)}"
        banner = ""
        if saved is not None:
            if live_now and saved == live_revision:
                banner += f"<p class='tag-warning'>Revision {saved} saved and live.</p>"
            else:
                banner += (
                    f"<p class='tag-warning'>Revision {saved} saved but not live yet (live revision {live_revision}); "
                    "press Reload once the running pass finishes.</p>"
                )
        if overlay_error:
            banner += f"<p class='tag-critical'>The overlay cannot be read: {overlay_error}</p>"
        poll_text = document.get("poll_interval")
        poll_text = poll_text if isinstance(poll_text, str) else f"{cfg.poll_interval_seconds}s"
        hidden = document.get("hidden_source_hosts")
        hidden_text = "\n".join(str(host) for host in hidden) if isinstance(hidden, list) else ""
        type_options = "".join(
            f"<option value='{esc(kind)}'>{esc(kind)}</option>" for kind in sorted(NOTIFIER_BUILDERS)
        )
        new_fields = " ".join(
            f"<label>{key} <input type='text' name='new:{key}'></label>" for key in NOTIFIER_FORM_KEYS
        )
        csrf = csrf_field(request)
        body = (
            f"<p>Live poll interval <b>{cfg.poll_interval_seconds}s</b> · state {esc(cfg.state_path)} · "
            f"watchlist {esc(cfg.watchlist_path or 'built-in default')}</p>"
            f"<p class='muted'>Settings overlay: {status}</p>{banner}"
            f'<form method="post" action="/reload">{csrf}<button>Reload configuration</button></form>'
            "<h2>Settings</h2>"
            f'<form method="post" action="/config/settings">{csrf}'
            f"<p><label>Poll interval <input type='text' name='poll_interval' value='{esc(poll_text)}'></label> "
            "(15m, 30s or 12h)</p>"
            "<p><label>Hidden source hosts (one per line)<br>"
            f"<textarea name='hidden_source_hosts' rows='4' cols='40'>{esc(hidden_text)}</textarea></label></p>"
            "<button>Save settings</button></form>"
            "<h2>Sources</h2>"
            f'<form method="post" action="/config/sources">{csrf}'
            "<table><tr><th>Source</th><th>Enabled</th><th>Tag</th></tr>"
            f"{source_form_entries(sources)}</table><button>Save sources</button></form>"
            "<h2>Notifiers</h2>"
            f'<form method="post" action="/config/notifiers">{csrf}'
            "<table><tr><th>Notifier</th><th>Enabled</th><th>Non-secret fields</th><th>Secrets</th></tr>"
            f"{notifier_form_entries(notifiers)}</table>"
            "<h3>New notifier</h3>"
            "<p class='muted'>Secrets stay in the environment: the reference field takes ${NAME} or ${NAME}_FILE "
            "and is stored instead of the value. A type that needs two references, or a header, is added by "
            "editing the YAML.</p>"
            "<p><label>id <input type='text' name='new:id'></label> "
            f"<label>type <select name='new:type'>{type_options}</select></label> "
            "<label>reference <input type='text' name='new:reference' placeholder='${NAME}'></label></p>"
            f"<p>{new_fields}</p><button>Save notifiers</button></form>"
            "<p class='muted'>The YAML file stays the source of every other setting; environment changes still "
            "need a restart.</p>"
        )
        return page("Configuration", body, nav_extra=sign_out_form(request))

    @app.get("/sources", response_class=HTMLResponse)
    def sources_page(request: Request):
        """The whole built-in catalogue, rendered from its one owner, plus what this instance configured."""
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        rows = []
        for spec in SOURCE_SPECS.values():
            example = yaml.safe_dump(spec.example, sort_keys=False)
            rows.append(
                f"<tr><td><b>{esc(spec.kind)}</b></td><td>{esc(spec.summary)}</td>"
                f"<td>{esc(', '.join(spec.required) or '(none)')}</td>"
                f"<td>{esc(', '.join(spec.optional) or '(none)')}</td>"
                f"<td><pre>{esc(example)}</pre></td><td><code>{esc(spec.docs_anchor)}</code></td></tr>"
            )
        configured = "".join(
            f"<li><b>{esc(source['id'])}</b> ({esc(source.get('type', ''))})</li>" for source in runtime.cfg.sources
        )
        body = (
            "<p>Every built-in source type, its keys and an example. Required keys have no default.</p>"
            "<table><tr><th>Kind</th><th>Summary</th><th>Required</th><th>Optional</th>"
            f"<th>Example</th><th>Docs</th></tr>{''.join(rows)}</table>"
            f"<h2>Configured sources</h2><ul>{configured or '<li>(none)</li>'}</ul>"
            "<p class='muted'>Try one without delivering anything: "
            "<code>advisory-radar sources test &lt;id&gt;</code>.</p>"
        )
        return page("Sources", body, nav_extra=sign_out_form(request))

    @app.get("/runs", response_class=HTMLResponse)
    def runs_page(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        runs = load_state().get("runs")
        runs = runs if isinstance(runs, list) else []
        rows = "".join(
            f"<tr><td>{esc(_when(r.get('at')))}</td><td>{r.get('sent', 0)}</td><td>{r.get('parked', 0)}</td>"
            f"<td>{r.get('pending', 0)}</td><td>{r.get('code', '')}</td></tr>"
            for r in reversed(runs)
            if isinstance(r, dict)
        )
        return page(
            "Runs",
            nav_extra=sign_out_form(request),
            body="<table><tr><th>At (UTC)</th><th>Sent</th><th>Parked</th><th>Pending</th><th>Exit</th></tr>"
            + rows
            + "</table>",
        )

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz():
        """Liveness only: this process answers HTTP. Pass freshness belongs to /readyz."""
        return PlainTextResponse("ok")

    @app.get("/readyz", response_class=PlainTextResponse)
    def readyz():
        """Readiness: the state is readable and a pass finished recently enough.

        503 makes a dead scheduler visible to a container probe or an uptime monitor; /healthz keeps answering
        while the process is alive, which is the only thing a liveness probe may ask. An unreadable state is
        also not ready: every page and the pass itself depend on it.
        """
        try:
            state = load_state()
        except SourceError as exc:
            return PlainTextResponse(f"not ready: {exc}", status_code=503)
        ok, reason = readiness(runtime.cfg, state, int(clock()))
        return PlainTextResponse(reason, status_code=200 if ok else 503)

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        try:
            state = load_state()
        except SourceError as exc:
            # The documented alert is `advisory_radar_ready == 0`, and a failed scrape produces no sample at all:
            # an unreadable state must still answer, with the one thing it can honestly report. Nothing else is
            # fabricated, because without the state every other number is unknown rather than zero.
            LOG.warning("metrics: state unreadable: %s", exc)
            return PlainTextResponse(
                "# HELP advisory_radar_ready 1 when the last pass is recent enough and the state is readable\n"
                "# TYPE advisory_radar_ready gauge\nadvisory_radar_ready 0\n"
                "# HELP advisory_radar_state_readable 1 when the state document could be read\n"
                "# TYPE advisory_radar_state_readable gauge\nadvisory_radar_state_readable 0\n"
            )
        raw_runs = state.get("runs")
        runs = raw_runs if isinstance(raw_runs, list) else []
        last = runs[-1] if runs and isinstance(runs[-1], dict) else {}
        ok, _ = readiness(runtime.cfg, state, int(clock()))
        gauges = [
            ("pending", "Pending messages awaiting delivery", "gauge", _length(state.get("pending"))),
            ("parked", "Parked messages awaiting an operator decision", "gauge", _length(state.get("parked"))),
            ("seen_total", "Advisory identities ever seen", "counter", _length(state.get("seen"))),
            ("watch_total", "CVEs under daily re-evaluation", "gauge", _length(state.get("watch"))),
            ("runs_retained", "Passes retained in the state (the last 200)", "gauge", len(runs)),
            # 0 means "no pass yet", which is also why ready is 0; both are honest about a fresh instance.
            (
                "last_pass_timestamp_seconds",
                "When the last pass finished (epoch seconds)",
                "gauge",
                _number(last.get("finished_at")) or _number(last.get("at")),
            ),
            ("last_pass_exit", "Exit code of the last pass", "gauge", last_pass_code(state)),
            ("last_pass_sent", "Messages delivered by the last pass", "gauge", _number(last.get("sent"))),
            ("last_pass_parked", "Messages parked by the last pass", "gauge", _number(last.get("parked"))),
            ("last_pass_pending", "Messages left pending by the last pass", "gauge", _number(last.get("pending"))),
            ("state_readable", "1 when the state document could be read", "gauge", 1),
            ("ready", "1 when the last pass is recent enough and the state is readable", "gauge", int(ok)),
        ]
        lines: list[str] = []
        for name, help_text, kind, value in gauges:
            lines.append(f"# HELP advisory_radar_{name} {help_text}")
            lines.append(f"# TYPE advisory_radar_{name} {kind}")
            lines.append(f"advisory_radar_{name} {value}")
        return PlainTextResponse("\n".join(lines) + "\n")

    #: Webhook inbox bounds: an unauthenticated or abusive caller must not be able to grow the state without
    #: limit, and the body is read bounded rather than trusted to be small.
    WEBHOOK_BODY_LIMIT = 64 * 1024
    WEBHOOK_INBOX_LIMIT = 500

    @app.post("/webhooks/{source_id}")
    async def webhook_intake(source_id: str, request: Request):
        """Inbound webhook (generic JSON or changedetection.io native payload).

        Fails closed: ingestion is disabled unless ``ADVISORY_RADAR_WEBHOOK_SECRET`` is set *and* ``source_id``
        names a configured webhook source. The request must carry ``Authorization: Bearer <secret>``.

        The state transaction runs in a worker thread: a file lock, a read and an fsync write must never block
        the event loop the scheduler and /healthz share, and the lock is taken non-blockingly so a running pass
        answers 503 rather than stalling the request.
        """
        from starlette.concurrency import run_in_threadpool

        from . import core as _core
        from .sources import webhook_item_from_payload
        from .state import load_state_document, save_state, state_lock

        secret = env.get("ADVISORY_RADAR_WEBHOOK_SECRET", "")
        if not secret or source_id not in webhook_source_ids():
            return JSONResponse({"error": "webhook ingestion is not configured"}, status_code=404)
        provided = request.headers.get("authorization", "")
        if not hmac.compare_digest(provided.encode(), f"Bearer {secret}".encode()):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            body = await _body(request, WEBHOOK_BODY_LIMIT)
        except BodyTooLarge:
            return JSONResponse({"error": "payload too large"}, status_code=413)
        try:
            payload = json.loads(body or b"null")
        except ValueError:
            return JSONResponse({"error": "payload is not JSON"}, status_code=400)
        entry = webhook_item_from_payload(payload)
        if entry is None:
            return JSONResponse({"error": "payload has no title"}, status_code=422)
        entry.pop("explicit_ids", None)  # ids are re-extracted from text at classify time

        state_path = runtime.cfg.state_path

        def store() -> None:
            with state_lock(state_path, blocking=False):
                state = load_state_document(state_path, _core.STATE_SCHEMA, "advisory state") or _core.new_state()
                inbox = state.setdefault("webhook_inbox", {}).setdefault(source_id, [])
                # A full inbox refuses the new entry rather than dropping an accepted one: an acknowledged
                # advisory must never be discarded unprocessed.
                if len(inbox) >= WEBHOOK_INBOX_LIMIT:
                    raise InboxFull
                inbox.append(entry)
                save_state(state_path, state)

        try:
            await run_in_threadpool(store)
        except LockBusy:
            return JSONResponse({"error": "busy, retry"}, status_code=503, headers={"Retry-After": "30"})
        except InboxFull:
            return JSONResponse(
                {"error": "inbox full, retry after the next pass"}, status_code=429, headers={"Retry-After": "60"}
            )
        return JSONResponse({"queued": entry["guid"]})

    @app.get("/api/state", response_class=JSONResponse)
    def api_state(request: Request):
        if not require_auth(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return JSONResponse(load_state())

    return app
