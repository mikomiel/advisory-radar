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

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeSerializer

from .config import Config

LOG = logging.getLogger("advisory_radar")

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>advisory-radar</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;max-width:60rem;color:#1a1a1a}}
nav a{{margin-right:1rem}} table{{border-collapse:collapse}} td,th{{border:1px solid #ccc;padding:.25rem .6rem}}
.tag-critical{{color:#b00020;font-weight:bold}} .tag-warning{{color:#9a6700}} .muted{{color:#666}}
form{{display:inline}} button{{cursor:pointer}}
</style></head><body><nav><a href="/">Dashboard</a><a href="/alerts">Alerts</a>
<a href="/parked">Parked</a><a href="/config">Config</a><a href="/runs">Runs</a>
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
    at = _number(last.get("at")) if isinstance(last, dict) else 0
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
    cfg: Config,
    env: dict[str, str],
    *,
    run_pass: Callable[..., int] | None = None,
    sources=None,
    notifiers=None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    app = FastAPI(title="advisory-radar", docs_url=None, redoc_url=None)
    auth = Auth(env.get("ADVISORY_RADAR_AUTH_TOKEN", ""))
    #: Inbound webhooks are open to a configured source id only; an unconfigured signal is refused, not stored.
    webhook_sources = {source.id for source in (sources or []) if getattr(source, "kind", "") == "webhook"}

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
        proxy that does not apply it. The body read here carries the token field only -- every endpoint using
        this dependency acts on the session cookie and reads no body of its own.
        """
        if not auth.valid(request):  # the endpoint itself redirects an unauthenticated caller
            return
        try:
            raw = await _body(request, LOGIN_BODY_LIMIT)
        except BodyTooLarge:
            raise HTTPException(status_code=413, detail="payload too large") from None
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

        return load_state_document(cfg.state_path, core.STATE_SCHEMA, "advisory state") or core.new_state()

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
        pending, parked, seen = state.get("pending", []), state.get("parked", []), state.get("seen", {})
        today = int(time.time()) - 86400
        today_seen = sum(1 for v in seen.values() if v.get("at", 0) >= today)
        runs = state.get("runs", [])
        last = runs[-1] if runs else {}
        body = (
            f"<p>Pending: <b>{len(pending)}</b> · Parked: <b>{len(parked)}</b> · "
            f"Seen in last 24h: <b>{today_seen}</b> · Total seen: <b>{len(seen)}</b></p>"
            f"<p class='muted'>Last pass: {esc(last.get('at', 'never'))} — sent {last.get('sent', 0)}, "
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
        rows = []
        for identifier, record in sorted(
            state.get("seen", {}).items(), key=lambda kv: kv[1].get("at", 0), reverse=True
        )[:200]:
            rows.append(
                f"<tr><td>{esc(identifier)}</td><td>{esc(record.get('outcome', ''))}</td>"
                f"<td class='muted'>{esc(record.get('at', ''))}</td></tr>"
            )
        body = "<table><tr><th>ID</th><th>Outcome</th><th>First seen (epoch)</th></tr>" + "".join(rows) + "</table>"
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

        with state_lock(cfg.state_path):
            core.manage_parked(cfg.state_path, release=True, now=int(time.time()))
        return RedirectResponse("/parked", status_code=303)

    @app.post("/parked/drop", dependencies=[Depends(require_csrf)])
    def parked_drop(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        from . import core
        from .state import state_lock

        with state_lock(cfg.state_path):
            core.manage_parked(cfg.state_path, release=False, now=int(time.time()))
        return RedirectResponse("/parked", status_code=303)

    @app.get("/config", response_class=HTMLResponse)
    def config_page(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        src = "".join(
            f"<li><b>{esc(s['id'])}</b> ({esc(s.get('type', ''))}) — {esc(_public_url(s.get('url', '')))}</li>"
            for s in cfg.sources
        )
        ntf = "".join(f"<li><b>{esc(n['id'])}</b> ({esc(n.get('type', ''))})</li>" for n in cfg.notifiers)
        body = (
            f"<h2>Sources</h2><ul>{src}</ul><h2>Notifiers</h2><ul>{ntf}</ul>"
            f"<p class='muted'>Poll interval {cfg.poll_interval_seconds}s · state {esc(cfg.state_path)} · "
            f"watchlist {esc(cfg.watchlist_path or 'built-in default')}</p>"
            "<p class='muted'>Edit config/config.yml on the volume and restart; secrets come from the "
            "environment only.</p>"
        )
        return page("Configuration", body, nav_extra=sign_out_form(request))

    @app.get("/runs", response_class=HTMLResponse)
    def runs_page(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        rows = "".join(
            f"<tr><td>{esc(r.get('at', ''))}</td><td>{r.get('sent', 0)}</td><td>{r.get('parked', 0)}</td>"
            f"<td>{r.get('pending', 0)}</td><td>{r.get('code', '')}</td></tr>"
            for r in reversed(load_state().get("runs", []))
        )
        return page(
            "Runs",
            nav_extra=sign_out_form(request),
            body="<table><tr><th>At</th><th>Sent</th><th>Parked</th><th>Pending</th><th>Exit</th></tr>"
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
        from .state import SourceError

        try:
            state = load_state()
        except SourceError as exc:
            return PlainTextResponse(f"not ready: {exc}", status_code=503)
        ok, reason = readiness(cfg, state, int(clock()))
        return PlainTextResponse(reason, status_code=200 if ok else 503)

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        from .state import SourceError

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
        ok, _ = readiness(cfg, state, int(clock()))
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
                _number(last.get("at")),
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
        from .state import LockBusy, load_state_document, save_state, state_lock

        secret = env.get("ADVISORY_RADAR_WEBHOOK_SECRET", "")
        if not secret or source_id not in webhook_sources:
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

        def store() -> None:
            with state_lock(cfg.state_path, blocking=False):
                state = load_state_document(cfg.state_path, _core.STATE_SCHEMA, "advisory state") or _core.new_state()
                inbox = state.setdefault("webhook_inbox", {}).setdefault(source_id, [])
                # A full inbox refuses the new entry rather than dropping an accepted one: an acknowledged
                # advisory must never be discarded unprocessed.
                if len(inbox) >= WEBHOOK_INBOX_LIMIT:
                    raise InboxFull
                inbox.append(entry)
                save_state(cfg.state_path, state)

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
