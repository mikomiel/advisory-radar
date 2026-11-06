"""Web UI and health/metrics endpoints (FastAPI, server-rendered HTML).

One process serves the UI, the REST-ish actions and the in-process scheduler
(see cli.py ``run``). Auth is a single bearer token from the environment
(``ADVISORY_RADAR_AUTH_TOKEN``); /healthz and /metrics stay unauthenticated for
container probes and scrapers. Pages are plain HTMLResponse renders -- no
frontend build step.
"""

from __future__ import annotations

import hmac
import html
import json
import os
import time
import urllib.parse
from collections.abc import Callable, Mapping

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeSerializer

from .config import Config

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>advisory-radar</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;max-width:60rem;color:#1a1a1a}}
nav a{{margin-right:1rem}} table{{border-collapse:collapse}} td,th{{border:1px solid #ccc;padding:.25rem .6rem}}
.tag-critical{{color:#b00020;font-weight:bold}} .tag-warning{{color:#9a6700}} .muted{{color:#666}}
form{{display:inline}} button{{cursor:pointer}}
</style></head><body><nav><a href="/">Dashboard</a><a href="/alerts">Alerts</a>
<a href="/parked">Parked</a><a href="/config">Config</a><a href="/runs">Runs</a>
<a href="/healthz">healthz</a></nav><h1>{title}</h1>{body}</body></html>"""


def esc(value: object) -> str:
    return html.escape(str(value))


def page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(PAGE.format(title=esc(title), body=body))


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


def last_pass_code(state: dict) -> int:
    runs = state.get("runs") or []
    return int(runs[-1].get("code", -1)) if runs else -1


class InboxFull(Exception):
    """A webhook source's inbox is at capacity; the sender must retry, nothing is discarded."""


def _insecure_cookies(env: Mapping[str, str]) -> bool:
    """Whether the plaintext-cookie opt-out is set (development only; the default is a Secure cookie)."""
    return env.get("ADVISORY_RADAR_INSECURE_COOKIES", "").strip().lower() in {"1", "true", "yes", "on"}


def create_app(
    cfg: Config, env: dict[str, str], *, run_pass: Callable[..., int] | None = None, sources=None, notifiers=None
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
        # parse the urlencoded body by hand: no python-multipart dependency
        import urllib.parse

        form = urllib.parse.parse_qs((await request.body()).decode("utf-8", "replace"))
        token = (form.get("token") or [""])[0]
        expected = env.get("ADVISORY_RADAR_AUTH_TOKEN", "")
        # constant-time compare: a byte-by-byte comparison leaks how much of the token matched
        if token and expected and hmac.compare_digest(token.encode(), expected.encode()):
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
        return page(
            "Login",
            '<p>Wrong token.</p><form method="post" action="/login">'
            '<input type="password" name="token"><button>Sign in</button></form>',
        )

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
            '<form method="post" action="/run"><button>Run a pass now</button></form>'
        )
        return page("Dashboard", body)

    @app.post("/run")
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
        return page("Alerts", body)

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
            '<form method="post" action="/parked/release"><button>Release all</button></form> '
            '<form method="post" action="/parked/drop"><button>Drop all</button></form>'
        )
        return page("Parked messages", body)

    @app.post("/parked/release")
    def parked_release(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        from . import core
        from .state import state_lock

        with state_lock(cfg.state_path):
            core.manage_parked(cfg.state_path, release=True, now=int(time.time()))
        return RedirectResponse("/parked", status_code=303)

    @app.post("/parked/drop")
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
        return page("Configuration", body)

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
            "<table><tr><th>At</th><th>Sent</th><th>Parked</th><th>Pending</th><th>Exit</th></tr>" + rows + "</table>",
        )

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz():
        return PlainTextResponse("ok")

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        state = load_state()
        lines = [
            "# HELP advisory_radar_pending Pending messages awaiting delivery",
            "# TYPE advisory_radar_pending gauge",
            f"advisory_radar_pending {len(state.get('pending', []))}",
            "# HELP advisory_radar_parked Parked messages awaiting an operator decision",
            "# TYPE advisory_radar_parked gauge",
            f"advisory_radar_parked {len(state.get('parked', []))}",
            "# HELP advisory_radar_seen_total Items ever seen",
            "# TYPE advisory_radar_seen_total counter",
            f"advisory_radar_seen_total {len(state.get('seen', {}))}",
            "# HELP advisory_radar_last_pass_exit Exit code of the last pass",
            "# TYPE advisory_radar_last_pass_exit gauge",
            f"advisory_radar_last_pass_exit {last_pass_code(load_state())}",
        ]
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
        body = await request.body()
        if len(body) > WEBHOOK_BODY_LIMIT:
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
