"""Web UI and health/metrics endpoints (FastAPI, server-rendered HTML).

One process serves the UI, the REST-ish actions and the in-process scheduler
(see cli.py ``run``). Auth is a single bearer token from the environment
(``ADVISORY_RADAR_AUTH_TOKEN``); /healthz and /metrics stay unauthenticated for
container probes and scrapers. Pages are plain HTMLResponse renders -- no
frontend build step.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import html
import json
import logging
import os
import re
import time
import urllib.parse
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeSerializer

from . import __version__, pipeline
from .catalogue import SOURCE_SPECS
from .config import Config, ConfigError, config_from_document, expand_entry, load_document, secret_values
from .http import Http, private_destination, resolve_host, urllib_http
from .notifiers import NOTIFIER_BUILDERS
from .runtime import Runtime
from .settings import (
    SECRET_KEYS,
    SETTINGS_LOCK,
    is_reference,
    load_settings_document,
    save_settings,
)
from .settings import (
    fingerprint as settings_fingerprint,
)
from .sources import build_source
from .state import LockBusy, SourceError

LOG = logging.getLogger("advisory_radar")

#: The page's one inline stylesheet. A plain string, not an f-string: its braces stay single because
#: ``page`` interpolates the value instead of formatting it. Every colour pair was measured against WCAG
#: AA (text 4.5:1, control borders 3:1) in both schemes; ``--line`` is a decorative hairline only.
_STYLE = """<style>
:root{--bg:#FBFAF8;--surface:#FFFFFF;--ink:#171512;--muted:#6B6660;--line:#E2DDD2;--control:#767065;
--hover:#F1EEE7;--critical:#A3150F;--on-critical:#FFFFFF;--warning:#7A5200;--ok:#1B6B3D;
--sans:ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace;
color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#12110F;--surface:#1A1916;--ink:#F3F0E8;--muted:#A9A39A;
--line:#2E2C27;--control:#6B665B;--hover:#1E1D19;--critical:#F87171;--on-critical:#12110F;--warning:#E0A63A;
--ok:#6FD08C}}
*,*::before,*::after{box-sizing:border-box}
body{margin:0 auto;max-width:72rem;padding:0 2rem;background:var(--bg);color:var(--ink);
font-family:var(--sans);font-size:15px;line-height:1.6;font-variant-numeric:tabular-nums}
a{color:inherit;text-underline-offset:2px;text-decoration-thickness:1px}
a:hover{text-decoration-thickness:2px}
:focus-visible{outline:2px solid var(--ink);outline-offset:2px;border-radius:1px}
::selection{background:var(--ink);color:var(--bg)}
p{margin:.6rem 0}
code,pre{font-family:var(--mono);font-size:.9em}
pre{margin:.3rem 0;padding:.6rem .7rem;background:var(--surface);border:1px solid var(--line);overflow-x:auto}
ul{margin:.6rem 0 1rem;padding-left:1.15rem}
.skip{position:absolute;left:-9999px}
.skip:focus{left:1rem;top:.6rem;z-index:20;padding:.4rem .7rem;background:var(--ink);
color:var(--bg);text-decoration:none}
header.top{display:flex;align-items:center;gap:1.25rem;flex-wrap:wrap;padding:1rem 0;
border-bottom:1px solid var(--ink);position:sticky;top:0;z-index:10;background:var(--bg)}
.brand{display:inline-flex;align-items:center;gap:.55rem;margin-right:auto;font-weight:600;
letter-spacing:-.01em;text-decoration:none}
.mark{position:relative;width:11px;height:11px;border:1.5px solid currentColor;border-radius:50%}
.mark::after{content:'';position:absolute;inset:2.5px;border-radius:50%;background:currentColor}
nav.links{display:flex;gap:1.1rem;font-size:13px}
nav.links a{color:var(--muted);text-decoration:none;padding:.15rem 0;border-bottom:2px solid transparent}
nav.links a:hover{color:var(--ink)}
nav.links a[aria-current='page']{color:var(--ink);border-bottom-color:var(--ink)}
.session{font-size:13px}
.session form{display:inline;margin:0}
main{width:100%;padding-bottom:2rem}
.page-head{padding:1.9rem 0 .75rem}
h1{margin:0;font-size:clamp(1.6rem,1.2rem + 1.4vw,2rem);line-height:1.12;font-weight:600;
letter-spacing:-.02em;overflow-wrap:anywhere}
h2{margin:2.4rem 0 .5rem;padding-top:1.2rem;border-top:1px solid var(--line);font-size:1.05rem;
font-weight:600;letter-spacing:-.01em}
h3{margin:1.8rem 0 .4rem;color:var(--muted);font-size:12px;font-weight:600;letter-spacing:.08em;
text-transform:uppercase}
.muted{color:var(--muted)}
.small{font-size:13px}
.sec-num{margin-right:.55rem;color:var(--muted);font-family:var(--mono);font-size:12px;letter-spacing:0}
table{width:100%;border-collapse:collapse;margin:.5rem 0 1rem;font-size:14px}
table.levels{max-width:34rem}
th{padding:.5rem .55rem;border-bottom:1px solid var(--ink);color:var(--muted);font-size:11px;
font-weight:600;letter-spacing:.09em;text-transform:uppercase;text-align:left;white-space:nowrap}
td{padding:.55rem;border-bottom:1px solid var(--line);vertical-align:top}
td.nowrap,th.nowrap{white-space:nowrap}
th.narrow{width:5rem}
th.tag-col{width:15rem}
tr:hover td{background:var(--hover)}
td.num,th.num{text-align:right}
.scroll{overflow-x:auto}
.scroll table{min-width:40rem}
table.compact{width:auto;min-width:32rem}
.scroll table.compact{min-width:32rem}
.badge{display:inline-block;padding:0 .38rem;border:1px solid currentColor;border-radius:2px;
font-family:var(--mono);font-size:11px;font-weight:600;line-height:1.7;letter-spacing:.05em;
text-transform:uppercase;white-space:nowrap}
.badge-critical{color:var(--critical)}
.badge-warning{color:var(--warning)}
.badge-ok{color:var(--ok)}
.badge-neutral{color:var(--muted)}
.dot{display:inline-block;width:8px;height:8px;margin-right:.45rem;border-radius:50%;
background:var(--muted);vertical-align:baseline}
.dot-ok{background:var(--ok)}
.dot-bad{background:var(--critical)}
.notice{margin:.8rem 0;padding:.6rem .8rem;border:1px solid var(--line);border-left:3px solid var(--muted);
background:var(--surface);font-size:13.5px}
.notice-ok{border-left-color:var(--ok)}
.notice-warning{border-left-color:var(--warning)}
.notice-critical{border-left-color:var(--critical)}
button,.btn{display:inline-flex;align-items:center;gap:.4rem;margin:0;padding:.5rem .75rem;
border:1px solid var(--control);border-radius:2px;background:transparent;color:var(--ink);
font-family:inherit;font-size:13px;font-weight:500;line-height:1.1;cursor:pointer;text-decoration:none}
button:hover,.btn:hover{background:var(--hover)}
.btn-primary,.btn-primary:hover{border-color:var(--ink);background:var(--ink);color:var(--bg)}
.btn-danger{color:var(--critical);border-color:var(--critical)}
.btn-danger:hover{background:var(--critical);color:var(--on-critical)}
.btn-quiet{border-color:transparent;color:var(--muted)}
.btn-quiet:hover{color:var(--ink)}
label{display:grid;gap:.3rem;color:var(--muted);font-size:12px}
label>input:not([type='checkbox']),label>select,label>textarea{width:100%}
label.inline{display:flex;align-items:center;gap:.45rem;margin:.15rem 0}
label.inline>input{flex:1;min-width:6rem}
input,select,textarea{max-width:100%;padding:.35rem .5rem;border:1px solid var(--control);border-radius:2px;
background:var(--surface);color:var(--ink);font-family:inherit;font-size:14px}
input[type='checkbox']{width:1rem;height:1rem;padding:0;accent-color:var(--ink)}
textarea{width:100%;min-height:5rem}
input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid var(--ink);outline-offset:1px}
form.toolbar{display:flex;flex-wrap:wrap;align-items:flex-end;gap:.85rem 1rem;padding:1rem 0 1.1rem;
border-bottom:1px solid var(--line)}
form.toolbar input,form.toolbar select{min-width:7.5rem}
form.toolbar input[type='date']{min-width:9rem}
.toolbar-actions{display:flex;gap:.5rem;margin-left:auto}
.fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(16rem,1fr));gap:1rem;margin:.8rem 0 1.1rem}
label.poll{max-width:18rem}
.field-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:.5rem .9rem}
.notifier{padding:1.1rem 0;border-bottom:1px solid var(--line)}
.notifier-head{display:flex;flex-wrap:wrap;align-items:center;gap:.6rem;margin-bottom:.7rem}
.notifier-head b{font-size:15px}
label.check{display:inline-flex;align-items:center;gap:.4rem;margin-left:auto;color:var(--muted);font-size:12px}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));margin:.5rem 0 .75rem;
border-top:1px solid var(--ink);border-bottom:1px solid var(--line)}
.stat{padding:.9rem 1rem .9rem 0;border-right:1px solid var(--line)}
.stat:last-child{border-right:0}
.stat-label{display:block;color:var(--muted);font-size:11px;letter-spacing:.09em;text-transform:uppercase}
.stat-value{display:block;font-family:var(--mono);font-size:1.9rem;line-height:1.25;letter-spacing:-.02em}
.pass{display:flex;flex-wrap:wrap;align-items:center;gap:.6rem 1.25rem;padding:1rem 0 1.1rem;
border-bottom:1px solid var(--line)}
.pass .grow{margin-right:auto}
.pass p{margin:0}
.bulk{display:flex;flex-wrap:wrap;gap:.5rem;padding:1rem 0;border-bottom:1px solid var(--line)}
.row-actions{display:flex;flex-wrap:wrap;gap:.4rem}
.row-actions form{display:inline}
nav.pager{display:flex;justify-content:space-between;gap:.6rem;margin:1rem 0 0}
.empty{margin:1.25rem 0;padding:1.25rem;border:1px dashed var(--control);color:var(--muted)}
.empty p:first-child{margin-top:0}
.empty p:last-child{margin-bottom:0}
dl.facts{display:grid;grid-template-columns:minmax(9rem,13rem) 1fr;gap:.15rem 1.25rem;margin:1.1rem 0 0}
dl.facts div{display:contents}
dt{padding:.25rem 0;color:var(--muted);font-size:11px;letter-spacing:.07em;text-transform:uppercase}
dd{margin:0;padding:.25rem 0;overflow-wrap:anywhere}
.strip{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:.75rem 1.5rem;
padding:.9rem 0;border-bottom:1px solid var(--line)}
.strip p{margin:0}
.login{max-width:24rem;margin:1.25rem 0 0;padding:1.5rem;background:var(--surface);border:1px solid var(--line)}
.login form{display:grid;gap:.6rem;margin-top:1rem}
.login button{justify-content:center}
.back{margin:1.75rem 0 0;font-size:13px}
footer.bottom{display:flex;flex-wrap:wrap;justify-content:space-between;gap:.4rem 1.5rem;
padding:1.1rem 0;border-top:1px solid var(--line);color:var(--muted);font-size:12px}
footer.bottom a{color:var(--muted);text-decoration:none}
footer.bottom a:hover{color:var(--ink);text-decoration:underline}
.probes{display:flex;gap:1rem}
@media (max-width:48rem){
body{padding:0 1.1rem}
header.top{position:static;gap:.6rem;padding:.85rem 0}
.brand{order:1}
.session{order:2;margin-left:auto}
nav.links{order:3;width:100%;flex-wrap:nowrap;overflow-x:auto;gap:.9rem;padding-bottom:.15rem}
.stats{grid-template-columns:repeat(2,minmax(0,1fr))}
.stat{padding:.8rem 0;border-right:0;border-bottom:1px solid var(--line)}
.stat:nth-child(2n){padding-left:1rem;border-left:1px solid var(--line)}
dl.facts{grid-template-columns:1fr;gap:0}
dt{margin-top:.55rem}
}
@media print{
header.top,footer.bottom,.session,form.toolbar,nav.pager,.bulk,.row-actions{display:none}
body{max-width:none;background:#fff;color:#000}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>"""

#: The authenticated navigation, in reading order: (path, label).
_NAV = (
    ("/", "Dashboard"),
    ("/alerts", "Alerts"),
    ("/parked", "Parked"),
    ("/config", "Config"),
    ("/sources", "Sources"),
    ("/runs", "Runs"),
)


def esc(value: object) -> str:
    return html.escape(str(value))


def _nav(active: str) -> str:
    """The section links, with the current page marked for assistive technology and for the stylesheet."""
    links = []
    for path, label in _NAV:
        current = " aria-current='page'" if path == active else ""
        links.append(f"<a href='{path}'{current}>{label}</a>")
    return f"<nav class='links' aria-label='Main'>{''.join(links)}</nav>"


def page(
    title: str,
    body: str,
    *,
    active: str = "",
    actions: str = "",
    minimal: bool = False,
    status_code: int = 200,
    headers: Mapping[str, str] | None = None,
) -> HTMLResponse:
    """One page: the shared shell (head, navigation, title, footer) around a page's body.

    ``actions`` is the sign-out form, and is what makes the navigation authenticated; ``minimal`` keeps the
    brand alone, for the pages a signed-out visitor sees. ``active`` is the path the navigation marks as the
    current section, so an advisory page keeps "Alerts" marked.
    """
    brand = "<a class='brand' href='/'><span class='mark' aria-hidden='true'></span>advisory-radar</a>"
    header = brand if minimal else f"{brand}{_nav(active)}<div class='session'>{actions}</div>"
    document = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta name='color-scheme' content='light dark'>"
        f"<title>{esc(title)} · advisory-radar</title>{_STYLE}</head><body>"
        "<a class='skip' href='#main'>Skip to content</a>"
        f"<header class='top'>{header}</header>"
        f"<main id='main'><div class='page-head'><h1>{esc(title)}</h1></div>{body}</main>"
        f"<footer class='bottom'><span>advisory-radar {esc(__version__)}</span>"
        "<span class='probes'><a href='/healthz'>healthz</a><a href='/readyz'>readyz</a>"
        "<a href='/metrics'>metrics</a></span></footer></body></html>"
    )
    return HTMLResponse(document, status_code=status_code, headers=headers)


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
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return ""
    if not parts.scheme or not parts.hostname:
        return ""
    return f"{parts.scheme}://{parts.hostname}"


#: Why a source added from the settings overlay may not point into a private network. One wording, so the probe
#: and the save form cannot drift.
PRIVATE_SOURCE_REFUSAL = (
    "this address is on a private network, and a source added on this page may not point there; "
    "add it in config.yml, or set allow_private_sources: true"
)


def _url_scheme(url: str) -> str:
    """The scheme of a URL a person typed, or "" when it cannot be parsed as one."""
    try:
        return urllib.parse.urlsplit(url).scheme
    except ValueError:
        return ""


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


#: One page of /alerts: a screenful of rows, and small enough to stay fast on a phone.
ALERT_PAGE_SIZE = 50
#: The filters /alerts keeps in the URL. One tuple, so the form and the pagination links cannot disagree.
ALERT_FILTERS = ("tag", "source", "outcome", "q", "since", "until")
#: The outcomes a seen record can carry. A filter value outside this list matches nothing.
SEEN_OUTCOMES = ("delivered", "dropped", "filtered", "suppressed", "backlog", "alias", "not-security")


def _advisory_token(identifier: str) -> str:
    """A slash-free path segment for an identifier, which may itself be (or contain) a URL."""
    return base64.urlsafe_b64encode(identifier.encode("utf-8")).decode("ascii").rstrip("=")


def _advisory_identifier(token: str) -> str:
    """The identifier an advisory link names; a 400 page when the segment was not produced by the list."""
    try:
        identifier = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True).decode("utf-8")
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="malformed advisory link; open /alerts and follow a row") from None
    if not identifier:
        raise HTTPException(status_code=400, detail="malformed advisory link; open /alerts and follow a row")
    return identifier


#: The severity tags a message can carry; the alert filter and the route form offer these.
TAGS = ("critical", "warning")
#: Fixed route rows on /config. More rules already configured are rendered too, so a save cannot drop them.
ROUTE_FORM_ROWS = 3


def _day_start(value: str, where: str) -> int:
    """A ``YYYY-MM-DD`` filter as the UTC epoch of that day's midnight; a 400 page when it is not a date."""
    try:
        return int(datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC).timestamp())
    except (ValueError, OverflowError):
        raise HTTPException(status_code=400, detail=f"{where} must be a date like 2026-10-21") from None


def _cursor_encode(at: int, identifier: str) -> str:
    """A page position as URL-safe base64 of ``at:identifier``, without padding."""
    return base64.urlsafe_b64encode(f"{at}:{identifier}".encode()).decode("ascii").rstrip("=")


def _cursor_decode(value: str) -> tuple[int, str]:
    """The position a ``cursor``/``before`` parameter names; a 400 page when it is not one.

    ``identifier`` is split off at the first colon, because a stored identifier may contain one
    (``src:<guid>``). Nothing else about the value is trusted: it comes from the URL.
    """
    malformed = HTTPException(status_code=400, detail="malformed page cursor; open /alerts again")
    try:
        # ``validate`` is the point: the default decoder silently drops characters outside the alphabet, so
        # ``...!`` would decode instead of being refused. URL-safe characters only, no padding requirement.
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True).decode("utf-8")
    except (binascii.Error, ValueError):
        raise malformed from None
    at, separator, identifier = raw.partition(":")
    if not separator or not identifier:
        raise malformed
    try:
        return int(at), identifier
    except ValueError:
        raise malformed from None


def _position(identifier: str, record: Mapping) -> tuple[int, str]:
    """A seen record's sort position: its recorded time, then the identifier ascending.

    A record without a usable time sorts as epoch zero rather than raising: one hand-edited field must
    not take the alert history down, and the page already renders such a time as blank.
    """
    return _number(record.get("at"), 0), identifier


def _matches_seen(
    identifier: str,
    record: Mapping,
    filters: Mapping[str, str],
    since: int | None,
    until: int | None,
) -> bool:
    """Whether one seen record passes every filter.

    A record that predates the delivery snapshot carries only ``at``/``outcome``, so a tag, source or
    title filter excludes it -- matching on an empty value would be a lie. The date range and the text
    filter still apply, so it stays findable by its identifier.
    """
    if filters.get("tag") and record.get("tag") != filters["tag"]:
        return False
    if filters.get("source") and record.get("source") != filters["source"]:
        return False
    if filters.get("outcome") and record.get("outcome") != filters["outcome"]:
        return False
    text = filters.get("q")
    if text:
        needle = text.casefold()
        title = record.get("title")
        if needle not in identifier.casefold() and not (isinstance(title, str) and needle in title.casefold()):
            return False
    at = _number(record.get("at"), 0)
    if since is not None and at < since:
        return False
    return until is None or at < until


def _alert_page(
    rows: Sequence[tuple[tuple[int, str], Mapping]],
    cursor: tuple[int, str] | None,
    before: tuple[int, str] | None,
) -> tuple[list[tuple[tuple[int, str], Mapping]], tuple[int, str] | None, tuple[int, str] | None]:
    """One page of seen records, and the positions its previous/next links point at.

    Keyset, not an offset: both directions slice the same ordered list, so a record arriving between two
    requests cannot shift a page and make a row repeat or go missing. ``cursor`` continues towards older
    records (the next link); ``before`` towards newer ones (the previous link). Newest first by
    ``(at desc, identifier asc)``.
    """
    ordered = sorted(rows, key=lambda item: (-item[0][0], item[0][1]))
    keys = [(-position[0], position[1]) for position, _ in ordered]
    if cursor is not None:
        start = (-cursor[0], cursor[1])
        window = [item for item, key in zip(ordered, keys, strict=True) if key > start][:ALERT_PAGE_SIZE]
    elif before is not None:
        limit = (-before[0], before[1])
        newer = [item for item, key in zip(ordered, keys, strict=True) if key < limit]
        window = newer[-ALERT_PAGE_SIZE:]
    else:
        window = ordered[:ALERT_PAGE_SIZE]
    if not window:
        return [], None, None
    first, last = window[0][0], window[-1][0]
    first_key, last_key = (-first[0], first[1]), (-last[0], last[1])
    # One row past either edge is enough to know that direction has a page, without counting pages.
    previous = first if keys and keys[0] < first_key else None
    following = last if keys and keys[-1] > last_key else None
    return list(window), previous, following


def _short(value: object, limit: int = 70) -> str:
    """A stored string cut to ``limit`` characters for a table cell, and escaped after the cut.

    Cutting the escaped text would split an entity such as ``&amp;`` and render the fragment literally.
    """
    text = "" if value is None else str(value)
    return esc(text if len(text) <= limit else f"{text[:limit]}…")


def _external_link(url: object, text: object = None) -> str:
    """A stored URL as an anchor when it is a public https URL, and as escaped text otherwise.

    The link comes from state, which is a file a person can edit: rendering it as an ``href`` without a
    check would make every page offer whatever scheme it named.
    """
    label = esc(_field(text) or _field(url))
    if not isinstance(url, str) or not url.startswith("https://"):
        return label
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        # A stored link can be malformed (``https://[broken``); it renders as text, never raises.
        return label
    if not parts.hostname or "@" in parts.netloc:
        return label
    return f"<a href='{esc(url)}' rel='noreferrer'>{label}</a>"


def _levels_table(levels: object, scores: object) -> str:
    """One row per recorded CVE, with the level and CVSS the message was classified with."""
    if not isinstance(levels, Mapping) or not levels:
        return "<p class='muted'>No per-CVE level was recorded for this message.</p>"
    recorded = scores if isinstance(scores, Mapping) else {}
    rows = []
    for cve in sorted(levels, key=str):
        score = recorded.get(cve)
        if cve not in recorded:
            shown = "<span class='muted'>not recorded</span>"
        elif isinstance(score, (int, float)) and not isinstance(score, bool):
            shown = esc(f"{score:g}")
        elif score is None:
            shown = "<span class='muted'>unscored</span>"
        elif isinstance(score, str):
            shown = esc(score)
        else:
            shown = "<span class='muted'>not recorded</span>"
        level = _field(levels[cve])
        rows.append(
            f"<tr><td class='mono'>{esc(cve)}</td>"
            f"<td>{_badge(level, level) if level else "<span class='muted'>not recorded</span>"}</td>"
            f"<td>{shown}</td></tr>"
        )
    return (
        "<div class='scroll'><table class='levels'><tr><th scope='col'>CVE</th><th scope='col'>Level</th>"
        "<th scope='col'>CVSS</th></tr>" + "".join(rows) + "</table></div>"
    )


def _facts(facts: Sequence[tuple[str, str]]) -> str:
    """A two-column definition list of already-escaped/rendered values."""
    rows = "".join(f"<div><dt>{esc(name)}</dt><dd>{value}</dd></div>" for name, value in facts)
    return f"<dl class='facts'>{rows}</dl>"


def _identifier_list(values: object) -> str:
    """A stored list of identifiers; a nested container is skipped, never rendered as a Python repr."""
    if not isinstance(values, (list, tuple)) or not values:
        return "<span class='muted'>(none recorded)</span>"
    shown = [value for value in values if not isinstance(value, (dict, list, tuple, set))]
    if not shown:
        return "<span class='muted'>(none recorded)</span>"
    return ", ".join(esc(value) for value in shown)


def _field(value: object) -> str:
    """A stored scalar as text; a malformed value is shown as the absence it is, never as a Python repr."""
    return value if isinstance(value, str) else ""


def _section(path: str) -> str:
    """The navigation section a path belongs to, so an error page keeps the reader's place.

    Action routes belong to the page that issued them: ``/run`` and ``/reload`` are reached from the
    dashboard and the configuration page. A global action such as ``/logout`` belongs to no section, which
    is the empty answer.
    """
    if path == "/":
        return "/"
    if path.startswith("/advisories/"):
        return "/alerts"
    if path == "/run":
        return "/"
    if path == "/reload":
        return "/config"
    for known, _ in _NAV:
        if known != "/" and (path == known or path.startswith(f"{known}/")):
            return known
    return ""


def _badge(text: object, kind: str = "neutral") -> str:
    """A small uppercase chip; ``kind`` is one of neutral, ok, warning or critical."""
    return f"<span class='badge badge-{esc(kind)}'>{esc(text)}</span>"


def _notice(rendered: str, kind: str = "neutral") -> str:
    """A tone-marked block around already-rendered HTML (never an unescaped value from the caller)."""
    return f"<p class='notice notice-{esc(kind)}'>{rendered}</p>"


def _empty(message: str, hint: str = "") -> str:
    """The answer when a list has no rows: one sentence instead of an empty table."""
    tail = f"<p>{hint}</p>" if hint else ""
    return f"<div class='empty'><p>{message}</p>{tail}</div>"


def _stats(pairs: Sequence[tuple[str, object]]) -> str:
    """The dashboard's headline numbers: one label above one value per tile."""
    tiles = "".join(
        f"<div class='stat'><span class='stat-label'>{esc(label)}</span>"
        f"<span class='stat-value'>{esc(value)}</span></div>"
        for label, value in pairs
    )
    return f"<section class='stats'>{tiles}</section>"


def _exit_code(value: object) -> tuple[str, str]:
    """A stored exit code as text and the tone it earns.

    Only an integer is a recorded result: 0 is good, anything else is a failure. A hand-edited or older
    value is shown as unknown with a neutral tone rather than as a Python repr or a false failure.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value), ("ok" if value == 0 else "critical")
    return "?", "neutral"


def _outcome_tone(outcome: str) -> str:
    """The tone a recorded outcome carries: an accepted delivery is good, a drop is the loss it is."""
    if not isinstance(outcome, str):
        return "neutral"
    return {"delivered": "ok", "dropped": "critical"}.get(outcome, "neutral")


def _seen_advisory(record: Mapping, delivery: Mapping | None = None) -> str:
    """The detail page for an identifier the state has seen: the snapshot, or only what an older record held."""
    outcome = _field(record.get("outcome"))
    facts: list[tuple[str, str]] = [
        ("Outcome", _badge(outcome, _outcome_tone(outcome)) if outcome else "<span class='muted'>—</span>"),
        ("Recorded (UTC)", esc(_when(record.get("at"))) or "<span class='muted'>not recorded</span>"),
    ]
    record = delivery if isinstance(delivery, Mapping) else record
    back = "<p class='back'><a href='/alerts'>← Back to alerts</a></p>"
    if not any(key in record for key in ("tag", "source", "title", "levels", "scores", "delivered_to")):
        return (
            "<p>The state holds this identifier, but only its outcome and when it was recorded.</p>"
            "<p class='muted'>The delivered message's details were not recorded: this record was written by an "
            "older version of advisory-radar, or no message was delivered for this identifier. Nothing is "
            "reconstructed here, and the message body is not retained.</p>" + _facts(facts) + back
        )
    accepted = record.get("delivered_to")
    if isinstance(accepted, list) and accepted:
        delivered = ", ".join(esc(value) for value in accepted)
    elif outcome == "dropped":
        delivered = "<span class='muted'>none: dropped before any channel accepted it</span>"
    else:
        delivered = "<span class='muted'>not recorded</span>"
    title = _field(record.get("title"))
    facts += [
        ("Tag", esc(_field(record.get("tag"))) or "<span class='muted'>not recorded</span>"),
        ("Source", esc(_field(record.get("source"))) or "<span class='muted'>not recorded</span>"),
        ("Message kind", esc(_field(record.get("kind"))) or "<span class='muted'>not recorded</span>"),
        ("Identifiers", _identifier_list(record.get("ids"))),
        ("CVEs in this message", _identifier_list(record.get("cves"))),
        ("KEV-only (not scored here)", _identifier_list(record.get("kev_only"))),
        ("Matched products", _identifier_list(record.get("products"))),
        ("Accepted by", delivered),
        ("Advisory", _external_link(record.get("link")) or "<span class='muted'>not recorded</span>"),
    ]
    return (
        (f"<p class='lead'><b>{esc(title)}</b></p>" if title else "")
        + _facts(facts)
        + "<h2>CVEs and levels</h2>"
        + _levels_table(record.get("levels"), record.get("scores"))
        + back
    )


def _queued_advisory(state_label: str, entry: Mapping) -> str:
    """The detail page for a pending or parked message: everything the queued entry itself holds."""
    attempts = _number(entry.get("attempts"), 0)
    first = _when(entry.get("first_attempt_at"))
    parked_at = _when(entry.get("parked_at"))
    status = entry.get("last_status")
    attempts_text = f"{attempts}" + (f" (last HTTP {esc(status)})" if status is not None else "")
    if not attempts:
        attempts_text = "0 (never attempted)"
    accepted = entry.get("sent_to")
    title = _field(entry.get("title"))
    facts = [
        ("State", _badge(state_label, "warning" if state_label == "parked" else "neutral")),
        ("Tag", esc(_field(entry.get("tag"))) or "<span class='muted'>not recorded</span>"),
        ("Source", esc(_field(entry.get("source"))) or "<span class='muted'>not recorded</span>"),
        ("Message kind", esc(_field(entry.get("kind"))) or "<span class='muted'>not recorded</span>"),
        ("Identifiers", _identifier_list(entry.get("ids"))),
        ("CVEs in this message", _identifier_list(entry.get("cves"))),
        ("KEV-only (not scored here)", _identifier_list(entry.get("kev_only"))),
        ("Matched products", _identifier_list(entry.get("products"))),
        ("Accepted by", _identifier_list(accepted)),
        ("Delivery attempts", attempts_text),
        ("First attempt (UTC)", esc(first) or "<span class='muted'>not attempted yet</span>"),
        ("Advisory", _external_link(entry.get("link")) or "<span class='muted'>not recorded</span>"),
    ]
    if parked_at:
        facts.append(("Parked (UTC)", esc(parked_at)))
    return (
        (f"<p class='lead'><b>{esc(title)}</b></p>" if title else "")
        + _facts(facts)
        + "<h2>CVEs and levels</h2>"
        + _levels_table(entry.get("levels"), entry.get("scores"))
        + "<p class='back'><a href='/parked'>← Back to the parked queue</a></p>"
    )


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
#: Every editable key of a built-in source kind, so the "new source" block offers one field per key rather than
#: one form per kind. Which of them the chosen kind actually reads comes from the catalogue.
SOURCE_FORM_KEYS = tuple(
    sorted(
        {key for spec in SOURCE_SPECS.values() for key in (*spec.required, *spec.optional)}
        - {"id", "type", "enabled", "tag"}
    )
)
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
    http: Http = urllib_http,
    resolve: Callable[[str], Iterable[str]] = resolve_host,
) -> FastAPI:
    """The web UI over one live configuration.

    ``runtime`` is the process's :class:`~advisory_radar.runtime.Runtime`; pages read ``runtime.cfg``
    and the intake looks the configured sources up per request, so a reload applies without a
    restart. A bare :class:`Config` is wrapped in a runtime that never reloads, for a caller that
    constructs the app from an already-loaded config. ``http`` is the transport a source probe uses; it is
    injectable so a test can answer without a network.
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
            actions = sign_out_form(request) if auth.valid(request) else ""
            return page(
                "Error",
                _notice(esc(exc.detail), "critical"),
                active=_section(request.url.path),
                actions=actions,
                status_code=exc.status_code,
            )
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
            "Sign in",
            "<div class='login'><p class='muted small'>Enter the token this instance runs with: "
            "<code>ADVISORY_RADAR_AUTH_TOKEN</code>.</p>"
            '<form method="post" action="/login"><input type="password" name="token" '
            'placeholder="auth token" aria-label="Auth token" autofocus>'
            '<button class="btn btn-primary">Sign in</button></form></div>',
            minimal=True,
        )

    @app.post("/login")
    async def login(request: Request):
        peer = request.client.host if request.client else "unknown"

        def throttled(wait: int):
            return page(
                "Too many attempts",
                _notice("Too many failed sign-in attempts. Try again shortly.", "warning"),
                minimal=True,
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
            "Sign in",
            "<div class='login'>"
            + _notice("Wrong token.", "critical")
            + '<form method="post" action="/login"><input type="password" name="token" '
            'aria-label="Auth token" autofocus><button class="btn btn-primary">Sign in</button></form></div>',
            minimal=True,
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
        when = _when(last.get("at"))
        code_text, code_tone = _exit_code(last.get("code"))
        dot = {"ok": "dot dot-ok", "critical": "dot dot-bad"}.get(code_tone, "dot") if when else "dot"
        exit_badge = _badge(code_text, code_tone)
        body = (
            _stats(
                [
                    ("Pending", len(pending)),
                    ("Parked", len(parked)),
                    ("Seen in last 24h", today_seen),
                    ("Total seen", len(seen)),
                ]
            )
            + "<div class='pass'>"
            f"<p class='grow'><span class='{dot}'></span>Last pass: {esc(when or 'never')}</p>"
            f"<p class='muted small'>sent {esc(last.get('sent', 0))} · parked {esc(last.get('parked', 0))} · "
            f"exit {exit_badge}</p>"
            f'<form method="post" action="/run">{csrf_field(request)}'
            "<button class='btn btn-primary'>Run a pass now</button></form>"
            "</div>"
        )
        return page("Dashboard", body, active="/", actions=sign_out_form(request))

    @app.post("/run", dependencies=[Depends(require_csrf)])
    def run_now(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        code = run_pass(lock_blocking=False) if run_pass is not None else -1
        return RedirectResponse(f"/?ran={code}", status_code=303)

    @app.get("/alerts", response_class=HTMLResponse)
    def alerts(request: Request):
        """The seen identifiers, filtered and paged from the URL alone, so a reload or a shared link keeps them."""
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        state = load_state()
        seen = state.get("seen")
        seen = seen if isinstance(seen, dict) else {}
        filters = {key: (request.query_params.get(key) or "").strip() for key in ALERT_FILTERS}
        since = _day_start(filters["since"], "since") if filters["since"] else None
        until = _day_start(filters["until"], "until") + 86400 if filters["until"] else None
        # ``cursor`` wins when both are present: the links never produce both, and a hand-written URL that
        # does still gets a page rather than an error.
        cursor = _cursor_decode(request.query_params["cursor"]) if request.query_params.get("cursor") else None
        before = _cursor_decode(request.query_params["before"]) if request.query_params.get("before") else None
        deliveries = state.get("deliveries")
        deliveries = deliveries if isinstance(deliveries, dict) else {}

        def resolved(record: dict) -> dict:
            """The snapshot a seen record points at; the record's own time and outcome stay authoritative.

            A record written before the delivery table has no ``delivery`` key and is rendered as it is.
            """
            reference = record.get("delivery")
            snapshot = deliveries.get(reference) if isinstance(reference, str) else None
            if not isinstance(snapshot, dict):
                return record
            return {**snapshot, "at": record.get("at"), "outcome": record.get("outcome")}

        rows = []
        for identifier, record in seen.items():
            if not isinstance(record, dict):
                continue
            view = resolved(record)
            if _matches_seen(identifier, view, filters, since, until):
                rows.append((_position(identifier, view), view))
        window, previous, following = _alert_page(rows, cursor, before)

        def link(**overrides: str) -> str:
            """This page's filters plus one pagination position; empties never reach the URL."""
            params = {key: value for key, value in filters.items() if value}
            params.update({key: value for key, value in overrides.items() if value})
            return "/alerts" + (f"?{urllib.parse.urlencode(sorted(params.items()))}" if params else "")

        def option(value: str, current: str) -> str:
            selected = " selected" if value == current else ""
            return f"<option value='{esc(value)}'{selected}>{esc(value or 'any')}</option>"

        outcome_values = SEEN_OUTCOMES
        if filters["outcome"] and filters["outcome"] not in SEEN_OUTCOMES:
            outcome_values = (*SEEN_OUTCOMES, filters["outcome"])
        filter_form = (
            "<form class='toolbar' method='get' action='/alerts'>"
            f"<label>Tag<select name='tag'>{''.join(option(value, filters['tag']) for value in ('', *TAGS))}"
            "</select></label>"
            f"<label>Source<input type='text' name='source' value='{esc(filters['source'])}'></label>"
            f"<label>Outcome<select name='outcome'>"
            f"{''.join(option(value, filters['outcome']) for value in ('', *outcome_values))}</select></label>"
            f"<label>Text<input type='text' name='q' value='{esc(filters['q'])}'></label>"
            f"<label>Since<input type='date' name='since' value='{esc(filters['since'])}'></label>"
            f"<label>Until<input type='date' name='until' value='{esc(filters['until'])}'></label>"
            "<div class='toolbar-actions'><button class='btn btn-primary'>Filter</button>"
            "<a class='btn btn-quiet' href='/alerts'>Reset</a></div></form>"
        )
        table_rows = []
        for (_, identifier), record in window:
            path = _advisory_token(identifier)
            tag = _field(record.get("tag"))
            outcome = _field(record.get("outcome"))
            source = _field(record.get("source"))
            title = _field(record.get("title"))
            tone = {"delivered": " dot-ok", "dropped": " dot-bad"}.get(outcome, "")
            table_rows.append(
                f"<tr><td><a href='/advisories/{esc(path)}'>{esc(identifier)}</a></td>"
                f"<td>{_badge(tag, tag) if tag else "<span class='muted'>—</span>"}</td>"
                f"<td>{esc(source) if source else '—'}</td>"
                f"<td>{_short(title) if title else '—'}</td>"
                f"<td><span class='dot{tone}'></span>{esc(outcome)}</td>"
                f"<td class='muted nowrap'>{esc(_when(record.get('at')))}</td></tr>"
            )
        if table_rows:
            table = (
                "<div class='scroll'><table><tr><th scope='col'>ID</th><th scope='col'>Tag</th>"
                "<th scope='col'>Source</th><th scope='col'>Title</th><th scope='col'>Outcome</th>"
                "<th scope='col'>First seen (UTC)</th></tr>" + "".join(table_rows) + "</table></div>"
            )
        elif any(filters.values()):
            table = _empty("No records match these filters.", "<a href='/alerts'>Clear the filters</a>")
        else:
            table = _empty("No advisory has been recorded yet: the first pass fills this list.")
        pager = []
        if previous is not None:
            pager.append(f"<a class='btn' href='{esc(link(before=_cursor_encode(*previous)))}'>← Newer</a>")
        if following is not None:
            pager.append(f"<a class='btn' href='{esc(link(cursor=_cursor_encode(*following)))}'>Older →</a>")
        body = (
            filter_form
            + f"<p class='muted small'>{len(rows)} matching record(s). A dash means the record predates the "
            "delivery snapshot, so it carries no tag, source or title.</p>" + table
        )
        if pager:
            body += f"<nav class='pager' aria-label='Pages'>{''.join(pager)}</nav>"
        elif cursor is not None or before is not None:
            body += _empty(
                f"No records on this page. <a href='{esc(link())}'>Newest alerts</a>.",
            )
        return page("Alerts", body, active="/alerts", actions=sign_out_form(request))

    @app.get("/advisories/{token}", response_class=HTMLResponse)
    def advisory_page(token: str, request: Request):
        """One advisory, from the seen record first, then a pending message, then a parked one."""
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        identifier = _advisory_identifier(token)
        state = load_state()
        seen = state.get("seen")
        if isinstance(seen, dict) and isinstance(seen.get(identifier), dict):
            record = seen[identifier]
            deliveries = state.get("deliveries")
            reference = record.get("delivery")
            snapshot = (
                deliveries.get(reference) if isinstance(deliveries, dict) and isinstance(reference, str) else None
            )
            body = _seen_advisory(record, snapshot if isinstance(snapshot, dict) else None)
            return page(f"Advisory {identifier}", body, active="/alerts", actions=sign_out_form(request))
        for label, queue in (("pending", state.get("pending")), ("parked", state.get("parked"))):
            for entry in queue if isinstance(queue, list) else ():
                if isinstance(entry, dict) and identifier in (entry.get("ids") or ()):
                    body = _queued_advisory(label, entry)
                    return page(f"Advisory {identifier}", body, active="/alerts", actions=sign_out_form(request))
        raise HTTPException(status_code=404, detail=f"no advisory {identifier} is recorded")

    @app.get("/parked", response_class=HTMLResponse)
    def parked_page(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        state = load_state()
        parked = state.get("parked")
        parked = parked if isinstance(parked, list) else []
        csrf = csrf_field(request)
        rows = []
        from . import core

        for index, entry in enumerate(parked):
            if not isinstance(entry, dict):
                continue
            token = core.parked_token(entry)
            identities = entry.get("ids")
            shown = ""
            if isinstance(identities, list):
                shown = ", ".join(value for value in identities if isinstance(value, str))
            tag = _field(entry.get("tag"))
            rows.append(
                f"<tr><td>{_badge(tag, tag) if tag else '—'}</td>"
                f"<td>{esc(_field(entry.get('title')))}</td><td class='muted'>{esc(shown[:80])}</td>"
                f"<td><div class='row-actions'>"
                f"<form method='post' action='/parked/{index}/release'>{csrf}"
                f"<input type='hidden' name='token' value='{esc(token)}'>"
                "<button class='btn btn-primary'>Release</button></form>"
                f"<form method='post' action='/parked/{index}/drop'>{csrf}"
                f"<input type='hidden' name='token' value='{esc(token)}'>"
                "<button class='btn btn-danger'>Drop</button></form></div></td></tr>"
            )
        if rows:
            body = (
                "<div class='scroll'><table class='compact'><tr><th scope='col'>Tag</th>"
                "<th scope='col'>Title</th><th scope='col'>IDs</th><th scope='col'>Actions</th></tr>"
                + "".join(rows)
                + "</table></div>"
                f'<div class="bulk"><form method="post" action="/parked/release">{csrf}'
                '<button class="btn">Release all</button></form>'
                f'<form method="post" action="/parked/drop">{csrf}'
                '<button class="btn btn-danger">Drop all</button></form></div>'
            )
        else:
            body = _empty("Nothing is parked: no message is waiting for a decision.")
        return page("Parked messages", body, active="/parked", actions=sign_out_form(request))

    def parked_decision(index: int, release: bool, request: Request):
        """Release or drop one parked message under the state lock; a stale row is a 404.

        The bulk routes block on the lock, as they always have. A per-row action answers 409 instead: an
        operator who clicked one row should not be left waiting for a whole pass to finish. The hidden token
        the row carried is checked under the lock, so a message that moved into that position is not touched.
        """
        from . import core
        from .state import state_lock

        expected = first(form_body(request), "token")
        if not re.fullmatch(r"[0-9a-f]{16}", expected):
            # Fail closed: a form without the row token is not a row this page offered, so there is no
            # message it could be asking about.
            raise HTTPException(status_code=400, detail="missing or malformed row token; reload the parked queue")
        state_path = runtime.cfg.state_path
        try:
            with state_lock(state_path, blocking=False):
                changed = core.manage_parked_entry(state_path, index, release, now=int(time.time()), expected=expected)
        except LockBusy:
            return page(
                "Busy",
                "<p>A pass holds the state lock, so the queue was not changed. Try again shortly.</p>"
                "<p><a href='/parked'>Back to the parked queue</a></p>",
                active="/parked",
                actions=sign_out_form(request),
                status_code=409,
            )
        if not changed:
            raise HTTPException(
                status_code=404, detail=f"no parked message at position {index}; reload the parked queue"
            )
        return RedirectResponse("/parked", status_code=303)

    @app.post("/parked/{index}/release", dependencies=[Depends(require_csrf)])
    def parked_release_one(index: int, request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        return parked_decision(index, release=True, request=request)

    @app.post("/parked/{index}/drop", dependencies=[Depends(require_csrf)])
    def parked_drop_one(index: int, request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        return parked_decision(index, release=False, request=request)

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

    def saved_overlay() -> tuple[dict, int]:
        """The overlay as saved and its revision.

        An unreadable file counts as revision 0: the save that follows replaces it, and the page shows the
        error. The revision is what makes a stale form detectable, so both come from one read.
        """
        if runtime.overlay_path is None:
            return {}, 0
        try:
            stored = load_settings_document(runtime.overlay_path)
            return dict(stored["settings"]), int(stored["revision"])
        except ConfigError:
            return dict(runtime.overlay["settings"]), 0

    def form_fingerprint(document: dict) -> str:
        """A stable hash of the configuration a form was rendered from.

        The saved revision alone is not enough: deleting the overlay resets the counter, and a YAML edit does
        not move it, so a form issued before either would pass a revision check and rewrite rows it never saw.
        """
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def stale_form(request: Request, form: dict, document: dict):
        """Refuse a form rendered against a different configuration.

        A second tab would rewrite the whole section from its own rows: the fingerprint it carries covers both
        the saved overlay and the YAML the rows came from, so any change is a refusal rather than a silent loss.
        """
        if first(form, "fingerprint") == form_fingerprint(document):
            return None
        return page(
            "Not saved",
            "<p>The configuration changed since this page was loaded. Reload "
            "<a href='/config'>the configuration page</a> and make the change again.</p>",
            active="/config",
            actions=sign_out_form(request),
            status_code=409,
        )

    def form_document(overlay: dict) -> tuple[dict, str]:
        """The document the forms edit: the saved overlay merged over the YAML.

        Not ``runtime.document``: a revision saved while a pass held the lock has not been applied yet, and
        editing another section from the live snapshot would silently drop it. Falls back to the live
        document, with the reason, when the saved overlay cannot be merged.
        """
        if runtime.config_path is None:
            return runtime.document, ""
        try:
            return load_document(runtime.config_path, settings=overlay), ""
        except ConfigError as exc:
            return runtime.document, esc(str(exc))

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
        """One block per configured notifier: enabled, its non-secret keys, and its secret references."""
        rows = []
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                continue
            identifier = entry["id"]
            checked = " checked" if entry.get("enabled", True) is not False else ""
            # Every optional field is rendered, not only those the entry already carries: a defaulted value
            # must be settable, and a value cleared in one save must be settable again in the next.
            fields = " ".join(
                f"<label>{key}<input type='text' name='field:{esc(identifier)}:{key}' "
                f"value='{esc(entry.get(key, ''))}' "
                f"aria-label='{esc(key)} for {esc(identifier)}'></label>"
                for key in NOTIFIER_FORM_KEYS
            )
            rows.append(
                "<div class='notifier'><div class='notifier-head'>"
                f"<b>{esc(identifier)}</b><span class='muted'>{esc(entry.get('type', ''))}</span>"
                f"<label class='check'><input type='checkbox' name='enabled:{esc(identifier)}' value='1'{checked} "
                f"aria-label='Enabled {esc(identifier)}'>enabled</label>"
                f"</div><div class='field-grid'>{fields}</div>"
                f"<p class='muted small'>{notifier_notes(entry) or 'no secret reference recorded'}</p></div>"
            )
        return "".join(rows)

    def source_spec(entry: dict):
        """The catalogue entry for a configured source, or None for a type the catalogue does not know."""
        kind = entry.get("type")
        return SOURCE_SPECS.get(kind) if isinstance(kind, str) else None

    def added_source_ids(settings: dict) -> set[str]:
        """The ids the overlay itself adds; a configured row outside this set belongs to the YAML."""
        added = settings.get("sources_added")
        if not isinstance(added, list):
            return set()
        return {entry["id"] for entry in added if isinstance(entry, dict) and isinstance(entry.get("id"), str)}

    def source_keys(spec) -> tuple[str, ...]:
        """The editable keys of one kind: everything it declares except the id, type, enable flag and tag."""
        return tuple(key for key in (*spec.required, *spec.optional) if key not in ("id", "type", "enabled", "tag"))

    def saved_source_entries(overlay: dict) -> list[dict]:
        """The merged source list the forms edit: every YAML entry plus every entry the overlay adds."""
        document, _ = form_document(overlay)
        sources = document.get("sources") if isinstance(document, dict) else None
        return [entry for entry in (sources or []) if isinstance(entry, dict) and isinstance(entry.get("id"), str)]

    def derive_source_id(url: str, kind: str, taken: set[str]) -> str:
        """A stable id from a source URL's host, unique against the ids already configured.

        Deterministic on purpose: the same URL added twice yields the same base and takes the next free suffix,
        so the operator can recognise the row and a collision can never silently take over another source.
        """
        try:
            host = urllib.parse.urlsplit(url).hostname
        except ValueError:
            host = None  # a URL nobody can parse still yields a usable id; the fetch reports the rest
        base = re.sub(r"[^a-z0-9]+", "-", (host or kind).lower()).strip("-")[:40] or kind
        identifier, suffix = base, 1
        while identifier in taken:
            suffix += 1
            identifier = f"{base}-{suffix}"
        return identifier

    def new_source_from_form(form: dict[str, list[str]]) -> tuple[dict | None, str]:
        """The source the "new source" block describes, or why it cannot be one yet.

        Only the keys the chosen kind declares are kept: the block shows every kind's keys, so a value left in a
        field another kind reads must not become a key this source ignores.
        """
        kind = first(form, "new:type").strip()
        spec = SOURCE_SPECS.get(kind)
        if spec is None:
            return None, f"{kind or 'the new source'} is not a built-in source type"
        entry: dict = {"type": kind}
        for key in source_keys(spec):
            value = first(form, f"new:{key}").strip()
            if value:
                entry[key] = value
        identifier = first(form, "new:id").strip()
        if not identifier and "url" in entry:
            taken = {candidate["id"] for candidate in saved_source_entries(saved_overlay()[0])}
            identifier = derive_source_id(entry["url"], kind, taken)
        if identifier:
            entry["id"] = identifier
        if not entry.get("id"):
            return None, "the new source needs an id, or a url to derive one from"
        missing = [key for key in spec.required if not entry.get(key)]
        if missing:
            return None, f"{kind} needs {', '.join(missing)}"
        return entry, ""

    def new_source_used(form: dict[str, list[str]]) -> bool:
        """Whether anything was typed into the "new source" block at all."""
        return any(first(form, name).strip() for name in ("new:id", *(f"new:{key}" for key in SOURCE_FORM_KEYS)))

    def added_source_fields(entry: dict, spec) -> str:
        """The editable keys of one added source, as inline inputs.

        The stored value is shown, not the origin: an operator fixing a feed path needs the whole URL, and the
        stored value is a ``${NAME}`` reference whenever the URL carries a credential.
        """
        if spec is None:
            return "<span class='muted small'>unknown type</span>"
        cells = []
        for key in source_keys(spec):
            reference = " placeholder='${NAME}'" if key in spec.secret_keys else ""
            value = str(entry.get(key, "") or "")
            cells.append(
                f"<label class='inline'>{esc(key)}"
                f"<input type='text' name='added_{esc(key)}:{esc(entry['id'])}' value='{esc(value)}'"
                f"{reference}></label>"
            )
        return "".join(cells)

    def source_row(entry: dict, *, added: bool) -> str:
        """One configured source: id, kind, origin, enable flag, watch tag, its keys and a probe button.

        The row's fields belong to the save form; its ``Test`` button submits the same body to the probe endpoint
        through ``formaction``, so one form serves both and no nested form is needed.
        """
        identifier = entry["id"]
        spec = source_spec(entry)
        checked = " checked" if entry.get("enabled", True) is not False else ""
        # The origin only: a source URL can carry a token in its userinfo, query or path.
        public = _public_url(str(entry.get("url", "")))
        origin = f"<br><span class='muted small'>{esc(public)}</span>" if public else ""
        badge = f"{_badge('added', 'neutral')} " if added else ""
        editable = (
            f"<td>{added_source_fields(entry, spec)}</td>"
            if added
            else "<td><span class='muted small'>keys in the YAML</span></td>"
        )
        remove = (
            f"<td><input type='checkbox' name='remove:{esc(identifier)}' value='1' "
            f"aria-label='Remove {esc(identifier)}'></td>"
            if added
            else "<td></td>"
        )
        return (
            f"<tr><td>{badge}<b>{esc(identifier)}</b> <span class='muted'>{esc(str(entry.get('type', '')))}</span>"
            f"{origin}</td>"
            f"<td><input type='checkbox' name='enabled:{esc(identifier)}' value='1'{checked} "
            f"aria-label='Enabled {esc(identifier)}'></td>"
            f"<td><input type='text' name='tag:{esc(identifier)}' value='{esc(str(entry.get('tag') or ''))}' "
            f"aria-label='Watch tag for {esc(identifier)}'></td>"
            f"{editable}{remove}"
            f"<td><button class='btn' type='submit' formaction='/config/sources/probe' "
            f"name='id' value='{esc(identifier)}'>Test</button></td></tr>"
        )

    def source_form_entries(entries, added_ids: set[str]) -> str:
        """One row per configured source, marking the ones the overlay adds as editable there."""
        return "".join(
            source_row(entry, added=entry["id"] in added_ids)
            for entry in entries
            if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        )

    def new_source_fields() -> str:
        """The "new source" inputs: one per editable key, labelled with the kinds that read it."""
        readers: dict[str, list[str]] = {}
        secret: set[str] = set()
        for spec in SOURCE_SPECS.values():
            for key in source_keys(spec):
                readers.setdefault(key, []).append(spec.kind)
                if key in spec.secret_keys:
                    secret.add(key)
        return "".join(
            f"<label>{esc(key)} <span class='muted small'>({esc(', '.join(sorted(readers[key])))})</span>"
            f"<input type='text' name='new:{esc(key)}'{' placeholder=${{NAME}}' if key in secret else ''}></label>"
            for key in sorted(readers)
        )

    def submitted_fields(form: dict[str, list[str]], prefix: str) -> str:
        """Re-emit one block of a submitted form as hidden inputs, so a second form can carry it on unchanged."""
        return "".join(
            f"<input type='hidden' name='{esc(name)}' value='{esc(value)}'>"
            for name in sorted(form)
            if name.startswith(prefix)
            for value in form[name][:1]
        )

    def redacted_origin(link: object, secrets: Sequence[str]) -> str:
        """A link's origin with every secret removed, or a marker when removing one left nothing showable.

        The redaction runs on the whole value *before* the origin is extracted: extracting lowercases a
        hostname and would transform a reflected credential into a string the redactor no longer matches. A
        redacted host is left bracketed (``[redacted].example.net``), which is not a URL any more, so the
        fallback is the marker alone rather than a fabricated origin.
        """
        text = str(link or "")
        redacted = pipeline.redact(text, secrets)
        if redacted == text:
            return _public_url(text)
        return _public_url(redacted) or "[redacted]"

    def probe_window(window, secrets: Sequence[str]) -> str:
        """What one probe answered: the entry count, the truncation flag and the first few items.

        A title is a value the *source* chose: a feed can echo a request token back in one, so every rendered
        field is redacted before it is truncated and escaped, exactly as an error message is.
        """
        items = list(window.items)
        rows = "".join(
            f"<tr><td>{esc(_short(pipeline.redact(item.title, secrets), 80))}</td>"
            f"<td class='mono nowrap'>{esc(_when(item.published))}</td>"
            f"<td>{esc(redacted_origin(item.link, secrets))}</td></tr>"
            for item in items[:5]
        )
        table = (
            "<div class='scroll'><table><tr><th scope='col'>Title</th><th scope='col'>Published</th>"
            f"<th scope='col'>Link</th></tr>{rows}</table></div>"
            if items
            else "<p class='muted'>The source answered, but its window holds no entries.</p>"
        )
        truncated = (
            "<p class='muted small'>This export is truncated: it reports fewer entries than the source holds.</p>"
            if window.truncated
            else ""
        )
        return _notice(f"Answered with {len(items)} entr{'y' if len(items) == 1 else 'ies'}.", "ok") + truncated + table

    def added_source_error(entry: dict) -> str:
        """Why a source added on this page may not be used, or "" when it may.

        The check runs on the *expanded* entry: ``${INTERNAL_HOST}`` is not a hostname, and the address it
        resolves to is the one the fetcher would contact. The stored entry keeps its references. A kind with no
        remote side (``webhook``) has no destination to judge.
        """
        try:
            expanded = expand_entry(entry, runtime.environment)
        except ConfigError as exc:
            return str(exc)  # a missing variable is named by name, never by value
        url = expanded.get("url")
        if not isinstance(url, str) or not url:
            return ""
        if _url_scheme(url) not in ("http", "https"):
            return "that source url is not an http or https url"
        if runtime.cfg.allow_private_sources or not private_destination(url, resolve):
            return ""
        return PRIVATE_SOURCE_REFUSAL

    def probe_source(entry: dict, *, adding: bool) -> tuple[bool, str]:
        """Fetch one source entry the way a pass would, and render what it answered. Nothing is written.

        A probe can hold a source that was never saved, so the values it resolves are redacted together with the
        configuration's own secrets -- in an error *and* in what the source answered.

        ``adding`` marks the case this page has in common with the save form: a source that is not in the YAML
        yet. Only that case is subject to the private-destination rule, because only that case is reachable
        with the UI token alone.
        """
        kind = entry.get("type")
        spec = SOURCE_SPECS.get(kind) if isinstance(kind, str) else None
        if spec is None:
            return False, _notice(f"{esc(str(kind))} is not a built-in source type.", "critical")
        if kind == "webhook":
            identifier = esc(str(entry.get("id", "")))
            return False, _notice(
                "A webhook source has no remote side to read: push an item to "
                f"<code>/webhooks/{identifier}</code> with the bearer secret.",
                "warning",
            )
        resolved: list[str] = []
        try:
            # Expanded before the URL is judged: ``url: ${FEED_URL}`` is a configured value, not a bad scheme,
            # and a missing variable must be named as one.
            expanded = expand_entry(entry, runtime.environment, resolved)
        except Exception as exc:
            message = pipeline.redact(f"{type(exc).__name__}: {exc}", [*secret_values(runtime.cfg), *resolved])
            return False, _notice(esc(message), "critical")
        secrets = [*secret_values(runtime.cfg), *resolved]
        url = expanded.get("url")
        if not isinstance(url, str) or not url:
            return False, _notice("This source has no url to fetch.", "critical")
        scheme = _url_scheme(url)
        if not scheme:
            return False, _notice("That url cannot be read as a URL.", "critical")
        if scheme not in ("http", "https"):
            return False, _notice("Only http and https URLs can be fetched.", "critical")
        if adding and not runtime.cfg.allow_private_sources and private_destination(url, resolve):
            return False, _notice(esc(PRIVATE_SOURCE_REFUSAL), "critical")
        try:
            window = build_source(expanded, runtime.environment).fetch(http, {})
        except Exception as exc:  # a probe reports every failure the pass would meet, and never a traceback
            message = pipeline.redact(f"{type(exc).__name__}: {exc}", secrets)
            return False, _notice(esc(message), "critical")
        return True, probe_window(window, secrets)

    def probe_result(request: Request, form: dict[str, list[str]], *, active: str) -> HTMLResponse:
        """The probe result page: one configured source by id, or the fields of a source that is not saved yet."""
        back = active if active in ("/config", "/sources") else "/config"
        identifier = first(form, "id").strip()
        add_form = ""
        if identifier:
            settings = saved_overlay()[0]
            owned = added_source_ids(settings)
            entry = next(
                (candidate for candidate in saved_source_entries(settings) if candidate["id"] == identifier),
                None,
            )
            if entry is None:
                return page(
                    "Source probe",
                    _notice(f"No configured source has id {esc(identifier)}.", "critical")
                    + f"<p><a href='{back}'>Back</a></p>",
                    active=active,
                    actions=sign_out_form(request),
                    status_code=404,
                )
            # Ownership, not "already saved": a disabled overlay source is still a source this page added, and
            # probing it must not become the way around the destination rule.
            ok, detail = probe_source(entry, adding=identifier in owned)
            tone = _badge("answered", "ok") if ok else _badge("failed", "critical")
            heading = (
                f"<h2>{esc(identifier)} <span class='muted'>{esc(str(entry.get('type', '')))}</span> {tone}</h2>"
                "<p class='muted small'>A configured source; the probe reads it and delivers nothing.</p>"
            )
            title = f"{identifier} probe"
        else:
            entry, problem = new_source_from_form(form)
            if entry is None:
                return page(
                    "Source probe",
                    _notice(esc(problem[:1].upper() + problem[1:]), "warning") + f"<p><a href='{back}'>Back</a></p>",
                    active=active,
                    actions=sign_out_form(request),
                    status_code=400,
                )
            ok, detail = probe_source(entry, adding=True)
            tone = _badge("answered", "ok") if ok else _badge("failed", "critical")
            heading = (
                f"<h2>New {esc(str(entry.get('type', '')))} source {tone}</h2>"
                "<p class='muted small'>Not saved yet: the probe fetched it with the values from the form.</p>"
            )
            # The probed values are carried into a real save, so a working probe is one click from being stored.
            add_form = (
                "<h2>Add this source</h2>"
                "<p class='muted small'>Saving stores these values in the settings overlay; the source is polled "
                "from the next pass.</p>"
                f"<form method='post' action='/config/sources'>{csrf_field(request)}"
                f"<input type='hidden' name='fingerprint' value='{esc(first(form, 'fingerprint'))}'>"
                f"{submitted_fields(form, 'new:')}"
                "<button class='btn btn-primary'>Add this source</button></form>"
            )
            title = "Source probe"
        body = heading + detail + add_form + f"<p><a href='{back}'>&larr; Back</a></p>"
        return page(title, body, active=active, actions=sign_out_form(request))

    def notifier_choices(entries) -> list[tuple[str, bool]]:
        """Every configured notifier id with its enabled flag; a route may only select an enabled one."""
        choices = []
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("id"), str):
                choices.append((entry["id"], entry.get("enabled", True) is not False))
        return choices

    def route_form_entries(routes: list, defaults: list, choices: list[tuple[str, bool]]) -> str:
        """Fixed route rows (at least three) and the default selection, prefilled from the merged config.

        More than three configured rules are rendered too: the form replaces the whole block, so a row it
        did not render would be lost on save.
        """
        rows = []
        for index in range(1, max(ROUTE_FORM_ROWS, len(routes)) + 1):
            route = routes[index - 1] if index <= len(routes) and isinstance(routes[index - 1], dict) else {}
            match = route.get("match")
            match = match if isinstance(match, dict) else {}
            selected = route.get("notifiers")
            selected = {value for value in selected if isinstance(value, str)} if isinstance(selected, list) else set()
            tag = match.get("tag") if isinstance(match.get("tag"), str) else ""
            # The document is unexpanded here: a ${...} reference is a valid configured value, and dropping it
            # from the select would silently broaden the rule the moment the form is saved.
            tag_values = ("", *TAGS, *((tag,) if tag and tag not in TAGS else ()))
            tag_options = "".join(
                f"<option value='{esc(value)}'{' selected' if value == tag else ''}>{esc(value or 'any tag')}</option>"
                for value in tag_values
            )
            known = {identifier for identifier, _ in choices}
            # A selection may be a ${...} reference (expanded when the configuration loads): offer it as its
            # own selected option, or the browser would submit only the literal ids and silently drop it.
            extra = sorted(value for value in selected if value not in known)
            options = "".join(
                f"<option value='{esc(identifier)}'{' selected' if identifier in selected else ''}>"
                f"{esc(identifier)}{'' if enabled else ' (disabled)'}</option>"
                for identifier, enabled in choices
            ) + "".join(f"<option value='{esc(value)}' selected>{esc(value)} (reference)</option>" for value in extra)
            rows.append(
                f"<tr><td><input type='text' name='route:{index}:source' "
                f"value='{esc(match.get('source', ''))}' placeholder='source id' "
                f"aria-label='Rule {index} source id'></td>"
                f"<td><select name='route:{index}:tag' aria-label='Rule {index} tag'>{tag_options}</select></td>"
                f"<td><input type='text' name='route:{index}:product' "
                f"value='{esc(match.get('product', ''))}' placeholder='product id' "
                f"aria-label='Rule {index} product id'></td>"
                f"<td><input type='text' name='route:{index}:ids' "
                f"value='{esc(match.get('ids', ''))}' placeholder='CVE-2026-*' "
                f"aria-label='Rule {index} ids pattern'></td>"
                f"<td><select name='route:{index}:notifiers' multiple size='2' "
                f"aria-label='Rule {index} notifiers'>{options}</select></td></tr>"
            )
        default_ids = {value for value in defaults if isinstance(value, str)}
        known = {identifier for identifier, _ in choices}
        extra_defaults = sorted(value for value in default_ids if value not in known)
        default_options = "".join(
            f"<option value='{esc(identifier)}'{' selected' if identifier in default_ids else ''}>"
            f"{esc(identifier)}{'' if enabled else ' (disabled)'}</option>"
            for identifier, enabled in choices
        ) + "".join(
            f"<option value='{esc(value)}' selected>{esc(value)} (reference)</option>" for value in extra_defaults
        )
        return (
            "<div class='scroll'><table><tr><th scope='col'>Source id</th><th scope='col'>Tag</th>"
            "<th scope='col'>Product id</th><th scope='col'>IDs pattern</th>"
            f"<th scope='col'>Notifiers</th></tr>{''.join(rows)}</table></div>"
            "<p><label>Default notifiers (when no rule matches)"
            f"<select name='default' multiple size='3'>{default_options}</select></label></p>"
            "<p class='muted'>Rules are checked in order and the first match wins. An entirely empty row is "
            "ignored; a partly filled one is saved as written and the validator reports what is wrong. Only "
            "enabled notifiers may be selected.</p>"
        )

    def commit_overlay(request: Request, overlay: dict):
        """Validate, build, save and apply one overlay; nothing is written when any step refuses.

        Building the plugins here is what makes a saved overlay safe: it is the same build the next
        start and the reload perform, so a value that would fail then is refused now, while the live
        configuration and the file on disk are still untouched.
        """
        if runtime.config_path is None or runtime.overlay_path is None:
            return page(
                "Not saved",
                "<p>This instance has no configuration file to update.</p>",
                active="/config",
                actions=sign_out_form(request),
                status_code=400,
            )
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
                active="/config",
                actions=sign_out_form(request),
                status_code=400,
            )
        try:
            stored = save_settings(runtime.overlay_path, overlay, now=int(clock()))
        except ConfigError as exc:
            return page(
                "Not saved",
                f"<p>{esc(pipeline.redact(str(exc), values))}</p>",
                active="/config",
                actions=sign_out_form(request),
                status_code=400,
            )
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
        with SETTINGS_LOCK:
            overlay, revision = saved_overlay()
            base, _ = form_document(overlay)
            stale = stale_form(request, form, base)
            if stale is not None:
                return stale
            poll = first(form, "poll_interval").strip()
            if poll:
                overlay["poll_interval"] = poll
            else:
                overlay.pop("poll_interval", None)  # an empty field means "use the YAML value"
            overlay["hidden_source_hosts"] = [
                line.strip() for line in first(form, "hidden_source_hosts").splitlines() if line.strip()
            ]
            return commit_overlay(request, overlay)

    @app.post("/config/sources", dependencies=[Depends(require_csrf)])
    def save_sources_form(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        form = form_body(request)
        with SETTINGS_LOCK:
            overlay, revision = saved_overlay()
            base, _ = form_document(overlay)
            stale = stale_form(request, form, base)
            if stale is not None:
                return stale
            # A row is only reconciled by a submission that rendered rows: every row submits at least its tag
            # field, even when the box is unchecked and the text is cleared. The probe result page's "Add this
            # source" form carries only the new block, and reconciling from it would read every row's absence as
            # a deliberate disable and clear.
            whole = any(name.startswith(("enabled:", "tag:", "remove:", "added_")) for name in form)
            owned = added_source_ids(overlay)
            if whole:
                changes = {}
                for entry in base.get("sources") or []:
                    if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                        continue
                    identifier = entry["id"]
                    if identifier in owned:
                        continue  # an added source is stored whole, below; two owners for one row would drift
                    changes[identifier] = {
                        "enabled": f"enabled:{identifier}" in form,
                        "tag": first(form, f"tag:{identifier}").strip(),
                    }
                overlay["sources"] = changes
            added: list[dict] = []
            error = ""
            stored = [entry for entry in (overlay.get("sources_added") or []) if isinstance(entry, dict)]
            if not whole:
                added = [dict(entry) for entry in stored]
            else:
                for entry in stored:
                    if not isinstance(entry.get("id"), str):
                        continue
                    identifier = entry["id"]
                    if f"remove:{identifier}" in form:
                        continue
                    updated = dict(entry)
                    updated["enabled"] = f"enabled:{identifier}" in form
                    tag = first(form, f"tag:{identifier}").strip()
                    if tag:
                        updated["tag"] = tag
                    else:
                        updated.pop("tag", None)
                    spec = source_spec(updated)
                    if spec is not None:
                        for key in source_keys(spec):
                            name = f"added_{key}:{identifier}"
                            if name not in form:
                                continue  # the row did not carry this field: keep what is stored
                            value = first(form, name).strip()
                            if value:
                                updated[key] = value
                            else:
                                updated.pop(key, None)
                    # Only what will actually run is judged: a disabled source is not built and not fetched, so
                    # neither a missing key nor a destination that has since become internal may stop it being
                    # disabled -- that would leave the operator unable to switch off a source they cannot edit.
                    if spec is not None and updated["enabled"]:
                        missing = [key for key in spec.required if not updated.get(key)]
                        if missing:
                            # Refused here, in words: letting the builder raise would report a bare KeyError.
                            error = f"{identifier}: {spec.kind} needs {', '.join(missing)}"
                            break
                        problem = added_source_error(updated)
                        if problem:
                            error = f"{identifier}: {problem}"
                            break
                    added.append(updated)
            if not whole and not new_source_used(form):
                error = "this form carried no source to save"
            if not error and new_source_used(form):
                candidate, problem = new_source_from_form(form)
                error = problem
                if candidate is not None:
                    if candidate["id"] in {entry.get("id") for entry in (base.get("sources") or [])}:
                        error = f"source id {candidate['id']!r} is already configured; pick another id"
                    else:
                        error = added_source_error(candidate)
                    if not error:
                        added.append(candidate)
            if error:
                return page(
                    "Not saved",
                    _notice(esc(error), "critical") + "<p><a href='/config'>Back to configuration</a></p>",
                    active="/config",
                    actions=sign_out_form(request),
                    status_code=400,
                )
            if added:
                overlay["sources_added"] = added
            else:
                overlay.pop("sources_added", None)
            return commit_overlay(request, overlay)

    @app.post("/config/sources/probe", dependencies=[Depends(require_csrf)])
    def probe_config_source(request: Request):
        """Probe one source from the configuration form: a configured row, or the fields of a new one."""
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        return probe_result(request, form_body(request), active="/config")

    @app.post("/sources/probe", dependencies=[Depends(require_csrf)])
    def probe_configured_source(request: Request):
        """Probe one configured source from the sources page; it reads the source and writes nothing."""
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        return probe_result(request, form_body(request), active="/sources")

    @app.post("/config/notifiers", dependencies=[Depends(require_csrf)])
    def save_notifiers_form(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        form = form_body(request)
        with SETTINGS_LOCK:
            overlay, revision = saved_overlay()
            base, _ = form_document(overlay)
            stale = stale_form(request, form, base)
            if stale is not None:
                return stale
            return _save_notifiers(request, overlay, base, form)

    def _save_notifiers(request: Request, overlay: dict, base: dict, form: dict):
        entries = []
        for entry in base.get("notifiers") or []:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                continue
            identifier = entry["id"]
            updated = dict(entry)
            # headers stay in the YAML (the overlay may not store a mapping that can carry a credential) and
            # are carried over by id when the overlay is merged.
            updated.pop("headers", None)
            updated["enabled"] = f"enabled:{identifier}" in form
            for key in NOTIFIER_FORM_KEYS:
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
                    active="/config",
                    actions=sign_out_form(request),
                    status_code=400,
                )
            new = {"id": identifier, "type": kind}
            if secret_key is not None:
                if not reference:
                    return page(
                        "Not saved",
                        f"<p>A {esc(kind)} needs a reference here: enter ${{NAME}} or ${{NAME_FILE}}. "
                        "The secret itself stays in the environment.</p>",
                        active="/config",
                        actions=sign_out_form(request),
                        status_code=400,
                    )
                new[secret_key] = reference
            for key in NOTIFIER_FORM_KEYS:
                value = first(form, f"new:{key}").strip()
                if value:
                    new[key] = value
            entries.append(new)
        overlay["notifiers"] = entries
        return commit_overlay(request, overlay)

    @app.post("/config/routes", dependencies=[Depends(require_csrf)])
    def save_routes_form(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        form = form_body(request)
        with SETTINGS_LOCK:
            overlay, revision = saved_overlay()
            base, _ = form_document(overlay)
            stale = stale_form(request, form, base)
            if stale is not None:
                return stale
            return _save_routes(request, overlay, base, form)

    def _save_routes(request: Request, overlay: dict, base: dict, form: dict):
        """Replace the overlay's ``routes``/``default`` with the form's rows, or remove them when empty.

        An empty form means "use the YAML": the overlay keeps no routes block, so the rules written by hand
        stay in force. Everything else is written as given and judged by the one configuration validator --
        the only place where an overlay-added notifier's membership is known.
        """
        configured = base.get("routes")
        rows = max(ROUTE_FORM_ROWS, len(configured)) if isinstance(configured, list) else ROUTE_FORM_ROWS
        routes = []
        for index in range(1, rows + 1):
            prefix = f"route:{index}"
            match = {}
            for key in ("source", "tag", "product", "ids"):
                value = first(form, f"{prefix}:{key}").strip()
                if value:
                    match[key] = value
            selected = [value for value in form.get(f"{prefix}:notifiers", []) if value]
            if not match and not selected:
                continue  # an entirely empty row is not a rule
            routes.append({"match": match, "notifiers": selected})
        default = [value for value in form.get("default", []) if value]
        if default and not routes:
            return page(
                "Not saved",
                "<p>A default selection needs at least one rule: with no rules every enabled notifier "
                "receives every message.</p><p>Add a rule, or leave the default empty to keep the YAML "
                "routing.</p>",
                active="/config",
                actions=sign_out_form(request),
                status_code=400,
            )
        if routes:
            overlay["routes"] = routes
            # Always stored with the rules: an empty default is a decision ("no fallback, so an unmatched
            # message goes to every enabled notifier"), and removing the key would restore the YAML default
            # the operator just cleared. An entirely empty form still removes both keys and keeps the YAML.
            overlay["default"] = default
        else:
            overlay.pop("routes", None)
            overlay.pop("default", None)
        return commit_overlay(request, overlay)

    @app.post("/reload", dependencies=[Depends(require_csrf)])
    def reload_configuration(request: Request):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        if runtime.config_path is None:
            return page(
                "Not reloaded",
                "<p>This instance has no configuration file to reload.</p>",
                active="/config",
                actions=sign_out_form(request),
                status_code=400,
            )
        try:
            runtime.reload(blocking=False)
        except LockBusy:
            return page(
                "Reload refused",
                "<p>A pass or another reload is running, so the configuration was not reloaded; try again shortly.</p>"
                '<p><a href="/config">Back to configuration</a></p>',
                active="/config",
                actions=sign_out_form(request),
                status_code=409,
            )
        except (ConfigError, SourceError) as exc:
            message = esc(pipeline.redact(str(exc), secret_values(runtime.cfg)))
            return page(
                "Reload refused",
                f"<p>{message}</p><p>The running configuration is unchanged.</p>",
                active="/config",
                actions=sign_out_form(request),
                status_code=400,
            )
        return RedirectResponse("/config", status_code=303)

    @app.get("/config", response_class=HTMLResponse)
    def config_page(request: Request, saved: int | None = None):
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        cfg = runtime.cfg
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
        # The state marker can be older than the file (a save while a pass held the lock, then a restart), and a
        # revision number can be reused after the overlay is deleted and recreated: the timestamp is only
        # reported for the settings fingerprint the marker recorded.
        applied_now = applied.get("fingerprint") == settings_fingerprint(saved_document["settings"])
        applied_at = _when(applied.get("applied_at")) if applied_now else ""
        if saved_revision == 0 and not saved_document["settings"]:
            if live_revision:
                status = (
                    f"no overlay file; the live configuration still has revision <b>{live_revision}</b> — "
                    "press Reload to return to the YAML"
                )
            else:
                status = "no overlay saved; the YAML is the whole configuration"
        else:
            status = f"saved revision <b>{saved_revision}</b> · " + (
                "<b>live</b>" if live_now else f"NOT live (live revision <b>{live_revision}</b>)"
            )
            if applied_at:
                status += f" · last applied {esc(applied_at)}"
        # The forms edit the saved overlay, not the live snapshot: a revision saved while a pass held the lock
        # must stay visible and editable, and saving another section must not drop it.
        with SETTINGS_LOCK:
            document, form_error = form_document(dict(saved_document["settings"]))
        if form_error and not overlay_error:
            overlay_error = form_error
        sources = document.get("sources")
        sources = sources if isinstance(sources, list) else []
        notifiers = document.get("notifiers")
        notifiers = notifiers if isinstance(notifiers, list) else []
        routes = document.get("routes")
        routes = routes if isinstance(routes, list) else []
        defaults = document.get("default")
        defaults = defaults if isinstance(defaults, list) else []
        added_ids = added_source_ids(dict(saved_document["settings"]))
        source_type_options = "".join(
            f"<option value='{esc(kind)}'>{esc(kind)}</option>" for kind in sorted(SOURCE_SPECS)
        )
        configured_source_ids = {
            entry["id"] for entry in sources if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        }
        route_warnings = []
        for index, route in enumerate(routes, start=1):
            match = route.get("match") if isinstance(route, dict) else None
            identifier = match.get("source") if isinstance(match, dict) else None
            if isinstance(identifier, str) and identifier and identifier not in configured_source_ids:
                # A rule for a source nobody configured can never fire. Staging a rule before its source is
                # legitimate, so this is reported rather than refused -- unlike an unknown tag, which no
                # configuration could ever match.
                route_warnings.append(
                    f"<li>Rule {index} matches source <code>{esc(identifier)}</code>, which no configured source "
                    "has: it stays inert until that source exists.</li>"
                )
        route_notice = _notice(f"<ul>{''.join(route_warnings)}</ul>", "warning") if route_warnings else ""
        banner = ""
        if saved is not None:
            if live_now and saved == live_revision:
                banner += _notice(f"Revision {saved} saved and live.", "ok")
            else:
                banner += _notice(
                    f"Revision {saved} saved but not live yet (live revision {live_revision}); "
                    "press Reload once the running pass finishes.",
                    "warning",
                )
        if overlay_error:
            banner += _notice(f"The overlay cannot be read: {overlay_error}", "critical")
        status_tone = "ok" if live_now and saved_revision else ("warning" if saved_revision else "neutral")
        poll_text = document.get("poll_interval")
        poll_text = poll_text if isinstance(poll_text, str) else f"{cfg.poll_interval_seconds}s"
        hidden = document.get("hidden_source_hosts")
        hidden_text = "\n".join(str(host) for host in hidden) if isinstance(hidden, list) else ""
        type_options = "".join(
            f"<option value='{esc(kind)}'>{esc(kind)}</option>" for kind in sorted(NOTIFIER_BUILDERS)
        )
        new_fields = " ".join(f"<label>{key}<input type='text' name='new:{key}'></label>" for key in NOTIFIER_FORM_KEYS)
        csrf = csrf_field(request)
        fingerprint = form_fingerprint(document)
        fingerprint_field = f"<input type='hidden' name='fingerprint' value='{fingerprint}'>"
        body = (
            f"<div class='strip'><p class='muted small'>Live poll interval <b>{cfg.poll_interval_seconds}s</b> · "
            f"state <code>{esc(cfg.state_path)}</code> · "
            f"watchlist <code>{esc(cfg.watchlist_path or 'built-in default')}</code></p>"
            f'<form method="post" action="/reload">{csrf}<button class="btn">Reload configuration</button></form>'
            "</div>"
            f"<p class='notice notice-{status_tone}'>Settings overlay: {status}</p>{banner}"
            "<h2><span class='sec-num'>01</span>Settings</h2>"
            f'<form method="post" action="/config/settings">{csrf}{fingerprint_field}'
            "<div class='fields'>"
            "<label class='poll'>Poll interval"
            f"<input type='text' name='poll_interval' value='{esc(poll_text)}'></label>"
            "<label>Hidden source hosts (one per line)"
            f"<textarea name='hidden_source_hosts' rows='3'>{esc(hidden_text)}</textarea></label>"
            "</div>"
            "<p class='muted small'>Poll interval: 15m, 30s or 12h.</p>"
            "<button class='btn btn-primary'>Save settings</button></form>"
            "<h2><span class='sec-num'>02</span>Sources</h2>"
            "<p class='muted small'>A source defined in the YAML keeps its keys there: this page edits its enable "
            "flag and its watch tag, and can test it. A source added here is stored whole in the settings overlay, "
            "so it needs no edit to a read-only config mount. The watch tag scopes a changedetection.io poll and "
            "is ignored by the other kinds.</p>"
            f'<form method="post" action="/config/sources">{csrf}{fingerprint_field}'
            "<div class='scroll'><table><tr><th scope='col'>Source</th>"
            "<th scope='col' class='narrow'>Enabled</th>"
            "<th scope='col' class='tag-col'>Watch tag</th>"
            "<th scope='col'>Keys</th>"
            "<th scope='col' class='narrow'>Remove</th>"
            "<th scope='col' class='narrow'>Test</th>"
            f"</tr>{source_form_entries(sources, added_ids)}</table></div>"
            "<h3>New source</h3>"
            "<div class='fields'><label>id <span class='muted small'>(optional)</span>"
            "<input type='text' name='new:id'></label>"
            f"<label>type<select name='new:type'>{source_type_options}</select></label></div>"
            f"<div class='fields'>{new_source_fields()}</div>"
            "<p class='muted small'>An id is derived from the URL host when it is empty. A field another kind "
            "reads is ignored. A secret key takes a ${NAME} or ${NAME_FILE} reference and is stored instead of "
            "the value.</p>"
            "<button class='btn btn-primary'>Save sources</button> "
            "<button class='btn' type='submit' formaction='/config/sources/probe'>Test the new source</button>"
            "</form>"
            "<h2><span class='sec-num'>03</span>Notifiers</h2>"
            f'<form method="post" action="/config/notifiers">{csrf}{fingerprint_field}'
            f"{notifier_form_entries(notifiers)}"
            "<h3>New notifier</h3>"
            "<p class='muted small'>Secrets stay in the environment: the reference field takes ${NAME} or "
            "${NAME_FILE} and is stored instead of the value. A type that needs two references, or a header, "
            "is added by editing the YAML.</p>"
            "<div class='fields'>"
            "<label>id<input type='text' name='new:id'></label>"
            f"<label>type<select name='new:type'>{type_options}</select></label>"
            "<label>reference <input type='text' name='new:reference' placeholder='${NAME}'></label>"
            f"{new_fields}</div>"
            "<button class='btn btn-primary'>Save notifiers</button></form>"
            "<h2><span class='sec-num'>04</span>Routes</h2>"
            f'<form method="post" action="/config/routes">{csrf}{fingerprint_field}'
            f"{route_form_entries(routes, defaults, notifier_choices(notifiers))}"
            "<button class='btn btn-primary'>Save routes</button></form>"
            f"{route_notice}"
            "<p class='muted small'>The YAML file stays the source of every other setting; environment changes "
            "still need a restart.</p>"
        )
        return page("Configuration", body, active="/config", actions=sign_out_form(request))

    @app.get("/sources", response_class=HTMLResponse)
    def sources_page(request: Request):
        """What this instance monitors and whether each source answers, plus the built-in catalogue.

        The state column is the state's own record of the last fetch. Run history says a pass finished, not that a
        feed answered, so one broken source needs its own line here -- and its own metric for a scraper.
        """
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        csrf = csrf_field(request)
        try:
            stored_health = load_state().get("source_health")
        except SourceError:
            stored_health = None
        health = stored_health if isinstance(stored_health, dict) else {}
        added_ids = added_source_ids(saved_overlay()[0])
        rows = []
        for source in runtime.cfg.sources:
            identifier = str(source.get("id", ""))
            record = health.get(identifier)
            record = record if isinstance(record, dict) else {}
            kind = str(source.get("type", ""))
            origin = redacted_origin(source.get("url", ""), secret_values(runtime.cfg))
            badge = f" {_badge('added', 'neutral')}" if identifier in added_ids else ""
            tone = (
                "<span class='muted small'>not polled yet</span>"
                if not record
                else (_badge("ok", "ok") if record.get("ok") else _badge("failing", "critical"))
            )
            error = str(record.get("error") or "")
            # 0 is the state's "never", not midnight 1970: a source that has not succeeded must say so.
            attempt = _when(record.get("at")) if record.get("at") else "never"
            success = _when(record.get("ok_at")) if record.get("ok_at") else "never"
            rows.append(
                f"<tr><td><b>{esc(identifier)}</b>{badge}<br>"
                f"<span class='muted small'>{esc(kind)}{' · ' + esc(origin) if origin else ''}</span></td>"
                f"<td>{tone}</td>"
                f"<td class='mono nowrap'>{esc(attempt)}</td>"
                f"<td class='mono nowrap'>{esc(success)}</td>"
                f"<td class='num'>{esc(str(_number(record.get('items'))))}</td>"
                f"<td>{esc(_short(error, 90)) if error else ''}</td>"
                f"<td><form method='post' action='/sources/probe'>{csrf}"
                f"<input type='hidden' name='id' value='{esc(identifier)}'>"
                f"<button class='btn'>Test</button></form></td></tr>"
            )
        configured = (
            "<div class='scroll'><table><tr><th scope='col'>Source</th><th scope='col'>State</th>"
            "<th scope='col'>Last attempt</th><th scope='col'>Last success</th>"
            "<th scope='col' class='narrow'>Items</th><th scope='col'>Last error</th>"
            f"<th scope='col' class='narrow'>Test</th></tr>{''.join(rows)}</table></div>"
            if rows
            else _empty("No source is enabled.", "Add one on the configuration page.")
        )
        catalogue_rows = []
        for spec in SOURCE_SPECS.values():
            example = yaml.safe_dump(spec.example, sort_keys=False)
            catalogue_rows.append(
                f"<tr><td><b>{esc(spec.kind)}</b></td><td>{esc(spec.summary)}</td>"
                f"<td>{esc(', '.join(spec.required) or '(none)')}</td>"
                f"<td>{esc(', '.join(spec.optional) or '(none)')}</td>"
                f"<td><pre>{esc(example)}</pre></td><td><code>{esc(spec.docs_anchor)}</code></td></tr>"
            )
        body = (
            "<div class='strip'><p class='muted small'>Every enabled source, when it last answered, and the error "
            "it reported when it did not. A probe reads the source now and delivers nothing.</p>"
            "<a class='btn' href='/config'>Add or edit a source</a></div>"
            f"<h2>Configured sources</h2>{configured}"
            "<h2>Built-in types</h2>"
            "<p class='muted'>Every built-in source type, its keys and an example. Required keys have no default.</p>"
            "<div class='scroll'><table><tr><th scope='col'>Kind</th><th scope='col'>Summary</th>"
            "<th scope='col'>Required</th><th scope='col'>Optional</th><th scope='col'>Example</th>"
            f"<th scope='col'>Docs</th></tr>{''.join(catalogue_rows)}</table></div>"
            "<p class='muted small'>The same probe from a shell: "
            "<code>advisory-radar sources test &lt;id&gt;</code>.</p>"
        )
        return page("Sources", body, active="/sources", actions=sign_out_form(request))

    @app.get("/runs", response_class=HTMLResponse)
    def runs_page(request: Request):
        """The pass history, filtered by exit code and day range. No pager: the writer keeps only 200 runs."""
        if not require_auth(request):
            return RedirectResponse("/login", status_code=303)
        runs = load_state().get("runs")
        runs = runs if isinstance(runs, list) else []
        filters = {key: (request.query_params.get(key) or "").strip() for key in ("code", "since", "until")}
        since = _day_start(filters["since"], "since") if filters["since"] else None
        until = _day_start(filters["until"], "until") + 86400 if filters["until"] else None
        code = None
        if filters["code"]:
            try:
                code = int(filters["code"])
            except ValueError:
                raise HTTPException(status_code=400, detail="code must be an integer exit code") from None
        shown = []
        for run in reversed(runs):
            if not isinstance(run, dict):
                continue
            if code is not None and _number(run.get("code"), -1) != code:
                continue
            at = _number(run.get("at"), 0)
            if since is not None and at < since:
                continue
            if until is not None and at >= until:
                continue
            shown.append(run)

        def run_row(run: dict) -> str:
            code_text, code_tone = _exit_code(run.get("code"))
            return (
                f"<tr><td class='nowrap'>{esc(_when(run.get('at')))}</td>"
                f"<td class='num'>{esc(run.get('sent', 0))}</td>"
                f"<td class='num'>{esc(run.get('parked', 0))}</td>"
                f"<td class='num'>{esc(run.get('pending', 0))}</td>"
                f"<td>{_badge(code_text, code_tone)}</td></tr>"
            )

        rows = "".join(run_row(run) for run in shown)
        filter_form = (
            "<form class='toolbar' method='get' action='/runs'>"
            f"<label>Exit code<input type='text' name='code' size='3' value='{esc(filters['code'])}'></label>"
            f"<label>Since<input type='date' name='since' value='{esc(filters['since'])}'></label>"
            f"<label>Until<input type='date' name='until' value='{esc(filters['until'])}'></label>"
            "<div class='toolbar-actions'><button class='btn btn-primary'>Filter</button>"
            "<a class='btn btn-quiet' href='/runs'>Reset</a></div></form>"
        )
        if shown:
            table = (
                "<div class='scroll'><table class='compact'><tr><th scope='col'>At (UTC)</th>"
                "<th scope='col' class='num'>Sent</th><th scope='col' class='num'>Parked</th>"
                "<th scope='col' class='num'>Pending</th><th scope='col'>Exit</th></tr>"
                f"{rows}</table></div>"
            )
        elif any(filters.values()):
            table = _empty("No pass matches these filters.", "<a href='/runs'>Clear the filters</a>")
        else:
            table = _empty("No pass has been recorded yet: the first run fills this list.")
        body = (
            filter_form
            + "<p class='muted small'>The writer keeps only the last 200 passes in the state, so this page has no "
            "pagination: older rows are not stored.</p>" + table
        )
        return page("Runs", body, active="/runs", actions=sign_out_form(request))

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
        # Per-source health, labelled by the configured source id. A configured id is validated to
        # ``[A-Za-z0-9._-]+``, so a label value never needs escaping, and the label set is bounded by the
        # configuration rather than by anything a feed says. A source nobody has polled yet has no sample:
        # absent is honest there, where 0 would claim it failed.
        raw_health = state.get("source_health")
        health = raw_health if isinstance(raw_health, dict) else {}
        configured = [str(source.get("id", "")) for source in runtime.cfg.sources]
        for name, help_text, key in (
            ("source_up", "1 when this source's last fetch succeeded", "ok"),
            ("source_last_success_timestamp_seconds", "When this source last answered (epoch seconds)", "ok_at"),
            ("source_items", "Entries in this source's last window", "items"),
        ):
            samples = []
            for identifier in configured:
                record = health.get(identifier)
                if not isinstance(record, dict):
                    continue
                value = int(bool(record.get(key))) if key == "ok" else _number(record.get(key))
                samples.append(f'advisory_radar_{name}{{source="{identifier}"}} {value}')
            if samples:
                lines.append(f"# HELP advisory_radar_{name} {help_text}")
                lines.append(f"# TYPE advisory_radar_{name} gauge")
                lines.extend(samples)
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
