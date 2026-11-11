"""HTTP transport, JSON parsing, log hygiene and message limits."""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping

USER_AGENT = "advisory-radar (+https://github.com/mikomiel/advisory-radar)"
#: One Discord message holds 2000 characters; titles and bodies are capped below it.
MESSAGE_LIMIT = 2000

#: ``http(method, url, headers, body) -> (status, headers, body)``; status 0 is any network error.
Http = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, dict[str, str], bytes]]

#: urllib buffers at most this many bytes plus one, so no response exhausts memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
HTTP_TIMEOUT = 30


def resolve_host(host: str) -> tuple[str, ...]:
    """Every address a host resolves to, as text; empty when it cannot be resolved."""
    return tuple(info[4][0] for info in socket.getaddrinfo(host, None))


def private_destination(url: str, resolve: Callable[[str], Iterable[str]] = resolve_host) -> bool:
    """Whether this URL's host is, or resolves to, an address that is not on the public internet.

    This answers a question about a *form*, not about every fetch: it is checked when a source is added from
    the settings overlay and when a new source is probed. A public name that later resolves to a private
    address is out of reach of a save-time check, so the rule it feeds is "who may point this instance at an
    internal address", and the YAML -- written by whoever runs the host -- is never subject to it.
    """
    try:
        # Unquoted exactly as ``urllib.request.Request`` unquotes it before it dials: ``%31%32%37.0.0.1`` is
        # ``127.0.0.1`` to the transport, so it has to be to this check too.
        host = urllib.parse.unquote(urllib.parse.urlsplit(url).hostname or "")
    except ValueError:
        return True  # a URL nobody can parse must not be fetched either
    if not host:
        return True
    try:
        addresses = tuple(resolve(host))
    except (OSError, UnicodeError):
        # Unresolvable is not private: the fetch fails and reports that, which is the more useful message.
        return False
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])  # an IPv6 zone id is not part of the address
        except ValueError:
            continue
        # ``is_global`` is the shortest statement of "routable on the public internet", and it is not enough on
        # its own: IPv6 site-local ``fec0::/10`` and IPv4 multicast both report ``is_global`` true, and only an
        # ``IPv6Address`` has ``is_site_local`` at all.
        if not parsed.is_global or parsed.is_multicast or getattr(parsed, "is_site_local", False):
            return True
    return False


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect is a final status, not a hop: a login page answering 200 must never count as delivery,
    and an Authorization header must never be forwarded to another origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102 - urllib hook
        return None


#: Built once: the opener owns no per-call state, and building it per request would leak connections.
_OPENER = urllib.request.build_opener(_NoRedirects)


def urllib_http(
    method: str, url: str, headers: Mapping[str, str], body: bytes | None
) -> tuple[int, dict[str, str], bytes]:
    try:
        scheme = urllib.parse.urlsplit(url).scheme
    except ValueError:
        # A malformed URL (an unclosed IPv6 bracket) is a refused request, exactly as it was when the
        # ``Request`` built it and raised inside the guard below.
        return 0, {}, b""
    if scheme not in ("http", "https"):
        # ``urllib`` opens its other handlers too -- ``file://`` would read a local file as a feed. Every source
        # and notifier this program talks to is HTTP(S), so any other scheme is a refused request, not a fetch.
        return 0, {}, b""
    try:
        # Built inside the guard: a malformed URL raises a ValueError whose text carries the URL, and a URL
        # can carry a token.
        request = urllib.request.Request(url, data=body, headers={"User-Agent": USER_AGENT, **headers}, method=method)
        with _OPENER.open(request, timeout=HTTP_TIMEOUT) as response:
            return response.status, dict(response.headers), response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        try:
            payload = exc.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException):
            payload = b""
        return exc.code, dict(exc.headers or {}), payload
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
        # The exception text may carry the URL, and the URL may carry a token.
        return 0, {}, b""


def parse_json(body: bytes) -> object | None:
    """Untrusted body parsed as JSON; invalid JSON is None (a failed lookup), never an exception."""
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        # RecursionError: a few thousand nested arrays defeat the decoder with a tiny body.
        return None


def header(headers: Mapping[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


class RedactFilter(logging.Filter):
    """Replace any secret in a fully formatted record with a placeholder."""

    def __init__(self, secrets) -> None:
        super().__init__()
        self._raw: set[str] = set()
        self.secrets: list[str] = []
        self.add(secrets)

    @property
    def raw(self) -> list[str]:
        """The secret values themselves, without the encoded variants."""
        return list(self._raw)

    def add(self, secrets) -> None:
        """Merge more secrets into this filter, longest first.

        A reload keeps the values an older configuration referenced (a pass may still be using it), and one
        cumulative filter must know all of them: chained filters would let a short old value replace its part
        of a longer new secret before the new filter could match it. Longest first is what makes that order
        safe, including for the percent-encoded form a token takes inside a URL.
        """
        self._raw.update(secret for secret in secrets if secret)
        encoded = {urllib.parse.quote(secret, safe="") for secret in self._raw}
        self.secrets = sorted({*self._raw, *encoded}, key=len, reverse=True)

    def filter(self, record: logging.LogRecord) -> bool:
        text = record.getMessage()
        for secret in self.secrets:
            text = text.replace(secret, "[redacted]")
        record.msg, record.args, record.exc_info, record.exc_text = text, None, None, None
        return True


def inert(line: str) -> str:
    """``line`` with every ``@`` followed by a zero-width space, so no renderer acts on a mention."""
    return line.replace("@", "@\u200b")
