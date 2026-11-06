"""HTTP transport, JSON parsing, log hygiene and message limits."""

from __future__ import annotations

import http.client
import json
import logging
import urllib.error
import urllib.request
from collections.abc import Mapping

USER_AGENT = "advisory-radar (+https://github.com/mikomiel/advisory-radar)"
#: One Discord message holds 2000 characters; titles and bodies are capped below it.
MESSAGE_LIMIT = 2000

#: ``http(method, url, headers, body) -> (status, headers, body)``; status 0 is any network error.
Http = "Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, dict[str, str], bytes]]"

from collections.abc import Callable  # noqa: E402

Http = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, dict[str, str], bytes]]

#: urllib buffers at most this many bytes plus one, so no response exhausts memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
HTTP_TIMEOUT = 30


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
    request = urllib.request.Request(url, data=body, headers={"User-Agent": USER_AGENT, **headers}, method=method)
    try:
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
    except ValueError:
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
        self.secrets = [secret for secret in secrets if secret]

    def filter(self, record: logging.LogRecord) -> bool:
        text = record.getMessage()
        for secret in self.secrets:
            text = text.replace(secret, "[redacted]")
        record.msg, record.args, record.exc_info, record.exc_text = text, None, None, None
        return True


def inert(line: str) -> str:
    """``line`` with every ``@`` followed by a zero-width space, so no renderer acts on a mention."""
    return line.replace("@", "@\u200b")
