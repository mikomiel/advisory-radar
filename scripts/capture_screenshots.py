#!/usr/bin/env python3
"""Write the README screenshots from demo data (opt-in; not part of the app or CI).

The script builds a throwaway configuration and state in a temporary directory, serves the real app on
``127.0.0.1`` with a random port and a throwaway session token, signs in through the real ``/login`` form,
and writes one PNG per page. Every page is captured at 1024 px wide and cropped to its rendered height.
Nothing outside ``--output-dir`` is written, and the demo data names no real source, notifier or CVE.

Playwright is deliberately *not* a project dependency: it is installed for one run, not shipped with the
app. Run the script with it added to the environment, and install the browser once:

    uv run --with playwright python scripts/capture_screenshots.py
    uv run --with playwright playwright install chromium

The output defaults to ``docs/screenshots``. The images are committed by a separate, later change; this
script only writes them.
"""

from __future__ import annotations

import argparse
import os
import secrets
import socket
import tempfile
import threading
import time
from pathlib import Path

from advisory_radar import core
from advisory_radar.runtime import Runtime
from advisory_radar.state import save_state
from advisory_radar.web import create_app

#: The pages the README illustrates, as ``(file stem, path)``, in capture order.
PAGES = (
    ("dashboard", "/"),
    ("alerts", "/alerts"),
    ("parked", "/parked"),
    ("config", "/config"),
    ("runs", "/runs"),
)
#: Every image is captured at this width; the pages are fluid, so one width keeps the set consistent.
WIDTH = 1024
#: The viewport height only decides the initial layout; each image is resized to the rendered document.
HEIGHT = 720
#: The blank space kept below the last element, so the crop does not touch the content.
BOTTOM_PAD = 16
#: The demo configuration. Sources and channels are example hosts and everything secret is a reference.
DEMO_CONFIG = """\
sources:
  - id: nodejs
    type: rss
    url: https://nodejs.org/en/feed/vulnerability.xml
  - id: debian-dsa
    type: rss
    url: https://www.debian.org/security/dsa-long.en.rss
  - id: php-releases
    type: freshrss
    url: https://rss.example.net/FreshRSS/api/greader.php
    token: ${DEMO_FRESHRSS_TOKEN}
    user: demo
  - id: adobe-commerce
    type: changedetection
    url: https://changes.example.net
    api_key: ${DEMO_CHANGEDETECTION_KEY}
notifiers:
  - id: discord-security
    type: discord_webhook
    url: ${DEMO_DISCORD_WEBHOOK}
  - id: ntfy-phone
    type: ntfy
    url: ${DEMO_NTFY_URL}
    topic: advisories
    priority: 4
routes:
  - match: {tag: critical}
    notifiers: [ntfy-phone]
  - match: {source: php-releases}
    notifiers: [discord-security]
default: [discord-security]
poll_interval: 15m
state_path: {state_path}
"""
#: The fake identifiers the screenshots may show. They are the ones the README images already used: no
#: value here belongs to a real advisory.
DEMO_ADVISORIES = (
    "CVE-2026-48211",
    "GHSA-3q9c-9x6v-2v8m",
    "CVE-2026-47120",
    "DSA-6104-1: openssl",
    "CVE-2026-44117",
    "APSB26-97",
    "CVE-2026-39887",
    "GHSA-7h2p-4m6c-9r3x",
    "DSA-6098-1: curl",
    # the queued and parked demo messages
    "CVE-2026-50111",
    "CVE-2026-46601",
    "CVE-2026-45230",
)
#: A seen record written before the delivery snapshot existed, so the Alerts screenshot shows the dash note.
DEMO_LEGACY = "CVE-2026-45510"
MISSING_PLAYWRIGHT = (
    "Playwright is not installed in this interpreter, so the screenshots cannot be captured.\n"
    "Run the script with Playwright added to the environment:\n"
    "  uv run --with playwright python scripts/capture_screenshots.py\n"
    "and install the browser once:\n"
    "  uv run --with playwright playwright install chromium"
)


def demo_environment(token: str) -> dict[str, str]:
    """The process environment the demo app is built with: a throwaway token and fake channel URLs."""
    return {
        "ADVISORY_RADAR_AUTH_TOKEN": token,
        # This instance is served over plain HTTP on loopback, so the Secure cookie would never come back.
        "ADVISORY_RADAR_INSECURE_COOKIES": "1",
        "DEMO_DISCORD_WEBHOOK": "https://discord.example.net/api/webhooks/demo",
        "DEMO_NTFY_URL": "https://ntfy.example.net/advisories",
        "DEMO_FRESHRSS_TOKEN": "demo",
        "DEMO_CHANGEDETECTION_KEY": "demo",
    }


def demo_config(state_path: Path) -> str:
    """The demo YAML: example hosts only, and every credential as a ``${NAME}`` reference."""
    return DEMO_CONFIG.replace("{state_path}", str(state_path))


def _seen(cve: str, tag: str, source: str, title: str, level: str, score: float, delivered: list[str]):
    """The delivery snapshot the advisory page reads, and the id its seen record points at."""
    snapshot = {
        "tag": tag,
        "source": source,
        "title": title,
        "link": f"https://vendor.example.net/advisories/{cve}",
        "kind": "new",
        "ids": [cve],
        "cves": [cve],
        "kev_only": [],
        "products": [],
        "levels": {cve: level},
        "scores": {cve: score},
        "delivered_to": delivered,
    }
    return snapshot, f"demo-{cve.lower().replace(':', '-')}"


def _queued(title: str, tag: str, cves: list[str], levels: dict, scores: dict, *, parked_at: int | None = None):
    """One pending or parked message, with the attempt history a failed delivery leaves behind."""
    entry = {
        "kind": "new",
        "tag": tag,
        "title": title,
        "body": "The rendered message body is not stored on a seen record and is not shown by the UI.",
        "ids": list(cves),
        "cves": list(cves),
        "levels": levels,
        "scores": scores,
        "kev_only": [],
        "source": "Vendor Feed",
        "link": f"https://vendor.example.net/advisories/{cves[0]}",
        "attempts": 3,
        "first_attempt_at": 0,
        "last_status": 0,
        "sent_to": [],
    }
    if parked_at is not None:
        entry["parked_at"] = parked_at
    return entry


def demo_state(now: int | None = None) -> dict:
    """The demo state: fake advisories, one pending message, two parked ones and a short run history.

    ``now`` is rounded down to the hour so repeated runs inside one hour render the same pages.
    """
    now = int(time.time()) if now is None else now
    now -= now % 3600
    hour = 3600
    state = core.new_state()
    #: ``(hours ago, tag, source heading, identifier, title)``; every identifier is in ``DEMO_ADVISORIES``.
    rows = (
        (2, "critical", "Vendor Feed", "CVE-2026-48211", "CRITICAL: CVE-2026-48211 in widgetd (CVSS 9.8)"),
        (6, "warning", "GitHub advisories", "GHSA-3q9c-9x6v-2v8m", "WARNING: GHSA-3q9c-9x6v-2v8m in http-client"),
        (23, "warning", "Vendor Feed", "CVE-2026-47120", "WARNING: CVE-2026-47120 in image-parser (CVSS 5.9)"),
        (29, "critical", "Debian security", "DSA-6104-1: openssl", "CRITICAL: DSA-6104-1: openssl (CVSS 9.8)"),
        (51, "critical", "Vendor Feed", "CVE-2026-44117", "CRITICAL: CVE-2026-44117 in auth-gateway (CVSS 9.1)"),
        (70, "warning", "Adobe bulletins", "APSB26-97", "WARNING: APSB26-97 in Commerce (CVSS 7.2)"),
        (77, "warning", "Vendor Feed", "CVE-2026-39887", "WARNING: CVE-2026-39887 in scheduler (CVSS 6.5)"),
        (96, "warning", "GitHub advisories", "GHSA-7h2p-4m6c-9r3x", "WARNING: GHSA-7h2p-4m6c-9r3x in template-engine"),
        (120, "warning", "Debian security", "DSA-6098-1: curl", "WARNING: DSA-6098-1: curl (CVSS 6.5)"),
    )
    scores = {
        "CVE-2026-48211": 9.8,
        "GHSA-3q9c-9x6v-2v8m": 6.1,
        "CVE-2026-47120": 5.9,
        "DSA-6104-1: openssl": 9.8,
        "CVE-2026-44117": 9.1,
        "APSB26-97": 7.2,
        "CVE-2026-39887": 6.5,
        "GHSA-7h2p-4m6c-9r3x": 6.8,
        "DSA-6098-1: curl": 6.5,
    }
    deliveries: dict[str, dict] = {}
    for hours, tag, source, identifier, title in rows:
        delivered = ["discord-security", "ntfy-phone"] if tag == "critical" else ["discord-security"]
        snapshot, delivery_id = _seen(identifier, tag, source, title, tag, scores[identifier], delivered)
        deliveries[delivery_id] = snapshot
        state["seen"][identifier] = {"at": now - hours * hour, "outcome": "delivered", "delivery": delivery_id}
    if deliveries:
        state["deliveries"] = deliveries
    # A record from before the delivery snapshot: the UI says its details were not recorded instead of guessing.
    state["seen"][DEMO_LEGACY] = {"at": now - 44 * hour, "outcome": "suppressed"}

    pending = _queued(
        "WARNING: CVE-2026-50111 in nginx (CVSS 7.5)",
        "warning",
        ["CVE-2026-50111"],
        {"CVE-2026-50111": "warning"},
        {"CVE-2026-50111": 7.5},
    )
    pending["attempts"] = 1
    pending["first_attempt_at"] = now - 5 * 60
    pending["last_status"] = 502
    state["pending"].append(pending)

    parked_critical = _queued(
        "CRITICAL: CVE-2026-46601 in phpMyAdmin (CVSS 9.1)",
        "critical",
        ["CVE-2026-46601"],
        {"CVE-2026-46601": "critical"},
        {"CVE-2026-46601": 9.1},
        parked_at=now - 20 * 60,
    )
    parked_critical["first_attempt_at"] = now - 2 * hour
    parked_critical["last_status"] = 500
    parked_warning = _queued(
        "WARNING: CVE-2026-45230 in libxml2 (CVSS 7.5)",
        "warning",
        ["CVE-2026-45230"],
        {"CVE-2026-45230": "warning"},
        {"CVE-2026-45230": 7.5},
        parked_at=now - 40 * 60,
    )
    parked_warning["first_attempt_at"] = now - 3 * hour
    parked_warning["last_status"] = 500
    state["parked"] = [parked_critical, parked_warning]
    # Oldest first, as the writer appends them: the page reverses the list to show the newest pass on top.
    history = ((3, 0, 0), (3, 0, 0), (2, 1, 1), (3, 0, 0), (4, 0, 0), (3, 0, 0))
    state["runs"] = [
        {
            "at": now - (len(history) - 1 - index) * 900,
            "finished_at": now - (len(history) - 1 - index) * 900 + 4,
            "sent": sent,
            "parked": parked,
            "pending": 1,
            "code": code,
        }
        for index, (sent, parked, code) in enumerate(history)
    ]
    return state


def load_playwright():
    """The Playwright entry point, imported only when screenshots are actually captured."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # not a project dependency: one run, then it is gone
        raise SystemExit(MISSING_PLAYWRIGHT) from exc
    return sync_playwright


def start_server(app) -> tuple[object, threading.Thread, int]:
    """Serve ``app`` on a free loopback port; returns the uvicorn server, its thread and the port."""
    import uvicorn  # imported here so the demo-data helpers above need no server dependency

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            raise RuntimeError("the demo server did not start")
        time.sleep(0.05)
    return server, thread, port


def rendered_height(page) -> int:
    """Where the rendered content ends, so an image is cropped to the page rather than to the viewport.

    A viewport-sized screenshot of a short page is mostly blank, and the README images are as tall as their
    content. ``getBoundingClientRect`` on the body's children is the bottom of the last element; body margins
    are excluded, so a small pad is added instead of guessing from a scroll height that never goes below the
    viewport.
    """
    bottom = page.evaluate(
        "() => { const kids = Array.from(document.body.children);"
        " const bottom = kids.length ? Math.max(...kids.map((e) => e.getBoundingClientRect().bottom))"
        " : document.body.getBoundingClientRect().bottom;"
        " return Math.ceil(bottom); }"
    )
    return max(200, int(bottom) + BOTTOM_PAD)


def capture(sync_playwright, base_url: str, token: str, output_dir: Path) -> list[Path]:
    """Sign in through ``/login`` and write one full-page PNG per entry in ``PAGES``."""
    written = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page(viewport={"width": WIDTH, "height": HEIGHT}, device_scale_factor=1)
            page.goto(f"{base_url}/login")
            page.fill("input[name=token]", token)
            page.click("form button")  # the sign-in button; the login page carries no other form
            # A wrong token renders the login page again, so this is also the check that sign-in worked.
            page.wait_for_url(f"{base_url}/")
            page.wait_for_load_state("load")
            for name, path in PAGES:
                page.goto(f"{base_url}{path}")
                page.wait_for_load_state("load")
                # The pages are fluid in width only, so setting the height to the content height and taking
                # the viewport crops the image without reflowing it.
                page.set_viewport_size({"width": WIDTH, "height": rendered_height(page)})
                destination = output_dir / f"{name}.png"
                page.screenshot(path=str(destination))
                written.append(destination)
        finally:
            browser.close()
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the README screenshots from demo data.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("docs/screenshots"),
        help="where the five PNGs are written (default: docs/screenshots)",
    )
    arguments = parser.parse_args(argv)
    sync_playwright = load_playwright()
    output_dir: Path = arguments.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    token = secrets.token_hex(16)  # throwaway: this process serves one local browser and exits
    environment = demo_environment(token)
    # The login handler reads the cookie switch from the process environment, not from the app's mapping.
    os.environ.update(environment)
    # The demo runs from its temporary directory with a relative state path, so the configuration page (and
    # therefore the screenshot) shows "data/state.json" rather than a path that changes on every run.
    previous_directory = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="advisory-radar-screenshots-") as directory:
        root = Path(directory)
        os.chdir(root)
        try:
            state_path = Path("data/state.json")
            config_path = root / "config.yml"
            config_path.write_text(demo_config(state_path), encoding="utf-8")
            save_state(state_path, demo_state())
            runtime = Runtime.build(config_path, environment)
            try:
                server, thread, port = start_server(create_app(runtime, environment))
                try:
                    written = capture(sync_playwright, f"http://127.0.0.1:{port}", token, output_dir)
                finally:
                    server.should_exit = True
                    thread.join(timeout=10)
            finally:
                runtime.detach_redaction()
        finally:
            os.chdir(previous_directory)
    for path in written:
        print(f"wrote {path}")
    print(f"{len(written)} screenshots in {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
