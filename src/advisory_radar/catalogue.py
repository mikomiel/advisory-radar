"""The built-in source catalogue: one entry per config ``type``.

Standard library only, deliberately: ``config.py`` derives the keys a source entry may carry from this
registry and ``sources.py`` owns the builders, so importing anything from the package here would close the
cycle ``config -> catalogue -> config``. This module is the single owner of a kind's summary, keys, example
and docs anchor; ``tests/test_catalogue.py`` pins the builders, the config allowlist, the README table and
the ``/sources`` page to it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SourceSpec:
    """What a user needs to configure one built-in source type, with an example that is tested.

    ``required`` and ``optional`` are the keys an entry may carry besides ``id`` and ``type``. The example
    is loaded through ``load_config`` and built through ``build_source`` by the test suite, so a snippet
    here cannot rot into one nobody checked.
    """

    kind: str
    summary: str
    required: tuple[str, ...]
    optional: tuple[str, ...]
    example: dict
    docs_anchor: str


#: Config ``type`` -> what the source is and which keys it takes; one entry per ``SOURCE_BUILDERS`` key.
SOURCE_SPECS: dict[str, SourceSpec] = {
    "rss": SourceSpec(
        kind="rss",
        summary="Any RSS 2.0 or Atom feed URL, read in one conditional GET.",
        required=("url",),
        optional=("tag", "enabled"),
        example={
            "id": "vendor-feed",
            "type": "rss",
            "url": "https://vendor.example.net/security.xml",
        },
        docs_anchor="README.md#sources",
    ),
    "freshrss": SourceSpec(
        kind="freshrss",
        summary="A FreshRSS shared query, read through its GReader JSON export.",
        required=("url", "token"),
        optional=("user", "enabled"),
        example={
            "id": "freshrss",
            "type": "freshrss",
            "url": "https://rss.example.net",
            "token": "${FRESHRSS_TOKEN}",
            "user": "advisory-radar",
        },
        docs_anchor="README.md#sources",
    ),
    "changedetection": SourceSpec(
        kind="changedetection",
        summary="Poll a changedetection.io instance; every watch whose page changed becomes one item.",
        required=("url", "api_key"),
        optional=("tag", "enabled"),
        example={
            "id": "changedetection",
            "type": "changedetection",
            "url": "https://changes.example.net",
            "api_key": "${CHANGEDETECTION_API_KEY}",
            "tag": "advisories",
        },
        docs_anchor="README.md#sources",
    ),
    "webhook": SourceSpec(
        kind="webhook",
        summary="Items pushed to this instance's /webhooks/<id> endpoint, read from the state inbox.",
        required=(),
        optional=("tag", "enabled"),
        example={"id": "vendor-webhook", "type": "webhook"},
        docs_anchor="README.md#sources",
    ),
}

__all__ = ["SOURCE_SPECS", "SourceSpec"]
