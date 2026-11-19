"""The built-in source and notifier catalogues: one entry per config ``type``.

Standard library only, deliberately: ``config.py`` derives the keys a source entry may carry from this
registry and ``sources.py`` owns the builders, so importing anything from the package here would close the
cycle ``config -> catalogue -> config``. This module is the single owner of a kind's summary, keys, example
and docs anchor; ``tests/test_catalogue.py`` pins the builders, the config allowlist, the docs/sources.md table and
the ``/sources`` page to it, and ``tests/test_notifier_catalogue.py`` does the same for ``NOTIFIER_SPECS``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SourceSpec:
    """What a user needs to configure one built-in source type, with an example that is tested.

    ``required`` and ``optional`` are the keys an entry may carry besides ``id`` and ``type``. The example
    is loaded through ``load_config`` and built through ``build_source`` by the test suite, so a snippet
    here cannot rot into one nobody checked.

    ``secret_keys`` names the keys the overlay refuses to store literally. A source URL is not one of them:
    it is usually public configuration, and a URL that carries a token must be written as a ``${NAME}``
    reference because nothing can tell the two apart.
    """

    kind: str
    summary: str
    required: tuple[str, ...]
    optional: tuple[str, ...]
    example: dict
    docs_anchor: str
    #: Keys whose value is a credential; the overlay accepts only an environment reference for them.
    secret_keys: tuple[str, ...] = ()


#: Config ``type`` -> what the source is and which keys it takes; one entry per ``SOURCE_BUILDERS`` key.
SOURCE_SPECS: dict[str, SourceSpec] = {
    "rss": SourceSpec(
        kind="rss",
        summary="Any RSS 2.0, Atom, RSS 1.0 or JSON Feed URL, or a page that advertises one, read in one "
        "conditional GET.",
        required=("url",),
        optional=("tag", "enabled"),
        example={
            "id": "vendor-feed",
            "type": "rss",
            "url": "https://vendor.example.net/security.xml",
        },
        docs_anchor="docs/sources.md",
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
        docs_anchor="docs/sources.md",
        secret_keys=("token",),
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
        docs_anchor="docs/sources.md",
        secret_keys=("api_key",),
    ),
    "webhook": SourceSpec(
        kind="webhook",
        summary="Items pushed to this instance's /webhooks/<id> endpoint, read from the state inbox.",
        required=(),
        optional=("tag", "enabled"),
        example={"id": "vendor-webhook", "type": "webhook"},
        docs_anchor="docs/sources.md",
    ),
}


@dataclass(frozen=True)
class NotifierSpec:
    """What a user needs to configure one built-in notifier type, with an example that is tested.

    ``required`` and ``optional`` are the keys an entry may carry besides ``id`` and ``type``, listed the way
    :class:`SourceSpec` lists them: ``enabled`` is optional for every type. The example is loaded through
    ``load_config`` and built through ``build_notifier`` by the test suite, so a snippet here cannot rot into one
    nobody checked.

    ``secret_keys`` are the keys the type reads that the settings overlay accepts only as a whole ``${NAME}``
    environment reference; the first one is the credential the page's "new notifier" form asks for before the
    others. ``yaml_only`` are the keys the page never writes, because a mapping or a value of that kind could
    carry a credential: they are set in the YAML file, and the page says so before anything is submitted.
    ``tests/test_notifier_catalogue.py`` pins the builders, the config allowlist, the overlay rules and the
    ``docs/notifiers.md`` table to this registry.
    """

    kind: str
    summary: str
    required: tuple[str, ...]
    optional: tuple[str, ...]
    example: dict
    docs_anchor: str
    #: Keys whose value is a credential; the overlay accepts only an environment reference for them.
    secret_keys: tuple[str, ...] = ()
    #: Keys only the YAML file can set; the overlay refuses them, so the page cannot offer a field.
    yaml_only: tuple[str, ...] = ()


#: Config ``type`` -> what the notifier is and which keys it takes; one entry per ``NOTIFIER_BUILDERS`` key.
NOTIFIER_SPECS: dict[str, NotifierSpec] = {
    "apprise": NotifierSpec(
        kind="apprise",
        summary="An Apprise API gateway: the message is posted to /notify/<key> as that key's login.",
        required=("url", "password"),
        optional=("key", "enabled"),
        example={
            "id": "apprise",
            "type": "apprise",
            "url": "${APPRISE_URL}",
            "password": "${APPRISE_PASSWORD}",
            "key": "${APPRISE_KEY}",
        },
        docs_anchor="docs/notifiers.md#apprise",
        secret_keys=("url", "password", "key"),
    ),
    "discord_webhook": NotifierSpec(
        kind="discord_webhook",
        summary="A Discord channel webhook; the message is cut to fit one Discord message.",
        required=("url",),
        optional=("enabled",),
        example={"id": "discord", "type": "discord_webhook", "url": "${DISCORD_WEBHOOK_URL}"},
        docs_anchor="docs/notifiers.md#discord_webhook",
        secret_keys=("url",),
    ),
    "webhook": NotifierSpec(
        kind="webhook",
        summary="Any JSON webhook: the whole structured message is posted, signed when a secret is set.",
        required=("url",),
        optional=("secret", "headers", "enabled"),
        example={
            "id": "hook",
            "type": "webhook",
            "url": "${WEBHOOK_URL}",
            "secret": "${WEBHOOK_SECRET}",
            "headers": {"X-Api-Key": "${WEBHOOK_API_KEY}"},
        },
        docs_anchor="docs/notifiers.md#webhook",
        secret_keys=("url", "secret"),
        yaml_only=("headers",),
    ),
    "matrix_webhook": NotifierSpec(
        kind="matrix_webhook",
        summary="A Matrix Hookshot or Element webhook; the bridge renders the Markdown.",
        required=("url",),
        optional=("enabled",),
        example={"id": "matrix", "type": "matrix_webhook", "url": "${MATRIX_WEBHOOK_URL}"},
        docs_anchor="docs/notifiers.md#matrix_webhook",
        secret_keys=("url",),
    ),
    "ntfy": NotifierSpec(
        kind="ntfy",
        summary="An ntfy topic, published through the server's JSON API.",
        required=("url", "topic"),
        optional=("priority", "enabled"),
        example={"id": "phone", "type": "ntfy", "url": "${NTFY_URL}", "topic": "advisories", "priority": 4},
        docs_anchor="docs/notifiers.md#ntfy",
        secret_keys=("url",),
    ),
    "gotify": NotifierSpec(
        kind="gotify",
        summary="A Gotify server, posted to /message with the application token.",
        required=("url", "token"),
        optional=("priority", "enabled"),
        example={
            "id": "gotify",
            "type": "gotify",
            "url": "${GOTIFY_URL}",
            "token": "${GOTIFY_TOKEN}",
            "priority": 5,
        },
        docs_anchor="docs/notifiers.md#gotify",
        secret_keys=("url", "token"),
    ),
    "smtp": NotifierSpec(
        kind="smtp",
        summary="Email through an SMTP server, over STARTTLS (587) or implicit TLS (465).",
        required=("host", "from", "to"),
        optional=("port", "username", "password", "use_tls", "implicit_tls", "enabled"),
        example={
            "id": "mail",
            "type": "smtp",
            "host": "smtp.example.net",
            "port": 587,
            "from": "radar@example.net",
            "to": "ops@example.net",
            "username": "radar",
            "password": "${SMTP_PASSWORD}",
            "use_tls": True,
        },
        docs_anchor="docs/notifiers.md#smtp",
        secret_keys=("password",),
    ),
    "log": NotifierSpec(
        kind="log",
        summary="Writes each message to the application log and delivers nothing, for a shadow run.",
        required=(),
        optional=("enabled",),
        example={"id": "shadow", "type": "log"},
        docs_anchor="docs/notifiers.md#log",
    ),
}

__all__ = ["NOTIFIER_SPECS", "SOURCE_SPECS", "NotifierSpec", "SourceSpec"]
