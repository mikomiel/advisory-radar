"""Delivery planning: the digest and quiet-hours rules, as pure functions.

A pass renders one queue entry per advisory (``core.classify_new``) and ``core.deliver`` posts each entry to
the notifiers routing selects. This module decides what a pass sends, before any POST: whether the queued
advisories travel as one digest, and whether a non-critical message waits in the queue until a local quiet
window ends. It is pure on purpose -- it imports neither ``core`` nor ``pipeline``, reads no state and
performs no I/O -- so the rules can be asserted with plain dicts and an epoch, and a scheduling decision can
never hide inside the retry loop.

Nothing here invents a delivery state. A held entry is simply absent from every batch, so ``core.deliver``
leaves it in ``state["pending"]`` exactly as it leaves a message whose notifiers all failed. A digest message
is a queue-entry-shaped dict, so the existing notifier interface posts it unchanged.
"""

from __future__ import annotations

import datetime
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import tzinfo

from .http import MESSAGE_LIMIT

#: At most this many advisories are listed in one digest. The character budget below is what protects the
#: tightest channel -- ``DiscordWebhookNotifier`` truncates its content at 1900 characters without saying so,
#: and a digest that loses its tail silently is worse than a shorter one. This cap bounds how many headings a
#: person has to scan when the titles are short enough that the budget would allow more.
DIGEST_MAX_LINES = 20
#: A digest line keeps this much of an entry's title. Rendered queue titles are capped at 200 characters, but
#: the state is JSON a person can edit, and one pathological title must not be able to fill the whole budget
#: and push every other advisory out of the message.
DIGEST_TITLE_CHARS = 140
#: The identifiers a digest line shows, and the room they may take. The digest is a summary: three short
#: identifiers help a reader find the advisory, forty do not, and they would crowd out the advisories below.
DIGEST_MAX_IDS = 3
DIGEST_MAX_ID_CHARS = 60
#: The body budget one digest may use, before the title is subtracted. The tightest built-in channel is
#: Discord: ``DiscordWebhookNotifier`` truncates its content at 1900 characters and spends four of them on the
#: ``**`` around the title, so the whole message survives when the body stays within ``MESSAGE_LIMIT`` less
#: those overheads. A digest whose final "(+N more)" line was cut off would hide exactly the count it exists
#: to report.
DIGEST_BODY_LIMIT = MESSAGE_LIMIT - 104

#: ``HH:MM-HH:MM``, both times 24-hour and zero-padded. Strict on purpose: a spelling such as ``7:00`` reads
#: unambiguously to a person but has two possible meanings in code, and a quiet window that starts at the
#: wrong hour is a silent delay or a silent early alarm.
_QUIET_HOURS = re.compile(r"(\d{2}):(\d{2})-(\d{2}):(\d{2})")


@dataclass(frozen=True)
class QuietHours:
    """A local-time window during which non-critical messages wait; half-open ``[start, end)``, wrapping.

    ``start`` and ``end`` are minutes since local midnight. A window that wraps midnight has ``start > end``.
    Equal bounds are an empty window, not a whole day: no minute is ever inside it, so ``00:00-00:00`` is a
    harmless way to write "no quiet hours", while a non-critical message that waited for a whole day would be
    an outage the operator did not ask for.
    """

    start: int
    end: int

    def contains(self, minute: int) -> bool:
        """Whether one local minute-of-day falls inside the window."""
        if self.start == self.end:
            return False
        if self.start < self.end:
            return self.start <= minute < self.end
        return minute >= self.start or minute < self.end


def parse_quiet_hours(value: object) -> QuietHours:
    """The validated window from a ``22:00-07:00`` string; ``ValueError`` for anything else.

    The value is never echoed in the message. A configuration value can be a ``${NAME}`` reference that
    expands to a credential, and configuration errors are logged before the redaction filter exists, so the
    message names the expected form instead of repeating what was read. The exception is a plain ``ValueError``
    rather than ``config.ConfigError`` so this module stays independent of the configuration layer, which can
    present it in its own words.
    """
    match = _QUIET_HOURS.fullmatch(value.strip()) if isinstance(value, str) else None
    if match is None:
        raise ValueError("quiet_hours must look like 22:00-07:00: two 24-hour HH:MM times separated by a dash")
    start_hour, start_minute, end_hour, end_minute = (int(part) for part in match.groups())
    if start_hour > 23 or end_hour > 23 or start_minute > 59 or end_minute > 59:
        raise ValueError("quiet_hours must look like 22:00-07:00: HH:MM hours must be 00-23 and minutes 00-59")
    return QuietHours(start_hour * 60 + start_minute, end_hour * 60 + end_minute)


def is_held(epoch: int, entry: dict, window: QuietHours | None, tz: tzinfo | None = None) -> bool:
    """Whether one entry waits for the quiet window to end instead of being sent now.

    A critical entry is never held: the window is for noise, and an exploited or remotely reachable advisory
    is what the phone is for. Any other tag waits, including a missing or damaged one, because an entry whose
    severity cannot be read is not evidence of a critical advisory and the wait ends with the window.

    ``tz`` is the local zone the window is written in. ``None`` uses the host's local time, which is what
    "22:00" means to the operator; a test or a deployment with a configured zone passes an explicit
    ``tzinfo`` so the answer does not depend on the machine running it.
    """
    if window is None or entry.get("tag") == "critical":
        return False
    moment = datetime.datetime.fromtimestamp(epoch, tz)
    return window.contains(moment.hour * 60 + moment.minute)


def _identifiers(value: object) -> tuple[str, ...]:
    """The string members of a stored ``ids`` list; anything else is ignored rather than raised on.

    The state is JSON a person can edit, so ``ids`` may be a string, a number or a list with non-string
    members. A bare string is not iterated as characters: ``"CVE-2026-1"`` is one identifier, not twelve.
    """
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(member for member in value if isinstance(member, str))


def _one_line(value: object) -> str:
    """One line of queue text, with any newline collapsed and the length capped with an ellipsis.

    Collapsing whitespace is what keeps "one line per advisory" true for a title that a feed or a hand edit
    gave a line break; without it a single entry could forge the rest of the digest.
    """
    text = " ".join(str(value or "").split())
    if len(text) <= DIGEST_TITLE_CHARS:
        return text
    return text[: DIGEST_TITLE_CHARS - 1].rstrip() + "…"


def _line_ids(entry: dict) -> str:
    """The identifiers worth showing on a digest line, or an empty string when they would not help.

    ``src:`` identifiers are the internal de-duplication markers ``core`` adds, not advisory names, so they
    are hidden here exactly as ``core.render`` hides them. The first few are enough to find the advisory; a
    long list is left out rather than truncated into a line that reads like a complete list.
    """
    identifiers = [identifier for identifier in _identifiers(entry.get("ids")) if not identifier.startswith("src:")]
    if not identifiers:
        return ""
    shown = identifiers[:DIGEST_MAX_IDS]
    text = ", ".join(shown)
    if len(identifiers) > len(shown):
        text += f" +{len(identifiers) - len(shown)}"
    if len(text) > DIGEST_MAX_ID_CHARS:
        return ""
    return f" ({text})"


def _digest_body(lines: Sequence[str], omitted: int) -> str:
    """The digest body: one line per advisory, then how many were left out.

    It starts with a newline for the same reason ``core.render`` does: every channel either prefixes the
    title to the body or sends them as two fields, and the newline keeps the title a paragraph of its own.
    """
    body = "\n" + "\n".join(lines)
    if omitted:
        body += f"\n(+{omitted} more not listed)"
    return body


def _union_ids(entries: Sequence[dict]) -> list[str]:
    """Every identifier the covered entries name, once each, in the order the entries name them.

    Order is kept rather than sorted so the digest is deterministic and a person can read the ids in the
    order the advisories appear in the body.
    """
    union: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        for identifier in _identifiers(entry.get("ids")):
            if identifier not in seen:
                seen.add(identifier)
                union.append(identifier)
    return union


def _digest_line(entry: dict) -> str:
    """One advisory as a Markdown bullet: its title, then its identifiers when they are short enough to help."""
    return f"- **{_one_line(entry.get('title')) or '(untitled advisory)'}**{_line_ids(entry)}"


def digest_message(entries: Sequence[dict]) -> dict:
    """One queue-entry-shaped message covering every entry; delivery posts it through the existing interface.

    The title states the count and the severity a digest of these entries carries: ``critical`` when any
    covered entry is critical, ``warning`` otherwise -- a digest is one message, so it can only be as urgent
    as its most urgent advisory. The body lists one line per advisory, capped by :data:`DIGEST_MAX_LINES` and
    by the character budget the tightest built-in channel accepts; the entries that do not fit are counted in
    a final line rather than dropped silently, and they are still covered by the digest.

    The budget is :data:`DIGEST_BODY_LIMIT` less the title: the same order of magnitude as the budget
    ``core.render`` gives a rendered message, and small enough that the whole digest survives the tightest
    channel instead of losing its last line.
    """
    entries = list(entries)
    if not entries:
        raise ValueError("a digest needs at least one advisory")
    tag = "critical" if any(entry.get("tag") == "critical" for entry in entries) else "warning"
    count = len(entries)
    title = f"{tag.upper()}: digest of {count} {'advisory' if count == 1 else 'advisories'}"
    budget = DIGEST_BODY_LIMIT - len(title)
    lines = [_digest_line(entry) for entry in entries[:DIGEST_MAX_LINES]]
    omitted = count - len(lines)
    # Trim from the end rather than skipping a line in the middle: the digest stays in queue order, and the
    # final count still accounts for every advisory the message covers.
    while lines and len(_digest_body(lines, omitted)) > budget:
        lines.pop()
        omitted += 1
    return {
        "title": title,
        "body": _digest_body(lines, omitted),
        "tag": tag,
        "kind": "digest",
        "ids": _union_ids(entries),
        "link": "",
        "source": "digest",
    }


@dataclass(frozen=True)
class Batch:
    """One send action: the queue entries it covers, and the message to post.

    ``message`` is a digest covering every entry when digesting is on. ``None`` means the entry is sent as it
    was rendered, which is why such a batch holds exactly one entry: one batch is one delivery, so a caller
    can count successes and failures per batch without splitting one.
    """

    entries: tuple[dict, ...]
    message: dict | None


def plan(
    entries: Sequence[dict],
    epoch: int,
    *,
    digest: bool = False,
    quiet: QuietHours | None = None,
    tz: tzinfo | None = None,
) -> list[Batch]:
    """What one pass sends now, in queue order; held entries are absent and therefore stay queued.

    ``digest`` turns every entry the pass is delivering into one :func:`digest_message`; with it off each
    entry becomes its own batch with ``message=None`` and is posted exactly as it was rendered, so the feature
    can be enabled without changing any channel's message. ``quiet`` holds the entries :func:`is_held` says
    are non-critical inside the window -- including warnings that would otherwise join a digest, while a
    critical entry in the same pass still goes out at once.

    The function is deterministic and order-preserving: the same entries, epoch and options always produce
    the same batches, and a batch lists its entries in the order it received them. It reads only its
    arguments, so the caller owns the clock and the state: ``core.deliver`` implements the result, and a held
    entry simply remains in ``state["pending"]``. ``entries`` is the slice this pass may deliver (``core``
    caps delivery at ``DELIVERY_CAP``), not the whole pending list: the rest waits for a later pass, and
    digesting it here would send more advisories than a normal pass is allowed to.
    """
    sendable = [entry for entry in entries if not is_held(epoch, entry, quiet, tz)]
    if not sendable:
        return []
    if digest:
        return [Batch(entries=tuple(sendable), message=digest_message(sendable))]
    return [Batch(entries=(entry,), message=None) for entry in sendable]
