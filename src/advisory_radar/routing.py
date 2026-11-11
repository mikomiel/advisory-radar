"""Notification routing: which notifiers a queued message goes to.

A pure function of the message entry and the configuration. Nothing here imports ``core``, so a routing
decision is testable without a state file, a notifier or HTTP. ``core.deliver`` is the only caller: it builds
the target notifier list from the ids returned here and keeps its per-notifier retry.

The predicates read only what the queue entry records, and only what the classification measured: the
CVSS and EPSS of the CVEs it judged, and whether any of them is in the KEV catalog. A rule may therefore
never be satisfied by a score nobody observed.
"""

from __future__ import annotations

import fnmatch
import math
from collections.abc import Sequence

#: The keys a route's ``match`` mapping may carry; ``config`` refuses any other and validates each value by
#: its key.
MATCH_KEYS = frozenset({"source", "tag", "product", "ids", "min_cvss", "epss_gte", "kev"})
#: The only tags a queued message can carry: they are its severity word (``core.LEVEL_LABEL``). A rule matching
#: any other value could never fire, so ``config`` refuses it instead of accepting a rule that delivers nothing.
SEVERITY_TAGS = frozenset({"critical", "warning"})


def _strings(value: object) -> tuple[str, ...]:
    """The string members of a list from the state document; anything else is ignored, never raised on.

    The state is JSON a person can edit by hand: ``ids`` or ``products`` may be a string, a number or a list
    with non-string members. None of that may break a delivery pass, and a bare string is not iterated as
    characters (``"magento" in "magento"`` must not be read as a product match).
    """
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(member for member in value if isinstance(member, str))


def _number(value: object) -> float | None:
    """A measured score, or None for anything that is not a finite number.

    A hand-edited state can hold a string, a boolean or NaN in a score position; none of them is a measurement.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return float(value)


def _highest(measured: object) -> float | None:
    """The highest value in a stored ``identifier -> score`` mapping, or None when nothing was measured.

    The mapping holds only what the classification observed; a member that is ``None`` or not a number was
    never scored, so it neither reaches a bar nor counts as zero.
    """
    if not isinstance(measured, dict):
        return None
    values = [score for score in (_number(member) for member in measured.values()) if score is not None]
    return max(values) if values else None


def _matches(entry: dict, match: object) -> bool:
    """Whether one route's ``match`` applies: every key present must match (AND).

    A rule with no usable key never matches, so a malformed or mistyped rule cannot swallow every message.
    A message with no measured score, or with an unmeasured KEV membership, satisfies neither a numeric
    predicate nor ``kev``: the rule describes evidence the message does not have, and inventing it would
    deliver an advisory down a channel chosen for a fact nobody observed.
    """
    if not isinstance(match, dict) or not match or set(match) - MATCH_KEYS:
        return False
    if "source" in match:
        # An entry with no source id (an escalation, an Adobe bulletin) never matches a source rule.
        source_id = entry.get("source_id")
        if not isinstance(source_id, str) or source_id != match["source"]:
            return False
    if "tag" in match and entry.get("tag") != match["tag"]:
        return False
    if "product" in match and match["product"] not in _strings(entry.get("products")):
        return False
    if "ids" in match:
        pattern = str(match["ids"]).lower()
        if not any(fnmatch.fnmatchcase(identifier.lower(), pattern) for identifier in _strings(entry.get("ids"))):
            return False
    for key, field in (("min_cvss", "scores"), ("epss_gte", "epss")):
        if key in match:
            bar = _number(match[key])
            highest = _highest(entry.get(field))
            if bar is None or highest is None or highest < bar:
                return False
    # ``None`` is "membership was not measured" (the KEV catalog was unreadable), so it satisfies neither
    # ``kev: true`` nor ``kev: false`` -- as an entry written before the key existed does.
    return "kev" not in match or entry.get("kev") is match["kev"]


def select(
    entry: dict, routes: Sequence[dict], default: Sequence[str], enabled: Sequence[str]
) -> tuple[list[str], str]:
    """The notifier ids for one message, and the label the delivery log names.

    The first matching route wins, so the order in the configuration is the order of precedence. With no routes
    at all nothing changes: every enabled notifier gets the message, as before routing existed. The returned ids
    are not checked against the built notifiers here; ``core.deliver`` refuses a selection that names none of
    them, so a misconfiguration fails the pass instead of silently dropping the message.
    """
    if not routes:
        return list(enabled), "all"
    for position, route in enumerate(routes, start=1):
        if isinstance(route, dict) and _matches(entry, route.get("match")):
            return list(_strings(route.get("notifiers"))), f"route {position}"
    if default:
        return list(default), "default"
    return list(enabled), "all"
