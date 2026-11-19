"""Version comparison for the package ecosystems an inventory is judged in.

Two schemes, because that is what the supported ecosystems publish: semantic versioning (npm, Go modules,
crates.io) and PEP 440 (PyPI). Every other ecosystem is unsupported on purpose. A wrong order becomes a wrong
"not affected", so a version that does not parse completely, or an ecosystem with no comparator here, answers
``None`` ("cannot tell"), never a guess and never a plain string comparison.

The range logic follows the OSV schema: a range is a list of ``introduced``, ``fixed`` and ``last_affected``
events, read in version order. ``GIT`` ranges name commits, not versions, and are never evaluated. A range that
introduces no version (an empty list, or only fixes) is unreadable too: it never says which versions are affected,
so it can never say that one is not. So is a listed affected version that does not parse: it may be the installed
one, in a spelling no comparator here reads.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

#: The OSV ecosystem names this module can compare, and the scheme each one uses.
SUPPORTED_ECOSYSTEMS = ("npm", "Go", "crates.io", "PyPI")

_SEMVER = re.compile(
    r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_PEP440 = re.compile(
    r"""
    v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_label>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_number>[0-9]+)?)?
    (?P<post>-(?P<post_implicit>[0-9]+)|[-_.]?(?P<post_label>post|rev|r)[-_.]?(?P<post_number>[0-9]+)?)?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_number>[0-9]+)?)?
    """,
    re.VERBOSE | re.IGNORECASE,
)
#: The longest version this module parses; a hostile value cannot make a regular expression or a tuple large.
MAX_VERSION_CHARS = 128
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
#: Sorts before every real version key: the OSV ``introduced: "0"`` event.
_FLOOR: tuple = ()

Key = tuple


def semver_key(version: str) -> Key | None:
    """A sortable key for a semantic version, or ``None`` when ``version`` is not one (build metadata is ignored)."""
    match = _SEMVER.fullmatch(version)
    if match is None:
        return None
    major, minor, patch, pre = match.groups()
    if pre is None:
        return (int(major), int(minor), int(patch), (1,))  # a release sorts after any of its pre-releases
    parts = []
    for part in pre.split("."):
        if part.isdigit():
            if len(part) > 1 and part.startswith("0"):
                return None  # a numeric pre-release identifier may not carry a leading zero
            parts.append((0, int(part)))  # numeric identifiers sort before alphanumeric ones
        else:
            parts.append((1, part))
    return (int(major), int(minor), int(patch), (0, *parts))


def pep440_key(version: str) -> Key | None:
    """A sortable key for a PEP 440 version, or ``None``. A local version (``+cpu``) is not compared."""
    match = _PEP440.fullmatch(version.strip())
    if match is None:
        return None
    release = [int(part) for part in match["release"].split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()  # 1.0 and 1.0.0 are one version
    pre_label = match["pre_label"]
    pre = (1, _PRE_RANK[pre_label.lower()], int(match["pre_number"] or 0)) if pre_label else None
    post = None
    if match["post"]:
        number = match["post_implicit"] or match["post_number"]
        post = (1, int(number or 0))
    dev = (0, int(match["dev_number"] or 0)) if match["dev"] else (1,)
    if pre is None and post is None and match["dev"]:
        pre = (0,)  # a bare dev release sorts before the pre-releases of its own release
    elif pre is None:
        pre = (2,)
    return (int(match["epoch"] or 0), tuple(release), pre, post or (0,), dev)


_SCHEMES: dict[str, Callable[[str], Key | None]] = {
    "npm": semver_key,
    "Go": semver_key,
    "crates.io": semver_key,
    "PyPI": pep440_key,
}


def version_key(ecosystem: str, version: str) -> Key | None:
    """The key ``version`` sorts by in ``ecosystem``, or ``None`` when the ecosystem or the version is unsupported."""
    scheme = _SCHEMES.get(ecosystem)
    if scheme is None or not isinstance(version, str) or not version or len(version) > MAX_VERSION_CHARS:
        return None
    return scheme(version)


@dataclass(frozen=True)
class RangeVerdict:
    """Whether a version is inside the affected ranges: ``True``, ``False`` or ``None`` (cannot tell).

    ``fixed`` is the fix that bounds the verdict when the record names one: for an affected version the first
    fix above it, for an unaffected one the latest fix at or below it.
    """

    affected: bool | None
    fixed: str = ""


def has_introduced(events: object) -> bool:
    """Whether ``events`` is a list of events that names at least one ``introduced`` event.

    The OSV schema requires at least one in every range. A range without it (an empty list, or only fixes) says
    where an affected span ends but never where one begins, so no version can be called outside it.
    """
    return (
        isinstance(events, Sequence)
        and not isinstance(events, str)
        and any(isinstance(event, Mapping) and "introduced" in event for event in events)
    )


def _events(ecosystem: str, events: object) -> list[tuple[Key, str, str]] | None:
    """The events of one range as ``(key, kind, version)`` in version order, or ``None`` when any is unreadable.

    An event that names none of the three kinds read here, and a ``limit`` event (a git-range bound), make the
    whole range unreadable: ignoring either could turn an unknown into a confident answer. So does a range that
    introduces no version (:func:`has_introduced`): "outside" it would be a guess from no data.
    """
    if not has_introduced(events):
        return None
    ordered: list[tuple[Key, str, str]] = []
    for event in events:
        if not isinstance(event, Mapping) or "limit" in event:
            return None
        kinds = [kind for kind in ("introduced", "fixed", "last_affected") if kind in event]
        if not kinds:
            return None
        for kind in kinds:
            version = event[kind]
            if not isinstance(version, str):
                return None
            key = _FLOOR if kind == "introduced" and version == "0" else version_key(ecosystem, version)
            if key is None:
                return None
            ordered.append((key, kind, version))
    return sorted(ordered, key=lambda event: event[0])  # stable: events with one version keep their order


def _in_events(key: Key, events: list[tuple[Key, str, str]]) -> bool:
    affected = False
    for bound, kind, _ in events:
        if kind == "introduced":
            if key >= bound:
                affected = True
        elif kind == "fixed":
            if key >= bound:
                affected = False
        elif key > bound:  # last_affected: the named version is itself affected
            affected = False
    return affected


def evaluate(
    ecosystem: str,
    version: str,
    ranges: Sequence[Mapping] = (),
    versions: Sequence[str] = (),
) -> RangeVerdict:
    """Judge one installed ``version`` against one OSV ``affected`` entry's ``ranges`` and ``versions``.

    Affected as soon as any range, or the explicit version list, says so. Unaffected only when every range and
    every listed version could be read and none applies. A range that cannot be read (a ``GIT`` range, an
    unparseable event, no ``introduced`` event), a listed version that cannot be read (text that is no version, or
    not text at all: it may be the installed one), an unparseable installed version and an entry that says nothing
    at all are all ``None``.
    """
    key = version_key(ecosystem, version)
    if key is None:
        return RangeVerdict(None)
    listed = [version_key(ecosystem, item) for item in versions]
    if key in listed:
        return RangeVerdict(True)
    undecided = None in listed  # a listed version no comparator reads may be the installed one
    fixes: list[tuple[Key, str]] = []
    for entry in ranges:
        events = _events(ecosystem, entry.get("events")) if isinstance(entry, Mapping) else None
        if events is None or entry.get("type") not in ("SEMVER", "ECOSYSTEM"):
            undecided = True
            continue
        if _in_events(key, events):
            above = [fix for fix in events if fix[1] == "fixed" and fix[0] > key]
            return RangeVerdict(True, above[0][2] if above else "")
        fixes += [(fix[0], fix[2]) for fix in events if fix[1] == "fixed" and fix[0] != _FLOOR and fix[0] <= key]
    if undecided or not (ranges or versions):
        return RangeVerdict(None)
    return RangeVerdict(False, max(fixes)[1] if fixes else "")
