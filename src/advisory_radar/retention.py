"""Delivery history older than two years leaves the live state for a dated archive file.

The state document is written whole by every save, and a pass saves it after each source, before delivery, after each
delivered message and at the end, so whatever grows in it is paid for many times per pass. What grows without bound is
the delivery history: one snapshot per delivered message, kept so that a page can show what was sent. After two years
the pages are the only readers of that history, so a pass moves it to a file that no pass reads again.

The seen set stays. It is the deduplication: ``core._claimed`` asks it, and only it, whether an identifier was ever
reported, and an identifier that no record claims is news unless its publication date makes it backlog
(``core._is_history``). An undated item, an item whose date was changed, and a new bulletin that names an old CVE all
reach the classifier with no date that says "old", so a seen record that was dropped would report them again. A seen
record is one short entry; the snapshot it points at is the heavy part. Only snapshots move, and a seen record whose
snapshot moved keeps its ``delivery`` pointer, which every page already tolerates.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from pathlib import Path

from .core import DAY
from .state import save_json, serialize_json

LOG = logging.getLogger("advisory_radar")

#: Two years, as 730 days. A delivery snapshot whose ``at`` is older moves to the archive.
RETENTION_SECONDS = 730 * DAY
ARCHIVE_SCHEMA = "advisory-radar-archive.v1"
#: ``state-archive-<UTC day>-<digest>.json``, beside the state path. The day is the retention line the file was cut
#: at, so one day's expiry is one file; the digest is of its content, so a retry on the same day finds its file.
ARCHIVE_PREFIX = "state-archive-"


def _is_old(snapshot: object, before: int) -> bool:
    """True for a snapshot with a real time that lies before the line; one with no usable time is never old."""
    if not isinstance(snapshot, dict):
        return False
    at = snapshot.get("at")
    return isinstance(at, int) and not isinstance(at, bool) and 0 < at < before


def retire_deliveries(state: dict, state_path: Path, now: int) -> int:
    """Move delivery snapshots older than two years into an archive file and return how many moved.

    The line is the start of the UTC day two years back, not the instant: a pass that runs every few minutes then
    finds something to move once a day, not once a pass, and one day's expiry is one file.

    The records leave ``state`` only after the archive file is on disk (written like the state: a temporary file,
    synced, renamed, then the directory synced), and they leave the document on disk with the next save. A pass that
    dies in between finds the same records again and archives them again; the file name carries a digest of its
    content, so a second attempt at the same records on the same UTC day finds its file and writes nothing. After
    midnight the day in the name changes and a retry may write a second file with the same records. An archive that
    cannot be written is logged and the records stay where they are: retention never fails a pass.

    Nothing reads an archive file back, and nothing here looks inside an existing one: a name that is already there
    holds the same records, because the rename that created it was atomic.
    """
    deliveries = state.get("deliveries")
    if not isinstance(deliveries, dict):
        return 0
    before = (now - RETENTION_SECONDS) // DAY * DAY
    old = {key: snapshot for key, snapshot in deliveries.items() if _is_old(snapshot, before)}
    if not old:
        return 0
    digest = hashlib.sha256(serialize_json(old, compact=True).encode("utf-8")).hexdigest()[:12]
    day = time.strftime("%Y-%m-%d", time.gmtime(before))
    path = state_path.parent / f"{ARCHIVE_PREFIX}{day}-{digest}.json"
    if not os.path.lexists(path):
        document = {"schema": ARCHIVE_SCHEMA, "archived_at": now, "before": before, "deliveries": old}
        try:
            save_json(path, document, compact=True)
        except OSError as exc:
            LOG.warning(
                "could not archive %d delivery record(s) older than two years to %s: %s; they stay in the state",
                len(old),
                path,
                exc,
            )
            return 0
    for key in old:
        del deliveries[key]
    LOG.info("archived %d delivery record(s) older than two years to %s", len(old), path)
    return len(old)
