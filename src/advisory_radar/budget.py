"""The wall-clock budget of one pass, and the ``Http`` that spends it.

A pass holds the state lock while it waits on other people's servers. ``HTTP_DEADLINE`` bounds one request, not the
pass, so a few slow publishers could hold the lock, and with it every administrative action, for as long as they
liked. The budget bounds the whole upstream part of a pass: a request never outlives what is left, and once nothing is
left the remaining work is deferred, never dropped (``pipeline`` records what, and the next pass starts with it).

The budget is divided into stages that each have to end by a share of it, so that one slow part cannot spend what the
parts after it need. The first stage holds the KEV catalogue, one request that comes before the work it shares the stage
with, so the catalogue has a share of the stage of its own (``KEV_SHARE``). Delivery is not upstream work. It never goes
through this module: ``pipeline`` hands it the plain ``Http``, so a spent budget cannot hold back a message that is
already queued.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable, Iterator, Mapping

from .http import Http, request_ceiling

DEFAULT_PASS_BUDGET_SECONDS = 600
#: The smallest budget a configuration may name, and the largest. Below a minute the first stage, which holds the
#: catalogue download, would be shorter than 12 seconds; above an hour the budget stops bounding anything a scheduler
#: would wait for.
MIN_PASS_BUDGET_SECONDS = 60
MAX_PASS_BUDGET_SECONDS = 3600

#: The share of the budget by which each stage must have ended. Re-evaluation and the catalogue come first and may
#: not spend more than a fifth, the source fetches may run until three quarters, and classifying what was fetched
#: keeps the last quarter: a slow source can never leave the candidates it already captured without a lookup.
REFRESH_STAGE = 0.2
FETCH_STAGE = 0.75
CLASSIFY_STAGE = 1.0
#: The share of what the first stage has left, when its request starts, that the KEV catalogue may spend. It is one
#: request at the head of the stage, so a response that trickles in could take the whole stage (120 s at the default
#: budget, which is also the longest one request may take) on every pass, and the re-scores and the drain behind it
#: would never begin. What it leaves is theirs.
KEV_SHARE = 0.5


class PassBudget:
    """The seconds one pass may spend waiting on upstream servers, counted from the pass's start."""

    def __init__(self, seconds: float, monotonic: Callable[[], float] = time.monotonic) -> None:
        self.seconds = seconds
        self._monotonic = monotonic
        self._start = monotonic()

    def remaining(self, stage: float = CLASSIFY_STAGE) -> float:
        """The seconds before ``stage`` (a share of the budget) is over; zero or less once it is."""
        return self._start + self.seconds * stage - self._monotonic()


class BudgetedHttp:
    """An ``Http`` that refuses a request once the current stage is over and cuts one short at the stage's end.

    The pipeline moves ``stage`` forward as the pass advances. A refused or cut request answers status 0, the
    answer for any network error, so a consumer that tolerates a down server tolerates this; ``refused`` counts them
    so the pipeline can tell a source the budget interrupted from a source that failed.
    """

    def __init__(self, http: Http, budget: PassBudget, stage: float = REFRESH_STAGE) -> None:
        self._http = http
        self._budget = budget
        self.stage = stage
        self.refused = 0

    def remaining(self) -> float:
        return self._budget.remaining(self.stage)

    def expired(self) -> bool:
        return self.remaining() <= 0

    @contextlib.contextmanager
    def at_most(self, share: float) -> Iterator[None]:
        """Cut every request made inside the block at ``share`` of what the stage has left as the block starts.

        That is one instant for all of its requests, not a share of what is left as each one starts, and the stage's
        own end still applies: a share of nothing is nothing, so a stage that is over stays over. A request the block
        cuts is cut like one the stage cuts, with status 0, and it counts in ``refused``.
        """
        stage = self.stage
        self.stage = stage - self._budget.remaining(stage) * (1 - share) / self._budget.seconds
        try:
            yield
        finally:
            self.stage = stage

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> tuple[int, dict[str, str], bytes]:
        if self.expired():
            self.refused += 1
            return 0, {}, b""
        with request_ceiling(self.remaining):
            result = self._http(method, url, headers, body)
        if result[0] == 0 and self.expired():
            self.refused += 1  # the ceiling ended it, or it failed as time ran out: either way the budget decided
        return result
