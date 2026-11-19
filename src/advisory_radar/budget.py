"""The wall-clock budget of one pass, and the ``Http`` that spends it.

A pass holds the state lock while it waits on other people's servers. ``HTTP_DEADLINE`` bounds one request, not the
pass, so a few slow publishers could hold the lock, and with it every administrative action, for as long as they
liked. The budget bounds the whole upstream part of a pass: a request never outlives what is left, and once nothing is
left the remaining work is deferred, never dropped (``pipeline`` records what, and the next pass starts with it).

The budget is divided into stages that each have to end by a share of it, so that one slow part cannot spend what the
parts after it need. Delivery is not upstream work. It never goes through this module: ``pipeline`` hands it the plain
``Http``, so a spent budget cannot hold back a message that is already queued.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping

from .http import Http, request_ceiling

DEFAULT_PASS_BUDGET_SECONDS = 600
#: The smallest budget a configuration may name, and the largest. Below a minute the catalogue download alone
#: could spend it; above an hour the budget stops bounding anything a scheduler would wait for.
MIN_PASS_BUDGET_SECONDS = 60
MAX_PASS_BUDGET_SECONDS = 3600

#: The share of the budget by which each stage must have ended. Re-evaluation and the catalogue come first and may
#: not spend more than a fifth, the source fetches may run until three quarters, and classifying what was fetched
#: keeps the last quarter: a slow source can never leave the candidates it already captured without a lookup.
REFRESH_STAGE = 0.2
FETCH_STAGE = 0.75
CLASSIFY_STAGE = 1.0


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
