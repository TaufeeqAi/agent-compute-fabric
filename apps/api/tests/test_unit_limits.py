"""The retry budget of the core: retries as a share of recent requests, and nothing remembered for longer.

Proves RT-4: when the budget is spent a retryable failure is surfaced instead of retried, so that the
platform cannot turn a host that sheds load into a retry storm.
"""

from __future__ import annotations

from acf_api.core.pipeline.limits import RetryBudget
from tests.support.harness import FakeClock


def test_retries_are_allowed_up_to_a_floor_and_a_share_of_recent_requests() -> None:
    clock = FakeClock()
    budget = RetryBudget(clock, ratio=0.2, floor=2, window_s=60.0)
    assert [budget.allow_retry() for _ in range(3)] == [True, True, False], "the floor, with no request at all"
    for _ in range(10):
        budget.request()
    assert [budget.allow_retry() for _ in range(3)] == [True, True, False], "a fifth of ten requests more"


def test_what_is_older_than_the_window_is_forgotten_whether_or_not_a_retry_is_ever_asked_for() -> None:
    """A host that stays reachable asks for no retry. The requests remembered must still not grow without end."""
    clock = FakeClock()
    budget = RetryBudget(clock, ratio=0.2, floor=2, window_s=60.0)
    for _ in range(50_000):
        budget.request()
        clock.advance(0.5)
    assert len(budget._requests) <= 121, "two requests a second for a window of sixty"
    assert len(budget._retries) == 0


def test_a_spent_budget_comes_back_as_time_passes() -> None:
    clock = FakeClock()
    budget = RetryBudget(clock, ratio=0.0, floor=1, window_s=60.0)
    assert budget.allow_retry() is True
    assert budget.allow_retry() is False
    clock.advance(59.0)
    assert budget.allow_retry() is False
    clock.advance(2.0)
    assert budget.allow_retry() is True
