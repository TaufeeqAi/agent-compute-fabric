"""Listings: cursors followed to the end, and a fresh start when a cursor expires.

A listing is collected as one complete pass before the first item is handed out. That is what makes the
restart safe: a pass that ends in ``CURSOR_EXPIRED`` is thrown away whole, so the caller never sees an
item of an abandoned pass next to the same item of the next one.
"""

from __future__ import annotations

from typing import Any

import pytest

from agentcompute import AsyncFabric, CursorExpiredError, Fabric, ServiceUnavailableError, UnexpectedResponseError
from support import (
    OP,
    OP2,
    SBX,
    SBX2,
    SNP,
    SNP2,
    Exchange,
    Harness,
    Json,
    ex,
    operation,
    page,
    refusal,
    reply,
    sandbox,
    snapshot,
)

_SBX3 = "sbx-" + "0" * 31 + "3"


def _page(cursor: str | None, response: Json) -> Exchange:
    if cursor is None:
        return ex("GET", "/sandboxes", response, absent_query=["cursor", "limit"])
    return ex("GET", "/sandboxes", response, query={"cursor": cursor})


def _ids(harness: Harness, fabric: Fabric | AsyncFabric) -> list[str]:
    return [item.sandbox_id for item in harness.collect(fabric.sandboxes.list())]


def test_a_listing_of_one_page_makes_one_request(harness: Harness) -> None:
    script = harness.script(_page(None, reply(200, page([sandbox(), sandbox(sandbox_id=SBX2)]))))
    assert _ids(harness, harness.client(script)) == [SBX, SBX2]


def test_an_empty_listing_is_empty(harness: Harness) -> None:
    script = harness.script(_page(None, reply(200, page([]))))
    assert _ids(harness, harness.client(script)) == []


def test_cursors_are_followed_to_the_end_in_order(harness: Harness) -> None:
    script = harness.script(
        _page(None, reply(200, page([sandbox()], more=True, cursor="c1"))),
        _page("c1", reply(200, page([], more=True, cursor="c2"))),  # an empty page is not the end
        _page("c2", reply(200, page([sandbox(sandbox_id=SBX2)], more=True, cursor="c 3&x=y"))),
        _page("c 3&x=y", reply(200, page([sandbox(sandbox_id=_SBX3)], more=False, cursor="c4"))),
    )
    assert _ids(harness, harness.client(script)) == [SBX, SBX2, _SBX3]


def test_every_item_carries_the_request_id_of_its_page_and_its_raw_view(harness: Harness) -> None:
    first = reply(200, page([sandbox(name="a")], more=True, cursor="c1"))
    first["headers"]["x-request-id"] = "req_page_1"
    second = reply(200, page([sandbox(sandbox_id=SBX2)]))
    second["headers"]["x-request-id"] = "req_page_2"
    script = harness.script(_page(None, first), _page("c1", second))
    items = harness.collect(harness.client(script).sandboxes.list())
    assert [item.request_id for item in items] == ["req_page_1", "req_page_2"]
    assert items[0].raw == sandbox(name="a")
    assert items[0].operation is None


def test_an_expired_cursor_starts_the_listing_again_and_yields_each_item_once(harness: Harness) -> None:
    script = harness.script(
        _page(None, reply(200, page([sandbox()], more=True, cursor="c1"))),
        _page("c1", refusal("CURSOR_EXPIRED")),
        _page(None, reply(200, page([sandbox(), sandbox(sandbox_id=SBX2)], more=True, cursor="d1"))),
        _page("d1", reply(200, page([sandbox(sandbox_id=_SBX3)]))),
    )
    # The first sandbox was on the abandoned pass and on the complete one: it is yielded once.
    assert _ids(harness, harness.client(script)) == [SBX, SBX2, _SBX3]
    assert harness.clock.slept == []


def test_the_listing_is_started_again_at_most_three_times(harness: Harness) -> None:
    abandoned = [
        _page(None, reply(200, page([sandbox()], more=True, cursor="c1"))),
        _page("c1", refusal("CURSOR_EXPIRED")),
    ]
    script = harness.script(*abandoned * 3, _page(None, reply(200, page([sandbox(sandbox_id=SBX2)]))))
    assert _ids(harness, harness.client(script)) == [SBX2]
    assert len(script.seen) == 7


def test_the_fourth_expired_cursor_is_surfaced(harness: Harness) -> None:
    abandoned = [
        _page(None, reply(200, page([sandbox()], more=True, cursor="c1"))),
        _page("c1", refusal("CURSOR_EXPIRED")),
    ]
    script = harness.script(*abandoned * 4)
    with pytest.raises(CursorExpiredError) as raised:
        _ids(harness, harness.client(script))
    assert raised.value.retry == "AFTER_CHANGE"
    assert len(script.seen) == 8


def test_an_expired_cursor_on_the_first_page_also_starts_again(harness: Harness) -> None:
    script = harness.script(_page(None, refusal("CURSOR_EXPIRED")), _page(None, reply(200, page([sandbox()]))))
    assert _ids(harness, harness.client(script)) == [SBX]


def test_a_page_is_retried_like_any_read_without_starting_the_listing_again(harness: Harness) -> None:
    script = harness.script(
        _page(None, reply(200, page([sandbox()], more=True, cursor="c1"))),
        _page("c1", refusal("UPSTREAM_UNAVAILABLE", retry_after=1)),
        _page("c1", {"fault": "connection_reset"}),
        _page("c1", reply(200, page([sandbox(sandbox_id=SBX2)]))),
    )
    assert _ids(harness, harness.client(script)) == [SBX, SBX2]


def test_a_page_that_cannot_be_read_ends_the_listing_with_its_error_and_no_items(harness: Harness) -> None:
    script = harness.script(
        _page(None, reply(200, page([sandbox()], more=True, cursor="c1"))),
        *[_page("c1", refusal("UPSTREAM_UNAVAILABLE", retry_after=1))] * 3,
    )
    fabric = harness.client(script)
    yielded: list[Any] = []
    with pytest.raises(ServiceUnavailableError):
        yielded.extend(harness.collect(fabric.sandboxes.list()))
    assert yielded == []


@pytest.mark.parametrize(
    "broken",
    [
        {"more": True, "items": []},  # more, and no cursor to continue with
        {"more": True, "next_cursor": "", "items": []},
        {"more": True, "next_cursor": 7, "items": []},
        {"next_cursor": "c1", "items": []},  # does not say whether there is more
        {"more": "yes", "next_cursor": "c1", "items": []},
        {"more": False, "next_cursor": "c1"},  # no items
        {"more": False, "next_cursor": "c1", "items": {"a": 1}},
        {"more": False, "next_cursor": "c1", "items": ["sbx-1"]},
    ],
)
def test_a_page_that_is_not_a_page_of_this_api_is_unexpected(harness: Harness, broken: Json) -> None:
    script = harness.script(_page(None, reply(200, broken)))
    with pytest.raises(UnexpectedResponseError):
        _ids(harness, harness.client(script))


@pytest.mark.parametrize("repeated", ["c1", "c2"])
def test_a_cursor_that_was_already_followed_ends_the_listing_instead_of_looping(
    harness: Harness, repeated: str
) -> None:
    script = harness.script(
        _page(None, reply(200, page([sandbox()], more=True, cursor="c1"))),
        _page("c1", reply(200, page([sandbox(sandbox_id=SBX2)], more=True, cursor="c2"))),
        _page("c2", reply(200, page([], more=True, cursor=repeated))),
    )
    with pytest.raises(UnexpectedResponseError, match="does not say where the listing continues"):
        _ids(harness, harness.client(script))


def test_snapshots_and_operations_are_listed_by_the_same_rules(harness: Harness) -> None:
    script = harness.script(
        ex("GET", "/snapshots", reply(200, page([snapshot()], more=True, cursor="s1"))),
        ex("GET", "/snapshots", refusal("CURSOR_EXPIRED"), query={"cursor": "s1"}),
        ex("GET", "/snapshots", reply(200, page([snapshot(), snapshot(snapshot_id=SNP2)]))),
        ex("GET", "/operations", reply(200, page([operation()], more=True, cursor="o1"))),
        ex("GET", "/operations", reply(200, page([operation(operation_id=OP2)])), query={"cursor": "o1"}),
    )
    fabric = harness.client(script)
    assert [item.snapshot_id for item in harness.collect(fabric.snapshots.list())] == [SNP, SNP2]
    assert [item.operation_id for item in harness.collect(fabric.operations.list())] == [OP, OP2]


def test_a_listing_makes_no_request_until_it_is_iterated(harness: Harness) -> None:
    script = harness.script(_page(None, reply(200, page([sandbox()]))))
    fabric = harness.client(script)
    listing = fabric.sandboxes.list()
    assert script.seen == []
    assert len(harness.collect(listing)) == 1
