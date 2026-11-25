"""The tests of the tests: the scripted server and the guards must be able to fail.

A suite that passes proves something only if its judge refuses what is wrong. These tests hand the
scripted server requests a correct client would never make and check that each one is refused, and they
check that the two guards of ``conftest`` really stop a connection and a real wait.
"""

from __future__ import annotations

import asyncio
import json
import socket
import time
from typing import Any

import httpx2
import pytest

from agentcompute import __version__
from contract import CONTRACT
from support import BASE_URL, CANARY_KEY, PROJECT, ROOT, SBX, SNP, Exchange, Script, ex, reply, sandbox

_HEADERS = {"Authorization": f"Bearer {CANARY_KEY}", "User-Agent": f"agent-compute-python/{__version__}"}


def _request(method: str, path: str, *, body: Any = None, base: str = BASE_URL, **headers: str) -> httpx2.Request:
    content = json.dumps(body).encode() if body is not None else None
    return httpx2.Request(method, base + path, headers={**_HEADERS, **headers}, content=content)


def _read() -> Exchange:
    return ex("GET", f"/sandboxes/{SBX}", reply(200, sandbox()))


def test_a_scripted_request_is_answered_and_recorded() -> None:
    script = Script([_read()])
    response = script.handler(_request("GET", f"{ROOT}/sandboxes/{SBX}"))
    assert response.status_code == 200
    assert response.json() == sandbox()
    assert [seen.path for seen in script.seen] == [f"{ROOT}/sandboxes/{SBX}"]
    script.finish()


def test_a_request_nobody_scripted_fails_the_test() -> None:
    script = Script([])
    with pytest.raises(AssertionError, match="unexpected request"):
        script.handler(_request("GET", f"{ROOT}/sandboxes/{SBX}"))
    with pytest.raises(AssertionError, match="unexpected request"):
        script.finish()


def test_an_exchange_never_asked_for_fails_the_test() -> None:
    script = Script([_read(), _read()])
    script.handler(_request("GET", f"{ROOT}/sandboxes/{SBX}"))
    with pytest.raises(AssertionError, match="never asked for"):
        script.finish()


def test_requests_must_arrive_in_the_scripted_order() -> None:
    script = Script([ex("GET", "/snapshots", reply(200, {"items": [], "more": False, "next_cursor": "x"})), _read()])
    with pytest.raises(AssertionError, match="expected GET"):
        script.handler(_request("GET", f"{ROOT}/sandboxes/{SBX}"))


@pytest.mark.parametrize(
    "base",
    ["https://elsewhere.example", "http://acf.test", "https://acf.test:8443", "https://acf.test.elsewhere.example"],
)
def test_a_request_to_any_other_origin_is_refused(base: str) -> None:
    script = Script([_read()])
    with pytest.raises(AssertionError, match="another origin"):
        script.handler(_request("GET", f"{ROOT}/sandboxes/{SBX}", base=base))


@pytest.mark.parametrize(
    ("headers", "message"),
    [
        ({"Authorization": "Bearer something-else"}, "did not carry the credential"),
        ({"Authorization": CANARY_KEY}, "did not carry the credential"),
        ({"User-Agent": "python-httpx2/2.16.2"}, "unexpected User-Agent"),
        ({"X-Debug": f"key={CANARY_KEY}"}, "sent in other headers"),
    ],
)
def test_a_request_that_misplaces_the_credential_or_hides_what_it_is_is_refused(
    headers: dict[str, str], message: str
) -> None:
    script = Script([_read()])
    with pytest.raises(AssertionError, match=message):
        script.handler(_request("GET", f"{ROOT}/sandboxes/{SBX}", **headers))


def test_a_credential_in_the_url_or_the_body_is_refused() -> None:
    with pytest.raises(AssertionError, match="outside the Authorization header"):
        Script([_read()]).handler(_request("GET", f"{ROOT}/sandboxes/{SBX}?token={CANARY_KEY}"))
    with pytest.raises(AssertionError, match="outside the Authorization header"):
        Script([_read()]).handler(_request("POST", f"{ROOT}/sandboxes", body={"image": CANARY_KEY}))


# ------------------------------------------------------------------------- the matching rules of the suite
def test_query_and_headers_are_matched_as_subsets_and_the_body_as_a_whole() -> None:
    expected = ex(
        "POST",
        f"/sandboxes/{SBX}/start",
        reply(200, {}),
        query={"wait": "5"},
        headers={"Idempotency-Key": "$KEY"},
        json={"expected_generation": 1},
    )
    request = _request(
        "POST", f"{ROOT}/sandboxes/{SBX}/start?wait=5", body={"expected_generation": 1}, **{"Idempotency-Key": "k-1"}
    )
    Script([expected], key="k-1").handler(request)

    wrong_query = _request(
        "POST", f"{ROOT}/sandboxes/{SBX}/start?wait=6", body={"expected_generation": 1}, **{"Idempotency-Key": "k-1"}
    )
    with pytest.raises(AssertionError, match="query wait"):
        Script([expected], key="k-1").handler(wrong_query)

    wrong_key = _request(
        "POST", f"{ROOT}/sandboxes/{SBX}/start?wait=5", body={"expected_generation": 1}, **{"Idempotency-Key": "k-2"}
    )
    with pytest.raises(AssertionError, match="header Idempotency-Key"):
        Script([expected], key="k-1").handler(wrong_key)

    wrong_body = _request(
        "POST", f"{ROOT}/sandboxes/{SBX}/start?wait=5", body={"expected_generation": 2}, **{"Idempotency-Key": "k-1"}
    )
    with pytest.raises(AssertionError, match="body"):
        Script([expected], key="k-1").handler(wrong_body)


def test_the_key_placeholder_stands_for_the_key_of_the_first_attempt_and_its_derived_keys() -> None:
    script = Script(
        [
            ex("POST", "/sandboxes", reply(200, {}), headers={"idempotency-key": "$KEY"}),
            ex("POST", f"/sandboxes/{SBX}/start", reply(200, {}), headers={"idempotency-key": "$KEY:start"}),
            ex("DELETE", f"/sandboxes/{SBX}", reply(200, {}), headers={"idempotency-key": "$KEY:destroy"}),
        ]
    )
    body = {"image": "python", "resources": {"vcpus": 1, "memory_mib": 1, "disk_mib": 1}}
    script.handler(_request("POST", f"{ROOT}/sandboxes", body=body, **{"Idempotency-Key": "generated"}))
    assert script.key == "generated"
    start = {"expected_generation": 1}
    script.handler(
        _request("POST", f"{ROOT}/sandboxes/{SBX}/start", body=start, **{"Idempotency-Key": "generated:start"})
    )
    with pytest.raises(AssertionError, match="header idempotency-key"):
        script.handler(
            _request(
                "DELETE", f"{ROOT}/sandboxes/{SBX}?expected_generation=1", **{"Idempotency-Key": "another:destroy"}
            )
        )


def test_a_fault_gives_the_client_no_response() -> None:
    with pytest.raises(httpx2.ReadError):
        Script([ex("GET", f"/sandboxes/{SBX}", {"fault": "connection_reset"})]).handler(
            _request("GET", f"{ROOT}/sandboxes/{SBX}")
        )
    with pytest.raises(httpx2.ReadTimeout):
        Script([ex("GET", f"/sandboxes/{SBX}", {"fault": "timeout"})]).handler(
            _request("GET", f"{ROOT}/sandboxes/{SBX}")
        )


# ------------------------------------------------------------------------------- the OpenAPI document as judge
_SPEC = {"image": "python", "resources": {"vcpus": 1, "memory_mib": 512, "disk_mib": 1024}}


@pytest.mark.parametrize(
    ("method", "path", "query", "key", "body", "complaint"),
    [
        ("GET", f"{ROOT}/sandboxes/{SBX}", {}, None, None, None),
        ("POST", f"{ROOT}/sandboxes", {}, "k", _SPEC, None),
        ("POST", f"{ROOT}/sandboxes", {"wait": "30"}, "k", _SPEC, None),
        ("DELETE", f"{ROOT}/sandboxes/{SBX}", {"expected_generation": "current"}, "k", None, None),
        ("DELETE", f"{ROOT}/snapshots/{SNP}", {"snapshot_generation": "3"}, "k", None, None),
        ("GET", "/v1/info", {}, None, None, None),
        ("GET", f"{ROOT}/sandbox/{SBX}", {}, None, None, "is not a route"),
        ("PUT", f"{ROOT}/sandboxes/{SBX}", {}, None, None, "is not a route"),
        ("GET", f"/v2/projects/{PROJECT}/sandboxes", {}, None, None, "is not a route"),
        ("GET", f"{ROOT}/sandboxes", {"page": "2"}, None, None, "query parameter page is not defined"),
        ("GET", f"{ROOT}/sandboxes", {"limit": "0"}, None, None, "limit='0' does not fit"),
        ("DELETE", f"{ROOT}/sandboxes/{SBX}", {}, "k", None, "expected_generation is required"),
        ("DELETE", f"{ROOT}/sandboxes/{SBX}", {"expected_generation": "latest"}, "k", None, "does not fit"),
        ("DELETE", f"{ROOT}/sandboxes/{SBX}", {"expected_generation": "0"}, "k", None, "does not fit"),
        ("POST", f"{ROOT}/sandboxes", {}, None, _SPEC, "an Idempotency-Key is required"),
        ("GET", f"{ROOT}/sandboxes", {}, "k", None, "takes no Idempotency-Key"),
        ("POST", f"{ROOT}/agent-credentials", {}, "k", {"label": "a", "lifetime_seconds": 60}, "no Idempotency-Key"),
        ("POST", f"{ROOT}/sandboxes", {}, "k", None, "a body is required"),
        ("POST", f"{ROOT}/sandboxes", {}, "k", {**_SPEC, "start": False, "cpu": 2}, "Additional properties"),
        ("POST", f"{ROOT}/sandboxes", {}, "k", {"image": "python"}, "'resources' is a required property"),
        ("POST", f"{ROOT}/sandboxes", {}, "k", {**_SPEC, "network": {"mode": "restricted"}}, "body:"),
        ("POST", f"{ROOT}/sandboxes/{SBX}/start", {}, "k", {"expected_generation": "1"}, "body:"),
        ("POST", f"{ROOT}/sandboxes/{SBX}/executions", {}, "k", {"expected_generation": 1, "argv": "ls"}, "body:"),
        ("POST", f"{ROOT}/sandboxes/{SBX}/executions", {}, "k", {"expected_generation": 1, "argv": []}, "body:"),
        ("POST", f"{ROOT}/executions/exe-1/cancel", {}, "k", {}, "takes no body"),
        ("GET", f"{ROOT}/sandboxes/{SBX}", {}, None, {"x": 1}, "takes no body"),
    ],
)
def test_the_document_accepts_the_requests_of_the_api_and_no_others(
    method: str, path: str, query: dict[str, str], key: str | None, body: Any, complaint: str | None
) -> None:
    headers = {} if key is None else {"idempotency-key": key}
    content = b"" if body is None else json.dumps(body).encode()
    problems = CONTRACT.judge(method, path, query, headers, content)
    if complaint is None:
        assert problems == []
    else:
        assert any(complaint in problem for problem in problems), problems


def test_the_scripted_server_asks_the_document_about_every_request() -> None:
    script = Script([ex("POST", "/sandboxes", reply(200, {}))])
    with pytest.raises(AssertionError, match="Additional properties"):
        script.handler(_request("POST", f"{ROOT}/sandboxes", body={**_SPEC, "cpu": 2}, **{"Idempotency-Key": "k"}))


# ------------------------------------------------------------------------------------------------ the guards
def test_no_test_can_reach_the_network() -> None:
    with socket.socket() as probe, pytest.raises(AssertionError, match="tried to reach the network"):
        probe.connect(("192.0.2.1", 443))
    with pytest.raises(AssertionError, match="tried to reach the network"):
        socket.create_connection(("192.0.2.1", 443), timeout=0.01)
    with pytest.raises(AssertionError, match="tried to reach the network"):
        socket.getaddrinfo("acf.example", 443)


def test_no_test_can_wait_in_real_time() -> None:
    with pytest.raises(AssertionError, match="tried to wait in real time"):
        time.sleep(0.01)
    with pytest.raises(AssertionError, match="tried to wait in real time"):
        asyncio.run(asyncio.sleep(0.01))


def test_a_real_http_client_cannot_slip_past_the_guard() -> None:
    with httpx2.Client(trust_env=False) as http, pytest.raises(AssertionError, match="tried to reach the network"):
        http.get("https://192.0.2.1/v1/info")
