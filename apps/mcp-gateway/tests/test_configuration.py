"""What the adapter takes from an edge configuration, what it refuses to start with, and how it listens."""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx2
import pytest
import uvicorn

from acf_api.command.client import SocketCoreClient
from acf_api.edge.config import EXIT_CONFIG, EdgeConfig, EdgeConfigError, parse_edge_config
from acf_mcp import __version__, cli, server
from acf_mcp.gateway import ConfigurationError, Gateway, Settings, create_app
from acf_mcp.metadata import metadata_document, metadata_path
from tests.support import FakeCore, edge_config, headers, rpc, running

OAUTH: dict[str, Any] = {
    "resource": "https://mcp.example.com/mcp",
    "authorization_servers": ["https://login.example.com", "https://sso.example.org/tenant"],
    "scopes_supported": ["acf:sandbox.read", "acf:sandbox.exec"],
}


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "edge.yaml"
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------- what it refuses to start with
def test_the_earlier_revision_is_not_implemented_and_the_adapter_says_so(core: FakeCore) -> None:
    """Off by default. Turned on, the adapter refuses to start rather than serve something it does not have."""
    assert edge_config().mcp.serve_2025_11_25 is False
    with pytest.raises(ConfigurationError) as refused:
        create_app(core, edge_config(mcp={"serve_2025_11_25": True}))
    message = str(refused.value)
    assert "mcp.serve_2025_11_25" in message
    assert "2025-11-25" in message
    assert "not implemented in this build" in message
    assert "Set it to false" in message


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10", "mcp.example.com"])  # noqa: S104 - what must be refused
def test_without_tls_it_listens_on_loopback_only(core: FakeCore, host: str) -> None:
    """The configuration loader refuses this already. The adapter does not rely on having been given a loaded one."""
    document = {"schema_version": 1, "command_socket": "/run/acf/core.sock", "listen": {"host": host}}
    with pytest.raises(EdgeConfigError, match="loopback"):
        parse_edge_config(document)
    with pytest.raises(ConfigurationError, match="loopback address only"):
        create_app(core, EdgeConfig.model_validate(document))


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "localhost"])
def test_a_loopback_address_needs_no_tls(core: FakeCore, host: str) -> None:
    app = create_app(core, edge_config(listen={"host": host}))
    assert server.server_config(app, edge_config(listen={"host": host})).host == host


def test_with_tls_it_may_listen_anywhere(core: FakeCore, tmp_path: Path) -> None:
    tls = {"certificate": str(tmp_path / "edge.crt"), "private_key": str(tmp_path / "edge.key")}
    config = edge_config(listen={"host": "0.0.0.0", "port": 443}, tls=tls, mcp={"allowed_hosts": ["mcp.example.com"]})  # noqa: S104
    settings = server.server_config(create_app(core, config), config)
    assert (settings.host, settings.port) == ("0.0.0.0", 443)  # noqa: S104
    assert settings.ssl_certfile == tls["certificate"]
    assert settings.ssl_keyfile == tls["private_key"]


def test_a_wait_longer_than_a_command_can_carry_is_refused(core: FakeCore) -> None:
    with pytest.raises(ConfigurationError, match=r"mcp\.tool_wait plus limits\.edge_core_deadline_margin"):
        create_app(core, edge_config(mcp={"tool_wait": 3600}, limits={"edge_core_deadline_margin": 1}))


@pytest.mark.parametrize(
    ("tool_wait", "margin", "budget_ms"), [(25.0, 2.0, 27_000), (0, 0.0004, 1), (3599, 1, 3_600_000), (0.5, 0.25, 750)]
)
def test_the_budget_of_a_command_is_the_tool_wait_and_the_margin(
    core: FakeCore, tool_wait: float, margin: float, budget_ms: int
) -> None:
    config = edge_config(mcp={"tool_wait": tool_wait}, limits={"edge_core_deadline_margin": margin})
    assert create_app(core, config).settings.budget_ms == budget_ms


def test_a_resource_without_an_authorization_server_is_refused(core: FakeCore) -> None:
    with pytest.raises(ConfigurationError, match=r"mcp\.authorization_servers is empty"):
        create_app(core, edge_config(mcp={"resource": "https://mcp.example.com/mcp"}))


@pytest.mark.parametrize(
    "entry", ["https://mcp.example.com", "mcp.example.com/mcp", "a b", "host:port", "host:123456", ""]
)
def test_an_entry_that_is_not_a_host_is_refused(core: FakeCore, entry: str) -> None:
    with pytest.raises(ConfigurationError, match="not a host"):
        create_app(core, edge_config(mcp={"allowed_hosts": [entry]}))


def test_what_is_kept_from_a_default_configuration() -> None:
    assert Settings.from_config(edge_config()) == Settings(
        path="/mcp",
        max_body_bytes=1024 * 1024,
        body_read_timeout=20.0,
        budget_ms=27_000,
        hosts=frozenset({"127.0.0.1", "localhost"}),
        hosts_with_port=frozenset(),
        origins=frozenset(),
        metadata=None,
    )


def test_an_ipv6_listen_address_is_answered_in_the_form_a_host_header_has() -> None:
    assert Settings.from_config(edge_config(listen={"host": "::1"})).hosts == frozenset({"[::1]", "localhost"})


# ---------------------------------------------------------------------------- how it listens
def test_the_server_carries_the_transport_bounds(core: FakeCore) -> None:
    config = edge_config(
        listen={"host": "127.0.0.1", "port": 9443},
        limits={"edge_max_connections": 77, "edge_max_header_bytes": 4096, "keep_alive_timeout": 9},
        log_level="WARNING",
    )
    app = create_app(core, config)
    settings = server.server_config(app, config)
    assert settings.app is app
    assert (settings.host, settings.port) == ("127.0.0.1", 9443)
    assert settings.limit_concurrency == 77
    assert settings.h11_max_incomplete_event_size == 4096
    assert settings.timeout_keep_alive == 9
    assert settings.http == "h11"
    assert settings.ws == "none"
    assert settings.lifespan == "on"
    assert settings.log_level == "warning"
    # Nothing about the software is told to a caller, no request line is logged, and no forwarded header is believed.
    assert settings.server_header is False
    assert settings.access_log is False
    assert settings.proxy_headers is False
    assert settings.ssl_certfile is None


def test_the_process_talks_to_the_core_over_its_command_socket_and_nothing_else() -> None:
    config = edge_config(
        command_socket="/run/acf/core.sock",
        limits={"edge_max_commands_in_flight": 40, "max_public_request_bytes": 2048},
    )
    app = server.build_app(config)
    core = app._core
    assert isinstance(core, SocketCoreClient)
    assert core._path == "/run/acf/core.sock"
    assert core._max_in_flight == 40
    assert core._max_request_frame == 2 * 2048 + 64 * 1024
    assert app.settings.max_body_bytes == 2048


# ---------------------------------------------------------------------------- the command
def test_the_command_serves_a_valid_configuration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    served: list[uvicorn.Config] = []
    monkeypatch.setattr(uvicorn.Server, "run", lambda self: served.append(self.config))
    path = write(
        tmp_path, "schema_version: 1\ncommand_socket: /run/acf/core.sock\nlisten: {port: 9100}\nmcp: {path: /agents}\n"
    )
    assert cli.main(["--config", str(path)]) == 0
    (config,) = served
    assert (config.host, config.port) == ("127.0.0.1", 9100)
    assert isinstance(config.app, Gateway)
    assert config.app.settings.path == "/agents"


@pytest.mark.parametrize(
    ("text", "said"),
    [
        (
            "schema_version: 1\ncommand_socket: /run/acf/core.sock\nmcp: {serve_2025_11_25: true}\n",
            "not implemented in this build",
        ),
        ("schema_version: 1\ncommand_socket: /run/acf/core.sock\nlisten: {host: 0.0.0.0}\n", "loopback"),
        ("schema_version: 1\ncommand_socket: /run/acf/core.sock\nmcp: {scopes: {exec: admin}}\n", "mcp.scopes"),
        ("schema_version: 1\n", "command_socket"),
        (": not yaml: [", "not valid YAML"),
    ],
)
def test_the_command_refuses_a_configuration_it_cannot_serve_and_says_why(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, text: str, said: str
) -> None:
    monkeypatch.setattr(uvicorn.Server, "run", lambda self: pytest.fail("the server was started"))
    with caplog.at_level(logging.ERROR, logger="acf_mcp"):
        assert cli.main(["--config", str(write(tmp_path, text))]) == EXIT_CONFIG
    (record,) = caplog.records
    assert said in record.getMessage()


def test_the_command_refuses_a_file_that_is_not_there(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR, logger="acf_mcp"):
        assert cli.main(["--config", str(tmp_path / "missing.yaml")]) == EXIT_CONFIG
    assert "cannot read" in caplog.records[0].getMessage()


def test_the_process_does_not_run_as_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(uvicorn.Server, "run", lambda self: pytest.fail("the server was started"))
    path = write(tmp_path, "schema_version: 1\ncommand_socket: /run/acf/core.sock\n")
    with caplog.at_level(logging.ERROR, logger="acf_mcp"):
        assert cli.main(["--config", str(path)]) == EXIT_CONFIG
    assert "must not run as root" in caplog.records[0].getMessage()


def test_a_refused_start_exits_with_the_status_the_units_do_not_restart_on() -> None:
    """Both edge programs share it; the unit that starts this one lists it under RestartPreventExitStatus."""
    assert EXIT_CONFIG == 78
    unit = Path(__file__).resolve().parents[3] / "deploy" / "platform" / "systemd" / "acf-platform-mcp.service"
    prevented = [
        line for line in unit.read_text(encoding="utf-8").splitlines() if line.startswith("RestartPreventExitStatus=")
    ]
    assert len(prevented) == 1
    assert str(EXIT_CONFIG) in prevented[0].partition("=")[2].split()


def test_the_command_says_its_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        cli.main(["--version"])
    assert stopped.value.code == 0
    assert capsys.readouterr().out.strip() == f"acf-mcp {__version__}"


def test_the_command_needs_a_configuration(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        cli.main([])
    assert stopped.value.code == 2
    assert "--config" in capsys.readouterr().err


# ---------------------------------------------------------------------------- protected-resource metadata
RESOURCES = [
    ("https://mcp.example.com/mcp", "/.well-known/oauth-protected-resource/mcp"),
    ("https://mcp.example.com", "/.well-known/oauth-protected-resource"),
    ("https://mcp.example.com/", "/.well-known/oauth-protected-resource"),
    ("https://mcp.example.com:8443/agents/v1", "/.well-known/oauth-protected-resource/agents/v1"),
    ("https://mcp.example.com/mcp/", "/.well-known/oauth-protected-resource/mcp/"),
    ("https://MCP.Example.com/Mcp", "/.well-known/oauth-protected-resource/Mcp"),
]


@pytest.mark.parametrize(("resource", "path"), RESOURCES)
def test_the_document_is_published_between_the_authority_and_the_path(resource: str, path: str) -> None:
    assert metadata_path(resource) == path


def test_the_rule_is_the_one_the_core_writes_into_its_challenges() -> None:
    """Two processes compute this address: the core names it, and this one serves it. They must agree.

    The core's rule is asked of the core's code in a process of its own, so that this one never loads it.
    """
    script = (
        "import json, sys\n"
        "from acf_api.core.app import resource_metadata_url\n"
        "print(json.dumps([resource_metadata_url(r) for r in json.loads(sys.argv[1])]))\n"
    )
    resources = [resource for resource, _ in RESOURCES]
    completed = subprocess.run(  # noqa: S603 - the interpreter running this test, and the script above
        [sys.executable, "-I", "-B", "-c", script, json.dumps(resources)],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    named_by_the_core = json.loads(completed.stdout)
    for resource, named in zip(resources, named_by_the_core, strict=True):
        authority = resource.partition("://")[2].partition("/")[0]
        assert named == f"https://{authority}{metadata_path(resource)}"


def test_the_document_says_where_tokens_come_from_and_nothing_about_who_may_do_what() -> None:
    document = json.loads(metadata_document(edge_config(mcp=OAUTH).mcp))
    assert document == {
        "resource": "https://mcp.example.com/mcp",
        "authorization_servers": ["https://login.example.com", "https://sso.example.org/tenant"],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["acf:sandbox.read", "acf:sandbox.exec"],
    }


def test_scopes_are_left_out_when_none_are_configured() -> None:
    oauth = {k: v for k, v in OAUTH.items() if k != "scopes_supported"}
    assert "scopes_supported" not in json.loads(metadata_document(edge_config(mcp=oauth).mcp))


async def test_the_document_is_served_to_anyone_at_the_well_known_path(core: FakeCore) -> None:
    async with running(core, mcp=OAUTH) as (_, http):
        response = await http.get("/.well-known/oauth-protected-resource/mcp", headers={"host": "mcp.example.com"})
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["resource"] == "https://mcp.example.com/mcp"
        assert response.json()["authorization_servers"] == OAUTH["authorization_servers"]

        for method in ("POST", "PUT", "DELETE"):
            refused = await http.request(
                method, "/.well-known/oauth-protected-resource/mcp", headers={"host": "mcp.example.com"}
            )
            assert refused.status_code == 405
            assert refused.headers["allow"] == "GET"
        assert (
            await http.get("/.well-known/oauth-protected-resource", headers={"host": "mcp.example.com"})
        ).status_code == 404
    # A public document: the core was never asked about anyone.
    assert core.asked == []


async def test_no_document_is_served_when_no_resource_is_configured(client: httpx2.AsyncClient, core: FakeCore) -> None:
    assert (await client.get("/.well-known/oauth-protected-resource/mcp")).status_code == 404
    assert (await client.get("/.well-known/oauth-protected-resource")).status_code == 404
    assert core.asked == []


async def test_the_endpoint_serves_calls_beside_the_document(core: FakeCore) -> None:
    async with running(core, mcp=OAUTH) as (_, http):
        sent = {**headers("tools/list"), "host": "mcp.example.com"}
        assert (await http.post("/mcp", json=rpc("tools/list"), headers=sent)).status_code == 200
