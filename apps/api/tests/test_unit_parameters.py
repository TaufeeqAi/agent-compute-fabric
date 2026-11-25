"""The bounds of the interface plane: named, finite, with defaults that work, and relations checked at startup.

Proves INV-113 and the register of the contract's section on bounds: every parameter of the register
exists with its recommended default; every relation among the platform's own parameters is validated,
and a violated relation refuses the configuration; a relation to a value of the host is validated as
soon as the host advertises that value. Also VER-11: a key the configuration schema does not define,
at any level, is a startup failure. Catalog entries: T3-PARAM-01 at the unit level and the static half
of T3-RED-38. That a maximal public request is refused before it reaches the host is proven by the
suite of the REST adapter.

The register is written out below as data. A parameter that is added, renamed or given another
default has to be changed here too, and so is changed knowingly.
"""

from __future__ import annotations

import copy
import math
import types
import typing
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from acf_api.core import config as cfg
from acf_api.core.parameters import DAY, HOUR, KIB, MIB, Parameters, host_violations, violations
from acf_api.edge.config import EdgeConfigError, Limits, parse_edge_config
from tests.support.harness import config_dict

MINUTE = 60

#: The register, row by row: the name in the contract and the recommended default in the units the code
#: uses (seconds, bytes, counts). ``None``: the default follows from another value, and a test below says how.
REGISTER: dict[str, Any] = {
    "max_public_request_bytes": 1 * MIB,
    "edge_max_connections": 1024,
    "edge_max_header_bytes": 16 * KIB,
    "edge_max_commands_in_flight": 256,
    "public_wait_max": 30,
    "server_deadline_margin": 10,
    "edge_core_deadline_margin": 2,
    "host_call_wait": 0,
    "host_deadline_margin": 10,
    "host_resolve_attempts": 5,
    "host_max_connections": 8,
    "host_conn_reserved_containment": 2,
    "host_conn_reserved_resolution": 1,
    "host_info_ttl": 60,
    "host_ops_allowance": 600,
    "host_reads_allowance": 6000,
    "host_allowance_reserve": 0.2,
    "project_default_share": 0.5,
    "principal_rate": None,
    "project_rate": None,
    "principal_max_in_flight": 16,
    "project_max_in_flight": 32,
    "project_max_live_sandboxes": None,
    "project_max_snapshots": None,
    "follow_poll_interval_min": 0.5,
    "follow_poll_interval_max": 5,
    "mcp_tool_wait": 25,
    "mcp_inline_output_max": 16 * KIB,
    "mcp_adoption_window": 5 * MINUTE,
    "mcp_exec_default_timeout": 10 * MINUTE,
    "mcp_serve_2025_11_25": False,
    "mcp_tasks_extension": False,
    "mcp_allow_developer_credentials": False,
    "output_chunk_max": 256 * KIB,
    "follow_max": 30 * MINUTE,
    "sdk_request_timeout": 120,
    "sdk_max_retries": 2,
    "sdk_backoff_initial": 0.5,
    "sdk_backoff_max": 8,
    "retry_budget_ratio": 0.2,
    "idempotency_retention": None,
    "idempotency_safety_margin": 1 * HOUR,
    "idempotency_key_max_len": 255,
    "claim_stale_after": 2 * MINUTE,
    "recovery_sweep_interval": 1 * MINUTE,
    "credential_revocation_bound": 60,
    "containment_auth_cache_ttl": 60,
    "credential_max_lifetime": 365 * DAY,
    "agent_credential_max_lifetime": 24 * HOUR,
    "agent_expiry_grace": 5 * MINUTE,
    "agent_label_max_len": 64,
    "auth_deadline": 2,
    "jwks_refresh_interval": 10 * MINUTE,
    "jwks_forced_refresh_min_interval": 60,
    "oauth_token_max_lifetime": 1 * HOUR,
    "store_deadline": 5,
    "store_reserve_bytes": 64 * MIB,
    "audit_budget_bytes": 1024 * MIB,
    "audit_retention": 90 * DAY,
    "audit_required": False,
    "drain_timeout": 30,
    "api_deprecation_window": 183,
    "dx_time_budget": 10 * MINUTE,
}
#: Register rows whose field carries its unit in its name. "6 months" is stored as a number of days.
FIELD_OF_ROW = {"api_deprecation_window": "api_deprecation_window_days"}
#: Fields the code has and the register does not name. Each is a bound all the same: named, finite, with a default.
#: Fields that the register does not list, each with its default. ``host_connect_timeout`` bounds the one
#: wait the register leaves unnamed. ``host_max_sandboxes`` and ``host_max_snapshots`` are the host's
#: envelope, which two rows of the register refer to and which the host does not advertise: the operator
#: states them, as with the two allowances, and the defaults are the host's own.
BEYOND_THE_REGISTER = {"host_connect_timeout": 5.0, "host_max_sandboxes": 16, "host_max_snapshots": 64}

#: What the host advertises with its shipped defaults.
HOST_DEFAULTS: dict[str, Any] = {
    "host_wait_max_s": 30.0,
    "host_operation_retention_s": 86400.0,
    "host_acceptance_horizon_s": 300.0,
    "host_max_request_bytes": 1 * MIB,
}


def field_of(row: str) -> str:
    return FIELD_OF_ROW.get(row, row)


def parameters_of(**changes: Any) -> Parameters:
    """The defaults with ``changes``, typed loosely: a test gives values the type forbids, to see them refused."""
    return Parameters(**changes)


def core_config(root: Path, **parameters: Any) -> dict[str, Any]:
    """A complete configuration of the core with the default parameters, and the ones a test names."""
    data = config_dict(root)
    data["parameters"] = dict(parameters)
    return data


# ------------------------------------------------------------------------------- the register
@pytest.mark.proves("T3-PARAM-01")
def test_every_parameter_of_the_register_exists() -> None:
    fields = set(Parameters.model_fields)
    rows = {field_of(row) for row in REGISTER}
    assert rows - fields == set(), "a register row has no field"
    assert fields - rows == set(BEYOND_THE_REGISTER), "a field is in neither the register nor the list of additions"
    assert len(REGISTER) == 63


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.parametrize("row", sorted(row for row, default in REGISTER.items() if default is not None))
def test_a_parameter_has_the_recommended_default(row: str) -> None:
    default = getattr(Parameters(), field_of(row))
    expected = REGISTER[row]
    assert default == expected
    assert isinstance(default, bool) == isinstance(expected, bool)
    assert Parameters.model_fields[field_of(row)].is_required() is False, (
        "a bound is never left for an operator to supply"
    )


@pytest.mark.proves("T3-PARAM-01")
def test_the_parameters_beyond_the_register_have_defaults_too() -> None:
    for name, expected in BEYOND_THE_REGISTER.items():
        assert getattr(Parameters(), name) == expected


@pytest.mark.proves("T3-PARAM-01")
def test_the_rates_default_to_the_projects_share_of_the_usable_allowance() -> None:
    """`principal_rate`, `project_rate`: that share, 240 a minute with the host's default allowance of 600."""
    p = Parameters()
    assert p.principal_rate is None
    assert p.project_rate is None
    assert p.usable_ops_per_minute() == pytest.approx(600 * (1 - 0.2)) == pytest.approx(480)
    assert p.project_ops_per_minute() == pytest.approx(240)
    assert p.principal_ops_per_minute() == pytest.approx(240)
    assert p.usable_reads_per_minute() == pytest.approx(4800)
    assert p.reserved_reads_per_minute() == pytest.approx(1200)
    assert p.project_reads_per_minute() == pytest.approx(2400)
    # A rate the operator sets is a ceiling below the share, never a way above it.
    slower = Parameters(principal_rate=10, project_rate=100)
    assert slower.project_ops_per_minute() == 100
    assert slower.principal_ops_per_minute() == 10
    assert Parameters(project_rate=100).principal_ops_per_minute() == 100
    assert p.project_ops_per_minute(share=0.25) == pytest.approx(120)
    assert p.usable_ops_per_minute(host_ops_allowance=1000) == pytest.approx(800)


@pytest.mark.proves("T3-PARAM-01")
def test_the_quotas_default_to_the_projects_share_of_the_host_envelope_and_to_one_at_least() -> None:
    p = Parameters()
    assert p.project_max_live_sandboxes is None
    assert p.project_max_snapshots is None
    # With the host's own envelope of 16 sandboxes and 64 snapshots, and the default share of a half.
    assert (p.quota_sandboxes(), p.quota_snapshots()) == (8, 32)
    for envelope, quota in ((8, 4), (64, 32), (3, 1), (1, 1)):
        assert Parameters(host_max_sandboxes=envelope).quota_sandboxes() == quota
        assert Parameters(host_max_snapshots=envelope).quota_snapshots() == quota
    assert Parameters(host_max_sandboxes=10, project_default_share=0.25).quota_sandboxes() == 2
    # An operator's number is the quota, whatever the share.
    assert Parameters(project_max_live_sandboxes=7).quota_sandboxes() == 7
    assert Parameters(project_max_snapshots=7).quota_snapshots() == 7


@pytest.mark.proves("T3-PARAM-01")
def test_a_quota_is_always_a_number_and_never_the_whole_host() -> None:
    """INV-113: no bound is left for an operator to supply. CC3-8: no single project can take everything."""
    for envelope in (2, 3, 16, 64, 4096):
        p = Parameters(host_max_sandboxes=envelope, host_max_snapshots=envelope)
        for quota in (p.quota_sandboxes(), p.quota_snapshots()):
            assert isinstance(quota, int)
            assert 1 <= quota < envelope
    # A host that admits one sandbox has one to give, and the quota says so.
    assert Parameters(host_max_sandboxes=1).quota_sandboxes() == 1


@pytest.mark.proves("T3-PARAM-01")
def test_the_retention_defaults_to_the_hosts_plus_the_safety_margin() -> None:
    """`idempotency_retention`: the host's `operation_retention` + 1 h, which is 25 h with the host's default."""
    p = Parameters()
    assert p.idempotency_retention is None
    assert p.retention(24 * HOUR) == 25 * HOUR
    assert p.retention(48 * HOUR) == 49 * HOUR
    assert p.retention(None) == 25 * HOUR
    assert Parameters(idempotency_retention=30.0 * HOUR).retention(24 * HOUR) == 30 * HOUR


@pytest.mark.proves("T3-PARAM-01")
def test_the_two_connection_reserves_leave_at_least_two_for_everything_else() -> None:
    assert Parameters().general_host_connections() == 8 - 2 - 1 == 5


@pytest.mark.proves("T3-PARAM-01")
def test_an_edge_process_starts_from_the_same_defaults_as_the_core() -> None:
    """Six bounds are enforced in the edge and known to the core. One default each, in two places."""
    edge, core = Limits(), Parameters()
    shared = sorted(set(Limits.model_fields) & set(Parameters.model_fields))
    assert shared == [
        "edge_core_deadline_margin",
        "edge_max_commands_in_flight",
        "edge_max_connections",
        "edge_max_header_bytes",
        "max_public_request_bytes",
        "public_wait_max",
    ]
    for name in shared:
        assert getattr(edge, name) == getattr(core, name), name
        assert getattr(edge, name) == REGISTER[name], name


@pytest.mark.proves("T3-PARAM-01")
def test_what_a_caller_is_told_is_a_subset_of_the_parameters_and_holds_their_values() -> None:
    p = Parameters(public_wait_max=20.0, mcp_tool_wait=10.0, sdk_max_retries=5)
    told = p.public()
    assert set(told) <= set(Parameters.model_fields)
    for name, value in told.items():
        assert value == getattr(p, name), name
    # Nothing about the host as a whole, the store or the core's own limits is told.
    assert not {
        name for name in told if name.startswith(("host_", "store_", "audit_", "edge_", "project_", "principal_"))
    }


# ------------------------------------------------------------------------------- finite, typed, bounded
def _is(annotation: Any, kind: type) -> bool:
    if annotation is kind:
        return True
    if typing.get_origin(annotation) in {typing.Union, types.UnionType}:
        return any(arg is kind for arg in typing.get_args(annotation))
    return False


NUMERIC = sorted(
    name
    for name, field in Parameters.model_fields.items()
    if _is(field.annotation, int) or _is(field.annotation, float)
)
REAL = sorted(name for name, field in Parameters.model_fields.items() if _is(field.annotation, float))
BOOLEAN = sorted(name for name, field in Parameters.model_fields.items() if _is(field.annotation, bool))


@pytest.mark.proves("T3-PARAM-01")
def test_every_parameter_is_a_number_or_a_switch() -> None:
    assert sorted(NUMERIC + BOOLEAN) == sorted(Parameters.model_fields)
    assert BOOLEAN == [
        "audit_required",
        "mcp_allow_developer_credentials",
        "mcp_serve_2025_11_25",
        "mcp_tasks_extension",
    ]
    assert len(REAL) > 20


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.parametrize("name", REAL)
@pytest.mark.parametrize("value", [math.inf, -math.inf, math.nan], ids=["inf", "-inf", "nan"])
def test_no_bound_can_be_set_to_something_that_is_not_finite(name: str, value: float) -> None:
    """Every bound is finite. A YAML file can say `.inf` and `.nan`; neither is a bound."""
    with pytest.raises(ValidationError):
        parameters_of(**{name: value})


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.parametrize("name", NUMERIC)
def test_no_bound_can_be_negative(name: str) -> None:
    with pytest.raises(ValidationError):
        parameters_of(**{name: -1.0 if name in REAL else -1})


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.parametrize(
    ("name", "refused", "accepted"),
    [
        ("server_deadline_margin", 0, 0.001),
        ("edge_core_deadline_margin", 0, 0.001),
        ("host_call_wait", 2.001, 2),
        ("host_call_wait", -0.001, 0),
        ("host_deadline_margin", 0, 0.001),
        ("host_resolve_attempts", 0, 1),
        ("host_conn_reserved_containment", 0, 1),
        ("host_conn_reserved_resolution", 0, 1),
        ("host_allowance_reserve", 0, 0.001),
        ("host_allowance_reserve", 1, 0.999),
        ("project_default_share", 0, 0.001),
        ("project_default_share", 1, 0.999),
        ("principal_rate", 0, 1),
        ("project_rate", 0, 1),
        ("project_max_live_sandboxes", 0, 1),
        ("project_max_snapshots", 0, 1),
        ("retry_budget_ratio", 1, 0.999),
        ("idempotency_safety_margin", 0, 1),
        ("idempotency_key_max_len", 256, 255),
        ("idempotency_key_max_len", 0, 1),
        ("agent_expiry_grace", -1, 0),
        ("agent_label_max_len", 65, 64),
        ("jwks_forced_refresh_min_interval", 0, 0.001),
        ("store_reserve_bytes", 0, 1),
        ("edge_max_commands_in_flight", 1, 2),
    ],
)
def test_the_bounds_the_register_states_for_one_parameter_alone(name: str, refused: float, accepted: float) -> None:
    kind = float if name in REAL else int
    with pytest.raises(ValidationError):
        parameters_of(**{name: kind(refused)})
    assert getattr(parameters_of(**{name: kind(accepted)}), name) == accepted


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.parametrize("name", BOOLEAN)
def test_a_switch_is_true_or_false_and_off_by_default(name: str) -> None:
    assert getattr(Parameters(), name) is False
    assert getattr(parameters_of(**{name: True}), name) is True
    for not_a_switch in ("true", "false", "yes", 1, 0, None):
        with pytest.raises(ValidationError):
            parameters_of(**{name: not_a_switch})


@pytest.mark.proves("T3-PARAM-01")
def test_a_number_is_not_read_from_text_and_a_parameter_cannot_be_changed_after_the_start() -> None:
    for name, text in (
        ("public_wait_max", "30"),
        ("host_max_connections", "8"),
        ("sdk_max_retries", "2"),
        ("store_deadline", "5s"),
    ):
        with pytest.raises(ValidationError):
            parameters_of(**{name: text})
    with pytest.raises(ValidationError):
        parameters_of(host_max_connections=8.5)
    with pytest.raises(ValidationError):
        Parameters(host_max_connections=True)
    p = Parameters()
    with pytest.raises(ValidationError):
        p.public_wait_max = 1.0  # type: ignore[misc]


# ------------------------------------------------------------------------------- relations among the platform's parameters
#: One targeted change per relation: the change, the two parameters the report must name, and the
#: nearest change that keeps the relation.
RELATIONS: list[tuple[dict[str, Any], tuple[str, ...], dict[str, Any]]] = [
    (
        {"edge_core_deadline_margin": 10.0},
        ("edge_core_deadline_margin", "server_deadline_margin"),
        {"edge_core_deadline_margin": 9.999},
    ),
    (
        {"server_deadline_margin": 2.0},
        ("edge_core_deadline_margin", "server_deadline_margin"),
        {"server_deadline_margin": 2.001},
    ),
    (
        {"host_max_connections": 4},
        ("host_max_connections", "host_conn_reserved_containment", "host_conn_reserved_resolution"),
        {"host_max_connections": 5},
    ),
    (
        {"host_conn_reserved_containment": 6},
        ("host_max_connections", "host_conn_reserved_containment"),
        {"host_conn_reserved_containment": 5},
    ),
    (
        {"host_conn_reserved_resolution": 5},
        ("host_max_connections", "host_conn_reserved_resolution"),
        {"host_conn_reserved_resolution": 4},
    ),
    (
        {"project_max_in_flight": 15},
        ("project_max_in_flight", "principal_max_in_flight"),
        {"project_max_in_flight": 16},
    ),
    (
        {"principal_max_in_flight": 33},
        ("project_max_in_flight", "principal_max_in_flight"),
        {"principal_max_in_flight": 32},
    ),
    ({"principal_rate": 241}, ("principal_rate",), {"principal_rate": 240}),
    ({"project_rate": 241}, ("project_rate",), {"project_rate": 240}),
    (
        {"principal_rate": 240, "host_ops_allowance": 599},
        ("principal_rate",),
        {"principal_rate": 240, "host_ops_allowance": 600},
    ),
    (
        {"project_rate": 240, "host_allowance_reserve": 0.21},
        ("project_rate",),
        {"project_rate": 240, "host_allowance_reserve": 0.2},
    ),
    (
        {"project_rate": 240, "project_default_share": 0.49},
        ("project_rate",),
        {"project_rate": 240, "project_default_share": 0.5},
    ),
    (
        {"follow_poll_interval_min": 5.0},
        ("follow_poll_interval_min", "follow_poll_interval_max"),
        {"follow_poll_interval_min": 4.999},
    ),
    (
        {"follow_poll_interval_max": 0.5},
        ("follow_poll_interval_min", "follow_poll_interval_max"),
        {"follow_poll_interval_max": 0.501},
    ),
    (
        {"project_max_live_sandboxes": 17},
        ("project_max_live_sandboxes", "host_max_sandboxes"),
        {"project_max_live_sandboxes": 16},
    ),
    (
        {"project_max_live_sandboxes": 8, "host_max_sandboxes": 7},
        ("project_max_live_sandboxes", "host_max_sandboxes"),
        {"project_max_live_sandboxes": 8, "host_max_sandboxes": 8},
    ),
    (
        {"project_max_snapshots": 65},
        ("project_max_snapshots", "host_max_snapshots"),
        {"project_max_snapshots": 64},
    ),
    (
        {"project_max_snapshots": 4, "host_max_snapshots": 3},
        ("project_max_snapshots", "host_max_snapshots"),
        {"project_max_snapshots": 4, "host_max_snapshots": 4},
    ),
    ({"mcp_serve_2025_11_25": True}, ("mcp_serve_2025_11_25",), {"mcp_serve_2025_11_25": False}),
    ({"mcp_tasks_extension": True}, ("mcp_tasks_extension",), {"mcp_tasks_extension": False}),
    ({"mcp_tool_wait": 30.001}, ("mcp_tool_wait", "public_wait_max"), {"mcp_tool_wait": 30.0}),
    ({"public_wait_max": 24.999}, ("mcp_tool_wait", "public_wait_max"), {"public_wait_max": 25.0}),
    (
        {"mcp_inline_output_max": 256 * KIB + 1},
        ("mcp_inline_output_max", "output_chunk_max"),
        {"mcp_inline_output_max": 256 * KIB},
    ),
    ({"output_chunk_max": 16 * KIB - 1}, ("mcp_inline_output_max", "output_chunk_max"), {"output_chunk_max": 16 * KIB}),
    ({"mcp_adoption_window": 25.0}, ("mcp_adoption_window", "mcp_tool_wait"), {"mcp_adoption_window": 25.001}),
    (
        {"sdk_request_timeout": 40.0},
        ("sdk_request_timeout", "public_wait_max", "server_deadline_margin"),
        {"sdk_request_timeout": 40.001},
    ),
    ({"sdk_backoff_initial": 8.0}, ("sdk_backoff_initial", "sdk_backoff_max"), {"sdk_backoff_initial": 7.999}),
    ({"sdk_backoff_max": 0.5}, ("sdk_backoff_initial", "sdk_backoff_max"), {"sdk_backoff_max": 0.501}),
    (
        {"claim_stale_after": 40.0},
        ("claim_stale_after", "public_wait_max", "server_deadline_margin"),
        {"claim_stale_after": 40.001},
    ),
    (
        {"containment_auth_cache_ttl": 60.001},
        ("containment_auth_cache_ttl", "credential_revocation_bound"),
        {"containment_auth_cache_ttl": 60.0},
    ),
    (
        {"credential_revocation_bound": 59.999},
        ("containment_auth_cache_ttl", "credential_revocation_bound"),
        {"credential_revocation_bound": 60.0},
    ),
    (
        {"agent_credential_max_lifetime": 365.0 * DAY + 1},
        ("agent_credential_max_lifetime", "credential_max_lifetime"),
        {"agent_credential_max_lifetime": 365.0 * DAY},
    ),
    (
        {"credential_max_lifetime": 1.0 * DAY - 1},
        ("agent_credential_max_lifetime", "credential_max_lifetime"),
        {"credential_max_lifetime": 1.0 * DAY},
    ),
    (
        {"idempotency_retention": 1.0 * HOUR},
        ("idempotency_retention", "idempotency_safety_margin"),
        {"idempotency_retention": 1.0 * HOUR + 1},
    ),
]


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.proves("T3-RED-38", level="L0")
def test_the_default_parameters_violate_no_relation() -> None:
    assert violations(Parameters()) == []
    assert host_violations(Parameters(), **HOST_DEFAULTS) == []
    assert (
        host_violations(Parameters(), **HOST_DEFAULTS, host_output_chunk_max=256 * KIB, host_identifier_slots=16) == []
    )


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.proves("T3-RED-38", level="L0")
@pytest.mark.parametrize(
    ("change", "named", "kept"),
    RELATIONS,
    ids=[",".join(change) + "=" + ",".join(map(str, change.values())) for change, _, _ in RELATIONS],
)
def test_each_relation_is_violated_by_one_targeted_change_and_reported(
    tmp_path: Path, change: dict[str, Any], named: tuple[str, ...], kept: dict[str, Any]
) -> None:
    broken = violations(Parameters(**change))
    assert len(broken) == 1, broken
    for parameter in named:
        assert parameter in broken[0], broken[0]
    assert violations(Parameters(**kept)) == []

    # A violated relation is a startup failure: the configuration is refused, and the report says why.
    with pytest.raises(cfg.ConfigError) as refused:
        cfg.parse_config(core_config(tmp_path, **change))
    assert broken[0] in str(refused.value)
    assert cfg.parse_config(core_config(tmp_path, **kept)).parameters == Parameters(**kept)


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.proves("T3-RED-38", level="L0")
def test_every_relation_of_the_register_among_the_platforms_own_parameters_is_covered() -> None:
    """The relations of the register that name two platform parameters, each with the change that breaks it."""
    stated = {
        ("edge_core_deadline_margin", "server_deadline_margin"),
        ("host_max_connections", "host_conn_reserved_containment", "host_conn_reserved_resolution"),
        ("project_max_in_flight", "principal_max_in_flight"),
        ("principal_rate",),
        ("project_rate",),
        # The two quotas against the host's envelope, which the operator states (BEYOND_THE_REGISTER).
        ("project_max_live_sandboxes", "host_max_sandboxes"),
        ("project_max_snapshots", "host_max_snapshots"),
        ("follow_poll_interval_min", "follow_poll_interval_max"),
        # Two surfaces of the register that this build does not have: each switch is refused when it is on.
        ("mcp_serve_2025_11_25",),
        ("mcp_tasks_extension",),
        ("mcp_tool_wait", "public_wait_max"),
        ("mcp_inline_output_max", "output_chunk_max"),
        ("mcp_adoption_window", "mcp_tool_wait"),
        ("sdk_request_timeout", "public_wait_max", "server_deadline_margin"),
        ("sdk_backoff_initial", "sdk_backoff_max"),
        ("claim_stale_after", "public_wait_max", "server_deadline_margin"),
        ("containment_auth_cache_ttl", "credential_revocation_bound"),
        ("agent_credential_max_lifetime", "credential_max_lifetime"),
        ("idempotency_retention", "idempotency_safety_margin"),
    }
    covered = {named for _, named, _ in RELATIONS}
    assert stated <= covered
    messages = {violations(Parameters(**change))[0] for change, _, _ in RELATIONS}
    assert len(messages) == len(stated), "two relations share one report, or one relation has two"


@pytest.mark.proves("T3-PARAM-01")
def test_several_violated_relations_are_all_reported() -> None:
    broken = violations(Parameters(mcp_tool_wait=31.0, sdk_backoff_initial=9.0, project_max_in_flight=1))
    assert len(broken) == 3
    assert len(set(broken)) == 3


# ------------------------------------------------------------------------------- relations to values of the host
@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.parametrize(
    ("parameters", "host", "named"),
    [
        ({"host_call_wait": 1.0}, {"host_wait_max_s": 0.999}, "host_call_wait"),
        (
            {"idempotency_retention": 25.0 * HOUR - 1},
            {"host_operation_retention_s": 24.0 * HOUR},
            "idempotency_retention",
        ),
        (
            {"idempotency_retention": 25.0 * HOUR, "idempotency_safety_margin": 1.0 * HOUR + 1},
            {"host_operation_retention_s": 24.0 * HOUR},
            "idempotency_retention",
        ),
        ({}, {"host_acceptance_horizon_s": 180.0}, "claim_stale_after"),
        ({"recovery_sweep_interval": 180.0}, {"host_acceptance_horizon_s": 300.0}, "recovery_sweep_interval"),
        ({"claim_stale_after": 240.0}, {"host_acceptance_horizon_s": 300.0}, "claim_stale_after"),
        ({}, {"host_max_request_bytes": 4 * KIB - 1}, "max_request_bytes"),
        ({}, {"host_output_chunk_max": 256 * KIB - 1}, "output_chunk_max"),
        ({}, {"host_identifier_slots": 15}, "host_max_sandboxes"),
        ({"host_max_sandboxes": 4097}, {"host_identifier_slots": 4096}, "host_max_sandboxes"),
    ],
)
def test_a_relation_to_a_value_of_the_host_is_checked_once_the_host_advertises_it(
    parameters: dict[str, Any], host: dict[str, Any], named: str
) -> None:
    p = Parameters(**parameters)
    assert violations(p) == [], "the change must break a relation to the host, and none of the platform's own"
    broken = host_violations(p, **{**HOST_DEFAULTS, **host})
    assert len(broken) == 1, broken
    assert named in broken[0]
    # Until the host advertises the value there is nothing to check it against: the operator answers for it.
    unknown = {**dict.fromkeys(HOST_DEFAULTS), **dict.fromkeys(host)}
    assert host_violations(p, **unknown) == []


@pytest.mark.proves("T3-PARAM-01")
def test_the_relations_to_the_host_hold_at_their_limits() -> None:
    assert host_violations(Parameters(host_call_wait=1.0), **{**HOST_DEFAULTS, "host_wait_max_s": 1.0}) == []
    assert host_violations(Parameters(idempotency_retention=25.0 * HOUR), **HOST_DEFAULTS) == []
    assert host_violations(Parameters(), **{**HOST_DEFAULTS, "host_acceptance_horizon_s": 180.001}) == []
    assert host_violations(Parameters(), **{**HOST_DEFAULTS, "host_max_request_bytes": 4 * KIB}) == []
    assert host_violations(Parameters(), **HOST_DEFAULTS, host_identifier_slots=16) == []
    assert host_violations(Parameters(host_max_sandboxes=4096), **HOST_DEFAULTS, host_identifier_slots=4096) == []
    # The default retention follows the host's, so it can never be below what the host keeps.
    for retention in (1.0, 24.0 * HOUR, 30.0 * DAY):
        assert host_violations(Parameters(), **{**HOST_DEFAULTS, "host_operation_retention_s": retention}) == []
        assert Parameters().retention(retention) >= retention + Parameters().idempotency_safety_margin


# ------------------------------------------------------------------------------- the configuration file
def _dict_paths(value: Any, path: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    paths = []
    if isinstance(value, dict):
        paths.append(path)
        for key, child in value.items():
            paths.extend(_dict_paths(child, (*path, key)))
    return paths


def full_core_config(root: Path) -> dict[str, Any]:
    """A configuration that names every section the schema has."""
    data = config_dict(root)
    data["paths"]["journal_mirror"] = str(root / "mirror" / "security.journal")
    data["edge"]["socket_gid"] = 0
    data["oauth"] = {
        "issuer": "https://issuer.example",
        "resource": "https://acf.example/mcp",
        "jwks_uri": "https://issuer.example/keys",
    }
    data["audit_sink"] = {"file": str(root / "audit" / "records.jsonl")}
    data["telemetry"] = {"log_level": "INFO"}
    return data


@pytest.mark.proves("T3-PARAM-01")
def test_the_default_configuration_validates(tmp_path: Path) -> None:
    """Every default works: a configuration that names no parameter at all is a valid one."""
    minimal = config_dict(tmp_path)
    del minimal["parameters"]
    del minimal["security"]
    config = cfg.parse_config(minimal)
    assert config.parameters == Parameters()
    assert violations(config.parameters) == []
    assert config.security.allow_shared_identity is False
    assert config.oauth is None
    assert config.audit_sink is None
    assert config.paths.journal_mirror is None
    assert cfg.parse_config(config_dict(tmp_path)).parameters.public_wait_max == 2.0
    full = cfg.parse_config(full_core_config(tmp_path))
    assert full.oauth is not None
    assert full.audit_sink is not None
    assert cfg.CONFIG_SCHEMA_VERSION == 1


@pytest.mark.proves("T3-PARAM-01", level="L3")
def test_the_shipped_example_configuration_violates_no_relation() -> None:
    """The configuration an operator starts from, with the allowances and the horizons the host ships with."""
    repository = Path(__file__).resolve().parents[3]
    text = (repository / "config" / "platform-core.example.yaml").read_text(encoding="utf-8")
    assert text.count("dep_REPLACE_ME") == 1, "the example names no deployment: an operator has to"
    config = cfg.parse_config(yaml.safe_load(text.replace("dep_REPLACE_ME", "dep_7Q2M9K4T1V8X3B6N")))
    assert violations(config.parameters) == []
    assert host_violations(config.parameters, **HOST_DEFAULTS) == []
    # Whatever the example leaves out is a default, so the whole of it is the default configuration.
    assert config.parameters == Parameters()
    # The edge example states the bounds both roles know, and states them as the core has them.
    edge = parse_edge_config(
        yaml.safe_load((repository / "config" / "platform-edge.example.yaml").read_text(encoding="utf-8"))
    )
    for name in set(Limits.model_fields) & set(Parameters.model_fields):
        assert getattr(edge.limits, name) == getattr(config.parameters, name), name
    assert edge.mcp.tool_wait == config.parameters.mcp_tool_wait
    assert edge.mcp.serve_2025_11_25 is config.parameters.mcp_serve_2025_11_25 is False


@pytest.mark.proves("T3-PARAM-01")
def test_an_unknown_key_anywhere_in_the_configuration_is_refused(tmp_path: Path) -> None:
    """VER-11. A setting that narrows what the platform does must not be ignored by a version that does not know it."""
    canary = "CANARY-51c0"
    complete = full_core_config(tmp_path)
    paths = _dict_paths(complete)
    assert sorted(".".join(path) for path in paths) == [
        "",
        "audit_sink",
        "edge",
        "host",
        "oauth",
        "parameters",
        "paths",
        "security",
        "telemetry",
    ]
    for path in paths:
        damaged = copy.deepcopy(complete)
        node = damaged
        for step in path:
            node = node[step]
        node["unknown_setting"] = canary
        with pytest.raises(cfg.ConfigError) as refused:
            cfg.parse_config(damaged)
        message = str(refused.value)
        assert ".".join((*path, "unknown_setting")) in message
        assert canary not in message, "the report names the setting and never repeats its value"
    cfg.parse_config(complete)


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.parametrize(
    "parameters",
    [
        {"max_public_request_byte": 1024},
        {"public_wait": 30.0},
        {"PUBLIC_WAIT_MAX": 30.0},
        {"public-wait-max": 30.0},
        {"api_deprecation_window": 183},
        {"mcp_serve_2025-11-25": True},
        {"": 1},
    ],
)
def test_a_parameter_under_a_name_the_schema_does_not_have_is_refused(
    tmp_path: Path, parameters: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        Parameters(**parameters)
    with pytest.raises(cfg.ConfigError):
        cfg.parse_config(core_config(tmp_path, **parameters))


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": 2},
        {"schema_version": 0},
        {"schema_version": "1"},
        {"deployment_id": "dep_short"},
        {"deployment_id": "prj_7Q2M9K4T1V8X3B6N"},
        {"deployment_id": None},
        {"paths": None},
        {"edge": {"uids": []}},
        {"edge": {"uids": [-1]}},
        {"host": None},
        {"parameters": None},
        {"parameters": []},
        {"parameters": {"public_wait_max": -1.0}},
        {"parameters": {"public_wait_max": float("inf")}},
        {"parameters": {"host_call_wait": 3.0}},
        {"parameters": {"audit_required": "sometimes"}},
        {"parameters": {"public_wait_max": "thirty"}},
        {"security": {"allow_shared_identity": "maybe"}},
        {"telemetry": {"log_level": "TRACE"}},
        {
            "oauth": {
                "issuer": "http://issuer.example",
                "resource": "https://acf.example/mcp",
                "jwks_uri": "https://issuer.example/keys",
            }
        },
        {"oauth": {"issuer": "https://issuer.example", "resource": "https://acf.example/mcp"}},
        {
            "oauth": {
                "issuer": "https://issuer.example",
                "resource": "https://acf.example/mcp",
                "jwks_uri": "https://issuer.example/keys",
                "jwks_file": "/etc/acf/jwks.json",
            }
        },
    ],
    ids=lambda change: str(change)[:60],
)
def test_a_configuration_that_is_not_valid_is_refused(tmp_path: Path, change: dict[str, Any]) -> None:
    data = config_dict(tmp_path)
    data.update(change)
    with pytest.raises(cfg.ConfigError):
        cfg.parse_config(data)


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.parametrize(
    "change",
    [
        {"parameters": {"host_max_connections": "8"}},
        {"parameters": {"host_max_connections": 8.0}},
        {"parameters": {"public_wait_max": "30"}},
        {"parameters": {"host_max_sandboxes": "16"}},
        {"parameters": {"mcp_serve_2025_11_25": 1}},
        {"parameters": {"mcp_serve_2025_11_25": "true"}},
        {"parameters": {"mcp_allow_developer_credentials": "no"}},
        {"parameters": {"project_max_live_sandboxes": "4"}},
        {"security": {"allow_shared_identity": 1}},
        {"security": {"allow_shared_identity": "false"}},
        {"edge": {"uids": ["1000"]}},
        {"edge": {"uids": [1000.5]}},
        {"edge": {"users": [1000]}},
        {"deployment_id": 7},
    ],
    ids=lambda change: str(change)[:60],
)
def test_a_value_of_another_type_than_its_setting_is_refused_and_never_interpreted(
    tmp_path: Path, change: dict[str, Any]
) -> None:
    """A number written as text, or a truth value written as a number, is a mistake: nobody can say what was meant.

    `allow_shared_identity: "false"` is the case that matters. Read loosely it is false, and `"no"` is false,
    and `"off"`; a file whose author wrote `"flase"` then stops the start with a message, and one whose author
    wrote `1` for another switch turns it on. A switch that changes what the platform admits is read exactly.
    """
    data = config_dict(tmp_path)
    data.update(change)
    with pytest.raises(cfg.ConfigError):
        cfg.parse_config(data)


@pytest.mark.proves("T3-PARAM-01")
def test_the_two_conversions_a_configuration_is_given(tmp_path: Path) -> None:
    """A path is written as text, and a whole number is a number: a file can say neither in another way."""
    data = config_dict(tmp_path)
    data["parameters"] = {"public_wait_max": 30, "drain_timeout": 5}
    config = cfg.parse_config(data)
    assert config.paths.store_dir == tmp_path / "store"
    assert isinstance(config.host.private_key, Path)
    assert (config.parameters.public_wait_max, config.parameters.drain_timeout) == (30.0, 5.0)
    assert isinstance(config.parameters.public_wait_max, float)
    # A path is text and nothing else.
    for not_text in (7, ["a"], {"a": 1}, None):
        data["paths"]["store_dir"] = not_text
        with pytest.raises(cfg.ConfigError):
            cfg.parse_config(data)


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.parametrize("missing", ["schema_version", "deployment_id", "paths", "edge", "host"])
def test_what_has_no_default_must_be_named(tmp_path: Path, missing: str) -> None:
    """Paths, identities and the host are the deployment's own. A bound never is: every bound has a default."""
    data = config_dict(tmp_path)
    del data[missing]
    with pytest.raises(cfg.ConfigError) as refused:
        cfg.parse_config(data)
    assert missing in str(refused.value)


@pytest.mark.proves("T3-PARAM-01")
@pytest.mark.parametrize("not_a_mapping", [None, [], "schema_version: 1", 1, [("schema_version", 1)]])
def test_a_configuration_must_be_a_mapping(not_a_mapping: Any) -> None:
    with pytest.raises(cfg.ConfigError, match="must be a mapping"):
        cfg.parse_config(not_a_mapping)


@pytest.mark.proves("T3-PARAM-01")
def test_the_configuration_is_read_from_a_file_with_the_same_rules(tmp_path: Path) -> None:
    path = tmp_path / "core.yaml"
    path.write_text(yaml.safe_dump(core_config(tmp_path, public_wait_max=20.0, mcp_tool_wait=15.0)), encoding="utf-8")
    assert cfg.load_config(path).parameters.public_wait_max == 20.0

    path.write_text(yaml.safe_dump(core_config(tmp_path, mcp_tool_wait=31.0)), encoding="utf-8")
    with pytest.raises(cfg.ConfigError, match="mcp_tool_wait must not exceed public_wait_max"):
        cfg.load_config(path)

    # What YAML reads as "not a number" and "infinity" is refused as any other value outside a bound.
    path.write_text(
        yaml.safe_dump(core_config(tmp_path)).replace("parameters: {}", "parameters:\n  idempotency_retention: .inf"),
        encoding="utf-8",
    )
    with pytest.raises(cfg.ConfigError):
        cfg.load_config(path)
    path.write_text(
        yaml.safe_dump(core_config(tmp_path)).replace("parameters: {}", "parameters:\n  drain_timeout: .nan"),
        encoding="utf-8",
    )
    with pytest.raises(cfg.ConfigError):
        cfg.load_config(path)

    path.write_text("parameters: [unclosed", encoding="utf-8")
    with pytest.raises(cfg.ConfigError, match="not valid YAML"):
        cfg.load_config(path)
    with pytest.raises(cfg.ConfigError, match="cannot read"):
        cfg.load_config(tmp_path / "absent.yaml")


@pytest.mark.proves("T3-PARAM-01")
def test_an_edge_configuration_refuses_an_unknown_key_too(tmp_path: Path) -> None:
    edge = {"schema_version": 1, "command_socket": str(tmp_path / "command.sock")}
    assert parse_edge_config(edge).limits == Limits()
    for damaged in (
        {**edge, "unknown_setting": 1},
        {**edge, "limits": {"unknown_setting": 1}},
        {**edge, "limits": {"max_public_request_byte": 1024}},
        {**edge, "listen": {"unknown_setting": 1}},
        {**edge, "mcp": {"unknown_setting": 1}},
        {**edge, "schema_version": 2},
        {**edge, "limits": {"max_public_request_bytes": float("inf")}},
        {**edge, "limits": {"public_wait_max": float("nan")}},
    ):
        with pytest.raises(EdgeConfigError):
            parse_edge_config(damaged)


@pytest.mark.proves("T3-PARAM-01")
def test_an_edge_configuration_is_read_as_exactly_as_the_cores(tmp_path: Path) -> None:
    edge: dict[str, Any] = {"schema_version": 1, "command_socket": str(tmp_path / "command.sock")}
    for damaged in (
        {**edge, "listen": {"port": "8443"}},
        {**edge, "listen": {"port": 8443.0}},
        {**edge, "limits": {"edge_max_connections": "1024"}},
        {**edge, "limits": {"public_wait_max": "30"}},
        {**edge, "mcp": {"serve_2025_11_25": "yes"}},
        {**edge, "mcp": {"serve_2025_11_25": 1}},
        {**edge, "mcp": {"allowed_origins": "https://app.example"}},
        {**edge, "command_socket": 7},
    ):
        with pytest.raises(EdgeConfigError):
            parse_edge_config(damaged)
    read = parse_edge_config(
        {
            **edge,
            "tls": {"certificate": str(tmp_path / "tls.crt"), "private_key": str(tmp_path / "tls.key")},
            "limits": {"public_wait_max": 30, "keep_alive_timeout": 15},
        }
    )
    assert read.command_socket == tmp_path / "command.sock"
    assert read.tls is not None
    assert read.tls.private_key == tmp_path / "tls.key"
    assert (read.limits.public_wait_max, read.limits.keep_alive_timeout) == (30.0, 15.0)
