"""The bounds of the interface plane: every one a named, finite parameter with a default that works.

No bound is left for an operator to supply. The relations among the platform's own parameters are
validated at startup, and a violated relation is a startup failure. A relation to a value of the host
is validated as soon as the host advertises that value (:func:`host_violations`); until then the
operator answers for it.

Defaults are configuration, not constants of the contract. The contract fixes the relations.
"""

from __future__ import annotations

from typing import Final

from pydantic import BaseModel, ConfigDict, Field

MIB: Final = 1024 * 1024
KIB: Final = 1024
HOUR: Final = 3600
DAY: Final = 24 * HOUR


class Parameters(BaseModel):
    """Every bound of the core and of the clients it tells about. Unknown keys are refused."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    # ---- one public request, per edge process
    max_public_request_bytes: int = Field(default=1 * MIB, ge=1024, le=32 * MIB)
    edge_max_connections: int = Field(default=1024, ge=1, le=1_000_000)
    edge_max_header_bytes: int = Field(default=16 * KIB, ge=1024, le=1 * MIB)
    edge_max_commands_in_flight: int = Field(default=256, ge=2, le=100_000)

    # ---- waits and deadlines (seconds)  # noqa: ERA001 - a heading of this table, not code
    public_wait_max: float = Field(default=30.0, ge=0, le=3600)
    server_deadline_margin: float = Field(default=10.0, gt=0, le=600)
    edge_core_deadline_margin: float = Field(default=2.0, gt=0, le=600)
    host_call_wait: float = Field(default=0.0, ge=0, le=2)
    host_deadline_margin: float = Field(default=10.0, gt=0, le=600)
    host_connect_timeout: float = Field(default=5.0, gt=0, le=120)
    host_resolve_attempts: int = Field(default=5, ge=1, le=100)

    # ---- the host binding
    host_max_connections: int = Field(default=8, ge=4, le=1024)
    host_conn_reserved_containment: int = Field(default=2, ge=1, le=512)
    host_conn_reserved_resolution: int = Field(default=1, ge=1, le=512)
    host_info_ttl: float = Field(default=60.0, gt=0, le=3600)
    host_ops_allowance: int = Field(default=600, ge=1, le=10_000_000)
    host_reads_allowance: int = Field(default=6000, ge=1, le=100_000_000)
    host_allowance_reserve: float = Field(default=0.2, gt=0, lt=1)
    #: What the host admits at once: its ``envelope.max_sandboxes`` and ``envelope.max_snapshots``. The host
    #: advertises neither, so the operator states them here, as with the two allowances, and answers for
    #: them. The defaults are the host's own.
    host_max_sandboxes: int = Field(default=16, ge=1, le=1_000_000)
    host_max_snapshots: int = Field(default=64, ge=1, le=1_000_000)

    # ---- shares, rates and concurrency
    project_default_share: float = Field(default=0.5, gt=0, lt=1)
    #: Requests per minute that create host operations. ``None``: the project's share of the usable allowance.
    principal_rate: int | None = Field(default=None, ge=1)
    project_rate: int | None = Field(default=None, ge=1)
    principal_max_in_flight: int = Field(default=16, ge=1, le=100_000)
    project_max_in_flight: int = Field(default=32, ge=1, le=100_000)
    #: Live sandboxes and snapshots per project. ``None``: the default share of what the host admits, at least 1.
    project_max_live_sandboxes: int | None = Field(default=None, ge=1)
    project_max_snapshots: int | None = Field(default=None, ge=1)

    # ---- following
    follow_poll_interval_min: float = Field(default=0.5, gt=0, le=60)
    follow_poll_interval_max: float = Field(default=5.0, gt=0, le=600)

    # ---- the agent interface
    mcp_tool_wait: float = Field(default=25.0, ge=0, le=3600)
    mcp_inline_output_max: int = Field(default=16 * KIB, ge=0, le=16 * MIB)
    mcp_adoption_window: float = Field(default=300.0, gt=0, le=DAY)
    mcp_exec_default_timeout: int = Field(default=600, ge=1, le=7 * DAY)
    mcp_serve_2025_11_25: bool = False
    mcp_tasks_extension: bool = False
    mcp_allow_developer_credentials: bool = False
    output_chunk_max: int = Field(default=256 * KIB, ge=1, le=16 * MIB)

    # ---- clients (told to them through platform info; the SDKs carry the same defaults)
    follow_max: float = Field(default=1800.0, gt=0, le=7 * DAY)
    sdk_request_timeout: float = Field(default=120.0, gt=0, le=3600)
    sdk_max_retries: int = Field(default=2, ge=0, le=20)
    sdk_backoff_initial: float = Field(default=0.5, gt=0, le=60)
    sdk_backoff_max: float = Field(default=8.0, gt=0, le=600)
    retry_budget_ratio: float = Field(default=0.2, ge=0, lt=1)

    # ---- idempotency and recovery
    #: Life of a ledger entry. ``None``: the host's operation retention plus the safety margin. It has no
    #: upper limit of its own, so "finite" is stated here: an entry that never expired would be no bound.
    idempotency_retention: float | None = Field(default=None, gt=0, allow_inf_nan=False)
    idempotency_safety_margin: float = Field(default=float(HOUR), gt=0, le=30 * DAY)
    idempotency_key_max_len: int = Field(default=255, ge=1, le=255)
    claim_stale_after: float = Field(default=120.0, gt=0, le=DAY)
    recovery_sweep_interval: float = Field(default=60.0, gt=0, le=DAY)

    # ---- credentials
    credential_revocation_bound: float = Field(default=60.0, gt=0, le=3600)
    containment_auth_cache_ttl: float = Field(default=60.0, gt=0, le=3600)
    credential_max_lifetime: float = Field(default=365.0 * DAY, gt=0, le=3650.0 * DAY)
    agent_credential_max_lifetime: float = Field(default=float(DAY), gt=0, le=3650.0 * DAY)
    agent_expiry_grace: float = Field(default=300.0, ge=0, le=DAY)
    agent_label_max_len: int = Field(default=64, ge=1, le=64)
    auth_deadline: float = Field(default=2.0, gt=0, le=60)
    jwks_refresh_interval: float = Field(default=600.0, gt=0, le=DAY)
    jwks_forced_refresh_min_interval: float = Field(default=60.0, gt=0, le=DAY)
    oauth_token_max_lifetime: float = Field(default=float(HOUR), gt=0, le=30 * DAY)

    # ---- the store and audit
    store_deadline: float = Field(default=5.0, gt=0, le=120)
    store_reserve_bytes: int = Field(default=64 * MIB, gt=0)
    audit_budget_bytes: int = Field(default=1024 * MIB, ge=1 * MIB)
    audit_retention: float = Field(default=90.0 * DAY, gt=0, le=3650.0 * DAY)
    audit_required: bool = False
    drain_timeout: float = Field(default=30.0, ge=0, le=3600)

    # ---- published promises
    api_deprecation_window_days: int = Field(default=183, ge=1, le=3650)
    dx_time_budget: float = Field(default=600.0, gt=0, le=DAY)

    # ------------------------------------------------------------------ derived values
    def usable_ops_per_minute(self, host_ops_allowance: int | None = None) -> float:
        """The host's operation allowance for one peer, less the reserve kept for containment and resolution."""
        allowance = host_ops_allowance if host_ops_allowance is not None else self.host_ops_allowance
        return allowance * (1.0 - self.host_allowance_reserve)

    def usable_reads_per_minute(self, host_reads_allowance: int | None = None) -> float:
        allowance = host_reads_allowance if host_reads_allowance is not None else self.host_reads_allowance
        return allowance * (1.0 - self.host_allowance_reserve)

    def reserved_reads_per_minute(self, host_reads_allowance: int | None = None) -> float:
        """Reads kept for resolution and the follower."""
        allowance = host_reads_allowance if host_reads_allowance is not None else self.host_reads_allowance
        return allowance * self.host_allowance_reserve

    def project_ops_per_minute(self, share: float | None = None) -> float:
        """A project's ceiling for requests that create host operations."""
        ceiling = self.usable_ops_per_minute() * (share if share is not None else self.project_default_share)
        return min(ceiling, float(self.project_rate)) if self.project_rate is not None else ceiling

    def principal_ops_per_minute(self, share: float | None = None) -> float:
        ceiling = self.project_ops_per_minute(share)
        return min(ceiling, float(self.principal_rate)) if self.principal_rate is not None else ceiling

    def project_reads_per_minute(self, share: float | None = None) -> float:
        return self.usable_reads_per_minute() * (share if share is not None else self.project_default_share)

    def general_host_connections(self) -> int:
        """Connections that serve granting work and reads: what is left after the two reserves."""
        return self.host_max_connections - self.host_conn_reserved_containment - self.host_conn_reserved_resolution

    def retention(self, host_operation_retention_s: float | None) -> float:
        """Life of a ledger entry, given what the host says about its own operation retention."""
        if self.idempotency_retention is not None:
            return self.idempotency_retention
        base = host_operation_retention_s if host_operation_retention_s is not None else float(DAY)
        return base + self.idempotency_safety_margin

    def quota_sandboxes(self) -> int:
        """Live sandboxes a project may have: the operator's number, or the project's share of what the host admits.

        Always a number. A quota that waited for somebody to supply it would be a bound that ships switched off.
        """
        if self.project_max_live_sandboxes is not None:
            return self.project_max_live_sandboxes
        return max(1, int(self.host_max_sandboxes * self.project_default_share))

    def quota_snapshots(self) -> int:
        """Snapshots a project may have. As for sandboxes."""
        if self.project_max_snapshots is not None:
            return self.project_max_snapshots
        return max(1, int(self.host_max_snapshots * self.project_default_share))

    def public(self) -> dict[str, int | float | bool]:
        """The parameters a caller depends on. Shown to an authenticated caller only."""
        return {
            "public_wait_max": self.public_wait_max,
            "max_public_request_bytes": self.max_public_request_bytes,
            "output_chunk_max": self.output_chunk_max,
            "mcp_tool_wait": self.mcp_tool_wait,
            "mcp_inline_output_max": self.mcp_inline_output_max,
            "mcp_exec_default_timeout": self.mcp_exec_default_timeout,
            "follow_max": self.follow_max,
            "sdk_request_timeout": self.sdk_request_timeout,
            "sdk_max_retries": self.sdk_max_retries,
            "sdk_backoff_initial": self.sdk_backoff_initial,
            "sdk_backoff_max": self.sdk_backoff_max,
            "retry_budget_ratio": self.retry_budget_ratio,
            "idempotency_key_max_len": self.idempotency_key_max_len,
            "agent_credential_max_lifetime": self.agent_credential_max_lifetime,
            "agent_expiry_grace": self.agent_expiry_grace,
            "api_deprecation_window_days": self.api_deprecation_window_days,
        }


def violations(p: Parameters) -> list[str]:
    """Every violated relation among the platform's own parameters. Empty: the configuration may start."""
    out: list[str] = []

    def need(ok: bool, text: str) -> None:  # noqa: FBT001 - a two-argument assertion helper
        if not ok:
            out.append(text)

    need(
        p.edge_core_deadline_margin < p.server_deadline_margin,
        "edge_core_deadline_margin must be less than server_deadline_margin",
    )
    need(
        p.general_host_connections() >= 2,  # noqa: PLR2004 - the relation is stated with this number
        "host_max_connections less host_conn_reserved_containment and host_conn_reserved_resolution must be at least 2",
    )
    need(
        p.project_max_in_flight >= p.principal_max_in_flight,
        "project_max_in_flight must not be less than principal_max_in_flight",
    )
    if p.principal_rate is not None:
        need(
            p.principal_rate <= p.usable_ops_per_minute() * p.project_default_share,
            "principal_rate must not exceed the project's share of the usable host allowance",
        )
    if p.project_rate is not None:
        need(
            p.project_rate <= p.usable_ops_per_minute() * p.project_default_share,
            "project_rate must not exceed the project's share of the usable host allowance",
        )
    need(
        p.follow_poll_interval_min < p.follow_poll_interval_max,
        "follow_poll_interval_min must be less than follow_poll_interval_max",
    )
    if p.project_max_live_sandboxes is not None:
        need(
            p.project_max_live_sandboxes <= p.host_max_sandboxes,
            "project_max_live_sandboxes must not exceed host_max_sandboxes, the host envelope's sandbox count",
        )
    if p.project_max_snapshots is not None:
        need(
            p.project_max_snapshots <= p.host_max_snapshots,
            "project_max_snapshots must not exceed host_max_snapshots, the host's snapshot count",
        )
    # Two surfaces of the register that this build does not have. Each stays a parameter, off by default,
    # so that the register is whole. Turned on, it would promise what nothing here serves.
    need(
        not p.mcp_serve_2025_11_25,
        "mcp_serve_2025_11_25 must be false: revision 2025-11-25 of the agent protocol is not built into this version",
    )
    need(
        not p.mcp_tasks_extension,
        "mcp_tasks_extension must be false: the tasks extension of the agent protocol is not built into this version",
    )
    need(p.mcp_tool_wait <= p.public_wait_max, "mcp_tool_wait must not exceed public_wait_max")
    need(p.mcp_inline_output_max <= p.output_chunk_max, "mcp_inline_output_max must not exceed output_chunk_max")
    need(p.mcp_adoption_window > p.mcp_tool_wait, "mcp_adoption_window must be greater than mcp_tool_wait")
    need(
        p.sdk_request_timeout > p.public_wait_max + p.server_deadline_margin,
        "sdk_request_timeout must be greater than public_wait_max plus server_deadline_margin",
    )
    need(p.sdk_backoff_initial < p.sdk_backoff_max, "sdk_backoff_initial must be less than sdk_backoff_max")
    need(
        p.claim_stale_after > p.public_wait_max + p.server_deadline_margin,
        "claim_stale_after must be greater than public_wait_max plus server_deadline_margin",
    )
    need(
        p.containment_auth_cache_ttl <= p.credential_revocation_bound,
        "containment_auth_cache_ttl must not exceed credential_revocation_bound",
    )
    need(
        p.agent_credential_max_lifetime <= p.credential_max_lifetime,
        "agent_credential_max_lifetime must not exceed credential_max_lifetime",
    )
    if p.idempotency_retention is not None:
        need(
            p.idempotency_retention > p.idempotency_safety_margin,
            "idempotency_retention must be greater than idempotency_safety_margin",
        )
    return out


def host_violations(
    p: Parameters,
    *,
    host_wait_max_s: float | None,
    host_operation_retention_s: float | None,
    host_acceptance_horizon_s: float | None,
    host_max_request_bytes: int | None,
    host_output_chunk_max: int | None = None,
    host_identifier_slots: int | None = None,
) -> list[str]:
    """Violated relations to values of the host, for the values the host advertises."""
    out: list[str] = []
    if host_wait_max_s is not None and p.host_call_wait > host_wait_max_s:
        out.append("host_call_wait must not exceed the host's wait_max")
    if host_operation_retention_s is not None and p.idempotency_retention is not None:
        floor = host_operation_retention_s + p.idempotency_safety_margin
        if p.idempotency_retention < floor:
            out.append(
                "idempotency_retention must be at least the host's operation_retention plus idempotency_safety_margin"
            )
    if (
        host_acceptance_horizon_s is not None
        and p.claim_stale_after + p.recovery_sweep_interval >= host_acceptance_horizon_s
    ):
        out.append("claim_stale_after plus recovery_sweep_interval must be shorter than the host's acceptance_horizon")
    if host_max_request_bytes is not None and host_max_request_bytes < 4 * KIB:
        out.append("the host's max_request_bytes is too small for any request of the platform")
    if host_output_chunk_max is not None and p.output_chunk_max > host_output_chunk_max:
        out.append("output_chunk_max must not exceed the host's bound for one output chunk")
    # The host gives every sandbox an identifier of its own, so it admits no more sandboxes than it has
    # identifiers. The pool is the one number about its capacity that the host advertises: it cannot confirm
    # the configured count, and it can show that the count is wrong.
    if host_identifier_slots is not None and p.host_max_sandboxes > host_identifier_slots:
        out.append("host_max_sandboxes must not exceed the host's identifier pool: it is not the host's sandbox count")
    return out
