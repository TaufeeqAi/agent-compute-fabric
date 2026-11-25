"""The public operations, in one table.

Every interface is a projection of this table: the REST routes, the tool catalogue of the agent
interface, the reversibility classes and the generated contract artifacts under ``protocols/``. A
public operation is exactly one host operation, or a read, or a platform operation that reaches no
host. Nothing here composes two.

``host_method`` is also the ``step`` input of the operation-id derivation, so it is part of what makes
one idempotency key mean one host operation. Changing it for an existing method is a new derivation
version, never an edit.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from acf_api.command.model import Reversibility


class OperationClass(StrEnum):
    """The class of a public operation, taken from the host's."""

    #: Removes privilege: stop, destroy, cancel, delete. Never refused for load.
    CONTAINMENT = "containment"
    #: Creates privilege or work: create, start, exec, snapshot, restore.
    GRANTING = "granting"
    READ = "read"
    #: Changes the platform's own records and reaches no host.
    PLATFORM = "platform"


@dataclass(frozen=True, slots=True)
class ToolAnnotations:
    """Hints of the agent protocol. Each states the worst case of its tool, and none is a control."""

    read_only: bool
    destructive: bool
    idempotent: bool
    open_world: bool


@dataclass(frozen=True, slots=True)
class PublicOperation:
    """One row: a public method and each of its projections."""

    #: Public method id. Grants name these.
    method: str
    operation_class: OperationClass
    #: The host method it maps to, and the ``step`` of the derivation. ``None``: reaches no host.
    host_method: str | None
    #: Command type on the command interface.
    command: str
    http_method: str
    #: Path template under the API root.
    path: str
    #: Tool name on the agent interface. ``None``: never a tool.
    tool: str | None
    annotations: ToolAnnotations | None
    #: The worst rollback class the operation can have.
    reversibility: Reversibility | None
    #: Whether a REST request must carry ``Idempotency-Key``.
    keyed: bool
    summary: str
    sdk: str
    cli: str


_P: Final = "/v1/projects/{project}"

_READ: Final = ToolAnnotations(read_only=True, destructive=False, idempotent=True, open_world=False)
_ADD: Final = ToolAnnotations(read_only=False, destructive=False, idempotent=False, open_world=False)
_REMOVE: Final = ToolAnnotations(read_only=False, destructive=True, idempotent=True, open_world=False)

OPERATIONS: Final[tuple[PublicOperation, ...]] = (
    PublicOperation(
        "sandbox.create",
        OperationClass.GRANTING,
        "sandbox.create",
        "create_sandbox",
        "POST",
        f"{_P}/sandboxes",
        "sandbox_create",
        _ADD,
        Reversibility.COMPENSATABLE,
        keyed=True,
        summary="Create a sandbox. It is created and not started.",
        sdk="sandboxes.create()",
        cli="acf sandbox create",
    ),
    PublicOperation(
        "sandbox.start",
        OperationClass.GRANTING,
        "sandbox.start",
        "start_sandbox",
        "POST",
        f"{_P}/sandboxes/{{sandbox}}/start",
        "sandbox_start",
        _ADD,
        Reversibility.COMPENSATABLE,
        keyed=True,
        summary="Start a sandbox that was created and has not been started.",
        sdk="sandbox.start()",
        cli="acf sandbox start",
    ),
    PublicOperation(
        "execution.create",
        OperationClass.GRANTING,
        "exec.run",
        "exec",
        "POST",
        f"{_P}/sandboxes/{{sandbox}}/executions",
        "sandbox_exec",
        # The worst case is a sandbox with network `allowlist`: effects outside it are not undone.
        ToolAnnotations(read_only=False, destructive=True, idempotent=False, open_world=True),
        Reversibility.IRREVERSIBLE,
        keyed=True,
        summary="Run one command in a started sandbox.",
        sdk="sandbox.exec()",
        cli="acf exec run",
    ),
    PublicOperation(
        "execution.get",
        OperationClass.READ,
        "run.inspect",
        "get_execution",
        "GET",
        f"{_P}/executions/{{execution}}",
        "exec_status",
        _READ,
        None,
        keyed=False,
        summary="Read the status and result of an execution.",
        sdk="executions.get()",
        cli="acf exec status",
    ),
    PublicOperation(
        "execution.output",
        OperationClass.READ,
        "run.output",
        "get_execution_output",
        "GET",
        f"{_P}/executions/{{execution}}/output",
        "exec_output",
        _READ,
        None,
        keyed=False,
        summary="Read a slice of one output stream of an execution that has ended.",
        sdk="execution.output()",
        cli="acf exec output",
    ),
    PublicOperation(
        "execution.cancel",
        OperationClass.CONTAINMENT,
        "operation.cancel",
        "cancel_execution",
        "POST",
        f"{_P}/executions/{{execution}}/cancel",
        "exec_cancel",
        _REMOVE,
        Reversibility.IRREVERSIBLE,
        keyed=True,
        summary="Cancel a running execution on the host.",
        sdk="execution.cancel()",
        cli="acf exec cancel",
    ),
    PublicOperation(
        "snapshot.create",
        OperationClass.GRANTING,
        "snapshot.create",
        "create_snapshot",
        "POST",
        f"{_P}/sandboxes/{{sandbox}}/snapshots",
        "sandbox_snapshot",
        _ADD,
        Reversibility.COMPENSATABLE,
        keyed=True,
        summary="Take a snapshot of a sandbox.",
        sdk="sandbox.snapshot()",
        cli="acf snapshot create",
    ),
    PublicOperation(
        "snapshot.restore",
        OperationClass.GRANTING,
        "snapshot.restore",
        "restore_snapshot",
        "POST",
        f"{_P}/snapshots/{{snapshot}}/restore",
        "sandbox_restore",
        # In place, the replaced generation is retired for good.
        ToolAnnotations(read_only=False, destructive=True, idempotent=False, open_world=False),
        Reversibility.IRREVERSIBLE,
        keyed=True,
        summary="Restore a snapshot, into an existing sandbox or as a new one.",
        sdk="sandbox.restore()",
        cli="acf snapshot restore",
    ),
    PublicOperation(
        "sandbox.list",
        OperationClass.READ,
        "sandbox.list",
        "list_sandboxes",
        "GET",
        f"{_P}/sandboxes",
        "sandbox_list",
        _READ,
        None,
        keyed=False,
        summary="List the sandboxes of the project.",
        sdk="sandboxes.list()",
        cli="acf sandbox list",
    ),
    PublicOperation(
        "sandbox.get",
        OperationClass.READ,
        "sandbox.inspect",
        "get_sandbox",
        "GET",
        f"{_P}/sandboxes/{{sandbox}}",
        "sandbox_inspect",
        _READ,
        None,
        keyed=False,
        summary="Read one sandbox, by identifier or by name.",
        sdk="sandboxes.get()",
        cli="acf sandbox inspect",
    ),
    PublicOperation(
        "snapshot.list",
        OperationClass.READ,
        "snapshot.list",
        "list_snapshots",
        "GET",
        f"{_P}/snapshots",
        "snapshot_list",
        _READ,
        None,
        keyed=False,
        summary="List the snapshots of the project.",
        sdk="snapshots.list()",
        cli="acf snapshot list",
    ),
    PublicOperation(
        "sandbox.stop",
        OperationClass.CONTAINMENT,
        "sandbox.stop",
        "stop_sandbox",
        "POST",
        f"{_P}/sandboxes/{{sandbox}}/stop",
        "sandbox_stop",
        _REMOVE,
        Reversibility.IRREVERSIBLE,
        keyed=True,
        summary="Stop a sandbox. A running execution is cancelled.",
        sdk="sandbox.stop()",
        cli="acf sandbox stop",
    ),
    PublicOperation(
        "sandbox.destroy",
        OperationClass.CONTAINMENT,
        "sandbox.destroy",
        "destroy_sandbox",
        "DELETE",
        f"{_P}/sandboxes/{{sandbox}}",
        "sandbox_destroy",
        _REMOVE,
        Reversibility.IRREVERSIBLE,
        keyed=True,
        summary="Destroy a sandbox. It is never resurrected.",
        sdk="sandbox.destroy()",
        cli="acf sandbox destroy",
    ),
    PublicOperation(
        "snapshot.delete",
        OperationClass.CONTAINMENT,
        "snapshot.delete",
        "delete_snapshot",
        "DELETE",
        f"{_P}/snapshots/{{snapshot}}",
        "snapshot_delete",
        _REMOVE,
        Reversibility.IRREVERSIBLE,
        keyed=True,
        summary="Delete a snapshot. It is never resurrected.",
        sdk="snapshot.delete()",
        cli="acf snapshot delete",
    ),
    PublicOperation(
        "operation.get",
        OperationClass.READ,
        "operation.get",
        "get_operation",
        "GET",
        f"{_P}/operations/{{operation}}",
        "operation_get",
        _READ,
        None,
        keyed=False,
        summary="Read an operation, or wait for it to end.",
        sdk="operations.get()",
        cli="acf operation get",
    ),
    PublicOperation(
        "operation.list",
        OperationClass.READ,
        "operation.list",
        "list_operations",
        "GET",
        f"{_P}/operations",
        None,
        None,
        None,
        keyed=False,
        summary="List the operations of the project.",
        sdk="operations.list()",
        cli="acf operation list",
    ),
    PublicOperation(
        "agent_credential.mint",
        OperationClass.PLATFORM,
        None,
        "mint_agent_credential",
        "POST",
        f"{_P}/agent-credentials",
        None,
        None,
        None,
        keyed=False,
        summary="Mint an agent credential, narrower and shorter-lived than the credential that mints it.",
        sdk="auth.mint_agent_credential()",
        cli="acf auth agent-key create",
    ),
    PublicOperation(
        "agent_credential.list",
        OperationClass.READ,
        None,
        "list_agent_credentials",
        "GET",
        f"{_P}/agent-credentials",
        None,
        None,
        None,
        keyed=False,
        summary="List the agent credentials this credential minted.",
        sdk="auth.agent_credentials()",
        cli="acf auth agent-key list",
    ),
    PublicOperation(
        "agent_credential.revoke",
        OperationClass.PLATFORM,
        None,
        "revoke_agent_credential",
        "DELETE",
        f"{_P}/agent-credentials/{{credential}}",
        None,
        None,
        None,
        keyed=False,
        summary="Revoke an agent credential this credential minted. Revoking twice is the same as revoking once.",
        sdk="auth.revoke_agent_credential()",
        cli="acf auth agent-key revoke",
    ),
    PublicOperation(
        "platform.info",
        OperationClass.READ,
        "host.info",
        "info",
        "GET",
        "/v1/info",
        "health_check",
        _READ,
        None,
        keyed=False,
        summary="Platform info: API versions and, for an authenticated caller, features, parameters and ceilings.",
        sdk="fabric.info()",
        cli="acf info",
    ),
    PublicOperation(
        "auth.whoami",
        OperationClass.READ,
        None,
        "whoami",
        "GET",
        "/v1/auth/whoami",
        None,
        None,
        None,
        keyed=False,
        summary="The calling credential's principal, project and effective grants.",
        sdk="fabric.whoami()",
        cli="acf policy inspect",
    ),
)

BY_METHOD: Final[dict[str, PublicOperation]] = {op.method: op for op in OPERATIONS}
BY_COMMAND: Final[dict[str, PublicOperation]] = {op.command: op for op in OPERATIONS}
BY_TOOL: Final[dict[str, PublicOperation]] = {op.tool: op for op in OPERATIONS if op.tool is not None}

#: Host methods the platform never calls. The enrolled peer has role ``caller``, so the host refuses
#: them as well. No row above may name one.
HOST_OPERATOR_METHODS: Final = frozenset({"profile.reload", "quarantine.release", "host.set_mode", "host.acknowledge"})

#: Tools that create a record whose duplicate the host refuses by name: called through an agent protocol
#: they require a ``name``, which is a second fence when a dropped call is re-issued with a change.
TOOLS_REQUIRING_NAME: Final = frozenset({"sandbox_create", "sandbox_snapshot"})

#: Methods that count against a quota, and what they count.
QUOTA_SANDBOX_METHODS: Final = frozenset({"sandbox.create"})
QUOTA_SNAPSHOT_METHODS: Final = frozenset({"snapshot.create"})

#: Platform features an authenticated caller may see advertised. `create_with_start` is not among them:
#: the host protocol this version speaks has no operation that creates and starts, and the platform builds
#: none from two. The name is the reason a request with `start: true` is refused with.
PLATFORM_FEATURES: Final = ("agent_credentials", "long_poll", "idempotency_replay")
FEATURE_CREATE_WITH_START: Final = "create_with_start"
FEATURE_SECRET_INJECTION: Final = "secret_injection"  # noqa: S105 - the name of a feature, not a secret
FEATURE_ALLOWLIST_NETWORK: Final = "allowlist_network"

#: Host features the platform requires before it serves granting work.
REQUIRED_HOST_FEATURES: Final = ("scope_tags", "operation_list")
HOST_PROTOCOLS: Final = ("acf.host/2",)


def operation_for_command(command: str) -> PublicOperation:
    return BY_COMMAND[command]


def mutating_commands() -> frozenset[str]:
    """Command types that can create a host operation."""
    return frozenset(
        op.command for op in OPERATIONS if op.operation_class in {OperationClass.GRANTING, OperationClass.CONTAINMENT}
    )


def containment_commands() -> frozenset[str]:
    return frozenset(op.command for op in OPERATIONS if op.operation_class is OperationClass.CONTAINMENT)
