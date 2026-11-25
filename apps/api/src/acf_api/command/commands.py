"""Commands: what an edge process may ask of the core, and nothing else.

One command per public operation, plus the three an agent-protocol adapter needs (``list_tools``,
``call_tool`` and ``discover``). Every command that acts in a project names it; the core accepts the
name only when the credential that came with the command is bound to that project.

A command never carries a principal, an owner scope, a host operation id or any value the platform
chooses. The edge has none of them to give.
"""

from __future__ import annotations

from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from acf_api.command.model import (
    CREDENTIAL_ID_PATTERN,
    EXECUTION_ID_PATTERN,
    MAX_PAGE_SIZE,
    OPERATION_ID_PATTERN,
    PROJECT_ID_PATTERN,
    SANDBOX_ID_PATTERN,
    SNAPSHOT_ID_PATTERN,
    ExecSpec,
    ExpectedGeneration,
    MintAgentCredentialSpec,
    OutputStream,
    RestoreSpec,
    SandboxSpec,
    SnapshotSpec,
)

#: A sandbox may be read by identifier or by name. Mutations take an identifier only.
SANDBOX_SELECTOR_PATTERN: Final = r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,62}$"
#: An entity tag as the platform issues it. Opaque to callers; validated before it is used.
REVISION_PATTERN: Final = r"^r[0-9]{1,20}\.[0-9a-f]{12}$"
CURSOR_PATTERN: Final = r"^[A-Za-z0-9_-]{1,512}$"

Project = Annotated[str, Field(pattern=PROJECT_ID_PATTERN)]
SandboxId = Annotated[str, Field(pattern=SANDBOX_ID_PATTERN)]
SnapshotId = Annotated[str, Field(pattern=SNAPSHOT_ID_PATTERN)]
ExecutionId = Annotated[str, Field(pattern=EXECUTION_ID_PATTERN)]
OperationId = Annotated[str, Field(pattern=OPERATION_ID_PATTERN)]
Revision = Annotated[str, Field(pattern=REVISION_PATTERN)]
Cursor = Annotated[str, Field(pattern=CURSOR_PATTERN)]
PageSize = Annotated[int, Field(ge=1, le=MAX_PAGE_SIZE)]
#: Seconds a mutation or an operation read waits for the operation to end. Capped by the core.
Wait = Annotated[int, Field(ge=0, le=3600)]


class _Command(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CreateSandbox(_Command):
    type: Literal["create_sandbox"] = "create_sandbox"
    project: Project
    spec: SandboxSpec
    wait: Wait | None = None


class StartSandbox(_Command):
    type: Literal["start_sandbox"] = "start_sandbox"
    project: Project
    sandbox_id: SandboxId
    expected_generation: ExpectedGeneration
    if_match: Revision | None = None
    wait: Wait | None = None


class StopSandbox(_Command):
    type: Literal["stop_sandbox"] = "stop_sandbox"
    project: Project
    sandbox_id: SandboxId
    expected_generation: ExpectedGeneration
    if_match: Revision | None = None
    wait: Wait | None = None


class DestroySandbox(_Command):
    type: Literal["destroy_sandbox"] = "destroy_sandbox"
    project: Project
    sandbox_id: SandboxId
    expected_generation: ExpectedGeneration
    if_match: Revision | None = None
    wait: Wait | None = None


class Exec(_Command):
    type: Literal["exec"] = "exec"
    project: Project
    sandbox_id: SandboxId
    spec: ExecSpec
    if_match: Revision | None = None
    wait: Wait | None = None


class CancelExecution(_Command):
    type: Literal["cancel_execution"] = "cancel_execution"
    project: Project
    execution_id: ExecutionId
    wait: Wait | None = None


class CreateSnapshot(_Command):
    type: Literal["create_snapshot"] = "create_snapshot"
    project: Project
    sandbox_id: SandboxId
    spec: SnapshotSpec
    if_match: Revision | None = None
    wait: Wait | None = None


class RestoreSnapshot(_Command):
    type: Literal["restore_snapshot"] = "restore_snapshot"
    project: Project
    snapshot_id: SnapshotId
    spec: RestoreSpec
    if_match: Revision | None = None
    wait: Wait | None = None


class DeleteSnapshot(_Command):
    type: Literal["delete_snapshot"] = "delete_snapshot"
    project: Project
    snapshot_id: SnapshotId
    snapshot_generation: Annotated[int, Field(ge=1)]
    wait: Wait | None = None


class GetOperation(_Command):
    type: Literal["get_operation"] = "get_operation"
    project: Project
    operation_id: OperationId
    wait: Wait | None = None


class ListOperations(_Command):
    type: Literal["list_operations"] = "list_operations"
    project: Project
    limit: PageSize | None = None
    cursor: Cursor | None = None


class GetSandbox(_Command):
    type: Literal["get_sandbox"] = "get_sandbox"
    project: Project
    sandbox: Annotated[str, Field(pattern=SANDBOX_SELECTOR_PATTERN)]


class ListSandboxes(_Command):
    type: Literal["list_sandboxes"] = "list_sandboxes"
    project: Project
    limit: PageSize | None = None
    cursor: Cursor | None = None


class ListSnapshots(_Command):
    type: Literal["list_snapshots"] = "list_snapshots"
    project: Project
    limit: PageSize | None = None
    cursor: Cursor | None = None


class GetExecution(_Command):
    type: Literal["get_execution"] = "get_execution"
    project: Project
    execution_id: ExecutionId


class GetExecutionOutput(_Command):
    type: Literal["get_execution_output"] = "get_execution_output"
    project: Project
    execution_id: ExecutionId
    stream: OutputStream = OutputStream.STDOUT
    offset: Annotated[int, Field(ge=0)] = 0
    max_bytes: Annotated[int, Field(ge=1, le=16_777_216)] | None = None


class MintAgentCredential(_Command):
    type: Literal["mint_agent_credential"] = "mint_agent_credential"
    project: Project
    spec: MintAgentCredentialSpec


class ListAgentCredentials(_Command):
    type: Literal["list_agent_credentials"] = "list_agent_credentials"
    project: Project


class RevokeAgentCredential(_Command):
    type: Literal["revoke_agent_credential"] = "revoke_agent_credential"
    project: Project
    credential_id: Annotated[str, Field(pattern=CREDENTIAL_ID_PATTERN)]


class WhoAmI(_Command):
    type: Literal["whoami"] = "whoami"


class Info(_Command):
    type: Literal["info"] = "info"


class ListTools(_Command):
    """The tool catalogue this credential may use, given what the host advertises."""

    type: Literal["list_tools"] = "list_tools"


class CallTool(_Command):
    """One tool call from an agent protocol. The core turns it into exactly one command above."""

    type: Literal["call_tool"] = "call_tool"
    name: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]
    arguments: dict[str, Any] = Field(default_factory=dict)


class Discover(_Command):
    """What an agent-protocol adapter advertises about the platform to this credential."""

    type: Literal["discover"] = "discover"


Command = Annotated[
    CreateSandbox
    | StartSandbox
    | StopSandbox
    | DestroySandbox
    | Exec
    | CancelExecution
    | CreateSnapshot
    | RestoreSnapshot
    | DeleteSnapshot
    | GetOperation
    | ListOperations
    | GetSandbox
    | ListSandboxes
    | ListSnapshots
    | GetExecution
    | GetExecutionOutput
    | MintAgentCredential
    | ListAgentCredentials
    | RevokeAgentCredential
    | WhoAmI
    | Info
    | ListTools
    | CallTool
    | Discover,
    Field(discriminator="type"),
]

COMMAND_ADAPTER: Final[TypeAdapter[Command]] = TypeAdapter(Command)

#: Commands that act in no project of their own: the credential's project is the only one there is.
PROJECTLESS: Final = frozenset({"whoami", "info", "list_tools", "call_tool", "discover"})
#: Commands an edge may send without a credential. The answer depends on nothing but the platform itself.
ANONYMOUS: Final = frozenset({"info"})


def command_types() -> tuple[str, ...]:
    """Every command type of this version of the command interface."""
    return tuple(
        sorted(
            str(member.model_fields["type"].default)
            for member in (
                CreateSandbox,
                StartSandbox,
                StopSandbox,
                DestroySandbox,
                Exec,
                CancelExecution,
                CreateSnapshot,
                RestoreSnapshot,
                DeleteSnapshot,
                GetOperation,
                ListOperations,
                GetSandbox,
                ListSandboxes,
                ListSnapshots,
                GetExecution,
                GetExecutionOutput,
                MintAgentCredential,
                ListAgentCredentials,
                RevokeAgentCredential,
                WhoAmI,
                Info,
                ListTools,
                CallTool,
                Discover,
            )
        )
    )
