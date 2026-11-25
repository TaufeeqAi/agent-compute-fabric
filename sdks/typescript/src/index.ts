/**
 * `@agent-compute/sdk`: the TypeScript SDK of Agent Compute Fabric.
 *
 * The client and the errors are values. Everything a client returns (handles, views, the resources
 * of a client) is exported as a type only: such an object is obtained from a client, never
 * constructed by a caller.
 */

export { Fabric } from "./client.js";
export { VERSION } from "./version.js";

export {
  APIConnectionError,
  APIError,
  APITimeoutError,
  AuthenticationError,
  CapacityError,
  ConfigurationError,
  ConflictError,
  CursorExpiredError,
  FabricError,
  IdempotencyConflictError,
  IncompatibleRuntimeError,
  IncompatibleServerError,
  IntegrityFailureError,
  InternalError,
  InvalidRequestError,
  NameReboundError,
  NotFoundError,
  OperationError,
  OperationFailedError,
  OperationStillRunningError,
  OutcomeLostError,
  OutcomeUnknownError,
  OutcomeUnresolvedError,
  PermissionDeniedError,
  QuarantinedError,
  RateLimitError,
  RefusedError,
  RequestInProgressError,
  RevisionConflictError,
  SafetyControlDeniedError,
  SandboxStartError,
  ServiceUnavailableError,
  StateConflictError,
  UnexpectedResponseError,
  UnresolvedError,
  UnsupportedFeatureError,
} from "./errors.js";
export type { APIErrorFields, FabricErrorOptions, StartCleanup } from "./errors.js";

export type { AgentCredential, Auth, ContainmentFailure, WhoAmI } from "./auth.js";
export type { Info } from "./client.js";
export type { Execution, Executions, OutputChunk } from "./execution.js";
export type { Operation, Operations } from "./operation.js";
export type { Sandbox, Sandboxes } from "./sandbox.js";
export type { Snapshot, Snapshots } from "./snapshot.js";

export type {
  Actor,
  AgentCredentialView,
  AllowEntryView,
  AllowName,
  AllowNetwork,
  CallOptions,
  Ceilings,
  Clock,
  CredentialView,
  Duration,
  Durations,
  ExecOptions,
  ExecutionView,
  FabricOptions,
  Failure,
  Fetch,
  FetchRequest,
  FetchResponse,
  Generation,
  Image,
  InfoView,
  JsonObject,
  MintAgentCredentialOptions,
  MutationOptions,
  Network,
  NetworkAllowlist,
  NetworkView,
  Normalized,
  OperationGetOptions,
  OperationResult,
  OperationTarget,
  OperationView,
  OperationWaitOptions,
  OutputChunkView,
  OutputOptions,
  OutputStream,
  OutputSummary,
  Port,
  PortRangeView,
  Random,
  Raw,
  RefreshOptions,
  ResourcesView,
  RestoreAsNewOptions,
  RevokeAgentCredentialOptions,
  SandboxCreateOptions,
  SandboxMutationOptions,
  SandboxRef,
  SandboxView,
  Size,
  Sleep,
  SnapshotRef,
  SnapshotView,
  TextOptions,
  WhoAmIView,
} from "./types.js";
