/**
 * The errors of the SDK.
 *
 * An unsuccessful answer of the platform is one of two kinds, and the classes keep them apart:
 *
 * - `RefusedError`: the request was not accepted. Nothing exists: no operation, no reservation.
 * - `UnresolvedError`: the platform could not establish whether the request was accepted. An
 *   operation may exist. The caller asks again with the same idempotency key, never a new one.
 *
 * A request that was accepted never produces either. Its outcome is the operation's, and an
 * operation that did not succeed is reported by the `OperationError` family.
 *
 * The class of an error answer is chosen from its `code` (the table is the platform's problem
 * registry), and for a code this version has never seen from its `kind`. No decision is taken from
 * the HTTP status alone or from message text.
 */

import type { Operation } from "./operation.js";

/**
 * Gives a class its name as a literal. `constructor.name` would not survive a minifier, and callers
 * read `error.name` in logs.
 */
function named(target: { readonly prototype: object }, name: string): void {
  Object.defineProperty(target.prototype, "name", { value: name, writable: true, configurable: true });
}

/** Options every error of the SDK accepts. */
export interface FabricErrorOptions {
  readonly requestId?: string | undefined;
  readonly cause?: unknown;
}

/** The base of every error this SDK throws on purpose. */
export class FabricError extends Error {
  static {
    named(this, "FabricError");
  }

  /** The request id of the answer the error came from, when there was one. Quote it when asking for help. */
  readonly requestId: string | undefined;

  constructor(message: string, options: FabricErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.requestId = options.requestId;
  }
}

/** The client was configured in a way that cannot work. Thrown before any request. */
export class ConfigurationError extends FabricError {
  static {
    named(this, "ConfigurationError");
  }
}

/** The server does not speak the API major this SDK requires. */
export class IncompatibleServerError extends ConfigurationError {
  static {
    named(this, "IncompatibleServerError");
  }
}

/**
 * No answer arrived. For a read, nothing can be said. For a mutation the SDK raises this only when
 * it could not repeat the request safely; whether the request was accepted is then not known.
 */
export class APIConnectionError extends FabricError {
  static {
    named(this, "APIConnectionError");
  }
}

/** No answer arrived within the request timeout. */
export class APITimeoutError extends APIConnectionError {
  static {
    named(this, "APITimeoutError");
  }
}

/**
 * An answer arrived that the SDK cannot use: it is neither a success nor an error answer of the
 * platform, or it lacks what the call needs (an identifier, or the result of an operation that
 * succeeded). Never retried.
 */
export class UnexpectedResponseError extends FabricError {
  static {
    named(this, "UnexpectedResponseError");
  }

  /** The HTTP status of the answer, when the fault was in an HTTP answer. */
  readonly status: number | undefined;

  constructor(message: string, options: FabricErrorOptions & { readonly status?: number | undefined } = {}) {
    super(message, options);
    this.status = options.status;
  }
}

/** The members of an error answer. */
export interface APIErrorFields {
  /** The HTTP status. A hint only. Absent when the SDK raised the error without an answer. */
  readonly status: number | undefined;
  /** The authoritative code. A plain string: a code this version does not know is kept as it is. */
  readonly code: string;
  /** `REFUSED` or `UNRESOLVED`, or a value this version does not know. */
  readonly kind: string;
  /** `SAME_REQUEST_LATER`, `AFTER_CHANGE` or `NEVER`, or a value this version does not know. */
  readonly retry: string;
  readonly requestId: string | undefined;
  /** On an unresolved answer: the key to ask again with, unchanged. */
  readonly idempotencyKey: string | undefined;
  /** A bounded reason code that refines `code`. */
  readonly reason: string | undefined;
  /** Seconds the server asked the caller to wait before asking again. */
  readonly retryAfter: number | undefined;
}

/** An error answer of the platform. `message` is the platform's own text. */
export class APIError extends FabricError implements APIErrorFields {
  static {
    named(this, "APIError");
  }

  readonly status: number | undefined;
  readonly code: string;
  readonly kind: string;
  readonly retry: string;
  readonly idempotencyKey: string | undefined;
  readonly reason: string | undefined;
  readonly retryAfter: number | undefined;

  constructor(message: string, fields: APIErrorFields, options: { readonly cause?: unknown } = {}) {
    super(message, { requestId: fields.requestId, cause: options.cause });
    this.status = fields.status;
    this.code = fields.code;
    this.kind = fields.kind;
    this.retry = fields.retry;
    this.idempotencyKey = fields.idempotencyKey;
    this.reason = fields.reason;
    this.retryAfter = fields.retryAfter;
  }
}

/** The request was not accepted. Nothing exists. Also thrown as it is for a code this version does not know. */
export class RefusedError extends APIError {
  static {
    named(this, "RefusedError");
  }
}

export class InvalidRequestError extends RefusedError {
  static {
    named(this, "InvalidRequestError");
  }
}

export class AuthenticationError extends RefusedError {
  static {
    named(this, "AuthenticationError");
  }
}

export class PermissionDeniedError extends RefusedError {
  static {
    named(this, "PermissionDeniedError");
  }
}

export class SafetyControlDeniedError extends RefusedError {
  static {
    named(this, "SafetyControlDeniedError");
  }
}

export class NotFoundError extends RefusedError {
  static {
    named(this, "NotFoundError");
  }
}

/** The generation or revision the request named is no longer the sandbox's. Refresh the handle and decide. */
export class RevisionConflictError extends RefusedError {
  static {
    named(this, "RevisionConflictError");
  }
}

/** The idempotency key was already used for a different request. Another key is never tried for the caller. */
export class IdempotencyConflictError extends RefusedError {
  static {
    named(this, "IdempotencyConflictError");
  }
}

export class RateLimitError extends RefusedError {
  static {
    named(this, "RateLimitError");
  }
}

export class CapacityError extends RefusedError {
  static {
    named(this, "CapacityError");
  }
}

export class ServiceUnavailableError extends RefusedError {
  static {
    named(this, "ServiceUnavailableError");
  }
}

export class UnsupportedFeatureError extends RefusedError {
  static {
    named(this, "UnsupportedFeatureError");
  }
}

export class CursorExpiredError extends RefusedError {
  static {
    named(this, "CursorExpiredError");
  }
}

export class InternalError extends RefusedError {
  static {
    named(this, "InternalError");
  }
}

/** The target is in a condition that does not allow the request. */
export class ConflictError extends RefusedError {
  static {
    named(this, "ConflictError");
  }
}

export class StateConflictError extends ConflictError {
  static {
    named(this, "StateConflictError");
  }
}

export class QuarantinedError extends ConflictError {
  static {
    named(this, "QuarantinedError");
  }
}

export class IntegrityFailureError extends ConflictError {
  static {
    named(this, "IntegrityFailureError");
  }
}

export class IncompatibleRuntimeError extends ConflictError {
  static {
    named(this, "IncompatibleRuntimeError");
  }
}

/** The platform could not establish whether the request was accepted. An operation may exist. */
export class UnresolvedError extends APIError {
  static {
    named(this, "UnresolvedError");
  }
}

/** An earlier request with the same key is still being decided. Retried automatically, with the same key. */
export class RequestInProgressError extends UnresolvedError {
  static {
    named(this, "RequestInProgressError");
  }
}

/**
 * Whether the request was accepted is still not known after every retry. `idempotencyKey` is the
 * key to ask again with, later, with the same arguments. A new key would risk a second operation.
 */
export class OutcomeUnresolvedError extends UnresolvedError {
  static {
    named(this, "OutcomeUnresolvedError");
  }
}

/**
 * The platform accepted the key and can no longer say what became of the work. Never retried, with
 * this key or with another: inspect the target before acting again.
 */
export class OutcomeLostError extends UnresolvedError {
  static {
    named(this, "OutcomeLostError");
  }
}

type APIErrorClass = new (message: string, fields: APIErrorFields) => APIError;

/**
 * Code to class, as the column `sdk_exception` of the platform's problem registry has it. A test
 * reads the registry and holds this table equal to it. A `Map`, because a code is server text and
 * must never be looked up among the properties every object inherits.
 */
const CLASS_OF_CODE: ReadonlyMap<string, APIErrorClass> = new Map<string, APIErrorClass>([
  ["INVALID_REQUEST", InvalidRequestError],
  ["UNAUTHENTICATED", AuthenticationError],
  ["PERMISSION_DENIED", PermissionDeniedError],
  ["SAFETY_CONTROL_DENIED", SafetyControlDeniedError],
  ["NOT_FOUND", NotFoundError],
  ["STATE_CONFLICT", StateConflictError],
  ["QUARANTINED", QuarantinedError],
  ["REVISION_CONFLICT", RevisionConflictError],
  ["IDEMPOTENCY_CONFLICT", IdempotencyConflictError],
  ["REQUEST_IN_PROGRESS", RequestInProgressError],
  ["RATE_LIMITED", RateLimitError],
  ["RESOURCE_EXHAUSTED", CapacityError],
  ["HOST_NOT_SERVING", ServiceUnavailableError],
  ["UNSUPPORTED", UnsupportedFeatureError],
  ["REQUEST_TOO_LARGE", InvalidRequestError],
  ["CURSOR_EXPIRED", CursorExpiredError],
  ["INTEGRITY_FAILURE", IntegrityFailureError],
  ["INCOMPATIBLE_RUNTIME", IncompatibleRuntimeError],
  ["CLOCK_SKEW", ServiceUnavailableError],
  ["UPSTREAM_UNAVAILABLE", ServiceUnavailableError],
  ["OUTCOME_UNRESOLVED", OutcomeUnresolvedError],
  ["OUTCOME_LOST", OutcomeLostError],
  ["INTERNAL_ERROR", InternalError],
  ["UNRECOGNIZED", RefusedError],
]);

/**
 * The error for an error answer. A code this version knows has its class. Any other is handled by
 * its kind: `UNRESOLVED` is an `UnresolvedError`; `REFUSED`, or a kind this version does not know
 * either, is a `RefusedError`.
 */
export function errorForAnswer(message: string, fields: APIErrorFields): APIError {
  const known = CLASS_OF_CODE.get(fields.code);
  if (known !== undefined) {
    return new known(message, fields);
  }
  return fields.kind === "UNRESOLVED" ? new UnresolvedError(message, fields) : new RefusedError(message, fields);
}

/** An operation was accepted and did not give the caller a result. */
export class OperationError extends FabricError {
  static {
    named(this, "OperationError");
  }

  /** The operation as last seen. */
  readonly operation: Operation;
  readonly operationId: string;
  /** The key the operation was requested under, when this client requested it. */
  readonly idempotencyKey: string | undefined;
  /** The operation's failure code, when it carries one. */
  readonly code: string | undefined;

  constructor(message: string, operation: Operation, idempotencyKey: string | undefined) {
    super(message, { requestId: operation.requestId });
    this.operation = operation;
    this.operationId = operation.operation_id;
    this.idempotencyKey = idempotencyKey;
    this.code = operation.failure?.code;
  }
}

/** The operation ended without success and nothing was applied. A new request, with a new key, is allowed. */
export class OperationFailedError extends OperationError {
  static {
    named(this, "OperationFailedError");
  }
}

/**
 * The operation ended and whether it was applied is not known. Neither success nor failure:
 * inspect the target before acting again.
 */
export class OutcomeUnknownError extends OperationError {
  static {
    named(this, "OutcomeUnknownError");
  }
}

/**
 * The follow bound passed and the operation had not ended. Nothing was cancelled and nothing is
 * assumed. Follow it by `operationId`, or repeat the call with `idempotencyKey`.
 */
export class OperationStillRunningError extends OperationError {
  static {
    named(this, "OperationStillRunningError");
  }
}

/** What became of a sandbox whose start did not succeed. */
export type StartCleanup = "destroyed" | "kept" | "destroy_failed";

/** `sandboxes.create` created the sandbox, and its start was refused or ended without success. */
export class SandboxStartError extends FabricError {
  static {
    named(this, "SandboxStartError");
  }

  readonly sandboxId: string;
  /** Why the start did not succeed. */
  readonly startError: FabricError;
  /** `destroyed`, `kept`, or `destroy_failed`: in the last case the sandbox still exists. */
  readonly cleanup: StartCleanup;
  /** Why the destroy did not succeed, when `cleanup` is `destroy_failed`. */
  readonly destroyError: FabricError | undefined;
  /** The code of the start failure. */
  readonly code: string | undefined;

  constructor(
    message: string,
    fields: {
      readonly sandboxId: string;
      readonly startError: FabricError;
      readonly cleanup: StartCleanup;
      readonly destroyError?: FabricError | undefined;
    },
  ) {
    super(message, { requestId: fields.startError.requestId });
    this.sandboxId = fields.sandboxId;
    this.startError = fields.startError;
    this.cleanup = fields.cleanup;
    this.destroyError = fields.destroyError;
    this.code = codeOf(fields.startError);
  }
}

/** The name a handle was obtained by now belongs to another sandbox. The handle is unchanged. */
export class NameReboundError extends FabricError {
  static {
    named(this, "NameReboundError");
  }

  /** The name the handle was obtained by. */
  readonly sandboxName: string;
  /** The sandbox the handle acts on. */
  readonly sandboxId: string;
  /** The sandbox the name belongs to now. */
  readonly reboundTo: string;

  constructor(
    message: string,
    fields: { readonly sandboxName: string; readonly sandboxId: string; readonly reboundTo: string },
    options: FabricErrorOptions = {},
  ) {
    super(message, options);
    this.sandboxName = fields.sandboxName;
    this.sandboxId = fields.sandboxId;
    this.reboundTo = fields.reboundTo;
  }
}

/** The code an error carries: of an error answer, or of the failure of an operation. */
export function codeOf(error: unknown): string | undefined {
  return error instanceof APIError || error instanceof OperationError || error instanceof SandboxStartError
    ? error.code
    : undefined;
}
