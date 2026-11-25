/**
 * Operations: what every mutation is answered with, and how a call follows one to its end.
 *
 * A mutation may outlive the request that started it. Its answer is the operation, which has ended
 * only if it ended within the request's wait. A convenience call follows the operation until it has
 * ended or the follow bound passes, and then says exactly one of four things:
 *
 * - it succeeded: the resource is returned;
 * - it ended without success and nothing was applied: `OperationFailedError`;
 * - it ended and whether it was applied is not known: `OutcomeUnknownError`, never success and
 *   never failure;
 * - it has not ended: `OperationStillRunningError`, with the operation and the key.
 *
 * Following only reads. Nothing here cancels anything: not the bound, not an abandoned call.
 */

import type { ClientContext } from "./context.js";
import {
  OperationFailedError,
  OperationStillRunningError,
  OutcomeUnknownError,
  UnexpectedResponseError,
} from "./errors.js";
import { followBound, type OptionNames, optionalInteger, optionsOf, segment } from "./inputs.js";
import { collect } from "./listing.js";
import { type Call, traced } from "./telemetry.js";
import type { RequestSpec } from "./transport.js";
import type {
  Actor,
  CallOptions,
  Failure,
  JsonObject,
  Normalized,
  OperationGetOptions,
  OperationResult,
  OperationTarget,
  OperationView,
  OperationWaitOptions,
  Raw,
} from "./types.js";
import { expose, no, none, objectOf, type Shape, stringOf } from "./view.js";

/**
 * The states in which an operation has ended. The SDK decides from the state, against this list: a
 * state it has never seen is neither terminal nor success, whatever else the answer says.
 */
const ENDED_STATES: ReadonlySet<string> = new Set(["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"]);

/**
 * The longest `wait` a read of an operation asks for, in seconds. It is also the wait the platform
 * applies to a mutation that names none.
 */
const FOLLOW_WAIT_MAX = 30;
/** Between two reads, when the answer carried no `Retry-After`: this, doubling up to the cap. */
const FOLLOW_BACKOFF_INITIAL = 0.5;
const FOLLOW_BACKOFF_MAX = 5;

const OPERATION: Shape<OperationView> = {
  operation_id: true,
  project: true,
  type: true,
  type_raw: none,
  state: true,
  state_raw: none,
  terminal: true,
  effect: none,
  effect_raw: none,
  failure: none,
  cleanup: none,
  cleanup_raw: none,
  cancelled_by: none,
  cancelled_by_raw: none,
  target: true,
  result: none,
  initiated_by: true,
  initiated_by_raw: none,
  actor: none,
  created_at: none,
  updated_at: none,
  replayed: no,
  recorded: no,
  idempotency_key_digest: none,
};

/** One accepted mutation, as one answer showed it. It does not change; read it again to see it later. */
export class Operation implements Normalized<OperationView> {
  declare readonly operation_id: string;
  declare readonly project: string;
  declare readonly type: string;
  declare readonly type_raw: string | null;
  declare readonly state: string;
  declare readonly state_raw: string | null;
  declare readonly terminal: boolean;
  declare readonly effect: string | null;
  declare readonly effect_raw: string | null;
  declare readonly failure: Failure | null;
  declare readonly cleanup: string | null;
  declare readonly cleanup_raw: string | null;
  declare readonly cancelled_by: string | null;
  declare readonly cancelled_by_raw: string | null;
  declare readonly target: OperationTarget;
  declare readonly result: OperationResult | null;
  declare readonly initiated_by: string;
  declare readonly initiated_by_raw: string | null;
  declare readonly actor: Actor | null;
  declare readonly created_at: string | null;
  declare readonly updated_at: string | null;
  declare readonly replayed: boolean;
  declare readonly recorded: boolean;
  declare readonly idempotency_key_digest: string | null;
  /** The view exactly as the server sent it, with every member this version does not know. */
  declare readonly raw: Raw<OperationView>;
  /** The request id of the answer that carried this view. */
  declare readonly requestId: string | undefined;

  /** @internal */
  constructor(view: unknown, requestId: string | undefined) {
    const source = { what: "An operation", requestId };
    const checked = objectOf(view, source);
    stringOf(checked, "operation_id", source);
    stringOf(checked, "state", source);
    expose<OperationView>(this, checked, OPERATION);
    (this as { requestId: string | undefined }).requestId = requestId;
  }

  /** The view as the server sent it. */
  toJSON(): Raw<OperationView> {
    return this.raw;
  }

  toString(): string {
    return `Operation(${this.operation_id}, type=${this.type}, state=${this.state})`;
  }
}

/** Whether the operation has ended, by the states this version knows. */
export function hasEnded(operation: Operation): boolean {
  return ENDED_STATES.has(operation.state);
}

function operationPath(projectPath: string, operationId: string): string {
  return `${projectPath}/operations/${segment(operationId, "operationId")}`;
}

interface Following {
  /** Seconds of following after which the operation is reported as still running. */
  readonly bound: number;
  /** The clock when the following began. */
  readonly startedAt: number;
  /** The key the operation was requested under, when this call requested it. */
  readonly key: string | undefined;
}

/**
 * Follows an operation until it has ended, the way every client of the platform does:
 *
 * 1. After an answer in which the operation has not ended, wait `Retry-After` seconds if the
 *    answer carried it, else the backoff.
 * 2. If that wait would reach the bound, stop and report the operation as still running.
 * 3. Otherwise read the operation with `wait` = the smaller of 30 and the whole seconds left.
 */
async function follow(
  context: ClientContext,
  call: Call,
  projectPath: string,
  first: Operation,
  firstRetryAfter: number | undefined,
  following: Following,
): Promise<Operation> {
  let operation = first;
  let retryAfter = firstRetryAfter;
  let backoff = FOLLOW_BACKOFF_INITIAL;
  while (!hasEnded(operation)) {
    let delay = retryAfter;
    if (delay === undefined) {
      delay = backoff;
      backoff = Math.min(backoff * 2, FOLLOW_BACKOFF_MAX);
    }
    if (context.clock() - following.startedAt + delay >= following.bound) {
      throw new OperationStillRunningError(
        `Operation ${operation.operation_id} (${operation.type}) had not ended after ${following.bound} s of following; ` +
          `its state is ${operation.state}. Nothing was cancelled and nothing is assumed. Follow it with ` +
          `operations.wait("${operation.operation_id}")` +
          (following.key === undefined ? "." : `, or repeat the call with the same idempotency key (${following.key}).`),
        operation,
        following.key,
      );
    }
    await context.sleep(delay, call.signal);
    call.throwIfAbandoned();
    const left = following.bound - (context.clock() - following.startedAt);
    const answer = await context.transport.request({
      method: "GET",
      path: operationPath(projectPath, operation.operation_id),
      query: { wait: Math.min(FOLLOW_WAIT_MAX, Math.max(0, Math.floor(left))) },
      call,
    });
    operation = new Operation(answer.body, answer.requestId);
    retryAfter = answer.retryAfter;
  }
  return operation;
}

/** One mutation of the platform. */
export interface Mutation {
  readonly method: "POST" | "DELETE";
  /** Below the project: begins with `/`. */
  readonly path: string;
  readonly query?: RequestSpec["query"];
  readonly body?: JsonObject | undefined;
  /** The idempotency key: one per intent, fixed before the first attempt. */
  readonly key: string;
  /** Seconds to follow the operation. */
  readonly followMax: number;
}

/**
 * Issues one mutation under its key and follows the operation it is answered with until that has ended.
 *
 * The platform holds a mutation open until its operation has ended, for up to its own wait: 30
 * seconds unless the request says otherwise. A bound shorter than that is said to the platform, in
 * whole seconds, so that it is not spent and overrun waiting for the first answer. A bound of zero
 * therefore submits and returns at once.
 */
export async function submit(context: ClientContext, call: Call, projectPath: string, mutation: Mutation): Promise<Operation> {
  const query =
    mutation.followMax < FOLLOW_WAIT_MAX ? { ...mutation.query, wait: Math.floor(mutation.followMax) } : mutation.query;
  const answer = await context.transport.request({
    method: mutation.method,
    path: `${projectPath}${mutation.path}`,
    query,
    body: mutation.body,
    idempotencyKey: mutation.key,
    call,
  });
  return follow(context, call, projectPath, new Operation(answer.body, answer.requestId), answer.retryAfter, {
    bound: mutation.followMax,
    // The bound is on the following. The request that started the operation has its own timeout.
    startedAt: context.clock(),
    key: mutation.key,
  });
}

/**
 * Throws unless the ended operation succeeded.
 *
 * `FAILED` or `CANCELLED` with effect `NOT_APPLIED` is a clean failure. `UNKNOWN`, and `FAILED` or
 * `CANCELLED` with any other effect (one this version does not know included), means the target may
 * have changed: that is reported as unknown, and never as success or as failure.
 */
export function requireSuccess(context: ClientContext, operation: Operation, key: string | undefined): void {
  if (operation.state === "SUCCEEDED") {
    return;
  }
  const subject = `Operation ${operation.operation_id} (${operation.type})`;
  const failure = operation.failure;
  const reason =
    failure === null ? "no failure is named" : context.transport.redact(`${failure.code}: ${failure.message}`);
  if ((operation.state === "FAILED" || operation.state === "CANCELLED") && operation.effect === "NOT_APPLIED") {
    throw new OperationFailedError(
      `${subject} ended ${operation.state} and nothing was applied (${reason}). A new request, with a new idempotency key, is allowed.`,
      operation,
      key,
    );
  }
  throw new OutcomeUnknownError(
    `${subject} ended ${operation.state} with effect ${operation.effect ?? "not stated"} (${reason}): whether it was ` +
      `applied is not known. Inspect the target before acting again, and do not repeat the request.`,
    operation,
    key,
  );
}

/** The resource an ended operation produced, or the error that says how it ended. */
export function resultOf(
  context: ClientContext,
  operation: Operation,
  member: "sandbox" | "snapshot" | "execution",
  key: string | undefined,
): JsonObject {
  requireSuccess(context, operation, key);
  const view = operation.result?.[member];
  if (view == null) {
    throw new UnexpectedResponseError(
      `Operation ${operation.operation_id} (${operation.type}) succeeded, and its answer carries no ${member}` +
        (operation.recorded ? ": the platform shows a recorded outcome, because the host no longer holds the operation" : "") +
        `. Read the ${member} by its identifier; operations.get("${operation.operation_id}") names it in target.`,
      { requestId: operation.requestId },
    );
  }
  return view as unknown as JsonObject;
}

const GET_OPTIONS: OptionNames<OperationGetOptions> = { wait: true, signal: true };
const WAIT_OPTIONS: OptionNames<OperationWaitOptions> = { followMax: true, signal: true };
const LIST_OPTIONS: OptionNames<CallOptions> = { signal: true };

/** `fabric.operations`: read, list and follow operations by identifier. */
export class Operations {
  readonly #context: ClientContext;

  /** @internal */
  constructor(context: ClientContext) {
    this.#context = context;
  }

  /**
   * Reads an operation. With `wait`, the platform holds the request open for up to that many
   * seconds and answers as soon as the operation has ended.
   */
  get(operationId: string, options?: OperationGetOptions): Promise<Operation> {
    const context = this.#context;
    return traced("operations.get", options?.signal, async (call) => {
      const known = optionsOf(options, GET_OPTIONS, "operations.get");
      const path = operationPath("", operationId);
      const wait = optionalInteger(known.wait, 0, "wait");
      const answer = await context.transport.request({
        method: "GET",
        path: `${await context.projectPath(call)}${path}`,
        query: { wait },
        call,
      });
      return new Operation(answer.body, answer.requestId);
    });
  }

  /** Every operation of the project, following cursors to the end. */
  async *list(options?: CallOptions): AsyncGenerator<Operation, void, undefined> {
    const context = this.#context;
    const listing = await traced("operations.list", options?.signal, async (call) => {
      optionsOf(options, LIST_OPTIONS, "operations.list");
      return collect(context, call, `${await context.projectPath(call)}/operations`, (view, requestId) => new Operation(view, requestId));
    });
    yield* listing.items;
  }

  /**
   * Follows an operation until it has ended and returns it, however it ended: a failed operation
   * is a result here, not an error. Throws `OperationStillRunningError` at the follow bound.
   */
  wait(operationId: string, options?: OperationWaitOptions): Promise<Operation> {
    const context = this.#context;
    return traced("operations.wait", options?.signal, async (call) => {
      const known = optionsOf(options, WAIT_OPTIONS, "operations.wait");
      const path = operationPath("", operationId);
      const bound = followBound(known.followMax, context.followMax);
      const projectPath = await context.projectPath(call);
      const startedAt = context.clock();
      const answer = await context.transport.request({
        method: "GET",
        path: `${projectPath}${path}`,
        query: { wait: Math.min(FOLLOW_WAIT_MAX, Math.floor(bound)) },
        call,
      });
      return follow(context, call, projectPath, new Operation(answer.body, answer.requestId), answer.retryAfter, {
        bound,
        startedAt,
        key: undefined,
      });
    });
  }
}
