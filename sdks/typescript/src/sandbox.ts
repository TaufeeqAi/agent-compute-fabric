/**
 * Sandboxes: create, start, run commands, snapshot, restore, stop, destroy.
 *
 * Two rules shape the handle:
 *
 * - A handle states what it saw. Every mutation names the generation the handle last observed, so
 *   a sandbox that was restored behind the caller's back refuses the request (`REVISION_CONFLICT`)
 *   rather than running a command in a generation the caller never looked at. `"current"` is sent
 *   only when the caller writes it.
 * - A name is resolved once. `sandboxes.get("name")` reads the sandbox the name belongs to now, and
 *   the handle acts on that sandbox's identifier from then on. A name is an alias that can be given
 *   to another sandbox later; an identifier cannot.
 *
 * The platform creates and starts with two operations, and `sandboxes.create` drives both.
 */

import type { ClientContext } from "./context.js";
import {
  FabricError,
  NameReboundError,
  OperationFailedError,
  OutcomeUnknownError,
  RefusedError,
  SandboxStartError,
  type StartCleanup,
  UnexpectedResponseError,
} from "./errors.js";
import { Execution } from "./execution.js";
import { CREATE_KEY_MAX_LENGTH, DESTROY_SUFFIX, keyOf, START_SUFFIX } from "./idempotency.js";
import {
  argvOf,
  envOf,
  flag,
  followBound,
  generationOf,
  networkBody,
  oneOf,
  type OptionNames,
  optionalText,
  optionsOf,
  segment,
  text,
} from "./inputs.js";
import { collect } from "./listing.js";
import { type Operation, requireSuccess, resultOf, submit } from "./operation.js";
import { Snapshot, snapshotPath } from "./snapshot.js";
import { type Call, traced } from "./telemetry.js";
import type {
  CallOptions,
  ExecOptions,
  Failure,
  Generation,
  Image,
  JsonObject,
  NetworkView,
  Normalized,
  Raw,
  RefreshOptions,
  ResourcesView,
  SandboxCreateOptions,
  SandboxMutationOptions,
  SandboxView,
  SnapshotRef,
} from "./types.js";
import { mebibytes, positiveInteger, seconds } from "./units.js";
import { emptyList, expose, hidden, integerOf, none, objectOf, type Shape, stringOf } from "./view.js";

const SANDBOX: Shape<SandboxView> = {
  sandbox_id: true,
  project: true,
  name: none,
  state: true,
  state_raw: none,
  generation: true,
  revision: true,
  image: true,
  resources: true,
  network: true,
  expires_at: true,
  last_execution: none,
  quarantined: none,
  failure: none,
  source_snapshot: none,
  notes: emptyList,
  updated_at: true,
};

const CALL_OPTIONS: OptionNames<CallOptions> = { signal: true };
const REFRESH_OPTIONS: OptionNames<RefreshOptions> = { rebind: true, signal: true };
const MUTATION_OPTIONS: OptionNames<SandboxMutationOptions> = {
  generation: true,
  idempotencyKey: true,
  followMax: true,
  signal: true,
};
const EXEC_OPTIONS: OptionNames<ExecOptions> = {
  cwd: true,
  env: true,
  timeout: true,
  generation: true,
  idempotencyKey: true,
  followMax: true,
  signal: true,
};
const CREATE_OPTIONS: OptionNames<SandboxCreateOptions> = {
  cpu: true,
  memory: true,
  disk: true,
  network: true,
  name: true,
  lifetime: true,
  start: true,
  onStartFailure: true,
  idempotencyKey: true,
  followMax: true,
  signal: true,
};

/** Where a view of a sandbox came from. */
interface Origin {
  readonly requestId: string | undefined;
  /** The operation whose result the view is, when a mutation produced it. */
  readonly operation?: Operation | undefined;
  /** What the caller asked for the sandbox by: an identifier or a name. */
  readonly askedFor?: string | undefined;
  /** The view is the identifier alone: the caller named the sandbox and nothing was read. */
  readonly unread?: boolean | undefined;
}

function sandboxPath(reference: string): string {
  return `/sandboxes/${segment(reference, "sandbox")}`;
}

function startSandbox(
  context: ClientContext,
  call: Call,
  projectPath: string,
  sandboxId: string,
  generation: Generation,
  key: string,
  followMax: number,
): Promise<Operation> {
  return submit(context, call, projectPath, {
    method: "POST",
    path: `${sandboxPath(sandboxId)}/start`,
    body: { expected_generation: generation },
    key,
    followMax,
  });
}

function destroySandbox(
  context: ClientContext,
  call: Call,
  projectPath: string,
  sandboxId: string,
  generation: Generation,
  key: string,
  followMax: number,
): Promise<Operation> {
  return submit(context, call, projectPath, {
    method: "DELETE",
    path: sandboxPath(sandboxId),
    query: { expected_generation: generation },
    key,
    followMax,
  });
}

/** A handle on one sandbox. It holds the view it last saw, and updates itself from every answer about the sandbox. */
export class Sandbox implements Normalized<SandboxView> {
  declare readonly sandbox_id: string;
  declare readonly project: string;
  declare readonly name: string | null;
  declare readonly state: string;
  declare readonly state_raw: string | null;
  declare readonly generation: number;
  declare readonly revision: string;
  declare readonly image: Image;
  declare readonly resources: ResourcesView;
  declare readonly network: NetworkView;
  declare readonly expires_at: string;
  declare readonly last_execution: string | null;
  declare readonly quarantined: string | null;
  declare readonly failure: Failure | null;
  declare readonly source_snapshot: SnapshotRef | null;
  declare readonly notes: readonly string[];
  declare readonly updated_at: string;
  /** The view exactly as the server sent it, with every member this version does not know. */
  declare readonly raw: Raw<SandboxView>;
  /** The request id of the answer that carried this view. */
  declare readonly requestId: string | undefined;
  /** The operation whose result this view is. `undefined` after a read. */
  declare readonly operation: Operation | undefined;
  readonly #context: ClientContext;
  /** The name the handle was obtained by. Only `refresh` reads by it; no mutation ever does. */
  readonly #obtainedByName: string | undefined;
  /** The generation of the view the handle holds. None until a handle made without a read has read. */
  #observed: number | undefined;

  /** @internal */
  constructor(context: ClientContext, view: unknown, origin: Origin) {
    this.#context = context;
    this.#show(view, origin, false);
    this.#obtainedByName = origin.askedFor !== undefined && origin.askedFor !== this.sandbox_id ? origin.askedFor : undefined;
  }

  #show(view: unknown, origin: Origin, rebinding: boolean): void {
    const source = { what: "A sandbox", requestId: origin.requestId };
    const checked = objectOf(view, source);
    const id = stringOf(checked, "sandbox_id", source);
    this.#observed = origin.unread === true ? undefined : integerOf(checked, "generation", source);
    if ("sandbox_id" in this && id !== this.sandbox_id && !rebinding) {
      throw new UnexpectedResponseError(`Sandbox ${this.sandbox_id} was answered with the view of ${id}.`, {
        requestId: origin.requestId,
      });
    }
    expose<SandboxView>(this, checked, SANDBOX);
    const own = this as { requestId: string | undefined };
    own.requestId = origin.requestId;
    hidden(this, "operation", origin.operation);
  }

  /**
   * One mutation whose result is this sandbox: check the arguments, issue, follow, update the
   * handle. `check` runs before any request, like every other check of what the caller passed.
   */
  #change(
    name: string,
    options: SandboxMutationOptions | undefined,
    issue: (call: Call, projectPath: string, generation: Generation, key: string, followMax: number) => Promise<Operation>,
    check?: () => void,
  ): Promise<this> {
    const context = this.#context;
    return traced(name, options?.signal, async (call) => {
      const known = optionsOf(options, MUTATION_OPTIONS, name);
      check?.();
      const generation = generationOf(known.generation, this.#observed);
      const key = keyOf(known.idempotencyKey);
      const followMax = followBound(known.followMax, context.followMax);
      const operation = await issue(call, await context.projectPath(call), generation, key, followMax);
      this.#show(resultOf(context, operation, "sandbox", key), { requestId: operation.requestId, operation }, false);
      return this;
    });
  }

  #run(name: string, method: string, argv: () => string[], options: ExecOptions | undefined): Promise<Execution> {
    const context = this.#context;
    return traced(name, options?.signal, async (call) => {
      const known = optionsOf(options, EXEC_OPTIONS, method);
      const body: { [member: string]: unknown } = {
        expected_generation: generationOf(known.generation, this.#observed),
        argv: argv(),
      };
      const cwd = optionalText(known.cwd, "cwd");
      if (cwd !== undefined) {
        body["cwd"] = cwd;
      }
      if (known.env != null) {
        body["env"] = envOf(known.env);
      }
      if (known.timeout != null) {
        body["timeout_seconds"] = seconds(known.timeout, "timeout");
      }
      const key = keyOf(known.idempotencyKey);
      const followMax = followBound(known.followMax, context.followMax);
      const operation = await submit(context, call, await context.projectPath(call), {
        method: "POST",
        path: `${sandboxPath(this.sandbox_id)}/executions`,
        body,
        key,
        followMax,
      });
      return new Execution(context, resultOf(context, operation, "execution", key), { requestId: operation.requestId, operation });
    });
  }

  /** Starts a sandbox that was created and has not been started. A stopped sandbox is not started again. */
  start(options?: SandboxMutationOptions): Promise<this> {
    return this.#change("sandbox.start", options, (call, projectPath, generation, key, followMax) =>
      startSandbox(this.#context, call, projectPath, this.sandbox_id, generation, key, followMax),
    );
  }

  /**
   * Runs one command, given as an argument vector, and returns its execution once it has ended.
   * The command is executed directly, never through a shell. A status other than 0 is a result:
   * read `exit_code`.
   */
  exec(argv: readonly string[], options?: ExecOptions): Promise<Execution> {
    return this.#run("sandbox.exec", "sandbox.exec", () => argvOf(argv), options);
  }

  /**
   * Runs a command line through the shell: sends `["/bin/sh", "-c", command]`. This is the only way
   * the SDK accepts a string, so that a shell is never introduced without the caller saying so.
   */
  execShell(command: string, options?: ExecOptions): Promise<Execution> {
    return this.#run("sandbox.exec_shell", "sandbox.execShell", () => ["/bin/sh", "-c", text(command, "command")], options);
  }

  /** Takes a snapshot of the sandbox and returns it. */
  snapshot(name?: string, options?: SandboxMutationOptions): Promise<Snapshot> {
    const context = this.#context;
    return traced("sandbox.snapshot", options?.signal, async (call) => {
      const known = optionsOf(options, MUTATION_OPTIONS, "sandbox.snapshot");
      const body: { [member: string]: unknown } = { expected_generation: generationOf(known.generation, this.#observed) };
      const alias = optionalText(name, "name");
      if (alias !== undefined) {
        body["name"] = alias;
      }
      const key = keyOf(known.idempotencyKey);
      const followMax = followBound(known.followMax, context.followMax);
      const operation = await submit(context, call, await context.projectPath(call), {
        method: "POST",
        path: `${sandboxPath(this.sandbox_id)}/snapshots`,
        body,
        key,
        followMax,
      });
      return new Snapshot(context, resultOf(context, operation, "snapshot", key), { requestId: operation.requestId, operation });
    });
  }

  /**
   * Restores a snapshot into this sandbox: the same sandbox, in a new generation. What the sandbox
   * held before is replaced. The handle then states the new generation.
   */
  restore(snapshot: Snapshot, options?: SandboxMutationOptions): Promise<this> {
    return this.#change(
      "sandbox.restore",
      options,
      (call, projectPath, generation, key, followMax) =>
        submit(this.#context, call, projectPath, {
          method: "POST",
          path: `${snapshotPath(snapshot.snapshot_id)}/restore`,
          body: {
            snapshot_generation: snapshot.snapshot_generation,
            target: { kind: "existing", sandbox_id: this.sandbox_id, expected_generation: generation },
          },
          key,
          followMax,
        }),
      () => {
        // The restore names the snapshot's generation, which only a handle on the snapshot knows.
        if (!(snapshot instanceof Snapshot)) {
          throw new TypeError("restore takes a Snapshot: get one from sandbox.snapshot() or from fabric.snapshots.get()");
        }
      },
    );
  }

  /** Stops the sandbox. A running execution is cancelled by the host. */
  stop(options?: SandboxMutationOptions): Promise<this> {
    return this.#change("sandbox.stop", options, (call, projectPath, generation, key, followMax) =>
      submit(this.#context, call, projectPath, {
        method: "POST",
        path: `${sandboxPath(this.sandbox_id)}/stop`,
        body: { expected_generation: generation },
        key,
        followMax,
      }),
    );
  }

  /** Destroys the sandbox. It is never resurrected. */
  destroy(options?: SandboxMutationOptions): Promise<this> {
    return this.#change("sandbox.destroy", options, (call, projectPath, generation, key, followMax) =>
      destroySandbox(this.#context, call, projectPath, this.sandbox_id, generation, key, followMax),
    );
  }

  /**
   * Reads the sandbox again and updates this handle.
   *
   * A handle that was obtained by a name reads by that name, and checks that the name still
   * belongs to the sandbox it acts on. If it now belongs to another, `refresh` throws
   * `NameReboundError` and leaves the handle as it was; with `rebind: true` the handle becomes
   * that other sandbox instead.
   */
  refresh(options?: RefreshOptions): Promise<this> {
    const context = this.#context;
    return traced("sandbox.refresh", options?.signal, async (call) => {
      const known = optionsOf(options, REFRESH_OPTIONS, "sandbox.refresh");
      const rebind = flag(known.rebind, "rebind", false);
      const name = this.#obtainedByName;
      const answer = await context.transport.request({
        method: "GET",
        path: `${await context.projectPath(call)}${sandboxPath(name ?? this.sandbox_id)}`,
        call,
      });
      const source = { what: "A sandbox", requestId: answer.requestId };
      const found = stringOf(objectOf(answer.body, source), "sandbox_id", source);
      const rebound = name !== undefined && found !== this.sandbox_id;
      if (rebound && !rebind) {
        throw new NameReboundError(
          `The name ${JSON.stringify(name)} now belongs to sandbox ${found}. This handle acts on ${this.sandbox_id} ` +
            `and was left as it was. Pass rebind: true to make it ${found}, or get the sandbox again.`,
          { sandboxName: name, sandboxId: this.sandbox_id, reboundTo: found },
          { requestId: answer.requestId },
        );
      }
      this.#show(answer.body, { requestId: answer.requestId }, rebound);
      return this;
    });
  }

  /** The view as the server sent it. */
  toJSON(): Raw<SandboxView> {
    return this.raw;
  }

  toString(): string {
    return `Sandbox(${this.sandbox_id}, state=${this.state}, generation=${this.generation})`;
  }
}

function createBody(image: unknown, options: SandboxCreateOptions): JsonObject {
  // The required members, and the members the caller set. A default the caller did not ask for is
  // not spelled out: the platform fills it in, and `start` is never sent because the SDK starts
  // the sandbox itself, with an operation of its own.
  const body: { [member: string]: unknown } = {
    image: text(image, "image"),
    resources: {
      vcpus: positiveInteger(options.cpu, "cpu"),
      memory_mib: mebibytes(options.memory, "memory"),
      disk_mib: mebibytes(options.disk, "disk"),
    },
  };
  if (options.network != null) {
    body["network"] = networkBody(options.network);
  }
  const name = optionalText(options.name, "name");
  if (name !== undefined) {
    body["name"] = name;
  }
  if (options.lifetime != null) {
    body["lifetime_seconds"] = seconds(options.lifetime, "lifetime");
  }
  return body;
}

/** The message of a `SandboxStartError`: both outcomes, the start's and the sandbox's. */
function describeStartFailure(sandboxId: string, startError: FabricError, cleanup: StartCleanup, destroyError?: FabricError): string {
  const outcome = {
    destroyed: "the sandbox was destroyed",
    kept: "the sandbox was kept, so start it again or destroy it",
    destroy_failed: `destroying it did not succeed either, so the sandbox still exists [${destroyError?.name}: ${destroyError?.message}]`,
  }[cleanup];
  return `Sandbox ${sandboxId} was created and its start did not succeed; ${outcome}. The start: ${startError.name}: ${startError.message}`;
}

/** `fabric.sandboxes`: create a sandbox, find one, list them. */
export class Sandboxes {
  readonly #context: ClientContext;

  /** @internal */
  constructor(context: ClientContext) {
    this.#context = context;
  }

  /**
   * Creates a sandbox and, unless `start` is `false`, starts it. Returns when the sandbox has
   * started.
   *
   * These are two operations of the platform. The create is issued under the call's idempotency
   * key and the start under that key with the suffix `:start`, so repeating the call with the same
   * key and the same arguments resumes it wherever it stopped. If the create fails, its error is
   * thrown and nothing else is sent. If the start is refused or ends without success,
   * `onStartFailure` decides what becomes of the sandbox, and the call throws `SandboxStartError`
   * naming both outcomes.
   */
  create(image: string, options: SandboxCreateOptions): Promise<Sandbox> {
    const context = this.#context;
    return traced("sandboxes.create", options?.signal, async (call) => {
      const known = optionsOf(options, CREATE_OPTIONS, "sandboxes.create");
      const body = createBody(image, known);
      const start = flag(known.start, "start", true);
      const onStartFailure = oneOf(known.onStartFailure, ["destroy", "keep"] as const, "onStartFailure", "destroy");
      const key = keyOf(known.idempotencyKey, CREATE_KEY_MAX_LENGTH);
      const followMax = followBound(known.followMax, context.followMax);
      const projectPath = await context.projectPath(call);

      const created = await submit(context, call, projectPath, { method: "POST", path: "/sandboxes", body, key, followMax });
      const sandbox = new Sandbox(context, resultOf(context, created, "sandbox", key), { requestId: created.requestId, operation: created });
      if (!start) {
        return sandbox;
      }

      const startKey = `${key}${START_SUFFIX}`;
      let startError: FabricError;
      try {
        const started = await startSandbox(context, call, projectPath, sandbox.sandbox_id, sandbox.generation, startKey, followMax);
        return new Sandbox(context, resultOf(context, started, "sandbox", startKey), { requestId: started.requestId, operation: started });
      } catch (error) {
        // Only a start that was refused, or that ended without success, is cleaned up after. One
        // that is still running, or whose answer is unresolved or lost, may yet succeed: its error
        // goes to the caller as it is, and the sandbox is left alone.
        if (!(error instanceof RefusedError || error instanceof OperationFailedError || error instanceof OutcomeUnknownError)) {
          throw error;
        }
        startError = error;
      }

      const { sandbox_id: sandboxId } = sandbox;
      if (onStartFailure === "keep") {
        throw new SandboxStartError(describeStartFailure(sandboxId, startError, "kept"), { sandboxId, startError, cleanup: "kept" });
      }
      try {
        // The destroy names the generation the handle saw: the start did not succeed, so the
        // sandbox is still the one that was created.
        const destroyKey = `${key}${DESTROY_SUFFIX}`;
        const destroyed = await destroySandbox(context, call, projectPath, sandboxId, sandbox.generation, destroyKey, followMax);
        requireSuccess(context, destroyed, destroyKey);
      } catch (destroyError) {
        if (!(destroyError instanceof FabricError)) {
          throw destroyError;
        }
        throw new SandboxStartError(describeStartFailure(sandboxId, startError, "destroy_failed", destroyError), {
          sandboxId,
          startError,
          cleanup: "destroy_failed",
          destroyError,
        });
      }
      throw new SandboxStartError(describeStartFailure(sandboxId, startError, "destroyed"), { sandboxId, startError, cleanup: "destroyed" });
    });
  }

  /**
   * A handle on a sandbox that was not read: no request is made.
   *
   * For a caller that already knows the identifier, such as a job that kept it from an earlier run.
   * The handle holds the identifier and nothing else until `refresh()`. It has seen no generation,
   * so every mutation through it must name one itself: a number, or `"current"`.
   */
  handle(sandboxId: string): Sandbox {
    // Checked as every identifier that becomes part of a path is, and kept as the caller wrote it.
    segment(sandboxId, "sandbox");
    return new Sandbox(this.#context, { sandbox_id: sandboxId }, { requestId: undefined, unread: true });
  }

  /**
   * Reads one sandbox, by identifier or by name. A name is resolved here, once: the handle acts on
   * the identifier of the sandbox the name belonged to at this moment.
   */
  get(sandbox: string, options?: CallOptions): Promise<Sandbox> {
    const context = this.#context;
    return traced("sandboxes.get", options?.signal, async (call) => {
      optionsOf(options, CALL_OPTIONS, "sandboxes.get");
      const path = sandboxPath(sandbox);
      const answer = await context.transport.request({ method: "GET", path: `${await context.projectPath(call)}${path}`, call });
      return new Sandbox(context, answer.body, { requestId: answer.requestId, askedFor: sandbox });
    });
  }

  /** Every sandbox of the project, following cursors to the end. */
  async *list(options?: CallOptions): AsyncGenerator<Sandbox, void, undefined> {
    const context = this.#context;
    const listing = await traced("sandboxes.list", options?.signal, async (call) => {
      optionsOf(options, CALL_OPTIONS, "sandboxes.list");
      return collect(context, call, `${await context.projectPath(call)}/sandboxes`, (view, requestId) => new Sandbox(context, view, { requestId }));
    });
    yield* listing.items;
  }
}
