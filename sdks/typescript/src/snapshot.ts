/**
 * Snapshots: a saved state of a sandbox, restored into a new sandbox or deleted.
 *
 * The platform has no route that reads one snapshot, so a snapshot is found by listing. A handle
 * acts on the identifier and the generation of the snapshot it saw, never on a name.
 */

import type { ClientContext } from "./context.js";
import { NotFoundError, UnexpectedResponseError } from "./errors.js";
import { keyOf } from "./idempotency.js";
import { followBound, type OptionNames, optionalText, optionsOf, segment, text } from "./inputs.js";
import { collect } from "./listing.js";
import { type Operation, resultOf, submit } from "./operation.js";
import { Sandbox } from "./sandbox.js";
import { traced } from "./telemetry.js";
import type {
  CallOptions,
  Failure,
  MutationOptions,
  Normalized,
  Raw,
  RestoreAsNewOptions,
  SandboxRef,
  SnapshotView,
} from "./types.js";
import { seconds } from "./units.js";
import { emptyList, expose, hidden, integerOf, none, objectOf, type Shape, stringOf } from "./view.js";

const SNAPSHOT: Shape<SnapshotView> = {
  snapshot_id: true,
  snapshot_generation: true,
  project: true,
  name: none,
  state: true,
  state_raw: none,
  revision: true,
  source_sandbox: none,
  size_bytes: true,
  restore_count: true,
  incompatible: emptyList,
  failure: none,
  created_at: true,
};

const CALL_OPTIONS: OptionNames<CallOptions> = { signal: true };
const MUTATION_OPTIONS: OptionNames<MutationOptions> = { idempotencyKey: true, followMax: true, signal: true };
const RESTORE_AS_NEW_OPTIONS: OptionNames<RestoreAsNewOptions> = {
  name: true,
  lifetime: true,
  idempotencyKey: true,
  followMax: true,
  signal: true,
};

/** Where a view of a snapshot came from. */
interface Origin {
  readonly requestId: string | undefined;
  /** The operation whose result the view is, when a mutation produced it. */
  readonly operation?: Operation | undefined;
}

/** The route of one snapshot, below the project. */
export function snapshotPath(snapshotId: string): string {
  return `/snapshots/${segment(snapshotId, "snapshot")}`;
}

/** A handle on one snapshot. It holds the view it last saw. */
export class Snapshot implements Normalized<SnapshotView> {
  declare readonly snapshot_id: string;
  declare readonly snapshot_generation: number;
  declare readonly project: string;
  declare readonly name: string | null;
  declare readonly state: string;
  declare readonly state_raw: string | null;
  declare readonly revision: string;
  declare readonly source_sandbox: SandboxRef | null;
  declare readonly size_bytes: number;
  declare readonly restore_count: number;
  declare readonly incompatible: readonly string[];
  declare readonly failure: Failure | null;
  declare readonly created_at: string;
  /** The view exactly as the server sent it, with every member this version does not know. */
  declare readonly raw: Raw<SnapshotView>;
  /** The request id of the answer that carried this view. */
  declare readonly requestId: string | undefined;
  /** The operation whose result this view is. `undefined` when the view came from a listing. */
  declare readonly operation: Operation | undefined;
  readonly #context: ClientContext;

  /** @internal */
  constructor(context: ClientContext, view: unknown, origin: Origin) {
    this.#context = context;
    this.#show(view, origin);
  }

  #show(view: unknown, origin: Origin): void {
    const source = { what: "A snapshot", requestId: origin.requestId };
    const checked = objectOf(view, source);
    const id = stringOf(checked, "snapshot_id", source);
    integerOf(checked, "snapshot_generation", source);
    if ("snapshot_id" in this && id !== this.snapshot_id) {
      throw new UnexpectedResponseError(`Snapshot ${this.snapshot_id} was answered with the view of ${id}.`, {
        requestId: origin.requestId,
      });
    }
    expose<SnapshotView>(this, checked, SNAPSHOT);
    const own = this as { requestId: string | undefined };
    own.requestId = origin.requestId;
    hidden(this, "operation", origin.operation);
  }

  /** Restores the snapshot as a new sandbox, generation 1, and returns that sandbox. */
  restoreAsNew(options?: RestoreAsNewOptions): Promise<Sandbox> {
    const context = this.#context;
    return traced("snapshot.restore_as_new", options?.signal, async (call) => {
      const known = optionsOf(options, RESTORE_AS_NEW_OPTIONS, "snapshot.restoreAsNew");
      const target: { [member: string]: unknown } = { kind: "new" };
      const name = optionalText(known.name, "name");
      if (name !== undefined) {
        target["name"] = name;
      }
      if (known.lifetime != null) {
        target["lifetime_seconds"] = seconds(known.lifetime, "lifetime");
      }
      const key = keyOf(known.idempotencyKey);
      const followMax = followBound(known.followMax, context.followMax);
      const operation = await submit(context, call, await context.projectPath(call), {
        method: "POST",
        path: `${snapshotPath(this.snapshot_id)}/restore`,
        body: { snapshot_generation: this.snapshot_generation, target },
        key,
        followMax,
      });
      return new Sandbox(context, resultOf(context, operation, "sandbox", key), { requestId: operation.requestId, operation });
    });
  }

  /** Deletes the snapshot and updates this handle from the result. A deleted snapshot is never resurrected. */
  delete(options?: MutationOptions): Promise<this> {
    const context = this.#context;
    return traced("snapshot.delete", options?.signal, async (call) => {
      const known = optionsOf(options, MUTATION_OPTIONS, "snapshot.delete");
      const key = keyOf(known.idempotencyKey);
      const followMax = followBound(known.followMax, context.followMax);
      const operation = await submit(context, call, await context.projectPath(call), {
        method: "DELETE",
        path: snapshotPath(this.snapshot_id),
        query: { snapshot_generation: this.snapshot_generation },
        key,
        followMax,
      });
      this.#show(resultOf(context, operation, "snapshot", key), { requestId: operation.requestId, operation });
      return this;
    });
  }

  /** The view as the server sent it. */
  toJSON(): Raw<SnapshotView> {
    return this.raw;
  }

  toString(): string {
    return `Snapshot(${this.snapshot_id}, generation=${this.snapshot_generation}, state=${this.state})`;
  }
}

/** `fabric.snapshots`: list the snapshots of the project and find one. */
export class Snapshots {
  readonly #context: ClientContext;

  /** @internal */
  constructor(context: ClientContext) {
    this.#context = context;
  }

  /** Every snapshot of the project, following cursors to the end. */
  async *list(options?: CallOptions): AsyncGenerator<Snapshot, void, undefined> {
    const context = this.#context;
    const listing = await traced("snapshots.list", options?.signal, async (call) => {
      optionsOf(options, CALL_OPTIONS, "snapshots.list");
      return collect(context, call, `${await context.projectPath(call)}/snapshots`, (view, requestId) => new Snapshot(context, view, { requestId }));
    });
    yield* listing.items;
  }

  /**
   * The snapshot with this identifier, or else with this name. It is found by listing; a name is
   * resolved here, once, and the handle acts on the identifier from then on. Throws `NotFoundError`
   * when the project has no such snapshot.
   */
  get(snapshot: string, options?: CallOptions): Promise<Snapshot> {
    const context = this.#context;
    return traced("snapshots.get", options?.signal, async (call) => {
      optionsOf(options, CALL_OPTIONS, "snapshots.get");
      const wanted = text(snapshot, "snapshot");
      const listing = await collect(context, call, `${await context.projectPath(call)}/snapshots`, (view, requestId) => new Snapshot(context, view, { requestId }));
      const found =
        listing.items.find((item) => item.snapshot_id === wanted) ?? listing.items.find((item) => item.name === wanted);
      if (found === undefined) {
        throw new NotFoundError(`The project has no snapshot with the identifier or the name ${JSON.stringify(wanted)}.`, {
          status: undefined,
          code: "NOT_FOUND",
          kind: "REFUSED",
          retry: "NEVER",
          requestId: listing.requestId,
          idempotencyKey: undefined,
          reason: undefined,
          retryAfter: undefined,
        });
      }
      return found;
    });
  }
}
