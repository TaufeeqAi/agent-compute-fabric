/**
 * `Fabric`: the client of the public API of Agent Compute Fabric.
 *
 * The client decides nothing. Who may ask, what is allowed, which transitions are legal and what
 * actually happened are decided by the platform; the client states the request once, keeps one
 * idempotency key equal to one operation when answers are lost, and reports each outcome as the
 * distinct thing it is.
 *
 * A client holds no state of the server except the project of its credential, and may be shared by
 * any number of concurrent calls.
 */

import { Auth, type WhoAmI } from "./auth.js";
import { ClientContext } from "./context.js";
import { Executions } from "./execution.js";
import { type OptionNames, optionsOf } from "./inputs.js";
import { Operations } from "./operation.js";
import { Sandboxes } from "./sandbox.js";
import { Snapshots } from "./snapshot.js";
import { traced } from "./telemetry.js";
import type { CallOptions, Ceilings, FabricOptions, InfoView, Normalized, Raw } from "./types.js";
import { expose, none, objectOf, type Shape } from "./view.js";

const INFO: Shape<InfoView> = {
  api_versions: true,
  serving: true,
  ready: none,
  not_ready_reasons: none,
  platform_features: none,
  host_features: none,
  parameters: none,
  ceilings: none,
};

const CALL_OPTIONS: OptionNames<CallOptions> = { signal: true };

/** What Node.js calls to print an object. Looked up by name, so that no module of Node.js is imported. */
const PRINT = Symbol.for("nodejs.util.inspect.custom");

/** Platform info: the API versions, whether the platform serves, and what it offers this credential. */
export class Info implements Normalized<InfoView> {
  declare readonly api_versions: readonly string[];
  declare readonly serving: boolean;
  declare readonly ready: boolean | null;
  declare readonly not_ready_reasons: readonly string[] | null;
  declare readonly platform_features: readonly string[] | null;
  declare readonly host_features: readonly string[] | null;
  declare readonly parameters: { readonly [name: string]: number | boolean } | null;
  declare readonly ceilings: Ceilings | null;
  /** The view exactly as the server sent it, with every member this version does not know. */
  declare readonly raw: Raw<InfoView>;
  /** The request id of the answer that carried this view. */
  declare readonly requestId: string | undefined;

  /** @internal */
  constructor(view: unknown, requestId: string | undefined) {
    expose<InfoView>(this, objectOf(view, { what: "The answer of info", requestId }), INFO);
    (this as { requestId: string | undefined }).requestId = requestId;
  }

  /** The view as the server sent it. */
  toJSON(): Raw<InfoView> {
    return this.raw;
  }

  toString(): string {
    return `Info(api_versions=${String(this.api_versions)}, serving=${this.serving})`;
  }
}

export class Fabric {
  readonly sandboxes: Sandboxes;
  readonly snapshots: Snapshots;
  readonly executions: Executions;
  readonly operations: Operations;
  readonly auth: Auth;
  readonly #context: ClientContext;

  /**
   * @throws ConfigurationError when the credential or the endpoint is missing or cannot be used,
   *   and when the client is constructed in a browser page without `dangerouslyAllowBrowser`.
   */
  constructor(options: FabricOptions = {}) {
    const context = new ClientContext(options);
    this.#context = context;
    this.sandboxes = new Sandboxes(context);
    this.snapshots = new Snapshots(context);
    this.executions = new Executions(context);
    this.operations = new Operations(context);
    this.auth = new Auth(context);
  }

  /** The calling credential's principal, project and effective grants. The same as `auth.whoami()`. */
  whoami(options?: CallOptions): Promise<WhoAmI> {
    return this.auth.whoami(options);
  }

  /** Platform info: the API versions, whether the platform serves, and what it offers this credential. */
  info(options?: CallOptions): Promise<Info> {
    const context = this.#context;
    return traced("fabric.info", options?.signal, async (call) => {
      optionsOf(options, CALL_OPTIONS, "fabric.info");
      const answer = await context.transport.request({ method: "GET", path: "/v1/info", call });
      return new Info(answer.body, answer.requestId);
    });
  }

  /** The endpoint and the project. The credential is in no text form of a client. */
  toJSON(): { baseUrl: string; project: string | null } {
    return { baseUrl: this.#context.baseUrl, project: this.#context.project ?? null };
  }

  toString(): string {
    return `Fabric(baseUrl=${this.#context.baseUrl}, project=${this.#context.project ?? "the credential's"})`;
  }

  [PRINT](): string {
    return this.toString();
  }
}
