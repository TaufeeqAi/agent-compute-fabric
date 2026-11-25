/**
 * The calling credential, and the agent credentials it minted.
 *
 * Minting and revoking are mutations that reach no host, and the platform gives them no idempotency
 * key. A mint whose answer is lost is therefore not repeated by the SDK: it would be a second
 * credential, or a refusal that hides the first. The caller lists its agent credentials and revokes
 * the one whose secret nobody saw. Revoking is the same done twice as done once, and is repeated.
 *
 * A revocation ends what a credential may ask for. It does not end what the credential already
 * started, and the platform cancels nothing by itself. `contain` is the client doing that part.
 */

import type { ClientContext } from "./context.js";
import { FabricError, UnexpectedResponseError } from "./errors.js";
import { cancelExecution } from "./execution.js";
import { newKey } from "./idempotency.js";
import { flag, type OptionNames, optionsOf, segment, text } from "./inputs.js";
import { collect } from "./listing.js";
import { hasEnded, Operation, requireSuccess } from "./operation.js";
import { type Call, traced } from "./telemetry.js";
import type {
  AgentCredentialView,
  CallOptions,
  CredentialView,
  JsonObject,
  MintAgentCredentialOptions,
  Normalized,
  Raw,
  RevokeAgentCredentialOptions,
  WhoAmIView,
} from "./types.js";
import { seconds } from "./units.js";
import { expose, hidden, none, objectOf, type Shape, stringOf } from "./view.js";

const WHOAMI: Shape<WhoAmIView> = {
  principal_id: true,
  project_id: true,
  credential: true,
  grants: true,
  policy_version: true,
};

const AGENT_CREDENTIAL: Shape<AgentCredentialView> = {
  credential_id: true,
  kind: true,
  label: none,
  display_prefix: true,
  status: true,
  issued_at: true,
  expires_at: true,
  narrowing: none,
  secret: none,
};

/** What stands for a minted secret wherever the credential is printed or serialized. */
const SECRET_SHOWN_AS = "[shown once: read .secret]";

/** The calling credential's principal, project and effective grants. */
export class WhoAmI implements Normalized<WhoAmIView> {
  declare readonly principal_id: string;
  declare readonly project_id: string;
  declare readonly credential: CredentialView;
  declare readonly grants: JsonObject;
  declare readonly policy_version: string;
  /** The view exactly as the server sent it, with every member this version does not know. */
  declare readonly raw: Raw<WhoAmIView>;
  /** The request id of the answer that carried this view. */
  declare readonly requestId: string | undefined;

  /** @internal */
  constructor(view: unknown, requestId: string | undefined) {
    const source = { what: "The answer of whoami", requestId };
    const checked = objectOf(view, source);
    stringOf(checked, "principal_id", source);
    expose<WhoAmIView>(this, checked, WHOAMI);
    (this as { requestId: string | undefined }).requestId = requestId;
  }

  /** The view as the server sent it. */
  toJSON(): Raw<WhoAmIView> {
    return this.raw;
  }

  toString(): string {
    return `WhoAmI(${this.principal_id}, project=${this.project_id})`;
  }
}

/** A cancel that containment issued and that did not succeed. */
export interface ContainmentFailure {
  /** The operation that runs the execution. */
  readonly operationId: string;
  /** The execution, or `null` when the operation named none and no cancel could be issued. */
  readonly executionId: string | null;
  readonly error: FabricError;
}

/** What containment did after a revocation. */
interface Containment {
  readonly contained: readonly string[];
  readonly failures: readonly ContainmentFailure[];
}

/** An agent credential: narrower and shorter-lived than the credential that minted it. */
export class AgentCredential implements Normalized<AgentCredentialView> {
  declare readonly credential_id: string;
  declare readonly kind: string;
  declare readonly label: string | null;
  declare readonly display_prefix: string;
  declare readonly status: string;
  declare readonly issued_at: string;
  declare readonly expires_at: string;
  declare readonly narrowing: JsonObject | null;
  /**
   * The credential itself. Present once, on the answer to minting, and `null` ever after. It is
   * left out when the object is printed or serialized: read it here, and store it as a secret.
   */
  declare readonly secret: string | null;
  /** After a revocation with `contain`: the executions whose cancel succeeded. */
  declare readonly contained: readonly string[];
  /** After a revocation with `contain`: the cancels that did not succeed. */
  declare readonly containmentErrors: readonly ContainmentFailure[];
  /** The view exactly as the server sent it. After minting it holds the secret. */
  declare readonly raw: Raw<AgentCredentialView>;
  /** The request id of the answer that carried this view. */
  declare readonly requestId: string | undefined;

  /** @internal */
  constructor(view: unknown, requestId: string | undefined, containment: Containment = { contained: [], failures: [] }) {
    const source = { what: "An agent credential", requestId };
    const checked = objectOf(view, source);
    stringOf(checked, "credential_id", source);
    expose<AgentCredentialView>(this, checked, AGENT_CREDENTIAL);
    hidden(this, "secret", this.secret);
    const own = this as { contained: readonly string[]; containmentErrors: readonly ContainmentFailure[]; requestId: string | undefined };
    own.contained = containment.contained;
    own.containmentErrors = containment.failures;
    own.requestId = requestId;
  }

  /** The view as the server sent it, without the secret. */
  toJSON(): JsonObject {
    return this.secret === null ? this.raw : { ...this.raw, secret: SECRET_SHOWN_AS };
  }

  toString(): string {
    return `AgentCredential(${this.credential_id}, label=${this.label ?? "none"}, status=${this.status})`;
  }
}

const CALL_OPTIONS: OptionNames<CallOptions> = { signal: true };
const MINT_OPTIONS: OptionNames<MintAgentCredentialOptions> = { lifetime: true, narrowing: true, signal: true };
const REVOKE_OPTIONS: OptionNames<RevokeAgentCredentialOptions> = { contain: true, signal: true };

async function readWhoAmI(context: ClientContext, call: Call): Promise<WhoAmI> {
  const answer = await context.transport.request({ method: "GET", path: "/v1/auth/whoami", call });
  return new WhoAmI(answer.body, answer.requestId);
}

/** `fabric.auth`: who the credential is, and the agent credentials it minted. */
export class Auth {
  readonly #context: ClientContext;

  /** @internal */
  constructor(context: ClientContext) {
    this.#context = context;
  }

  /** The calling credential's principal, project and effective grants. */
  whoami(options?: CallOptions): Promise<WhoAmI> {
    const context = this.#context;
    return traced("auth.whoami", options?.signal, async (call) => {
      optionsOf(options, CALL_OPTIONS, "auth.whoami");
      return readWhoAmI(context, call);
    });
  }

  /**
   * Mints an agent credential. Its secret is on the returned object, once.
   *
   * If no answer arrives, the SDK does not ask again: list the agent credentials, and revoke the
   * one with this label whose secret was never seen.
   */
  mintAgentCredential(label: string, options: MintAgentCredentialOptions): Promise<AgentCredential> {
    const context = this.#context;
    return traced("auth.mint_agent_credential", options?.signal, async (call) => {
      const known = optionsOf(options, MINT_OPTIONS, "auth.mintAgentCredential");
      const body: { [member: string]: unknown } = {
        label: text(label, "label"),
        lifetime_seconds: seconds(known.lifetime, "lifetime"),
      };
      if (known.narrowing != null) {
        if (typeof known.narrowing !== "object" || Array.isArray(known.narrowing)) {
          throw new TypeError("narrowing must be an object in the platform's grant schema");
        }
        body["narrowing"] = known.narrowing;
      }
      const answer = await context.transport.request({
        method: "POST",
        path: `${await context.projectPath(call)}/agent-credentials`,
        body,
        call,
      });
      return new AgentCredential(answer.body, answer.requestId);
    });
  }

  /** The agent credentials this credential minted. */
  agentCredentials(options?: CallOptions): Promise<AgentCredential[]> {
    const context = this.#context;
    return traced("auth.agent_credentials", options?.signal, async (call) => {
      optionsOf(options, CALL_OPTIONS, "auth.agentCredentials");
      const answer = await context.transport.request({
        method: "GET",
        path: `${await context.projectPath(call)}/agent-credentials`,
        call,
      });
      const items = answer.body["items"];
      if (!Array.isArray(items)) {
        throw new UnexpectedResponseError("The list of agent credentials has no items.", {
          status: answer.status,
          requestId: answer.requestId,
        });
      }
      return items.map((view: unknown) => new AgentCredential(view, answer.requestId));
    });
  }

  /**
   * Revokes an agent credential this credential minted.
   *
   * With `contain`, the call then cancels what the revoked credential left running: it lists the
   * operations of the project, and for every execution that has not ended and whose actor is this
   * principal under the revoked credential's label, it issues a cancel, each under a key of its
   * own. The returned credential names the executions that were cancelled (`contained`) and the
   * cancels that did not succeed (`containmentErrors`).
   */
  revokeAgentCredential(credentialId: string, options?: RevokeAgentCredentialOptions): Promise<AgentCredential> {
    const context = this.#context;
    return traced("auth.revoke_agent_credential", options?.signal, async (call) => {
      const known = optionsOf(options, REVOKE_OPTIONS, "auth.revokeAgentCredential");
      const contain = flag(known.contain, "contain", false);
      const credential = segment(credentialId, "credentialId");
      const projectPath = await context.projectPath(call);
      const answer = await context.transport.request({
        method: "DELETE",
        path: `${projectPath}/agent-credentials/${credential}`,
        idempotent: true,
        call,
      });
      const revoked = new AgentCredential(answer.body, answer.requestId);
      return contain ? new AgentCredential(answer.body, answer.requestId, await this.#contain(call, projectPath, revoked)) : revoked;
    });
  }

  async #contain(call: Call, projectPath: string, revoked: AgentCredential): Promise<Containment> {
    const context = this.#context;
    const { label } = revoked;
    if (label === null) {
      throw new UnexpectedResponseError(
        `Credential ${revoked.credential_id} was revoked, and its view names no label: the executions it started ` +
          `cannot be told apart from others, so none was cancelled.`,
        { requestId: revoked.requestId },
      );
    }
    // An agent credential acts as the principal that minted it, under its label. The actor of an
    // operation is that pair, so the principal to look for is this credential's own.
    const { principal_id: principal } = await readWhoAmI(context, call);
    const listing = await collect(context, call, `${projectPath}/operations`, (view, requestId) => new Operation(view, requestId));
    const contained: string[] = [];
    const failures: ContainmentFailure[] = [];
    for (const operation of listing.items) {
      const started = operation.type === "execution.create" && !hasEnded(operation);
      if (!started || operation.actor?.principal_id !== principal || operation.actor.agent_label !== label) {
        continue;
      }
      const executionId = operation.target?.execution_id ?? null;
      try {
        if (executionId === null) {
          throw new UnexpectedResponseError(`Operation ${operation.operation_id} names no execution to cancel.`, {
            requestId: operation.requestId,
          });
        }
        const key = newKey();
        requireSuccess(context, await cancelExecution(context, call, projectPath, executionId, key, context.followMax), key);
        contained.push(executionId);
      } catch (error) {
        if (!(error instanceof FabricError)) {
          throw error;
        }
        failures.push({ operationId: operation.operation_id, executionId, error });
      }
    }
    return { contained, failures };
  }
}
