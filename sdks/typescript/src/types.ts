/**
 * The types of the SDK's surface: what a caller passes, and the views the platform answers with.
 *
 * Two naming rules meet here, on purpose. A member of a server view keeps the name the server sends
 * (`sandbox_id`, `expires_at`), so that a view reads exactly like the JSON it came from. Everything
 * the SDK itself defines (options, methods, the fields it adds) is camelCase.
 *
 * Every vocabulary of the platform (states, statuses, codes, effects) is typed `string`. The platform
 * may add a value within an API major, and a value this SDK has never seen must reach the caller
 * unchanged: it is never an error and never mapped onto a known one.
 */

// ----------------------------------------------------------------------------------- JSON

/** A JSON object as it was received. */
export type JsonObject = { readonly [member: string]: unknown };

/**
 * A view exactly as the server sent it: the members this SDK knows, typed, and every other member
 * the server sent, reachable by name as `unknown`.
 */
export type Raw<View> = View & JsonObject;

/**
 * A view as a returned object exposes it. Every member is present: one the server left out carries
 * the default of its schema (`null`, an empty list, `false`), so that reading it never yields
 * `undefined`.
 */
export type Normalized<View> = { readonly [Member in keyof View]-?: Exclude<View[Member], undefined> };

// ----------------------------------------------------------------------------------- shared views

/** Why an operation, a sandbox or a snapshot failed, as the host reported it. */
export interface Failure {
  /** A failure class of the public vocabulary, or `UNRECOGNIZED`. */
  readonly code: string;
  /** The host's value, when `code` is `UNRECOGNIZED`. */
  readonly code_raw?: string | null;
  readonly retry: string;
  readonly message: string;
  readonly side_effect?: string | null;
  /** The host's value, when `side_effect` is `UNRECOGNIZED`. */
  readonly side_effect_raw?: string | null;
}

export interface Image {
  readonly alias?: string | null;
  /** Identity of the image the sandbox runs. */
  readonly digest: string;
}

/** What a sandbox was given: vCPUs and MiB. */
export interface ResourcesView {
  readonly vcpus: number;
  readonly memory_mib: number;
  readonly disk_mib: number;
}

/** One inclusive range of TCP ports. */
export interface PortRangeView {
  readonly from: number;
  readonly to: number;
}

export interface AllowEntryView {
  readonly name?: string | null;
  readonly network?: string | null;
  readonly ports: readonly PortRangeView[];
}

export interface NetworkView {
  readonly mode: string;
  readonly mode_raw?: string | null;
  readonly entries?: readonly AllowEntryView[];
}

export interface SnapshotRef {
  readonly snapshot_id: string;
  readonly snapshot_generation: number;
}

export interface SandboxRef {
  readonly sandbox_id: string;
  readonly generation: number;
}

export interface OutputSummary {
  readonly stored_bytes: number;
  readonly produced_bytes: number;
  readonly completeness: string;
  readonly completeness_raw?: string | null;
}

export interface Durations {
  /** Reported by the guest. */
  readonly guest_ms?: number | null;
  /** Observed by the host. */
  readonly wall_ms?: number | null;
}

/** Who asked for an operation, as the host recorded it. */
export interface Actor {
  readonly principal_id?: string | null;
  /** Chosen by whoever minted the agent credential: text this caller did not write. */
  readonly agent_label?: string | null;
}

/** Identifiers of what an operation acts on and of what it produced. */
export interface OperationTarget {
  readonly sandbox_id?: string | null;
  readonly generation?: number | null;
  readonly snapshot_id?: string | null;
  readonly snapshot_generation?: number | null;
  readonly execution_id?: string | null;
}

/** The resource an operation produced, as of the answer that carried it. Absent in a recorded view. */
export interface OperationResult {
  readonly sandbox?: SandboxView | null;
  readonly snapshot?: SnapshotView | null;
  readonly execution?: ExecutionView | null;
}

export interface CredentialView {
  readonly credential_id: string;
  readonly kind: string;
  readonly agent_label?: string | null;
  readonly expires_at: string;
}

export interface Ceilings {
  readonly vcpus: number;
  readonly memory_mib: number;
  readonly disk_mib: number;
  readonly execution_timeout_seconds: number;
  readonly sandbox_lifetime_seconds: number;
  readonly allowlist_entries: number;
}

// ----------------------------------------------------------------------------------- resource views

export interface SandboxView {
  readonly sandbox_id: string;
  readonly project: string;
  /** An alias, unique in the project. Chosen by a caller: text this SDK did not write. */
  readonly name?: string | null;
  readonly state: string;
  readonly state_raw?: string | null;
  /** The generation a mutation must name. A restore in place starts a new one. */
  readonly generation: number;
  /** Opaque validator, also sent as `ETag`. Compare for equality only. */
  readonly revision: string;
  readonly image: Image;
  readonly resources: ResourcesView;
  readonly network: NetworkView;
  readonly expires_at: string;
  readonly last_execution?: string | null;
  readonly quarantined?: string | null;
  readonly failure?: Failure | null;
  readonly source_snapshot?: SnapshotRef | null;
  /** Observed by the host. */
  readonly notes?: readonly string[];
  readonly updated_at: string;
}

export interface SnapshotView {
  readonly snapshot_id: string;
  readonly snapshot_generation: number;
  readonly project: string;
  /** An alias, unique in the project. Chosen by a caller: text this SDK did not write. */
  readonly name?: string | null;
  readonly state: string;
  readonly state_raw?: string | null;
  readonly revision: string;
  readonly source_sandbox?: SandboxRef | null;
  readonly size_bytes: number;
  readonly restore_count: number;
  /** Why the snapshot cannot be restored on this host, as the host observed it. */
  readonly incompatible?: readonly string[];
  readonly failure?: Failure | null;
  readonly created_at: string;
}

/** One command run in one generation of one sandbox. */
export interface ExecutionView {
  readonly execution_id: string;
  readonly operation_id: string;
  readonly project: string;
  readonly sandbox_id?: string | null;
  readonly generation?: number | null;
  /** State of the operation that runs the command. */
  readonly state: string;
  readonly state_raw?: string | null;
  readonly terminal: boolean;
  /** How the command ended, as the guest reported it. */
  readonly status?: string | null;
  readonly status_raw?: string | null;
  /** Reported by the guest. A status other than 0 is a result, not an error. */
  readonly exit_code?: number | null;
  /** Reported by the guest. */
  readonly signal?: number | null;
  readonly durations?: Durations | null;
  readonly stdout?: OutputSummary | null;
  readonly stderr?: OutputSummary | null;
  readonly host_backstop_fired?: boolean | null;
  readonly runtime_ended?: boolean | null;
  readonly evidence_status?: string | null;
  readonly evidence_status_raw?: string | null;
  readonly note?: string | null;
  /** The provenance label of each field of this result: `HOST_OBSERVED` or `GUEST_REPORTED`. */
  readonly provenance?: { readonly [field: string]: string };
}

/** A slice of one stream of an execution's stored output. The bytes are guest data. */
export interface OutputChunkView {
  readonly execution_id: string;
  readonly stream: string;
  readonly offset: number;
  readonly data_base64: string;
  readonly next_offset: number;
  readonly eof: boolean;
  readonly stored_bytes: number;
  readonly produced_bytes: number;
  readonly completeness: string;
  readonly completeness_raw?: string | null;
  readonly provenance?: string;
}

/** One accepted mutation. Exactly one host operation stands behind it. */
export interface OperationView {
  readonly operation_id: string;
  readonly project: string;
  readonly type: string;
  readonly type_raw?: string | null;
  readonly state: string;
  readonly state_raw?: string | null;
  /**
   * The server's own judgement, false for every state the server does not know. The SDK decides
   * whether an operation has ended from `state`, against the states it knows itself.
   */
  readonly terminal: boolean;
  readonly effect?: string | null;
  readonly effect_raw?: string | null;
  readonly failure?: Failure | null;
  readonly cleanup?: string | null;
  readonly cleanup_raw?: string | null;
  readonly cancelled_by?: string | null;
  readonly cancelled_by_raw?: string | null;
  readonly target: OperationTarget;
  readonly result?: OperationResult | null;
  readonly initiated_by: string;
  readonly initiated_by_raw?: string | null;
  readonly actor?: Actor | null;
  readonly created_at?: string | null;
  readonly updated_at?: string | null;
  /** True when the answer reports work that existed before the request that received it. */
  readonly replayed?: boolean;
  /** True when the host no longer holds the operation and this is the outcome the platform recorded. */
  readonly recorded?: boolean;
  readonly idempotency_key_digest?: string | null;
}

export interface AgentCredentialView {
  readonly credential_id: string;
  readonly kind: string;
  /** Chosen by whoever minted the credential: text this caller may not have written. */
  readonly label?: string | null;
  readonly display_prefix: string;
  readonly status: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly narrowing?: JsonObject | null;
  /** The credential itself. Present once, in the answer to minting, and never again. */
  readonly secret?: string | null;
}

export interface WhoAmIView {
  readonly principal_id: string;
  readonly project_id: string;
  readonly credential: CredentialView;
  /** The effective grants of this credential, and of no other. */
  readonly grants: JsonObject;
  readonly policy_version: string;
}

/** Platform info. The members after `serving` are shown to an authenticated caller only. */
export interface InfoView {
  readonly api_versions: readonly string[];
  readonly serving: boolean;
  /** Whether the platform accepts granting work now. */
  readonly ready?: boolean | null;
  readonly not_ready_reasons?: readonly string[] | null;
  readonly platform_features?: readonly string[] | null;
  readonly host_features?: readonly string[] | null;
  readonly parameters?: { readonly [name: string]: number | boolean } | null;
  readonly ceilings?: Ceilings | null;
}

// ----------------------------------------------------------------------------------- what a caller passes

/**
 * Memory or disk: an integer number of MiB, or a string with a binary unit (`"512MiB"`, `"4GiB"`).
 * Anything ambiguous is refused: `"4GB"`, `"4G"`, a value that is not a whole number of MiB.
 */
export type Size = number | string;

/**
 * A duration: an integer number of seconds, or a string with a unit (`"90s"`, `"10m"`, `"2h"`,
 * `"1d"`). A value that is not a whole number of seconds is refused.
 */
export type Duration = number | string;

/** One port, or an inclusive `[from, to]` range. */
export type Port = number | readonly [from: number, to: number];

/** Outbound TLS to an exact DNS name, on the listed ports. */
export interface AllowName {
  readonly name: string;
  readonly ports: readonly Port[];
}

/** Outbound TCP to an IPv4 network in CIDR form, on the listed ports. */
export interface AllowNetwork {
  readonly network: string;
  readonly ports: readonly Port[];
}

/** Outbound connections to the listed destinations only. */
export interface NetworkAllowlist {
  readonly mode: "allowlist";
  readonly entries: readonly (AllowName | AllowNetwork)[];
}

/** `"none"`: no network device exists in the sandbox. Or an allowlist. No other mode exists. */
export type Network = "none" | NetworkAllowlist;

/** The generation a mutation acts on: a number, or `"current"` to let the platform read it. */
export type Generation = number | "current";

/** What every call accepts. */
export interface CallOptions {
  /**
   * Abandons the call: the pending request is dropped and no further one is made. Nothing is
   * cancelled on the server; an operation that was accepted continues.
   */
  readonly signal?: AbortSignal | undefined;
}

/** What every call that creates an operation accepts. */
export interface MutationOptions extends CallOptions {
  /**
   * The idempotency key of this call: 1 to 255 characters in the range 0x21 to 0x7E. Pass one to be
   * able to repeat the call later, from this process or another, without creating a second
   * operation. When absent the SDK generates a UUID.
   */
  readonly idempotencyKey?: string | undefined;
  /** Seconds to follow the operation before reporting it as still running. Default: the client's. */
  readonly followMax?: number | undefined;
}

/** What a mutation of a sandbox accepts. */
export interface SandboxMutationOptions extends MutationOptions {
  /**
   * The generation the request acts on. Default: the generation this handle last observed. Pass
   * `"current"` to act on whatever generation the sandbox has when the platform reads it.
   */
  readonly generation?: Generation | undefined;
}

export interface SandboxCreateOptions extends MutationOptions {
  /** vCPUs: a positive integer. */
  readonly cpu: number;
  readonly memory: Size;
  readonly disk: Size;
  /** Default when absent: the platform's, which is no network. */
  readonly network?: Network | undefined;
  /** An alias, unique in the project. */
  readonly name?: string | undefined;
  /** Lifetime from creation. Default: the host's. */
  readonly lifetime?: Duration | undefined;
  /** Start the sandbox after creating it. Default `true`. */
  readonly start?: boolean | undefined;
  /**
   * What happens to the created sandbox when its start is refused or ends without success.
   * `"destroy"` (the default) destroys it; `"keep"` leaves it. Either way the call throws
   * `SandboxStartError`.
   */
  readonly onStartFailure?: "destroy" | "keep" | undefined;
}

export interface ExecOptions extends SandboxMutationOptions {
  readonly cwd?: string | undefined;
  readonly env?: { readonly [name: string]: string } | undefined;
  /** How long the command may run. */
  readonly timeout?: Duration | undefined;
}

export interface RefreshOptions extends CallOptions {
  /**
   * For a handle obtained by a name: accept that the name now belongs to another sandbox, and make
   * this handle that sandbox. Default `false`: `refresh` throws `NameReboundError` instead.
   */
  readonly rebind?: boolean | undefined;
}

export interface RestoreAsNewOptions extends MutationOptions {
  readonly name?: string | undefined;
  readonly lifetime?: Duration | undefined;
}

/** Which stream of an execution's output. */
export type OutputStream = "stdout" | "stderr";

export interface OutputOptions extends CallOptions {
  /** Byte offset into the stored output of the stream. Default 0. */
  readonly offset?: number | undefined;
  /** At most this many bytes. The platform caps it. */
  readonly maxBytes?: number | undefined;
}

export interface TextOptions extends CallOptions {
  /** A label the platform's `TextDecoder` knows. Default `"utf-8"`. */
  readonly encoding?: string | undefined;
  /** `"strict"` (the default) throws on bytes that are not valid in the encoding; `"replace"` substitutes U+FFFD. */
  readonly errors?: "strict" | "replace" | undefined;
}

export interface OperationGetOptions extends CallOptions {
  /** Whole seconds the platform may hold the request open for the operation to end. */
  readonly wait?: number | undefined;
}

export interface OperationWaitOptions extends CallOptions {
  /** Seconds to follow the operation before reporting it as still running. Default: the client's. */
  readonly followMax?: number | undefined;
}

export interface MintAgentCredentialOptions extends CallOptions {
  readonly lifetime: Duration;
  /** A subset of this credential's effective grants, in the platform's grant schema. Default: the `agent` template. */
  readonly narrowing?: JsonObject | undefined;
}

export interface RevokeAgentCredentialOptions extends CallOptions {
  /**
   * After revoking, cancel every unfinished execution the revoked credential started. A revocation
   * alone ends what the credential may ask for, not what it already started.
   */
  readonly contain?: boolean | undefined;
}

// ----------------------------------------------------------------------------------- the client

/** What the SDK needs of an HTTP response. Every `Response` of the platform's `fetch` has it. */
export interface FetchResponse {
  readonly status: number;
  readonly headers: { get(name: string): string | null };
  text(): Promise<string>;
}

/** What the SDK passes with every request. */
export interface FetchRequest {
  readonly method: string;
  readonly headers: { readonly [name: string]: string };
  readonly body?: string;
  readonly signal: AbortSignal;
  /** A redirect is never followed: the credential goes to the configured endpoint and nowhere else. */
  readonly redirect: "manual";
}

/** The transport: the platform's `fetch`, or anything with this part of its shape. */
export type Fetch = (url: string, request: FetchRequest) => Promise<FetchResponse>;

/** A monotonic clock, in seconds. */
export type Clock = () => number;

/** Waits the given number of seconds. Rejects with the signal's reason when the signal aborts. */
export type Sleep = (seconds: number, signal?: AbortSignal) => Promise<void>;

/** A uniform random number in `[0, 1)`. */
export type Random = () => number;

export interface FabricOptions {
  /** The credential. Default: the environment variable `ACF_API_KEY`. */
  readonly apiKey?: string | undefined;
  /** The endpoint, `https://`, or `http://` to a loopback address. Default: `ACF_BASE_URL`. */
  readonly baseUrl?: string | undefined;
  /**
   * The project. Default: `ACF_PROJECT`, else the project the credential is bound to, read once
   * from the platform on first need.
   */
  readonly project?: string | undefined;
  /** Seconds one HTTP request may take. It does not bound a followed operation. Default 120. */
  readonly timeout?: number | undefined;
  /** How often one call is retried. Default 2. */
  readonly maxRetries?: number | undefined;
  /** Seconds a call follows its operation before reporting it as still running. Default 1800. */
  readonly followMax?: number | undefined;
  /**
   * Seconds one call may spend retrying. Default 82800: the platform remembers an idempotency key
   * for a day, and the last retry must arrive while it still does.
   */
  readonly retryTotalMax?: number | undefined;
  /** Allow `http://` to an address that is not loopback. The credential then travels in clear text. */
  readonly allowInsecureHttp?: boolean | undefined;
  /**
   * Allow the client to be constructed in a browser page. A credential in a page is a credential
   * published to everyone who can open the page.
   */
  readonly dangerouslyAllowBrowser?: boolean | undefined;
  /** The transport. Default: the platform's `fetch`. */
  readonly fetch?: Fetch | undefined;
  /** Replaces the clock, for tests. */
  readonly clock?: Clock | undefined;
  /** Replaces the wait between retries and while following, for tests. */
  readonly sleep?: Sleep | undefined;
  /** Replaces the source of jitter, for tests. */
  readonly random?: Random | undefined;
}
