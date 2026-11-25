/**
 * What every test of the SDK stands on: a scripted transport, a virtual clock, and the canary.
 *
 * The scripted transport is a `fetch` that plays a list of exchanges and enforces the matching
 * rules of the client conformance suite: requests arrive in the order of the script, one per
 * exchange, none unexpected and none left over; method and path are equal; query and headers are
 * subsets; a body, when the script states one, is equal. It also refuses any request to an origin
 * other than the configured endpoint.
 *
 * Nothing waits in real time. The client's clock and sleep are virtual, and every wait the client
 * asks for is recorded.
 *
 * Every client a test makes carries a canary credential. Whatever a test gets back from the SDK,
 * returned or thrown, is recorded, and after each test every text form of every recorded object is
 * searched for the credential (see `setup.ts`).
 */

import { readFileSync } from "node:fs";
import { inspect } from "node:util";

import { Fabric } from "../../src/index.js";
import type { FabricOptions, Fetch } from "../../src/index.js";

/** The credential of every client under test. It must never appear in anything the SDK produces. */
export const CANARY_KEY = "acf1_dev_CANARYcanaryCANARY0123456789abcdefCANARY";

export const BASE_URL = "https://acf.example";
export const PROJECT = "prj_0000000000000001";
/** The prefix of every route that acts in the project. */
export const P = `/v1/projects/${PROJECT}`;

export const SBX = `sbx-${"0".repeat(31)}1`;
export const SBX2 = `sbx-${"0".repeat(31)}2`;
export const SNP = `snp-${"0".repeat(31)}1`;
export const EXE = `exe-${"0".repeat(31)}1`;
export const OP = `op-${"a".repeat(32)}`;
export const REQ = "req_000000000000000000000001";

export type Json = { [member: string]: unknown };

// ------------------------------------------------------------------------------- virtual time

/** A clock that moves only when the client sleeps. */
export class VirtualTime {
  now = 0;
  /** Every wait the client asked for, in order. */
  readonly waits: number[] = [];

  readonly clock = (): number => this.now;

  readonly sleep = async (seconds: number, signal?: AbortSignal): Promise<void> => {
    signal?.throwIfAborted();
    this.waits.push(seconds);
    this.now += seconds;
  };

  /** Seconds the client waited, in total. */
  get waited(): number {
    return this.waits.reduce((sum, wait) => sum + wait, 0);
  }
}

// ------------------------------------------------------------------------------- the script

export interface ScriptedRequest {
  readonly method: string;
  readonly path: string;
  readonly query?: { readonly [name: string]: string };
  readonly headers?: { readonly [name: string]: string };
  readonly json?: unknown;
}

export type ScriptedResponse =
  | { readonly status: number; readonly headers?: { readonly [name: string]: string }; readonly json?: unknown; readonly text?: string }
  | { readonly fault: "connection_reset" | "timeout" }
  | { readonly throws: unknown };

export interface Exchange {
  readonly request: ScriptedRequest;
  readonly response: ScriptedResponse;
}

/** A request as the transport received it. */
export interface Received {
  readonly method: string;
  readonly origin: string;
  readonly path: string;
  readonly query: { readonly [name: string]: string };
  /** Header names in lower case. */
  readonly headers: { readonly [name: string]: string };
  /** The body exactly as it was sent. */
  readonly body: string | undefined;
  readonly redirect: string;
}

function deepEqual(left: unknown, right: unknown): boolean {
  if (left === right) {
    return true;
  }
  if (typeof left !== "object" || typeof right !== "object" || left === null || right === null) {
    return false;
  }
  if (Array.isArray(left) !== Array.isArray(right)) {
    return false;
  }
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] && deepEqual((left as Json)[key], (right as Json)[key]))
  );
}

/** In a scripted header: the request must carry the header, with any value. Not part of the suite's format. */
export const SOME_KEY = "$SOME";

/** Puts the idempotency key of the call where the script says `$KEY`, `$KEY:start` and so on. */
function withKey(value: unknown, key: string | undefined): unknown {
  if (typeof value === "string") {
    if (!value.startsWith("$KEY")) {
      return value;
    }
    if (key === undefined) {
      throw new Error("the script names $KEY, and no request has carried an idempotency key yet");
    }
    return key + value.slice("$KEY".length);
  }
  if (Array.isArray(value)) {
    return value.map((item) => withKey(item, key));
  }
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([name, member]) => [name, withKey(member, key)]));
  }
  return value;
}

/** A `fetch` that plays a script and holds the client to it. */
export class Script {
  /** Every request that arrived, expected or not. */
  readonly received: Received[] = [];
  /** Every way the client departed from the script. */
  readonly violations: string[] = [];
  readonly #origin: string;
  readonly #exchanges: readonly Exchange[];
  #key: string | undefined;
  #checked = false;

  /**
   * @param key The idempotency key of the call, when its caller chose one. Otherwise `$KEY` stands
   *   for the key of the first request that carries one.
   */
  constructor(baseUrl: string, exchanges: readonly Exchange[], key?: string) {
    this.#origin = new URL(baseUrl).origin;
    this.#exchanges = exchanges;
    this.#key = key;
  }

  /** The key `$KEY` stands for. */
  get key(): string | undefined {
    return this.#key;
  }

  #violation(message: string): Error {
    this.violations.push(message);
    return new Error(`scripted transport: ${message}`);
  }

  readonly fetch: Fetch = async (url, request) => {
    const target = new URL(url);
    const headers: { [name: string]: string } = {};
    for (const [name, value] of Object.entries(request.headers)) {
      headers[name.toLowerCase()] = value;
    }
    const received: Received = {
      method: request.method,
      origin: target.origin,
      path: target.pathname,
      query: Object.fromEntries(target.searchParams),
      headers,
      body: request.body,
      redirect: request.redirect,
    };
    const index = this.received.push(received) - 1;
    const where = `request ${index + 1} (${received.method} ${received.path})`;

    if (target.origin !== this.#origin) {
      throw this.#violation(`${where} went to ${target.origin}, which is not the configured endpoint ${this.#origin}`);
    }
    const exchange = this.#exchanges[index];
    if (exchange === undefined) {
      throw this.#violation(`${where} is unexpected: the script has ${this.#exchanges.length} exchanges`);
    }
    this.#key ??= headers["idempotency-key"];
    const expected = exchange.request;
    if (received.method !== expected.method || received.path !== expected.path) {
      throw this.#violation(`${where} should be ${expected.method} ${expected.path}`);
    }
    for (const [name, value] of Object.entries(expected.query ?? {})) {
      if (received.query[name] !== value) {
        throw this.#violation(`${where} should carry the query ${name}=${value}; it carries ${String(received.query[name])}`);
      }
    }
    for (const [name, value] of Object.entries(expected.headers ?? {})) {
      if (value === SOME_KEY) {
        if (headers[name.toLowerCase()] === undefined || headers[name.toLowerCase()] === "") {
          throw this.#violation(`${where} should carry the header ${name}; it carries none`);
        }
        continue;
      }
      const wanted = withKey(value, this.#key);
      if (headers[name.toLowerCase()] !== wanted) {
        throw this.#violation(`${where} should carry the header ${name}: ${String(wanted)}; it carries ${String(headers[name.toLowerCase()])}`);
      }
    }
    if (expected.json !== undefined) {
      const sent: unknown = received.body === undefined ? undefined : JSON.parse(received.body);
      const wanted = withKey(expected.json, this.#key);
      if (!deepEqual(sent, wanted)) {
        throw this.#violation(`${where} should carry the body ${JSON.stringify(wanted)}; it carries ${String(received.body)}`);
      }
    }

    const response = exchange.response;
    if ("throws" in response) {
      throw response.throws;
    }
    if ("fault" in response) {
      // A fault happens after the request has been received: the client gets no response.
      if (response.fault === "timeout") {
        throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
      }
      throw new TypeError("fetch failed", { cause: Object.assign(new Error("read ECONNRESET"), { code: "ECONNRESET" }) });
    }
    const body = response.text ?? (response.json === undefined ? "" : JSON.stringify(response.json));
    return new Response(body, { status: response.status, headers: { ...response.headers } });
  };

  /** No request unexpected, none left over. */
  check(): void {
    this.#checked = true;
    if (this.violations.length > 0) {
      throw new Error(`the client departed from the script:\n  ${this.violations.join("\n  ")}`);
    }
    if (this.received.length !== this.#exchanges.length) {
      const next = this.#exchanges[this.received.length]?.request;
      throw new Error(
        `the script has ${this.#exchanges.length} exchanges and the client made ${this.received.length} requests; ` +
          `the next expected was ${next?.method} ${next?.path}`,
      );
    }
  }

  get checked(): boolean {
    return this.#checked;
  }
}

// ------------------------------------------------------------------------------- what a test records

/** The scripts of the running test. Each is checked when the test ends, whether or not the test did. */
export const scripts: Script[] = [];

/** Everything the running test got back from the SDK: returned or thrown. */
export const produced: unknown[] = [];

/** The credentials of the clients of the running test. */
export const secrets = new Set<string>([CANARY_KEY]);

/** Runs a call of the SDK and records what came of it. */
export async function value<Result>(call: () => Promise<Result>): Promise<Result> {
  try {
    const result = await call();
    produced.push(result);
    return result;
  } catch (error) {
    produced.push(error);
    throw error;
  }
}

/** Runs a call of the SDK that must fail, records the error and returns it. */
export async function failure(call: () => Promise<unknown>): Promise<unknown> {
  let result: unknown;
  try {
    result = await call();
  } catch (error) {
    produced.push(error);
    return error;
  }
  produced.push(result);
  throw new Error(`the call succeeded with ${inspect(result, { depth: 1 })}; it should have failed`);
}

/** Every item of an async listing, recorded. */
export async function all<Item>(listing: AsyncIterable<Item>): Promise<Item[]> {
  return value(async () => {
    const items: Item[] = [];
    for await (const item of listing) {
      items.push(item);
    }
    return items;
  });
}

/**
 * Every text form of a value: as a string, as JSON, and as Node.js prints it with nothing held
 * back. For an error also its message, its stack, and the same for what caused it.
 */
export function textForms(subject: unknown): string[] {
  const forms: string[] = [];
  const add = (make: () => unknown): void => {
    try {
      const text = make();
      if (typeof text === "string") {
        forms.push(text);
      }
    } catch {
      // A form that cannot be made shows nothing.
    }
  };
  add(() => String(subject));
  add(() => JSON.stringify(subject));
  const everything = { depth: Infinity, showHidden: true, getters: true, maxStringLength: Infinity, maxArrayLength: Infinity };
  add(() => inspect(subject, everything));
  // Once more without the object's own say in how it is printed: what it holds, not what it shows.
  add(() => inspect(subject, { ...everything, customInspect: false }));
  if (subject instanceof Error) {
    add(() => subject.message);
    add(() => subject.stack);
    if (subject.cause !== undefined) {
      forms.push(...textForms(subject.cause));
    }
  }
  return forms;
}

/** Throws when any text form of the value shows any of the secrets. */
export function expectNoSecret(subject: unknown, forbidden: Iterable<string> = secrets): void {
  for (const text of textForms(subject)) {
    for (const secret of forbidden) {
      if (text.includes(secret)) {
        const at = text.indexOf(secret);
        throw new Error(`a credential appears in a text form of the SDK's output: …${text.slice(Math.max(0, at - 60), at)}[CREDENTIAL]…`);
      }
    }
  }
}

// ------------------------------------------------------------------------------- a client under test

export interface Scripted {
  readonly fabric: Fabric;
  readonly script: Script;
  readonly time: VirtualTime;
  /** The options the client was made with, for a test that makes another like it. */
  readonly options: FabricOptions;
}

/** A client whose transport plays `exchanges`, whose time is virtual, and whose jitter is fixed. */
export function scripted(exchanges: readonly Exchange[], options: FabricOptions = {}, key?: string): Scripted {
  const baseUrl = options.baseUrl ?? BASE_URL;
  const script = new Script(baseUrl, exchanges, key);
  scripts.push(script);
  const time = new VirtualTime();
  const complete: FabricOptions = {
    apiKey: CANARY_KEY,
    baseUrl,
    project: PROJECT,
    fetch: script.fetch,
    clock: time.clock,
    sleep: time.sleep,
    random: () => 0.5,
    ...options,
  };
  if (typeof complete.apiKey === "string") {
    secrets.add(complete.apiKey);
  }
  return { fabric: new Fabric(complete), script, time, options: complete };
}

// ------------------------------------------------------------------------------- exchanges

export function get(path: string, query?: { readonly [name: string]: string }): ScriptedRequest {
  return query === undefined ? { method: "GET", path } : { method: "GET", path, query };
}

/**
 * A keyed mutation. `key` is the key the request must carry: a literal, or `"$KEY"` (with or
 * without a suffix) for the key of the script's one logical call. By default any key will do, for
 * a script that plays several calls, each with a key of its own.
 */
export function post(path: string, json?: unknown, key: string = SOME_KEY): ScriptedRequest {
  const request = { method: "POST", path, headers: { "idempotency-key": key } };
  return json === undefined ? request : { ...request, json };
}

export function del(path: string, query?: { readonly [name: string]: string }, key: string = SOME_KEY): ScriptedRequest {
  const request = { method: "DELETE", path, headers: { "idempotency-key": key } };
  return query === undefined ? request : { ...request, query };
}

export function answer(json: unknown, status = 200, headers: { readonly [name: string]: string } = {}): ScriptedResponse {
  return { status, headers: { "content-type": "application/json", "x-request-id": REQ, ...headers }, json };
}

/** An operation that was accepted and has not ended: 202, with where and when to follow it. */
export function accepted(operation: Json, retryAfter: number | null = 1): ScriptedResponse {
  return answer(operation, 202, {
    location: `${P}/operations/${String(operation["operation_id"])}`,
    ...(retryAfter === null ? {} : { "retry-after": String(retryAfter) }),
  });
}

export const reset: ScriptedResponse = { fault: "connection_reset" };
export const timedOut: ScriptedResponse = { fault: "timeout" };

// ------------------------------------------------------------------------------- the problem registry

export interface RegisteredCode {
  readonly code: string;
  readonly kind: string | null;
  readonly retry: string;
  readonly http_status: number | null;
  readonly retry_after: boolean;
  readonly sdk_exception: string;
  readonly error_answer: boolean;
}

function scalar(text: string): string | number | boolean | null {
  if (text === "null") {
    return null;
  }
  if (text === "true" || text === "false") {
    return text === "true";
  }
  return /^\d+$/.test(text) ? Number(text) : text.replace(/^'(.*)'$/, "$1");
}

/**
 * The platform's problem registry, read from the repository. The file is a flat list of records,
 * which is all this reads of YAML.
 */
export function registry(): RegisteredCode[] {
  const text = readFileSync(new URL("../../../../protocols/api/problems/registry.yaml", import.meta.url), "utf8");
  const records: { [member: string]: unknown }[] = [];
  let inCodes = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^codes:/.test(line)) {
      inCodes = true;
      continue;
    }
    const first = /^- (\w+): (.*)$/.exec(line);
    const next = /^ {2}(\w+): (.*)$/.exec(line);
    if (inCodes && first !== null) {
      records.push({ [first[1] as string]: scalar(first[2] as string) });
    } else if (inCodes && next !== null) {
      (records.at(-1) as { [member: string]: unknown })[next[1] as string] = scalar(next[2] as string);
    }
  }
  return records as unknown as RegisteredCode[];
}

const registered = new Map(registry().map((record) => [record.code, record]));

/** An error answer the platform can give for a code of its registry, or for a code no client has seen. */
export function problem(
  code: string,
  over: {
    readonly kind?: string | undefined;
    readonly retry?: string | undefined;
    readonly status?: number | undefined;
    readonly retryAfter?: number | undefined;
    readonly key?: string | undefined;
    readonly reason?: string | undefined;
    readonly message?: string | undefined;
  } = {},
): ScriptedResponse {
  const known = registered.get(code);
  const status = over.status ?? known?.http_status ?? 400;
  const title = over.message ?? `The title of ${code}`;
  const json: Json = {
    code,
    kind: over.kind ?? known?.kind ?? "REFUSED",
    retry: over.retry ?? known?.retry ?? "NEVER",
    message: title,
    request_id: REQ,
    type: `urn:acf:problem:${code.toLowerCase().replaceAll("_", "-")}`,
    title,
    status,
    detail: title,
    instance: `urn:acf:request:${REQ}`,
  };
  if (over.key !== undefined) {
    json["idempotency_key"] = over.key;
  }
  if (over.reason !== undefined) {
    json["reason"] = over.reason;
  }
  return {
    status,
    headers: {
      "content-type": "application/problem+json",
      "x-request-id": REQ,
      ...(over.retryAfter === undefined ? {} : { "retry-after": String(over.retryAfter) }),
    },
    json,
  };
}

// ------------------------------------------------------------------------------- views

export function sandboxView(over: Json = {}): Json {
  return {
    sandbox_id: SBX,
    project: PROJECT,
    state: "READY",
    generation: 1,
    revision: "r11.0123456789ab",
    image: { alias: "python", digest: `sha256:${"1".repeat(64)}` },
    resources: { vcpus: 1, memory_mib: 512, disk_mib: 1024 },
    network: { mode: "none", entries: [] },
    expires_at: "2026-11-19T12:00:00.000Z",
    notes: [],
    updated_at: "2026-11-19T10:00:02.000Z",
    ...over,
  };
}

export function snapshotView(over: Json = {}): Json {
  return {
    snapshot_id: SNP,
    snapshot_generation: 1,
    project: PROJECT,
    state: "READY",
    revision: "r3.0123456789ab",
    source_sandbox: { sandbox_id: SBX, generation: 1 },
    size_bytes: 4096,
    restore_count: 0,
    incompatible: [],
    created_at: "2026-11-19T10:00:00.000Z",
    ...over,
  };
}

export function executionView(over: Json = {}): Json {
  return {
    execution_id: EXE,
    operation_id: `op-${"c".repeat(32)}`,
    project: PROJECT,
    sandbox_id: SBX,
    generation: 1,
    state: "SUCCEEDED",
    terminal: true,
    status: "EXITED",
    exit_code: 0,
    provenance: { status: "GUEST_REPORTED", exit_code: "GUEST_REPORTED" },
    ...over,
  };
}

export function operationView(over: Json = {}): Json {
  return {
    operation_id: OP,
    project: PROJECT,
    type: "sandbox.create",
    state: "IN_PROGRESS",
    terminal: false,
    target: { sandbox_id: SBX, generation: 1 },
    initiated_by: "CALLER",
    actor: { principal_id: "prn_0000000000000001" },
    created_at: "2026-11-19T10:00:00.000Z",
    updated_at: "2026-11-19T10:00:02.000Z",
    replayed: false,
    recorded: false,
    ...over,
  };
}

/** An operation that succeeded and produced `result`. */
export function succeeded(type: string, result: Json, over: Json = {}): Json {
  return operationView({ type, state: "SUCCEEDED", terminal: true, effect: "APPLIED", result, ...over });
}

/** An operation that ended without success. */
export function ended(type: string, state: string, effect: string | undefined, code: string, over: Json = {}): Json {
  return operationView({
    type,
    state,
    terminal: true,
    ...(effect === undefined ? {} : { effect }),
    failure: { code, retry: "AFTER_CHANGE", message: `The message of ${code}`, side_effect: effect === "NOT_APPLIED" ? "NONE" : "POSSIBLE" },
    ...over,
  });
}

export const CREATE_BODY = { image: "python", resources: { vcpus: 1, memory_mib: 512, disk_mib: 1024 } };
export const CREATE_ARGS = { cpu: 1, memory: 512, disk: 1024 } as const;
