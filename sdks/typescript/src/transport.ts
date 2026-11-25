/**
 * One logical request: sent, and repeated only when repeating it is proven safe.
 *
 * What is repeated, always with the same idempotency key and the same body text:
 *
 * - an error answer whose `retry` says `SAME_REQUEST_LATER`, whatever its code;
 * - no answer at all, for a read, for a mutation that carries a key, and for a mutation whose
 *   repetition is the same as doing it once.
 *
 * What is never repeated: an error answer that says `AFTER_CHANGE` or `NEVER`, an answer with a
 * retry advice this version does not know, `OUTCOME_LOST`, and an answer that is not the
 * platform's. No rule here looks at the HTTP status alone, and none reads message text.
 *
 * `fetch` does not say whether a request left before it failed, so every transport failure is
 * treated as "sent, and no answer came". A mutation without an answer is therefore never reported
 * as refused: with a key it ends as `OutcomeUnresolvedError`, which carries the key to ask again
 * with.
 *
 * The credential lives in this module and nowhere else. It is put into the `Authorization` header
 * of requests to the configured endpoint, and it is removed from any text of foreign origin before
 * that text becomes part of an error.
 */

import {
  APIConnectionError,
  type APIError,
  APITimeoutError,
  errorForAnswer,
  type FabricError,
  IncompatibleServerError,
  OutcomeUnresolvedError,
  UnexpectedResponseError,
} from "./errors.js";
import type { Call } from "./telemetry.js";
import type { Clock, Fetch, JsonObject, Random, Sleep } from "./types.js";
import { API_VERSION, USER_AGENT } from "./version.js";

/** The n-th retry waits a random time in `[0, min(BACKOFF_MAX, BACKOFF_INITIAL * 2 ** n)]` seconds. */
const BACKOFF_INITIAL = 0.5;
const BACKOFF_MAX = 8;

/** A retry is allowed while the retries of the window are fewer than `FLOOR + RATIO * requests of the window`. */
const BUDGET_WINDOW = 60;
const BUDGET_FLOOR = 10;
const BUDGET_RATIO = 0.2;

/** Causes of a failure that a message names, at most. */
const CAUSE_DEPTH = 4;

/** Values of a foreign error that are examined for the credential before the error is given up on. */
const EXAMINED_MAX = 10_000;

/** What stands in an error where the credential stood in the text it was built from. */
const REDACTED = "[redacted]";

export interface RequestSpec {
  readonly method: "GET" | "POST" | "DELETE";
  /** Begins with `/v1/`. Every segment is already percent-encoded. */
  readonly path: string;
  /** A member whose value is `undefined` is not sent. */
  readonly query?: { readonly [name: string]: string | number | undefined } | undefined;
  /** Serialized once. Every attempt sends the same text. */
  readonly body?: JsonObject | undefined;
  /** Sent as `Idempotency-Key`, unchanged, with every attempt. */
  readonly idempotencyKey?: string | undefined;
  /** For a mutation without a key: repeating it is the same as doing it once. */
  readonly idempotent?: boolean | undefined;
  readonly call: Call;
}

export interface Answer {
  readonly status: number;
  readonly body: JsonObject;
  readonly requestId: string | undefined;
  /** `Retry-After` in seconds, when the answer carried one. */
  readonly retryAfter: number | undefined;
}

export interface TransportOptions {
  readonly apiKey: string;
  /** Without a trailing slash, a query or a fragment. */
  readonly baseUrl: string;
  readonly fetch: Fetch;
  readonly timeout: number;
  readonly maxRetries: number;
  readonly retryTotalMax: number;
  readonly clock: Clock;
  readonly sleep: Sleep;
  readonly random: Random;
}

/**
 * How one attempt ended, unless it ended the call by throwing.
 *
 * - `refusal`: an error answer of the platform.
 * - `silence`: no usable answer. The transport failed, the request timed out, or a mutation met a
 *   5xx that is not the platform's.
 */
type Unanswered =
  | { readonly kind: "refusal"; readonly error: APIError }
  | { readonly kind: "silence"; readonly error: FabricError };
type Attempt = { readonly kind: "answer"; readonly answer: Answer } | Unanswered;

export const systemClock: Clock = () => globalThis.performance.now() / 1000;

export const systemSleep: Sleep = (seconds, signal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(signal.reason);
      return;
    }
    const abandon = (): void => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abandon);
      resolve();
    }, seconds * 1000);
    signal?.addEventListener("abort", abandon, { once: true });
  });

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringMember(body: JsonObject, name: string): string | undefined {
  const value = body[name];
  return typeof value === "string" ? value : undefined;
}

/** `Retry-After` as the API defines it: whole seconds. Any other form is not advice this client can act on. */
function retryAfterOf(value: string | null): number | undefined {
  return value !== null && /^\d{1,9}$/.test(value.trim()) ? Number(value.trim()) : undefined;
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

/** Keeps a retry storm from forming against a platform that is shedding load. One per client. */
class RetryBudget {
  readonly #requests: number[] = [];
  readonly #retries: number[] = [];

  static #forget(times: number[], now: number): void {
    let stale = 0;
    while (stale < times.length && (times[stale] ?? now) <= now - BUDGET_WINDOW) {
      stale += 1;
    }
    times.splice(0, stale);
  }

  /** Counts a request that is about to be sent, a first attempt or a retry. */
  request(now: number): void {
    RetryBudget.#forget(this.#requests, now);
    this.#requests.push(now);
  }

  allowsRetry(now: number): boolean {
    RetryBudget.#forget(this.#requests, now);
    RetryBudget.#forget(this.#retries, now);
    return this.#retries.length < BUDGET_FLOOR + BUDGET_RATIO * this.#requests.length;
  }

  retry(now: number): void {
    this.#retries.push(now);
  }
}

export class Transport {
  readonly #apiKey: string;
  readonly #baseUrl: string;
  readonly #fetch: Fetch;
  readonly #timeout: number;
  readonly #maxRetries: number;
  readonly #retryTotalMax: number;
  readonly #clock: Clock;
  readonly #sleep: Sleep;
  readonly #random: Random;
  readonly #budget = new RetryBudget();

  constructor(options: TransportOptions) {
    this.#apiKey = options.apiKey;
    this.#baseUrl = options.baseUrl;
    this.#fetch = options.fetch;
    this.#timeout = options.timeout;
    this.#maxRetries = options.maxRetries;
    this.#retryTotalMax = options.retryTotalMax;
    this.#clock = options.clock;
    this.#sleep = options.sleep;
    this.#random = options.random;
  }

  /** Text of foreign origin, with the credential removed. */
  redact(text: string): string {
    return text.split(this.#apiKey).join(REDACTED);
  }

  /** Sends one logical request and returns its successful answer, or throws what the call ends with. */
  async request(spec: RequestSpec): Promise<Answer> {
    const url = this.#url(spec);
    const body = spec.body === undefined ? undefined : JSON.stringify(spec.body);
    const repeatable = spec.method === "GET" || spec.idempotencyKey !== undefined || spec.idempotent === true;
    const startedAt = this.#clock();
    for (let retries = 0; ; retries += 1) {
      this.#budget.request(this.#clock());
      const attempt = await this.#attempt(spec, url, body);
      if (attempt.kind === "answer") {
        return attempt.answer;
      }
      const delay = this.#delayBeforeRetry(attempt, retries, repeatable, startedAt);
      if (delay === undefined) {
        throw this.#ending(spec, attempt, retries + 1);
      }
      spec.call.retried(retries + 1, delay, attempt.kind === "refusal" ? attempt.error.code : attempt.error.name);
      await this.#sleep(delay, spec.call.signal);
      spec.call.throwIfAbandoned();
    }
  }

  /** Seconds to wait before the next attempt, or `undefined` when the call is not repeated. */
  #delayBeforeRetry(attempt: Unanswered, retries: number, repeatable: boolean, startedAt: number): number | undefined {
    let advised: number | undefined;
    if (attempt.kind === "refusal") {
      // The advice decides, for a code this version knows and for one it does not. OUTCOME_LOST is
      // named because no advice may ever turn it into a repetition.
      if (attempt.error.retry !== "SAME_REQUEST_LATER" || attempt.error.code === "OUTCOME_LOST") {
        return undefined;
      }
      advised = attempt.error.retryAfter;
    } else if (!repeatable) {
      return undefined;
    }
    if (retries >= this.#maxRetries) {
      return undefined;
    }
    if (advised !== undefined && advised > BACKOFF_MAX) {
      // The server asks for more patience than a call has. The caller gets the advice instead.
      return undefined;
    }
    const jittered = this.#random() * Math.min(BACKOFF_MAX, BACKOFF_INITIAL * 2 ** retries);
    const delay = Math.max(jittered, advised ?? 0);
    const now = this.#clock();
    if (now - startedAt + delay > this.#retryTotalMax) {
      return undefined;
    }
    if (!this.#budget.allowsRetry(now)) {
      return undefined;
    }
    this.#budget.retry(now);
    return delay;
  }

  /** What a call that is not repeated ends with. */
  #ending(spec: RequestSpec, attempt: Unanswered, attempts: number): Error {
    if (attempt.kind === "refusal" || spec.idempotencyKey === undefined) {
      return attempt.error;
    }
    const status = attempt.error instanceof UnexpectedResponseError ? attempt.error.status : undefined;
    return new OutcomeUnresolvedError(
      `No usable answer to ${spec.method} ${spec.path} after ${plural(attempts, "attempt")}: whether the request ` +
        `was accepted is not known. Repeat the call later with the same arguments and the same idempotency key ` +
        `(${spec.idempotencyKey}). A new key could create a second operation.`,
      {
        status,
        code: "OUTCOME_UNRESOLVED",
        kind: "UNRESOLVED",
        retry: "SAME_REQUEST_LATER",
        requestId: attempt.error.requestId,
        idempotencyKey: spec.idempotencyKey,
        reason: undefined,
        retryAfter: undefined,
      },
      { cause: attempt.error },
    );
  }

  #url(spec: RequestSpec): string {
    const pairs = Object.entries(spec.query ?? {})
      .filter((pair): pair is [string, string | number] => pair[1] !== undefined)
      .map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(String(value))}`);
    return `${this.#baseUrl}${spec.path}${pairs.length > 0 ? `?${pairs.join("&")}` : ""}`;
  }

  #headers(spec: RequestSpec, hasBody: boolean): { [name: string]: string } {
    const headers: { [name: string]: string } = {
      Accept: "application/json, application/problem+json",
      Authorization: `Bearer ${this.#apiKey}`,
      "User-Agent": USER_AGENT,
    };
    if (hasBody) {
      headers["Content-Type"] = "application/json";
    }
    if (spec.idempotencyKey !== undefined) {
      headers["Idempotency-Key"] = spec.idempotencyKey;
    }
    return headers;
  }

  async #attempt(spec: RequestSpec, url: string, body: string | undefined): Promise<Attempt> {
    const { call } = spec;
    call.throwIfAbandoned();
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.#timeout * 1000);
    const abandon = (): void => controller.abort();
    call.signal?.addEventListener("abort", abandon, { once: true });

    let status: number;
    let text: string;
    let requestId: string | undefined;
    let retryAfter: number | undefined;
    try {
      const response = await this.#fetch(url, {
        method: spec.method,
        headers: this.#headers(spec, body !== undefined),
        ...(body === undefined ? {} : { body }),
        signal: controller.signal,
        redirect: "manual",
      });
      // The timeout covers the body: an answer cut off halfway is no answer.
      text = await response.text();
      status = response.status;
      requestId = response.headers.get("x-request-id") ?? undefined;
      retryAfter = retryAfterOf(response.headers.get("retry-after"));
    } catch (failure) {
      if (call.signal?.aborted === true) {
        // The caller abandoned the call. Nothing is assumed and nothing is cancelled on the server.
        throw call.signal.reason;
      }
      return { kind: "silence", error: this.#noAnswer(spec, failure, timedOut) };
    } finally {
      clearTimeout(timer);
      call.signal?.removeEventListener("abort", abandon);
    }
    return this.#read(spec, { status, text, requestId, retryAfter });
  }

  /** Classifies an HTTP answer. Throws for an answer that ends the call whatever the retry rules say. */
  #read(
    spec: RequestSpec,
    response: { status: number; text: string; requestId: string | undefined; retryAfter: number | undefined },
  ): Attempt {
    const { status, retryAfter } = response;
    const what = `${spec.method} ${spec.path}`;
    let body: unknown;
    try {
      body = JSON.parse(response.text);
    } catch {
      body = undefined;
    }

    if (status >= 200 && status < 300) {
      if (!isObject(body)) {
        throw new UnexpectedResponseError(`${what} was answered ${status} with a body that is not a JSON object.`, {
          status,
          requestId: response.requestId,
        });
      }
      return { kind: "answer", answer: { status, body, requestId: response.requestId, retryAfter } };
    }

    const code = isObject(body) ? stringMember(body, "code") : undefined;
    if (isObject(body) && code !== undefined) {
      const kind = stringMember(body, "kind") ?? "";
      const message = stringMember(body, "message") ?? `${what} was answered ${status} with code ${code}.`;
      const reason = stringMember(body, "reason");
      const error = errorForAnswer(this.redact(message), {
        status,
        code,
        kind,
        retry: stringMember(body, "retry") ?? "",
        requestId: stringMember(body, "request_id") ?? response.requestId,
        // An unresolved answer names the key to ask again with. When it does not, the key that was sent is that key.
        idempotencyKey: stringMember(body, "idempotency_key") ?? (kind === "UNRESOLVED" ? spec.idempotencyKey : undefined),
        reason: reason === undefined ? undefined : this.redact(reason),
        retryAfter,
      });
      return { kind: "refusal", error };
    }

    if (status === 404) {
      throw new IncompatibleServerError(
        `${what} was answered 404 without a problem document: the server at ${this.#baseUrl} does not speak ` +
          `API ${API_VERSION}, which this SDK requires. Check baseUrl, or use the SDK that matches the server.`,
        { requestId: response.requestId },
      );
    }
    const fault = new UnexpectedResponseError(
      `${what} was answered ${status} without a problem document: the answer is not the platform's.` +
        (status >= 500 && spec.method !== "GET" ? " Whether the request was accepted is not known." : ""),
      { status, requestId: response.requestId },
    );
    if (status >= 500 && spec.method !== "GET") {
      // Something in front of the platform failed after the request may have reached it.
      return { kind: "silence", error: fault };
    }
    throw fault;
  }

  /**
   * The error for a request that got no answer. The credential never reaches it, whatever the
   * transport said: its words are redacted, and it is attached as `cause` only when nothing in it
   * shows the credential. A transport that quotes its request headers in its errors is common.
   */
  #noAnswer(spec: RequestSpec, failure: unknown, timedOut: boolean): FabricError {
    const what = `${spec.method} ${spec.path}`;
    const cause = shows(failure, this.#apiKey) ? undefined : failure;
    if (timedOut || (failure instanceof Error && failure.name === "TimeoutError")) {
      return new APITimeoutError(`No answer to ${what} within ${this.#timeout} s.`, { cause });
    }
    return new APIConnectionError(`No answer to ${what}: ${this.redact(describe(failure))}.`, { cause });
  }
}

/**
 * Whether a value of foreign origin shows a secret anywhere a printer would reach: in a string, a
 * property name, a nested object, a cause, the entries of a map or a set. What cannot be examined
 * counts as showing it: a value too large to walk, an accessor that would have to be run, a value
 * that throws when it is looked at.
 */
function shows(subject: unknown, secret: string): boolean {
  try {
    const visited = new Set<object>();
    const pending: unknown[] = [subject];
    for (let examined = 0; pending.length > 0; examined += 1) {
      if (examined >= EXAMINED_MAX) {
        return true;
      }
      const current = pending.pop();
      if (typeof current === "string") {
        if (current.includes(secret)) {
          return true;
        }
        continue;
      }
      if (typeof current !== "object" || current === null || visited.has(current)) {
        continue;
      }
      visited.add(current);
      const isError = current instanceof Error;
      if (isError) {
        // What every printer of an error reads. Depending on the engine these are data of the
        // error, accessors of the error, or accessors of its prototype; reading them covers all three.
        pending.push(current.name, current.message, current.stack);
      }
      if (current instanceof Map) {
        pending.push(...current.keys(), ...current.values());
      } else if (current instanceof Set) {
        pending.push(...current);
      }
      for (const name of Reflect.ownKeys(current)) {
        const property = Object.getOwnPropertyDescriptor(current, name);
        if (property === undefined || (isError && name === "stack")) {
          continue;
        }
        if (!("value" in property)) {
          return true;
        }
        pending.push(typeof name === "string" ? name : name.description, property.value);
      }
    }
    return false;
  } catch {
    return true;
  }
}

/** A transport failure in words: its own, and those of what caused it. */
function describe(failure: unknown): string {
  const parts: string[] = [];
  let current = failure;
  for (let depth = 0; depth <= CAUSE_DEPTH && current !== undefined && current !== null; depth += 1) {
    if (current instanceof Error) {
      parts.push(current.message === "" ? current.name : `${current.name}: ${current.message}`);
      current = current.cause;
    } else {
      parts.push(typeof current === "string" ? current : `a thrown value of type ${typeof current}`);
      break;
    }
  }
  return parts.length > 0 ? parts.join(", caused by ") : "the transport failed without saying why";
}
