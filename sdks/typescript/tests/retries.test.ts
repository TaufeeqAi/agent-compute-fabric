/**
 * Retries: only what is retryable, always the same key and the same body, the server's advice
 * honoured and capped, a budget per client, a cap on the time one call spends retrying.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import * as sdk from "../src/index.js";
import type { Fetch } from "../src/index.js";
import { systemClock, systemSleep } from "../src/transport.js";
import {
  accepted,
  answer,
  CANARY_KEY,
  CREATE_ARGS,
  CREATE_BODY,
  type Exchange,
  failure,
  get,
  operationView,
  P,
  post,
  problem,
  registry,
  reset,
  sandboxView,
  SBX,
  scripted,
  succeeded,
  timedOut,
  value,
  VirtualTime,
} from "./support/harness.js";

const CREATED = answer(succeeded("sandbox.create", { sandbox: sandboxView() }));
const CREATE = post(`${P}/sandboxes`, CREATE_BODY, "$KEY");
const READ = get(`${P}/sandboxes/${SBX}`);
const SANDBOX = answer(sandboxView());
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const create = (fabric: sdk.Fabric, options: object = {}) => fabric.sandboxes.create("python", { ...CREATE_ARGS, start: false, ...options });
const read = (fabric: sdk.Fabric) => fabric.sandboxes.get(SBX);

/** `count` copies of one exchange. */
function times(count: number, exchange: Exchange): Exchange[] {
  return Array.from({ length: count }, () => exchange);
}

describe("which answers are repeated", () => {
  const answers = registry().filter((record) => record.error_answer && record.http_status !== null);

  it("the registry names the codes this suite expects to find", () => {
    expect(answers.map((record) => record.code)).toEqual(expect.arrayContaining(["RATE_LIMITED", "OUTCOME_UNRESOLVED", "OUTCOME_LOST", "STATE_CONFLICT"]));
  });

  it.each(answers.filter((record) => record.retry === "SAME_REQUEST_LATER").map((record) => [record.code, record] as const))(
    "%s says SAME_REQUEST_LATER: the same request is sent again, and its answer is the call's",
    async (code, record) => {
      const refusal = problem(code, record.retry_after ? { retryAfter: 1 } : {});
      const { fabric, script } = scripted([
        { request: CREATE, response: refusal },
        { request: CREATE, response: CREATED },
      ]);
      const sandbox = await value(() => create(fabric));
      expect(sandbox.sandbox_id).toBe(SBX);
      expect(script.received[1]?.headers["idempotency-key"]).toBe(script.received[0]?.headers["idempotency-key"]);
      expect(script.received[1]?.body).toBe(script.received[0]?.body);
    },
  );

  it.each(answers.filter((record) => record.retry === "SAME_REQUEST_LATER").map((record) => [record.code, record] as const))(
    "%s that persists is thrown as the class the registry names",
    async (code, record) => {
      const refusal = { request: CREATE, response: problem(code, { key: record.kind === "UNRESOLVED" ? "resume-1" : undefined, retryAfter: 1 }) };
      const { fabric } = scripted(times(3, refusal), {}, "resume-1");
      const error = await failure(() => create(fabric, { idempotencyKey: "resume-1" }));
      expect((error as Error).name).toBe(record.sdk_exception);
      expect(error).toBeInstanceOf(record.kind === "UNRESOLVED" ? sdk.UnresolvedError : sdk.RefusedError);
      expect(error).toMatchObject({ code, kind: record.kind, retry: "SAME_REQUEST_LATER", retryAfter: 1 });
    },
  );

  it.each(answers.filter((record) => record.retry !== "SAME_REQUEST_LATER").map((record) => [record.code, record] as const))(
    "%s does not say SAME_REQUEST_LATER: it is thrown at once, as the class the registry names",
    async (code, record) => {
      const { fabric, script } = scripted([{ request: CREATE, response: problem(code) }]);
      const error = await failure(() => create(fabric));
      expect((error as Error).name).toBe(record.sdk_exception);
      expect(error).toMatchObject({ code, kind: record.kind, retry: record.retry, status: record.http_status });
      expect(script.received).toHaveLength(1);
    },
  );

  it("an advice the client has never seen is not a reason to repeat", async () => {
    const { fabric } = scripted([{ request: CREATE, response: problem("RATE_LIMITED", { retry: "WHENEVER_YOU_LIKE" }) }]);
    const error = await failure(() => create(fabric));
    expect(error).toBeInstanceOf(sdk.RateLimitError);
    expect(error).toMatchObject({ retry: "WHENEVER_YOU_LIKE" });
  });

  it("OUTCOME_LOST is never repeated, whatever advice came with it", async () => {
    const lost = problem("OUTCOME_LOST", { retry: "SAME_REQUEST_LATER", retryAfter: 1, key: "lost-1" });
    const { fabric, script } = scripted([{ request: CREATE, response: lost }], {}, "lost-1");
    const error = await failure(() => create(fabric, { idempotencyKey: "lost-1" }));
    expect(error).toBeInstanceOf(sdk.OutcomeLostError);
    expect(error).toMatchObject({ idempotencyKey: "lost-1" });
    expect(script.received).toHaveLength(1);
  });

  it("the HTTP status alone decides nothing: the same status is repeated or not by what the answer says", async () => {
    const conflict = scripted([{ request: CREATE, response: problem("STATE_CONFLICT", { status: 503, retryAfter: 1 }) }]);
    expect(await failure(() => create(conflict.fabric))).toBeInstanceOf(sdk.StateConflictError);

    const later = scripted([
      { request: CREATE, response: problem("RATE_LIMITED", { status: 400 }) },
      { request: CREATE, response: CREATED },
    ]);
    await value(() => create(later.fabric));
  });

  it("message text decides nothing", async () => {
    const { fabric, script } = scripted([{ request: CREATE, response: problem("PERMISSION_DENIED", { message: "please retry later, SAME_REQUEST_LATER" }) }]);
    expect(await failure(() => create(fabric))).toBeInstanceOf(sdk.PermissionDeniedError);
    expect(script.received).toHaveLength(1);
  });
});

describe("no answer", () => {
  it("a mutation with a key is sent again, with the key it generated before the first attempt and the same bytes", async () => {
    const { fabric, script } = scripted([
      { request: CREATE, response: reset },
      { request: CREATE, response: timedOut },
      { request: CREATE, response: CREATED },
    ]);
    await value(() => create(fabric));
    const keys = script.received.map((request) => request.headers["idempotency-key"]);
    expect(keys[0]).toMatch(UUID4);
    expect(new Set(keys).size).toBe(1);
    expect(new Set(script.received.map((request) => request.body)).size).toBe(1);
    expect(script.received[0]?.body).toBe(JSON.stringify(CREATE_BODY));
  });

  it("a mutation that never gets an answer is unresolved, never refused, and the error carries the key", async () => {
    const { fabric, script } = scripted(times(3, { request: CREATE, response: reset }));
    const error = await failure(() => create(fabric));
    expect(error).toBeInstanceOf(sdk.OutcomeUnresolvedError);
    expect(error).not.toBeInstanceOf(sdk.RefusedError);
    expect(error).toMatchObject({
      code: "OUTCOME_UNRESOLVED",
      kind: "UNRESOLVED",
      retry: "SAME_REQUEST_LATER",
      status: undefined,
      idempotencyKey: script.received[0]?.headers["idempotency-key"],
    });
    expect((error as Error).message).toContain(script.key);
    expect((error as Error).cause).toBeInstanceOf(sdk.APIConnectionError);
  });

  it("is unresolved after one attempt when the client may not retry", async () => {
    const { fabric } = scripted([{ request: CREATE, response: reset }], { maxRetries: 0 }, "once-1");
    const error = await failure(() => create(fabric, { idempotencyKey: "once-1" }));
    expect(error).toBeInstanceOf(sdk.OutcomeUnresolvedError);
    expect(error).toMatchObject({ idempotencyKey: "once-1" });
    expect((error as Error).message).toMatch(/after 1 attempt:/);
  });

  it("a read is sent again, and one that never gets an answer says the server could not be reached", async () => {
    const recovered = scripted([
      { request: READ, response: reset },
      { request: READ, response: SANDBOX },
    ]);
    await value(() => read(recovered.fabric));

    const unreachable = scripted(times(3, { request: READ, response: reset }));
    const error = await failure(() => read(unreachable.fabric));
    expect(error).toBeInstanceOf(sdk.APIConnectionError);
    expect(error).not.toBeInstanceOf(sdk.APITimeoutError);
    expect((error as Error).message).toMatch(/^No answer to GET \/v1\/projects\/prj_0000000000000001\/sandboxes\/sbx-0+1: TypeError: fetch failed, caused by Error: read ECONNRESET\.$/);
  });

  it("a read that times out every time ends as a timeout", async () => {
    const { fabric } = scripted(times(3, { request: READ, response: timedOut }));
    const error = await failure(() => read(fabric));
    expect(error).toBeInstanceOf(sdk.APITimeoutError);
    expect(error).toBeInstanceOf(sdk.APIConnectionError);
  });

  it("minting carries no key and is not repeated: a second request could be a second credential", async () => {
    const mint = { method: "POST", path: `${P}/agent-credentials`, json: { label: "worker", lifetime_seconds: 3600 } };
    const { fabric, script } = scripted([{ request: mint, response: reset }]);
    const error = await failure(() => fabric.auth.mintAgentCredential("worker", { lifetime: "1h" }));
    expect(error).toBeInstanceOf(sdk.APIConnectionError);
    expect(error).not.toBeInstanceOf(sdk.APIError);
    expect(script.received[0]?.headers["idempotency-key"]).toBeUndefined();
  });

  it("minting is repeated when the platform says nothing exists and to ask later", async () => {
    const mint = { method: "POST", path: `${P}/agent-credentials`, json: { label: "worker", lifetime_seconds: 3600 } };
    const minted = { credential_id: "crd_0000000000000001", kind: "agent", label: "worker", display_prefix: "acf1_agt_ab", status: "ACTIVE", issued_at: "t0", expires_at: "t1" };
    const { fabric } = scripted([
      { request: mint, response: problem("UPSTREAM_UNAVAILABLE", { retryAfter: 1 }) },
      { request: mint, response: answer(minted, 201) },
    ]);
    const credential = await value(() => fabric.auth.mintAgentCredential("worker", { lifetime: "1h" }));
    expect(credential.credential_id).toBe("crd_0000000000000001");
  });

  it("revoking carries no key and is repeated: revoking twice is revoking once", async () => {
    const revoke = { method: "DELETE", path: `${P}/agent-credentials/crd_0000000000000001` };
    const revoked = { credential_id: "crd_0000000000000001", kind: "agent", label: "worker", display_prefix: "acf1_agt_ab", status: "REVOKED", issued_at: "t0", expires_at: "t1" };
    const { fabric, script } = scripted([
      { request: revoke, response: reset },
      { request: revoke, response: answer(revoked) },
    ]);
    const credential = await value(() => fabric.auth.revokeAgentCredential("crd_0000000000000001"));
    expect(credential.status).toBe("REVOKED");
    expect(script.received.every((request) => request.headers["idempotency-key"] === undefined)).toBe(true);
  });
});

describe("an answer that is not the platform's", () => {
  const html = { status: 502, headers: { "content-type": "text/html" }, text: "<html>Bad Gateway</html>" };

  it("a 5xx on a mutation counts as no answer: the request is sent again under the same key", async () => {
    const { fabric, script } = scripted([
      { request: CREATE, response: html },
      { request: CREATE, response: CREATED },
    ]);
    await value(() => create(fabric));
    expect(script.received[1]?.headers["idempotency-key"]).toBe(script.received[0]?.headers["idempotency-key"]);
  });

  it("a 5xx on a mutation that persists is unresolved, with the key and the status that was seen", async () => {
    const { fabric } = scripted(times(3, { request: CREATE, response: html }), {}, "gateway-1");
    const error = await failure(() => create(fabric, { idempotencyKey: "gateway-1" }));
    expect(error).toBeInstanceOf(sdk.OutcomeUnresolvedError);
    expect(error).toMatchObject({ idempotencyKey: "gateway-1", status: 502 });
    expect((error as Error).cause).toBeInstanceOf(sdk.UnexpectedResponseError);
  });

  it("a 5xx on a read is unexpected, and is not repeated", async () => {
    const { fabric, script } = scripted([{ request: READ, response: html }]);
    const error = await failure(() => read(fabric));
    expect(error).toBeInstanceOf(sdk.UnexpectedResponseError);
    expect(error).toMatchObject({ status: 502 });
    expect(script.received).toHaveLength(1);
  });

  it.each([
    ["a read", READ, read],
    ["a mutation", CREATE, create],
  ] as const)("a 404 without a code on %s means the server does not speak this API", async (_what, request, call) => {
    const { fabric, script } = scripted([{ request, response: { status: 404, headers: { "content-type": "application/json" }, json: { detail: "Not Found" } } }]);
    const error = await failure(() => call(fabric));
    expect(error).toBeInstanceOf(sdk.IncompatibleServerError);
    expect(error).toBeInstanceOf(sdk.ConfigurationError);
    expect((error as Error).message).toMatch(/does not speak API v1/);
    expect(script.received).toHaveLength(1);
  });

  it("a 404 with a code is the platform's answer", async () => {
    const { fabric } = scripted([{ request: READ, response: problem("NOT_FOUND") }]);
    expect(await failure(() => read(fabric))).toBeInstanceOf(sdk.NotFoundError);
  });

  it("an error answer is known by its code, whatever its content type", async () => {
    const plain = problem("STATE_CONFLICT");
    const { fabric } = scripted([{ request: CREATE, response: { ...plain, headers: { "content-type": "application/json" } } }]);
    expect(await failure(() => create(fabric))).toBeInstanceOf(sdk.StateConflictError);
  });

  it.each([
    ["a 400 that is a page", { status: 400, headers: {}, text: "<html>Bad Request</html>" }],
    ["a 401 without a code", { status: 401, headers: {}, json: { error: "unauthorized" } }],
    ["a 200 that is not JSON", { status: 200, headers: {}, text: "OK" }],
    ["a 200 that is a JSON array", { status: 200, headers: {}, json: [] }],
    ["a 200 that is JSON null", { status: 200, headers: {}, text: "null" }],
    ["an empty 200", { status: 200, headers: {}, text: "" }],
  ])("%s is unexpected, and is not repeated", async (_what, response) => {
    for (const [request, call] of [
      [READ, read],
      [CREATE, create],
    ] as const) {
      const { fabric, script } = scripted([{ request, response }]);
      const error = await failure(() => call(fabric));
      expect(error).toBeInstanceOf(sdk.UnexpectedResponseError);
      expect(error).toMatchObject({ status: response.status });
      expect(script.received).toHaveLength(1);
    }
  });
});

describe("how long the client waits", () => {
  it("the n-th wait is random in [0, min(8, 0.5 * 2**n)] seconds", async () => {
    for (const [random, waits] of [
      [1, [0.5, 1, 2, 4, 8, 8, 8]],
      [0.5, [0.25, 0.5, 1, 2, 4, 4, 4]],
      [0, [0, 0, 0, 0, 0, 0, 0]],
    ] as const) {
      const { fabric, time } = scripted(times(8, { request: READ, response: reset }), { maxRetries: 7, random: () => random });
      await failure(() => read(fabric));
      expect(time.waits).toEqual(waits);
    }
  });

  it("a Retry-After replaces the computed wait when it is longer, and only then", async () => {
    const limited = (retryAfter: number): Exchange => ({ request: CREATE, response: problem("RATE_LIMITED", { retryAfter }) });
    const { fabric, time } = scripted([limited(3), limited(0), limited(1), limited(8), { request: CREATE, response: CREATED }], {
      maxRetries: 4,
      random: () => 1,
    });
    await value(() => create(fabric));
    // Computed: 0.5, 1, 2, 4. Advised: 3, 0, 1, 8.
    expect(time.waits).toEqual([3, 1, 2, 8]);
  });

  it("a Retry-After longer than 8 seconds is not waited for: the failure is thrown with the advice", async () => {
    const { fabric, script, time } = scripted([{ request: CREATE, response: problem("RATE_LIMITED", { retryAfter: 9 }) }]);
    const error = await failure(() => create(fabric));
    expect(error).toBeInstanceOf(sdk.RateLimitError);
    expect(error).toMatchObject({ retryAfter: 9, retry: "SAME_REQUEST_LATER" });
    expect(script.received).toHaveLength(1);
    expect(time.waits).toEqual([]);
  });

  it("a Retry-After that is not whole seconds is not advice the client can act on", async () => {
    const dated = problem("RATE_LIMITED");
    const response = { ...dated, headers: { "content-type": "application/problem+json", "retry-after": "Fri, 20 Nov 2026 10:00:00 GMT" } };
    const { fabric, time } = scripted([
      { request: CREATE, response },
      { request: CREATE, response: CREATED },
    ]);
    await value(() => create(fabric));
    expect(time.waits).toEqual([0.25]);
  });

  it.each([
    [0, 1],
    [1, 2],
    [2, 3],
    [5, 6],
  ])("with maxRetries %d a call makes at most %d requests", async (maxRetries, requests) => {
    const { fabric, script } = scripted(times(requests, { request: CREATE, response: problem("UPSTREAM_UNAVAILABLE", { retryAfter: 0 }) }), { maxRetries });
    expect(await failure(() => create(fabric))).toBeInstanceOf(sdk.ServiceUnavailableError);
    expect(script.received).toHaveLength(requests);
  });

  it("the time one call spends retrying is capped", async () => {
    const limited = { request: CREATE, response: problem("RATE_LIMITED", { retryAfter: 3 }) };
    // After the first wait 3 s have passed; a second wait of 3 s would pass the cap of 5 s.
    const { fabric, script, time } = scripted(times(2, limited), { maxRetries: 10, retryTotalMax: 5 });
    const error = await failure(() => create(fabric));
    expect(error).toBeInstanceOf(sdk.RateLimitError);
    expect(script.received).toHaveLength(2);
    expect(time.waits).toEqual([3]);
  });

  it("by default one call may retry for 23 hours: a day of key retention less an hour", async () => {
    const limited = { request: CREATE, response: problem("RATE_LIMITED", { retryAfter: 8 }) };
    /** A client with the default cap, whose clock jumps to `at` once the first wait is over. */
    const jumpingTo = (at: number, exchanges: Exchange[]) => {
      const made = scripted(exchanges, { maxRetries: 10 });
      const sleep = async (seconds: number): Promise<void> => {
        await made.time.sleep(seconds);
        if (made.time.waits.length === 1) {
          made.time.now = at;
        }
      };
      return { ...made, fabric: new sdk.Fabric({ ...made.options, sleep }) };
    };
    const cap = 23 * 3600;

    // The second wait of 8 s would end exactly at the cap: it is allowed.
    const inside = jumpingTo(cap - 8, [limited, limited, { request: CREATE, response: CREATED }]);
    await value(() => create(inside.fabric));

    // One second later it would end past the cap: the failure is thrown instead.
    const outside = jumpingTo(cap - 7, [limited, limited]);
    expect(await failure(() => create(outside.fabric))).toBeInstanceOf(sdk.RateLimitError);
    expect(outside.script.received).toHaveLength(2);
  });
});

describe("the retry budget", () => {
  const down = { request: READ, response: problem("UPSTREAM_UNAVAILABLE") };

  it("allows a retry while the retries of the last 60 s are fewer than 10 + 0.2 x the requests of the last 60 s", async () => {
    // One call alone: after r retries it has made r + 1 requests. r < 10 + 0.2 (r + 1) holds up to r = 12.
    const { fabric, script, time } = scripted(times(14, down), { maxRetries: 100, random: () => 0 });
    const error = await failure(() => read(fabric));
    expect(error).toBeInstanceOf(sdk.ServiceUnavailableError);
    expect(script.received).toHaveLength(14);
    expect(time.waited).toBe(0);
  });

  it("grows with the requests the client makes", async () => {
    // 50 answered requests first. Then r < 10 + 0.2 (50 + r + 1) holds up to r = 25.
    const { fabric, script } = scripted([...times(50, { request: READ, response: SANDBOX }), ...times(27, down)], { maxRetries: 100, random: () => 0 });
    for (let request = 0; request < 50; request += 1) {
      await read(fabric);
    }
    expect(await failure(() => read(fabric))).toBeInstanceOf(sdk.ServiceUnavailableError);
    expect(script.received).toHaveLength(77);
  });

  it("when it is spent, a failure that could be retried is thrown instead, and a lost answer stays unresolved", async () => {
    const lost = { request: CREATE, response: reset };
    const { fabric, script } = scripted([...times(14, down), lost], { maxRetries: 100, random: () => 0 });
    await failure(() => read(fabric));
    const error = await failure(() => create(fabric));
    expect(error).toBeInstanceOf(sdk.OutcomeUnresolvedError);
    expect(error).toMatchObject({ idempotencyKey: script.received.at(-1)?.headers["idempotency-key"] });
    expect(script.received).toHaveLength(15);
  });

  it("counts the retries of the last 60 seconds only", async () => {
    const { fabric, script, time } = scripted([...times(14, down), ...times(2, down), { request: READ, response: SANDBOX }], {
      maxRetries: 100,
      random: () => 0,
    });
    await failure(() => read(fabric));
    time.now += 59;
    // Still inside the window: the 13 retries count, and no retry is allowed.
    await failure(() => read(fabric));
    expect(script.received).toHaveLength(15);
    time.now += 2;
    // The first call's retries are older than 60 s now.
    await value(() => read(fabric));
    expect(script.received).toHaveLength(17);
  });

  it("counts the requests of the last 60 seconds only", async () => {
    // 50 answered requests would allow 26 retries. A minute later they allow none beyond the floor: 13.
    const { fabric, script, time } = scripted([...times(50, { request: READ, response: SANDBOX }), ...times(14, down)], { maxRetries: 100, random: () => 0 });
    for (let request = 0; request < 50; request += 1) {
      await read(fabric);
    }
    time.now += 60;
    expect(await failure(() => read(fabric))).toBeInstanceOf(sdk.ServiceUnavailableError);
    expect(script.received).toHaveLength(64);
  });

  it("belongs to one client: another client has its own", async () => {
    const first = scripted(times(14, down), { maxRetries: 100, random: () => 0 });
    await failure(() => read(first.fabric));
    const second = scripted([down, { request: READ, response: SANDBOX }], { maxRetries: 100, random: () => 0 });
    await value(() => read(second.fabric));
  });
});

describe("the platform's clock, sleep and jitter, when the caller replaces none", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("the sleep waits the seconds it is given", async () => {
    vi.useFakeTimers();
    let woke = false;
    const sleeping = systemSleep(2.5).then(() => {
      woke = true;
    });
    await vi.advanceTimersByTimeAsync(2499);
    expect(woke).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await sleeping;
    expect(woke).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("the sleep ends with the signal's reason when the signal aborts, and leaves no timer behind", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const reason = new Error("stop waiting");
    const sleeping = systemSleep(60, controller.signal).catch((thrown: unknown) => thrown);
    controller.abort(reason);
    expect(await sleeping).toBe(reason);
    expect(vi.getTimerCount()).toBe(0);
    expect(await systemSleep(60, controller.signal).catch((thrown: unknown) => thrown)).toBe(reason);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("the clock counts seconds and never runs backwards", () => {
    const first = systemClock();
    const second = systemClock();
    expect(second).toBeGreaterThanOrEqual(first);
    // Seconds, not milliseconds: a process that has run for a few minutes reads a few hundred.
    expect(first).toBeLessThan(performance.now());
  });

  it("the jitter is the platform's: the first wait falls in [0, 0.5] seconds", async () => {
    for (let run = 0; run < 20; run += 1) {
      const { time, options } = scripted([
        { request: READ, response: reset },
        { request: READ, response: SANDBOX },
      ]);
      const { random: _fixed, ...platform } = options;
      await value(() => read(new sdk.Fabric(platform)));
      expect(time.waits).toHaveLength(1);
      expect(time.waits[0]).toBeGreaterThanOrEqual(0);
      expect(time.waits[0]).toBeLessThanOrEqual(0.5);
    }
  });
});

describe("the request timeout", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /** A transport that never answers: each request ends only when its signal aborts it. */
  function silent(): { fetch: Fetch; requests: string[] } {
    const requests: string[] = [];
    const fetch: Fetch = (url, request) =>
      new Promise((_resolve, reject) => {
        requests.push(`${request.method} ${url}`);
        request.signal.addEventListener("abort", () => reject(new DOMException("This operation was aborted", "AbortError")));
      });
    return { fetch, requests };
  }

  it("bounds each HTTP request, and a request that exceeds it is a timeout that the retry rules treat as no answer", async () => {
    vi.useFakeTimers();
    const transport = silent();
    const time = new VirtualTime();
    const fabric = new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: "https://acf.example", project: "prj_0000000000000001", fetch: transport.fetch, clock: time.clock, sleep: time.sleep, timeout: 30 });
    const outcome = failure(() => fabric.sandboxes.get(SBX));
    await vi.advanceTimersByTimeAsync(29_999);
    expect(transport.requests).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(transport.requests).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(60_000);
    const error = await outcome;
    expect(error).toBeInstanceOf(sdk.APITimeoutError);
    expect((error as Error).message).toMatch(/within 30 s\.$/);
    expect(transport.requests).toHaveLength(3);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("is 120 seconds by default, and leaves no timer behind a request that was answered", async () => {
    vi.useFakeTimers();
    const transport = silent();
    const time = new VirtualTime();
    const fabric = new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: "https://acf.example", project: "prj_0000000000000001", fetch: transport.fetch, clock: time.clock, sleep: time.sleep, maxRetries: 0 });
    const outcome = failure(() => fabric.sandboxes.get(SBX));
    await vi.advanceTimersByTimeAsync(119_999);
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(await outcome).toBeInstanceOf(sdk.APITimeoutError);

    const answered = scripted([{ request: READ, response: SANDBOX }]);
    await value(() => read(answered.fabric));
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("abandoning a call", () => {
  it("a signal that is not an AbortSignal is refused before any request", async () => {
    const { fabric, script } = scripted([]);
    expect(await failure(() => fabric.sandboxes.get(SBX, { signal: true as never }))).toBeInstanceOf(TypeError);
    expect(await failure(() => fabric.sandboxes.get(SBX, { signal: { aborted: false } as never }))).toBeInstanceOf(TypeError);
    expect(script.received).toEqual([]);
  });

  it("a call whose signal is already aborted makes no request", async () => {
    const { fabric, script } = scripted([]);
    const reason = new Error("the caller gave up");
    const error = await failure(() => fabric.sandboxes.get(SBX, { signal: AbortSignal.abort(reason) }));
    expect(error).toBe(reason);
    expect(script.received).toEqual([]);
  });

  it("abandoning during a wait between attempts ends the call with the signal's reason, and no further request", async () => {
    const controller = new AbortController();
    const { script, options } = scripted([{ request: CREATE, response: problem("RATE_LIMITED", { retryAfter: 1 }) }]);
    const abandoning = new sdk.Fabric({
      ...options,
      sleep: async () => {
        controller.abort(new Error("stop waiting"));
      },
    });
    const error = await failure(() => create(abandoning, { signal: controller.signal }));
    expect((error as Error).message).toBe("stop waiting");
    expect(script.received).toHaveLength(1);
  });

  it("abandoning a request in flight ends the call with the signal's reason; it is not retried and nothing is cancelled", async () => {
    const controller = new AbortController();
    const requests: string[] = [];
    const fetch: Fetch = (url, request) =>
      new Promise((_resolve, reject) => {
        requests.push(`${request.method} ${new URL(url).pathname}`);
        request.signal.addEventListener("abort", () => reject(new DOMException("This operation was aborted", "AbortError")));
        controller.abort(new Error("abandoned in flight"));
      });
    const time = new VirtualTime();
    const fabric = new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: "https://acf.example", project: "prj_0000000000000001", fetch, clock: time.clock, sleep: time.sleep });
    const error = await failure(() => create(fabric, { signal: controller.signal }));
    expect((error as Error).message).toBe("abandoned in flight");
    expect(requests).toEqual([`POST ${P}/sandboxes`]);
  });

  it("abandoning while an operation is followed sends nothing more: no cancel, no stop, no destroy", async () => {
    const controller = new AbortController();
    const running = operationView({ state: "IN_PROGRESS" });
    const { script, options } = scripted([
      { request: CREATE, response: accepted(running) },
      { request: get(`${P}/operations/${String(running["operation_id"])}`), response: answer(running, 200, { "retry-after": "1" }) },
    ]);
    let waits = 0;
    const abandoning = new sdk.Fabric({
      ...options,
      sleep: async () => {
        waits += 1;
        if (waits === 2) {
          controller.abort(new Error("stop following"));
        }
      },
    });
    const error = await failure(() => create(abandoning, { signal: controller.signal }));
    expect((error as Error).message).toBe("stop following");
    expect(script.received.map((request) => request.method)).toEqual(["POST", "GET"]);
  });
});
