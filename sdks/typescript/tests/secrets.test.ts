/**
 * The credential never appears: not in a text form of the client, of a handle or of an error, not
 * in an error message, not on the console, and in a request only in the `Authorization` header.
 *
 * Every other test file is searched the same way: whatever a test gets back from the SDK is
 * recorded and searched after the test (`support/setup.ts`). This file adds the cases that try to
 * make the credential leak.
 */

import { inspect } from "node:util";

import { describe, expect, it } from "vitest";

import * as sdk from "../src/index.js";
import type { Fetch } from "../src/index.js";
import {
  accepted,
  all,
  answer,
  BASE_URL,
  CANARY_KEY,
  CREATE_ARGS,
  CREATE_BODY,
  del,
  EXE,
  executionView,
  expectNoSecret,
  failure,
  get,
  operationView,
  P,
  post,
  problem,
  PROJECT,
  reset,
  sandboxView,
  SBX,
  scripted,
  snapshotView,
  succeeded,
  textForms,
  timedOut,
  value,
  VirtualTime,
} from "./support/harness.js";

const READ = get(`${P}/sandboxes/${SBX}`);

describe("the canary", () => {
  it("is a credential the search would find if it were there", () => {
    expect(() => expectNoSecret({ nested: [new Error(`Bearer ${CANARY_KEY}`)] })).toThrow(/a credential appears/);
    expect(() => expectNoSecret(Object.defineProperty({}, "hidden", { value: CANARY_KEY, enumerable: false }))).toThrow(/a credential appears/);
    expect(() => expectNoSecret(new Error("outer", { cause: new Error(CANARY_KEY) }))).toThrow(/a credential appears/);
    expect(() => expectNoSecret({ toJSON: () => ({ key: CANARY_KEY }) })).toThrow(/a credential appears/);
  });
});

describe("a client", () => {
  it("shows its endpoint and its project, and never its credential", () => {
    const { fabric } = scripted([]);
    expect(String(fabric)).toBe(`Fabric(baseUrl=${BASE_URL}, project=${PROJECT})`);
    expect(inspect(fabric)).toBe(String(fabric));
    expect(JSON.stringify(fabric)).toBe(JSON.stringify({ baseUrl: BASE_URL, project: PROJECT }));
    for (const part of [fabric, fabric.sandboxes, fabric.snapshots, fabric.executions, fabric.operations, fabric.auth]) {
      expectNoSecret(part);
      expect(Object.values(part).some((member) => typeof member === "string")).toBe(false);
    }
  });

  it("says that the project is the credential's until it has read it", () => {
    const { fabric } = scripted([], { project: undefined });
    expect(String(fabric)).toBe(`Fabric(baseUrl=${BASE_URL}, project=the credential's)`);
    expect(JSON.parse(JSON.stringify(fabric))).toEqual({ baseUrl: BASE_URL, project: null });
  });

  it("sends the credential in the Authorization header of each request, and nowhere else in it", async () => {
    const creating = operationView();
    const { fabric, script } = scripted([
      { request: post(`${P}/sandboxes`, CREATE_BODY), response: accepted(creating) },
      { request: get(`${P}/operations/${String(creating["operation_id"])}`), response: answer(succeeded("sandbox.create", { sandbox: sandboxView() })) },
      { request: post(`${P}/sandboxes/${SBX}/start`), response: answer(succeeded("sandbox.start", { sandbox: sandboxView({ state: "RUNNING" }) })) },
      { request: post(`${P}/sandboxes/${SBX}/executions`), response: answer(succeeded("execution.create", { execution: executionView() })) },
      { request: get(`${P}/executions/${EXE}/output`), response: answer({ execution_id: EXE, stream: "stdout", offset: 0, data_base64: "aGk=", next_offset: 2, eof: true, stored_bytes: 2, produced_bytes: 2, completeness: "COMPLETE" }) },
      { request: get(`${P}/sandboxes`), response: answer({ items: [sandboxView()], more: true, next_cursor: "c1" }) },
      { request: get(`${P}/sandboxes`, { cursor: "c1" }), response: answer({ items: [], more: false, next_cursor: "c2" }) },
      { request: get(`${P}/snapshots`), response: answer({ items: [snapshotView()], more: false, next_cursor: "end" }) },
      { request: get("/v1/info"), response: answer({ api_versions: ["v1"], serving: true }) },
      { request: del(`${P}/sandboxes/${SBX}`), response: answer(succeeded("sandbox.destroy", { sandbox: sandboxView({ state: "DESTROYED" }) })) },
    ]);
    const sandbox = await value(() => fabric.sandboxes.create("python", CREATE_ARGS));
    const execution = await value(() => sandbox.exec(["echo", "hi"], { env: { TOKEN: "not-the-credential" } }));
    expect(await value(() => execution.text())).toBe("hi");
    await all(fabric.sandboxes.list());
    await all(fabric.snapshots.list());
    await value(() => fabric.info());
    await value(() => sandbox.destroy());

    expect(script.received).toHaveLength(10);
    for (const request of script.received) {
      const { authorization, ...others } = request.headers;
      expect(authorization).toBe(`Bearer ${CANARY_KEY}`);
      expectNoSecret({ ...request, headers: others });
    }
    for (const subject of [sandbox, execution, sandbox.operation, execution.operation]) {
      expectNoSecret(subject);
    }
  });
});

describe("a refused configuration", () => {
  it.each([
    ["user information", `https://deploy:${CANARY_KEY}@acf.example`],
    ["a user name", `https://${CANARY_KEY}@acf.example`],
    ["a query string", `https://acf.example/?api_key=${CANARY_KEY}`],
    ["a fragment", `https://acf.example/#${CANARY_KEY}`],
    ["a scheme that is not HTTP", `ftp://${CANARY_KEY}@acf.example`],
    ["plain HTTP to another machine", `http://acf.example/${CANARY_KEY}`],
    ["text that is not a URL", `not a url ${CANARY_KEY}`],
  ])("an endpoint with %s is refused in words that repeat nothing of it", (_what, baseUrl) => {
    let error: unknown;
    try {
      new sdk.Fabric({ apiKey: "acf1_dev_another_key_entirely", baseUrl, fetch: scripted([]).script.fetch });
    } catch (thrown) {
      error = thrown;
    }
    expect(error).toBeInstanceOf(sdk.ConfigurationError);
    expectNoSecret(error);
    expect((error as Error).message).not.toMatch(/acf\.example\/|deploy|api_key/);
  });

  it.each([
    ["a trailing line break", `${CANARY_KEY}\n`],
    ["a leading space", ` ${CANARY_KEY}`],
    ["a character outside ASCII", `${CANARY_KEY}é`],
    ["a carriage return and a header of its own", `${CANARY_KEY}\r\nX-Injected: 1`],
  ])("a credential with %s is refused in words that do not repeat it", (_what, apiKey) => {
    let error: unknown;
    try {
      new sdk.Fabric({ apiKey, baseUrl: BASE_URL, fetch: scripted([]).script.fetch });
    } catch (thrown) {
      error = thrown;
    }
    expect(error).toBeInstanceOf(sdk.ConfigurationError);
    expectNoSecret(error);
    expect((error as Error).message).toMatch(/cannot be sent in a header/);
  });
});

describe("a transport that shows the credential in its errors", () => {
  /** A client whose every request fails the way `fail` says. */
  function failing(fail: (authorization: string) => unknown): sdk.Fabric {
    const time = new VirtualTime();
    const fetch: Fetch = async (_url, request) => {
      throw fail(request.headers["Authorization"] ?? "");
    };
    return new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: BASE_URL, project: PROJECT, fetch, clock: time.clock, sleep: time.sleep });
  }

  const leaks: [string, (authorization: string) => unknown][] = [
    ["in its message", (authorization) => new TypeError(`Headers.append: "${authorization}" is an invalid header value.`)],
    ["in what caused it", (authorization) => new TypeError("fetch failed", { cause: new Error(`could not send ${authorization}`) })],
    ["deep in what caused it", (authorization) => new Error("a", { cause: new Error("b", { cause: new Error("c", { cause: new Error("d", { cause: new Error("e", { cause: new Error(authorization) }) }) }) }) })],
    ["in the request it attaches", (authorization) => Object.assign(new Error("Request failed"), { config: { url: "/v1", headers: { Authorization: authorization } } })],
    ["in a property it hides", (authorization) => Object.defineProperty(new Error("Request failed"), "request", { value: [authorization], enumerable: false })],
    ["in a map of its headers", (authorization) => Object.assign(new Error("Request failed"), { headers: new Map([["authorization", authorization]]) })],
    ["in the name of a property", (authorization) => Object.assign(new Error("Request failed"), { [authorization]: true })],
    ["in a string it throws", (authorization) => `could not send ${authorization}`],
    ["behind an accessor", (authorization) => Object.defineProperty(new Error("Request failed"), "detail", { get: () => authorization, enumerable: true })],
  ];

  it.each(leaks)("%s: a read fails in words without the credential, and the foreign error is not passed on", async (_where, fail) => {
    const error = await failure(() => failing(fail).sandboxes.get(SBX));
    expect(error).toBeInstanceOf(sdk.APIConnectionError);
    expect((error as Error).cause).toBeUndefined();
    expect((error as Error).message).toMatch(/^No answer to GET /);
  });

  it.each(leaks)("%s: a mutation is unresolved, in words without the credential", async (_where, fail) => {
    const error = await failure(() => failing(fail).sandboxes.create("python", { ...CREATE_ARGS, start: false }));
    expect(error).toBeInstanceOf(sdk.OutcomeUnresolvedError);
    expect(((error as Error).cause as Error).cause).toBeUndefined();
  });

  it("says what the transport said, with the credential struck out", async () => {
    const error = await failure(() => failing((authorization) => new TypeError(`"${authorization}" is an invalid header value`)).sandboxes.get(SBX));
    expect((error as Error).message).toMatch(/TypeError: "Bearer \[redacted\]" is an invalid header value\.$/);
  });

  it("passes on a foreign error that shows nothing: what failed is worth knowing", async () => {
    const lost = scripted(Array.from({ length: 3 }, () => ({ request: READ, response: reset })));
    const error = await failure(() => lost.fabric.sandboxes.get(SBX));
    expect((error as Error).cause).toBeInstanceOf(TypeError);
    expect(((error as Error).cause as Error).cause).toMatchObject({ code: "ECONNRESET" });

    const slow = scripted(Array.from({ length: 3 }, () => ({ request: READ, response: timedOut })));
    const timeout = await failure(() => slow.fabric.sandboxes.get(SBX));
    expect((timeout as Error).cause).toMatchObject({ name: "TimeoutError" });
  });
});

describe("a server that repeats the credential", () => {
  it("in the message and the reason of an error answer: both are struck out", async () => {
    const echo = problem("PERMISSION_DENIED", { message: `the key ${CANARY_KEY} may not do this`, reason: `key:${CANARY_KEY}` });
    const { fabric } = scripted([{ request: READ, response: echo }]);
    const error = await failure(() => fabric.sandboxes.get(SBX));
    expect(error).toBeInstanceOf(sdk.PermissionDeniedError);
    expect(error).toMatchObject({ message: "the key [redacted] may not do this", reason: "key:[redacted]" });
  });

  it("in the failure of an operation: the message the SDK writes has it struck out", async () => {
    const failed = operationView({ state: "FAILED", terminal: true, effect: "NOT_APPLIED", failure: { code: "TIMEOUT", retry: "NEVER", message: `gave up on ${CANARY_KEY}` } });
    const { fabric } = scripted([{ request: post(`${P}/sandboxes`, CREATE_BODY), response: answer(failed) }]);
    // Not recorded for the search after the test: the error carries the operation as the server
    // sent it, and what a server puts into a view is the server's to answer for.
    const error = await fabric.sandboxes.create("python", { ...CREATE_ARGS, start: false }).catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(sdk.OperationFailedError);
    expect((error as Error).message).toContain("TIMEOUT: gave up on [redacted]");
    expect((error as Error).message).not.toContain(CANARY_KEY);
  });
});

describe("every error the SDK writes itself", () => {
  it("has a message and members without the credential", async () => {
    const unresolved = scripted(Array.from({ length: 3 }, () => ({ request: post(`${P}/sandboxes`, CREATE_BODY), response: reset })));
    const errors: unknown[] = [await failure(() => unresolved.fabric.sandboxes.create("python", { ...CREATE_ARGS, start: false }))];

    const incompatible = scripted([{ request: READ, response: { status: 404, headers: {}, text: "Not Found" } }]);
    errors.push(await failure(() => incompatible.fabric.sandboxes.get(SBX)));

    const unexpected = scripted([{ request: READ, response: { status: 200, headers: {}, text: "<html>" } }]);
    errors.push(await failure(() => unexpected.fabric.sandboxes.get(SBX)));

    const running = scripted([{ request: post(`${P}/sandboxes`, CREATE_BODY), response: accepted(operationView(), 9) }], { followMax: 1 });
    errors.push(await failure(() => running.fabric.sandboxes.create("python", { ...CREATE_ARGS, start: false })));

    const missing = scripted([{ request: get(`${P}/snapshots`), response: answer({ items: [], more: false, next_cursor: "end" }) }]);
    errors.push(await failure(() => missing.fabric.snapshots.get("nightly")));

    const badUnits = scripted([]);
    errors.push(await failure(() => badUnits.fabric.sandboxes.create("python", { ...CREATE_ARGS, memory: "4GB" })));

    expect(errors.map((error) => (error as Error).name)).toEqual([
      "OutcomeUnresolvedError",
      "IncompatibleServerError",
      "UnexpectedResponseError",
      "OperationStillRunningError",
      "NotFoundError",
      "RangeError",
    ]);
    for (const error of errors) {
      expectNoSecret(error);
      expect(textForms(error).join("\n")).not.toContain("Bearer");
    }
  });
});

describe("a minted credential", () => {
  const SECRET = "acf1_agt_MINTEDsecretMINTEDsecret0123456789";
  const view = { credential_id: "crd_0000000000000001", kind: "agent", label: "worker", display_prefix: "acf1_agt_MI", status: "ACTIVE", issued_at: "2026-11-19T10:00:00.000Z", expires_at: "2026-11-19T11:00:00.000Z" };
  const mint = { method: "POST", path: `${P}/agent-credentials`, json: { label: "worker", lifetime_seconds: 3600 } };

  it("gives its secret once, where the caller reads it, and keeps it out of every text form", async () => {
    const { fabric } = scripted([{ request: mint, response: answer({ ...view, secret: SECRET }, 201) }]);
    const credential = await value(() => fabric.auth.mintAgentCredential("worker", { lifetime: "1h" }));
    expect(credential.secret).toBe(SECRET);
    expect(credential.raw.secret).toBe(SECRET);
    for (const shown of [String(credential), JSON.stringify(credential), inspect(credential), inspect({ nested: [credential] }, { depth: 5 }), JSON.stringify({ ...credential })]) {
      expect(shown).not.toContain(SECRET);
    }
    expect(JSON.parse(JSON.stringify(credential))).toEqual({ ...view, secret: "[shown once: read .secret]" });
    expect(String(credential)).toBe("AgentCredential(crd_0000000000000001, label=worker, status=ACTIVE)");
  });

  it("has no secret when it is listed, and says so plainly", async () => {
    const { fabric } = scripted([{ request: get(`${P}/agent-credentials`), response: answer({ items: [view] }) }]);
    const [credential] = await value(() => fabric.auth.agentCredentials());
    expect(credential?.secret).toBeNull();
    expect(JSON.parse(JSON.stringify(credential))).toEqual(view);
  });
});
