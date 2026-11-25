/**
 * The client: where its configuration comes from, what it refuses to be constructed with, where
 * its requests go, and the calls that are not about a sandbox.
 */

import { readdirSync, readFileSync } from "node:fs";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import * as sdk from "../src/index.js";
import type { Fetch } from "../src/index.js";
import { USER_AGENT } from "../src/version.js";
import {
  all,
  answer,
  BASE_URL,
  CANARY_KEY,
  type Exchange,
  expectNoSecret,
  failure,
  get,
  type Json,
  operationView,
  P,
  post,
  problem,
  PROJECT,
  REQ,
  sandboxView,
  SBX,
  Script,
  scripted,
  scripts,
  succeeded,
  value,
  VirtualTime,
} from "./support/harness.js";

const READ = get(`${P}/sandboxes/${SBX}`);
const SANDBOX = answer(sandboxView());
const WHOAMI = { principal_id: "prn_0000000000000001", project_id: PROJECT, credential: { credential_id: "crd_0000000000000009", kind: "developer", expires_at: "2027-01-01T00:00:00.000Z" }, grants: { schema_version: 1 }, policy_version: "3" };

/** The error a constructor throws. */
function refusal(make: () => unknown): unknown {
  try {
    make();
  } catch (error) {
    return error;
  }
  throw new Error("the client was constructed; it should have been refused");
}

/** A transport for a client that is only constructed, or that plays `exchanges` at `baseUrl`. */
function transport(exchanges: Exchange[] = [], baseUrl: string = BASE_URL): Script {
  const script = new Script(baseUrl, exchanges);
  scripts.push(script);
  return script;
}

beforeEach(() => {
  // Whatever the machine that runs the tests has set must not reach them.
  for (const name of ["ACF_API_KEY", "ACF_BASE_URL", "ACF_PROJECT"]) {
    vi.stubEnv(name, undefined);
  }
});

describe("configuration", () => {
  it("comes from the options", async () => {
    const script = transport([{ request: READ, response: SANDBOX }]);
    const fabric = new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: BASE_URL, project: PROJECT, fetch: script.fetch });
    await value(() => fabric.sandboxes.get(SBX));
    expect(script.received[0]?.headers["authorization"]).toBe(`Bearer ${CANARY_KEY}`);
  });

  it("or from ACF_API_KEY, ACF_BASE_URL and ACF_PROJECT", async () => {
    vi.stubEnv("ACF_API_KEY", CANARY_KEY);
    vi.stubEnv("ACF_BASE_URL", "https://env.acf.example/");
    vi.stubEnv("ACF_PROJECT", "prj_00000000000000ee");
    const script = transport([{ request: get(`/v1/projects/prj_00000000000000ee/sandboxes/${SBX}`), response: SANDBOX }], "https://env.acf.example");
    const fabric = new sdk.Fabric({ fetch: script.fetch });
    expect(String(fabric)).toBe("Fabric(baseUrl=https://env.acf.example, project=prj_00000000000000ee)");
    await value(() => fabric.sandboxes.get(SBX));
    expect(script.received[0]?.headers["authorization"]).toBe(`Bearer ${CANARY_KEY}`);
  });

  it("an option wins over the environment", async () => {
    vi.stubEnv("ACF_API_KEY", "acf1_dev_from_the_environment");
    vi.stubEnv("ACF_BASE_URL", "https://env.acf.example");
    vi.stubEnv("ACF_PROJECT", "prj_00000000000000ee");
    const script = transport([{ request: READ, response: SANDBOX }]);
    const fabric = new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: BASE_URL, project: PROJECT, fetch: script.fetch });
    await value(() => fabric.sandboxes.get(SBX));
    expect(script.received[0]).toMatchObject({ origin: BASE_URL, headers: { authorization: `Bearer ${CANARY_KEY}` } });
  });

  it("a credential that is missing is refused at construction, and the message says where to put it", () => {
    const error = refusal(() => new sdk.Fabric({ baseUrl: BASE_URL, fetch: transport().fetch }));
    expect(error).toBeInstanceOf(sdk.ConfigurationError);
    expect((error as Error).message).toBe("No credential: pass apiKey, or set the environment variable ACF_API_KEY.");
  });

  it("an endpoint that is missing is refused at construction, and the message says where to put it", () => {
    const error = refusal(() => new sdk.Fabric({ apiKey: CANARY_KEY, fetch: transport().fetch }));
    expect(error).toBeInstanceOf(sdk.ConfigurationError);
    expect((error as Error).message).toBe("No endpoint: pass baseUrl, or set the environment variable ACF_BASE_URL.");
  });

  it("a variable that is set and empty is a variable that is not set", () => {
    vi.stubEnv("ACF_API_KEY", "");
    vi.stubEnv("ACF_BASE_URL", "");
    vi.stubEnv("ACF_PROJECT", "");
    expect(refusal(() => new sdk.Fabric({ baseUrl: BASE_URL, fetch: transport().fetch }))).toBeInstanceOf(sdk.ConfigurationError);
    expect(refusal(() => new sdk.Fabric({ apiKey: CANARY_KEY, fetch: transport().fetch }))).toBeInstanceOf(sdk.ConfigurationError);
    const fabric = new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: BASE_URL, fetch: transport().fetch });
    expect(String(fabric)).toContain("project=the credential's");
  });

  it("is refused with no options at all in an empty environment, before anything else happens", () => {
    expect(refusal(() => new sdk.Fabric())).toBeInstanceOf(sdk.ConfigurationError);
  });

  it("works where there is no process: the environment is simply not there", () => {
    vi.stubGlobal("process", undefined);
    try {
      const fabric = new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: BASE_URL, fetch: async () => new Response("{}") });
      expect(String(fabric)).toBe(`Fabric(baseUrl=${BASE_URL}, project=the credential's)`);
      expect(refusal(() => new sdk.Fabric({ baseUrl: BASE_URL }))).toBeInstanceOf(sdk.ConfigurationError);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("works where the environment may not be read", () => {
    const denied = {
      get env(): never {
        throw new Error("access to the environment is denied");
      },
    };
    vi.stubGlobal("process", denied);
    try {
      expect(String(new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: BASE_URL, fetch: async () => new Response("{}") }))).toContain(BASE_URL);
      expect(refusal(() => new sdk.Fabric({ baseUrl: BASE_URL }))).toBeInstanceOf(sdk.ConfigurationError);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it.each([
    ["apiKey", { apiKey: "" }],
    ["apiKey", { apiKey: 42 }],
    ["baseUrl", { baseUrl: 42 }],
    ["project", { project: ".." }],
    ["project", { project: 7 }],
    ["timeout", { timeout: 0 }],
    ["timeout", { timeout: -1 }],
    ["timeout", { timeout: Number.NaN }],
    ["timeout", { timeout: Number.POSITIVE_INFINITY }],
    ["timeout", { timeout: "120" }],
    ["timeout", { timeout: 2_147_484 }],
    ["maxRetries", { maxRetries: -1 }],
    ["maxRetries", { maxRetries: 1.5 }],
    ["maxRetries", { maxRetries: "2" }],
    ["followMax", { followMax: -1 }],
    ["followMax", { followMax: Number.NaN }],
    ["retryTotalMax", { retryTotalMax: -1 }],
    ["fetch", { fetch: "fetch" }],
    ["clock", { clock: 5 }],
    ["sleep", { sleep: {} }],
    ["random", { random: 0.5 }],
  ])("refuses a bad %s (%o) at construction", (name, option) => {
    const error = refusal(() => new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: BASE_URL, fetch: transport().fetch, ...(option as object) }));
    expect(error).toBeInstanceOf(sdk.ConfigurationError);
    expect((error as Error).message).toContain(name);
  });

  it("refuses an option it does not know, and recognizes the spelling of the Python SDK", () => {
    const error = refusal(() => new sdk.Fabric({ api_key: CANARY_KEY, baseUrl: BASE_URL } as never));
    expect(error).toBeInstanceOf(sdk.ConfigurationError);
    expect((error as Error).message).toMatch(/^new Fabric: unknown option "api_key"\. Did you mean apiKey\?/);
    expectNoSecret(error);
  });

  it("accepts zero retries and a follow bound of zero", () => {
    expect(() => new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: BASE_URL, fetch: transport().fetch, maxRetries: 0, followMax: 0, retryTotalMax: 0 })).not.toThrow();
  });
});

describe("the endpoint", () => {
  const make = (baseUrl: unknown, more: object = {}) => new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: baseUrl as string, fetch: transport().fetch, ...more });

  it.each([
    ["https://acf.example", "https://acf.example"],
    ["https://acf.example/", "https://acf.example"],
    ["https://acf.example///", "https://acf.example"],
    ["HTTPS://ACF.EXAMPLE", "https://acf.example"],
    ["https://acf.example:8443/gateway/", "https://acf.example:8443/gateway"],
    ["http://localhost:8080", "http://localhost:8080"],
    ["http://127.0.0.1:8080", "http://127.0.0.1:8080"],
    ["http://127.9.8.7", "http://127.9.8.7"],
    ["http://[::1]:8080/", "http://[::1]:8080"],
  ])("%s is accepted, as %s", (baseUrl, normalized) => {
    expect(String(make(baseUrl))).toBe(`Fabric(baseUrl=${normalized}, project=the credential's)`);
  });

  it.each([
    ["http://acf.example"],
    ["http://10.0.0.1:8080"],
    ["http://192.168.1.10"],
    ["http://localhost.acf.example"],
    ["http://127.0.0.1.acf.example"],
    ["http://[::2]"],
    ["http://0.0.0.0"],
  ])("%s is plain HTTP to an address that is not loopback: refused, unless the caller accepts it", (baseUrl) => {
    const error = refusal(() => make(baseUrl));
    expect(error).toBeInstanceOf(sdk.ConfigurationError);
    expect((error as Error).message).toMatch(/allowInsecureHttp: true/);
    expect(() => make(baseUrl, { allowInsecureHttp: true })).not.toThrow();
  });

  it.each([
    ["ftp://acf.example"],
    ["file:///etc/passwd"],
    ["ws://acf.example"],
    ["acf.example"],
    ["//acf.example"],
    [""],
    ["https://"],
    ["https://user@acf.example"],
    ["https://user:secret@acf.example"],
    ["https://acf.example?tenant=1"],
    ["https://acf.example/?"],
    ["https://acf.example/#top"],
    ["https://acf.example/#"],
    // What URL parsing would tidy away without a word: the address used would not be the one written.
    ["https://acf.exam\nple"],
    ["https://acf.exam\tple"],
    ["https://acf.example\n"],
    [" https://acf.example"],
    ["https://acf.example "],
    ["https://acf exam.ple"],
    [`https://acf.example/${String.fromCharCode(0xa0)}v1`],
    [`https://acf.example/${String.fromCharCode(0x200b)}v1`],
    [`https://${String.fromCharCode(0x202e)}acf.example`],
    [`https://acf.example/${String.fromCharCode(0)}`],
    [`https://acf.example/${String.fromCharCode(0x7f)}`],
    [`${String.fromCharCode(0xfeff)}https://acf.example`],
  ])("%j is refused whatever the caller accepts", (baseUrl) => {
    expect(refusal(() => make(baseUrl))).toBeInstanceOf(sdk.ConfigurationError);
    expect(refusal(() => make(baseUrl, { allowInsecureHttp: true }))).toBeInstanceOf(sdk.ConfigurationError);
  });

  it("an address with a character that does not show is refused in words that do not repeat it", () => {
    const error = refusal(() => make("https://acf.exam\nple.attacker.example")) as Error;
    expect(error).toBeInstanceOf(sdk.ConfigurationError);
    expect(error.message).toBe("baseUrl must not contain a space, a line break or a character that does not show.");
  });

  it("a path in the endpoint is a prefix of every route", async () => {
    const script = transport([{ request: get(`/gateway${P}/sandboxes/${SBX}`), response: SANDBOX }], "https://acf.example/gateway");
    const fabric = new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: "https://acf.example/gateway/", project: PROJECT, fetch: script.fetch });
    await value(() => fabric.sandboxes.get(SBX));
  });
});

describe("a browser page", () => {
  const options = () => ({ apiKey: CANARY_KEY, baseUrl: BASE_URL, fetch: transport().fetch });

  it("is refused: a credential in a page is a credential published", () => {
    vi.stubGlobal("window", { document: {} });
    const error = refusal(() => new sdk.Fabric(options()));
    expect(error).toBeInstanceOf(sdk.ConfigurationError);
    expect((error as Error).message).toMatch(/browser page/);
    expect((error as Error).message).toMatch(/dangerouslyAllowBrowser: true/);
    expectNoSecret(error);
  });

  it("is allowed when the caller says so in so many words", () => {
    vi.stubGlobal("window", { document: {} });
    expect(() => new sdk.Fabric({ ...options(), dangerouslyAllowBrowser: true })).not.toThrow();
    expect(refusal(() => new sdk.Fabric({ ...options(), dangerouslyAllowBrowser: "yes" as never }))).toBeInstanceOf(sdk.ConfigurationError);
    expect(refusal(() => new sdk.Fabric({ ...options(), dangerouslyAllowBrowser: false }))).toBeInstanceOf(sdk.ConfigurationError);
  });

  it.each([
    ["a window without a document", {}],
    ["no window", undefined],
    ["a window that is null", null],
  ])("%s is not a page", (_what, window) => {
    vi.stubGlobal("window", window);
    expect(() => new sdk.Fabric(options())).not.toThrow();
  });

  it("the missing credential is reported first: without one there is nothing to publish", () => {
    vi.stubGlobal("window", { document: {} });
    expect((refusal(() => new sdk.Fabric({ baseUrl: BASE_URL })) as Error).message).toMatch(/^No credential/);
  });
});

describe("the transport", () => {
  it("is the platform's fetch unless one is given, looked up when a request is made", async () => {
    const fabric = new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: BASE_URL, project: PROJECT });
    const calls: [string, sdk.FetchRequest][] = [];
    vi.stubGlobal("fetch", async (url: string, request: sdk.FetchRequest) => {
      calls.push([url, request]);
      return new Response(JSON.stringify(sandboxView()), { status: 200, headers: { "x-request-id": REQ } });
    });
    const sandbox = await value(() => fabric.sandboxes.get(SBX));
    expect(sandbox.requestId).toBe(REQ);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.[0]).toBe(`${BASE_URL}${P}/sandboxes/${SBX}`);
    expect(calls[0]?.[1]).toMatchObject({ method: "GET", redirect: "manual" });
    expect(calls[0]?.[1].signal).toBeInstanceOf(AbortSignal);
    expect(calls[0]?.[1]).not.toHaveProperty("body");
  });

  it("must exist: a runtime without fetch is refused at construction unless one is given", () => {
    vi.stubGlobal("fetch", undefined);
    const error = refusal(() => new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: BASE_URL }));
    expect(error).toBeInstanceOf(sdk.ConfigurationError);
    expect((error as Error).message).toMatch(/has no fetch/);
    expect(() => new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: BASE_URL, fetch: transport().fetch })).not.toThrow();
  });

  it("names the SDK and its version in every request, and nothing about the machine or the user", async () => {
    const { fabric, script } = scripted([
      { request: READ, response: SANDBOX },
      { request: post(`${P}/sandboxes/${SBX}/stop`, { expected_generation: 1 }), response: answer(succeeded("sandbox.stop", { sandbox: sandboxView({ state: "STOPPED" }) })) },
    ]);
    const sandbox = await value(() => fabric.sandboxes.get(SBX));
    await value(() => sandbox.stop());
    expect(USER_AGENT).toBe(`agent-compute-typescript/${sdk.VERSION}`);
    const [read, mutation] = script.received;
    expect(read?.headers).toEqual({
      accept: "application/json, application/problem+json",
      authorization: `Bearer ${CANARY_KEY}`,
      "user-agent": USER_AGENT,
    });
    expect(Object.keys(mutation?.headers ?? {}).sort()).toEqual(["accept", "authorization", "content-type", "idempotency-key", "user-agent"]);
    expect(mutation?.headers["content-type"]).toBe("application/json");
  });

  it("never follows a redirect: the credential goes to the configured endpoint and nowhere else", async () => {
    const redirect = { status: 307, headers: { location: "https://elsewhere.example/v1/collect" }, text: "" };
    const { fabric, script } = scripted([{ request: READ, response: redirect }]);
    const error = await failure(() => fabric.sandboxes.get(SBX));
    expect(error).toBeInstanceOf(sdk.UnexpectedResponseError);
    expect(error).toMatchObject({ status: 307 });
    expect(script.received.map((request) => request.origin)).toEqual([BASE_URL]);
    expect(script.received[0]?.redirect).toBe("manual");
  });

  it("the scripted transport of this suite refuses any other origin, so a request that strayed would fail its test", async () => {
    const script = transport([]);
    await expect(script.fetch("https://elsewhere.example/v1/info", { method: "GET", headers: {}, signal: new AbortController().signal, redirect: "manual" })).rejects.toThrow(/not the configured endpoint/);
    expect(() => script.check()).toThrow(/departed from the script/);
    scripts.length = 0;
  });
});

describe("the project", () => {
  it("is read once from the platform when neither an option nor the environment names it", async () => {
    const { fabric, script } = scripted(
      [
        { request: get("/v1/auth/whoami"), response: answer(WHOAMI) },
        { request: READ, response: SANDBOX },
        { request: READ, response: SANDBOX },
        { request: get(`${P}/sandboxes`), response: answer({ items: [], more: false, next_cursor: "end" }) },
      ],
      { project: undefined },
    );
    await value(() => fabric.sandboxes.get(SBX));
    expect(String(fabric)).toBe(`Fabric(baseUrl=${BASE_URL}, project=${PROJECT})`);
    await value(() => fabric.sandboxes.get(SBX));
    await all(fabric.sandboxes.list());
    expect(script.received.filter((request) => request.path === "/v1/auth/whoami")).toHaveLength(1);
  });

  it("is read once by calls that need it at the same moment", async () => {
    const { fabric, script } = scripted(
      [
        { request: get("/v1/auth/whoami"), response: answer(WHOAMI) },
        { request: READ, response: SANDBOX },
        { request: READ, response: SANDBOX },
        { request: READ, response: SANDBOX },
      ],
      { project: undefined },
    );
    await value(() => Promise.all([fabric.sandboxes.get(SBX), fabric.sandboxes.get(SBX), fabric.sandboxes.get(SBX)]));
    expect(script.received.map((request) => request.path)).toEqual(["/v1/auth/whoami", `${P}/sandboxes/${SBX}`, `${P}/sandboxes/${SBX}`, `${P}/sandboxes/${SBX}`]);
  });

  it("a lookup that fails is not remembered: the next call asks again", async () => {
    const { fabric } = scripted(
      [
        { request: get("/v1/auth/whoami"), response: problem("UNAUTHENTICATED") },
        { request: get("/v1/auth/whoami"), response: answer(WHOAMI) },
        { request: READ, response: SANDBOX },
      ],
      { project: undefined },
    );
    expect(await failure(() => fabric.sandboxes.get(SBX))).toBeInstanceOf(sdk.AuthenticationError);
    await value(() => fabric.sandboxes.get(SBX));
  });

  it("one caller abandoning its call does not fail another that was waiting for the same lookup", async () => {
    const abandoned = new AbortController();
    const requests: string[] = [];
    const fetch: Fetch = (url, request) => {
      const path = new URL(url).pathname;
      requests.push(path);
      if (requests.length === 1) {
        // The first lookup never answers; it ends when its caller gives up.
        return new Promise((_resolve, reject) => {
          request.signal.addEventListener("abort", () => reject(new DOMException("This operation was aborted", "AbortError")));
        });
      }
      const body = path === "/v1/auth/whoami" ? WHOAMI : sandboxView();
      return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
    };
    const time = new VirtualTime();
    const fabric = new sdk.Fabric({ apiKey: CANARY_KEY, baseUrl: BASE_URL, fetch, clock: time.clock, sleep: time.sleep });
    const first = failure(() => fabric.sandboxes.get(SBX, { signal: abandoned.signal }));
    const second = value(() => fabric.sandboxes.get(SBX));
    await Promise.resolve();
    abandoned.abort(new Error("the first caller gave up"));
    expect(((await first) as Error).message).toBe("the first caller gave up");
    expect((await second).sandbox_id).toBe(SBX);
    expect(requests).toEqual(["/v1/auth/whoami", "/v1/auth/whoami", `${P}/sandboxes/${SBX}`]);
  });

  it("an answer without a project is refused, not guessed around", async () => {
    const { fabric } = scripted([{ request: get("/v1/auth/whoami"), response: answer({ principal_id: "prn_1" }) }], { project: undefined });
    expect(await failure(() => fabric.sandboxes.get(SBX))).toBeInstanceOf(sdk.UnexpectedResponseError);
  });

  it("a route that is not in a project needs none", async () => {
    const { fabric, script } = scripted(
      [
        { request: get("/v1/info"), response: answer({ api_versions: ["v1"], serving: true }) },
        { request: get("/v1/auth/whoami"), response: answer(WHOAMI) },
        { request: get("/v1/auth/whoami"), response: answer(WHOAMI) },
      ],
      { project: undefined },
    );
    const info = await value(() => fabric.info());
    expect(info).toMatchObject({ api_versions: ["v1"], serving: true, ready: null, requestId: REQ });
    const me = await value(() => fabric.whoami());
    expect(me).toMatchObject({ principal_id: "prn_0000000000000001", project_id: PROJECT, policy_version: "3" });
    expect((await value(() => fabric.auth.whoami())).raw).toEqual(WHOAMI);
    // whoami as a call of its own does not configure the client: that is the lookup's job, on first need.
    expect(script.received).toHaveLength(3);
  });
});

describe("agent credentials", () => {
  const CRD = "crd_0000000000000001";
  const credential = (over: Json = {}): Json => ({ credential_id: CRD, kind: "agent", label: "worker", display_prefix: "acf1_agt_ab", status: "ACTIVE", issued_at: "2026-11-19T10:00:00.000Z", expires_at: "2026-11-19T11:00:00.000Z", ...over });
  const REVOKE = { method: "DELETE", path: `${P}/agent-credentials/${CRD}` };

  it("are minted with a label, a lifetime in the API's seconds, and a narrowing passed as it is", async () => {
    const narrowing = { schema_version: 1, methods: ["execution.create"], ceilings: { vcpus: 1, memory_mib: 512, disk_mib: 1024, execution_timeout_seconds: 60, sandbox_lifetime_seconds: 600 } };
    const { fabric, script } = scripted([
      { request: { method: "POST", path: `${P}/agent-credentials`, json: { label: "worker", lifetime_seconds: 3600 } }, response: answer(credential({ secret: "acf1_agt_once" }), 201) },
      { request: { method: "POST", path: `${P}/agent-credentials`, json: { label: "worker-2", lifetime_seconds: 90, narrowing } }, response: answer(credential({ label: "worker-2", narrowing }), 201) },
    ]);
    const first = await value(() => fabric.auth.mintAgentCredential("worker", { lifetime: "1h" }));
    expect(first).toMatchObject({ credential_id: CRD, label: "worker", status: "ACTIVE", contained: [], containmentErrors: [] });
    expect(first.secret).toBe("acf1_agt_once");
    const second = await value(() => fabric.auth.mintAgentCredential("worker-2", { lifetime: 90, narrowing }));
    expect(second.narrowing).toEqual(narrowing);
    expect(script.received.every((request) => request.headers["idempotency-key"] === undefined)).toBe(true);
  });

  it.each([
    ["no lifetime", "worker", {}, TypeError],
    ["a lifetime without a unit", "worker", { lifetime: "60" }, RangeError],
    ["a label that is not text", 7, { lifetime: 60 }, TypeError],
    ["a narrowing that is not an object", "worker", { lifetime: 60, narrowing: "agent" }, TypeError],
    ["a key: minting takes none", "worker", { lifetime: 60, idempotencyKey: "k" }, TypeError],
  ])("minting refuses %s before any request", async (_what, label, options, errorClass) => {
    const { fabric } = scripted([]);
    expect(await failure(() => fabric.auth.mintAgentCredential(label as never, options as never))).toBeInstanceOf(errorClass);
  });

  it("are listed", async () => {
    const { fabric } = scripted([{ request: get(`${P}/agent-credentials`), response: answer({ items: [credential(), credential({ credential_id: "crd_0000000000000002", status: "REVOKED" })] }) }]);
    const listed = await value(() => fabric.auth.agentCredentials());
    expect(listed.map((item) => [item.credential_id, item.status])).toEqual([
      [CRD, "ACTIVE"],
      ["crd_0000000000000002", "REVOKED"],
    ]);
  });

  it("are revoked with one request, and nothing else unless the caller asks for containment", async () => {
    const { fabric, script } = scripted([{ request: REVOKE, response: answer(credential({ status: "REVOKED" })) }]);
    const revoked = await value(() => fabric.auth.revokeAgentCredential(CRD));
    expect(revoked).toMatchObject({ status: "REVOKED", contained: [], containmentErrors: [] });
    expect(script.received[0]?.body).toBeUndefined();
  });

  it("with contain, the client cancels what the revoked credential left running, and only that", async () => {
    const exe = (n: number): string => `exe-${String(n).padStart(32, "0")}`;
    const op = (n: number, over: Json): Json => operationView({ operation_id: `op-${String(n).padStart(8, "0")}`, type: "execution.create", state: "IN_PROGRESS", target: { sandbox_id: SBX, generation: 1, execution_id: exe(n) }, actor: { principal_id: "prn_0000000000000001", agent_label: "worker" }, ...over });
    const cancelled = (n: number): Json => succeeded("execution.cancel", { execution: { execution_id: exe(n), operation_id: "op-x", project: PROJECT, state: "CANCELLED", terminal: true } }, { operation_id: `op-cancel-${n}` });
    const { fabric, script } = scripted([
      { request: REVOKE, response: answer(credential({ status: "REVOKED" })) },
      { request: get("/v1/auth/whoami"), response: answer(WHOAMI) },
      {
        request: get(`${P}/operations`),
        response: answer({
          items: [
            op(1, {}),
            op(2, { state: "SUCCEEDED", terminal: true }),
            op(3, { actor: { principal_id: "prn_0000000000000001", agent_label: "another-agent" } }),
            op(4, { actor: { principal_id: "prn_0000000000000002", agent_label: "worker" } }),
            op(5, { type: "sandbox.start" }),
          ],
          more: true,
          next_cursor: "c1",
        }),
      },
      {
        request: get(`${P}/operations`, { cursor: "c1" }),
        response: answer({
          items: [
            op(6, { state: "ACCEPTED" }),
            op(7, { state: "PARKED" }),
            op(8, { target: { sandbox_id: SBX, generation: 1 } }),
            op(9, { actor: null }),
            op(10, { actor: { principal_id: "prn_0000000000000001" } }),
          ],
          more: false,
          next_cursor: "c2",
        }),
      },
      { request: post(`${P}/executions/${exe(1)}/cancel`), response: answer(cancelled(1)) },
      { request: post(`${P}/executions/${exe(6)}/cancel`), response: problem("STATE_CONFLICT") },
      { request: post(`${P}/executions/${exe(7)}/cancel`), response: answer(cancelled(7)) },
    ]);
    const revoked = await value(() => fabric.auth.revokeAgentCredential(CRD, { contain: true }));
    expect(revoked.status).toBe("REVOKED");
    // Cancelled: the running execution, and the one in a state this version has never seen, which has not ended.
    expect(revoked.contained).toEqual([exe(1), exe(7)]);
    expect(revoked.containmentErrors.map((entry) => [entry.operationId, entry.executionId, entry.error.name])).toEqual([
      ["op-00000006", exe(6), "StateConflictError"],
      ["op-00000008", null, "UnexpectedResponseError"],
    ]);
    // Each cancel is a request of its own, under a key of its own.
    const keys = script.received.slice(4).map((request) => request.headers["idempotency-key"]);
    expect(keys).toHaveLength(3);
    expect(new Set(keys).size).toBe(3);
    expect(keys.every((key) => /^[0-9a-f-]{36}$/.test(key ?? ""))).toBe(true);
  });

  it("with contain, a listing that fails is the caller's to know: the credential is revoked and nothing is reported as contained", async () => {
    const { fabric } = scripted([
      { request: REVOKE, response: answer(credential({ status: "REVOKED" })) },
      { request: get("/v1/auth/whoami"), response: answer(WHOAMI) },
      { request: get(`${P}/operations`), response: problem("PERMISSION_DENIED") },
    ]);
    expect(await failure(() => fabric.auth.revokeAgentCredential(CRD, { contain: true }))).toBeInstanceOf(sdk.PermissionDeniedError);
  });

  it("with contain, a credential whose view names no label cannot be contained, and the SDK says so", async () => {
    const { fabric } = scripted([{ request: REVOKE, response: answer(credential({ status: "REVOKED", label: null })) }]);
    const error = await failure(() => fabric.auth.revokeAgentCredential(CRD, { contain: true }));
    expect(error).toBeInstanceOf(sdk.UnexpectedResponseError);
    expect((error as Error).message).toMatch(/was revoked, and its view names no label/);
  });

  it("revoking refuses a flag that is not one, before any request", async () => {
    const { fabric } = scripted([]);
    expect(await failure(() => fabric.auth.revokeAgentCredential(CRD, { contain: "yes" as never }))).toBeInstanceOf(TypeError);
    expect(await failure(() => fabric.auth.revokeAgentCredential("", {}))).toBeInstanceOf(RangeError);
  });
});

describe("OpenTelemetry", () => {
  const SLOT = Symbol.for("opentelemetry.js.api.1");

  interface Recorded {
    name: string;
    kind: number;
    attributes: { [name: string]: unknown };
    events: [string, unknown][];
    status: { code: number; message?: string } | undefined;
    ended: number;
  }

  /** Registers a tracer provider the way an application's OpenTelemetry installation does. */
  function install(startActiveSpan?: (name: string, options: { kind: number }, body: (span: unknown) => unknown, make: () => unknown) => unknown) {
    const spans: Recorded[] = [];
    const scopes: unknown[][] = [];
    const make = (name: string, options: { kind: number }) => {
      const recorded: Recorded = { name, kind: options.kind, attributes: {}, events: [], status: undefined, ended: 0 };
      spans.push(recorded);
      return {
        setAttribute: (attribute: string, attributeValue: unknown) => void (recorded.attributes[attribute] = attributeValue),
        addEvent: (event: string, attributes: unknown) => void recorded.events.push([event, attributes]),
        setStatus: (status: { code: number; message?: string }) => void (recorded.status = status),
        end: () => void (recorded.ended += 1),
      };
    };
    const tracer = {
      startActiveSpan: (name: string, options: { kind: number }, body: (span: unknown) => unknown) =>
        startActiveSpan === undefined ? body(make(name, options)) : startActiveSpan(name, options, body, () => make(name, options)),
    };
    const provider = {
      getTracer: (...scope: unknown[]) => {
        scopes.push(scope);
        return tracer;
      },
    };
    (globalThis as { [SLOT]?: unknown })[SLOT] = { version: "1.10.0", trace: provider };
    return { spans, scopes };
  }

  afterEach(() => {
    delete (globalThis as { [SLOT]?: unknown })[SLOT];
  });

  const CREATE = post(`${P}/sandboxes`, { image: "python", resources: { vcpus: 1, memory_mib: 512, disk_mib: 1024 } });
  const START = post(`${P}/sandboxes/${SBX}/start`, { expected_generation: 1 });
  const created = answer(succeeded("sandbox.create", { sandbox: sandboxView() }));
  const started = answer(succeeded("sandbox.start", { sandbox: sandboxView({ state: "RUNNING" }) }));
  const create = (fabric: sdk.Fabric) => fabric.sandboxes.create("python", { cpu: 1, memory: 512, disk: 1024 });

  it("is not there by default: a call makes no span and needs nothing", async () => {
    const { fabric } = scripted([{ request: READ, response: SANDBOX }]);
    await value(() => fabric.sandboxes.get(SBX));
    expect((globalThis as { [SLOT]?: unknown })[SLOT]).toBeUndefined();
  });

  it("one logical call is one span in the application's own tracer, however many requests it makes", async () => {
    const { spans, scopes } = install();
    const { fabric } = scripted([
      { request: CREATE, response: problem("RATE_LIMITED", { retryAfter: 1 }) },
      { request: CREATE, response: created },
      { request: START, response: started },
    ]);
    await value(() => create(fabric));
    expect(spans).toEqual([
      {
        name: "acf.sandboxes.create",
        kind: 2,
        attributes: {},
        events: [["retry", { "acf.attempt": 1, "acf.delay_s": 1, "acf.cause": "RATE_LIMITED" }]],
        status: undefined,
        ended: 1,
      },
    ]);
    expect(scopes).toEqual([["agent-compute-typescript", sdk.VERSION]]);
  });

  it("a call that fails is a span with the class, the code and the request id of the failure, and no message", async () => {
    const { spans } = install();
    const { fabric } = scripted([{ request: READ, response: problem("NOT_FOUND", { message: "no sandbox named after the caller's dog" }) }]);
    await failure(() => fabric.sandboxes.get(SBX));
    expect(spans).toEqual([
      {
        name: "acf.sandboxes.get",
        kind: 2,
        attributes: { "error.type": "NotFoundError", "acf.code": "NOT_FOUND", "acf.request_id": REQ },
        events: [],
        status: { code: 2, message: "NotFoundError" },
        ended: 1,
      },
    ]);
  });

  it("a span carries no credential, no argument, no environment value and no output", async () => {
    const { spans } = install();
    const { fabric } = scripted([
      { request: READ, response: SANDBOX },
      { request: post(`${P}/sandboxes/${SBX}/executions`), response: problem("PERMISSION_DENIED") },
      { request: get(`${P}/sandboxes`), response: answer({ items: [sandboxView()], more: false, next_cursor: "end" }) },
    ]);
    const sandbox = await value(() => fabric.sandboxes.get(SBX));
    await failure(() => sandbox.exec(["deploy", "--token", "s3cret-argument"], { env: { API_TOKEN: "s3cret-environment" } }));
    await all(fabric.sandboxes.list());
    expect(spans.map((span) => span.name)).toEqual(["acf.sandboxes.get", "acf.sandbox.exec", "acf.sandboxes.list"]);
    expectNoSecret(spans, [CANARY_KEY, "s3cret-argument", "s3cret-environment", "deploy"]);
  });

  it.each([
    ["throws before it runs the call", () => { throw new Error("tracer is broken"); }],
    ["never runs the call", () => undefined],
    ["runs the call and then throws", (_name: string, _options: unknown, body: (span: unknown) => unknown, make: () => unknown) => { void body(make()); throw new Error("tracer is broken"); }],
    ["runs the call twice", (_name: string, _options: unknown, body: (span: unknown) => unknown, make: () => unknown) => { void body(make()); return body(make()); }],
    ["hands out a span whose every method throws", (_name: string, _options: unknown, body: (span: unknown) => unknown) => body(new Proxy({}, { get: () => () => { throw new Error("span is broken"); } }))],
  ] as const)("a tracer that %s changes nothing: the call runs exactly once and its outcome is its own", async (_what, startActiveSpan) => {
    install(startActiveSpan as never);
    const succeeding = scripted([
      { request: CREATE, response: created },
      { request: START, response: started },
    ]);
    expect((await value(() => create(succeeding.fabric))).state).toBe("RUNNING");
    expect(succeeding.script.received).toHaveLength(2);

    const failing = scripted([{ request: READ, response: problem("NOT_FOUND") }]);
    expect(await failure(() => failing.fabric.sandboxes.get(SBX))).toBeInstanceOf(sdk.NotFoundError);
  });

  it("a provider that hands out no tracer, or one that cannot start a span, is the same as none", async () => {
    for (const trace of [{ getTracer: () => undefined }, { getTracer: () => ({}) }, { getTracer: () => { throw new Error("no tracer"); } }, {}, undefined]) {
      (globalThis as { [SLOT]?: unknown })[SLOT] = { version: "1.10.0", trace };
      const { fabric } = scripted([{ request: READ, response: SANDBOX }]);
      await value(() => fabric.sandboxes.get(SBX));
    }
  });
});

describe("the package", () => {
  const root = new URL("../", import.meta.url);
  const manifest = JSON.parse(readFileSync(new URL("package.json", root), "utf8")) as { [member: string]: unknown };

  it("states its version once: the manifest and the module agree", () => {
    expect(manifest["version"]).toBe(sdk.VERSION);
    expect(manifest["name"]).toBe("@agent-compute/sdk");
  });

  it("is ESM only, has no side effects on import, and supports the Node.js lines in maintenance", () => {
    expect(manifest).toMatchObject({
      type: "module",
      sideEffects: false,
      license: "Apache-2.0",
      engines: { node: ">=22.12.0" },
      exports: { ".": { types: "./dist/index.d.ts", default: "./dist/index.js" } },
    });
  });

  it("depends on nothing at run time, and pins what it is built and tested with exactly", () => {
    for (const kind of ["dependencies", "peerDependencies", "optionalDependencies", "bundledDependencies"]) {
      expect(manifest[kind], kind).toBeUndefined();
    }
    const development = manifest["devDependencies"] as { [name: string]: string };
    expect(Object.keys(development).sort()).toEqual(["@types/node", "typescript", "vitest"]);
    for (const version of Object.values(development)) {
      expect(version).toMatch(/^\d+\.\d+\.\d+$/);
    }
  });

  it("uses no API of Node.js in the client: no module of it, and no global of it but the guarded environment", () => {
    const sources = readdirSync(new URL("src/", root)).filter((name) => name.endsWith(".ts"));
    expect(sources.length).toBeGreaterThan(10);
    for (const name of sources) {
      const code = readFileSync(new URL(`src/${name}`, root), "utf8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/^\s*\/\/.*$/gm, "");
      expect(code, `${name} imports no module of Node.js`).not.toMatch(/from\s+["']node:|require\s*\(|import\s*\(/);
      expect(code, `${name} names no global of Node.js`).not.toMatch(/\b(Buffer|__dirname|__filename|setImmediate|global)\b/);
      const process = code.split("\n").filter((line) => /\bprocess\b/.test(line));
      if (name === "context.ts") {
        expect(process.every((line) => /scope\.process\?\.env|process\?: \{ env\?:/.test(line)), "process is only reached through the guarded lookup").toBe(true);
        expect(process).toHaveLength(2);
      } else {
        expect(process, `${name} does not name process`).toEqual([]);
      }
    }
  });

  it("never names a stage of the project's plan: things are called what they are", () => {
    const forbidden = new RegExp(["pha", "se"].join(""), "i");
    const files = [
      "README.md",
      "package.json",
      "tsconfig.json",
      "tsconfig.build.json",
      "vitest.config.ts",
      ".gitignore",
      ...readdirSync(new URL("src/", root)).map((name) => `src/${name}`),
      ...readdirSync(new URL("tests/", root), { recursive: true })
        .map((name) => `tests/${String(name).replaceAll("\\", "/")}`)
        .filter((name) => name.endsWith(".ts")),
    ];
    expect(files.length).toBeGreaterThan(25);
    for (const file of files) {
      expect(readFileSync(new URL(file, root), "utf8"), file).not.toMatch(forbidden);
    }
  });
});
