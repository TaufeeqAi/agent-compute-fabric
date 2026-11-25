/**
 * What a later version of the platform may send that this version of the SDK has never seen: a
 * member, a value of a vocabulary, a code. None of it is an error, none of it is mapped onto
 * something known, and a code is handled by its kind and its retry advice.
 *
 * Also here: the SDK's table of codes, held against the platform's registry.
 */

import { describe, expect, it } from "vitest";

import { errorForAnswer } from "../src/errors.js";
import * as sdk from "../src/index.js";
import {
  answer,
  CREATE_ARGS,
  CREATE_BODY,
  EXE,
  executionView,
  failure,
  get,
  operationView,
  P,
  post,
  problem,
  registry,
  REQ,
  sandboxView,
  SBX,
  scripted,
  snapshotView,
  succeeded,
  value,
} from "./support/harness.js";

const CREATE = post(`${P}/sandboxes`, CREATE_BODY, "$KEY");
const create = (fabric: sdk.Fabric, options: object = {}) => fabric.sandboxes.create("python", { ...CREATE_ARGS, start: false, ...options });

describe("members and values the SDK has never seen", () => {
  it("a sandbox with an unknown member, an unknown state and unknown values inside it", async () => {
    const view = sandboxView({
      state: "HIBERNATED",
      state_raw: "S7",
      placement: { zone: "a", rack: 12 },
      network: { mode: "mesh", mode_raw: "M2", entries: [], peers: ["sbx-x"] },
      failure: { code: "COSMIC_RAY", retry: "EVENTUALLY", message: "a bit flipped", side_effect: "SOME", blast_radius: 3 },
      quarantined: "FUTURE_REASON",
    });
    const { fabric } = scripted([{ request: get(`${P}/sandboxes/${SBX}`), response: answer(view) }]);
    const sandbox = await value(() => fabric.sandboxes.get(SBX));
    expect(sandbox.state).toBe("HIBERNATED");
    expect(sandbox.state_raw).toBe("S7");
    expect(sandbox.network.mode).toBe("mesh");
    expect(sandbox.failure).toEqual(view["failure"]);
    expect(sandbox.quarantined).toBe("FUTURE_REASON");
    // The unknown member is not an attribute, and is kept where everything received is kept.
    expect("placement" in sandbox).toBe(false);
    expect(sandbox.raw["placement"]).toEqual({ zone: "a", rack: 12 });
    expect(sandbox.raw).toEqual(view);
  });

  it("an operation of an unknown type, with an unknown effect and cleanup, is shown as it is", async () => {
    const view = operationView({ type: "sandbox.migrate", type_raw: "T9", state: "RECOVERING", effect: "PARTLY_APPLIED", cleanup: "DEFERRED", cancelled_by: "OPERATOR", initiated_by: "SCHEDULER", shard: 4 });
    const { fabric } = scripted([{ request: get(`${P}/operations/op-future-0001`), response: answer(view) }]);
    const operation = await value(() => fabric.operations.get("op-future-0001"));
    expect(operation).toMatchObject({ type: "sandbox.migrate", effect: "PARTLY_APPLIED", cleanup: "DEFERRED", cancelled_by: "OPERATOR", initiated_by: "SCHEDULER" });
    expect(operation.raw["shard"]).toBe(4);
  });

  it("an execution with an unknown status, and a snapshot in an unknown state", async () => {
    const execution = executionView({ status: "OOM_KILLED", status_raw: "X1", evidence_status: "SEALED", cgroup: "v3" });
    const snapshot = snapshotView({ state: "ARCHIVING", incompatible: ["FUTURE_CPU_FLAG"], tier: "cold" });
    const { fabric } = scripted([
      { request: get(`${P}/executions/${EXE}`), response: answer(execution) },
      { request: get(`${P}/snapshots`), response: answer({ items: [snapshot], more: false, next_cursor: "end", total: 1 }) },
    ]);
    const read = await value(() => fabric.executions.get(EXE));
    expect(read).toMatchObject({ status: "OOM_KILLED", status_raw: "X1", evidence_status: "SEALED" });
    const [listed] = await value(async () => {
      const items: sdk.Snapshot[] = [];
      for await (const item of fabric.snapshots.list()) {
        items.push(item);
      }
      return items;
    });
    expect(listed).toMatchObject({ state: "ARCHIVING", incompatible: ["FUTURE_CPU_FLAG"] });
    expect(listed?.raw["tier"]).toBe("cold");
  });

  it("output with an unknown completeness", async () => {
    const chunk = { execution_id: EXE, stream: "stdout", offset: 0, data_base64: "", next_offset: 0, eof: true, stored_bytes: 0, produced_bytes: 9, completeness: "SAMPLED", sampling: 0.1 };
    const { fabric } = scripted([
      { request: get(`${P}/executions/${EXE}`), response: answer(executionView()) },
      { request: get(`${P}/executions/${EXE}/output`), response: answer(chunk) },
    ]);
    const execution = await value(() => fabric.executions.get(EXE));
    const output = await value(() => execution.output());
    expect(output.completeness).toBe("SAMPLED");
    expect(output.raw["sampling"]).toBe(0.1);
  });

  it("info and whoami with members of a later version", async () => {
    const info = { api_versions: ["v1", "v2"], serving: true, ready: true, platform_features: ["future_feature"], regions: ["eu"] };
    const whoami = { principal_id: "prn_1", project_id: "prj_0000000000000001", credential: { credential_id: "crd_1", kind: "robot", expires_at: "t1" }, grants: { schema_version: 2, anything: [1] }, policy_version: "7", tenant: "t" };
    const { fabric } = scripted([
      { request: get("/v1/info"), response: answer(info) },
      { request: get("/v1/auth/whoami"), response: answer(whoami) },
    ]);
    const platform = await value(() => fabric.info());
    expect(platform).toMatchObject({ api_versions: ["v1", "v2"], serving: true, ready: true, host_features: null, ceilings: null });
    expect(platform.raw["regions"]).toEqual(["eu"]);
    const me = await value(() => fabric.whoami());
    expect(me.credential.kind).toBe("robot");
    expect(me.grants).toEqual({ schema_version: 2, anything: [1] });
    expect(me.raw["tenant"]).toBe("t");
  });

  it("a result of an operation with an unknown state of the resource is still the result", async () => {
    const { fabric } = scripted([{ request: CREATE, response: answer(succeeded("sandbox.create", { sandbox: sandboxView({ state: "WARMING" }), receipt: { id: 1 } })) }]);
    const sandbox = await value(() => create(fabric));
    expect(sandbox.state).toBe("WARMING");
  });
});

describe("codes the SDK has never seen", () => {
  it("with kind REFUSED it is a RefusedError, exactly", async () => {
    const { fabric } = scripted([{ request: CREATE, response: problem("QUOTA_FROZEN", { kind: "REFUSED", retry: "AFTER_CHANGE", status: 409, reason: "billing" }) }]);
    const error = await failure(() => create(fabric));
    expect(Object.getPrototypeOf(error)).toBe(sdk.RefusedError.prototype);
    expect(error).toMatchObject({ name: "RefusedError", code: "QUOTA_FROZEN", kind: "REFUSED", retry: "AFTER_CHANGE", status: 409, reason: "billing", requestId: REQ });
    expect((error as Error).message).toBe("The title of QUOTA_FROZEN");
  });

  it("with kind UNRESOLVED it is an UnresolvedError, exactly, and carries the key to ask again with", async () => {
    const { fabric, script } = scripted([{ request: CREATE, response: problem("LEDGER_SPLIT", { kind: "UNRESOLVED", retry: "AFTER_CHANGE", status: 503 }) }]);
    const error = await failure(() => create(fabric));
    expect(Object.getPrototypeOf(error)).toBe(sdk.UnresolvedError.prototype);
    expect(error).toMatchObject({ code: "LEDGER_SPLIT", kind: "UNRESOLVED", idempotencyKey: script.key });
  });

  it("with a kind it has never seen either, it is a RefusedError, and the kind is kept as it is", async () => {
    const { fabric } = scripted([{ request: CREATE, response: problem("PARKED", { kind: "DEFERRED", retry: "NEVER", status: 409 }) }]);
    const error = await failure(() => create(fabric));
    expect(Object.getPrototypeOf(error)).toBe(sdk.RefusedError.prototype);
    expect(error).toMatchObject({ kind: "DEFERRED" });
  });

  it("is repeated when it says SAME_REQUEST_LATER, whatever its kind, with the same key", async () => {
    for (const kind of ["REFUSED", "UNRESOLVED", "DEFERRED"]) {
      const { fabric, script } = scripted([
        { request: CREATE, response: problem("LEDGER_SPLIT", { kind, retry: "SAME_REQUEST_LATER", status: 503, retryAfter: 1 }) },
        { request: CREATE, response: answer(succeeded("sandbox.create", { sandbox: sandboxView() })) },
      ]);
      await value(() => create(fabric));
      expect(script.received).toHaveLength(2);
    }
  });

  it.each(["TIMEOUT", "DEPENDENCY_UNAVAILABLE", "UNKNOWN_OUTCOME", "constructor", "__proto__", "toString", "hasOwnProperty", ""])(
    "a code that is not a code of an error answer (%j) is handled by its kind like any other",
    async (code) => {
      const { fabric } = scripted([{ request: CREATE, response: problem(code, { kind: "REFUSED", retry: "NEVER", status: 400 }) }]);
      const error = await failure(() => create(fabric));
      expect(Object.getPrototypeOf(error)).toBe(sdk.RefusedError.prototype);
      expect(error).toMatchObject({ code });
    },
  );

  it("an error answer without a kind or an advice is refused and not repeated", async () => {
    const { fabric, script } = scripted([{ request: CREATE, response: { status: 503, headers: {}, json: { code: "BARE" } } }]);
    const error = await failure(() => create(fabric));
    expect(Object.getPrototypeOf(error)).toBe(sdk.RefusedError.prototype);
    expect(error).toMatchObject({ code: "BARE", kind: "", retry: "", status: 503, requestId: undefined });
    expect((error as Error).message).toMatch(/was answered 503 with code BARE\.$/);
    expect(script.received).toHaveLength(1);
  });

  it("a failure code of an operation that the SDK has never seen is carried as it is", async () => {
    const failed = operationView({ state: "FAILED", terminal: true, effect: "NOT_APPLIED", failure: { code: "UNRECOGNIZED", code_raw: "HOST_ON_FIRE", retry: "NEVER", message: "unrecognized" } });
    const { fabric } = scripted([{ request: CREATE, response: answer(failed) }]);
    const error = await failure(() => create(fabric));
    expect(error).toBeInstanceOf(sdk.OperationFailedError);
    expect(error).toMatchObject({ code: "UNRECOGNIZED" });
    expect((error as sdk.OperationFailedError).operation.failure?.code_raw).toBe("HOST_ON_FIRE");
  });
});

describe("the SDK's codes and the platform's registry", () => {
  const records = registry();
  const fields = (code: string, kind: string | null) => ({ status: 400, code, kind: kind ?? "REFUSED", retry: "NEVER", requestId: undefined, idempotencyKey: undefined, reason: undefined, retryAfter: undefined });

  it("the registry is read from the repository and holds the codes of this version", () => {
    expect(records.length).toBeGreaterThanOrEqual(29);
    expect(records.map((record) => record.code)).toEqual(expect.arrayContaining(["INVALID_REQUEST", "OUTCOME_LOST", "UNRECOGNIZED", "UNKNOWN_OUTCOME"]));
  });

  it.each(records.filter((record) => record.error_answer).map((record) => [record.code, record] as const))(
    "%s is thrown as the class the registry names",
    (code, record) => {
      const error = errorForAnswer("message", fields(code, record.kind));
      expect(error.name).toBe(record.sdk_exception);
      expect(Object.getPrototypeOf(error)).toBe((sdk as unknown as { [name: string]: { prototype: object } })[record.sdk_exception]?.prototype);
      expect(error).toBeInstanceOf(record.kind === "UNRESOLVED" ? sdk.UnresolvedError : sdk.RefusedError);
    },
  );

  it.each(records.map((record) => [record.sdk_exception] as const))("the package exports %s", (name) => {
    const exported = (sdk as unknown as { [name: string]: unknown })[name];
    expect(exported).toBeTypeOf("function");
    expect((exported as { prototype: unknown }).prototype).toBeInstanceOf(sdk.FabricError);
  });

  it.each(records.filter((record) => !record.error_answer).map((record) => [record.code, record] as const))(
    "%s only ever ends an operation, and is then %s",
    async (code, record) => {
      // The effect that goes with the class: nothing applied for a failure, not known for an unknown outcome.
      const unknown = record.sdk_exception === "OutcomeUnknownError";
      const ending = operationView({ state: unknown ? "UNKNOWN" : "FAILED", terminal: true, effect: unknown ? "MAY_BE_APPLIED" : "NOT_APPLIED", failure: { code, retry: record.retry, message: "m" } });
      const { fabric } = scripted([{ request: CREATE, response: answer(ending) }]);
      const error = await failure(() => create(fabric));
      expect((error as Error).name).toBe(record.sdk_exception);
      expect(error).toMatchObject({ code });
    },
  );
});

describe("the hierarchy of errors", () => {
  const tree: [keyof typeof sdk, keyof typeof sdk | "Error"][] = [
    ["FabricError", "Error"],
    ["ConfigurationError", "FabricError"],
    ["IncompatibleServerError", "ConfigurationError"],
    ["APIConnectionError", "FabricError"],
    ["APITimeoutError", "APIConnectionError"],
    ["UnexpectedResponseError", "FabricError"],
    ["APIError", "FabricError"],
    ["RefusedError", "APIError"],
    ["InvalidRequestError", "RefusedError"],
    ["AuthenticationError", "RefusedError"],
    ["PermissionDeniedError", "RefusedError"],
    ["SafetyControlDeniedError", "RefusedError"],
    ["NotFoundError", "RefusedError"],
    ["RevisionConflictError", "RefusedError"],
    ["IdempotencyConflictError", "RefusedError"],
    ["RateLimitError", "RefusedError"],
    ["CapacityError", "RefusedError"],
    ["ServiceUnavailableError", "RefusedError"],
    ["UnsupportedFeatureError", "RefusedError"],
    ["CursorExpiredError", "RefusedError"],
    ["InternalError", "RefusedError"],
    ["ConflictError", "RefusedError"],
    ["StateConflictError", "ConflictError"],
    ["QuarantinedError", "ConflictError"],
    ["IntegrityFailureError", "ConflictError"],
    ["IncompatibleRuntimeError", "ConflictError"],
    ["UnresolvedError", "APIError"],
    ["RequestInProgressError", "UnresolvedError"],
    ["OutcomeUnresolvedError", "UnresolvedError"],
    ["OutcomeLostError", "UnresolvedError"],
    ["OperationError", "FabricError"],
    ["OperationFailedError", "OperationError"],
    ["OutcomeUnknownError", "OperationError"],
    ["OperationStillRunningError", "OperationError"],
    ["SandboxStartError", "FabricError"],
    ["NameReboundError", "FabricError"],
  ];

  it.each(tree)("%s is directly below %s, and is named as it is exported", (name, parent) => {
    const errorClass = sdk[name] as unknown as { prototype: { name: string } };
    const parentClass = parent === "Error" ? Error : (sdk[parent] as unknown as { prototype: object });
    expect(Object.getPrototypeOf(errorClass.prototype)).toBe(parentClass.prototype);
    expect(errorClass.prototype.name).toBe(name);
  });

  it("names every error the package exports, and the package exports nothing else that is a value but the client and the version", () => {
    const values = Object.keys(sdk).sort();
    expect(values).toEqual([...tree.map(([name]) => name), "Fabric", "VERSION"].sort());
  });
});
