/**
 * `sandboxes.create`: the client drives two operations of the platform, create and then start, and
 * says exactly what became of the sandbox when the start does not succeed.
 */

import { describe, expect, it } from "vitest";

import * as sdk from "../src/index.js";
import {
  accepted,
  answer,
  CREATE_ARGS,
  CREATE_BODY,
  del,
  ended,
  type Exchange,
  failure,
  get,
  operationView,
  P,
  post,
  problem,
  reset,
  sandboxView,
  SBX,
  scripted,
  succeeded,
  value,
} from "./support/harness.js";

const OP_CREATE = `op-${"a".repeat(32)}`;
const OP_START = `op-${"b".repeat(32)}`;
const OP_DESTROY = `op-${"d".repeat(32)}`;

/** The sandbox as created: generation 4, so that a wrong generation in a later request shows. */
const READY = sandboxView({ state: "READY", generation: 4 });
const created = answer(succeeded("sandbox.create", { sandbox: READY }, { operation_id: OP_CREATE }));
const started = answer(succeeded("sandbox.start", { sandbox: sandboxView({ state: "RUNNING", generation: 4 }) }, { operation_id: OP_START }));
const destroyed = answer(succeeded("sandbox.destroy", { sandbox: sandboxView({ state: "DESTROYED", generation: 4 }) }, { operation_id: OP_DESTROY }));

const CREATE = post(`${P}/sandboxes`, CREATE_BODY, "$KEY");
const START = post(`${P}/sandboxes/${SBX}/start`, { expected_generation: 4 }, "$KEY:start");
const DESTROY = del(`${P}/sandboxes/${SBX}`, { expected_generation: "4" }, "$KEY:destroy");

const startFailed = answer(ended("sandbox.start", "FAILED", "NOT_APPLIED", "RESOURCE_EXHAUSTED", { operation_id: OP_START }));

async function createFails(exchanges: Exchange[], options: object = {}, clientOptions: object = {}): Promise<{ error: unknown; requests: string[] }> {
  const { fabric, script } = scripted(exchanges, clientOptions, "k1");
  const error = await failure(() => fabric.sandboxes.create("python", { ...CREATE_ARGS, idempotencyKey: "k1", ...options }));
  return { error, requests: script.received.map((request) => `${request.method} ${request.path.replace(P, "")}`) };
}

describe("create, then start", () => {
  it("issues the create under the key and the start under the key with the suffix :start, and returns the started sandbox", async () => {
    const { fabric, script } = scripted([
      { request: CREATE, response: created },
      { request: START, response: started },
    ]);
    const sandbox = await value(() => fabric.sandboxes.create("python", CREATE_ARGS));
    expect(sandbox.state).toBe("RUNNING");
    expect(sandbox.operation?.operation_id).toBe(OP_START);
    const [first, second] = script.received.map((request) => request.headers["idempotency-key"]);
    expect(first).toMatch(/^[0-9a-f-]{36}$/);
    expect(second).toBe(`${first}:start`);
  });

  it("uses the caller's key for the create and derives the start's from it", async () => {
    const { fabric, script } = scripted(
      [
        { request: CREATE, response: created },
        { request: START, response: started },
      ],
      {},
      "nightly-build-42",
    );
    await value(() => fabric.sandboxes.create("python", { ...CREATE_ARGS, idempotencyKey: "nightly-build-42" }));
    expect(script.received.map((request) => request.headers["idempotency-key"])).toEqual(["nightly-build-42", "nightly-build-42:start"]);
  });

  it("accepts a key of 247 characters: the longest key it derives is then 255", async () => {
    const key = "k".repeat(247);
    const { fabric, script } = scripted(
      [
        { request: CREATE, response: created },
        { request: START, response: startFailed },
        { request: DESTROY, response: destroyed },
      ],
      {},
      key,
    );
    await failure(() => fabric.sandboxes.create("python", { ...CREATE_ARGS, idempotencyKey: key }));
    expect(script.received.map((request) => request.headers["idempotency-key"]?.length)).toEqual([247, 253, 255]);
  });

  it("states the generation of the created sandbox when it starts it", async () => {
    const { fabric, script } = scripted([
      { request: CREATE, response: created },
      { request: START, response: started },
    ]);
    await value(() => fabric.sandboxes.create("python", CREATE_ARGS));
    expect(JSON.parse(script.received[1]?.body ?? "")).toEqual({ expected_generation: 4 });
  });

  it("with start: false it issues the create only, and returns the sandbox as created", async () => {
    const { fabric } = scripted([{ request: CREATE, response: created }]);
    const sandbox = await value(() => fabric.sandboxes.create("python", { ...CREATE_ARGS, start: false }));
    expect(sandbox.state).toBe("READY");
    expect(sandbox.operation?.operation_id).toBe(OP_CREATE);
  });

  it("follows each of the two operations", async () => {
    const creating = operationView({ operation_id: OP_CREATE, type: "sandbox.create" });
    const starting = operationView({ operation_id: OP_START, type: "sandbox.start" });
    const { fabric, time } = scripted([
      { request: CREATE, response: accepted(creating, 2) },
      { request: get(`${P}/operations/${OP_CREATE}`, { wait: "30" }), response: created },
      { request: START, response: accepted(starting, 3) },
      { request: get(`${P}/operations/${OP_START}`, { wait: "30" }), response: started },
    ]);
    const sandbox = await value(() => fabric.sandboxes.create("python", CREATE_ARGS));
    expect(sandbox.state).toBe("RUNNING");
    expect(time.waits).toEqual([2, 3]);
  });

  it("repeats a start that is refused for now under the same derived key", async () => {
    const { fabric, script } = scripted([
      { request: CREATE, response: created },
      { request: START, response: problem("HOST_NOT_SERVING", { retryAfter: 1 }) },
      { request: START, response: started },
    ]);
    await value(() => fabric.sandboxes.create("python", CREATE_ARGS));
    expect(script.received[2]?.headers["idempotency-key"]).toBe(script.received[1]?.headers["idempotency-key"]);
  });

  it("repeated with the same key and the same arguments, sends the same two requests: the call can be resumed", async () => {
    const replayedCreate = answer(succeeded("sandbox.create", { sandbox: READY }, { operation_id: OP_CREATE, replayed: true }));
    const replayedStart = answer(succeeded("sandbox.start", { sandbox: sandboxView({ state: "RUNNING", generation: 4 }) }, { operation_id: OP_START, replayed: true }));
    const { fabric, script } = scripted(
      [
        { request: CREATE, response: created },
        { request: START, response: reset },
        { request: START, response: reset },
        { request: START, response: reset },
        { request: CREATE, response: replayedCreate },
        { request: START, response: replayedStart },
      ],
      {},
      "resume-7",
    );
    const call = () => fabric.sandboxes.create("python", { ...CREATE_ARGS, idempotencyKey: "resume-7" });
    const unresolved = await failure(call);
    expect(unresolved).toBeInstanceOf(sdk.OutcomeUnresolvedError);
    expect(unresolved).toMatchObject({ idempotencyKey: "resume-7:start" });

    const sandbox = await value(call);
    expect(sandbox.state).toBe("RUNNING");
    expect(sandbox.operation?.replayed).toBe(true);
    expect(script.received[4]?.body).toBe(script.received[0]?.body);
    expect(script.received[5]?.body).toBe(script.received[1]?.body);
  });
});

describe("when the create itself fails", () => {
  it.each([
    ["is refused", [{ request: CREATE, response: problem("PERMISSION_DENIED") }], sdk.PermissionDeniedError],
    ["ends without success", [{ request: CREATE, response: answer(ended("sandbox.create", "FAILED", "NOT_APPLIED", "RESOURCE_EXHAUSTED")) }], sdk.OperationFailedError],
    ["ends unknown", [{ request: CREATE, response: answer(ended("sandbox.create", "UNKNOWN", "MAY_BE_APPLIED", "UNKNOWN_OUTCOME")) }], sdk.OutcomeUnknownError],
    ["is lost", [{ request: CREATE, response: problem("OUTCOME_LOST", { key: "k1" }) }], sdk.OutcomeLostError],
    ["stays unresolved", Array.from({ length: 3 }, () => ({ request: CREATE, response: reset })), sdk.OutcomeUnresolvedError],
    ["is still running at the bound", [{ request: CREATE, response: accepted(operationView(), 9) }], sdk.OperationStillRunningError],
  ] as const)("a create that %s throws its own error, and nothing else is sent", async (_what, exchanges, errorClass) => {
    const { error, requests } = await createFails([...exchanges], {}, { followMax: 5 });
    expect(error).toBeInstanceOf(errorClass);
    expect(error).not.toBeInstanceOf(sdk.SandboxStartError);
    expect(new Set(requests)).toEqual(new Set(["POST /sandboxes"]));
  });
});

describe("when the start does not succeed", () => {
  const refusedStart = problem("STATE_CONFLICT");

  it("destroys the sandbox by default, under the key with the suffix :destroy and the generation the handle saw, and names both outcomes", async () => {
    const { error, requests } = await createFails([
      { request: CREATE, response: created },
      { request: START, response: startFailed },
      { request: DESTROY, response: destroyed },
    ]);
    expect(requests).toEqual(["POST /sandboxes", `POST /sandboxes/${SBX}/start`, `DELETE /sandboxes/${SBX}`]);
    expect(error).toBeInstanceOf(sdk.SandboxStartError);
    const failed = error as sdk.SandboxStartError;
    expect(failed).toMatchObject({ sandboxId: SBX, cleanup: "destroyed", code: "RESOURCE_EXHAUSTED", destroyError: undefined });
    expect(failed.startError).toBeInstanceOf(sdk.OperationFailedError);
    expect(failed.message).toMatch(/was created and its start did not succeed; the sandbox was destroyed\./);
    expect(failed.message).toContain("OperationFailedError");
  });

  it.each([
    ["is refused", refusedStart, sdk.StateConflictError, "STATE_CONFLICT"],
    ["is refused for now, beyond what the client waits", problem("RESOURCE_EXHAUSTED", { retryAfter: 60 }), sdk.CapacityError, "RESOURCE_EXHAUSTED"],
    ["is refused with a code the client has never seen", problem("FUTURE_REFUSAL", { status: 409 }), sdk.RefusedError, "FUTURE_REFUSAL"],
    ["ends FAILED with nothing applied", startFailed, sdk.OperationFailedError, "RESOURCE_EXHAUSTED"],
    ["ends CANCELLED with nothing applied", answer(ended("sandbox.start", "CANCELLED", "NOT_APPLIED", "TIMEOUT")), sdk.OperationFailedError, "TIMEOUT"],
    ["ends FAILED and may have been applied", answer(ended("sandbox.start", "FAILED", "MAY_BE_APPLIED", "TIMEOUT")), sdk.OutcomeUnknownError, "TIMEOUT"],
    ["ends UNKNOWN", answer(ended("sandbox.start", "UNKNOWN", "MAY_BE_APPLIED", "UNKNOWN_OUTCOME")), sdk.OutcomeUnknownError, "UNKNOWN_OUTCOME"],
  ] as const)("a start that %s is cleaned up after: destroy", async (_what, response, startClass, code) => {
    const { error } = await createFails([
      { request: CREATE, response: created },
      { request: START, response },
      { request: DESTROY, response: destroyed },
    ]);
    expect(error).toBeInstanceOf(sdk.SandboxStartError);
    const failed = error as sdk.SandboxStartError;
    expect(failed.startError).toBeInstanceOf(startClass);
    expect(failed).toMatchObject({ sandboxId: SBX, cleanup: "destroyed", code });
  });

  it('with onStartFailure: "keep" it sends no destroy, and names the sandbox it left behind', async () => {
    const { error, requests } = await createFails(
      [
        { request: CREATE, response: created },
        { request: START, response: refusedStart },
      ],
      { onStartFailure: "keep" },
    );
    expect(requests).toEqual(["POST /sandboxes", `POST /sandboxes/${SBX}/start`]);
    expect(error).toBeInstanceOf(sdk.SandboxStartError);
    expect(error).toMatchObject({ sandboxId: SBX, cleanup: "kept", code: "STATE_CONFLICT", destroyError: undefined });
    expect((error as Error).message).toMatch(new RegExp(`^Sandbox ${SBX} was created and its start did not succeed; the sandbox was kept`));
  });

  it.each([
    ["is refused", [{ request: DESTROY, response: problem("PERMISSION_DENIED") }], sdk.PermissionDeniedError],
    ["ends without success", [{ request: DESTROY, response: answer(ended("sandbox.destroy", "FAILED", "NOT_APPLIED", "TIMEOUT")) }], sdk.OperationFailedError],
    ["ends unknown", [{ request: DESTROY, response: answer(ended("sandbox.destroy", "UNKNOWN", undefined, "UNKNOWN_OUTCOME")) }], sdk.OutcomeUnknownError],
    ["gets no answer", Array.from({ length: 3 }, () => ({ request: DESTROY, response: reset })), sdk.OutcomeUnresolvedError],
    ["is still running at the bound", [{ request: DESTROY, response: accepted(operationView({ operation_id: OP_DESTROY, type: "sandbox.destroy" }), 9) }], sdk.OperationStillRunningError],
  ] as const)("a destroy that %s is named too: the sandbox still exists", async (_what, exchanges, destroyClass) => {
    const { error } = await createFails([{ request: CREATE, response: created }, { request: START, response: refusedStart }, ...exchanges], {}, { followMax: 5 });
    expect(error).toBeInstanceOf(sdk.SandboxStartError);
    const failed = error as sdk.SandboxStartError;
    expect(failed).toMatchObject({ sandboxId: SBX, cleanup: "destroy_failed", code: "STATE_CONFLICT" });
    expect(failed.startError).toBeInstanceOf(sdk.StateConflictError);
    expect(failed.destroyError).toBeInstanceOf(destroyClass);
    expect(failed.message).toMatch(/destroying it did not succeed either, so the sandbox still exists/);
  });

  it("an unresolved destroy carries the derived key to ask again with", async () => {
    const { error } = await createFails([
      { request: CREATE, response: created },
      { request: START, response: refusedStart },
      ...Array.from({ length: 3 }, () => ({ request: DESTROY, response: reset })),
    ]);
    expect((error as sdk.SandboxStartError).destroyError).toMatchObject({ idempotencyKey: "k1:destroy" });
  });

  it("a destroy that succeeded counts as destroyed even when its answer carries no view of the sandbox", async () => {
    const recorded = answer(operationView({ operation_id: OP_DESTROY, type: "sandbox.destroy", state: "SUCCEEDED", terminal: true, effect: "APPLIED", recorded: true }));
    const { error } = await createFails([
      { request: CREATE, response: created },
      { request: START, response: refusedStart },
      { request: DESTROY, response: recorded },
    ]);
    expect(error).toMatchObject({ cleanup: "destroyed" });
  });
});

describe("when it is not known that the start failed", () => {
  it.each([
    ["is still running at the bound", [{ request: START, response: accepted(operationView({ operation_id: OP_START, type: "sandbox.start" }), 9) }], sdk.OperationStillRunningError],
    ["gets no answer", Array.from({ length: 3 }, () => ({ request: START, response: reset })), sdk.OutcomeUnresolvedError],
    ["stays in progress on the platform", Array.from({ length: 3 }, () => ({ request: START, response: problem("REQUEST_IN_PROGRESS", { key: "k1:start", retryAfter: 1 }) })), sdk.RequestInProgressError],
    ["is lost", [{ request: START, response: problem("OUTCOME_LOST", { key: "k1:start" }) }], sdk.OutcomeLostError],
    ["is answered by something that is not the platform", [{ request: START, response: { status: 302, headers: { location: "https://elsewhere.example/" }, text: "" } }], sdk.UnexpectedResponseError],
  ] as const)("a start that %s throws its own error and leaves the sandbox alone, whatever the policy", async (_what, exchanges, errorClass) => {
    for (const onStartFailure of ["destroy", "keep"] as const) {
      const { error, requests } = await createFails([{ request: CREATE, response: created }, ...exchanges], { onStartFailure }, { followMax: 5 });
      expect(error).toBeInstanceOf(errorClass);
      expect(error).not.toBeInstanceOf(sdk.SandboxStartError);
      expect(requests.filter((request) => request.startsWith("DELETE"))).toEqual([]);
    }
  });

  it("the error of a start that is still running or unresolved carries the start's key", async () => {
    const running = await createFails(
      [
        { request: CREATE, response: created },
        { request: START, response: accepted(operationView({ operation_id: OP_START, type: "sandbox.start" }), 9) },
      ],
      {},
      { followMax: 5 },
    );
    expect(running.error).toMatchObject({ idempotencyKey: "k1:start", operationId: OP_START });
  });
});
