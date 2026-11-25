/**
 * Following an operation to its end, and what each end means for the call that started it.
 */

import { describe, expect, it } from "vitest";

import * as sdk from "../src/index.js";
import type { FabricOptions } from "../src/index.js";
import {
  accepted,
  answer,
  ended,
  type Exchange,
  EXE,
  executionView,
  failure,
  get,
  type Json,
  operationView,
  P,
  post,
  problem,
  REQ,
  sandboxView,
  SBX,
  scripted,
  succeeded,
  value,
} from "./support/harness.js";

const OP_EXEC = `op-${"c".repeat(32)}`;
const EXEC = post(`${P}/sandboxes/${SBX}/executions`, { expected_generation: 2, argv: ["true"] }, "$KEY");
const FOLLOW = `${P}/operations/${OP_EXEC}`;
const TARGET = { sandbox_id: SBX, generation: 2, execution_id: EXE };
const running = (over: Json = {}): Json => operationView({ operation_id: OP_EXEC, type: "execution.create", state: "IN_PROGRESS", target: TARGET, ...over });
const done = (over: Json = {}): Json => succeeded("execution.create", { execution: executionView() }, { operation_id: OP_EXEC, target: TARGET, ...over });

/** A handle on a sandbox in generation 2, and a script that continues after the read that made it. */
async function sandbox(exchanges: Exchange[], options: FabricOptions = {}, key?: string) {
  const made = scripted([{ request: get(`${P}/sandboxes/${SBX}`), response: answer(sandboxView({ generation: 2, state: "RUNNING" })) }, ...exchanges], options, key);
  return { ...made, handle: await value(() => made.fabric.sandboxes.get(SBX)) };
}

describe("following", () => {
  it("waits Retry-After when the answer carried it", async () => {
    const { handle, time } = await sandbox([
      { request: EXEC, response: accepted(running(), 2) },
      { request: get(FOLLOW, { wait: "30" }), response: answer(running(), 200, { "retry-after": "7" }) },
      { request: get(FOLLOW, { wait: "30" }), response: answer(done()) },
    ]);
    await value(() => handle.exec(["true"]));
    expect(time.waits).toEqual([2, 7]);
  });

  it("backs off from 0.5 s, doubling, capped at 5 s, when no answer carries Retry-After", async () => {
    const { handle, time } = await sandbox([
      { request: EXEC, response: accepted(running(), null) },
      ...Array.from({ length: 6 }, () => ({ request: get(FOLLOW, { wait: "30" }), response: answer(running()) })),
      { request: get(FOLLOW, { wait: "30" }), response: answer(done()) },
    ]);
    await value(() => handle.exec(["true"]));
    expect(time.waits).toEqual([0.5, 1, 2, 4, 5, 5, 5]);
  });

  it("reads with wait = the smaller of 30 and the whole seconds left before the bound", async () => {
    const { handle } = await sandbox(
      [
        { request: EXEC, response: accepted(running(), 40) },
        { request: get(FOLLOW, { wait: "30" }), response: answer(running(), 200, { "retry-after": "40" }) },
        { request: get(FOLLOW, { wait: "20" }), response: answer(running(), 200, { "retry-after": "10" }) },
        { request: get(FOLLOW, { wait: "10" }), response: answer(running(), 200, { "retry-after": "9" }) },
        { request: get(FOLLOW, { wait: "1" }), response: answer(done()) },
      ],
      { followMax: 100.9 },
    );
    await value(() => handle.exec(["true"]));
  });

  it("stops when the next wait would reach the bound, and reports the operation as still running", async () => {
    const latest = running({ state: "RECOVERING" });
    const { handle, script, time } = await sandbox(
      [
        { request: EXEC, response: accepted(running(), 4) },
        { request: get(FOLLOW, { wait: "6" }), response: answer(latest, 200, { "retry-after": "6" }) },
      ],
      { followMax: 10 },
    );
    const error = await failure(() => handle.exec(["true"]));
    expect(error).toBeInstanceOf(sdk.OperationStillRunningError);
    const still = error as sdk.OperationStillRunningError;
    expect(still.operation.state).toBe("RECOVERING");
    expect(still.operationId).toBe(OP_EXEC);
    expect(still.idempotencyKey).toBe(script.key);
    expect(still.idempotencyKey).toMatch(/^[0-9a-f-]{36}$/);
    expect(still.code).toBeUndefined();
    expect(still.requestId).toBe(REQ);
    expect(still.message).toContain(`operations.wait("${OP_EXEC}")`);
    expect(time.waits).toEqual([4]);
  });

  it("a bound of zero follows nothing: an operation that has not ended is still running", async () => {
    const { handle, time } = await sandbox([{ request: EXEC, response: accepted(running(), 1) }]);
    expect(await failure(() => handle.exec(["true"], { followMax: 0 }))).toBeInstanceOf(sdk.OperationStillRunningError);
    expect(time.waits).toEqual([]);
  });

  it.each([
    [0, "0"],
    [0.9, "0"],
    [1, "1"],
    [5.9, "5"],
    [29.99, "29"],
  ])("a bound of %s s is shorter than the platform's own wait, so the mutation says wait=%s", async (bound, said) => {
    // A mutation that names no wait is held for 30 seconds: a shorter bound would be spent on the first answer.
    const { handle, time } = await sandbox([{ request: { ...EXEC, query: { wait: said } }, response: accepted(running(), 60) }]);
    expect(await failure(() => handle.exec(["true"], { followMax: bound }))).toBeInstanceOf(sdk.OperationStillRunningError);
    expect(time.waits).toEqual([]);
  });

  it.each([[30], [30.5], [1800], [undefined]])("a bound of %s s leaves the wait to the platform", async (bound) => {
    const { handle, script } = await sandbox([{ request: EXEC, response: answer(done()) }]);
    await value(() => handle.exec(["true"], bound === undefined ? {} : { followMax: bound }));
    expect(script.received.at(-1)?.query).toEqual({});
  });

  it("the wait said to the platform is the same on every attempt: a retry is the same request", async () => {
    const short = { ...EXEC, query: { wait: "3" } };
    const { handle } = await sandbox([
      { request: short, response: { fault: "connection_reset" } },
      { request: short, response: answer(done()) },
    ]);
    await value(() => handle.exec(["true"], { followMax: 3 }));
  });

  it("the bound of a call replaces the client's", async () => {
    const { handle } = await sandbox(
      [
        { request: EXEC, response: accepted(running(), 1) },
        { request: get(FOLLOW, { wait: "2" }), response: answer(running(), 200, { "retry-after": "2" }) },
      ],
      { followMax: 1800 },
    );
    expect(await failure(() => handle.exec(["true"], { followMax: 3 }))).toBeInstanceOf(sdk.OperationStillRunningError);
  });

  it("the bound is on the following, not on the request that started the operation", async () => {
    // The first attempt is refused and retried after 3 s. The following then has its whole 5 s.
    const { handle } = await sandbox(
      [
        { request: EXEC, response: problem("RATE_LIMITED", { retryAfter: 3 }) },
        { request: EXEC, response: accepted(running(), 1) },
        { request: get(FOLLOW, { wait: "4" }), response: answer(done()) },
      ],
      { followMax: 5 },
    );
    await value(() => handle.exec(["true"]));
  });

  it("decides from the state: one it has never seen is not an end, whatever the answer says about it", async () => {
    const { handle } = await sandbox([
      { request: EXEC, response: answer(running({ state: "ARCHIVED", terminal: true })) },
      { request: get(FOLLOW, { wait: "30" }), response: answer(running({ state: "UNRECOGNIZED", state_raw: "PARKED" })) },
      { request: get(FOLLOW, { wait: "30" }), response: answer(done()) },
    ]);
    const execution = await value(() => handle.exec(["true"]));
    expect(execution.execution_id).toBe(EXE);
  });

  it("a state it knows as an end is an end, in a 202 too", async () => {
    const { handle } = await sandbox([{ request: EXEC, response: accepted(done({ terminal: false })) }]);
    await value(() => handle.exec(["true"]));
  });

  it("follows at the operation's identifier on the configured endpoint, never at the Location the answer names", async () => {
    const elsewhere = answer(running(), 202, { location: "https://elsewhere.example/v1/projects/x/operations/y", "retry-after": "1" });
    const { handle, script } = await sandbox([
      { request: EXEC, response: elsewhere },
      { request: get(FOLLOW, { wait: "30" }), response: answer(done()) },
    ]);
    await value(() => handle.exec(["true"]));
    expect(new Set(script.received.map((request) => request.origin))).toEqual(new Set(["https://acf.example"]));
  });

  it("a read of the operation that is refused for now is repeated, and one that is refused for good ends the call", async () => {
    const recovered = await sandbox([
      { request: EXEC, response: accepted(running(), 1) },
      { request: get(FOLLOW), response: problem("UPSTREAM_UNAVAILABLE", { retryAfter: 1 }) },
      { request: get(FOLLOW), response: answer(done()) },
    ]);
    await value(() => recovered.handle.exec(["true"]));

    const gone = await sandbox([
      { request: EXEC, response: accepted(running(), 1) },
      { request: get(FOLLOW), response: problem("NOT_FOUND") },
    ]);
    expect(await failure(() => gone.handle.exec(["true"]))).toBeInstanceOf(sdk.NotFoundError);
  });

  it("the handle a call returns names the operation that produced it, and whether the answer was a replay", async () => {
    const fresh = await sandbox([{ request: EXEC, response: answer(done()) }]);
    const first = await value(() => fresh.handle.exec(["true"]));
    expect(first.operation?.operation_id).toBe(OP_EXEC);
    expect(first.operation?.replayed).toBe(false);
    expect(first.requestId).toBe(REQ);

    const again = await sandbox([{ request: EXEC, response: answer(done({ replayed: true }), 200, { "idempotent-replayed": "true" }) }]);
    const second = await value(() => again.handle.exec(["true"]));
    expect(second.operation?.replayed).toBe(true);
  });
});

describe("how an operation ended", () => {
  it("SUCCEEDED returns the resource of the result; a command that exits with another status than 0 is a result", async () => {
    const result = { execution: executionView({ exit_code: 3 }) };
    const { handle } = await sandbox([{ request: EXEC, response: answer(succeeded("execution.create", result, { operation_id: OP_EXEC })) }]);
    const execution = await value(() => handle.exec(["true"]));
    expect(execution.exit_code).toBe(3);
    expect(execution.status).toBe("EXITED");
  });

  it.each([
    ["FAILED", "NOT_APPLIED", "DEPENDENCY_UNAVAILABLE"],
    ["CANCELLED", "NOT_APPLIED", "TIMEOUT"],
  ])("%s with effect %s is a failure: nothing was applied", async (state, effect, code) => {
    const { handle } = await sandbox([{ request: EXEC, response: answer(ended("execution.create", state, effect, code, { operation_id: OP_EXEC })) }], {}, "exec-1");
    const error = await failure(() => handle.exec(["true"], { idempotencyKey: "exec-1" }));
    expect(error).toBeInstanceOf(sdk.OperationFailedError);
    expect(error).toMatchObject({ code, operationId: OP_EXEC, idempotencyKey: "exec-1", requestId: REQ });
    expect((error as sdk.OperationFailedError).operation.state).toBe(state);
    expect((error as Error).message).toContain(`The message of ${code}`);
  });

  it.each([
    ["UNKNOWN", "MAY_BE_APPLIED", "UNKNOWN_OUTCOME"],
    ["UNKNOWN", "NOT_APPLIED", "UNKNOWN_OUTCOME"],
    ["UNKNOWN", undefined, "UNKNOWN_OUTCOME"],
    ["FAILED", "MAY_BE_APPLIED", "TIMEOUT"],
    ["FAILED", "APPLIED", "PARTIAL_COMPLETION"],
    ["FAILED", "UNRECOGNIZED", "SECURITY_CONTROL_FAILURE"],
    ["FAILED", "HALF_APPLIED", "TIMEOUT"],
    ["FAILED", undefined, "TIMEOUT"],
    ["CANCELLED", "MAY_BE_APPLIED", "TIMEOUT"],
    ["CANCELLED", undefined, "TIMEOUT"],
  ])("%s with effect %s is unknown: never success, never a clean failure", async (state, effect, code) => {
    const { handle } = await sandbox([{ request: EXEC, response: answer(ended("execution.create", state, effect, code, { operation_id: OP_EXEC })) }]);
    const error = await failure(() => handle.exec(["true"]));
    expect(error).toBeInstanceOf(sdk.OutcomeUnknownError);
    expect(error).not.toBeInstanceOf(sdk.OperationFailedError);
    expect(error).toMatchObject({ code, operationId: OP_EXEC });
    expect((error as Error).message).toMatch(/Inspect the target before acting again/);
  });

  it("an operation that ended without naming a failure is still reported, with no code", async () => {
    const bare = operationView({ operation_id: OP_EXEC, type: "execution.create", state: "FAILED", terminal: true, effect: "NOT_APPLIED" });
    const { handle } = await sandbox([{ request: EXEC, response: answer(bare) }]);
    const error = await failure(() => handle.exec(["true"]));
    expect(error).toBeInstanceOf(sdk.OperationFailedError);
    expect((error as sdk.OperationFailedError).code).toBeUndefined();
  });

  it("a success that carries no result cannot be returned, and is not passed off as a failure of the operation", async () => {
    const recorded = operationView({ operation_id: OP_EXEC, type: "execution.create", state: "SUCCEEDED", terminal: true, effect: "APPLIED", recorded: true, target: TARGET });
    const { handle } = await sandbox([{ request: EXEC, response: answer(recorded) }]);
    const error = await failure(() => handle.exec(["true"]));
    expect(error).toBeInstanceOf(sdk.UnexpectedResponseError);
    expect(error).not.toBeInstanceOf(sdk.OperationError);
    expect((error as Error).message).toMatch(/succeeded, and its answer carries no execution: the platform shows a recorded outcome/);
  });

  it("an answer that is not an operation cannot be followed", async () => {
    const { handle } = await sandbox([{ request: EXEC, response: answer({ state: "SUCCEEDED" }) }]);
    const error = await failure(() => handle.exec(["true"]));
    expect(error).toBeInstanceOf(sdk.UnexpectedResponseError);
    expect((error as Error).message).toBe("An operation has no operation_id.");
  });
});

describe("operations", () => {
  const PATH = `${P}/operations/${OP_EXEC}`;

  it("get reads once, and passes wait only when the caller set it", async () => {
    const { fabric, script } = scripted([
      { request: get(PATH), response: answer(running()) },
      { request: get(PATH, { wait: "12" }), response: answer(running()) },
      { request: get(PATH, { wait: "0" }), response: answer(running()) },
    ]);
    const operation = await value(() => fabric.operations.get(OP_EXEC));
    expect(operation.state).toBe("IN_PROGRESS");
    expect(script.received[0]?.query).toEqual({});
    await value(() => fabric.operations.get(OP_EXEC, { wait: 12 }));
    await value(() => fabric.operations.get(OP_EXEC, { wait: 0 }));
  });

  it.each([
    [{ wait: -1 }, RangeError],
    [{ wait: 1.5 }, RangeError],
    [{ wait: "30" }, TypeError],
    [{ followMax: 10 }, TypeError],
  ])("get refuses %j before any request", async (options, errorClass) => {
    const { fabric } = scripted([]);
    expect(await failure(() => fabric.operations.get(OP_EXEC, options as never))).toBeInstanceOf(errorClass);
  });

  it("wait follows to the end and returns the operation however it ended", async () => {
    const failed = ended("execution.create", "FAILED", "NOT_APPLIED", "TIMEOUT", { operation_id: OP_EXEC });
    const { fabric, time } = scripted([
      { request: get(PATH, { wait: "30" }), response: answer(running(), 200, { "retry-after": "2" }) },
      { request: get(PATH, { wait: "30" }), response: answer(failed) },
    ]);
    const operation = await value(() => fabric.operations.wait(OP_EXEC));
    expect(operation.state).toBe("FAILED");
    expect(operation.failure?.code).toBe("TIMEOUT");
    expect(time.waits).toEqual([2]);
  });

  it("wait reports an operation that outlasts the bound as still running, and names no key: this call requested nothing", async () => {
    const { fabric } = scripted(
      [
        { request: get(PATH, { wait: "5" }), response: answer(running(), 200, { "retry-after": "3" }) },
        { request: get(PATH, { wait: "2" }), response: answer(running(), 200, { "retry-after": "3" }) },
      ],
      { followMax: 1800 },
    );
    const error = await failure(() => fabric.operations.wait(OP_EXEC, { followMax: 5.5 }));
    expect(error).toBeInstanceOf(sdk.OperationStillRunningError);
    expect(error).toMatchObject({ operationId: OP_EXEC, idempotencyKey: undefined });
  });

  it("list follows cursors to the end", async () => {
    const { fabric } = scripted([
      { request: get(`${P}/operations`), response: answer({ items: [running()], more: true, next_cursor: "c1" }) },
      { request: get(`${P}/operations`, { cursor: "c1" }), response: answer({ items: [done({ operation_id: "op-22222222" })], more: false, next_cursor: "c2" }) },
    ]);
    const operations: sdk.Operation[] = [];
    for await (const operation of fabric.operations.list()) {
      operations.push(operation);
    }
    expect(operations.map((operation) => operation.operation_id)).toEqual([OP_EXEC, "op-22222222"]);
  });
});
