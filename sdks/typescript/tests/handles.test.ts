/**
 * Handles: what a sandbox, a snapshot and an execution send, what they keep, and what they refuse
 * to guess.
 */

import { describe, expect, it } from "vitest";

import * as sdk from "../src/index.js";
import {
  answer,
  del,
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
  SBX2,
  scripted,
  SNP,
  snapshotView,
  succeeded,
  value,
  type Exchange,
} from "./support/harness.js";

const READ = get(`${P}/sandboxes/${SBX}`);
const sandboxAt = (generation: number, over: Json = {}): Json => sandboxView({ generation, state: "RUNNING", ...over });
const result = (type: string, view: Json) => answer(succeeded(type, { sandbox: view }));

/** A handle on the sandbox, read at `generation`, and a script that continues after that read. */
async function handleAt(generation: number, exchanges: Exchange[], key?: string) {
  const made = scripted([{ request: READ, response: answer(sandboxAt(generation), 200, { etag: '"r11.0123456789ab"' }) }, ...exchanges], {}, key);
  return { ...made, handle: await value(() => made.fabric.sandboxes.get(SBX)) };
}

describe("a handle made without a read", () => {
  it("makes no request, holds the identifier, and names the generation its caller names", async () => {
    const { fabric, script } = scripted([
      { request: post(`${P}/sandboxes/${SBX}/executions`, { expected_generation: 7, argv: ["true"] }), response: answer(succeeded("execution.create", { execution: executionView() })) },
      { request: post(`${P}/sandboxes/${SBX}/stop`, { expected_generation: "current" }), response: result("sandbox.stop", sandboxAt(7, { state: "STOPPED" })) },
    ]);
    const handle = fabric.sandboxes.handle(SBX);
    expect(script.received).toEqual([]);
    expect(handle.sandbox_id).toBe(SBX);
    await value(() => handle.exec(["true"], { generation: 7 }));
    await value(() => handle.stop({ generation: "current" }));
    // The answer showed the sandbox: from here on the handle states what it saw.
    expect(handle.generation).toBe(7);
    expect(handle.state).toBe("STOPPED");
  });

  it("has seen no generation: a mutation that names none is refused before any request", async () => {
    const { fabric, script } = scripted([]);
    const handle = fabric.sandboxes.handle(SBX);
    for (const act of [() => handle.start(), () => handle.exec(["true"]), () => handle.snapshot(), () => handle.stop(), () => handle.destroy()]) {
      const refused = await failure(act);
      expect(refused).toBeInstanceOf(RangeError);
      expect(String(refused)).toContain("has not seen a generation");
    }
    expect(script.received).toEqual([]);
  });

  it("states the generation it reads once it has read", async () => {
    const { fabric } = scripted([
      { request: READ, response: answer(sandboxAt(4)) },
      { request: post(`${P}/sandboxes/${SBX}/start`, { expected_generation: 4 }), response: result("sandbox.start", sandboxAt(4)) },
    ]);
    const handle = fabric.sandboxes.handle(SBX);
    await value(() => handle.refresh());
    await value(() => handle.start());
  });

  it.each(["", ".", "..", "a/b"])("refuses the identifier %j before it can become a path", (bad) => {
    const { fabric } = scripted([]);
    if (bad === "a/b") {
      // A separator is escaped, never refused: it cannot end the segment it is in.
      expect(fabric.sandboxes.handle(bad).sandbox_id).toBe(bad);
    } else {
      expect(() => fabric.sandboxes.handle(bad)).toThrow();
    }
  });
});

describe("a sandbox handle states the generation it saw", () => {
  it("in every mutation", async () => {
    const snapshot = snapshotView();
    const { handle } = await handleAt(5, [
      { request: post(`${P}/sandboxes/${SBX}/start`, { expected_generation: 5 }), response: result("sandbox.start", sandboxAt(5)) },
      { request: post(`${P}/sandboxes/${SBX}/executions`, { expected_generation: 5, argv: ["true"] }), response: answer(succeeded("execution.create", { execution: executionView() })) },
      { request: post(`${P}/sandboxes/${SBX}/snapshots`, { expected_generation: 5, name: "baseline" }), response: answer(succeeded("snapshot.create", { snapshot })) },
      { request: post(`${P}/sandboxes/${SBX}/stop`, { expected_generation: 5 }), response: result("sandbox.stop", sandboxAt(5, { state: "STOPPED" })) },
      { request: del(`${P}/sandboxes/${SBX}`, { expected_generation: "5" }), response: result("sandbox.destroy", sandboxAt(5, { state: "DESTROYED" })) },
    ]);
    await value(() => handle.start());
    await value(() => handle.exec(["true"]));
    const taken = await value(() => handle.snapshot("baseline"));
    expect(taken.snapshot_id).toBe(SNP);
    await value(() => handle.stop());
    await value(() => handle.destroy());
    expect(handle.state).toBe("DESTROYED");
  });

  it("and updates itself from the answer: after a restore it states the new generation", async () => {
    const snapshot = snapshotView({ snapshot_generation: 3 });
    const restoreBody = { snapshot_generation: 3, target: { kind: "existing", sandbox_id: SBX, expected_generation: 5 } };
    const { handle, fabric } = await handleAt(5, [
      { request: get(`${P}/snapshots`), response: answer({ items: [snapshot], more: false, next_cursor: "end" }) },
      { request: post(`${P}/snapshots/${SNP}/restore`, restoreBody), response: result("snapshot.restore", sandboxAt(6, { source_snapshot: { snapshot_id: SNP, snapshot_generation: 3 } })) },
      { request: post(`${P}/sandboxes/${SBX}/stop`, { expected_generation: 6 }), response: result("sandbox.stop", sandboxAt(6, { state: "STOPPED" })) },
    ]);
    const baseline = await value(() => fabric.snapshots.get(SNP));
    const restored = await value(() => handle.restore(baseline));
    // The same handle, changed in place: the sandbox is the same sandbox, in a new generation.
    expect(restored).toBe(handle);
    expect(handle.generation).toBe(6);
    expect(handle.source_snapshot).toEqual({ snapshot_id: SNP, snapshot_generation: 3 });
    expect(handle.operation?.type).toBe("snapshot.restore");
    await value(() => handle.stop());
  });

  it('sends "current" only when the caller writes it, and the caller\'s number when the caller writes one', async () => {
    const { handle } = await handleAt(5, [
      { request: post(`${P}/sandboxes/${SBX}/stop`, { expected_generation: "current" }), response: result("sandbox.stop", sandboxAt(9, { state: "STOPPED" })) },
      { request: post(`${P}/sandboxes/${SBX}/start`, { expected_generation: 2 }), response: result("sandbox.start", sandboxAt(9)) },
      { request: del(`${P}/sandboxes/${SBX}`, { expected_generation: "current" }), response: result("sandbox.destroy", sandboxAt(9, { state: "DESTROYED" })) },
    ]);
    await value(() => handle.stop({ generation: "current" }));
    expect(handle.generation).toBe(9);
    await value(() => handle.start({ generation: 2 }));
    await value(() => handle.destroy({ generation: "current" }));
  });

  it("surfaces REVISION_CONFLICT and leaves the decision to the caller: refresh, then act again", async () => {
    const { handle } = await handleAt(5, [
      { request: post(`${P}/sandboxes/${SBX}/executions`, { expected_generation: 5, argv: ["true"] }), response: problem("REVISION_CONFLICT") },
      { request: READ, response: answer(sandboxAt(6)) },
      { request: post(`${P}/sandboxes/${SBX}/executions`, { expected_generation: 6, argv: ["true"] }), response: answer(succeeded("execution.create", { execution: executionView({ generation: 6 }) })) },
    ]);
    const conflict = await failure(() => handle.exec(["true"]));
    expect(conflict).toBeInstanceOf(sdk.RevisionConflictError);
    expect(conflict).toMatchObject({ code: "REVISION_CONFLICT", status: 412, retry: "AFTER_CHANGE" });
    expect(handle.generation).toBe(5);
    await value(() => handle.refresh());
    expect(handle.generation).toBe(6);
    expect(handle.operation).toBeUndefined();
    await value(() => handle.exec(["true"]));
  });

  it("a snapshot without a name sends no name", async () => {
    const { handle, script } = await handleAt(5, [
      { request: post(`${P}/sandboxes/${SBX}/snapshots`, { expected_generation: 5 }), response: answer(succeeded("snapshot.create", { snapshot: snapshotView() })) },
    ]);
    const snapshot = await value(() => handle.snapshot());
    expect(snapshot.name).toBeNull();
    expect(snapshot.operation?.type).toBe("snapshot.create");
    expect(script.received[1]?.body).toBe('{"expected_generation":5}');
  });

  it("restore takes a snapshot handle and nothing else: the generation of the snapshot is not something to guess", async () => {
    const { handle, script } = await handleAt(5, []);
    expect(await failure(() => handle.restore(SNP as never))).toBeInstanceOf(TypeError);
    expect(await failure(() => handle.restore({ snapshot_id: SNP, snapshot_generation: 1 } as never))).toBeInstanceOf(TypeError);
    expect(script.received).toHaveLength(1);
  });

  it("refuses an answer about another sandbox rather than become it", async () => {
    const { handle } = await handleAt(5, [
      { request: post(`${P}/sandboxes/${SBX}/stop`, { expected_generation: 5 }), response: result("sandbox.stop", sandboxAt(5, { sandbox_id: SBX2 })) },
    ]);
    const error = await failure(() => handle.stop());
    expect(error).toBeInstanceOf(sdk.UnexpectedResponseError);
    expect(handle.sandbox_id).toBe(SBX);
  });
});

describe("a name is resolved once", () => {
  const BY_NAME = get(`${P}/sandboxes/web`);
  const named = (id: string, over: Json = {}): Json => sandboxView({ sandbox_id: id, name: "web", generation: 2, ...over });

  it("the handle acts on the identifier the name belonged to, never on the name", async () => {
    const { fabric, script } = scripted([
      { request: BY_NAME, response: answer(named(SBX)) },
      { request: post(`${P}/sandboxes/${SBX}/stop`, { expected_generation: 2 }), response: result("sandbox.stop", named(SBX, { state: "STOPPED" })) },
      { request: del(`${P}/sandboxes/${SBX}`, { expected_generation: "2" }), response: result("sandbox.destroy", named(SBX, { state: "DESTROYED" })) },
    ]);
    const handle = await value(() => fabric.sandboxes.get("web"));
    expect(handle.sandbox_id).toBe(SBX);
    await value(() => handle.stop());
    await value(() => handle.destroy());
    expect(script.received.slice(1).every((request) => !request.path.includes("/web"))).toBe(true);
  });

  it("refresh reads by the name and updates the handle while the name still belongs to its sandbox", async () => {
    const { fabric } = scripted([
      { request: BY_NAME, response: answer(named(SBX)) },
      { request: BY_NAME, response: answer(named(SBX, { state: "STOPPED", generation: 3 })) },
    ]);
    const handle = await value(() => fabric.sandboxes.get("web"));
    await value(() => handle.refresh());
    expect(handle).toMatchObject({ sandbox_id: SBX, state: "STOPPED", generation: 3 });
  });

  it("refresh throws NameReboundError when the name now belongs to another sandbox, and leaves the handle as it was", async () => {
    const { fabric } = scripted([
      { request: BY_NAME, response: answer(named(SBX)) },
      { request: BY_NAME, response: answer(named(SBX2, { generation: 1 })) },
      { request: post(`${P}/sandboxes/${SBX}/stop`, { expected_generation: 2 }), response: result("sandbox.stop", named(SBX, { state: "STOPPED" })) },
    ]);
    const handle = await value(() => fabric.sandboxes.get("web"));
    const error = await failure(() => handle.refresh());
    expect(error).toBeInstanceOf(sdk.NameReboundError);
    expect(error).toMatchObject({ sandboxName: "web", sandboxId: SBX, reboundTo: SBX2, requestId: REQ });
    expect((error as Error).message).toContain("rebind: true");
    expect(handle).toMatchObject({ sandbox_id: SBX, generation: 2 });
    // The handle still acts on the sandbox it was obtained for.
    await value(() => handle.stop());
  });

  it("with rebind: true the handle becomes the sandbox the name belongs to now", async () => {
    const { fabric } = scripted([
      { request: BY_NAME, response: answer(named(SBX)) },
      { request: BY_NAME, response: answer(named(SBX2, { generation: 1 })) },
      { request: post(`${P}/sandboxes/${SBX2}/stop`, { expected_generation: 1 }), response: result("sandbox.stop", named(SBX2, { generation: 1, state: "STOPPED" })) },
      { request: BY_NAME, response: answer(named(SBX2, { generation: 1, state: "STOPPED" })) },
    ]);
    const handle = await value(() => fabric.sandboxes.get("web"));
    await value(() => handle.refresh({ rebind: true }));
    expect(handle).toMatchObject({ sandbox_id: SBX2, generation: 1 });
    await value(() => handle.stop());
    await value(() => handle.refresh());
  });

  it("a handle obtained by identifier reads by identifier", async () => {
    const { fabric } = scripted([
      { request: READ, response: answer(named(SBX)) },
      { request: READ, response: answer(named(SBX, { generation: 3 })) },
    ]);
    const handle = await value(() => fabric.sandboxes.get(SBX));
    await value(() => handle.refresh());
    expect(handle.generation).toBe(3);
  });

  it("refresh refuses a rebind that is not a flag", async () => {
    const { fabric, script } = scripted([{ request: BY_NAME, response: answer(named(SBX)) }]);
    const handle = await value(() => fabric.sandboxes.get("web"));
    expect(await failure(() => handle.refresh({ rebind: "yes" as never }))).toBeInstanceOf(TypeError);
    expect(script.received).toHaveLength(1);
  });

  it.each(["", ".", ".."])("get refuses %j before any request", async (reference) => {
    const { fabric, script } = scripted([]);
    expect(await failure(() => fabric.sandboxes.get(reference))).toBeInstanceOf(RangeError);
    expect(script.received).toEqual([]);
  });
});

describe("a snapshot handle", () => {
  const LISTED = { request: get(`${P}/snapshots`), response: answer({ items: [snapshotView({ snapshot_generation: 2, name: "baseline" })], more: false, next_cursor: "end" }) };

  it("restores as a new sandbox, with the members the caller set", async () => {
    const fresh = sandboxView({ sandbox_id: SBX2, name: "copy", source_snapshot: { snapshot_id: SNP, snapshot_generation: 2 } });
    const { fabric } = scripted([
      LISTED,
      { request: post(`${P}/snapshots/${SNP}/restore`, { snapshot_generation: 2, target: { kind: "new" } }), response: result("snapshot.restore", sandboxView({ sandbox_id: SBX2 })) },
      { request: post(`${P}/snapshots/${SNP}/restore`, { snapshot_generation: 2, target: { kind: "new", name: "copy", lifetime_seconds: 5400 } }), response: result("snapshot.restore", fresh) },
    ]);
    const snapshot = await value(() => fabric.snapshots.get("baseline"));
    const plain = await value(() => snapshot.restoreAsNew());
    expect(plain.sandbox_id).toBe(SBX2);
    const copy = await value(() => snapshot.restoreAsNew({ name: "copy", lifetime: "1.5h" }));
    expect(copy).toMatchObject({ sandbox_id: SBX2, name: "copy", generation: 1 });
    expect(copy.operation?.type).toBe("snapshot.restore");
  });

  it("deletes itself by identifier and generation, and shows the result", async () => {
    const { fabric } = scripted([
      LISTED,
      { request: del(`${P}/snapshots/${SNP}`, { snapshot_generation: "2" }), response: answer(succeeded("snapshot.delete", { snapshot: snapshotView({ snapshot_generation: 2, state: "DELETED" }) })) },
    ]);
    const snapshot = await value(() => fabric.snapshots.get("baseline"));
    const deleted = await value(() => snapshot.delete());
    expect(deleted).toBe(snapshot);
    expect(snapshot.state).toBe("DELETED");
  });

  it("refuses a lifetime it cannot convert, before any request", async () => {
    const { fabric, script } = scripted([LISTED]);
    const snapshot = await value(() => fabric.snapshots.get(SNP));
    expect(await failure(() => snapshot.restoreAsNew({ lifetime: "1.5s" }))).toBeInstanceOf(RangeError);
    expect(await failure(() => snapshot.delete({ generation: 2 } as never))).toBeInstanceOf(TypeError);
    expect(script.received).toHaveLength(1);
  });
});

describe("an execution handle", () => {
  const GET_EXECUTION = get(`${P}/executions/${EXE}`);
  const OUTPUT = `${P}/executions/${EXE}/output`;
  const base64 = (bytes: number[]): string => Buffer.from(bytes).toString("base64");
  const chunk = (bytes: number[], offset: number, eof: boolean, over: Json = {}): Json => ({
    execution_id: EXE,
    stream: "stdout",
    offset,
    data_base64: base64(bytes),
    next_offset: offset + bytes.length,
    eof,
    stored_bytes: 6,
    produced_bytes: 6,
    completeness: "COMPLETE",
    ...over,
  });

  async function execution(exchanges: Exchange[]) {
    const made = scripted([{ request: GET_EXECUTION, response: answer(executionView()) }, ...exchanges]);
    return { ...made, handle: await value(() => made.fabric.executions.get(EXE)) };
  }

  it("made without a read, it cancels at once: no read stands between a caller and stopping a command", async () => {
    const cancelled = succeeded("execution.cancel", { execution: executionView({ state: "CANCELLED", status: "CANCELLED", exit_code: null }) }, { operation_id: "op-cancel-0002" });
    const { fabric, script } = scripted([{ request: post(`${P}/executions/${EXE}/cancel`), response: answer(cancelled) }]);
    const handle = fabric.executions.handle(EXE);
    expect(script.received).toEqual([]);
    expect(handle.execution_id).toBe(EXE);
    expect(handle.raw).toEqual({ execution_id: EXE });
    expect(handle.requestId).toBeUndefined();
    expect(handle.operation).toBeUndefined();
    expect(await value(() => handle.cancel({ idempotencyKey: "stop-it" }))).toBe(handle);
    expect(script.received.map((request) => request.method)).toEqual(["POST"]);
    expect(script.received[0]?.headers["idempotency-key"]).toBe("stop-it");
    expect(handle.status).toBe("CANCELLED");
    expect(handle.operation?.operation_id).toBe("op-cancel-0002");
  });

  it("made without a read, it reads output and can be read itself", async () => {
    const { fabric } = scripted([
      { request: get(OUTPUT, { stream: "stdout", offset: "0" }), response: answer(chunk([104, 105], 0, true)) },
      { request: GET_EXECUTION, response: answer(executionView({ exit_code: 3 })) },
    ]);
    const handle = fabric.executions.handle(EXE);
    expect(await value(() => handle.read())).toEqual(new Uint8Array([104, 105]));
    await value(() => handle.refresh());
    expect(handle.exit_code).toBe(3);
    expect(handle.requestId).toBe(REQ);
  });

  it("made without a read, it does not take the answer about another execution", async () => {
    const other = succeeded("execution.cancel", { execution: executionView({ execution_id: "exe_00000000000000000099" }) });
    const { fabric } = scripted([{ request: post(`${P}/executions/${EXE}/cancel`), response: answer(other) }]);
    const handle = fabric.executions.handle(EXE);
    expect(await failure(() => handle.cancel())).toBeInstanceOf(sdk.UnexpectedResponseError);
    expect(handle.raw).toEqual({ execution_id: EXE });
  });

  it.each(["", ".", ".."])("is not made for %j, which cannot be an identifier", (bad) => {
    const { fabric, script } = scripted([]);
    expect(() => fabric.executions.handle(bad)).toThrow();
    expect(() => fabric.executions.handle(7 as never)).toThrow();
    expect(script.received).toEqual([]);
  });

  it("reads one slice: stdout from offset 0 unless the caller says otherwise", async () => {
    const { handle, script } = await execution([
      { request: get(OUTPUT, { stream: "stdout", offset: "0" }), response: answer(chunk([104, 105], 0, true)) },
      { request: get(OUTPUT, { stream: "stderr", offset: "4", max_bytes: "16" }), response: answer(chunk([33], 4, true, { stream: "stderr" })) },
    ]);
    const first = await value(() => handle.output());
    expect(first.data).toEqual(new Uint8Array([104, 105]));
    expect(first).toMatchObject({ next_offset: 2, eof: true, completeness: "COMPLETE", provenance: "GUEST_REPORTED", requestId: REQ });
    expect(script.received[1]?.query).toEqual({ stream: "stdout", offset: "0" });
    const second = await value(() => handle.output("stderr", { offset: 4, maxBytes: 16 }));
    expect(second.stream).toBe("stderr");
  });

  it("reads every chunk to the end, and gives the bytes back as they are", async () => {
    const all = Array.from({ length: 256 }, (_, byte) => byte);
    const { handle } = await execution([
      { request: get(OUTPUT, { stream: "stdout", offset: "0" }), response: answer(chunk(all.slice(0, 100), 0, false)) },
      { request: get(OUTPUT, { stream: "stdout", offset: "100" }), response: answer(chunk(all.slice(100, 255), 100, false)) },
      { request: get(OUTPUT, { stream: "stdout", offset: "255" }), response: answer(chunk(all.slice(255), 255, true)) },
    ]);
    const bytes = await value(() => handle.read());
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect([...bytes]).toEqual(all);
  });

  it("an empty stream is no bytes", async () => {
    const { handle } = await execution([{ request: get(OUTPUT, { stream: "stderr", offset: "0" }), response: answer(chunk([], 0, true, { stream: "stderr" })) }]);
    expect(await value(() => handle.read("stderr"))).toEqual(new Uint8Array());
  });

  it("decodes text as UTF-8, strictly, unless the caller names another encoding or policy", async () => {
    const euro = [0xe2, 0x82, 0xac];
    const broken = [0x68, 0xff, 0x69];
    const { handle } = await execution([
      { request: get(OUTPUT, { stream: "stdout", offset: "0" }), response: answer(chunk(euro, 0, true)) },
      { request: get(OUTPUT, { stream: "stdout", offset: "0" }), response: answer(chunk(broken, 0, true)) },
      { request: get(OUTPUT, { stream: "stdout", offset: "0" }), response: answer(chunk(broken, 0, true)) },
      { request: get(OUTPUT, { stream: "stdout", offset: "0" }), response: answer(chunk(broken, 0, true)) },
    ]);
    expect(await value(() => handle.text())).toBe("€");
    // Bytes that are not UTF-8: strict throws, replace substitutes, another encoding reads them its way.
    expect(await failure(() => handle.text())).toBeInstanceOf(TypeError);
    expect(await value(() => handle.text("stdout", { errors: "replace" }))).toBe("h�i");
    expect(await value(() => handle.text("stdout", { encoding: "latin1" }))).toBe("hÿi");
  });

  it("keeps a byte-order mark: the text is the bytes, decoded", async () => {
    const { handle } = await execution([{ request: get(OUTPUT, { stream: "stdout", offset: "0" }), response: answer(chunk([0xef, 0xbb, 0xbf, 0x68], 0, true)) }]);
    expect(await value(() => handle.text())).toBe("\uFEFFh");
  });

  it.each([
    ["an encoding the runtime cannot decode", () => ({ encoding: "klingon" }), RangeError],
    ["an error policy it does not have", () => ({ errors: "ignore" }), RangeError],
    ["an encoding that is not text", () => ({ encoding: 8 }), TypeError],
    ["an unknown option", () => ({ charset: "utf-8" }), TypeError],
  ])("text refuses %s before any request", async (_what, options, errorClass) => {
    const { handle, script } = await execution([]);
    expect(await failure(() => handle.text("stdout", options() as never))).toBeInstanceOf(errorClass);
    expect(script.received).toHaveLength(1);
  });

  it.each([
    ["a stream that is not stdout or stderr", (handle: sdk.Execution) => handle.output("stdin" as never), RangeError],
    ["an offset below zero", (handle: sdk.Execution) => handle.output("stdout", { offset: -1 }), RangeError],
    ["a size of zero", (handle: sdk.Execution) => handle.output("stdout", { maxBytes: 0 }), RangeError],
    ["an offset that is not a number", (handle: sdk.Execution) => handle.output("stdout", { offset: "0" as never }), TypeError],
    ["options in the place of the stream", (handle: sdk.Execution) => handle.read({ signal: undefined } as never), TypeError],
  ])("output refuses %s before any request", async (_what, call, errorClass) => {
    const { handle, script } = await execution([]);
    expect(await failure(() => call(handle))).toBeInstanceOf(errorClass);
    expect(script.received).toHaveLength(1);
  });

  it("refuses output it cannot read rather than loop or guess", async () => {
    const stuck = await execution([
      { request: get(OUTPUT, { stream: "stdout", offset: "0" }), response: answer(chunk([1, 2], 0, false)) },
      { request: get(OUTPUT, { stream: "stdout", offset: "2" }), response: answer(chunk([], 2, false)) },
    ]);
    const looping = await failure(() => stuck.handle.read());
    expect(looping).toBeInstanceOf(sdk.UnexpectedResponseError);
    expect((looping as Error).message).toMatch(/does not advance past offset 2/);

    const garbled = await execution([{ request: get(OUTPUT), response: answer(chunk([1], 0, true, { data_base64: "not base64 !!" })) }]);
    expect(await failure(() => garbled.handle.output())).toBeInstanceOf(sdk.UnexpectedResponseError);

    const silent = await execution([{ request: get(OUTPUT), response: answer({ execution_id: EXE, data_base64: "", next_offset: 0 }) }]);
    expect(await failure(() => silent.handle.output())).toBeInstanceOf(sdk.UnexpectedResponseError);
  });

  it("is cancelled only by the call that says so: a keyed request without a body, followed like any other", async () => {
    const cancelling = operationView({ operation_id: "op-cancel-0001", type: "execution.cancel", target: { execution_id: EXE } });
    const cancelled = succeeded("execution.cancel", { execution: executionView({ state: "CANCELLED", status: "CANCELLED", exit_code: null }) }, { operation_id: "op-cancel-0001" });
    const { handle, script } = await execution([
      { request: post(`${P}/executions/${EXE}/cancel`), response: answer(cancelling, 202, { "retry-after": "1" }) },
      { request: get(`${P}/operations/op-cancel-0001`, { wait: "30" }), response: answer(cancelled) },
    ]);
    const returned = await value(() => handle.cancel());
    expect(returned).toBe(handle);
    expect(handle).toMatchObject({ state: "CANCELLED", status: "CANCELLED", exit_code: null });
    expect(handle.operation?.type).toBe("execution.cancel");
    expect(script.received[1]?.body).toBeUndefined();
    expect(script.received[1]?.headers["content-type"]).toBeUndefined();
    expect(script.received[1]?.headers["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("refresh reads the execution again", async () => {
    const { handle } = await execution([{ request: GET_EXECUTION, response: answer(executionView({ state: "IN_PROGRESS", terminal: false, status: null, exit_code: null })) }]);
    await value(() => handle.refresh());
    expect(handle).toMatchObject({ state: "IN_PROGRESS", terminal: false, status: null, exit_code: null });
  });
});

describe("what a returned object exposes", () => {
  it("every member of its view, the defaults of the members the server left out, and the JSON as received", async () => {
    const view = { sandbox_id: SBX, project: "prj_0000000000000001", state: "READY", generation: 1, revision: "r1.0123456789ab", image: { digest: "sha256:00" }, resources: { vcpus: 1, memory_mib: 512, disk_mib: 1024 }, network: { mode: "none" }, expires_at: "t1", updated_at: "t0" };
    const { fabric } = scripted([{ request: READ, response: answer(view) }]);
    const sandbox = await value(() => fabric.sandboxes.get(SBX));
    expect({ ...sandbox }).toEqual({
      ...view,
      name: null,
      state_raw: null,
      last_execution: null,
      quarantined: null,
      failure: null,
      source_snapshot: null,
      notes: [],
      requestId: REQ,
    });
    expect(sandbox.raw).toEqual(view);
    expect(JSON.parse(JSON.stringify(sandbox))).toEqual(view);
    expect(String(sandbox)).toBe(`Sandbox(${SBX}, state=READY, generation=1)`);
    expect(sandbox.operation).toBeUndefined();
  });

  it("the defaults of an operation: not a replay, not recorded, and null where the server said nothing", async () => {
    const bare = { operation_id: "op-bare-0001", project: "prj_0000000000000001", type: "sandbox.stop", state: "IN_PROGRESS", terminal: false, target: {}, initiated_by: "HOST" };
    const { fabric } = scripted([{ request: get(`${P}/operations/op-bare-0001`), response: answer(bare) }]);
    const operation = await value(() => fabric.operations.get("op-bare-0001"));
    expect({ ...operation }).toEqual({
      ...bare,
      type_raw: null,
      state_raw: null,
      effect: null,
      effect_raw: null,
      failure: null,
      cleanup: null,
      cleanup_raw: null,
      cancelled_by: null,
      cancelled_by_raw: null,
      initiated_by_raw: null,
      result: null,
      actor: null,
      created_at: null,
      updated_at: null,
      replayed: false,
      recorded: false,
      idempotency_key_digest: null,
      requestId: REQ,
    });
    expect(String(operation)).toBe("Operation(op-bare-0001, type=sandbox.stop, state=IN_PROGRESS)");
  });
});
