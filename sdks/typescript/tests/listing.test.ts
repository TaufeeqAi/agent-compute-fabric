/**
 * Listings: cursors followed to the end, the listing begun again on `CURSOR_EXPIRED`, at most three
 * times, and each item handed out once.
 */

import { describe, expect, it } from "vitest";

import * as sdk from "../src/index.js";
import { LIST_RESTARTS_MAX } from "../src/listing.js";
import {
  all,
  answer,
  type Exchange,
  failure,
  get,
  type Json,
  P,
  problem,
  REQ,
  sandboxView,
  scripted,
  SNP,
  snapshotView,
  value,
} from "./support/harness.js";

const LIST = `${P}/sandboxes`;
const id = (n: number): string => `sbx-${String(n).padStart(32, "0")}`;
const page = (ids: number[], next?: string): Json => ({
  items: ids.map((n) => sandboxView({ sandbox_id: id(n) })),
  more: next !== undefined,
  next_cursor: next ?? "end",
});
const expired = problem("CURSOR_EXPIRED");

/** A pass that reads one page and then finds its cursor expired. */
const expiringPass: Exchange[] = [
  { request: get(LIST), response: answer(page([1], "c1")) },
  { request: get(LIST, { cursor: "c1" }), response: expired },
];

describe("a listing", () => {
  it("follows next_cursor while more is true, and hands out the items in the platform's order", async () => {
    const { fabric, script } = scripted([
      { request: get(LIST), response: answer(page([1, 2], "c1")) },
      { request: get(LIST, { cursor: "c1" }), response: answer(page([3], "c2")) },
      { request: get(LIST, { cursor: "c2" }), response: answer(page([4, 5])) },
    ]);
    const sandboxes = await all(fabric.sandboxes.list());
    expect(sandboxes.map((sandbox) => sandbox.sandbox_id)).toEqual([1, 2, 3, 4, 5].map(id));
    // The first page is asked for with no cursor, and no page with a size the caller did not ask for.
    expect(script.received.map((request) => request.query)).toEqual([{}, { cursor: "c1" }, { cursor: "c2" }]);
  });

  it("may be empty", async () => {
    const { fabric } = scripted([{ request: get(LIST), response: answer(page([])) }]);
    expect(await all(fabric.sandboxes.list())).toEqual([]);
  });

  it("makes no request until it is iterated", async () => {
    const { fabric, script } = scripted([{ request: get(LIST), response: answer(page([1])) }]);
    const listing = fabric.sandboxes.list();
    await Promise.resolve();
    expect(script.received).toEqual([]);
    await all(listing);
  });

  it("passes a cursor back exactly as it was given, whatever characters it holds", async () => {
    const cursor = "a b+c/d=&more=1?#%41";
    const { fabric } = scripted([
      { request: get(LIST), response: answer(page([1], cursor)) },
      { request: get(LIST, { cursor }), response: answer(page([2])) },
    ]);
    expect(await all(fabric.sandboxes.list())).toHaveLength(2);
  });

  it("begins again in full when a cursor has expired, and hands out each item once", async () => {
    const { fabric } = scripted([
      ...expiringPass,
      { request: get(LIST), response: answer(page([1, 2], "c7")) },
      { request: get(LIST, { cursor: "c7" }), response: answer(page([3])) },
    ]);
    const sandboxes = await all(fabric.sandboxes.list());
    // Sandbox 1 was read twice, on the abandoned pass and on the completed one.
    expect(sandboxes.map((sandbox) => sandbox.sandbox_id)).toEqual([1, 2, 3].map(id));
  });

  it("hands out nothing before a pass is complete", async () => {
    const { fabric, script } = scripted([
      { request: get(LIST), response: answer(page([1], "c1")) },
      { request: get(LIST, { cursor: "c1" }), response: answer(page([2])) },
    ]);
    const listing = fabric.sandboxes.list();
    const first = await listing.next();
    expect(script.received).toHaveLength(2);
    expect(first.value?.sandbox_id).toBe(id(1));
    expect((await listing.next()).value?.sandbox_id).toBe(id(2));
    expect((await listing.next()).done).toBe(true);
  });

  it("begins again at most three times", () => {
    expect(LIST_RESTARTS_MAX).toBe(3);
  });

  it("completes when the third restart completes", async () => {
    const { fabric, script } = scripted([...expiringPass, ...expiringPass, ...expiringPass, { request: get(LIST), response: answer(page([1, 2])) }]);
    const sandboxes = await all(fabric.sandboxes.list());
    expect(sandboxes.map((sandbox) => sandbox.sandbox_id)).toEqual([1, 2].map(id));
    expect(script.received).toHaveLength(7);
  });

  it("throws CURSOR_EXPIRED when the third restart expires too, having handed out nothing", async () => {
    const { fabric, script } = scripted([...expiringPass, ...expiringPass, ...expiringPass, ...expiringPass]);
    const seen: string[] = [];
    const error = await failure(async () => {
      for await (const sandbox of fabric.sandboxes.list()) {
        seen.push(sandbox.sandbox_id);
      }
    });
    expect(error).toBeInstanceOf(sdk.CursorExpiredError);
    expect(error).toMatchObject({ code: "CURSOR_EXPIRED", retry: "AFTER_CHANGE" });
    expect(seen).toEqual([]);
    expect(script.received).toHaveLength(8);
  });

  it("does not begin again for any other refusal", async () => {
    const { fabric, script } = scripted([
      { request: get(LIST), response: answer(page([1], "c1")) },
      { request: get(LIST, { cursor: "c1" }), response: problem("PERMISSION_DENIED") },
    ]);
    expect(await failure(() => all(fabric.sandboxes.list()))).toBeInstanceOf(sdk.PermissionDeniedError);
    expect(script.received).toHaveLength(2);
  });

  it("repeats a page that is refused for now, at the same cursor, without beginning again", async () => {
    const { fabric, script } = scripted([
      { request: get(LIST), response: answer(page([1], "c1")) },
      { request: get(LIST, { cursor: "c1" }), response: problem("UPSTREAM_UNAVAILABLE", { retryAfter: 1 }) },
      { request: get(LIST, { cursor: "c1" }), response: answer(page([2])) },
    ]);
    expect(await all(fabric.sandboxes.list())).toHaveLength(2);
    expect(script.received).toHaveLength(3);
  });

  it.each([
    ["has no items", { more: false, next_cursor: "end" }],
    ["does not say whether more follow", { items: [], next_cursor: "end" }],
    ["says more follow and names no cursor", { items: [], more: true }],
    ["holds an item that is not a view", { items: ["sbx-1"], more: false, next_cursor: "end" }],
    ["holds a view without an identifier", { items: [{ state: "READY", generation: 1 }], more: false, next_cursor: "end" }],
  ])("refuses a page that %s", async (_what, body) => {
    const { fabric } = scripted([{ request: get(LIST), response: answer(body) }]);
    const error = await failure(() => all(fabric.sandboxes.list()));
    expect(error).toBeInstanceOf(sdk.UnexpectedResponseError);
    expect(error).toMatchObject({ requestId: REQ });
  });

  it("refuses to follow cursors in a circle", async () => {
    const { fabric } = scripted([
      { request: get(LIST), response: answer(page([1], "c1")) },
      { request: get(LIST, { cursor: "c1" }), response: answer(page([2], "c2")) },
      { request: get(LIST, { cursor: "c2" }), response: answer(page([3], "c1")) },
    ]);
    const error = await failure(() => all(fabric.sandboxes.list()));
    expect(error).toBeInstanceOf(sdk.UnexpectedResponseError);
    expect((error as Error).message).toMatch(/the listing would never end/);
  });
});

describe("snapshots", () => {
  const SNAPSHOTS = `${P}/snapshots`;
  const SNP2 = `snp-${"0".repeat(31)}2`;

  it("are listed to the end", async () => {
    const { fabric } = scripted([
      { request: get(SNAPSHOTS), response: answer({ items: [snapshotView()], more: true, next_cursor: "c1" }) },
      { request: get(SNAPSHOTS, { cursor: "c1" }), response: answer({ items: [snapshotView({ snapshot_id: SNP2 })], more: false, next_cursor: "c2" }) },
    ]);
    const snapshots = await all(fabric.snapshots.list());
    expect(snapshots.map((snapshot) => snapshot.snapshot_id)).toEqual([SNP, SNP2]);
  });

  it("are found by identifier or by name, by listing: the platform has no route that reads one", async () => {
    const listing = answer({ items: [snapshotView({ name: "baseline" }), snapshotView({ snapshot_id: SNP2, name: "nightly", snapshot_generation: 4 })], more: false, next_cursor: "end" });
    const { fabric } = scripted([
      { request: get(SNAPSHOTS), response: listing },
      { request: get(SNAPSHOTS), response: listing },
    ]);
    const byId = await value(() => fabric.snapshots.get(SNP2));
    expect(byId.name).toBe("nightly");
    const byName = await value(() => fabric.snapshots.get("nightly"));
    expect(byName.snapshot_id).toBe(SNP2);
    expect(byName.snapshot_generation).toBe(4);
  });

  it("an identifier wins over a name that is spelled like it", async () => {
    const listing = answer({ items: [snapshotView({ snapshot_id: SNP2, name: SNP }), snapshotView({ snapshot_id: SNP, name: "real" })], more: false, next_cursor: "end" });
    const { fabric } = scripted([{ request: get(SNAPSHOTS), response: listing }]);
    expect((await value(() => fabric.snapshots.get(SNP))).name).toBe("real");
  });

  it("a snapshot the project does not have is NOT_FOUND, said by the SDK from the listing", async () => {
    const { fabric } = scripted([{ request: get(SNAPSHOTS), response: answer({ items: [snapshotView()], more: false, next_cursor: "end" }) }]);
    const error = await failure(() => fabric.snapshots.get("missing"));
    expect(error).toBeInstanceOf(sdk.NotFoundError);
    expect(error).toMatchObject({ code: "NOT_FOUND", kind: "REFUSED", retry: "NEVER", status: undefined, requestId: REQ });
    expect((error as Error).message).toContain('"missing"');
  });
});
