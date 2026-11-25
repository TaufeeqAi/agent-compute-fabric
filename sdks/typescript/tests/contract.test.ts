/**
 * The views this package exposes are the views the platform publishes.
 *
 * The platform writes its tool definitions from the same model as its REST views, as JSON Schema,
 * and checks the files in (`protocols/mcp/tools`). This test reads the members of each view from
 * there. A member that the platform adds to a view and this package does not know would still
 * reach a caller in `raw`, but it would be missing from the typed surface without anyone noticing:
 * here it fails a test instead.
 */

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { answer, EXE, executionView, get, operationView, OP, P, sandboxView, SBX, scripted, SNP, snapshotView, value } from "./support/harness.js";

interface Definition {
  readonly properties: { readonly [member: string]: unknown };
}

const PUBLISHED = (
  JSON.parse(readFileSync(new URL("../../../protocols/mcp/tools/operation_get.json", import.meta.url), "utf8")) as {
    readonly outputSchema: { readonly $defs: { readonly [name: string]: Definition } };
  }
).outputSchema.$defs;

function published(view: string): string[] {
  const definition = PUBLISHED[view];
  if (definition === undefined) {
    throw new Error(`the platform publishes no view named ${view}`);
  }
  return Object.keys(definition.properties).sort();
}

/** The members a returned object shows: every one of its view, and the request id of the answer. */
function exposed(object: object): string[] {
  return Object.keys({ ...object })
    .filter((member) => member !== "requestId")
    .sort();
}

describe("a returned object has exactly the members of the view the platform publishes", () => {
  it("a sandbox", async () => {
    const { fabric } = scripted([{ request: get(`${P}/sandboxes/${SBX}`), response: answer(sandboxView()) }]);
    expect(exposed(await value(() => fabric.sandboxes.get(SBX)))).toEqual(published("Sandbox"));
  });

  it("a snapshot", async () => {
    const { fabric } = scripted([{ request: get(`${P}/snapshots`), response: answer({ items: [snapshotView()], more: false, next_cursor: "end" }) }]);
    expect(exposed(await value(() => fabric.snapshots.get(SNP)))).toEqual(published("Snapshot"));
  });

  it("an execution", async () => {
    const { fabric } = scripted([{ request: get(`${P}/executions/${EXE}`), response: answer(executionView()) }]);
    expect(exposed(await value(() => fabric.executions.get(EXE)))).toEqual(published("Execution"));
  });

  it("an operation", async () => {
    const { fabric } = scripted([{ request: get(`${P}/operations/${OP}`), response: answer(operationView()) }]);
    expect(exposed(await value(() => fabric.operations.get(OP)))).toEqual(published("Operation"));
  });

  it("and the platform publishes the nested views this package describes as types", () => {
    // Types leave nothing behind to compare at run time. What can be held here is that every nested
    // view this package names still exists under that name.
    for (const view of ["Failure", "Image", "ResourcesView", "NetworkView", "AllowEntryView", "PortRangeView", "SnapshotRef", "SandboxRef", "OutputSummary", "Durations", "Actor", "OperationTarget", "OperationResult"]) {
      expect(published(view).length, view).toBeGreaterThan(0);
    }
  });
});
