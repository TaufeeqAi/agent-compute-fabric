/**
 * The client conformance suite, run against this SDK.
 *
 * The scenarios are the platform's (`protocols/conformance/scenarios.json`): each scripts what a
 * server answers and states what a correct client does. The file is read here, at test time, so
 * that this runner always plays the scenarios the repository holds. The matching rules of the
 * suite are enforced by the scripted transport of the harness.
 */

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import * as sdk from "../src/index.js";
import type { Execution, FabricOptions, Sandbox as SandboxHandle } from "../src/index.js";
import { USER_AGENT } from "../src/version.js";
import { type Exchange, produced, Script, scripts, secrets, VirtualTime } from "./support/harness.js";

interface Expectation {
  readonly outcome: "success" | "error";
  readonly error?: { readonly class: string; readonly code?: string; readonly kind?: string; readonly retry?: string };
  readonly result?: { readonly [member: string]: unknown };
  readonly replayed?: boolean;
  readonly exit_code: string;
  readonly min_wait_s?: number;
}

interface Scenario {
  readonly id: string;
  readonly title: string;
  readonly rules: readonly string[];
  readonly call: { readonly name: string; readonly args: { readonly [name: string]: unknown } };
  readonly config?: { readonly [name: string]: unknown };
  readonly exchanges: readonly Exchange[];
  readonly expect: Expectation;
}

interface Suite {
  readonly schema_version: number;
  readonly defaults: { readonly project: string; readonly base_url: string; readonly api_key: string };
  readonly scenarios: readonly Scenario[];
}

const suite = JSON.parse(
  readFileSync(new URL("../../../protocols/conformance/scenarios.json", import.meta.url), "utf8"),
) as Suite;

/** The arguments of a scenario's call. Each must be taken by the mapping: one left over fails the scenario. */
class Arguments {
  readonly #left: Map<string, unknown>;

  constructor(args: { readonly [name: string]: unknown }) {
    this.#left = new Map(Object.entries(args));
  }

  take<Value>(name: string): Value {
    const value = this.#left.get(name);
    this.#left.delete(name);
    return value as Value;
  }

  get left(): string[] {
    return [...this.#left.keys()];
  }
}

/**
 * The neutral calls of the suite, on this SDK's surface. Only the calls the scenarios use are
 * mapped: a call or an argument this table does not know fails the scenario, so that a new scenario
 * is mapped on purpose and never passes by being ignored.
 */
const CALLS: { readonly [name: string]: (options: FabricOptions, args: Arguments) => Promise<unknown> } = {
  "sandbox.create": (options, args) =>
    new sdk.Fabric(options).sandboxes.create(args.take("image"), {
      cpu: args.take("vcpus"),
      memory: args.take("memory_mib"),
      disk: args.take("disk_mib"),
      start: args.take("start"),
      idempotencyKey: args.take("idempotency_key"),
    }),
  "sandbox.get": (options, args) => new sdk.Fabric(options).sandboxes.get(args.take("sandbox")),
  "sandbox.list": async (options) => {
    const ids: string[] = [];
    for await (const sandbox of new sdk.Fabric(options).sandboxes.list()) {
      ids.push(sandbox.sandbox_id);
    }
    return { count: ids.length, ids };
  },
  // The scenario states the sandbox and the generation its caller holds, and scripts no read: the
  // handle is made without one, and the call names the generation, through the public surface.
  "sandbox.exec": (options, args) => {
    const handle = new sdk.Fabric(options).sandboxes.handle(args.take("sandbox_id"));
    return handle.exec(args.take("argv"), {
      generation: args.take("expected_generation"),
      idempotencyKey: args.take("idempotency_key"),
    });
  },
};

/** The client settings a scenario may fix, in this SDK's spelling. */
const SETTINGS: { readonly [name: string]: keyof FabricOptions } = {
  max_retries: "maxRetries",
  follow_max_s: "followMax",
};

function settingsOf(config: Scenario["config"]): FabricOptions {
  const options: { [name: string]: unknown } = {};
  for (const [name, value] of Object.entries(config ?? {})) {
    const option = SETTINGS[name];
    if (option === undefined) {
      throw new Error(`the runner does not know the client setting ${name}`);
    }
    options[option] = value;
  }
  return options;
}

type Outcome = { readonly result: unknown; readonly error?: undefined } | { readonly result?: undefined; readonly error: unknown };

/**
 * The exit class the command-line client would end with. This SDK has no command line; deriving
 * the class shows that an outcome carries everything a client needs to tell the classes apart.
 */
function exitClass(outcome: Outcome): string {
  const { error } = outcome;
  if (error === undefined) {
    const exitCode = (outcome.result as Partial<Execution>).exit_code;
    return typeof exitCode === "number" && exitCode !== 0 ? "command_failed" : "success";
  }
  const cause = error instanceof sdk.SandboxStartError ? error.startError : error;
  if (cause instanceof sdk.OutcomeLostError) {
    return "outcome_lost";
  }
  if (cause instanceof sdk.UnresolvedError) {
    return "unresolved";
  }
  if (cause instanceof sdk.RefusedError) {
    return "refused";
  }
  if (cause instanceof sdk.OperationFailedError) {
    return "operation_failed";
  }
  if (cause instanceof sdk.OutcomeUnknownError) {
    return "outcome_unknown";
  }
  if (cause instanceof sdk.OperationStillRunningError) {
    return "still_running";
  }
  if (cause instanceof sdk.APIConnectionError) {
    return "unreachable";
  }
  return cause instanceof RangeError || cause instanceof TypeError || cause instanceof sdk.ConfigurationError ? "usage" : "unclassified";
}

async function play(scenario: Scenario): Promise<{ outcome: Outcome; script: Script; time: VirtualTime }> {
  const args = new Arguments(scenario.call.args);
  const script = new Script(suite.defaults.base_url, scenario.exchanges, scenario.call.args["idempotency_key"] as string | undefined);
  scripts.push(script);
  secrets.add(suite.defaults.api_key);
  const time = new VirtualTime();
  const options: FabricOptions = {
    apiKey: suite.defaults.api_key,
    baseUrl: suite.defaults.base_url,
    project: suite.defaults.project,
    fetch: script.fetch,
    clock: time.clock,
    sleep: time.sleep,
    random: () => 0.5,
    ...settingsOf(scenario.config),
  };
  const call = CALLS[scenario.call.name];
  if (call === undefined) {
    throw new Error(`the runner has no mapping for the call ${scenario.call.name}`);
  }
  let outcome: Outcome;
  try {
    outcome = { result: await call(options, args) };
  } catch (error) {
    outcome = { error };
  }
  produced.push(outcome.result ?? outcome.error);
  expect(args.left, "every argument of the call is mapped").toEqual([]);
  return { outcome, script, time };
}

describe("the client conformance suite", () => {
  it("is the suite the platform publishes: schema version 1, at least 27 scenarios, each with its own id", () => {
    expect(suite.schema_version).toBe(1);
    expect(suite.scenarios.length).toBeGreaterThanOrEqual(27);
    expect(new Set(suite.scenarios.map((scenario) => scenario.id)).size).toBe(suite.scenarios.length);
  });

  it.each(suite.scenarios.map((scenario) => [scenario.id, scenario] as const))("%s", async (_id, scenario) => {
    const { outcome, script, time } = await play(scenario);
    const expected = scenario.expect;

    // No request unexpected, none left over, each as the script states it.
    script.check();

    if (expected.outcome === "success") {
      expect(outcome.error, `${scenario.title} (the call should succeed)`).toBeUndefined();
      expect(outcome.result).toMatchObject(expected.result ?? {});
      if (expected.replayed !== undefined) {
        expect((outcome.result as SandboxHandle).operation?.replayed).toBe(expected.replayed);
      }
    } else {
      const wanted = expected.error;
      if (wanted === undefined) {
        throw new Error("a scenario that expects an error names its class");
      }
      const errorClass = (sdk as { readonly [name: string]: unknown })[wanted.class];
      expect(errorClass, `the SDK exports ${wanted.class}`).toBeTypeOf("function");
      // Exactly the class: a subclass, or a class above it, is another answer.
      expect(Object.getPrototypeOf(outcome.error)).toBe((errorClass as { prototype: object }).prototype);
      expect((outcome.error as Error).name).toBe(wanted.class);
      const { class: _class, ...members } = wanted;
      expect(outcome.error).toMatchObject(members);
    }

    if (expected.min_wait_s !== undefined) {
      expect(time.waited).toBeGreaterThanOrEqual(expected.min_wait_s);
    }
    expect(exitClass(outcome)).toBe(expected.exit_code);

    // What holds for every request of every scenario, whatever the scenario is about.
    const bodiesOfKey = new Map<string, Set<string | undefined>>();
    for (const request of script.received) {
      expect(request.headers["authorization"]).toBe(`Bearer ${suite.defaults.api_key}`);
      expect(request.headers["user-agent"]).toBe(USER_AGENT);
      expect(request.redirect).toBe("manual");
      const key = request.headers["idempotency-key"];
      if (request.method === "GET") {
        expect(key, "a read carries no idempotency key").toBeUndefined();
        expect(request.body, "a read carries no body").toBeUndefined();
      } else {
        expect(key, "a mutation carries an idempotency key").toBeTypeOf("string");
        const bodies = bodiesOfKey.get(key as string) ?? new Set();
        bodiesOfKey.set(key as string, bodies.add(`${request.method} ${request.path} ${request.body ?? ""}`));
      }
    }
    for (const [key, requests] of bodiesOfKey) {
      expect(requests.size, `every request under the key ${key} is the same request, byte for byte`).toBe(1);
    }
  });
});
