/**
 * Units, argument vectors, networks, keys and options: what is accepted, what it becomes, and that
 * everything ambiguous is refused before any request is made.
 */

import { describe, expect, it } from "vitest";

import { checkedKey, CREATE_KEY_MAX_LENGTH, KEY_MAX_LENGTH, keyOf } from "../src/idempotency.js";
import { argvOf, generationOf, networkBody, optionsOf, segment } from "../src/inputs.js";
import { mebibytes, positiveInteger, seconds } from "../src/units.js";
import {
  answer,
  CREATE_ARGS,
  CREATE_BODY,
  executionView,
  failure,
  P,
  post,
  sandboxView,
  SBX,
  scripted,
  succeeded,
  value,
} from "./support/harness.js";

describe("memory and disk", () => {
  it.each([
    [512, 512],
    [1, 1],
    ["512MiB", 512],
    ["4GiB", 4096],
    ["1TiB", 1_048_576],
    ["1024KiB", 1],
    ["2048KiB", 2],
    ["0004GiB", 4096],
    // A fraction is accepted when it is a whole number of MiB, and only then.
    ["1.5GiB", 1536],
    ["0.5GiB", 512],
    ["2.25GiB", 2304],
    ["0.5TiB", 524_288],
  ])("%j is %d MiB", (input, mib) => {
    expect(mebibytes(input, "memory")).toBe(mib);
  });

  it.each([
    // Decimal units, and units without their letter: 4000 or 4096 MiB? Nobody can say.
    "4GB",
    "4G",
    "4MB",
    "4M",
    "4kB",
    "4Gi",
    "4gb",
    "4gib",
    "4GIB",
    // Not a whole number of MiB.
    "1.5MiB",
    "0.1GiB",
    "0.3GiB",
    "1000KiB",
    "1KiB",
    // No unit, no number, or not written the one way a quantity is written.
    "4",
    "",
    "GiB",
    "4 GiB",
    " 4GiB",
    "4GiB ",
    "+4GiB",
    "-4GiB",
    "1e3MiB",
    "1.GiB",
    ".5GiB",
    "0x10MiB",
    "4GiB4GiB",
    // Zero and below, a bare fraction, and what is not a finite integer.
    "0MiB",
    "0.0GiB",
    0,
    -1,
    -512,
    1.5,
    512.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    2 ** 53,
  ])("%j is refused with a RangeError", (input) => {
    expect(() => mebibytes(input, "memory")).toThrow(RangeError);
  });

  it.each([null, undefined, true, 5n, {}, ["4GiB"]])("%o is refused with a TypeError", (input) => {
    expect(() => mebibytes(input, "memory")).toThrow(TypeError);
  });

  it("says what was passed and what is accepted", () => {
    expect(() => mebibytes("4GB", "disk")).toThrow(/^disk must be .*"512MiB".*got "4GB"$/);
  });
});

describe("lifetimes and timeouts", () => {
  it.each([
    [90, 90],
    [1, 1],
    ["90s", 90],
    ["10m", 600],
    ["2h", 7200],
    ["1d", 86_400],
    ["1.5h", 5400],
    ["0.5m", 30],
    ["0.25d", 21_600],
  ])("%j is %d seconds", (input, expected) => {
    expect(seconds(input, "timeout")).toBe(expected);
  });

  it.each([
    "10",
    "10min",
    "10sec",
    "10M",
    "10S",
    "1D",
    "1w",
    "1y",
    "100ms",
    "1h30m",
    "5 s",
    " 5s",
    "-5s",
    "+5s",
    "",
    "s",
    // Not a whole number of seconds.
    "1.5s",
    "0.0001h",
    "0.01m",
    // Zero and below, a bare fraction, and what is not a finite integer.
    "0s",
    "0.0h",
    0,
    -5,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
  ])("%j is refused with a RangeError", (input) => {
    expect(() => seconds(input, "lifetime")).toThrow(RangeError);
  });

  it.each([null, undefined, false, 5n, {}])("%o is refused with a TypeError", (input) => {
    expect(() => seconds(input, "lifetime")).toThrow(TypeError);
  });
});

describe("cpu", () => {
  it.each([1, 2, 64])("%j is accepted", (input) => {
    expect(positiveInteger(input, "cpu")).toBe(input);
  });

  it.each([0, -1, 1.5, "2", Number.NaN])("%j is refused with a RangeError", (input) => {
    expect(() => positiveInteger(input, "cpu")).toThrow(RangeError);
  });

  it.each([null, undefined, true, 2n])("%o is refused with a TypeError", (input) => {
    expect(() => positiveInteger(input, "cpu")).toThrow(TypeError);
  });
});

describe("argument vectors", () => {
  it("accepts an array of strings and copies it", () => {
    const argv = ["python", "-c", "print('a b')"];
    expect(argvOf(argv)).toEqual(argv);
    expect(argvOf(argv)).not.toBe(argv);
  });

  it("never accepts a string, and says how to ask for a shell", () => {
    expect(() => argvOf("python -V")).toThrow(TypeError);
    expect(() => argvOf("python -V")).toThrow(/execShell/);
  });

  it.each([[[]]])("refuses an empty vector with a RangeError", (input) => {
    expect(() => argvOf(input)).toThrow(RangeError);
  });

  it.each([[["python", 3]], [["python", null]], [[["nested"]]], [undefined], [null], [{ 0: "python", length: 1 }]])(
    "refuses %j with a TypeError",
    (input) => {
      expect(() => argvOf(input)).toThrow(TypeError);
    },
  );
});

describe("networks", () => {
  it('"none" is the mode none', () => {
    expect(networkBody("none")).toEqual({ mode: "none" });
  });

  it("an allowlist is sent with every port as a range", () => {
    expect(
      networkBody({
        mode: "allowlist",
        entries: [
          { name: "packages.example", ports: [443] },
          { network: "10.0.0.0/8", ports: [[8000, 8100], 22] },
        ],
      }),
    ).toEqual({
      mode: "allowlist",
      entries: [
        { name: "packages.example", ports: [{ from: 443, to: 443 }] },
        {
          network: "10.0.0.0/8",
          ports: [
            { from: 8000, to: 8100 },
            { from: 22, to: 22 },
          ],
        },
      ],
    });
  });

  it("an allowlist may be empty", () => {
    expect(networkBody({ mode: "allowlist", entries: [] })).toEqual({ mode: "allowlist", entries: [] });
  });

  it.each([
    ["restricted"],
    ["allowlist"],
    ["open"],
    ["NONE"],
    [""],
    [{ mode: "none" }],
    [{ mode: "restricted", entries: [] }],
    [{ mode: "allowlist" }],
    [{ mode: "allowlist", entries: [], fallback: "none" }],
    [{ mode: "allowlist", entries: [{ name: "packages.example" }] }],
    [{ mode: "allowlist", entries: [{ ports: [443] }] }],
    [{ mode: "allowlist", entries: [{ name: "packages.example", network: "10.0.0.0/8", ports: [443] }] }],
    [{ mode: "allowlist", entries: [{ name: "packages.example", ports: [443], comment: "x" }] }],
    [{ mode: "allowlist", entries: [{ name: "packages.example", ports: ["443"] }] }],
    [{ mode: "allowlist", entries: [{ name: "packages.example", ports: [1.5] }] }],
    [{ mode: "allowlist", entries: [{ name: "packages.example", ports: [[8000]] }] }],
    [{ mode: "allowlist", entries: [{ name: "packages.example", ports: [[1, 2, 3]] }] }],
    [{ mode: "allowlist", entries: [{ name: "packages.example", ports: [{ from: 1, to: 2 }] }] }],
  ])("%j is refused with a RangeError", (input) => {
    expect(() => networkBody(input)).toThrow(RangeError);
  });

  it.each([
    [42],
    [true],
    [["none"]],
    [{ mode: "allowlist", entries: "packages.example" }],
    [{ mode: "allowlist", entries: ["packages.example"] }],
    [{ mode: "allowlist", entries: [{ name: 7, ports: [443] }] }],
    [{ mode: "allowlist", entries: [{ name: "packages.example", ports: 443 }] }],
  ])("%j is refused with a TypeError", (input) => {
    expect(() => networkBody(input)).toThrow(TypeError);
  });
});

describe("idempotency keys", () => {
  const visible = Array.from({ length: 0x7e - 0x21 + 1 }, (_, index) => String.fromCharCode(0x21 + index)).join("");

  it.each([["k"], ["key-0001"], ["0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"], [visible], ["a".repeat(KEY_MAX_LENGTH)]])(
    "accepts %j unchanged",
    (key) => {
      expect(checkedKey(key)).toBe(key);
    },
  );

  it.each([
    [""],
    ["a".repeat(KEY_MAX_LENGTH + 1)],
    ["with space"],
    [" leading"],
    ["trailing "],
    ["tab\there"],
    ["line\nbreak"],
    ["del\u007f"],
    ["nul\u0000"],
    ["café"],
    ["\u{1F511}"],
  ])("refuses %j with a RangeError", (key) => {
    expect(() => checkedKey(key)).toThrow(RangeError);
  });

  it.each([[5], [true], [{}], [["k"]]])("refuses %j with a TypeError", (key) => {
    expect(() => checkedKey(key)).toThrow(TypeError);
  });

  it("generates a UUID of version 4 when the caller passes none, and a new one each time", () => {
    const first = keyOf(undefined);
    expect(first).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(keyOf(null)).not.toBe(first);
  });

  it("leaves room in a key of create for the suffixes the SDK derives", () => {
    expect(CREATE_KEY_MAX_LENGTH).toBe(247);
    expect(`${"a".repeat(CREATE_KEY_MAX_LENGTH)}:destroy`).toHaveLength(KEY_MAX_LENGTH);
    expect(checkedKey("a".repeat(247), CREATE_KEY_MAX_LENGTH)).toHaveLength(247);
    expect(() => checkedKey("a".repeat(248), CREATE_KEY_MAX_LENGTH)).toThrow(RangeError);
  });
});

describe("generations", () => {
  it("a handle states the generation it observed unless the caller says otherwise", () => {
    expect(generationOf(undefined, 3)).toBe(3);
    expect(generationOf(null, 3)).toBe(3);
    expect(generationOf(7, 3)).toBe(7);
    expect(generationOf("current", 3)).toBe("current");
  });

  it.each([0, -1, 1.5, "latest", "1", "CURRENT", ""])("%j is refused with a RangeError", (input) => {
    expect(() => generationOf(input, 3)).toThrow(RangeError);
  });

  it.each([true, {}, [1]])("%j is refused with a TypeError", (input) => {
    expect(() => generationOf(input, 3)).toThrow(TypeError);
  });
});

describe("path segments", () => {
  it("encodes every character that could end the path or start a query", () => {
    expect(segment("sbx-1", "sandbox")).toBe("sbx-1");
    expect(segment("a/b", "sandbox")).toBe("a%2Fb");
    expect(segment("a?b#c", "sandbox")).toBe("a%3Fb%23c");
    expect(segment("%2e%2e", "sandbox")).toBe("%252e%252e");
  });

  it.each(["", ".", ".."])("refuses %j, which would name another route", (input) => {
    expect(() => segment(input, "sandbox")).toThrow(RangeError);
  });

  it.each([undefined, null, 7, {}])("refuses %j with a TypeError", (input) => {
    expect(() => segment(input, "sandbox")).toThrow(TypeError);
  });
});

describe("options", () => {
  const names = { idempotencyKey: true, followMax: true } as const;

  it("returns the options it was given, and none when it was given none", () => {
    const options = { idempotencyKey: "k" };
    expect(optionsOf(options, names, "call")).toBe(options);
    expect(optionsOf(undefined, names, "call")).toEqual({});
    expect(optionsOf(null, names, "call")).toEqual({});
  });

  it("refuses an option it does not know, and recognizes the spelling of the Python SDK", () => {
    expect(() => optionsOf({ idempotency_key: "k" } as object, names, "call")).toThrow(
      /^call: unknown option "idempotency_key"\. Did you mean idempotencyKey\? The options are: idempotencyKey, followMax$/,
    );
    expect(() => optionsOf({ retries: 3 } as object, names, "call")).toThrow(TypeError);
  });

  it.each(["key", 5, ["idempotencyKey"]])("refuses %j in place of the options", (input) => {
    expect(() => optionsOf(input as unknown as object, names, "call")).toThrow(TypeError);
  });
});

describe("before any request", () => {
  // The script is empty: any request at all fails the test.
  const refusedCreates: [string, object, typeof RangeError | typeof TypeError][] = [
    ["memory in a decimal unit", { ...CREATE_ARGS, memory: "4GB" }, RangeError],
    ["memory without a unit letter", { ...CREATE_ARGS, memory: "4G" }, RangeError],
    ["memory that is not whole MiB", { ...CREATE_ARGS, memory: "0.1GiB" }, RangeError],
    ["memory of zero", { ...CREATE_ARGS, memory: 0 }, RangeError],
    ["memory below zero", { ...CREATE_ARGS, memory: -512 }, RangeError],
    ["memory as a bare fraction", { ...CREATE_ARGS, memory: 512.5 }, RangeError],
    ["disk in a decimal unit", { ...CREATE_ARGS, disk: "10GB" }, RangeError],
    ["no disk", { cpu: 1, memory: 512 }, TypeError],
    ["cpu as a fraction", { ...CREATE_ARGS, cpu: 0.5 }, RangeError],
    ["cpu of zero", { ...CREATE_ARGS, cpu: 0 }, RangeError],
    ["a lifetime without a unit", { ...CREATE_ARGS, lifetime: "90" }, RangeError],
    ["a lifetime of zero", { ...CREATE_ARGS, lifetime: 0 }, RangeError],
    ["a lifetime below zero", { ...CREATE_ARGS, lifetime: -60 }, RangeError],
    ["a lifetime that is not whole seconds", { ...CREATE_ARGS, lifetime: "1.5s" }, RangeError],
    ["the network mode restricted", { ...CREATE_ARGS, network: "restricted" }, RangeError],
    ["a network mode that is another word", { ...CREATE_ARGS, network: "host" }, RangeError],
    ["a key with a space", { ...CREATE_ARGS, idempotencyKey: "my key" }, RangeError],
    ["an empty key", { ...CREATE_ARGS, idempotencyKey: "" }, RangeError],
    ["a key too long for its suffixes", { ...CREATE_ARGS, idempotencyKey: "a".repeat(248) }, RangeError],
    ["a start that is not a flag", { ...CREATE_ARGS, start: "false" }, TypeError],
    ["an unknown start policy", { ...CREATE_ARGS, onStartFailure: "retry" }, RangeError],
    ["a follow bound below zero", { ...CREATE_ARGS, followMax: -1 }, RangeError],
    ["an option in the spelling of another SDK", { ...CREATE_ARGS, idempotency_key: "k" }, TypeError],
    ["a name that is not text", { ...CREATE_ARGS, name: 7 }, TypeError],
  ];

  it.each(refusedCreates)("create refuses %s", async (_what, options, errorClass) => {
    const { fabric, script } = scripted([]);
    const error = await failure(() => fabric.sandboxes.create("python", options as never));
    expect(error).toBeInstanceOf(errorClass);
    expect(script.received).toEqual([]);
  });

  it("create refuses an image that is not text", async () => {
    const { fabric, script } = scripted([]);
    expect(await failure(() => fabric.sandboxes.create(undefined as never, CREATE_ARGS))).toBeInstanceOf(TypeError);
    expect(script.received).toEqual([]);
  });

  it("create refuses bad arguments before it asks the platform which project the credential is bound to", async () => {
    // No project is configured: the first request of a valid call would be the lookup.
    const { fabric, script } = scripted([], { project: undefined });
    expect(await failure(() => fabric.sandboxes.create("python", { ...CREATE_ARGS, memory: "4GB" }))).toBeInstanceOf(RangeError);
    expect(script.received).toEqual([]);
  });

  async function sandbox() {
    const exchanges = [{ request: post(`${P}/sandboxes`, CREATE_BODY), response: answer(succeeded("sandbox.create", { sandbox: sandboxView() })) }];
    const made = scripted(exchanges);
    return { ...made, handle: await value(() => made.fabric.sandboxes.create("python", { ...CREATE_ARGS, start: false })) };
  }

  const refusedExecs: [string, unknown, object, typeof RangeError | typeof TypeError][] = [
    ["a command line in place of a vector", "python -V", {}, TypeError],
    ["an empty vector", [], {}, RangeError],
    ["a vector with a number in it", ["sleep", 5], {}, TypeError],
    ["a timeout without a unit", ["true"], { timeout: "10" }, RangeError],
    ["a timeout of zero", ["true"], { timeout: 0 }, RangeError],
    ["a timeout that is not whole seconds", ["true"], { timeout: "0.5s" }, RangeError],
    ["a generation of zero", ["true"], { generation: 0 }, RangeError],
    ["a generation that is another word", ["true"], { generation: "latest" }, RangeError],
    ["an environment value that is not text", ["true"], { env: { PORT: 8080 } }, TypeError],
    ["an environment that is not an object", ["true"], { env: ["A=1"] }, TypeError],
    ["a working directory that is not text", ["true"], { cwd: 7 }, TypeError],
    ["a key with a line break", ["true"], { idempotencyKey: "key\n" }, RangeError],
    ["an unknown option", ["true"], { shell: true }, TypeError],
  ];

  it.each(refusedExecs)("exec refuses %s", async (_what, argv, options, errorClass) => {
    const { handle, script } = await sandbox();
    const error = await failure(() => handle.exec(argv as never, options as never));
    expect(error).toBeInstanceOf(errorClass);
    expect(script.received).toHaveLength(1);
  });

  it("execShell refuses what is not a command line", async () => {
    const { handle, script } = await sandbox();
    expect(await failure(() => handle.execShell(["echo", "hi"] as never))).toBeInstanceOf(TypeError);
    expect(script.received).toHaveLength(1);
  });
});

describe("what a call sends", () => {
  it("create sends the required members and the members the caller set, converted to the API's integers", async () => {
    const body = {
      image: "python",
      resources: { vcpus: 2, memory_mib: 4096, disk_mib: 10_240 },
      network: { mode: "allowlist", entries: [{ name: "packages.example", ports: [{ from: 443, to: 443 }] }] },
      name: "trainer",
      lifetime_seconds: 7200,
    };
    const { fabric } = scripted([{ request: post(`${P}/sandboxes`, body), response: answer(succeeded("sandbox.create", { sandbox: sandboxView() })) }]);
    await value(() =>
      fabric.sandboxes.create("python", {
        cpu: 2,
        memory: "4GiB",
        disk: "10GiB",
        network: { mode: "allowlist", entries: [{ name: "packages.example", ports: [443] }] },
        name: "trainer",
        lifetime: "2h",
        start: false,
      }),
    );
  });

  it("create spells out no default: not the network, and never start", async () => {
    const { fabric, script } = scripted([{ request: post(`${P}/sandboxes`, CREATE_BODY), response: answer(succeeded("sandbox.create", { sandbox: sandboxView() })) }]);
    await value(() => fabric.sandboxes.create("python", { ...CREATE_ARGS, start: false, name: undefined, lifetime: undefined, network: undefined }));
    expect(Object.keys(JSON.parse(script.received[0]?.body ?? "") as object)).toEqual(["image", "resources"]);
  });

  it('create sends the mode none when the caller wrote "none"', async () => {
    const body = { ...CREATE_BODY, network: { mode: "none" } };
    const { fabric } = scripted([{ request: post(`${P}/sandboxes`, body), response: answer(succeeded("sandbox.create", { sandbox: sandboxView() })) }]);
    await value(() => fabric.sandboxes.create("python", { ...CREATE_ARGS, network: "none", start: false }));
  });

  it("exec sends the vector as it is, and the members the caller set", async () => {
    const body = {
      expected_generation: 1,
      argv: ["python", "-c", "print('a b')"],
      cwd: "/work",
      env: { MODE: "test", constructor: "data" },
      timeout_seconds: 600,
    };
    const exchanges = [
      { request: post(`${P}/sandboxes`, CREATE_BODY, "create-key"), response: answer(succeeded("sandbox.create", { sandbox: sandboxView() })) },
      { request: post(`${P}/sandboxes/${SBX}/executions`, body, "exec-key"), response: answer(succeeded("execution.create", { execution: executionView() })) },
    ];
    const { fabric } = scripted(exchanges);
    const handle = await value(() => fabric.sandboxes.create("python", { ...CREATE_ARGS, start: false, idempotencyKey: "create-key" }));
    const execution = await value(() =>
      handle.exec(["python", "-c", "print('a b')"], {
        cwd: "/work",
        env: { MODE: "test", constructor: "data" },
        timeout: "10m",
        idempotencyKey: "exec-key",
      }),
    );
    expect(execution.exit_code).toBe(0);
  });

  it("execShell sends /bin/sh -c and the command line as one argument", async () => {
    const exchanges = [
      { request: post(`${P}/sandboxes`, CREATE_BODY, "create-key"), response: answer(succeeded("sandbox.create", { sandbox: sandboxView() })) },
      {
        request: post(`${P}/sandboxes/${SBX}/executions`, { expected_generation: 1, argv: ["/bin/sh", "-c", "ls -la | wc -l"] }, "shell-key"),
        response: answer(succeeded("execution.create", { execution: executionView() })),
      },
    ];
    const { fabric } = scripted(exchanges);
    const handle = await value(() => fabric.sandboxes.create("python", { ...CREATE_ARGS, start: false, idempotencyKey: "create-key" }));
    await value(() => handle.execShell("ls -la | wc -l", { idempotencyKey: "shell-key" }));
  });
});
