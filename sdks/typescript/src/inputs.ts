/**
 * What a caller passes, checked and converted before any request is made.
 *
 * The platform decides what is allowed. These checks decide something narrower: whether the SDK can
 * say what the caller meant. A value it would have to guess at (a string where an argument vector
 * belongs, an option it does not know, a network mode that does not exist) is refused here, so that
 * a typing mistake never becomes a request that means something else.
 *
 * A wrong type is a `TypeError`; a value of the right type that cannot be used is a `RangeError`.
 */

import type { Generation, JsonObject, OutputStream } from "./types.js";

/** The names of the options of a call. The mapped type makes a missing or misspelled name a compile error. */
export type OptionNames<Options> = { readonly [Name in keyof Required<Options>]: true };

function typeOf(value: unknown): string {
  if (value === null) {
    return "null";
  }
  return Array.isArray(value) ? "an array" : `a value of type ${typeof value}`;
}

function isRecord(value: unknown): value is { readonly [member: string]: unknown } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function camelCase(name: string): string {
  return name.replace(/_([a-z0-9])/g, (_, letter: string) => letter.toUpperCase());
}

/**
 * The options of a call, with every name known. An unknown name is refused rather than ignored: the
 * documentation of the Python SDK spells the same options `idempotency_key` and `follow_max`, and a
 * call that silently dropped one of those would run without the key its caller relied on.
 */
export function optionsOf<Options extends object>(
  options: Options | null | undefined,
  names: OptionNames<Options>,
  call: string,
): Options {
  if (options == null) {
    return {} as Options;
  }
  if (!isRecord(options)) {
    throw new TypeError(`${call}: the options must be an object; got ${typeOf(options)}`);
  }
  for (const name of Object.keys(options)) {
    if (!Object.hasOwn(names, name)) {
      const camel = camelCase(name);
      const hint = camel !== name && Object.hasOwn(names, camel) ? ` Did you mean ${camel}?` : "";
      throw new TypeError(
        `${call}: unknown option ${JSON.stringify(name)}.${hint} The options are: ${Object.keys(names).join(", ")}`,
      );
    }
  }
  return options;
}

/** A string, when one was passed. `null` and `undefined` both mean that the caller set nothing. */
export function optionalText(value: unknown, what: string): string | undefined {
  if (value == null) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new TypeError(`${what} must be a string; got ${typeOf(value)}`);
  }
  return value;
}

export function text(value: unknown, what: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${what} must be a string; got ${typeOf(value)}`);
  }
  return value;
}

/** A flag. A string such as `"false"` is refused: it is truthy, and would turn the flag on. */
export function flag(value: unknown, what: string, fallback: boolean): boolean {
  if (value == null) {
    return fallback;
  }
  if (typeof value !== "boolean") {
    throw new TypeError(`${what} must be true or false; got ${typeOf(value)}`);
  }
  return value;
}

/** One of a fixed set of words. */
export function oneOf<Word extends string>(value: unknown, words: readonly Word[], what: string, fallback: Word): Word {
  if (value == null) {
    return fallback;
  }
  const found = words.find((word) => word === value);
  if (found === undefined) {
    const expected = words.map((word) => JSON.stringify(word)).join(" or ");
    if (typeof value !== "string") {
      throw new TypeError(`${what} must be ${expected}; got ${typeOf(value)}`);
    }
    throw new RangeError(`${what} must be ${expected}; got ${JSON.stringify(value)}`);
  }
  return found;
}

export function streamOf(value: unknown): OutputStream {
  return oneOf<OutputStream>(value, ["stdout", "stderr"], "stream", "stdout");
}

function integerAtLeast(value: unknown, minimum: number, what: string): number {
  if (typeof value !== "number") {
    throw new TypeError(`${what} must be an integer; got ${typeOf(value)}`);
  }
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new RangeError(`${what} must be an integer, ${minimum} or more; got ${value}`);
  }
  return value;
}

/** An integer of at least `minimum`, when one was passed. */
export function optionalInteger(value: unknown, minimum: number, what: string): number | undefined {
  return value == null ? undefined : integerAtLeast(value, minimum, what);
}

/** Seconds to follow an operation: the caller's, or the client's default. Zero means "do not follow". */
export function followBound(value: unknown, fallback: number): number {
  if (value == null) {
    return fallback;
  }
  if (typeof value !== "number") {
    throw new TypeError(`followMax must be a number of seconds; got ${typeOf(value)}`);
  }
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError(`followMax must be a finite number of seconds, 0 or more; got ${value}`);
  }
  return value;
}

/**
 * The generation a mutation names. A handle states the generation it last observed; `"current"` is
 * sent only when the caller wrote it, because it gives up the protection the generation is for. A
 * handle that was made without reading the sandbox has observed none, and the caller must name one.
 */
export function generationOf(requested: unknown, observed: number | undefined): Generation {
  if (requested == null) {
    if (observed === undefined) {
      throw new RangeError(
        'This handle has not seen a generation of the sandbox: call refresh() first, or pass generation (a number, or "current" to act on whatever is current).',
      );
    }
    return observed;
  }
  if (requested === "current") {
    return "current";
  }
  if (typeof requested === "number" || typeof requested === "string") {
    if (typeof requested === "number" && Number.isSafeInteger(requested) && requested >= 1) {
      return requested;
    }
    throw new RangeError(`generation must be a positive integer or "current"; got ${JSON.stringify(requested)}`);
  }
  throw new TypeError(`generation must be a positive integer or "current"; got ${typeOf(requested)}`);
}

/**
 * One segment of a request path. It is percent-encoded, so no character of it can end the path or
 * start a query. `.` and `..` survive encoding and a URL parser would resolve them into another
 * route, so they are refused.
 */
export function segment(value: unknown, what: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${what} must be a string; got ${typeOf(value)}`);
  }
  if (value === "" || value === "." || value === "..") {
    throw new RangeError(`${what} must name one resource; got ${JSON.stringify(value)}`);
  }
  try {
    return encodeURIComponent(value);
  } catch {
    throw new RangeError(`${what} must be well-formed text; it holds half of a surrogate pair`);
  }
}

/**
 * An argument vector. A string is never accepted here and never split: introducing a shell, or a
 * word-splitting rule, has to be the caller's explicit choice (`execShell`).
 */
export function argvOf(argv: unknown): string[] {
  if (typeof argv === "string") {
    throw new TypeError(
      'exec takes an argument vector, such as ["python", "-V"]: a string is never split. ' +
        "To run a command line through a shell, say so with execShell(command), which sends /bin/sh -c.",
    );
  }
  if (!Array.isArray(argv)) {
    throw new TypeError(`argv must be an array of strings; got ${typeOf(argv)}`);
  }
  if (argv.length === 0) {
    throw new RangeError("argv must name a program; it is empty");
  }
  return argv.map((argument: unknown, index) => text(argument, `argv[${index}]`));
}

/** Environment variables: names to string values. */
export function envOf(env: unknown): { [name: string]: string } {
  if (!isRecord(env)) {
    throw new TypeError(`env must be an object of names to strings; got ${typeOf(env)}`);
  }
  // A null prototype, so that a variable named like a member every object inherits is only data.
  const checked: { [name: string]: string } = Object.create(null) as { [name: string]: string };
  for (const [name, value] of Object.entries(env)) {
    checked[name] = text(value, `env[${JSON.stringify(name)}]`);
  }
  return checked;
}

function portBody(port: unknown, what: string): JsonObject {
  if (typeof port === "number" && Number.isSafeInteger(port)) {
    return { from: port, to: port };
  }
  if (Array.isArray(port) && port.length === 2 && port.every((bound) => typeof bound === "number" && Number.isSafeInteger(bound))) {
    return { from: port[0] as number, to: port[1] as number };
  }
  throw new RangeError(`${what} must be a port number or a [from, to] pair of port numbers`);
}

function entryBody(entry: unknown, what: string): JsonObject {
  if (!isRecord(entry)) {
    throw new TypeError(`${what} must be an object; got ${typeOf(entry)}`);
  }
  const members = Object.keys(entry).sort().join(",");
  const destination = members === "name,ports" ? "name" : members === "network,ports" ? "network" : undefined;
  if (destination === undefined) {
    throw new RangeError(`${what} must have exactly "ports" and one of "name" and "network"; it has: ${members}`);
  }
  if (!Array.isArray(entry["ports"])) {
    throw new TypeError(`${what}.ports must be an array; got ${typeOf(entry["ports"])}`);
  }
  return {
    [destination]: text(entry[destination], `${what}.${destination}`),
    ports: entry["ports"].map((port: unknown, index) => portBody(port, `${what}.ports[${index}]`)),
  };
}

/**
 * The network of a sandbox, in the API's form. There are two modes and no third: `"restricted"`,
 * like every other word, is refused, so that a caller never believes in a mode the host does not
 * enforce.
 */
export function networkBody(network: unknown): JsonObject {
  if (network === "none") {
    return { mode: "none" };
  }
  const expected = 'network must be "none" or an allowlist, {mode: "allowlist", entries: [...]}; no other mode exists';
  if (!isRecord(network)) {
    if (typeof network === "string") {
      throw new RangeError(`${expected}; got ${JSON.stringify(network)}`);
    }
    throw new TypeError(`${expected}; got ${typeOf(network)}`);
  }
  const mode = network["mode"];
  if (mode !== "allowlist") {
    throw new RangeError(`${expected}; got an object whose mode is ${typeof mode === "string" ? JSON.stringify(mode) : typeOf(mode)}`);
  }
  const members = Object.keys(network).sort().join(", ");
  if (members !== "entries, mode") {
    throw new RangeError(`an allowlist has exactly "mode" and "entries"; this one has: ${members}`);
  }
  if (!Array.isArray(network["entries"])) {
    throw new TypeError(`network.entries must be an array; got ${typeOf(network["entries"])}`);
  }
  return {
    mode: "allowlist",
    entries: network["entries"].map((entry: unknown, index) => entryBody(entry, `network.entries[${index}]`)),
  };
}
