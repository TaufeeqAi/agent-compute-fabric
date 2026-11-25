/**
 * Human units in, the API's integers out.
 *
 * The API speaks integers only: vCPUs, MiB, seconds. Parsing units is the client's job, and the rule
 * is that nothing ambiguous gets through. `"4GB"` could mean 4000 or 4096 MiB, `"4G"` could mean
 * anything, and a value that is not a whole number of the API's unit would have to be rounded by
 * someone. Each is refused here, with a `RangeError`, before any request is made.
 *
 * The arithmetic is exact (`BigInt`), so that `"0.1GiB"` is refused because it is 102.4 MiB and not
 * because a binary fraction happened to round one way.
 */

/** Binary units of memory and disk, in KiB. KiB is the smallest, so every factor is an integer. */
const SIZE_UNITS: ReadonlyMap<string, bigint> = new Map([
  ["KiB", 1n],
  ["MiB", 1024n],
  ["GiB", 1024n ** 2n],
  ["TiB", 1024n ** 3n],
]);
const KIB_PER_MIB = 1024n;

/** Units of time, in seconds. Lower case only: `M` and `D` are not units here. */
const DURATION_UNITS: ReadonlyMap<string, bigint> = new Map([
  ["s", 1n],
  ["m", 60n],
  ["h", 3600n],
  ["d", 86400n],
]);

/** Digits, an optional decimal fraction, a unit. No sign, no exponent, no space. */
const QUANTITY = /^(\d+)(?:\.(\d+))?([A-Za-z]+)$/;

/** Longest piece of a caller's value that an error message repeats. */
const SHOWN_MAX = 40;

function shown(value: unknown): string {
  if (typeof value === "string") {
    return JSON.stringify(value.length > SHOWN_MAX ? `${value.slice(0, SHOWN_MAX)}…` : value);
  }
  return typeof value === "number" || typeof value === "bigint" || typeof value === "boolean" || value == null
    ? String(value)
    : `a value of type ${typeof value}`;
}

/**
 * The quantity a string states, in units of `1 / divisor` of the smallest unit of `units`, or
 * `undefined` when the string is not a quantity, names another unit, or is not a whole number.
 */
function wholeQuantity(text: string, units: ReadonlyMap<string, bigint>, divisor: bigint): bigint | undefined {
  const match = QUANTITY.exec(text);
  if (match === null) {
    return undefined;
  }
  const [, whole = "", fraction = "", unit = ""] = match;
  const factor = units.get(unit);
  if (factor === undefined) {
    return undefined;
  }
  const scale = 10n ** BigInt(fraction.length);
  const scaled = BigInt(whole + fraction) * factor;
  const denominator = scale * divisor;
  return scaled % denominator === 0n ? scaled / denominator : undefined;
}

function positiveSafeInteger(quantity: bigint | undefined): number | undefined {
  return quantity !== undefined && quantity > 0n && quantity <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(quantity)
    : undefined;
}

function refuse(what: string, expected: string, value: unknown): never {
  if (typeof value !== "number" && typeof value !== "string") {
    throw new TypeError(`${what} must be ${expected}; got ${shown(value)}`);
  }
  throw new RangeError(`${what} must be ${expected}; got ${shown(value)}`);
}

/** A positive integer, as `cpu` is. */
export function positiveInteger(value: unknown, what: string): number {
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) {
    return value;
  }
  return refuse(what, "a positive integer", value);
}

/** Memory or disk, in MiB. */
export function mebibytes(value: unknown, what: string): number {
  const expected =
    'a positive integer number of MiB, or a string with a binary unit that is a whole number of MiB, such as "512MiB" or "4GiB"';
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value > 0 ? value : refuse(what, expected, value);
  }
  if (typeof value === "string") {
    return positiveSafeInteger(wholeQuantity(value, SIZE_UNITS, KIB_PER_MIB)) ?? refuse(what, expected, value);
  }
  return refuse(what, expected, value);
}

/** A lifetime or a timeout, in seconds. */
export function seconds(value: unknown, what: string): number {
  const expected =
    'a positive integer number of seconds, or a string that is a whole number of seconds, such as "90s", "10m", "2h" or "1d"';
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value > 0 ? value : refuse(what, expected, value);
  }
  if (typeof value === "string") {
    return positiveSafeInteger(wholeQuantity(value, DURATION_UNITS, 1n)) ?? refuse(what, expected, value);
  }
  return refuse(what, expected, value);
}
