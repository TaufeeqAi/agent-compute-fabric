/**
 * How a JSON view becomes a returned object.
 *
 * A returned object exposes every member of its view under the name the server sent, and keeps the
 * JSON exactly as received in `raw`. A member the server left out reads as the default of its
 * schema rather than `undefined`. A member this version does not know stays in `raw` and is
 * otherwise ignored. A value of a vocabulary is copied as the string it is, known or not.
 *
 * Only the members the SDK itself acts on (an identifier, a generation, a cursor) are checked. An
 * answer that lacks one of those cannot be acted on, and is an `UnexpectedResponseError`.
 */

import { UnexpectedResponseError } from "./errors.js";
import type { JsonObject } from "./types.js";

/**
 * Every member of a view: `true` for one the server always sends, and for one it may leave out a
 * function that makes its default. The mapped type makes a missing member, a misspelled one, and a
 * default of the wrong type compile errors, so a view and the object that exposes it cannot drift.
 */
export type Shape<View> = {
  readonly [Member in keyof View]-?: undefined extends View[Member] ? () => Exclude<View[Member], undefined> : true;
};

export const none = (): null => null;
export const emptyList = (): readonly never[] => [];
export const emptyObject = (): { readonly [member: string]: never } => ({});
export const no = (): boolean => false;

/** Where an answer came from, for the errors about it. */
export interface Source {
  readonly what: string;
  readonly requestId: string | undefined;
}

export function objectOf(value: unknown, source: Source): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new UnexpectedResponseError(`${source.what} is not a JSON object.`, { requestId: source.requestId });
  }
  return value as JsonObject;
}

export function stringOf(view: JsonObject, member: string, source: Source): string {
  const value = view[member];
  if (typeof value !== "string" || value === "") {
    throw new UnexpectedResponseError(`${source.what} has no ${member}.`, { requestId: source.requestId });
  }
  return value;
}

export function integerOf(view: JsonObject, member: string, source: Source): number {
  const value = view[member];
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new UnexpectedResponseError(`${source.what} has no integer ${member}.`, { requestId: source.requestId });
  }
  return value;
}

/** Sets a member that printing the object does not show. */
export function hidden(target: object, member: string, value: unknown): void {
  Object.defineProperty(target, member, { value, writable: true, configurable: true, enumerable: false });
}

/**
 * Copies a view onto the object that exposes it. `raw` is the view as received; it is hidden from
 * printing, so that printing the object shows each member once.
 */
export function expose<View>(target: object, view: JsonObject, shape: Shape<View>): void {
  const members = target as { [member: string]: unknown };
  for (const [member, rule] of Object.entries<true | (() => unknown)>(shape)) {
    members[member] = rule === true ? view[member] : (view[member] ?? rule());
  }
  hidden(target, "raw", view);
}
