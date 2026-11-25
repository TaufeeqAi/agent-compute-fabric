/**
 * Idempotency keys.
 *
 * One key stands for one intent. It is fixed before the first attempt and sent, unchanged, with
 * every retry of that call, so that a lost answer can be asked for again without creating a second
 * operation. Nothing in the SDK ever replaces a key to get past an answer it does not like.
 */

/** The platform's bound on a key. */
export const KEY_MAX_LENGTH = 255;

/** `sandboxes.create` issues its start under the caller's key with this suffix. */
export const START_SUFFIX = ":start";

/** `sandboxes.create` issues the destroy that follows a failed start under the caller's key with this suffix. */
export const DESTROY_SUFFIX = ":destroy";

/** The longest key `sandboxes.create` accepts: the longest derived key must still be a valid key. */
export const CREATE_KEY_MAX_LENGTH = KEY_MAX_LENGTH - Math.max(START_SUFFIX.length, DESTROY_SUFFIX.length);

/** A fresh key: a random UUID, version 4. */
export function newKey(): string {
  return globalThis.crypto.randomUUID();
}

/**
 * The caller's key, checked: 1 to `maxLength` characters, each in the range 0x21 to 0x7E. The
 * platform compares keys byte for byte and never normalizes them, so a key that would have to be
 * trimmed or re-encoded to be sent is refused here rather than altered.
 */
export function checkedKey(key: unknown, maxLength: number = KEY_MAX_LENGTH): string {
  if (typeof key !== "string") {
    throw new TypeError(`idempotencyKey must be a string; got a value of type ${typeof key}`);
  }
  if (key.length === 0 || key.length > maxLength) {
    throw new RangeError(`idempotencyKey must be 1 to ${maxLength} characters long; got ${key.length}`);
  }
  for (let index = 0; index < key.length; index += 1) {
    const unit = key.charCodeAt(index);
    if (unit < 0x21 || unit > 0x7e) {
      const code = unit.toString(16).toUpperCase().padStart(4, "0");
      throw new RangeError(
        `idempotencyKey may only hold characters in the range 0x21 to 0x7E (no space, no control character, ` +
          `nothing outside ASCII); found U+${code} at index ${index}`,
      );
    }
  }
  return key;
}

/** The key of a logical call: the caller's, checked, or a fresh one. */
export function keyOf(supplied: string | null | undefined, maxLength: number = KEY_MAX_LENGTH): string {
  return supplied == null ? newKey() : checkedKey(supplied, maxLength);
}
