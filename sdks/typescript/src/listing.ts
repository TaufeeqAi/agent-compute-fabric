/**
 * A listing, followed to its end.
 *
 * A page names the next one with an opaque cursor, and the host may forget a cursor before the
 * client comes back with it (`CURSOR_EXPIRED`). The listing is then begun again from the start. A
 * pass is collected in full before any item is handed out: a caller who had already received the
 * items of an abandoned pass would see them a second time.
 */

import type { ClientContext } from "./context.js";
import { CursorExpiredError, UnexpectedResponseError } from "./errors.js";
import type { Call } from "./telemetry.js";
import { stringOf } from "./view.js";

/** How often one listing is begun again after `CURSOR_EXPIRED`. The next one is the caller's to see. */
export const LIST_RESTARTS_MAX = 3;

export interface Listing<Item> {
  readonly items: Item[];
  /** The request id of the last page: the answer that showed where the listing ends. */
  readonly requestId: string | undefined;
}

async function onePass<Item>(
  context: ClientContext,
  call: Call,
  path: string,
  wrap: (view: unknown, requestId: string | undefined) => Item,
): Promise<Listing<Item>> {
  const items: Item[] = [];
  const visited = new Set<string>();
  let cursor: string | undefined;
  for (;;) {
    const answer = await context.transport.request({ method: "GET", path, query: { cursor }, call });
    const source = { what: `A page of GET ${path}`, requestId: answer.requestId };
    const page = answer.body;
    if (!Array.isArray(page["items"]) || typeof page["more"] !== "boolean") {
      throw new UnexpectedResponseError(`${source.what} has no items or does not say whether more follow.`, {
        status: answer.status,
        requestId: answer.requestId,
      });
    }
    for (const view of page["items"] as unknown[]) {
      items.push(wrap(view, answer.requestId));
    }
    if (!page["more"]) {
      return { items, requestId: answer.requestId };
    }
    cursor = stringOf(page, "next_cursor", source);
    if (visited.has(cursor)) {
      throw new UnexpectedResponseError(`${source.what} names a page already read as the next: the listing would never end.`, {
        status: answer.status,
        requestId: answer.requestId,
      });
    }
    visited.add(cursor);
  }
}

/** Every item of the listing at `path`, in the order the platform gave them. */
export async function collect<Item>(
  context: ClientContext,
  call: Call,
  path: string,
  wrap: (view: unknown, requestId: string | undefined) => Item,
): Promise<Listing<Item>> {
  for (let restarts = 0; ; restarts += 1) {
    try {
      return await onePass(context, call, path, wrap);
    } catch (error) {
      if (!(error instanceof CursorExpiredError) || restarts >= LIST_RESTARTS_MAX) {
        throw error;
      }
    }
  }
}
