/**
 * Executions: one command run in one generation of one sandbox, and its output.
 *
 * A command that exits with a status other than 0 is a result, not an error: the operation that ran
 * it succeeded, and the caller reads `exit_code`. Output is guest data. The SDK hands it over as
 * the bytes the guest wrote, and turns it into text only when asked, with the encoding and the
 * error policy the caller names.
 */

import type { ClientContext } from "./context.js";
import { UnexpectedResponseError } from "./errors.js";
import { keyOf } from "./idempotency.js";
import { followBound, oneOf, type OptionNames, optionalInteger, optionalText, optionsOf, segment, streamOf } from "./inputs.js";
import { type Operation, resultOf, submit } from "./operation.js";
import { type Call, traced } from "./telemetry.js";
import type {
  CallOptions,
  Durations,
  ExecutionView,
  MutationOptions,
  Normalized,
  OutputChunkView,
  OutputOptions,
  OutputStream,
  OutputSummary,
  Raw,
  TextOptions,
} from "./types.js";
import { emptyObject, expose, hidden, integerOf, none, objectOf, type Shape, type Source, stringOf } from "./view.js";

const OUTPUT_CHUNK: Shape<OutputChunkView> = {
  execution_id: true,
  stream: true,
  offset: true,
  data_base64: true,
  next_offset: true,
  eof: true,
  stored_bytes: true,
  produced_bytes: true,
  completeness: true,
  completeness_raw: none,
  provenance: () => "GUEST_REPORTED",
};

const EXECUTION: Shape<ExecutionView> = {
  execution_id: true,
  operation_id: true,
  project: true,
  sandbox_id: none,
  generation: none,
  state: true,
  state_raw: none,
  terminal: true,
  status: none,
  status_raw: none,
  exit_code: none,
  signal: none,
  durations: none,
  stdout: none,
  stderr: none,
  host_backstop_fired: none,
  runtime_ended: none,
  evidence_status: none,
  evidence_status_raw: none,
  note: none,
  provenance: emptyObject,
};

function bytesOf(base64: unknown, source: Source): Uint8Array {
  let binary: string;
  try {
    if (typeof base64 !== "string") {
      throw new TypeError("not a string");
    }
    binary = atob(base64);
  } catch {
    throw new UnexpectedResponseError(`${source.what} carries data that is not base64.`, { requestId: source.requestId });
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/** A slice of one stream of an execution's stored output. */
export class OutputChunk implements Normalized<OutputChunkView> {
  declare readonly execution_id: string;
  declare readonly stream: string;
  declare readonly offset: number;
  declare readonly data_base64: string;
  declare readonly next_offset: number;
  declare readonly eof: boolean;
  declare readonly stored_bytes: number;
  declare readonly produced_bytes: number;
  declare readonly completeness: string;
  declare readonly completeness_raw: string | null;
  declare readonly provenance: string;
  /** The bytes of the slice. Guest data: the guest wrote them, and nothing vouches for them. */
  declare readonly data: Uint8Array;
  /** The view exactly as the server sent it, with every member this version does not know. */
  declare readonly raw: Raw<OutputChunkView>;
  /** The request id of the answer that carried this view. */
  declare readonly requestId: string | undefined;

  /** @internal */
  constructor(view: unknown, requestId: string | undefined) {
    const source = { what: "A chunk of output", requestId };
    const checked = objectOf(view, source);
    integerOf(checked, "next_offset", source);
    if (typeof checked["eof"] !== "boolean") {
      throw new UnexpectedResponseError(`${source.what} does not say whether the stream ends here.`, { requestId });
    }
    const data = bytesOf(checked["data_base64"], source);
    expose<OutputChunkView>(this, checked, OUTPUT_CHUNK);
    const own = this as { data: Uint8Array; requestId: string | undefined };
    own.data = data;
    own.requestId = requestId;
  }

  /** The view as the server sent it. */
  toJSON(): Raw<OutputChunkView> {
    return this.raw;
  }

  toString(): string {
    return `OutputChunk(${this.execution_id}, stream=${this.stream}, offset=${this.offset}, bytes=${this.data.length}, eof=${this.eof})`;
  }
}

function executionPath(executionId: string): string {
  return `/executions/${segment(executionId, "executionId")}`;
}

/**
 * Asks the host to cancel an execution, and follows the cancel to its end. Cancelling is an
 * explicit request of its own, with its own key: nothing else in the SDK ever ends an execution.
 */
export function cancelExecution(
  context: ClientContext,
  call: Call,
  projectPath: string,
  executionId: string,
  key: string,
  followMax: number,
): Promise<Operation> {
  return submit(context, call, projectPath, { method: "POST", path: `${executionPath(executionId)}/cancel`, key, followMax });
}

const CALL_OPTIONS: OptionNames<CallOptions> = { signal: true };
const OUTPUT_OPTIONS: OptionNames<OutputOptions> = { offset: true, maxBytes: true, signal: true };
const TEXT_OPTIONS: OptionNames<TextOptions> = { encoding: true, errors: true, signal: true };
const CANCEL_OPTIONS: OptionNames<MutationOptions> = { idempotencyKey: true, followMax: true, signal: true };

/** Where a view of an execution came from. */
interface Origin {
  readonly requestId: string | undefined;
  /** The operation whose result the view is, when a mutation produced it. */
  readonly operation?: Operation | undefined;
}

/** A handle on one execution. It holds the view it last saw; `refresh` reads it again. */
export class Execution implements Normalized<ExecutionView> {
  declare readonly execution_id: string;
  declare readonly operation_id: string;
  declare readonly project: string;
  declare readonly sandbox_id: string | null;
  declare readonly generation: number | null;
  declare readonly state: string;
  declare readonly state_raw: string | null;
  declare readonly terminal: boolean;
  declare readonly status: string | null;
  declare readonly status_raw: string | null;
  declare readonly exit_code: number | null;
  declare readonly signal: number | null;
  declare readonly durations: Durations | null;
  declare readonly stdout: OutputSummary | null;
  declare readonly stderr: OutputSummary | null;
  declare readonly host_backstop_fired: boolean | null;
  declare readonly runtime_ended: boolean | null;
  declare readonly evidence_status: string | null;
  declare readonly evidence_status_raw: string | null;
  declare readonly note: string | null;
  declare readonly provenance: { readonly [field: string]: string };
  /** The view exactly as the server sent it, with every member this version does not know. */
  declare readonly raw: Raw<ExecutionView>;
  /** The request id of the answer that carried this view. */
  declare readonly requestId: string | undefined;
  /** The operation whose result this view is. `undefined` after a read. */
  declare readonly operation: Operation | undefined;
  readonly #context: ClientContext;

  /** @internal */
  constructor(context: ClientContext, view: unknown, origin: Origin) {
    this.#context = context;
    this.#show(view, origin);
  }

  #show(view: unknown, origin: Origin): void {
    const source = { what: "An execution", requestId: origin.requestId };
    const checked = objectOf(view, source);
    const id = stringOf(checked, "execution_id", source);
    if ("execution_id" in this && id !== this.execution_id) {
      throw new UnexpectedResponseError(`Execution ${this.execution_id} was answered with the view of ${id}.`, {
        requestId: origin.requestId,
      });
    }
    expose<ExecutionView>(this, checked, EXECUTION);
    const own = this as { requestId: string | undefined };
    own.requestId = origin.requestId;
    hidden(this, "operation", origin.operation);
  }

  async #chunk(call: Call, stream: OutputStream, offset: number, maxBytes: number | undefined): Promise<OutputChunk> {
    const context = this.#context;
    const answer = await context.transport.request({
      method: "GET",
      path: `${await context.projectPath(call)}${executionPath(this.execution_id)}/output`,
      query: { stream, offset, max_bytes: maxBytes },
      call,
    });
    return new OutputChunk(answer.body, answer.requestId);
  }

  /** Every byte the stream stored, chunk after chunk until the platform says the stream ends. */
  async #all(call: Call, stream: OutputStream): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    let length = 0;
    let offset = 0;
    for (;;) {
      const chunk = await this.#chunk(call, stream, offset, undefined);
      chunks.push(chunk.data);
      length += chunk.data.length;
      if (chunk.eof) {
        break;
      }
      if (chunk.next_offset <= offset) {
        throw new UnexpectedResponseError(
          `The ${stream} of execution ${this.execution_id} does not advance past offset ${offset}: reading it would never end.`,
          { requestId: chunk.requestId },
        );
      }
      offset = chunk.next_offset;
    }
    const bytes = new Uint8Array(length);
    let position = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, position);
      position += chunk.length;
    }
    return bytes;
  }

  /** One slice of the stored output of a stream. `data` holds its bytes. */
  output(stream?: OutputStream, options?: OutputOptions): Promise<OutputChunk> {
    return traced("execution.output", options?.signal, async (call) => {
      const known = optionsOf(options, OUTPUT_OPTIONS, "execution.output");
      const offset = optionalInteger(known.offset, 0, "offset") ?? 0;
      const maxBytes = optionalInteger(known.maxBytes, 1, "maxBytes");
      return this.#chunk(call, streamOf(stream), offset, maxBytes);
    });
  }

  /** The whole stored output of a stream, as bytes. */
  read(stream?: OutputStream, options?: CallOptions): Promise<Uint8Array> {
    return traced("execution.read", options?.signal, async (call) => {
      optionsOf(options, CALL_OPTIONS, "execution.read");
      return this.#all(call, streamOf(stream));
    });
  }

  /**
   * The whole stored output of a stream, as text. The encoding and the error policy are the
   * caller's to name, because the bytes are whatever the guest wrote: `"strict"` (the default)
   * throws on bytes that are not valid in the encoding, `"replace"` substitutes U+FFFD.
   */
  text(stream?: OutputStream, options?: TextOptions): Promise<string> {
    return traced("execution.text", options?.signal, async (call) => {
      const known = optionsOf(options, TEXT_OPTIONS, "execution.text");
      const encoding = optionalText(known.encoding, "encoding") ?? "utf-8";
      const errors = oneOf(known.errors, ["strict", "replace"] as const, "errors", "strict");
      let decoder: TextDecoder;
      try {
        // ignoreBOM keeps a leading byte-order mark as the character it is: the text is the bytes, decoded.
        decoder = new TextDecoder(encoding, { fatal: errors === "strict", ignoreBOM: true });
      } catch {
        throw new RangeError(`encoding must be one this runtime can decode; got ${JSON.stringify(encoding)}`);
      }
      return decoder.decode(await this.#all(call, streamOf(stream)));
    });
  }

  /**
   * Asks the host to cancel the execution, follows the cancel, and updates this handle from its
   * result. This is the only way the SDK ends an execution.
   */
  cancel(options?: MutationOptions): Promise<this> {
    const context = this.#context;
    return traced("execution.cancel", options?.signal, async (call) => {
      const known = optionsOf(options, CANCEL_OPTIONS, "execution.cancel");
      const key = keyOf(known.idempotencyKey);
      const followMax = followBound(known.followMax, context.followMax);
      const projectPath = await context.projectPath(call);
      const operation = await cancelExecution(context, call, projectPath, this.execution_id, key, followMax);
      this.#show(resultOf(context, operation, "execution", key), { requestId: operation.requestId, operation });
      return this;
    });
  }

  /** Reads the execution again and updates this handle. */
  refresh(options?: CallOptions): Promise<this> {
    const context = this.#context;
    return traced("execution.refresh", options?.signal, async (call) => {
      optionsOf(options, CALL_OPTIONS, "execution.refresh");
      const answer = await context.transport.request({
        method: "GET",
        path: `${await context.projectPath(call)}${executionPath(this.execution_id)}`,
        call,
      });
      this.#show(answer.body, { requestId: answer.requestId });
      return this;
    });
  }

  /** The view as the server sent it. */
  toJSON(): Raw<ExecutionView> {
    return this.raw;
  }

  toString(): string {
    return `Execution(${this.execution_id}, state=${this.state}, status=${this.status ?? "none"}, exit_code=${this.exit_code ?? "none"})`;
  }
}

/** `fabric.executions`: find an execution by its identifier. */
export class Executions {
  readonly #context: ClientContext;

  /** @internal */
  constructor(context: ClientContext) {
    this.#context = context;
  }

  /**
   * A handle on an execution that was not read: no request is made.
   *
   * The handle holds the identifier and nothing else until `cancel()` or `refresh()`. It is the way
   * to cancel an execution, or to read its output, by an identifier that is already known. A cancel
   * takes a privilege away: it is sent at once, and never waits behind a read that a limit could
   * refuse.
   */
  handle(executionId: string): Execution {
    // Checked as every identifier that becomes part of a path is, and kept as the caller wrote it.
    executionPath(executionId);
    return new Execution(this.#context, { execution_id: executionId }, { requestId: undefined });
  }

  /** Reads the status and the result of an execution. */
  get(executionId: string, options?: CallOptions): Promise<Execution> {
    const context = this.#context;
    return traced("executions.get", options?.signal, async (call) => {
      optionsOf(options, CALL_OPTIONS, "executions.get");
      const path = executionPath(executionId);
      const answer = await context.transport.request({ method: "GET", path: `${await context.projectPath(call)}${path}`, call });
      return new Execution(context, answer.body, { requestId: answer.requestId });
    });
  }
}
