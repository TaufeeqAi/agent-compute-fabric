/**
 * One span per logical call, and only into an OpenTelemetry installation the application set up.
 *
 * The SDK does not import OpenTelemetry, does not depend on it, and exports nothing by itself. An
 * application that sets OpenTelemetry up registers its tracer provider in a well-known slot of the
 * global object, which is how the copies of the OpenTelemetry API in one process find each other.
 * This module reads that slot. When it is empty there is no span and no cost. Reading the slot,
 * rather than importing the API, works the same under every package manager, bundler and runtime,
 * and cannot fail a build where OpenTelemetry is absent.
 *
 * Telemetry never changes an outcome: every call into the application's tracer is guarded, and a
 * tracer that throws is ignored.
 *
 * A span carries the name of the call, the retries, and for a failure its class, code and request
 * id. It never carries the credential, an argument, an environment value or output.
 */

import { codeOf, FabricError } from "./errors.js";
import { VERSION } from "./version.js";

/** The slot of the OpenTelemetry API, major 1. */
const OPENTELEMETRY_GLOBAL = Symbol.for("opentelemetry.js.api.1");

/** `SpanKind.CLIENT` and `SpanStatusCode.ERROR` of the OpenTelemetry API. */
const SPAN_KIND_CLIENT = 2;
const SPAN_STATUS_ERROR = 2;

/** The instrumentation scope the spans are recorded under. */
const SCOPE = "agent-compute-typescript";

type Attributes = { readonly [name: string]: string | number | boolean };

/** The part of an OpenTelemetry span this module uses. */
interface Span {
  setAttribute(name: string, value: string | number | boolean): unknown;
  addEvent(name: string, attributes?: Attributes): unknown;
  setStatus(status: { code: number; message?: string }): unknown;
  end(): void;
}

interface Tracer {
  startActiveSpan<Result>(name: string, options: { kind: number }, body: (span: Span) => Result): Result;
}

function applicationTracer(): Tracer | undefined {
  const registry = (globalThis as { [OPENTELEMETRY_GLOBAL]?: { trace?: { getTracer?: unknown } } })[OPENTELEMETRY_GLOBAL];
  const provider = registry?.trace;
  if (provider === undefined || typeof provider.getTracer !== "function") {
    return undefined;
  }
  const tracer = (provider.getTracer as (name: string, version: string) => Partial<Tracer> | undefined).call(
    provider,
    SCOPE,
    VERSION,
  );
  return typeof tracer?.startActiveSpan === "function" ? (tracer as Tracer) : undefined;
}

function guarded(action: () => unknown): void {
  try {
    action();
  } catch {
    // The application's tracer failed. The call it was recording is unaffected.
  }
}

/** One logical call of the SDK: what its requests share. */
export class Call {
  /** The caller's signal. Aborting it abandons the call and cancels nothing on the server. */
  readonly signal: AbortSignal | undefined;
  readonly #span: Span | undefined;

  constructor(signal: AbortSignal | undefined, span: Span | undefined) {
    this.signal = signal;
    this.#span = span;
  }

  /** Stops the call here when the caller has abandoned it. */
  throwIfAbandoned(): void {
    this.signal?.throwIfAborted();
  }

  /** A retry is never silent: each one is an event on the span, with the attempt it follows. */
  retried(attempt: number, delaySeconds: number, cause: string): void {
    const span = this.#span;
    if (span !== undefined) {
      guarded(() => span.addEvent("retry", { "acf.attempt": attempt, "acf.delay_s": delaySeconds, "acf.cause": cause }));
    }
  }

  /** Records how the call ended, and ends the span. */
  finish(error?: unknown): void {
    const span = this.#span;
    if (span === undefined) {
      return;
    }
    if (error !== undefined) {
      // The class name only. A message may quote what the caller passed; a span must not.
      const type = error instanceof Error ? error.name : "Error";
      guarded(() => span.setStatus({ code: SPAN_STATUS_ERROR, message: type }));
      guarded(() => span.setAttribute("error.type", type));
      const code = codeOf(error);
      if (code !== undefined) {
        guarded(() => span.setAttribute("acf.code", code));
      }
      if (error instanceof FabricError && error.requestId !== undefined) {
        const requestId = error.requestId;
        guarded(() => span.setAttribute("acf.request_id", requestId));
      }
    }
    guarded(() => span.end());
  }
}

/**
 * Runs one logical call. When the application has registered a tracer provider the call is one
 * span, active while the call runs, so that the application's own HTTP spans nest under it.
 */
export async function traced<Result>(
  name: string,
  signal: AbortSignal | undefined,
  body: (call: Call) => Promise<Result>,
): Promise<Result> {
  // Checked before a span is started, so that a call that never begins leaves no span open.
  if (signal != null && typeof (signal as Partial<AbortSignal>).throwIfAborted !== "function") {
    throw new TypeError("signal must be an AbortSignal");
  }
  const run = async (span: Span | undefined): Promise<Result> => {
    const call = new Call(signal, span);
    try {
      const result = await body(call);
      call.finish();
      return result;
    } catch (error) {
      call.finish(error);
      throw error;
    }
  };

  // The call must run exactly once, whatever the application's tracer does with the callback:
  // call it, not call it, call it twice, or throw before or after. A second run would be a second
  // request under a second key.
  const once: { call?: Promise<Result> } = {};
  try {
    applicationTracer()?.startActiveSpan(`acf.${name}`, { kind: SPAN_KIND_CLIENT }, (span) => {
      once.call ??= run(span);
      return once.call;
    });
  } catch {
    // The tracer failed. If it failed after the call began, `once.call` is that call.
  }
  once.call ??= run(undefined);
  return once.call;
}
