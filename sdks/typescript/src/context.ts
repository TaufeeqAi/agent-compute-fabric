/**
 * The configuration of one client, resolved and checked once, at construction.
 *
 * Three values come from the caller or from the environment, in that order, and from nowhere else:
 * the credential (`ACF_API_KEY`), the endpoint (`ACF_BASE_URL`) and the project (`ACF_PROJECT`).
 * A project that neither names is the one the credential is bound to: it is read from the platform
 * once, on first need, and kept.
 *
 * Everything that cannot work is refused here, before any request, with a `ConfigurationError`
 * whose message never repeats the endpoint or the credential it was given: both may hold a secret.
 */

import { ConfigurationError, UnexpectedResponseError } from "./errors.js";
import { type OptionNames, optionsOf, segment } from "./inputs.js";
import type { Call } from "./telemetry.js";
import { systemClock, systemSleep, Transport } from "./transport.js";
import type { Clock, FabricOptions, Fetch, Sleep } from "./types.js";

const DEFAULT_TIMEOUT = 120;
const DEFAULT_MAX_RETRIES = 2;
const DEFAULT_FOLLOW_MAX = 1800;
/** The platform remembers a key for a day; the last retry of a call must arrive an hour before it forgets. */
const DEFAULT_RETRY_TOTAL_MAX = 24 * 3600 - 3600;
/** The longest delay the platform's timer takes, in seconds. A longer one would fire at once. */
const TIMEOUT_MAX = 2_147_483;

const OPTION_NAMES: OptionNames<FabricOptions> = {
  apiKey: true,
  baseUrl: true,
  project: true,
  timeout: true,
  maxRetries: true,
  followMax: true,
  retryTotalMax: true,
  allowInsecureHttp: true,
  dangerouslyAllowBrowser: true,
  fetch: true,
  clock: true,
  sleep: true,
  random: true,
};

/**
 * A variable of the environment, where the runtime has one. `process` is looked up on the global
 * object rather than named, so that this module loads in a runtime that has no such thing.
 */
function environment(name: string): string | undefined {
  try {
    const scope = globalThis as { process?: { env?: { [variable: string]: string | undefined } } };
    const value = scope.process?.env?.[name];
    return typeof value === "string" && value !== "" ? value : undefined;
  } catch {
    // A runtime that has an environment and does not let this code read it.
    return undefined;
  }
}

/** A page: a `window` that has a `document`. A worker, a server and a command-line runtime are not. */
function inBrowserPage(): boolean {
  const scope = globalThis as { window?: { document?: unknown } | null };
  return typeof scope.window === "object" && scope.window !== null && scope.window.document != null;
}

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(hostname);
}

function credentialOf(value: unknown): string {
  if (value === undefined) {
    throw new ConfigurationError("No credential: pass apiKey, or set the environment variable ACF_API_KEY.");
  }
  if (typeof value !== "string" || value === "") {
    throw new ConfigurationError("apiKey must be a string that is not empty.");
  }
  // Checked here because a transport that meets a character it cannot send may quote the whole
  // header, credential included, in its error.
  if (!/^[\x21-\x7e]+$/.test(value)) {
    throw new ConfigurationError(
      "apiKey holds a character that cannot be sent in a header: a space, a line break or one outside ASCII. " +
        "Check for a trailing line break where the key is read from.",
    );
  }
  return value;
}

/** The endpoint, without a trailing slash. The message of a refusal never repeats the value. */
function endpointOf(value: unknown, allowInsecureHttp: boolean): string {
  if (value === undefined) {
    throw new ConfigurationError("No endpoint: pass baseUrl, or set the environment variable ACF_BASE_URL.");
  }
  if (typeof value !== "string") {
    throw new ConfigurationError("baseUrl must be a string.");
  }
  // URL parsing removes a tab or a line break, and trims a space, without saying so: the address that
  // is then used is not the one that was written. An address is used as it was written, or not at all.
  if (/[\s\p{Cc}\p{Cf}]/u.test(value)) {
    throw new ConfigurationError("baseUrl must not contain a space, a line break or a character that does not show.");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigurationError("baseUrl is not a URL. It must look like https://acf.example");
  }
  if (url.username !== "" || url.password !== "") {
    throw new ConfigurationError(
      "baseUrl must not carry user information: a credential is never accepted inside a URL. " +
        "Pass the credential as apiKey, or set ACF_API_KEY.",
    );
  }
  if (value.includes("?") || value.includes("#")) {
    throw new ConfigurationError(
      "baseUrl must not carry a query string or a fragment: a credential is never accepted inside a URL, " +
        "and the SDK writes the query of every request itself.",
    );
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new ConfigurationError(`baseUrl must be https://, or http:// to a loopback address; its scheme is ${url.protocol}`);
  }
  if (url.protocol === "http:" && !isLoopback(url.hostname) && !allowInsecureHttp) {
    throw new ConfigurationError(
      "baseUrl is http:// to an address that is not loopback: the credential would travel in clear text. " +
        "Use https://, or pass allowInsecureHttp: true to accept that.",
    );
  }
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

function numberOf(
  value: unknown,
  name: string,
  fallback: number,
  rule: { readonly integer?: boolean; readonly aboveZero?: boolean; readonly max?: number },
): number {
  if (value == null) {
    return fallback;
  }
  const max = rule.max ?? Number.MAX_SAFE_INTEGER;
  const valid =
    typeof value === "number" &&
    Number.isFinite(value) &&
    value <= max &&
    (rule.aboveZero === true ? value > 0 : value >= 0) &&
    (rule.integer !== true || Number.isInteger(value));
  if (!valid) {
    const kind = rule.integer === true ? "an integer" : "a number of seconds";
    const range = `${rule.aboveZero === true ? "above 0" : "0 or more"}${rule.max === undefined ? "" : ` and at most ${rule.max}`}`;
    throw new ConfigurationError(`${name} must be ${kind}, ${range}; got ${String(value)}`);
  }
  return value;
}

/** The function the caller gave for `name`, or the platform's, which is looked up only when it is needed. */
function functionOf<Callable>(value: Callable | null | undefined, name: string, platform: () => Callable): Callable {
  if (value == null) {
    return platform();
  }
  if (typeof value !== "function") {
    throw new ConfigurationError(`${name} must be a function.`);
  }
  return value;
}

/** The platform's `fetch`, for a client that was given none. */
function platformFetch(): Fetch {
  if (typeof globalThis.fetch !== "function") {
    throw new ConfigurationError("This runtime has no fetch. Pass one as the option fetch.");
  }
  // Looked up at each request, and called on the global object: `fetch` refuses any other receiver,
  // and an application may replace the global after this client is made.
  return (url, request) => globalThis.fetch(url, request);
}

/** What the resources of one client share. Holds no state of the server except the project. */
export class ClientContext {
  readonly baseUrl: string;
  readonly followMax: number;
  readonly clock: Clock;
  readonly sleep: Sleep;
  readonly transport: Transport;
  #project: string | undefined;
  #lookup: Promise<string> | undefined;

  constructor(options: FabricOptions) {
    let known: FabricOptions;
    try {
      known = optionsOf(options, OPTION_NAMES, "new Fabric");
    } catch (error) {
      throw new ConfigurationError(error instanceof Error ? error.message : "new Fabric: the options cannot be read");
    }
    const apiKey = credentialOf(known.apiKey ?? environment("ACF_API_KEY"));
    if (inBrowserPage() && known.dangerouslyAllowBrowser !== true) {
      throw new ConfigurationError(
        "This client was constructed in a browser page. A credential in a page is published to everyone who can " +
          "open the page. Call the platform from a server instead. If the page is one only you can open, pass " +
          "dangerouslyAllowBrowser: true.",
      );
    }
    this.baseUrl = endpointOf(known.baseUrl ?? environment("ACF_BASE_URL"), known.allowInsecureHttp === true);

    const project = known.project ?? environment("ACF_PROJECT");
    if (project !== undefined) {
      try {
        segment(project, "project");
      } catch (error) {
        throw new ConfigurationError(error instanceof Error ? error.message : "project cannot be used");
      }
      this.#project = project;
    }

    this.followMax = numberOf(known.followMax, "followMax", DEFAULT_FOLLOW_MAX, {});
    this.clock = functionOf(known.clock, "clock", () => systemClock);
    this.sleep = functionOf(known.sleep, "sleep", () => systemSleep);
    this.transport = new Transport({
      apiKey,
      baseUrl: this.baseUrl,
      fetch: functionOf(known.fetch, "fetch", platformFetch),
      timeout: numberOf(known.timeout, "timeout", DEFAULT_TIMEOUT, { aboveZero: true, max: TIMEOUT_MAX }),
      maxRetries: numberOf(known.maxRetries, "maxRetries", DEFAULT_MAX_RETRIES, { integer: true }),
      retryTotalMax: numberOf(known.retryTotalMax, "retryTotalMax", DEFAULT_RETRY_TOTAL_MAX, {}),
      clock: this.clock,
      sleep: this.sleep,
      random: functionOf(known.random, "random", () => Math.random),
    });
  }

  /** The project, once it is known. For the text form of a client only: requests use `projectPath`. */
  get project(): string | undefined {
    return this.#project;
  }

  /** `/v1/projects/{project}`, the prefix of every route that acts in the project. */
  async projectPath(call: Call): Promise<string> {
    return `/v1/projects/${segment(await this.#projectOf(call), "project")}`;
  }

  /**
   * The configured project, or the one the credential is bound to. Calls that need it at the same
   * moment share one lookup. A lookup that fails is not remembered, and a caller that only waited
   * for it asks for itself, so that one caller abandoning its call never fails another's.
   */
  async #projectOf(call: Call): Promise<string> {
    for (;;) {
      if (this.#project !== undefined) {
        return this.#project;
      }
      if (this.#lookup === undefined) {
        const lookup = this.#boundProject(call).finally(() => {
          this.#lookup = undefined;
        });
        this.#lookup = lookup;
        return lookup;
      }
      try {
        return await this.#lookup;
      } catch {
        call.throwIfAbandoned();
      }
    }
  }

  async #boundProject(call: Call): Promise<string> {
    const answer = await this.transport.request({ method: "GET", path: "/v1/auth/whoami", call });
    const project = answer.body["project_id"];
    if (typeof project !== "string" || project === "") {
      throw new UnexpectedResponseError("GET /v1/auth/whoami was answered without a project_id.", {
        status: answer.status,
        requestId: answer.requestId,
      });
    }
    this.#project = project;
    return project;
  }
}
