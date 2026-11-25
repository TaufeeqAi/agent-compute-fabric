/** The version of this package. A test holds it equal to `version` in `package.json`. */
export const VERSION = "0.1.0";

/** The one major of the public API that this major of the SDK speaks. */
export const API_VERSION = "v1";

/** Sent with every request. It names the SDK and nothing about the machine or the user. */
export const USER_AGENT = `agent-compute-typescript/${VERSION}`;
