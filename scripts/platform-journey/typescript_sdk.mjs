// The developer journey with the TypeScript SDK, against a platform that is running.
//
//   (cd sdks/typescript && npm ci && npm run build)
//   ACF_BASE_URL=https://acf.example:8443 ACF_API_KEY=acf1_dev_... \
//     [NODE_EXTRA_CA_CERTS=authority.pem] node scripts/platform-journey/typescript_sdk.mjs
//
// A developer key of a project that holds nothing is all it needs. Every step is a check; the exit status
// is 0 when every check passed. The built SDK is taken from this checkout; ACF_SDK names another build.
//
// What a pass means depends on what is behind the platform: python_sdk.py, beside this file, says it.
import { pathToFileURL } from "node:url";

const built = process.env.ACF_SDK ?? new URL("../../sdks/typescript/dist/index.js", import.meta.url).href;
const sdk = await import(built.includes("://") ? built : pathToFileURL(built).href);

// Small enough for the snapshot quota of a default host, of which a snapshot takes memory and disk.
const SIZE = { cpu: 1, memory: "128MiB", disk: "256MiB" };
const RUN = String(Math.floor(Date.now() / 1000) % 1_000_000).padStart(6, "0");
const checks = [];
function check(what, passed, detail = "") {
  checks.push(Boolean(passed));
  console.log((passed ? "ok   " : "FAIL ") + what + (detail !== "" ? `  [${String(detail).slice(0, 160)}]` : ""));
}
async function failure(run) {
  try {
    await run();
  } catch (error) {
    return error;
  }
  return undefined;
}

const started = Date.now();
const fabric = new sdk.Fabric(); // ACF_API_KEY and ACF_BASE_URL
const info = await fabric.info();
check("info: the platform serves and is ready", info.raw.serving === true && info.raw.ready === true);
const who = await fabric.whoami();
check("whoami: a developer key, bound to one project", who.credential.kind === "developer", who.project_id);

const spec = { ...SIZE, name: `journey-ts-${RUN}`, idempotencyKey: `journey-ts-create-${RUN}` };
const sandbox = await fabric.sandboxes.create("python", spec);
check("create (create, then start): the sandbox is up", sandbox.state === "READY", sandbox.sandbox_id);
const again = await fabric.sandboxes.create("python", spec);
check("the same call under the same key is the same sandbox", again.sandbox_id === sandbox.sandbox_id);
let count = 0;
for await (const listed of fabric.sandboxes.list()) if (listed.sandbox_id === sandbox.sandbox_id) count += 1;
check("and not a second one", count === 1, count);

const execution = await sandbox.exec(["python", "-c", "print(6 * 7)"], { timeout: "1m" });
check("exec: a result with a status and an exit code", execution.status === "EXITED" && execution.exit_code === 0);
const bytes = await execution.read("stdout");
const text = await execution.text("stdout");
check("exec: output is bytes, and text when asked", bytes instanceof Uint8Array && typeof text === "string");
check("exec: what the guest reported is labelled as the guest's", execution.provenance.exit_code === "GUEST_REPORTED");
const shell = await sandbox.execShell("echo one; echo two");
check("execShell asks for a shell explicitly", shell.exit_code === 0);
const unread = fabric.executions.handle(execution.execution_id);
check("a handle made without a read reads output", (await unread.read()) instanceof Uint8Array);

const byName = await fabric.sandboxes.get(spec.name);
check("a name resolves to the identifier", byName.sandbox_id === sandbox.sandbox_id);
const viaHandle = await fabric.sandboxes.handle(sandbox.sandbox_id).exec(["true"], { generation: sandbox.generation });
check("a sandbox handle made without a read acts when it names the generation", viaHandle.exit_code === 0);

const missing = await failure(() => fabric.sandboxes.get(`sbx-${"0".repeat(32)}`));
check("a sandbox that does not exist is NotFoundError", missing instanceof sdk.NotFoundError && missing.code === "NOT_FOUND");
const stale = await failure(() => sandbox.stop({ generation: 99 }));
check("a stale generation is RevisionConflictError", stale instanceof sdk.RevisionConflictError && stale.retry === "AFTER_CHANGE");

const snapshot = await sandbox.snapshot(`journey-ts-base-${RUN}`);
check("snapshot", snapshot.state === "READY", snapshot.snapshot_id);
const copy = await snapshot.restoreAsNew({ name: `journey-ts-copy-${RUN}` });
check("restore as a new sandbox: up without a start", copy.sandbox_id !== sandbox.sandbox_id && copy.state === "READY");

const minted = await fabric.auth.mintAgentCredential(`journey-ts-agent-${RUN}`, { lifetime: "10m" });
const hidden = !JSON.stringify(minted).includes(minted.secret) && !String(minted).includes(minted.secret);
check("an agent key is minted, and printing it does not show the secret", minted.secret.startsWith("acf1_agt_") && hidden);
const agent = new sdk.Fabric({ apiKey: minted.secret });
let seen = 0;
for await (const listed of agent.sandboxes.list()) if (listed.sandbox_id === sandbox.sandbox_id) seen += 1;
check("the agent key works within its grant", seen === 1, seen);
const nested = await failure(() => agent.auth.mintAgentCredential("nested", { lifetime: "1m" }));
check("an agent cannot mint keys", nested instanceof sdk.PermissionDeniedError, nested?.reason);
await fabric.auth.revokeAgentCredential(minted.credential_id, { contain: true });
const revoked = await failure(() => agent.whoami());
check("a revoked agent key no longer authenticates", revoked instanceof sdk.AuthenticationError, revoked?.code);

const immediate = await failure(() => sandbox.exec(["sleep", "0"], { followMax: 0 }));
check("followMax: 0 answers at once", immediate === undefined || immediate instanceof sdk.OperationStillRunningError);

const deleted = await snapshot.delete();
check("snapshot deleted", deleted.state === "DELETED");
for (const box of [copy, sandbox]) {
  await box.stop({ generation: "current" });
  const gone = await box.destroy({ generation: "current" });
  check(`stop and destroy ${box.sandbox_id.slice(-6)}`, gone.state === "DESTROYED");
}
let left = 0;
for await (const listed of fabric.sandboxes.list()) {
  if (listed.state !== "DESTROYED" && [sandbox.sandbox_id, copy.sandbox_id].includes(listed.sandbox_id)) left += 1;
}
check("nothing this journey made is left", left === 0, left);

const passed = checks.filter(Boolean).length;
const seconds = ((Date.now() - started) / 1000).toFixed(1);
console.log(`\n${passed} of ${checks.length} checks passed in ${seconds} s on Node.js ${process.version}`);
process.exit(passed === checks.length ? 0 : 1);
