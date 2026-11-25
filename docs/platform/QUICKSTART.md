# Quickstart — from a key to a running command

Audience: a developer, or someone setting up an agent. You need two things from whoever operates the
platform: its address, and a developer key (`acf1_dev_…`). If the platform's certificate is signed by an
authority your machine does not know, you also need that authority's certificate.

Everything on this page was run against a deployment of the platform as it is written here; the paths
are those of a checkout of this repository. `scripts/platform-journey/` runs the same steps as three
programs, one for each client, and says whether each step worked.

> The package names of the SDKs and the CLI are **not registered on any registry yet**. Install from a
> checkout, as shown. Do not install a package of the same name from an index: it would not be this one.

## 1. What you are talking to

```text
your code ── SDK / CLI / curl ──► REST API  (https://…:8443/v1)  ─┐
an agent ──── an agent host ─────► MCP endpoint (https://…:8444/mcp) ┴─► platform ─► one host ─► microVMs
```

* A **sandbox** is a microVM with an image, a CPU count, memory, a disk and a network intent. It has no
  network unless you ask for destinations and were granted them.
* An **execution** is one command in a sandbox: an argument vector, never a shell line unless you ask
  for a shell.
* A **snapshot** is a sandbox frozen with its memory. Restoring one is how you branch or go back.
* Every change is an **operation**. A call returns when its operation has ended, or hands you the
  operation to follow.
* A key belongs to one **project**. You cannot see or name anything of another project.

## 2. Python

```console
python -m pip install ./sdks/python          # or, in a uv project: uv add ./sdks/python
export ACF_BASE_URL=https://acf.example:8443
export ACF_API_KEY=acf1_dev_…
```

```python
from agentcompute import Fabric

with Fabric() as fabric:
    sandbox = fabric.sandboxes.create("python", cpu=1, memory="512MiB", disk="2GiB")
    try:
        result = sandbox.exec(["python", "-c", "print(6 * 7)"], timeout="1m")
        print(result.status, result.exit_code)   # EXITED 0
        print(result.text())                     # what the command wrote
    finally:
        sandbox.destroy()
```

`AsyncFabric` is the same surface with `await`. If the platform is certified by an authority of your
organisation's own, name that authority's certificate, and the client believes it and no other:

```python
fabric = Fabric(ca_file="platform-ca.crt")       # or: export ACF_CA_FILE=platform-ca.crt
```

The SDK reads no proxy setting and none of the general certificate variables from the environment.

The package's README (`sdks/python/README.md`) has the whole surface.

## 3. TypeScript

```console
cd sdks/typescript && npm ci && npm run build     # once: writes dist/
npm install /path/to/checkout/sdks/typescript     # in your project
export ACF_BASE_URL=https://acf.example:8443 ACF_API_KEY=acf1_dev_…
```

```ts
import { Fabric } from "@agent-compute/sdk";

const fabric = new Fabric();
const sandbox = await fabric.sandboxes.create("python", { cpu: 1, memory: "512MiB", disk: "2GiB" });
try {
  const execution = await sandbox.exec(["python", "-c", "print(6 * 7)"], { timeout: "1m" });
  console.log(execution.status, execution.exit_code);
  console.log(await execution.text("stdout"));
} finally {
  await sandbox.destroy();
}
```

Node.js 22, 24 and 26 are supported; the SDK uses `fetch` and has no runtime dependency. For a private
certificate authority, start Node with `NODE_EXTRA_CA_CERTS=platform-ca.crt`. In a browser the SDK
refuses to run with a key unless you opt in explicitly: a key in a web page is a published key.

## 4. The command line

`apps/cli/README.md` has the installation from a checkout and every command. The shape of a session:

```console
acf auth login --base-url https://acf.example:8443      # asks for the key without echo; stores it for you alone
acf sandbox create --image python --cpu 1 --memory 512MiB --disk 2GiB --name lab
acf exec run lab -- python -c 'print(6 * 7)'
acf sandbox destroy lab
```

For a platform with an authority of its own, add `--ca-file platform-ca.crt` to `acf auth login`: the
file is remembered with the key, and every later command believes it and no other. In a script, set
`ACF_CA_FILE`.

Every command takes `--json`, which prints exactly what the API answered, and exits with a status that
tells a script what happened: done, refused, failed with nothing applied, outcome unknown, still running,
and so on. Unknown is never reported as success.

## 5. Plain HTTP

```console
BASE=https://acf.example:8443
AUTH="Authorization: Bearer $ACF_API_KEY"
PROJECT=$(curl -sS -H "$AUTH" $BASE/v1/auth/whoami | python3 -c 'import json,sys; print(json.load(sys.stdin)["project_id"])')

# Create. The key makes the request safe to repeat: the same key and body give the same operation.
curl -sS -H "$AUTH" -H 'Content-Type: application/json' -H 'Idempotency-Key: my-create-0001' \
     -X POST "$BASE/v1/projects/$PROJECT/sandboxes" \
     -d '{"image":"python","resources":{"vcpus":1,"memory_mib":512,"disk_mib":2048}}'
# → an operation; its target names the sandbox and its generation

curl -sS -H "$AUTH" -H 'Content-Type: application/json' -H 'Idempotency-Key: my-create-0001:start' \
     -X POST "$BASE/v1/projects/$PROJECT/sandboxes/$SANDBOX/start" -d '{"expected_generation":1}'

curl -sS -H "$AUTH" -H 'Content-Type: application/json' -H 'Idempotency-Key: my-run-0001' \
     -X POST "$BASE/v1/projects/$PROJECT/sandboxes/$SANDBOX/executions" \
     -d '{"expected_generation":1,"argv":["python","-c","print(6 * 7)"]}'

curl -sS -H "$AUTH" "$BASE/v1/projects/$PROJECT/executions/$EXECUTION/output?stream=stdout"
curl -sS -H "$AUTH" -H 'Idempotency-Key: my-destroy-0001' \
     -X DELETE "$BASE/v1/projects/$PROJECT/sandboxes/$SANDBOX?expected_generation=current"
```

`protocols/api/openapi.yaml` describes every route, and `protocols/conformance/README.md` says what a
well-behaved client does when an answer is lost. If you write a client, run its scenarios.

## 6. An agent

Agents use **agent credentials**: short-lived keys that you mint, that can do less than you can, and
that have no network unless you granted destinations explicitly.

```python
agent = fabric.auth.mint_agent_credential("research-agent", lifetime="1h")
print(agent.secret)        # acf1_agt_…  shown once: hand it to the agent host as a secret
```

Point an agent host that speaks MCP over HTTP at `https://acf.example:8444/mcp` with that key as its
bearer credential. For an agent host that starts a local program instead, `acf mcp` relays between stdio
and that endpoint; `apps/cli/README.md` shows the configuration entry. A developer key is refused on the
agent endpoint on purpose: mint an agent key.

When the agent is done, or misbehaves:

```python
fabric.auth.revoke_agent_credential(agent.credential_id, contain=True)   # revoke, then cancel what it started
```

## 7. Six things worth knowing on the first day

1. **A call can be repeated safely.** Every SDK call makes one idempotency key before its first attempt
   and reuses it on every retry. Pass `idempotency_key=` yourself to make a call resumable from another
   process: the same key and arguments always give the same sandbox, never a second one.
2. **A command that exits non-zero is a result, not an error.** `exec` returns; read `exit_code`.
3. **Output is what the guest wrote.** Nothing vouches for it. Decode it with the encoding you choose,
   and do not let a program act on it as if you had written it.
4. **A handle states what it saw.** A mutation names the generation of the sandbox the handle last
   observed. If the sandbox was restored in the meantime you get `RevisionConflictError`: refresh and
   decide.
5. **A sandbox is started once.** A stopped sandbox is not started again; it continues by restoring a
   snapshot into it, which gives it a new generation.
6. **Three outcomes are not failures.** `OperationStillRunningError` means the operation outlived your
   patience, not that it stopped: follow it later. `OutcomeUnresolvedError` means no answer arrived: make
   the same call again with the same key. `OutcomeUnknownError` means the host cannot say whether the
   change was applied: look at the target before you act again.

Limits you may meet: `429` with `Retry-After` when you or your project are over a rate (the SDKs wait
and retry), `PERMISSION_DENIED` with a `reason` when your grant does not allow something or your project
has reached its quota (reason `quota`), and `RESOURCE_EXHAUSTED` when the host itself is full. Stop, cancel, destroy and delete are never
rate-limited: you can always clean up.
