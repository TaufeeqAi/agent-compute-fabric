# The developer journey, against a platform that is running

Three programs that do what a developer does in their first minutes, each through one client, against a
deployment you name. Every step is a check, and each program exits with a status that says whether all
of them passed.

| Program | Through | Needs |
|---|---|---|
| `python_sdk.py` | the Python SDK | `python -m pip install ./sdks/python` |
| `typescript_sdk.mjs` | the TypeScript SDK | `cd sdks/typescript && npm ci && npm run build`; Node.js 22 or later |
| `cli.sh` | `acf`, as a real process | `python -m pip install ./sdks/python ./apps/cli` |

Each needs the address of the public API and a developer key of a project that holds nothing
(`docs/platform/OPERATIONS.md`, section 5.1, is how an operator issues one):

```bash
export ACF_BASE_URL=https://acf.example:8443
export ACF_API_KEY=acf1_dev_...
export ACF_CA_FILE=platform-ca.crt            # only if the platform has an authority of its own
export NODE_EXTRA_CA_CERTS=$ACF_CA_FILE       # the same, for Node.js
export ACF_MCP_URL=https://acf.example:8444/mcp   # optional: cli.sh then also relays the agent protocol

python scripts/platform-journey/python_sdk.py
node scripts/platform-journey/typescript_sdk.mjs
bash scripts/platform-journey/cli.sh
```

Each creates a small sandbox, runs commands in it, takes a snapshot, restores or repeats, mints an agent
key and revokes it, and removes everything it made. Names carry the time of the run, so the programs
can be run again and beside each other. `cli.sh` gives `acf` a home directory of its own: the
credentials you have stored are neither read nor changed.

## What a pass means

It depends on what is behind the platform.

* Behind the deployment test (`make platform-deploy-test`) is the host's in-memory test build. A pass
  proves the client, the platform and the deployment: real TLS, real processes, the real host protocol.
  It proves nothing about a microVM, because none is booted.
* Behind a platform that is bound to a real host, a pass is the journey the contract names as the
  acceptance test of the developer experience. No `make` target runs that, because this repository has
  no way to provide such a host; these three programs are how it is run when one exists.

The sandbox they create is 128 MiB of memory and 256 MiB of disk, so that its snapshot fits the snapshot
quota of a host with default settings.
