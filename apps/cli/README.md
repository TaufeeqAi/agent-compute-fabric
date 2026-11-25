# acf

`acf` is the developer's command-line client of Agent Compute Fabric: create sandboxes, run commands
in them, read what the commands wrote, snapshot and restore, and look at every operation the platform
holds. One more command, `acf mcp`, lets an agent host reach the platform's agent interface over
standard input and output.

It is a thin layer over the Python SDK in `sdks/python`. A command parses its options, makes one call
of the SDK, prints what the platform answered and picks an exit status. What is allowed and what
happened is the platform's to say; whether to ask again is the SDK's. This tool decides neither.

This is version 0.1.0, for version `v1` of the public API. It needs Python 3.12 or later and runs on
Linux, macOS and Windows.

## Install

The distributions in this repository are **not registered on any package index yet**. Do not install a
package of a similar name from an index: it would not be this one. Install from a checkout of this
repository, and give both paths in the same command, because the tool needs the SDK and both have to
come from the checkout:

```console
python -m pip install ./sdks/python ./apps/cli
acf --version
```

To work on the tool itself, use the locked environment:

```console
cd apps/cli
uv sync --locked
uv run --locked acf --help
```

## Configure

A command needs a key and the address of the platform.

| What | Flag | Environment | Stored profile |
|---|---|---|---|
| API key | none, on purpose | `ACF_API_KEY` | yes |
| Address of the public API | `--base-url` | `ACF_BASE_URL` | yes |
| Project | `--project` | `ACF_PROJECT` | yes |
| Address of the MCP endpoint (`acf mcp` only) | `--endpoint` | `ACF_MCP_URL` | yes |
| Certificate authorities to believe | `--ca-file`, on `acf auth login` | `ACF_CA_FILE` | yes |
| Which profile | `--profile` | `ACF_PROFILE` | `default` |

Each value is taken from the flag, then from the environment, then from the stored profile. Three
things are deliberate:

- **There is no flag for the key.** A key on a command line ends up in shell history and in process
  listings.
- **The project of a profile goes with the key of that profile.** A project belongs to a key, so a key
  from the environment is asked for its own project, once, and is never given the stored one.
- **The authorities of a profile go with the address of that profile.** They were named for one
  platform and say nothing about another, so an address from a flag or the environment is not given
  the stored ones.

### A platform with a certificate authority of its own

A platform that you or your organisation run is usually certified by your own authority, which no
system trusts by itself. Name that authority's certificate, a PEM file, once:

```console
acf auth login --base-url https://acf.internal.example --ca-file ./internal-ca.pem
```

The path is stored with the profile, as an absolute path, and every later command believes the
authorities in that file **and no others**: not the ones your system trusts either. `acf mcp` believes
the same ones about the MCP endpoint, so a file may hold more than one authority. In a script, set
`ACF_CA_FILE` instead. A file that is missing, or holds no certificate, stops the command; it is never
passed over in favour of the system's authorities, because those are exactly the ones it was meant to
exclude. Nothing else about certificates or proxies is read from the environment.

An address must be `https`. Plain `http` is accepted for this machine only. An address that carries
user information or a query string is refused: a key is never accepted inside a URL. So is an address
with a space or a line break in it: it is refused, not tidied, because an address that was typed wrong
is one nobody looked at.

### Storing a key

```console
acf auth login --base-url https://acf.example
```

asks for the key without showing it, checks it with the platform, and stores it. It prints who the key
is, the project it belongs to and where it was stored, and at no point the key. In a script, pipe the
key in: `acf auth login --base-url https://acf.example --key-stdin < key-file`.

The file is `$XDG_CONFIG_HOME/acf/credentials.json` (`~/.config/acf/credentials.json` when the variable
is not set), and `%APPDATA%\acf\credentials.json` on Windows. On Linux and macOS it is created readable
and writable by its owner only (mode `0600`), in a directory only the owner can enter (mode `0700`),
and it is replaced as a whole, never written in place. **A file that other users can read or change is
refused**, with a message that says so: its key has to be considered seen. `acf auth logout` removes a
profile from the file; the key itself stays valid until it expires or is revoked.

## Commands

```text
acf auth login [--base-url URL] [--profile NAME] [--key-stdin] [--mcp-url URL] [--ca-file FILE]
acf auth logout [--profile NAME]
acf auth agent-key create --label LABEL --lifetime DURATION [--narrowing FILE]
acf auth agent-key list
acf auth agent-key revoke CREDENTIAL [--contain]
acf policy inspect
acf info
acf sandbox create --image IMAGE --cpu N --memory SIZE --disk SIZE [--network none|FILE] [--name NAME]
                   [--lifetime DURATION] [--no-start] [--keep-on-start-failure]
acf sandbox list | inspect SANDBOX | start SANDBOX | stop SANDBOX | destroy SANDBOX
acf exec run SANDBOX [--cwd PATH] [--env NAME=VALUE ...] [--timeout DURATION] -- ARGV...
acf exec run SANDBOX --shell 'COMMAND LINE'
acf exec status EXECUTION | cancel EXECUTION
acf exec output EXECUTION [--stream stdout|stderr] [--offset N] [--max-bytes N] [--raw [--force]]
acf snapshot create SANDBOX [--name NAME] | list | delete SNAPSHOT
acf snapshot restore SNAPSHOT [--into SANDBOX | --name NAME --lifetime DURATION]
acf operation get OPERATION [--wait SECONDS] | list
acf mcp [--endpoint URL] [--profile NAME]
acf --version
```

Every command takes `--help`. A command that calls the platform takes `--json`, `--profile`,
`--base-url`, `--project`, `--verbose` and `--timeout`. A command that changes something also takes
`--idempotency-key`, `--follow-max` and `--no-wait`, and `--generation` where it acts on a sandbox.

A first session:

```console
acf sandbox create --image python --cpu 1 --memory 512MiB --disk 2GiB --name build
acf exec run build -- python -c "print(6 * 7)"
acf snapshot create build --name baseline
acf sandbox destroy build
```

### What a few options mean

- **Sizes and durations.** `--memory` and `--disk` take a number of MiB (`512`) or a binary unit
  (`512MiB`, `4GiB`). `--lifetime` and the `--timeout` of `exec run` take seconds (`90`) or `90s`,
  `10m`, `2h`, `1d`. Anything that could mean two things is refused before a request is made: `4GB`,
  `4G`, `1.5`.
- **`--network`.** `none`, which is also the default, or a JSON file holding an allowlist:
  `{"mode": "allowlist", "entries": [{"name": "packages.acf.example", "ports": [443]}]}`. There is no
  third mode.
- **`--timeout`.** How long one HTTP request may take. On `acf exec run` it is how long the command
  may run on the host instead, and the request is bounded with `--request-timeout`.
- **`--generation N|current`.** A command that changes a sandbox states the generation it acts on. By
  default it reads the sandbox first and states the generation it saw, so a sandbox that was restored
  in the meantime refuses the request. `current` says "whatever is there". Naming an identifier
  together with a generation makes the read unnecessary.
- **Names.** A sandbox or a snapshot can be named by its identifier or by its name. A name is only
  used to find the record, once; the command then acts on the identifier it found.

### Running a command

The command is an **argument vector**: everything after `--`, passed as the list it is. No shell is
involved and nothing is joined or split. The `--` is required, so that an option of your command can
never be taken for an option of this tool. To run a command line through the sandbox's shell, say so:
`--shell 'ls -l | wc -l'` sends `/bin/sh -c 'ls -l | wc -l'`.

`acf exec run` writes the command's standard output to standard output and its standard error to
standard error, and exits 0 if the command exited with status 0 and 1 if it did not. With `--json` it
prints the execution instead and relays no output; read it with `acf exec output`.

### Operations, keys and waiting

Everything that changes something is an operation on the platform, and it can outlive the command that
started it. A command follows its operation until it has ended, or for `--follow-max` (30 minutes by
default), and then says that it is still running. Stopping the wait cancels nothing, and neither does
Ctrl-C: `acf exec cancel EXECUTION` is the explicit request.

Each such command gives its request one **idempotency key** before anything is sent: yours
(`--idempotency-key`), or one it makes. Repeating the command with the same key and the same arguments
returns the same operation and starts nothing twice. Every message that tells you to ask again names
the key to ask with. `acf sandbox create` is two operations, create and then start, under one key: the
same command with the same key picks the sequence up wherever it stopped.

`--no-wait` issues the operation, asks the platform to answer at once, prints the operation as that
answer shows it, and exits without following it. With `--no-wait` the output is always the operation,
never the resource, and the exit status is 0 unless the operation had already ended without success.
On `acf sandbox create` it requires `--no-start`, because creating a started sandbox is two
operations.

## Output

Without `--json` a command prints a table or a key-value view on standard output, and its own remarks
on standard error. There is no colour and no table border when standard output is not a terminal or
`NO_COLOR` is set.

With `--json` standard output is **exactly one JSON document: the answer as the platform sent it**. A
listing is one array of the items. Members this version does not know are printed like any other, and
a state it has never seen is printed as the word it is. The document is written in printable ASCII.

When a command fails with `--json`, and the platform gave an answer, the **first line of standard
error is that answer as one line of JSON**: the members of the problem document for a refusal (`code`,
`kind`, `retry`, `message`, `request_id`, and `idempotency_key`, `reason`, `status` when present), or
the operation that did not succeed. The lines after it are the same words as without `--json`.

`--verbose` writes the request id of every result and of every error to standard error, the
idempotency key before anything is sent, where each configuration value came from, and each retry. It
never writes a key or a header.

### Text that is not this tool's

A name is chosen by whoever created the record, a message by the host, output by the command that ran.
None of it reaches a terminal as it is: every control and format character is shown as a visible
escape, and a table cell is bounded. Output of a command is written to a pipe or a file byte for byte,
and to a terminal as safe text. `acf exec output --raw` insists on the exact bytes and is refused when
standard output is a terminal, unless `--force` is given. A character that the encoding of the output
does not have is written as an escape too, so a name can never make a command fail after it did its
work.

Nothing this tool writes contains the key in use. Should the platform or a sandbox ever repeat it, the
place where it stood reads `[redacted]`.

## Exit statuses

Scripts can branch on the exit status. It is part of the contract of this tool, with the `--json`
output, and both follow the version of the public API.

| Status | Meaning |
|---|---|
| 0 | Done. |
| 1 | `acf exec run` only: the command ran and did not exit with status 0. |
| 2 | Usage or configuration error. Nothing that changes anything was sent. |
| 3 | The platform refused the request. Nothing exists because of it. |
| 4 | The operation failed and nothing was applied. A new request is allowed. |
| 5 | The outcome is unknown, or the operation may have been applied. Neither success nor failure: inspect the target before acting again. |
| 6 | The platform could not be reached, or a read got no answer. |
| 7 | What answered does not speak this API. |
| 8 | Unresolved: a request that changes something got no usable answer. Ask again with the same idempotency key, which the message names. |
| 9 | The outcome is lost for good. Inspect the target; the key is finished. |
| 10 | The operation was still running when the tool stopped following it. The message names the operation and the command that follows it. |
| 130 | Interrupted. Nothing was cancelled. |
| 141 | The reader of standard output went away. |

An unknown outcome and a lost outcome never exit 0. When `acf sandbox create` created the sandbox and
could not start it, the status is that of the start, and the message says what became of the sandbox.

A defect of the tool itself is shown with its traceback and also exits 5: the tool then does not know
what became of the request, and says so. It never exits 1 for that, because 1 says that a command ran.

Two commands state the condition of what they show:

- `acf operation get` prints the operation and exits 0 if it succeeded, 4 if it ended and nothing was
  applied, 5 if its outcome is unknown or it may have been applied, and 10 if it has not ended. It is
  the command that follows an operation: `acf operation get OPERATION --wait 30`.
- `acf exec status` is a read and exits 0 when the platform answered, except that an execution whose
  state is `UNKNOWN` exits 5.

Every failure ends with a line that says what you can do next.

## Agent keys

An agent is an untrusted caller even when you trust it, so it gets a key of its own, narrower and
shorter-lived than yours:

```console
acf auth agent-key create --label builder --lifetime 2h
```

prints the secret of the new key on standard output, **once**. The platform never shows it again.
`--narrowing FILE` gives a grant as a JSON file: a subset of what your own key may do.

`acf auth agent-key revoke CREDENTIAL` ends what the key may ask for. It does not end what the key
already started. `--contain` also cancels every execution the key started that has not ended, and
exits with a status other than 0 if one of those cancels did not succeed.

## acf mcp: the agent interface over standard input and output

An agent host that starts its tools as programs can reach the platform through `acf mcp`. It relays
messages of the Model Context Protocol between standard input and output and the platform's MCP
endpoint, adding the key. It implements no tool: every tool and every decision is the platform's.

It **only starts with an agent key**. A developer key is refused before any message is read, by the
marker every key carries; when the address of the public API is known, the platform is also asked who
the key is. An agent host is never handed a developer's authority.

Configure the host with the path of the installed program. The path below is an example: use the one
`acf` has on your machine, for instance the `bin` directory of the environment you installed it into.

```json
{
  "mcpServers": {
    "acf": {
      "command": "/home/you/acf-env/bin/acf",
      "args": ["mcp", "--endpoint", "https://acf.example/mcp"],
      "env": {
        "ACF_API_KEY": "the agent key",
        "ACF_BASE_URL": "https://acf.example"
      }
    }
  }
}
```

For a platform with a certificate authority of its own, add `"ACF_CA_FILE": "/path/to/authority.pem"`
to `env`.

What the relay does and does not do:

- It carries each message with its content unchanged. It does not validate, rewrite, cache or retry
  one, and standard output carries messages of the protocol and nothing else. Its own remarks go to
  standard error.
- A request the endpoint does not answer gets a JSON-RPC error that says so, marked as made by the
  relay. It never makes up the result of a tool. An error the endpoint gave before it had read which
  request it was answering is given the identifier of that request: on standard output nothing else
  says which call an answer belongs to.
- When the host cancels a call that started a command in a sandbox, the relay asks the platform to
  cancel that command. That is the one thing it does of its own accord.
- Closing its input is a disconnect: what was read is carried to its end, and nothing is cancelled.
  Neither does Ctrl-C or a termination signal cancel anything.

## What this tool never does

- It sends nothing anywhere but to the platform you configured: no update check and no telemetry.
- It never lets a variable another program set move its connection or change whom it believes: no
  proxy variable and no general certificate variable is read. `ACF_CA_FILE` is this tool's own.
- It never talks to a host directly. Its only doors are the public API and the MCP endpoint.
- It never prints, logs or raises a key, and never shows one again after `acf auth login`.
- It never cancels anything because it stopped waiting.
- It never makes a new idempotency key to get past a problem.

## Development

```console
cd apps/cli
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
uv run --locked pytest -q
```

The tests talk to a scripted transport and run on a clock that does not wait: none of them opens a
connection. They drive every command from the generated table of the API's operations
(`protocols/api/surface.yaml`) and run the client conformance suite of the API
(`protocols/conformance/scenarios.json`) through the commands.
