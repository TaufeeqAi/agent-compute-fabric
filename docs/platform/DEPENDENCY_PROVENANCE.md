# Dependency provenance — the developer platform

Where every version in the platform's five projects came from, how it was checked, when, and what could
not be checked. The execution plane's record is [`docs/DEPENDENCY_PROVENANCE.md`](../DEPENDENCY_PROVENANCE.md);
the rule and the labels are the same.

The rule: *resolve versions from the registries at write time, not from memory.* What an author
remembers as "the latest" is stale by construction, so the repository records its evidence.

| Label | Meaning |
|---|---|
| **Verified** | Read from the authoritative registry or git remote on the stated date, by the method described. |
| **Exercised** | Installed from the lock and tested in this repository ([VERIFICATION_STATUS.md](VERIFICATION_STATUS.md)). |
| **Unverified** | Could not be reached or checked from where this was written. Listed in §7. |

## 1. Method

| Ecosystem | Authority used | How the version was chosen |
|---|---|---|
| Python packages | PyPI JSON API (`https://pypi.org/pypi/<name>/json`) | `info.version`: the newest release that is not a pre-release |
| npm packages | the registry (`https://registry.npmjs.org/<name>`), and `npm view` | `dist-tags.latest` |
| Node.js lines | the release schedule of the Node.js project (`https://github.com/nodejs/Release`) | lines in Active LTS or Maintenance on the date of writing |
| GitHub Actions | `git ls-remote` on the action's repository | newest `vX.Y.Z` tag; an annotated tag is peeled (`refs/tags/<tag>^{}`) to its commit |
| Protocols and conventions | the specification's own pages, fetched on the date of writing | the revision the contract names; the page's stated status |

Every request used a generic client name and public URLs only.

A manifest carries a floor and a cap; the committed lock (`uv.lock`, `package-lock.json`) carries the
exact resolution with the hash of every file; every command of the gate runs `--locked` (or `npm ci`),
which fails instead of resolving again. A floor is the version the code was tested against, not an older
one that might also work: a published range is as narrow as what was tested.

## 2. Resolution log

| Date | What was resolved or re-checked |
|---|---|
| 2026-11-19 | Every direct dependency of the five projects, the Node.js lines, the action tags and commits, the protocol revision and its SDK. Locks created. |
| 2026-11-20 | `pip-audit` and `pypi-attestations` (tools named in the release procedure); the registries' documentation of trusted publishing; the OpenTelemetry conventions for the agent protocol; the retry and idempotency behaviour of one widely used API SDK, read from its source. |
| 2026-11-20 | How `httpx2` 2.16.2 takes trust anchors, read from its signature and tried: an `ssl.SSLContext` is the supported way, and a path given as text is deprecated. The clients' `ca_file` setting builds a context accordingly. |

## 3. Python: what the locks hold

Direct dependencies, with the locked version. All **Verified** on 2026-11-19 and **Exercised**.

| Package | Locked | Used by | Why it is there |
|---|---|---|---|
| `pydantic` (`pydantic-core` 2.50.5) | 2.14.4 | API | the public model, the commands and answers, both configuration schemas |
| `PyYAML` | 6.0.3 | API | configuration files, grant templates, the generated YAML artifacts |
| `starlette` | 1.10.0 | API (REST edge), adapter | ASGI routing; nothing else of it is used |
| `uvicorn` (`h11` 0.16.0) | 0.54.0 | both edges | the HTTP server, with its limits set; the `h11` implementation only |
| `PyJWT[crypto]` (`cryptography` 50.0.2) | 2.15.1 | API (core) | verification of OAuth access tokens, when that mode is configured |
| `mcp` (`mcp-types` 2.3.0) | 2.3.0 | adapter | the official SDK of the agent protocol: message shapes and the Streamable HTTP transport |
| `httpx2` (`httpcore2` 2.16.2) | 2.16.2 | Python SDK, CLI | the HTTP client. The one runtime dependency of the SDK |
| `typer` | 0.29.2 | CLI | commands and options |
| `rich` | 15.0.0 | CLI | tables for people |
| `opentelemetry-api` | 1.45.2 | API (optional extra `otel`) | spans, only where an operator installs it; a development dependency of the API and the SDK so that the tests can show what a span carries |

Tools, in every lock that uses them: `pytest` 9.2.0, `pytest-asyncio` 1.5.0, `pytest-timeout` 2.4.0,
`pytest-cov` 7.1.0, `hypothesis` 6.170.15, `jsonschema` 4.26.0, `openapi-spec-validator` 0.9.0,
`mypy` 2.4.1, `ruff` 0.17.6, `types-PyYAML` 6.0.12.20261113, `types-jsonschema` 4.26.0.20261006. Build
backend: `hatchling` 1.33.0 (a build requirement, not in a lock). Locking and installing: `uv` 0.13.9.

Size of each lock, counting the packages that come from the index and not the packages of this
repository: API 55, adapter 50, CLI 35, Python SDK 32.

Three choices that follow from looking instead of remembering:

* **`httpx2`, not `httpx`.** On the day of writing `httpx` stood at a release of 2024 with only a
  pre-release after it, and `httpx2` (2.16.2) is its maintained continuation, which the official SDK of
  the agent protocol and the SDKs of the large API vendors depend on. The Python SDK's one runtime
  dependency was chosen accordingly.
* **Starlette without a framework on top.** The REST edge has to do things in an order a
  request-validating framework does not offer ([DECISIONS.md](DECISIONS.md), ADR-103).
* **No telemetry dependency in any client.** The SDKs and the CLI depend on no telemetry package. They
  use an OpenTelemetry installation only if the application has one.

The adapter's lock also records the dependency metadata of `acf-api`, which it installs from its
directory. After any change to the dependencies of `apps/api`, run `uv lock` in `apps/mcp-gateway` too
(and in `apps/cli` after a change to `sdks/python`): `--locked` fails until it is done.

## 4. TypeScript: what the lock holds

| Package | Locked | Why it is there |
|---|---|---|
| `typescript` | 7.0.2 | the compiler; the build is plain `tsc`, with no bundler |
| `vitest` (`vite` 8.3.8) | 5.1.1 | the test runner |
| `@types/node` | 26.6.6 | types for the tests; the package's own sources compile without Node types |

All three are development dependencies, pinned exactly. **The package has no runtime dependency.** The
lock holds 90 packages, every one of them a tool. **Verified** on 2026-11-19 and **Exercised**.

Node.js: 26 (Active LTS), 24 and 22 (Maintenance). The package declares `node >= 22.12.0`.

## 5. Actions

Resolved with `git ls-remote`; annotated tags peeled to the commit. Dependabot proposes updates and
rewrites both the commit and the tag comment.

| Action | Tag | Commit | Used in |
|---|---|---|---|
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | every job that reads the repository |
| `astral-sh/setup-uv` | v10.3.3 | `68559e99cc807c1eb7e9238fd43a15bba460eec2` | Python jobs |
| `actions/setup-node` | v7.1.0 | `949feb2413d6458794dcd2491c4babbbce0c15c1` | TypeScript, package and release jobs |
| `Swatinem/rust-cache` | v2.9.3 | `d1527c8f67ef9af357290475d4af4b0fab8f12e0` | jobs that build the host's test build |
| `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` | packages, release |
| `actions/download-artifact` | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` | release |
| `pypa/gh-action-pypi-publish` | v1.14.3 | `7245906fb61fa33a13554f9d5fb856fe61758086` | release |

Tools the workflows and the release procedure name, with their versions: `pip-audit` 2.10.1 (pinned in
the Makefile), `pypi-attestations` 0.0.31 (named in [RELEASING.md](RELEASING.md); not run here).

## 6. Protocols, conventions and prior art

What the implementation follows, where it was read, and what was taken from it. The contract records
the wider survey; this table is what the code depends on.

| Source | Read on | What was taken | What was not |
|---|---|---|---|
| Model Context Protocol, revision 2026-07-28: transports, versioning, tools, discovery, cancellation | 2026-11-19 | stateless Streamable HTTP, POST only; the `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers; the protocol's own error codes for a wrong header and an unsupported revision; results with structured content and the same JSON as text | sessions; the older revision and the tasks extension, which this build does not serve |
| Official Python SDK of that protocol (`mcp` 2.3.0), read from its source | 2026-11-19 | the low-level server and its Streamable HTTP transport | its Host and Origin check, its tool listing before each call and its span middleware, each replaced or switched off for a stated reason |
| OpenTelemetry conventions for MCP server spans (`semantic-conventions-genai`, Development status; shared attributes at 1.45.0) | 2026-11-20 | the span name (`{method} {tool}`), kind `SERVER`, `mcp.method.name`, `gen_ai.tool.name`, `gen_ai.operation.name`, `mcp.protocol.version`, `error.type` = `tool_error`; the parent taken from `params._meta` | attributes that would carry arguments or results |
| RFC 9457 (problem details) | per the contract | `application/problem+json` with `type`, `status`, `title`, `detail`, `instance`, and the platform's members beside them | — |
| IETF draft `Idempotency-Key` header (08) and Stripe's documented behaviour | per the contract | the header; 422 for the same key with another request; nothing recorded before execution begins; a replay marked as one | stored responses: the host is asked instead |
| One widely used API SDK (`openai-python`, `_base_client.py`) | 2026-11-20 | bounded retries with exponential backoff and jitter; honouring `Retry-After`; one key made per call before the first attempt and reused on every retry | retrying by status code alone (it retries every 409): here the problem document's `retry` member decides |
| A sandbox SDK of the same kind (`e2b`, its Python README) | 2026-11-20 | a key from the environment; handles with methods; a context manager for clean-up | starting work without an idempotency key |
| GitHub's token format | per the contract | a typed prefix and a CRC32 checksum, so that a key is recognisable offline | — |
| PyPI and npm documentation of trusted publishing | 2026-11-20 | the identity token as a job-level permission; a protected environment; npm ≥ 11.5.1; provenance only from a public repository; no self-hosted runner | long-lived tokens |
| systemd 257, as installed on the machine the deployment test ran on | 2026-11-20 | the confinement options of the three units, accepted by `systemd-analyze verify` and then proven by starting each unit and inspecting its process | `PrivateUsers=`, which would hide the peer's identity from the core |

## 7. Unverified

* The five package names and the npm scope are **not registered**; whether they are still free was last
  read from the registries on 2026-11-19, by the contract's author.
* The release workflow has never run: a trusted publisher can be configured only by the owner of a name.
  `pypi-attestations` and `npm audit signatures` were therefore not run against a published file.
* The GitHub workflows have not run on GitHub. Their commands were run locally through the same `make`
  targets; the actions themselves were only resolved.
* Platforms other than Linux on `x86_64`: the SDKs and the CLI are written to be portable and their
  tests cover both branches of every platform-specific path, but they ran on Linux only (the TypeScript
  SDK's tests also on Windows).
