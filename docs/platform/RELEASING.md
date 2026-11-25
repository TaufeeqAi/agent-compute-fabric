# Releasing — publishing the platform's packages

Audience: a maintainer with the right to push tags. This is how a package of the developer platform
reaches a registry, and what makes a published file trustworthy.

The rules come from the contract and are enforced by the workflow, not by this text:

* **Identity, not tokens.** Packages are published only by `.github/workflows/release.yml`, through OIDC
  trusted publishing on PyPI and on npm. No registry token exists for this project, anywhere. If you are
  ever asked to create one, the answer is no.
* **Provenance or nothing.** Every published file carries a provenance attestation that ties it to the
  commit and the workflow run: PEP 740 attestations on PyPI, Sigstore provenance on npm. A release that
  cannot attach it is not published.
* **Fixed by content.** Every dependency is locked to an exact version and to the hash of its files, and
  a dependency with a known advisory stops the release.
* **Owned names only.** No document, example or tool description names a package the project does not
  control on the registry it is installed from.

## 1. The packages

| Tag | Directory | Registry | Package | Version is declared in |
|---|---|---|---|---|
| `agent-compute-v<version>` | `sdks/python` | PyPI | `agent-compute` | `src/agentcompute/_version.py` |
| `agent-compute-cli-v<version>` | `apps/cli` | PyPI | `agent-compute-cli` | `src/agentcompute_cli/_version.py` |
| `acf-api-v<version>` | `apps/api` | PyPI | `acf-api` | `src/acf_api/__init__.py` |
| `acf-mcp-gateway-v<version>` | `apps/mcp-gateway` | PyPI | `acf-mcp-gateway` | `src/acf_mcp/__init__.py` |
| `sdk-typescript-v<version>` | `sdks/typescript` | npm | `@agent-compute/sdk` | `package.json` (and `src/version.ts`, held equal by a test) |

One tag releases one package. Each package has its own semantic version; a release of one does not
release the others. The CLI follows the Python SDK it is built on: when a release of the SDK changes
what the CLI depends on, release the SDK first and then the CLI with its dependency range moved.

## 2. Current state: nothing is published, and the names are not registered

On 2026-11-19 the name `agent-compute` on PyPI and the scope `@agent-compute` on npm were unclaimed, and
none of the five packages has been published. Until they are:

* every README in this repository installs from a checkout, never from a registry, and must keep doing
  so (`make platform-dist` builds the files; the READMEs say how to install them);
* `sdks/typescript/package.json` carries `"private": true`, which makes `npm publish` refuse. It is
  removed in the same change that registers the scope, not before;
* the release workflow cannot succeed: a registry accepts a trusted publisher only from the owner of the
  name.

## 3. Once, before the first release

An owner of the repository does this, in this order.

1. **Register the names.** Create the PyPI projects `agent-compute`, `agent-compute-cli`, `acf-api` and
   `acf-mcp-gateway`, and the npm organisation `agent-compute`. If a name has been taken in the
   meantime, choose another, change it in the package's metadata, in `release.yml`
   (`tests/scripts/test_makefile_and_ci.py` holds the two together) and in every document that names it,
   and only then go on.
2. **Add the trusted publishers.** For each PyPI project: publisher GitHub Actions, this repository,
   workflow `release.yml`, environment `pypi`. For the npm package: trusted publisher GitHub Actions,
   this repository, workflow `release.yml`, environment `npm`. Three facts of the registries, read from
   their documentation on 2026-11-20, decide when and where this works:
   * npm makes provenance only for a public package published from a **public repository**. The workflow
     asks for provenance explicitly, so from a private repository the npm release fails, as the rule
     above requires.
   * A new npm trusted-publisher configuration expires unless its first publish succeeds within two
     days. Add it when the first release is ready, not weeks before.
   * npm trusted publishing does not work from self-hosted runners. The workflow uses hosted ones.
3. **Protect the two environments.** In the repository settings, create the environments `pypi` and
   `npm` with required reviewers and with deployment restricted to tags that match the patterns of
   section 1. A publishing job then waits for a second person, and a branch can never publish.
4. **Protect the tags.** A tag ruleset that lets only maintainers create tags of those patterns and lets
   nobody move or delete one.
5. **Remove `"private": true`** from `sdks/typescript/package.json`, and replace the from-a-checkout
   installation in the READMEs with the registry one, in one reviewed change.

## 4. A release

```bash
# 1. On main, with a clean tree: move the version (section 1), update the package's README if its
#    interface changed, and run the gate.
make platform-ci
make platform-audit

# 2. Rehearse: the dry run plans, audits and builds exactly as the tag will, and publishes nothing.
gh workflow run release.yml -f tag=agent-compute-v0.2.0
#    Its summary lists the files and their SHA-256. Download the artifact `release-files` if you want
#    to look at them.

# 3. Merge. Tag the merge commit, and push the tag.
git tag -s agent-compute-v0.2.0 -m "agent-compute 0.2.0"
git push origin agent-compute-v0.2.0

# 4. Approve the publishing job in the environment when it asks.
```

What the workflow does with the tag:

| Job | What it does | It fails when |
|---|---|---|
| `plan` | reads the tag: which package, which registry, which version | the tag names no package, or the version is not a version |
| `audit` | `make platform-audit`: advisories against everything the five locks name, development tools included; npm registry signatures | any advisory, any unsigned package |
| `build` | `make platform-dist`: builds every package, installs the files into an empty environment, imports them, runs each program's `--version`; then keeps the files of the tagged package | the files of the tagged version were not built (the tag and the declared version disagree) |
| `publish-pypi` or `publish-npm` | uploads the files the build job made, with provenance | the registry refuses the identity, the provenance cannot be made, or the version exists |

The two publishing jobs are the only jobs in any workflow of this repository with a permission beyond
`contents: read`: an identity token. They do not check out the repository and run none of its code.

A version is published once. If a release is wrong, publish the next version; do not try to replace a
file. Yank on PyPI or deprecate on npm if the wrong version must not be installed.

### 4.1 The public interface between two releases

A tag `acf-api-v*` is also the released version of the contract files under `protocols/`: the REST
description, the tool catalogue and the problem registry. Within a major version of the interface
nothing is removed, renamed, retyped or made newly required, and no request becomes stricter.
`make platform-compat`, which is part of `make platform-check` and of CI, compares the files of the
checkout with those of the newest `acf-api-v*` tag it descends from and fails on a difference that
breaks that promise. Before the first such tag there is no release to compare with, and it says so.

When it reports a finding, one of three things is true:

| What is true | What to do |
|---|---|
| The change does take something from a caller | Undo it, or make it additive: a new optional member, a new route, a new tool. A tool that must change gets a new name, and the old one stays. |
| The change is compatible and the comparison cannot prove it (a pattern that was rewritten and accepts every old value) | Copy the finding, exactly as printed, into `apps/api/compat-accepted.txt` under a comment that says why. It is reviewed like code. A line that matches no finding fails the comparison, so remove it once the release that contains the change is the one compared with. |
| The interface is to break on purpose | That is a new major version: the version in the OpenAPI document changes its first number, the path prefix changes with it, and the old major stays served for its deprecation window. A comparison across majors lists what breaks and passes. |

The comparison reads the generated files only. It cannot see a change of meaning behind an unchanged
shape: a member that keeps its name and type and means something else. That stays a reviewer's job.

## 5. After a release: check what was published

```bash
# PyPI: the attestation of each file, against this repository.
uvx pypi-attestations verify pypi --repository https://github.com/OWNER/agent-compute-fabric \
    pypi:agent_compute-0.2.0-py3-none-any.whl

# npm: registry signatures and provenance of what a project installed.
npm audit signatures
```

Replace `OWNER` with the owner of the repository. Compare the SHA-256 that the build job printed with the
digest the registry shows for each file.

Then run the developer journey from the published packages, in an empty directory on a machine that has
no checkout: install the SDK, set a key, create a sandbox, run a command. That is the test the contract
names for a release, and it cannot be run from this repository.

## 6. What a contributor runs

Nothing here needs a registry account.

```bash
make platform-dist      # the files of every package, in dist/platform/, proven to install and import
make platform-audit     # the same audit the release runs
make platform-compat    # what the contract files would take from a caller of the last release
```

Dependencies are changed by changing a range in a `pyproject.toml` or `package.json` and re-locking
(`uv lock`, `npm install --package-lock-only`); the lock file is reviewed like code. A version is chosen
as the current version on the registry at the time of the change, validated by the tests, and locked
exactly: [DEPENDENCY_PROVENANCE.md](DEPENDENCY_PROVENANCE.md) records how. Dependabot proposes updates
for every lock (`.github/dependabot.yml`); nothing is merged automatically.
