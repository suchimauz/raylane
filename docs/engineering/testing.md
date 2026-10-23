# T004 — Testing and CI

Task: **T004** — "После T002 настроить unit/race/frontend/contract CI в
`.github/workflows/verify.yml` и `docs/engineering/testing.md`; network runner
только opt-in disposable VM, не host root."

Artifacts:

- `.github/workflows/verify.yml` — the CI definition.
- This document — what the CI does, what it does not do, and what is not
  yet known.

## Status and the honest summary

**The workflow has never been executed.** It was authored in a task with no
network access, was never dispatched, never run by a hosted runner, and was
never validated by GitHub's workflow parser. Every statement below about how
CI *behaves* is a design intent, not an observed result.

What was actually verified locally, offline:

| Property | How | Result |
|---|---|---|
| The workflow is valid YAML and has the expected shape | PyYAML 6.0.1 parse + 70 structural assertions | PASS |
| Every action is pinned to a full 40-hex commit SHA | Regex + assertion over the parsed file | PASS |
| Both pins are corroborated by an independent local source | Grep over the local Go module cache and other checked-out repositories | PASS (checkout: 21 files, upload-artifact: 8 files) |
| The toolchain checksums match `packaging/versions.lock` | Substring check of the parsed `env` against the lock file | PASS |
| The "no tests present" branches really do report NOT_RUN and exit 0 | The branch bodies were executed locally against the real repo | PASS |
| The embedded contract-check Python runs verbatim | Extracted from the YAML and executed against the real `contracts/openapi.yaml` | PASS, exit 0 |

What was **not** verified, and is honestly recorded as NOT_RUN:

| Check | Why NOT_RUN |
|---|---|
| The workflow as GitHub executes it | No network, no dispatch, no runner |
| GitHub's own workflow-schema validation | Not available offline; the YAML is well-formed but schema-validity is unproven |
| Any hosted-runner behaviour (cache behaviour, artifact upload, runner image contents) | Never ran |
| Full OpenAPI conformance validation | No OpenAPI validator is vendored, installed, or available |
| Any actual unit, race, frontend or E2E test result | The scaffold contains **no test files at all** |
| The arm64 toolchain path | `packaging/versions.lock` records no arm64 checksum |

## Why no `actions/cache`, `actions/setup-go` or `actions/setup-node`

The task requires immutable, verified action pins and forbids inventing a
digest. On this machine the only action pins that exist anywhere locally
are these seven:

```
actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1   (v7.0.1)
actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1
actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97
actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a  (v7.0.1)
github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d
ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc
step-security/harden-runner@ccd8616d44fd3846e67624a50d5aad6d37bf2d25
```

`actions/cache`, `actions/setup-go` and `actions/setup-node` appear on this
machine **only as mutable tags** (`@v4`, `@v3`, `@v7`, `@v2`, `@v3`). There
is no locally verifiable SHA for any of them, and the task forbids fetching
one without new scope.

So the workflow installs both toolchains the direct way: download the
official tarball from go.dev / nodejs.org, **verify its SHA-256 against the
value recorded in `packaging/versions.lock`**, and only then use it. This
satisfies the pinning requirement more strictly than a pinned action would
— the toolchain bytes are checksum-verified against the project's own lock
file, not merely against an action's own manifest.

The cost is that **there is no dependency cache**. Every run downloads the
Go module closure and the npm closure. This is a deliberate trade: cache
correctness is unverifiable here, and a wrong cache key silently serves a
stale closure, which is exactly the failure mode the lock file exists to
prevent. When a verified `actions/cache` digest becomes available, caching
can be added without changing anything else — the cache directories are
already set up in the workflow comments.

Gap **T4-C1**: `actions/cache` is unused because no verifiable SHA exists
locally. Consequence: no caching, slower runs, more network use per run.
Owner: 01 or the Chief Architect, once a digest source is agreed.

Gap **T4-C2**: `actions/setup-go` and `actions/setup-node` are unused for the
same reason. Consequence: the toolchain-install steps are hand-written and
have never been executed. They are the most likely place for a first-run
failure.

Gap **T4-C3**: only `linux-amd64` toolchain checksums exist in
`packaging/versions.lock`. The workflow therefore targets `ubuntu-24.04`
(the x64 hosted runner) and does not claim arm64 support. If an arm64
runner is ever wanted, the lock file must gain the arm64 checksums first.

## The workflow

`.github/workflows/verify.yml`, four jobs.

### Triggers and permissions

- `push` to `main`, and `pull_request` targeting `main`.
- **Never** `pull_request_target`. That trigger runs with repository
  secrets and write permissions even for fork pull requests, which is the
  classic privilege-escalation path. Its absence is a hard rule here.
- No `workflow_dispatch`, so the workflow is not manually dispatchable in
  its current form.
- Workflow-level `permissions: contents: read`. No job widens it. No job
  requests `write`, `id-token`, `packages` or `actions`.
- **No secret is referenced anywhere.** No deploy, publish, release or
  package step exists.

### Job 1 — `go`

Working directory: repository root.

| Step | Command | Purpose |
|---|---|---|
| Checkout | `actions/checkout@3d3c42e…` (v7.0.1), `persist-credentials: false` | The token is not left in the git config, so no later step can use it. |
| Install Go | `curl` go.dev tarball → `sha256sum --check --strict` → extract | Toolchain pinned to `go1.27.3`, checksum `65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40` from `versions.lock` §2. |
| Version check | `test "$(go env GOVERSION)" = "go1.27.3"` | Fails the job if the wrong toolchain was installed. |
| Module closure | `go mod verify`, `go mod tidy -diff` | Read-only. `tidy -diff` reports drift without writing `go.mod`/`go.sum`. |
| Build | `go build ./cmd/...`, `go vet ./...` | Both binaries, then vet. |
| Unit tests | `go test -count=1 ./...` | See below. |
| Race tests | `go test -count=1 -race ./...` | See below. |

`-count=1` disables the test result cache, so a run never reports a cached
result as a fresh pass.

The unit and race steps **detect** whether any test file exists:

```sh
go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... | grep -q .
```

If the list is empty, the step prints `NOT_RUN: no *_test.go files exist in
this commit (2 packages, 0 with tests).`, prints `This step exits 0 and
asserts NOTHING.`, and exits 0. If tests exist, they run for real and a
failure fails the job.

The package count is echoed, never asserted. Asserting "2 packages" would
break the moment a third package appears, and asserting "tests exist" would
break the moment the first test lands — which is precisely the wrong moment
to fail a build.

Both branches were executed locally against the real repository: the
no-tests branch prints the NOT_RUN lines and exits 0.

**The race step runs as an unprivileged user on the hosted runner.** It
creates no network namespace, changes no firewall rule, and needs no root
capability. The race detector itself is the only thing being exercised.

### Job 2 — `frontend`

Working directory: `web/` (set with `defaults.run.working-directory`).

| Step | Command | Purpose |
|---|---|---|
| Checkout | as above | |
| Install Node | `curl` nodejs.org tarball → `sha256sum --check --strict` → extract | Toolchain pinned to `v22.23.4`, checksum `1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce` from `versions.lock` §3. |
| Version check | `test "$(node --version)" = "v22.23.4"` | |
| Install deps | `npm ci --ignore-scripts --no-audit --no-fund` | See below. |
| Lockfile not rewritten | `git diff --exit-code -- package.json package-lock.json` | Fails if the install mutated a committed manifest. |
| Typecheck | `npm run typecheck` | `tsc --noEmit`. |
| Build | `npm run build` | `tsc --noEmit && vite build`. |
| Unit tests | `npm run test -- --run` | Detects absence; see below. |
| E2E tests | `npm run test:e2e` | Detects absence; see below. |
| Upload artifact | `actions/upload-artifact@043fb46d…` (v7.0.1), `if: always()` | The built `web/dist`, 7-day retention, `if-no-files-found: ignore`. |

**`npm ci`, never `npm install`.** `npm ci` installs strictly from
`package-lock.json` and fails if the lockfile is out of sync with
`package.json`; `npm install` would silently rewrite the lockfile. The
lockfile is the reviewed artefact and CI must not mutate it.

**`--ignore-scripts` is mandatory, not precautionary.** The closure contains
a package with an install script (`fsevents`, optional, darwin-only), and
`--ignore-scripts` is what prevents any third-party build code from
executing during install. This is the same rule T002 established locally
(`docs/engineering/T002-setup.md`).

`--no-audit --no-fund` avoids the two network calls npm makes by default;
neither is needed for a verification run.

The frontend test steps detect whether the script exists:

```sh
node -e "const s=require('./package.json').scripts||{};process.exit(s.test?0:1)"
```

`web/package.json` currently declares only `dev`, `build`, `typecheck` and
`preview`. There is no `test` and no `test:e2e`, so both steps report
`NOT_RUN` and exit 0. The day the scripts appear, the same steps run them
for real — no workflow edit is needed. Both branches were executed locally
against the real `web/package.json`.

### Job 3 — `contract`

Working directory: repository root. No toolchain installation needed: the
checks use `python3` and `PyYAML`, both present on the hosted runner image.

| Step | Purpose |
|---|---|
| JSON contracts parse | `json.load` over `contracts/*.json` — currently `helper.schema.json`. |
| OpenAPI parses and its references resolve | PyYAML parse; asserts `openapi` starts with `3.1`; walks every `$ref` and asserts the target exists; asserts `operationId`s are present and unique. Prints the counts. |
| Whitespace and manifest consistency | `git diff --check`; `git diff --exit-code -- go.mod go.sum web/package.json web/package-lock.json`. |

**This is a structural check, not an OpenAPI conformance check.** The
difference is real and is not papered over:

- A *structural* check asks "does this file parse, do the references
  resolve, are the identifiers unique". That is what this job does, and it
  is a genuine assertion that fails the job on failure.
- A *conformance* check asks "does this document satisfy the OpenAPI 3.1
  specification". That requires a validator implementing the specification.

No OpenAPI validator is vendored in this repository, none is installed on
this machine, and the task forbids inventing a passing checker. The step
therefore prints, in its own output:

```
NOT_RUN: full OpenAPI conformance validation — no validator is vendored or installed.
```

Gap **T4-C4**: OpenAPI conformance validation is NOT_RUN. The prerequisite
is a decision about which validator to trust and vendor. This is the same
prerequisite the T005 artifact names — the OpenAPI document itself is
partial, so full conformance would in any case validate only a partial
contract.

The manifest-consistency step is what makes "the CI installs exactly the
reviewed closure" a checkable claim rather than an intention: if any step
mutated `go.mod`, `go.sum` or the npm manifests, the job fails.

### Job 4 — `network-integration` (opt-in, disposable VM only)

**Inert.** `if: false`, and it would additionally require a repository
variable set by a human. It provisions nothing: no VM is created, no
namespace is set up, no firewall rule is written, no root capability is
requested, and the job's only step prints an explanation.

This is the gate described below, not an implementation of it.

## Validation versus coverage — the distinction this workflow preserves

This is the point the task asks to be stated explicitly, so it is stated
in the workflow itself as well as here.

| | Validation | Coverage |
|---|---|---|
| Question | "Is the thing correct?" | "Is the thing exercised?" |
| Example | `go build`, `go vet`, `go mod verify`, `npm run typecheck`, `npm run build`, contract structure | `go test`, `go test -race`, frontend unit, E2E |
| On the current scaffold | **PASS** — these run and assert | **NOT_RUN** — there is nothing to run |
| In CI | fails the job on failure | runs when the test files appear |

A green CI run on the current scaffold therefore means: *the code builds,
the dependency closure is intact and reproducible, the type check passes,
the contracts are structurally sound.* It does **not** mean *the code has
been tested.* The workflow prints that distinction in the log of every
affected step, so the claim cannot be misread from the logs alone.

There are **no test files in the repository**: no `*_test.go`, no
`*.test.ts`, no `*.spec.ts`, no Vitest/Jest/Playwright config, no `test/`
directory. The Go side has 2 packages (`cmd/raylane`,
`cmd/raylane-net`); neither has a test file.

## Command reference

Every command the workflow runs, with its working directory. This is the
contract the workflow implements.

| Working directory | Command | Job |
|---|---|---|
| repository root | `go mod verify` | go |
| repository root | `go mod tidy -diff` | go |
| repository root | `go build ./cmd/...` | go |
| repository root | `go vet ./...` | go |
| repository root | `go test -count=1 ./...` | go (when tests exist) |
| repository root | `go test -count=1 -race ./...` | go (when tests exist) |
| `web/` | `npm ci --ignore-scripts --no-audit --no-fund` | frontend |
| `web/` | `git diff --exit-code -- package.json package-lock.json` | frontend |
| `web/` | `npm run typecheck` | frontend |
| `web/` | `npm run build` | frontend |
| `web/` | `npm run test -- --run` | frontend (when the script exists) |
| `web/` | `npm run test:e2e` | frontend (when the script exists) |
| repository root | `python3 -c "import json,sys; json.load(...)"` over `contracts/*.json` | contract |
| repository root | `python3` — OpenAPI parse, `$ref` resolution, `operationId` uniqueness | contract |
| repository root | `git diff --check` | contract |
| repository root | `git diff --exit-code -- go.mod go.sum web/package.json web/package-lock.json` | contract |

The future-test commands match the contract already recorded in
`specs/001-selected-connections/quickstart.md`:

```sh
go test ./...
go test -race ./...
npm --prefix web ci
npm --prefix web run test -- --run
npm --prefix web run test:e2e
```

The quickstart also states that the namespace tests need "a separate runner
inside a disposable VM", and that its exact command is added after
implementation, and that an arbitrary root script must not be run on the
working machine. That is the gate below.

## Network-integration runner — opt-in, disposable VM only

The network-integration suite (US-05: synthetic router/client/Ubuntu/WAN
namespaces; FR-020; FR-021 restore; FR-023 update race) cannot run on a
host root and must never touch the operator's LAN or real subscriptions.
The requirements, from the plan and the quickstart:

1. **A disposable Linux VM per run**, never the developer's host and never a
   long-lived server. The VM is destroyed after the run.
2. **Isolated namespaces inside that VM** — separate network namespaces for
   the router, the client and the WAN side, with the test's own resolver and
   its own routing table. Not host namespaces, not the host's firewall.
3. **Synthetic fixtures only.** No real subscriptions, no real credentials,
   no real certificate authorities, no live endpoints. The plan's scenario
   table is explicit: synthetic router/client/Ubuntu/WAN namespaces.
4. **Explicit human approval** before the suite is enabled, and again
   before any run that could reach the operator's LAN. The plan records
   that a real LAN smoke test and an Ubuntu disconnect are permitted only
   after separate user confirmation and only after isolation succeeds.
5. **Evidence, not vibes.** Each run is bound to a commit, the versions,
   the stand configuration and the scenario ID; redacted logs, exit code,
   expected vs actual, and PASS / FAIL / NOT_RUN.

**What this task did:** documented the gate. It did **not** provision a VM,
create a runner, write a namespace script, enable the job, or schedule
anything. The `network-integration` job is `if: false` and stays that way
until a human deliberately changes it.

**The enabling sequence, when it is authorised:**

1. The Chief Architect chooses the runner technology and the VM lifecycle.
2. The VM image and its provisioning script are written and reviewed.
3. The exact namespace-test command is recorded in
   `specs/001-selected-connections/quickstart.md`, which currently reserves
   a placeholder for it.
4. A human sets the repository variable that gates the job, and removes
   `if: false`.
5. Only then does the suite run — still against a disposable VM, still with
   synthetic fixtures, never against the host's LAN.

Gap **T4-C5**: the network-integration suite is NOT implemented and NOT_RUN.
It is blocked on the runner-technology decision and on the test
implementation itself, not on anything in this task.

## Failure propagation

Every shell step uses `set -euo pipefail`, so a failing command fails the
step, and a failing step fails the job, and a failing job fails the
workflow. There is no `|| true` anywhere and no step that swallows an exit
code.

Two steps deliberately exit 0 on a condition that is not a failure:
the "no tests present" branches. Those conditions are absences of
*coverage*, not defects, and they are announced in the log. Every other step
propagates failure.

`concurrency.cancel-in-progress` cancels a superseded run of the same
ref, so a force-push does not leave two runs competing.

## Cache safety

There is no cache in the current workflow, so there is no cache-poisoning
surface — but the reason is not an oversight, and it is worth stating what
would change if caching is added:

- The cache key must include the lockfile hash (`go.sum`,
  `web/package-lock.json`), so a dependency change can never be served a
  stale closure.
- The cache must be scoped to the runner OS and the toolchain version.
- `actions/cache` is safe to use *only* with a verified digest. A mutable
  `@v4` reference would let a compromised or merely updated upstream
  action run arbitrary code with the job's permissions.
- The npm cache path must be the runner's tool cache, not the repository,
  so nothing cached can be committed or influence a later build.

## What a reviewer should check

- That no step claims a passing test run while the scaffold has no tests.
- That the `set -euo pipefail` discipline is intact in every step, and that
  no step hides an exit code.
- That `permissions` is `contents: read` throughout, that no secret is
  referenced, and that `pull_request_target` is absent.
- That the two action pins are the ones corroborated locally, and that no
  third action was added without a verifiable digest.
- That the checksums in `env` still match `packaging/versions.lock` after
  any lock-file update — the workflow hard-codes them, so a lock revision
  must be mirrored here or the job fails loudly at the checksum step.
- That the `network-integration` job stays inert.

## Gaps summary

| ID | Subject | State |
|---|---|---|
| T4-C1 | `actions/cache` unused — no verifiable local digest | Bounded gap; consequence is no caching |
| T4-C2 | `actions/setup-go` / `actions/setup-node` unused — no verifiable local digest | Bounded gap; consequence is hand-written, never-executed install steps |
| T4-C3 | No arm64 checksums in `versions.lock` | Bounded gap; workflow targets x64 only |
| T4-C4 | OpenAPI conformance validation | NOT_RUN; prerequisite is a validator decision |
| T4-C5 | Network-integration suite | NOT_RUN; blocked on runner-technology decision and implementation |

## Scope note

This task changed exactly two paths: `.github/workflows/verify.yml` and
`docs/engineering/testing.md`. It did not change the feature contracts,
the task list, the acceptance criteria, `packaging/versions.lock`, the
dependency manifests, or any product source. T004 is not APPROVED: it waits
for the 03 review and the 04 checks.
