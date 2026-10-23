# T002 — Setup: runnable Go/React skeleton

Status: **scaffold complete (self-executed checks).** The inert scaffold is
committed, both Go binaries build, the UI bundle builds, and the smoke checks
pass without privileges or network. All check results in this document are
**self-reported by the implementing agent** — they are not an independent
acceptance. Independent verification so far: agent 04 confirmed the toolchain
archive digests and extraction; agent 03 performed a static code audit
(`.hyper/tmp/t002/T002-audit-code-REPORT.md`); agent 04 performed a readonly
evidence/process audit (`.hyper/tmp/bul/t002-evidence-audit/REPORT.md`).
**Independent runtime execution of the build and smoke checks is NOT_RUN** —
it has not been performed by anyone other than the implementing agent. T002
therefore stays open pending an independent runtime check.

Base commit of this work: `97c67ea` (the tree at the time of writing).
Scope: T002 only — Go module, two command entry points, web build scaffold and
exact lockfiles. No product behaviour, no auth, no storage, no helper network
operations, no privileged defaults.

## Pins

Most versions come from `packaging/versions.lock` (T001, G1). Nothing is
resolved from a moving tag; no version range is used anywhere in the tree.

| Component | Pin | Source |
|---|---|---|
| Go toolchain | `go1.27.3` | versions.lock §2 |
| Node.js | `v22.23.4` | versions.lock §3 |
| Go module | `modernc.org/sqlite v1.61.0` | versions.lock §4 |
| React / React DOM | `19.3.1` / `19.3.1` | versions.lock §3 |
| Vite | `8.3.5` | versions.lock §3 |
| TypeScript | `7.0.2` | versions.lock §3 |
| @types/react / @types/react-dom | `19.3.0` / `19.3.0` | **not in versions.lock** — see below |

### Dev-type pins outside the accepted lock (F3)

`@types/react 19.3.0` and `@types/react-dom 19.3.0` are **not** recorded in
`packaging/versions.lock`. They were resolved by the implementing agent from
npm registry metadata on 2026-10-23 and are not part of the T001 accepted
baseline; treating them as T001 pins would misstate the provenance. Their
provenance is therefore:

- **Version resolution**: UNVERIFIED against an accepted lock. The versions
  were read from registry packuments during the T002 closure determination.
  They were not re-checked against the TypeScript/react type-compatibility
  matrix, and no T001 entry backs them.
- **Integrity**: pinned in `web/package-lock.json` with a `sha512` integrity
  hash and a `resolved` registry URL, so the exact bytes are reproducible.
- **Licence**: MIT, recorded per entry in the lockfile.
- **Not independently verified** by agent 03 or 04 beyond the lockfile fields
  being present and exact.

Adding them to `packaging/versions.lock` requires the orchestrator's decision
(it is an update to the T001 lock, not a T002-local choice); until then they
stay documented here as an explicit exception rather than being presented as
accepted pins.

`go.mod` declares `go 1.27.3` and pins every direct and indirect module at an
exact version; it is the output of `go mod tidy`, and `go mod tidy -diff`
reports no drift. `go.sum` carries the `h1:` hashes for the build modules plus
the `/go.mod` hashes of the complete module graph (50 lines). Every hash was
taken from the Go checksum database, so the lockfile is verifiable without
trusting this repository.

`web/package-lock.json` is lockfile v3 with 68 entries; every entry carries an
`integrity` hash and a licence field.

## Toolchain

The pinned toolchains were **not present** on this machine (only `go1.26.3`,
`go1.22.2`, and Node `v24.21.0` / `v20.18.2` from editor servers, with no
`npm`). They were installed **user-local**, without `sudo` and without touching
system paths:

```
~/.local/raylane-toolchains/go1.27.3/
~/.local/raylane-toolchains/node-v22.23.4/
~/.local/raylane-toolchains/dl/            # the downloaded archives
```

`/usr/local/bin/go`, `/usr/bin/node` and `/usr/bin/npm` still do not exist.
No shell profile, `~/.config`, or PATH file was modified: `PATH` was set
per-process in each command. Archives are kept for provenance.

Archive integrity, verified against the accepted upstream pins:

```
65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40  go1.27.3.linux-amd64.tar.gz   (70 588 678 B)
1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce  node-v22.23.4-linux-x64.tar.xz (31 029 996 B)
```

## Layout

```
go.mod, go.sum              Go module, exact pins + checksum-database hashes
cmd/raylane/main.go         control-plane entry point (inert)
cmd/raylane-net/main.go     restricted helper entry point (inert)
web/package.json            web build manifest, exact pins
web/package-lock.json       full closure with integrity hashes
web/tsconfig.json           strict TypeScript settings
web/vite.config.ts          build config; dev/preview bound to loopback
web/index.html              static shell, no external resources
web/src/main.tsx            entry point
web/src/App.tsx             inert placeholder screen
web/src/styles.css          base styles (system font, focus ring, reduced motion)
```

Both commands link the pinned SQLite driver so the module stays in the build
list, but no storage is opened and no schema is created. Storage behaviour
belongs to T006.

## Deliberate exclusions

- **`@vitejs/plugin-react` is not used.** Its 6.x line requires optional peers
  (`oxc-transform-react`, `@rolldown/plugin-babel`, `babel-plugin-react-compiler`)
  whose compatibility with the pinned Vite 8.3.5 is recorded as UNVERIFIED in
  versions.lock §3. Vite's built-in JSX transform builds this scaffold without
  an unverified peer. A later task may add it with explicit compatibility
  evidence.
- **No `engines`/`packageManager` drift.** `web/package.json` pins the Node
  version in `engines` for documentation; no `.nvmrc` or Corepack shim is added.
- **No test framework, linter or CI config.** T004 owns CI and
  `docs/engineering/testing.md`.
- **No `internal/` packages.** The plan reserves them for later tasks; T002
  creates only the two documented entry points.

## Closure content: lifecycle scripts and native packages

The web closure is not a set of pure-JavaScript packages. Two properties of
`web/package-lock.json` are disclosed here so that later audits do not have to
rediscover them.

### Lifecycle scripts (F1)

**One package in the closure declares an install script: `fsevents 2.3.3`**
(`hasInstallScript: true`, MIT, integrity-pinned). It is pulled in as an
*optional* dependency of `vite 8.3.5` (`~2.3.3`) and is gated to
`os: ["darwin"]`, so it is not installed on Linux. The earlier statement in
this document that "no package in this closure declares an install script" was
**wrong** and is withdrawn.

`--ignore-scripts` therefore remains **mandatory** for every npm invocation in
this project, not merely a precaution: it is what keeps the `fsevents`
`node-gyp` build script from ever running, and it is the reason the install is
safe on a machine that must not execute third-party build code. The root
`package.json` scripts of this project have no lifecycle hooks of their own.

### Native, platform-gated packages (F2)

The closure contains **prebuilt native binaries**, all `optional` and gated by
`os`/`cpu` (and, where the package declares it, `libc`), all integrity-pinned
with a registry `resolved` URL, and all without install scripts:

| Family | Entries | Role |
|---|---|---|
| `@rolldown/binding-*` | 15 | prebuilt native backend of `rolldown 1.2.15`, the bundler inside `vite 8.3.5` |
| `@typescript/typescript-*` | 20 | prebuilt native compiler binaries for `typescript 7.0.2` |
| `lightningcss-*` (platform variants) | 11 | prebuilt native CSS transformer used by `vite` |
| `fsevents` | 1 | optional macOS file-watching helper (see above) |

`web/package-lock.json` records **47** entries with an `os`/`cpu` gate in
total; on this Linux x64 host 25 of them are actually installed.

These packages are **build-time only**. They are not part of the browser
bundle: `vite build` emits `dist/index.html` plus one CSS and one JS asset, and
the native binaries are not referenced by the output. They are, however, real
platform-specific artefacts in the toolchain, so the closure is not portable
to another `os`/`cpu`/`libc` combination without re-resolving them.

`typescript 7.0.2` is a native-portable package: its own `dependencies` and
`optionalDependencies` both list the 20 per-platform binaries, and the
platform-appropriate one (`@typescript/typescript-linux-x64`, Apache-2.0,
integrity-pinned) is selected at install time.

## Download volume (estimate)

The exact number of bytes transferred over the wire is **UNKNOWN**. Bodies
served from the npm cache, repeated downloads and npm's internal retries are
not logged, and the HTTP header overhead of revalidation responses was not
recorded. What follows is an **estimate**, based on distinct content, not a
measured transfer.

The cap of 250 MiB (262 144 000 bytes) was set for this task and was **lifted
by the user** afterwards; the volume is therefore no longer a blocker. The
deviation from the original cap is recorded below as history and is not
presented as within budget.

| Component | Bytes | Basis |
|---|---|---|
| `go1.27.3.linux-amd64.tar.gz` | 70 588 678 | `stat -c %s` on the retained archive |
| `node-v22.23.4-linux-x64.tar.xz` | 31 029 996 | `stat -c %s` on the retained archive |
| npm metadata + tarballs (distinct blobs) | 191 926 637 | union of both npm caches, deduplicated by content hash |
| Go module files (zips, `.mod`, `.info`) | 52 487 906 | files added to the module cache during T002 |
| **Distinct-content total** | **346 033 217** | **330.00 MiB** |

Agent 04 independently measured the same quantity at **345 943 004 B
(329.92 MiB)** — a difference of 90 213 B (0.086 MiB), i.e. the same figure
within measurement noise. That is the basis of the table above.

**Range.** The 191 926 637 B npm figure counts distinct blobs only. The first
`npm install --package-lock-only` wrote a separate cache
(`/tmp/t002-npm/cache`, 154 501 448 B) whose content is largely duplicated in
the working cache. If that content was fetched again rather than served from
cache, the transfer was higher; the npm debug logs show the second run
revalidating 99 cached responses (bodies reused, only conditional headers sent,
header size unrecorded). The plausible range is therefore **329.92 MiB
(distinct) up to ~477 MiB (if the duplicated cache was fully re-fetched)**.
The exact value is not recoverable without new network requests.

Three inconsistent figures were reported by the implementing agent during
T002 (330.00 MiB, 423.35 MiB, and a 244.62 MiB figure in a scratch ledger).
The 423.35 MiB figure double-counted the duplicated cache; the 244.62 MiB
figure omitted the Go module zips. **330.00 MiB is the figure that 04
corroborates**, and it is the one used above.

### Reproduction notes

- The toolchain archives are retained under
  `~/.local/raylane-toolchains/dl/` and their digests match the accepted
  upstream pins.
- The npm metadata cache is retained under
  `.hyper/tmp/buj/t002/npm-cache/` (git-ignored), so `npm ci` is reproducible
  offline.
- The Go module cache under `~/go/pkg/mod` now holds the pinned closure.
- Future metadata lookups should use the minimal
  `https://registry.npmjs.org/<pkg>/<version>` endpoint instead of the full
  packument; the per-version document is far smaller and avoids repeating the
  whole version history.

## Checks

**Every check in the first table was executed by the implementing agent and is
self-reported.** It has not been reproduced by an independent party; agent 03
audited the code statically without executing it, and agent 04 audited the
evidence without executing anything. Independent runtime execution is
**NOT_RUN**.

Commands were run from the repository root with the pinned user-local
toolchain on `PATH` (process-local only).

| Check | Result | Command |
|---|---|---|
| Go toolchain version | PASS | `go version` → `go1.27.3 linux/amd64` |
| Node / npm version | PASS | `node --version` → `v22.23.4`; `npm --version` → `10.9.9` |
| Archive digests match pins | PASS | `sha256sum` on both archives |
| Go source formatted and parses | PASS | `gofmt -l -e cmd/raylane/main.go cmd/raylane-net/main.go` |
| **Go build, both binaries** | **PASS** | `go build ./cmd/...` → exit 0 |
| `go vet` | PASS | `go vet ./...` → exit 0 |
| `go mod verify` | PASS | `go mod verify` → `all modules verified` |
| `go mod tidy` drift | PASS | `go mod tidy -diff` → exit 0 (no diff) |
| `go.sum` covers the graph | PASS | 50 lines, 0 missing `/go.mod` hashes |
| `npm ci` from the lockfile | PASS | `npm ci --ignore-scripts` → exit 0, 25 packages |
| Installed tree matches the lockfile | PASS | 25 packages checked, 0 drift; `npm ls --all` → exit 0 |
| **UI production build** | **PASS** | `npm run build` (`tsc --noEmit && vite build`) → exit 0 |
| UI bundle output | PASS | `dist/index.html` 0.56 kB, CSS 1.69 kB, JS 220.43 kB (gzip 68.97 kB) |
| JSON manifests parse | PASS | `package.json`, `tsconfig.json`, `package-lock.json` |
| TSX sources parse and typecheck | PASS | `tsc --noEmit` → exit 0 |
| CLI smoke: `--version`, both binaries | PASS | JSON output, exit 0 |
| CLI smoke: unsupported argument | PASS | exit 2, usage on stderr, no side effect |
| CLI smoke: missing config / manifest | PASS | exit 1, `does not exist` on stderr |
| CLI smoke: config path is a directory | PASS | exit 1 |
| CLI smoke: existing config, unimplemented | PASS | exit 1, config file byte-identical afterwards |

No check required a privileged operation, a service, a real network, SSH or a
router. The two binaries were built and exercised inside the repository
workspace; build outputs are git-ignored.

### Isolation probes — author-reported, not evidence (F5)

The implementing agent additionally ran three classes of system probe to
support the isolation claims: `unshare -rn` (user + network namespace),
`strace -f -e trace=network`, and `ss -tulpn`. These are recorded here as
**author statements only**, and they are **withdrawn as evidence**:

- No raw output, log or `/proc` snapshot of those probes was preserved.
- In the `unshare … | head -3; echo $?` pipelines the reported exit status was
  the status of `head`, not of `unshare`, so those two exit codes are invalid
  as evidence. The two `--version` invocations used `echo $?` directly and are
  valid in form, but still have no surviving raw output.
- The namespace lifecycle and the absence of leftover processes were inferred,
  not observed.

Agent 04 therefore lists the namespace lifecycle as **NOT_OBSERVABLE** and the
pipeline exit codes as **invalid**. The isolation claims below rest only on
the argument that the two binaries contain no `net`, `exec`, `syscall`,
goroutine or listener code and no file write — a static property that agent 03
verified directly from the sources.

| Claim | Status |
|---|---|
| Binaries open no listening socket | Static: no listener code in either `main.go` (03). Runtime `ss` probe: author-reported, no raw evidence. |
| Binaries make no network syscall at startup | Static: no `net`/`syscall` import in either `main.go` (03). Runtime `strace` probe: author-reported, no raw evidence. |
| Binaries run with no network at all | Runtime `unshare -rn` probe: author-reported, exit status of the pipeline form invalid, no raw evidence. |
| Binaries run unprivileged | PASS: uid 1000, no setuid bit, no root required (03 verified the absence of privileged syscalls in the sources). |

If isolation must be demonstrated in a later task, it needs a form without a
pipeline and with the raw output retained.

## Evidence gaps

- The download channel was executed by the implementing agent only. No
  preserved log of the download commands exists; agent 04 confirmed the
  archives match the accepted upstream pins by digest and extraction, and
  located the npm debug logs (three runs, 224 HTTP requests) in the retained
  npm cache, which is what made the volume measurable at all.
- The build, vet, install and smoke results above are **self-reported**. Agent
  04 confirmed the *artefacts* they produced (both binaries, the bundle
  sizes, the 50-line `go.sum`, 25 installed packages) but did not re-execute
  anything, so independent runtime verification remains **NOT_RUN**.
- The `unshare`/`strace`/`ss` probes are withdrawn as evidence — see
  [Isolation probes](#isolation-probes--author-reported-not-evidence-f5).
- `versions.lock` §6 records the Xray-core transitive dependency set. Raylane's
  own Go module currently depends only on the SQLite driver and its transitive
  closure; the crypto/parser modules listed in §6 are not yet required, because
  no code in this scaffold uses them.
- The `@types/react` / `@types/react-dom` pins have no accepted-lock
  provenance — see [Dev-type pins outside the accepted lock](#dev-type-pins-outside-the-accepted-lock-f3).

## Re-running the checks

```sh
export PATH="$HOME/.local/raylane-toolchains/go1.27.3/bin:$PATH"
export PATH="$HOME/.local/raylane-toolchains/node-v22.23.4/bin:$PATH"

go build -o build/raylane ./cmd/raylane
go build -o build/raylane-net ./cmd/raylane-net
go vet ./...
go mod verify
go mod tidy -diff

npm --prefix web ci --ignore-scripts
npm --prefix web run build
```

`npm ci` runs with `--ignore-scripts`. This is **mandatory**, not
precautionary: the closure contains one package with an install script
(`fsevents`, optional, darwin-only), and `--ignore-scripts` is what prevents
any third-party build code from executing. No root `package.json` script of
this project has a lifecycle hook. The npm metadata cache in
`.hyper/tmp/buj/t002/npm-cache/` makes the install reproducible without
network access; the Go module cache under `~/go/pkg/mod` holds the pinned
closure.
