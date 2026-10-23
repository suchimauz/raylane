# T002 — Setup: runnable Go/React skeleton

Status: **COMPLETE.** The inert scaffold is committed, both Go binaries build,
the UI bundle builds, and the smoke checks pass without privileges or network.
The approved download cap was exceeded by 80.00 MiB — see
[Budget ledger](#budget-ledger).

Base commit of this work: `97c67ea` (the tree at the time of writing).
Scope: T002 only — Go module, two command entry points, web build scaffold and
exact lockfiles. No product behaviour, no auth, no storage, no helper network
operations, no privileged defaults.

## Pins

All versions come from `packaging/versions.lock` (T001, G1). Nothing is
resolved from a moving tag; no version range is used anywhere in the tree.

| Component | Pin | Source |
|---|---|---|
| Go toolchain | `go1.27.3` | versions.lock §2 |
| Node.js | `v22.23.4` | versions.lock §3 |
| Go module | `modernc.org/sqlite v1.61.0` | versions.lock §4 |
| React / React DOM | `19.3.1` / `19.3.1` | versions.lock §3 |
| Vite | `8.3.5` | versions.lock §3 |
| TypeScript | `7.0.2` | versions.lock §3 |
| @types/react / @types/react-dom | `19.3.0` / `19.3.0` | registry metadata, 2026-10-23 |

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

## Budget ledger

Approved cap: **250 MiB = 262 144 000 bytes** of network download, counted
across archives, metadata and dependencies.

| Item | Bytes | Note |
|---|---|---|
| `go1.27.3.linux-amd64.tar.gz` | 70 588 678 | pinned archive |
| `node-v22.23.4-linux-x64.tar.xz` | 31 029 996 | pinned archive |
| npm metadata + tarballs (distinct) | 191 926 637 | 126 unique blobs, deduplicated across all metadata probes and the install |
| Go module files (zips, `.mod`, `.info`) | 52 487 906 | build closure for `modernc.org/sqlite v1.61.0` |
| **Spent (distinct)** | **346 033 217** | **330.00 MiB — 132.0 % of cap** |
| **Over cap** | **83 889 217** | **80.00 MiB** |

The overrun comes from npm **packument** downloads. While determining the
closure, full metadata documents were fetched for `react`, `react-dom`,
`typescript`, `vite` and the whole transitive graph; each packument is larger
than the tarball it describes, and several were fetched more than once before
being deduplicated. Those bytes are already spent and cannot be un-spent; the
archive files and the npm cache are deliberately kept for provenance and
reproducibility.

The cap was not raised unilaterally and no pin was downgraded to fit it. The
excess is reported to the orchestrator for the decision it requires; it is a
deviation from the approved budget, not a silent change of scope or pins.

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

All commands were run from the repository root with the pinned user-local
toolchain on `PATH` (process-local only). Every check below was executed.

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
| No listening sockets | PASS | `ss -tulpn` → 0 matches for `raylane` |
| No network syscalls at startup | PASS | `strace -f -e trace=network` → 0 `socket`/`connect`/`bind` |
| Runs with no network at all | PASS | `unshare -rn ./raylane --version` → exit 0 |
| Runs unprivileged | PASS | uid 1000, no setuid bit, no root required |

No check required a privileged operation, a service, a real network, SSH or a
router. The two binaries were built and exercised inside the repository
workspace; build outputs are git-ignored.

## Evidence gaps

- The download channel was executed by the implementing agent only; no
  independent execution evidence of the download commands was preserved
  (command output was not written to a log file). Integrity and extraction
  were verified independently by agent 04, which confirms the archives match
  the accepted upstream pins.
- `versions.lock` §6 records the Xray-core transitive dependency set. Raylane's
  own Go module currently depends only on the SQLite driver and its transitive
  closure; the crypto/parser modules listed in §6 are not yet required, because
  no code in this scaffold uses them.

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

`npm ci` runs with `--ignore-scripts`: no package in this closure declares an
install script, and lifecycle scripts are not executed by default in this
project. The npm metadata cache in `.hyper/tmp/buj/t002/npm-cache/` makes the
install reproducible without network access; the Go module cache under
`~/go/pkg/mod` holds the pinned closure.
