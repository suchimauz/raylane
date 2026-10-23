# T001 — research log & verification evidence — revision 2 (T001-fix-r1)

Task: T001 (G1) — release/capability/license matrix and provenance for the Xray source
baseline, Go, Node, React, SQLite driver, dnsmasq/nft/iproute2, crypto/parser deps.
Author: agent 05 (Researcher). Verification dates: rev1 2026-10-23, rev2 2026-10-23 (UTC).
Base for rev2: d7b75a8 (includes 01's review-round-1 record). Review target of round 1
was 521b018; this revision answers docs/verification/T001-review-round1.md (H1–H4,
M1–M7, L1–L2). Dispositions: §9. T001/G1 remain OPEN.
Constraints honored: public HTTPS GET only, no sudo/host changes/binary execution,
no private sources/secrets, no push/deploy. tasks.md untouched. Budget: one bounded
correction package (≈35 GETs, <2 MiB downloaded; no archives).

## 1. Method

1. Read spec.md FR-001–008/017/019/020/021, plan.md, research.md, analysis.md,
   contracts/, DECISIONS.md (D-061 closes A01), XRAY_TRANSPARENT_CONTRACT.md,
   PASSWALL_RESEARCH.md, PASSWALL_NETWORK_TRACE.md, SETTINGS_REFERENCE.md,
   CONNECTION_GAPS.md, UBUNTU_NETWORK_PORTABILITY.md, and round-1 review.
2. Rev2 corrections verified against authoritative metadata on 2026-10-23:
   Launchpad API + archive.ubuntu.com Sources.xz (Ubuntu), proxy.golang.org (Go
   modules + Origin hashes), gitlab.com/cznic/sqlite, go.dev, nodejs.org,
   npm registry, GitHub API (incl. git trees for the finalmask directory).
3. Local tag claim (research.md:49) re-verified via GitHub API: tag v26.10.21 →
   commit 1b1647cd9ddf0abc34b981d4611fc03bcac1ca74. Confirmed at metadata level.
4. Trust recorded separately: source / release-metadata / binary (binary NOT trusted;
   01 decision: not an accepted runnable baseline).

## 2. Key findings (rev2 state)

- Xray v26.10.21 (commit 1b1647cd…, 2026-10-21), MPL-2.0, go.mod `go 1.27`, upstream
  release workflow setup-go@v7 + go-version-file. .dgst assets carry MD5/SHA1/
  SHA2-256/SHA2-512; linux-64 SHA2-256 recorded verbatim in versions.lock. No
  signature-like files were observed in the release asset list on 2026-10-23
  (observation limited to the asset list — M1; not a claim about all upstream
  signing channels).
- Go: pinned go1.27.3 with published SHA2-256 from go.dev JSON (M7). Static
  compatibility only — NO build was run (M2); build validation is a T002 gate.
- Node: v22.23.4 (family kept per 01 decision), published SHA2-256 from
  nodejs.org/dist/v22.23.4/SHASUMS256.txt recorded (M7).
- React 19.3.1 / react-dom 19.3.1 (MIT), vite 8.3.5 (MIT), typescript 7.0.2
  (Apache-2.0) — exact dist-tag resolutions of 2026-10-23.
- SQLite: DIRECT PIN NOW SET (H3): modernc.org/sqlite v1.61.0
  (gitlab tag v1.61.0 = commit 4df1ebea0f1cf0cd6ec3245b26f5fec4234ce738,
  BSD-3-Clause-style, go 1.26.0 directive). Transitive closure stays T002.
- Ubuntu noble (H1): rev1 versions were wrong/stale. Corrected against Launchpad +
  Sources.xz: dnsmasq GA 2.90-2build2 → pin 2.91-0ubuntu0.24.04.2 (noble-updates,
  Published 2026-10-06, supersedes 2026-07-14 security pocket lineage); nftables
  GA 1.0.9-1build1 → pin 1.0.9-1ubuntu0.1 (noble-updates 2026-03-10); iproute2 GA
  6.1.0-1ubuntu6 → pin 6.1.0-1ubuntu6.4 (noble-updates 2026-07-01; rev1's
  6.1.0-1ubuntu6.2 Superseded 2025-07-29).
- dnsmasq nftset (H2): build-config evidence — noble Sources.xz Build-Depends for
  dnsmasq includes libnftables-dev → nftset backend built in noble package.
  Runtime `dnsmasq --version` on stand remains NOT_RUN and required.
- FinalMask (M4): mapping established from pinned source — see capabilities.md
  FR-008 row (proxy/wireguard/client.go L149–150 DialUDP + streamSettings.finalmask
  JSON surface). The rev1 "noisetls/noiseqq" identifiers were not found in the
  pinned source and are removed.
- quic-go (L1): github.com/apernet/quic-go → HTTP 301 → github.com/HyNetworks/quic-go
  (MIT). Module path unchanged; recorded as canonical-redirect note.

## 3. Blockers / escalations (honest status — NOT "none")

- OPEN GAPS (not blockers of this research, but not closed):
  1. Raylane's own Go dependency set beyond modernc.org/sqlite — T002.
  2. npm transitive closure (package-lock.json) — T002.
  3. Runtime dnsmasq/nft/iproute2 stand checks — NOT_RUN (out of scope/permissions).
  4. Kernel exact package pin — UNVERIFIED (hardware-dependent).
  5. Build validation (Xray with go1.27.3) — NOT_RUN, T002 gate.
  6. IPv6 profile proof (R-03) — open research gate.
  7. Happy Eyeballs RFC 8305 parity mapping — UNVERIFIED (T005+).
  8. allowInsecure semantic parity (PASSWALL_RESEARCH.md:66) — UNRESOLVED, must close
     before the affected subscription contract/compiler task (01 decision).
  9. Per-mask FinalMask JSON semantics valid for WireGuard UDP — UNVERIFIED (T005).
- No component required for the T001 lock remains unpinned after rev2; the gaps above
  are downstream tasks, tracked honestly instead of "no missing pins".
- Escalation posture unchanged: any failure of the T002 build gate or FinalMask
  contract tests → BLOCKED component report to 01, not silent scope change.

## 4. Artifacts

- packaging/versions.lock (rev2) — pins, provenance, trust levels, licenses.
- docs/engineering/capabilities.md (rev2) — per-FR matrix with corrected evidence.
- docs/verification/T001-research.md (this file, rev2).
- Raw evidence (scratch, git-ignored): .hyper/tmp/t001/*.json (rev1) and
  .hyper/tmp/t001/r1/* (rev2: lp-*.json, noble-main-Sources.xz, modernc-*.json/txt,
  node-shasums.txt, xray-wireguard.go, wg-client.go, conf-transport.go,
  conf-finalmask.go, transport-config.proto, tree-transport.json, pkg-*.html).

## 5. Checks (executed) — complete commands, HTTP status, timestamps (M5)

All from repo workspace, 2026-10-23 UTC, read-only GET. executedAt = date -u at run
time (19:00–19:06 UTC for rev2; rev1 18:39–18:45 UTC). artifactPath under
.hyper/tmp/t001/ (scratch, git-ignored).

Revision-1 checks (carried, still valid):
| # | command | exit | HTTP | artifact |
|---|---|---|---|---|
| 1 | `curl -sS -H "Accept: application/vnd.github+json" https://api.github.com/repos/XTLS/Xray-core/git/refs/tags/v26.10.21 -o xray-tag.json` | 0 | 200 | r1-.. / xray-tag.json |
| 2 | `curl … /commits/1b1647cd9ddf0abc34b981d4611fc03bcac1ca74 -o xray-commit.json` | 0 | 200 | xray-commit.json |
| 3 | `curl … /releases/latest -o xray-latest.json` | 0 | 200 | xray-latest.json |
| 4 | `curl https://raw.githubusercontent.com/XTLS/Xray-core/1b1647cd…/LICENSE` and `…/go.mod` | 0 | 200 | xray-LICENSE, xray-go.mod |
| 5 | `curl …/go.sum` | 0 | 200 | xray-go.sum (172 lines) |
| 6 | `curl …/.github/workflows/release.yml` | 0 | 200 | xray-release.yml |
| 7 | `curl -L https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip.dgst` | 0 | 200 | xray64.dgst |
| 8 | `curl "https://go.dev/dl/?mode=json&include=all"` | 0 | 200 | go-versions.json |
| 9 | `curl https://nodejs.org/dist/index.json` | 0 | 200 | node-versions.json |
| 10 | `curl https://registry.npmjs.org/{react,react-dom,vite,typescript}/latest` | 0 | 200 | npm-*.json |
| 11 | `curl https://api.github.com/repos/mattn/go-sqlite3/releases/latest` + master go.mod | 0 | 200 | (stdout) v1.14.52 |
| 12 | `curl https://gitlab.com/cznic/sqlite/-/raw/master/{go.mod,LICENSE}` | 0 | 200 | (stdout) |
| 13 | `curl https://api.github.com/repos/{golang/crypto,gorilla/websocket,xtls/reality,refraction-networking/utls,quic-go/quic-go,miekg/dns,mattn/go-sqlite3}` | 0 | 200 | license SPDX (stdout) |
| 14 | `curl …/transport/internet/config.proto` (grep TProxyMode) | 0 | 200 | (stdout) |
| 15 | `curl …/infra/conf/xray.go` (grep dokodemo/sniffing) | 0 | 200 | (stdout) |
| 16 | `git log -1 --format=%H; git status --porcelain` | 0 | n/a | base 7ebd985+c21bb12, clean |

Revision-2 checks (new, T001-fix-r1):
| # | command | exit | HTTP | executedAt (UTC) | artifact |
|---|---|---|---|---|---|
| 17 | `curl https://archive.ubuntu.com/ubuntu/dists/noble/main/source/Sources.xz -o r1/noble-main-Sources.xz` | 0 | 200 (1 383 940 B) | 19:01 | r1/noble-main-Sources.xz |
| 18 | `curl "https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedSources&source_name={dnsmasq,nftables,iproute2}&distro_series=/ubuntu/noble&exact_match=true"` | 0 | 200 | 19:01–19:02 | r1/lp-{dnsmasq,nftables,iproute2}.json |
| 19 | `xzcat r1/noble-main-Sources.xz | awk '/^Package: dnsmasq$/,/^$/'` (Version 2.90-2build2; Build-Contains libnftables-dev) — also nftables 1.0.9-1build1, iproute2 6.1.0-1ubuntu6 | 0 | n/a | 19:02 | (stdout) |
| 20 | `curl https://proxy.golang.org/modernc.org/sqlite/@latest` → v1.61.0 + Origin hash | 0 | 200 | 19:02 | r1/modernc-latest.json |
| 21 | `curl https://proxy.golang.org/modernc.org/sqlite/@v/v1.61.0.mod` | 0 | 200 | 19:03 | (stdout) go 1.26.0 |
| 22 | `curl https://gitlab.com/cznic/sqlite/-/raw/v1.61.0/LICENSE` | 0 | 200 | 19:03 | r1/modernc-LICENSE.txt |
| 23 | `curl https://proxy.golang.org/<mod>/@v/<ver>.info` for utls v1.8.3-0.20260301010127-aa6edf4b11af, xtls/reality v0.0.0-20261014101318-83f621788ca8, apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e, ghodss/yaml v1.0.1-0.20220118164431-d8423dcdf344, grpc v1.84.0 | 0 | 200 each | 19:05 | (stdout, Origin hashes in versions.lock §6) |
| 24 | `curl -sI https://github.com/apernet/quic-go` → 301 → HyNetworks/quic-go; `curl https://api.github.com/repos/HyNetworks/quic-go` → license MIT | 0 | 301/200 | 19:05 | (stdout) |
| 25 | `curl https://nodejs.org/dist/v22.23.4/SHASUMS256.txt` | 0 | 200 | 19:05 | r1/node-shasums.txt |
| 26 | go1.27.3 file SHA256 extracted from saved go-versions.json (check 8 artifact) | 0 | n/a | 19:05 | (stdout) |
| 27 | `curl https://api.github.com/repos/XTLS/Xray-core/git/trees/1b1647cd…:transport?recursive=1` | 0 | 200 | 19:04 | r1/tree-transport.json (finalmask subtree listing) |
| 28 | `curl …/infra/conf/transport_internet.go` `…/infra/conf/transport_finalmask.go` `…/infra/conf/wireguard.go` `…/proxy/wireguard/client.go` @1b1647cd | 0 | 200 | 19:03–19:04 | r1/conf-transport.go, r1/conf-finalmask.go, r1/xray-wireguard.go, r1/wg-client.go |
| 29 | `curl https://packages.ubuntu.com/{dnsmasq,nftables,iproute2}/{noble,noble-updates,noble-security}` | 0 | mixed (several "Internal Server Error" pages, some empty) | 19:00 | r1/pkg-*.html — RECORDED AS UNRELIABLE; not used as evidence; Launchpad+archive used instead (negative check, not claimed as PASS) |
| 30 | `curl https://raw.githubusercontent.com/modernc.org/sqlite/master/go.mod` | 0 | 404 body | 18:44 (rev1) | recorded ONLY as "this URL 404s" (M6); no mirror-absence inference |
| 31 | `git diff --check` on rev2 changes | 0 | n/a | commit time | clean |
| NOT_RUN | local archive-hash vs .dgst comparison (no binary downloads allowed) | — | — | — | — |
| NOT_RUN | `dnsmasq --version` / `nft --version` / host probing | — | — | — | forbidden by scope |
| NOT_RUN | signature verification of upstream assets (no signature channel observed in asset list; binary path rejected by 01 anyway) | — | — | — | — |
| NOT_RUN | any build of Xray/Raylane/UI | — | — | — | T002 gate |

## 6. Risks

- npm dist-tag drift: T002 must diff lockfiles against §3 numbers of versions.lock.
- dnsmasq nftset is build-config-proven only; stand must run `dnsmasq --version`
  before relying on nftset directives (gate).
- Ubuntu package versions continue to move in -updates; re-run checks 17–19 at stand
  provisioning time; pins recorded here are exact as of 2026-10-23.
- modernc.org/sqlite v1.61.0 is one day newer than the Xray release — no relation,
  but its own transitive deps resolve at T002 (go.sum).
- finalmask per-mask JSON semantics for WireGuard UDP unproven → T005 contract test;
  failure there = BLOCKED component, escalation per workflow.

## 7. Reproducible verification invariants (for 03/04 re-check)

- tag v26.10.21 → commit 1b1647cd… (mismatch → FAIL G1, stop before T002).
- go.mod at pinned commit still `go 1.27` (upstream bump → re-check Go pin).
- .dgst SHA2-256 line equals versions.lock §1 value (mismatch → treat assets as
  re-issued → BLOCKED, escalate).
- Launchpad: dnsmasq/nftables/iproute2 Published-in-Updates versions ≥ recorded pins;
  a newer Published version is NOT a mismatch of this lock (pins stand until 01
  approves a bump) but must be re-evaluated at provisioning.
- proxy.golang.org .info Origin hashes equal versions.lock §6 values (mismatch →
  module retraction/substitution → BLOCKED, escalate).
- go1.26.x + Xray v26.10.21 must fail at build (go.mod directive) — expected failure;
  never work around with -mod=mod edits.
- kernel < 4.18 or nftables < 1.0 on target → tproxy unavailable → deployment
  rejected with reason (FR-020), not silently downgraded.

## 8. Questions for 01

1. (answered round-1) Node stays 22 LTS. Recorded.
2. (answered round-1) Upstream binary path rejected as trusted baseline. Recorded;
   digests kept as provenance only.
3. Kernel exact pin: defer to stand provisioning (hardware metapackage) or pin
   linux-image-generic HWE version now? Currently UNVERIFIED by design.
4. allowInsecure parity closure: assign to T005 contract scope (recommend) or a
   separate research spin?

## 9. Disposition of round-1 findings

| ID | Disposition |
|---|---|
| H1 | FIXED. Exact versions from Launchpad API + archive.ubuntu.com Sources.xz with pocket/status/published dates (checks 17–19): dnsmasq pin 2.91-0ubuntu0.24.04.2 (noble-updates), nftables 1.0.9-1ubuntu0.1, iproute2 6.1.0-1ubuntu6.4; rev1 wrong values documented as corrected. Pocket/security rationale in versions.lock §5. |
| H2 | FIXED (to available evidence level). Build-config evidence: noble Sources.xz dnsmasq Build-Depends include libnftables-dev (check 19). Runtime proof stays NOT_RUN and is an explicit gate (§7). Claim reworded accordingly. |
| H3 | FIXED. Direct pin modernc.org/sqlite v1.61.0 with gitlab tag commit 4df1ebea…, license text at tag, go 1.26.0 directive (checks 20–22). Only transitive closure deferred to T002. |
| H4 | FIXED. Complete versions recorded (utls v1.8.3-0.20260301010127-aa6edf4b11af, reality v0.0.0-20261014101318-83f621788ca8, apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e, ghodss/yaml v1.0.1-0.20220118164431-d8423dcdf344) with proxy.golang.org .info re-verification and Origin hashes (check 23). Lock/matrix cross-references reconciled. |
| M1 | FIXED. Claim restricted: "no signature-like files observed in the release asset list on 2026-10-23"; no categorical statement about all upstream signing channels. |
| M2 | FIXED. "Static compatibility only" wording; build validation explicitly NOT_RUN, T002 gate (versions.lock §2, capabilities summary). |
| M3 | FIXED. grpc v1.84.0 now in versions.lock §6 with license/canonical source and in capabilities.md FR-002 grpc row. |
| M4 | FIXED. Mapping established from pinned source: proxy/wireguard/client.go L149–156 (FinalMask.DialUDP) + streamSettings.finalmask JSON (transport_internet.go L56, transport_finalmask.go L1303–1307), finalmask tree listing via git trees API (checks 27–28). Unfounded "noisetls/noiseqq" removed. Per-mask WireGuard validity honestly marked UNVERIFIED (T005); FR-008 not dropped. |
| M5 | FIXED. §5 now lists complete commands, exit codes, HTTP statuses, per-batch UTC timestamps, artifact paths. |
| M6 | FIXED. 404 on one raw.githubusercontent URL recorded as bare HTTP outcome only (check 30); no mirror-absence inference; canonical source from proxy Origin. |
| M7 | FIXED. go1.27.3 linux-amd64+src SHA2-256 (go.dev JSON) and node v22.23.4 linux-x64+src SHA2-256 (SHASUMS256.txt) recorded with algorithm, artifact identity, origin, retrieval date (checks 25–26). Archive-vs-digest verification stays NOT_RUN, recorded as such. |
| L1 | FIXED. apernet/quic-go → 301 → HyNetworks/quic-go recorded as canonical redirect; module path unchanged (check 24). |
| L2 | FIXED. "Commit is HEAD of the release branch" removed (no evidence); only tag→commit and release-object facts retained. |

Status: rev2 research COMPLETE within scope/allowed paths. T001/G1 NOT closed;
awaits 03/04 review of the new immutable commit.
