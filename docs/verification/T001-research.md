# T001 — research log & verification evidence

Task: T001 (G1) — release/capability/license matrix and provenance for the Xray source
baseline, Go, Node, React, SQLite driver, dnsmasq/nft/iproute2, crypto/parser deps.
Author: agent 05 (Researcher). Date of verification: 2026-10-23 (UTC).
Base commit: 7ebd9852ef5144f1377f723601abc9ef60e1c66d (+ 01's 047f2b4 review-criteria commit).
Budget: single bounded research package, public sources only, no paid services, no new agents.
Constraints honored: no sudo, no host firewall/DNS/sysctl changes, no untrusted script/binary
execution, no private sources/secrets, no push/deploy. tasks.md untouched.

## 1. Method

1. Read spec.md (FR-001–008/017/019/020/021), plan.md, research.md, analysis.md,
   contracts/, docs/discovery/DECISIONS.md (incl. D-061 closing A01),
   XRAY_TRANSPARENT_CONTRACT.md, PASSWALL_RESEARCH.md, PASSWALL_NETWORK_TRACE.md,
   SETTINGS_REFERENCE.md, CONNECTION_GAPS.md, UBUNTU_NETWORK_PORTABILITY.md.
2. Verified every pinned fact against live authoritative sources on 2026-10-23
   (GitHub API, go.dev, nodejs.org, npm registry, Ubuntu noble package versions,
   upstream changelogs). No `latest` used as a value; where a moving dist-tag was
   consulted, the exact resolved version is recorded with its date.
3. Local tag claim check: research.md line 49 states a LOCAL `git describe`/
   `tag --points-at` confirmed v26.10.21 on 1b1647cd. Re-verified independently via
   GitHub API (tag ref → commit) — confirmed. This is still NOT treated as proof of
   upstream signature trust (none exists); binary path stays optional.
4. Recorded trust separately: source / release-metadata / binary, per G1.

## 2. Key findings

- Xray v26.10.21 (commit 1b1647cd9ddf0abc34b981d4611fc03bcac1ca74, 2026-10-21) is the
  official latest release; MPL-2.0; go.mod `go 1.27`; upstream release workflow builds
  with setup-go@v7 + go-version-file → ≥ go1.27.0. Digest file (MD5/SHA1/SHA2-256/SHA2-512)
  published per asset; linux-64 SHA2-256 recorded in versions.lock. No GPG/cosign/SLSA
  signatures published → binary trust PARTIAL; baseline builds from source.
- Go: pinned go1.27.3 (latest stable 1.27 patch, 2026-10-23). No incompatibility with
  Xray's `go 1.27` requirement → NOT a blocker. go1.26.x unsupported; 1.28+ unverified.
- Node: v22.23.4 (latest v22 LTS "Jod", 2026-10-23). Node 24 "Krypton" is now the active
  LTS; family choice stays 22 LTS per plan R-01 — upgrade decision belongs to 01.
- React 19.3.1 / react-dom 19.3.1 (MIT), vite 8.3.5 (MIT), typescript 7.0.2 (Apache-2.0)
  — npm `latest` dist-tags resolved 2026-10-23; T002 must lock exact closure.
- SQLite: modernc.org/sqlite (BSD-3-Clause, pure Go, go.mod requires go 1.26.0 →
  compatible with 1.27) selected as default driver; exact module version pinned at T002
  via go.sum (not invented here). mattn/go-sqlite3 v1.14.52 (MIT) viable but cgo —
  not default.
- dnsmasq 2.90-4build1 / nftables 1.0.9-1build1 / iproute2 6.1.0-1ubuntu6.2 / kernel 6.8
  (Ubuntu 24.04 noble): nftset + nft tproxy + policy routing all present design-level.
  Runtime checks NOT_RUN (forbidden in this task).
- Crypto/parser deps (from pinned Xray go.mod): x/crypto v0.58.0 BSD-3, utls
  v1.8.3-0.20260301 BSD-3, xtls/reality MPL-2.0, gorilla/websocket v1.5.3 BSD-2,
  miekg/dns v1.1.73 BSD-3, wireguard-go MIT, protobuf BSD-3. No license conflict:
  MPL-2.0 file-level copyleft acceptable; Xray consumed as separate unmodified process.

## 3. Blockers / escalations

- No NEW blockers. Specifically: no Go 1.27 incompatibility found; no unconfirmable pin
  among required components (exact npm closure is deferred to T002 by design, not a
  blocker for T001).
- Pre-existing open gates carried over (not resolved by this task, by scope):
  IPv6 profile proof (R-03), upstream binary signature trust (absent upstream),
  Happy Eyeballs RFC-parity mapping, PassWall allowInsecure semantic parity
  (PASSWALL_RESEARCH.md:66 open question), runtime dnsmasq/nft stand checks.
- Node 22 vs 24 LTS: noted as observation; decision stays with 01/plan.

## 4. Artifacts

- packaging/versions.lock — pins, provenance, trust levels, licenses.
- docs/engineering/capabilities.md — per-FR capability matrix (SUPPORTED/UNVERIFIED/
  UNSUPPORTED/BLOCKED) with source citations.
- docs/verification/T001-research.md — this log.
- Raw fetched evidence (not committed): .hyper/tmp/t001/*.json, xray-go.mod,
  xray-go.sum, xray64.dgst, xray-release.yml (git-ignored scratch).

## 5. Checks (executed)

All commands run on 2026-10-23 UTC from repo workspace, network read-only (GET only).
`artifactPath` = .hyper/tmp/t001/<file> (scratch, git-ignored).

| # | command (abridged) | exitCode | artifact |
|---|---|---|---|
| 1 | `curl api.github.com/repos/XTLS/Xray-core/git/refs/tags/v26.10.21` | 0 | xray-tag.json — tag→commit 1b1647cd… (lightweight tag) |
| 2 | `curl api.github.com/repos/XTLS/Xray-core/commits/1b1647cd…` | 0 | xray-commit.json — date 2026-10-21T11:59:30Z, msg "Xray-core v26.10.21" |
| 3 | `curl api.github.com/repos/XTLS/Xray-core/releases/latest` | 0 | xray-latest.json — tag v26.10.21, published 2026-10-21T12:07:11Z, full asset list incl. .dgst |
| 4 | `curl raw.githubusercontent.com/…/LICENSE` and `…/go.mod` @1b1647cd | 0 | xray-LICENSE (MPL-2.0 header), xray-go.mod (`go 1.27`, full require list) |
| 5 | `curl raw …/go.sum @1b1647cd` | 0 | xray-go.sum — 172 pinned entries |
| 6 | `curl raw …/.github/workflows/release.yml @1b1647cd` | 0 | xray-release.yml — setup-go@v7, go-version-file: go.mod |
| 7 | `curl github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip.dgst` | 0 | xray64.dgst — SHA2-256 0eec3ed4…631978 (recorded in lock) |
| 8 | `curl "https://go.dev/dl/?mode=json&include=all"` | 0 | go-versions.json — go1.27.3 latest stable 1.27 patch |
| 9 | `curl nodejs.org/dist/index.json` | 0 | node-versions.json — v22.23.4 latest v22 LTS; v24.x "Krypton" active LTS |
| 10 | `curl registry.npmjs.org/{react,react-dom,vite,typescript}/latest` | 0 | npm-*.json — 19.3.1/19.3.1/8.3.5/7.0.2 + licenses |
| 11 | `curl raw.githubusercontent.com/mattn/go-sqlite3/master/go.mod` + releases/latest | 0 | v1.14.52 (2026-09-05), go 1.21 |
| 12 | `curl gitlab.com/cznic/sqlite/-/raw/master/go.mod + LICENSE` | 0 | modernc.org/sqlite, go 1.26.0, BSD-3-Clause-style license |
| 13 | `curl api.github.com/repos/{golang/crypto, gorilla/websocket, xtls/reality, refraction-networking/utls, quic-go/quic-go, miekg/dns, mattn/go-sqlite3}` | 0 | license SPDX ids as recorded |
| 14 | `curl raw …/transport/internet/config.proto @1b1647cd` (grep tproxy) | 0 | TProxyMode enum present |
| 15 | `curl raw …/infra/conf/xray.go @1b1647cd` (grep dokodemo/sniffing) | 0 | tunnel/dokodemo-door + sniffing config present |
| 16 | `git log -1 --format=%H; git status --porcelain` | 0 | base 7ebd985… (+047f2b4 by 01), tree clean before my changes |

Mismatch / unavailability probes (negative checks):
| # | command | exitCode | result |
|---|---|---|---|
| 17 | `curl raw.githubusercontent.com/modernc.org/sqlite/master/go.mod` | 0 (HTTP 404 body) | confirms GitHub mirror absent → canonical host is gitlab.com/cznic/sqlite; documented in lock |
| 18 | local `dnsmasq --version` / `nft --version` | NOT_RUN | host probing forbidden by task constraints; deferred to stand task |
| 19 | upstream release signature verification (gpg/cosign) | NOT_RUN (unavailable) | upstream publishes no signatures → binary trust PARTIAL, documented |

## 6. Risks

- npm dist-tags drift: recorded React/vite/TS versions are exact-as-of-2026-10-23;
  T002 must regenerate lockfiles and diff against these numbers.
- dnsmasq noble build flags (HAVE_NFTSET) verified at package/changelog level only;
  first stand boot must run `dnsmasq --version` before relying on nftset directives.
- Xray release cadence ~monthly: re-run §5 checks 1–7 before first baseline build;
  pin stays v26.10.21 until 01 approves a bump.
- modernc.org/sqlite exact version unresolved here (by design); T002 `go mod tidy`
  output becomes part of the lock evidence.

## 7. Reproducible verification (for 03/04)

Re-run any row of §5 with the listed curl commands (they are read-only). Expected
invariants:
- tag v26.10.21 → commit 1b1647cd9ddf0abc34b981d4611fc03bcac1ca74 (mismatch = FAIL G1,
  do not proceed to T002);
- releases/latest ≥ v26.10.21; if a newer tag exists, that is NOT a mismatch — the pin
  stands until 01 approves a bump (recorded observation, not drift);
- go.mod at the pinned commit still says `go 1.27`; if upstream bumps the directive,
  re-check Go pin compatibility before build;
- Xray-linux-64.zip.dgst SHA2-256 equals the value in versions.lock (mismatch = treat
  release assets as compromised/re-issued → BLOCKED, escalate);
- go.dev JSON lists a 1.27.x ≥ 1.27.0 as stable (if 1.27 line disappears from stable
  list, escalate toolchain decision).

Unsupported-combination checks (for later tasks, listed here per assignment):
- go1.26.x + Xray v26.10.21 → must fail at `go build` (go.mod directive) — expected
  failure, do not work around with `-mod=mod` edits;
- nftables < 1.0 or kernel < 4.18 on target → tproxy unavailable → deployment rejected
  with reason (FR-020 protective behavior), not silently downgraded.

## 8. Questions for 01

1. Node family: stay on 22 LTS (plan R-01) or move to 24 LTS "Krypton" (now active LTS)?
   No action taken; locked 22.23.4 per plan.
2. Binary-download path for Xray: keep as optional with recorded digests, or forbid
   entirely (source-build only)? Currently documented as optional + re-verify at T002.
3. allowInsecure semantic parity (PASSWALL_RESEARCH.md:66) — assign to contract-test
   task (T005 area) or keep as open question in analysis?

Status of this research: COMPLETE within approved scope/allowed paths. G1 evidence
assembled; APPROVED/Done NOT set (awaits 03 review + 04 evidence per workflow).
