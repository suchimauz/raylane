# T007 — SecretRef/AEAD key access and allowlisted redaction: scoped acceptance record

This document records an EXTERNAL acceptance decision: the Orchestrator (bui) accepted
the approved scoped T007 deliverable only after BOTH independent review (03B) and
independent execution (04) roles closed every actual finding. It is not author
self-acceptance; author-run logs are context only, never independent proof. T007
acceptance is scoped to the approved secret-store/key-access/projection deliverable and
is NOT overall security-runtime, product, HTTP or foundation acceptance.

Accepted decision source: `.hyper/tmp/bui/T007-handoff/acceptance-decision.json`
(`ACCEPTED_SCOPED_AFTER_BOTH_INDEPENDENT_ROLES`), final consolidation
`.hyper/tmp/bui/T007-handoff/fixture-cleanup-independent-consolidation.json`, parent
identity verification `.hyper/tmp/bui/T007-handoff/fixture-cleanup-independent-consolidation-identity.txt`
(exit 0, 2026-10-24T05:37:19Z).

## Approved scope

`specs/001-selected-connections/tasks.md` T007 on the approved baseline: FR-019 and the
relevant FR-021 guarantees, research R-06, the Secret model, accepted D1/D4 and the
capability-profile boundaries. No requirement or architecture change was introduced or
needed.

## Immutable source identity

Accepted source target `27270c40a1d67e770cd4e13725485da4c3a7fa64`, parent
`f84fade4d49e8f79ec0698d690866d39d35cc5a1`, tree
`57274c86b4e313c488ba6001e49428a352fa98fe`. Implementation chain:

| Commit | Role | Substance |
| --- | --- | --- |
| `a41b5e4c…` | T006 acceptance baseline | unchanged starting point |
| `6257e28b…` | original T007 | eight authorized files, +1817/−0: appended migration 2, secret store, key access, profile projection. Independent review found S1/S2; tests found committed nonce-coverage gap C1. Independent inventory 36 top / 29 sub / 65 RUN |
| `c76cbaa6…` | correction 1 | six paths, +609/−134: S2 closed by a closed package-owned diagnostic vocabulary; C1 nonce regression committed. S1 stayed OPEN: `os.Root.OpenRoot` follows contained RELATIVE symlinks. The earlier 04 absolute-link-based S1 closure claim was explicitly withdrawn in the later 04 report; that historical failed evidence is preserved, not rewritten |
| `f84fade4…` | correction 2 | four store paths, +349/−323: true raw Linux `Openat` no-follow per literal component from `/`, final object no-follow/non-blocking/regular/euid-owned/exact 0600/exact 32 bytes, sound fd lifecycle; both production alternate-anchor test exports removed. S1 independently CLOSED; original package-init/TMPDIR panic resolved; shared-directory mutation removed. Committed inventory 40 top / 38 sub / 78 RUN / 0 FAIL. C2 fixture lifetime still OPEN (fresh HOME fixtures left behind) |
| `27270c40…` | fixture cleanup | one test file, +42/−0: owning-test cleanup registered immediately after the fresh `MkdirTemp` and before the fallible chmod, plus a meaningful subtest lifecycle regression with production positive control. Both final independent roles CLOSED C2 lifetime; no remaining scoped finding |

## Accepted criteria (statuses verbatim from the decision)

| # | Criterion | Status |
| --- | --- | --- |
| 0 | Maintained AEAD (AES-256-GCM with random nonce), authenticated ref/purpose/version binding, no homegrown cryptography | PASS_SCOPED |
| 1 | Append-only migration 2 preserving core/T006, immutable sealed records, presence distinct from placeholder, rollback with no partial publication | PASS_SCOPED |
| 2 | Final key object and full ancestor trust chain truly no-follow; same-chain secure positive vs contained-relative-symlink negative; no production alternate-anchor exports | PASS_SCOPED |
| 3 | Allowlisted profile-based projections, unknown/secret/opaque-nested omission, active/inactive filtering; closed diagnostic vocabulary rejects credential casts | PASS_SCOPED_UNIT_NOT_HTTP |
| 4 | Committed same-plaintext/two-ref nonce regression; corruption/key/version/purpose/swap/canary tests | PASS_SCOPED |
| 5 | Ordinary meaningful TMPDIR tests without shared-dir mutation or accumulating fresh fixtures; cleanup lifecycle with production positive control | PASS_SCOPED |
| 6 | Independent affected unit/vet/race and exact immutable scope checks; final committed 41 top / 39 sub / 80 RUN / 0 FAIL | PASS_SCOPED_REUSED_BYTE_UNCHANGED_PRODUCTION_EVIDENCE |

## Finding closure

- **S1 (symlink-following trust chain)** — CLOSED by both independent roles at
  `f84fade4`, retained at `27270c40`. The original `os.Root` failure evidence is kept.
- **S2 (diagnostic vocabulary)** — CLOSED at `c76cbaa6` (closed package-owned
  vocabulary), retained later.
- **C1 (nonce coverage)** — committed regression test, PASS.
- **C2 original package-init/TMPDIR panic** — CLOSED (production constructors only,
  self-owned fresh fixtures).
- **C2 fixture lifetime** — CLOSED by both independent roles at `27270c40`
  (controlled fresh HOME fixture counts 0→0 in four modes).

## Independent reports and fingerprints

- Final 03B source review: `.hyper/tmp/cah/foundation-T007-fixture-cleanup-security-recheck/REPORT.md`,
  SHA256 `40006552a912be279094a3b0ac78ce4a065b0314e0f7d82db2d1c82e6d3dd3ea` (4861 bytes) — READY.
- Final 04 execution: `.hyper/tmp/bul/T007-cleanup-test/REPORT.md`,
  SHA256 `0da45a0f67bd339b3caf1ad784c094a7e7216fef183f274d7179dbf4f77bc6b4` (9929 bytes) — READY.
- Correction-2 era reports preserved: 03B
  `.hyper/tmp/cah/foundation-T007-correction-2-security-recheck/REPORT.md`
  SHA256 `6a21cf11c141490faba95c60b5902d5e83da6098eb861f75640bdedaf56c5418`;
  04 `.hyper/tmp/bul/T007-c2-test/REPORT.md`
  SHA256 `36454e3fe25c196729e87064ae8e01c182947c4b8f9946650a296fc69c7c453c`.
- Earlier correction-1 review
  `.hyper/tmp/cah/foundation-T007-correction-1-security-recheck/REPORT.md`
  SHA256 `23c5e5a77b230d6469e7bd9efc6e1b5cd9dbd054dda1e585a2457c5351de82f6`; its
  historical S1 relative-symlink failure log (`logs/relative-symlink-distinction.txt`,
  exit 1 at 2026-10-24T03:05:21Z) is retained as history, not as a current failure.
- Consolidations: `.hyper/tmp/bui/T007-handoff/independent-consolidation.json`,
  `correction-1-independent-consolidation.json`,
  `correction-2-independent-consolidation.json`,
  `fixture-cleanup-independent-consolidation.json`.

## Checks (independent unless marked; scratch paths are local evidence, not hosted artifacts)

| Command | Exit | Executed (UTC) | Artifact |
| --- | --- | --- | --- |
| bui: final target/parent/tree/clean/one-file scope, report hashes, raw unit counts | 0 | 2026-10-24T05:37:19Z | `.hyper/tmp/bui/T007-handoff/fixture-cleanup-independent-consolidation-identity.txt` |
| 04: `env -u TMPDIR go test -count=1 -v ./internal/domain/ ./internal/store/ ./internal/api/` on fresh controlled compliant HOME (41 top / 39 sub / 80 RUN / 0 FAIL, reviewer extras 0) | 0 | 2026-10-24T05:35:46Z | `.hyper/tmp/bul/T007-cleanup-test/logs/unit-v.log` |
| 04: owned fixture counts before/after, ONLY fresh reviewer-controlled HOME, zero→zero in all four modes | 0 | 2026-10-24T05:35:46Z | `.hyper/tmp/bul/T007-cleanup-test/logs/counts.log` |
| 04: explicit `TMPDIR=/tmp` focused store lifecycle/shared-mode/key-chain/nonce/key-file tests | 0 | 2026-10-24T05:35:59Z | `.hyper/tmp/bul/T007-cleanup-test/logs/focus-tmp.log` |
| 04: fresh private 0700 TMPDIR focused tests; mode/uid unchanged; zero accumulation | 0 | 2026-10-24T05:36:00Z | `.hyper/tmp/bul/T007-cleanup-test/logs/focus-priv.log` |
| 04: `env -u TMPDIR` focused store `-race` lifecycle/key tests | 0 | 2026-10-24T05:36:07Z | `.hyper/tmp/bul/T007-cleanup-test/logs/focus-race.log` |
| 04: `gofmt -l internal/store/key_access_test.go` (empty output recorded in report; no separate raw log) | 0 | 2026-10-24T05:36:10Z | `.hyper/tmp/bul/T007-cleanup-test/REPORT.md` |
| 04: `git diff --check f84fade4 27270c40` (empty; repeated independently by parent identity check) | 0 | 2026-10-24T05:36:11Z | `.hyper/tmp/bul/T007-cleanup-test/REPORT.md` |
| 04 (correction-2 round, reused for byte-unchanged production — NOT rerun at `27270c40`): affected verbose unit 40/38/78/0 | 0 | 2026-10-24T05:23:13Z | `.hyper/tmp/bul/T007-c2-test/REPORT.md` |
| 04 (correction-2 round, reused): affected vet and full affected race | 0 | 2026-10-24T05:23:29Z | `.hyper/tmp/bul/T007-c2-test/logs/vet.log`, `.hyper/tmp/bul/T007-c2-test/logs/race.log` |
| 03B (cleanup round): identity/diffcheck + source-only cleanup boundary/lifecycle/LIFO review | 0 | 2026-10-24T05:35:25Z | `.hyper/tmp/cah/foundation-T007-fixture-cleanup-security-recheck/logs/identity.txt`, `logs/cleanup.diff` |

Final committed inventory on `27270c40`: **41 top-level PASS / 39 subtests / 80 RUN /
0 FAIL**, reviewer extras 0. Full vet/race at `27270c40` were intentionally not
duplicated because production source is byte-unchanged since `f84fade4` (test file only).
Author-run context logs (never independent proof):
`.hyper/tmp/agent-qw/t007-c2-20261024T051543Z/evidence.txt`,
`.hyper/tmp/agent-qw/t007-fixture-cleanup-20261024T053124Z/` (01–09 logs, HANDOFF.json).

## Limits, risks, NOT_RUN

- NOT_RUN: hosted CI; product/server/helper/UI/HTTP/network/dataplane behavior;
  power-loss durability; T008 auth, T009 UI, T011 compiler, T016 apply, T021 backup.
- The allowlisted projection result is a UNIT-level guarantee; it is NOT end-to-end HTTP
  secret-leak acceptance.
- Opaque object values without nested leaf metadata are intentionally omitted; this is
  not a complete future node API.
- Key rotation / multiple-key lifecycle and persistent enforcement of the 2^32-message
  ceiling per key are documented NOT_IMPLEMENTED; they are not newly imposed requirements.
- Key-path trust assumes a Linux target and a policy-compliant fixture HOME
  prerequisite (documented).
- Historical synthetic orphan fixture directories created BEFORE the cleanup commit
  remain untouched pre-existing files; no listing/sweeping/deletion of the real HOME was
  performed or authorized, and no removal task is claimed. Reviewers used only their own
  fresh controlled HOME for counting.
- Foundation stays ACTIVE until T008/T009 and the full foundation criteria; G1 runnable
  and G2–G4 remain OPEN. IPv6 and every approved specification guarantee remain in scope.
