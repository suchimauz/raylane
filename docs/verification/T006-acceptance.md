# T006 — scoped domain/store configuration-store acceptance

Status: ACCEPTED for the T006 domain/validation envelopes and SQLite configuration-store deliverable by Orchestrator after independent 03B review and 04 execution. Foundation remains incomplete. This is not foundation, product-runtime, security-runtime, network, crypto, actual apply-readiness or power-loss durability acceptance.

## Immutable revisions and scope

Final source target: `59d62afdb8a01f2ee940e95cc6a5f6f16e86229b`, parent `9870a3169030382e7c6ad66f3540a237edba147a`, tree `247646450ae20349ba539d4b1bc5f8fc00d8eaa5`. Prerequisites T002 and T005 were accepted; T004/T005 scoped acceptance is unchanged.

Delivery chain:
- `6191dd6ad743e38b74f9c6cef4df32bdeeeedc05` — documentation baseline preceding T006 (accepted T004/T005 scope).
- `9870a3169030382e7c6ad66f3540a237edba147a` — T006 implementation: twelve added files under `internal/domain/**` and `internal/store/**`.
- `59d62afdb8a01f2ee940e95cc6a5f6f16e86229b` — T006-R1 correction: exactly two files, `internal/store/revision.go` (+19) and `internal/store/store_test.go` (+97), insertions only, no removals.

Both final independent roles froze the exact targets with local `git archive`, verified identity, parent, scoped deltas and `git diff --check`, and reused prior evidence for byte-unchanged areas. The developer's author logs are context, not independent proof. Orchestrator independently confirmed final HEAD, clean tracked worktree, report fingerprints and diff check at 2026-10-24T01:59:56Z (`.hyper/tmp/bui/T006-R1-handoff/acceptance-identity.txt`) before recording this decision; no reset or source change was used for acceptance.

## Accepted deliverables

**Domain envelopes (`internal/domain/`):** `Document`/`Revision`/`ActiveState`/`Draft`/`SecretRef` vocabulary with a three-way explicit `ValidationStatus` where the zero value is `ValidationNotRun` — NOT_RUN is structurally distinct from and never upgraded to PASS; `ParseDocument` enforces JSON syntax only and never implies a semantic verdict; stable typed store errors (`ErrNotFound`, `ErrStaleRevision`, `ErrConflict`, `ErrDependency`, `ErrMalformedJSON`) carry identifiers and counters only, never stored document bytes or driver payloads.

**Configuration store (`internal/store/`):** ordered transactional migrations with per-migration rollback and idempotent reopen; per-connection DSN pragmas holding `foreign_keys` and WAL on every pooled connection; immutable revision history with separate draft head and active reference — saving never promotes anything to active, and the active fixture used in tests is synthetic, not proof of the future T016 apply protocol; malformed JSON preserves the prior state and adds no history rows; optimistic guards on draft head and entities yield typed stale-revision conflicts with exactly-one-winner under concurrent submissions; FK RESTRICT (deferred) and uniqueness violations roll the whole transaction back (referenced nodes are not deletable); source settings revision stays distinct from content draft/active versions, with a server-side capturedRevision commit check that rejects publication over intervening manual settings changes; restore lands atomically in draft and never touches active; mid-transaction failure and context cancellation leave no partial publication; reference-only SecretRef metadata (names only, never values — T007 owns encryption) is written and read symmetrically.

## Single blocker and its closure

T006-R1: `SaveDraft` persisted `revision_secrets` rows, but the shared `LoadRevision` never selected them, so `LoadRevision`/`LoadDraft`/`LoadActive` returned empty `SecretRefs` — observable immediately after save, not only after reopen. Independently reproduced by both roles on `9870a316`; consolidated in `.hyper/tmp/bui/T006-independent-consolidation.md`. The correction fixes the single shared read path (ordered by ref for stable set reads; delegating loaders inherit it); no schema, API or crypto changes. Both focused roles closed it on `59d62afd`, including 04's previously failing unchanged vector now passing.

Withdrawn tester claims (recorded so they are not re-litigated): the malformed-JSON `[]`/`null` expectation and the fresh-DB expectation were retracted as synthetic-vector mistakes; valid-JSON behavior and fresh-store `ErrNotFound` are unchanged. The original 04 headline `15/16` was a report typo contradicted by its raw 16 PASS log; raw logs govern and this was not another defect.

## Independent evidence

Local ignored evidence is not bundled into Git and is not a portable signed attestation. Historical failing reports are retained rather than rewritten — the baseline failing reproductions below are preserved in their original reports/logs and are not restated as PASS.

Reference records:
- `.hyper/tmp/cah/foundation-T006-review/REPORT.md` — original independent 03B review at `9870a316`.
- `.hyper/tmp/bul/T006-test/REPORT.md` — original independent 04 execution at `9870a316`.
- `.hyper/tmp/bui/T006-independent-consolidation.md` — consolidated single-blocker decision.
- `.hyper/tmp/cah/foundation-T006-R1-review/REPORT.md` — focused 03B recheck verdict T006-R1 CLOSED; SHA-256 `d2ffeaf2b5aeef6eb5b4d2af20ce931be4c973ca8aad7f1e7f5220aa8b4cd33c`.
- `.hyper/tmp/bul/T006-R1-test/REPORT.md` — focused 04 recheck verdict (8160 bytes); SHA-256 `f52cf4bb003a884caa3f6fd73bcefc1f1d8b85fc4416bc8d5e8e211d9e6bd1d2`.

Check toolchain for the inherited records: existing Go `go1.27.3 linux/amd64` at `/home/suchimauz/.local/raylane-toolchains/go1.27.3/bin`, GCC `13.3.0-6ubuntu2~24.04.1`, `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off`, `CGO_ENABLED=1` for race. Focused roots: 03B `.hyper/tmp/cah/foundation-T006-R1-review`, 04 `.hyper/tmp/bul/T006-R1-test`.

| command | exitCode | executedAt | artifactPath |
|---|---:|---|---|
| 03B: `git archive` target; identity/scope/`git diff --check` (original, at 9870a316) | 0 | 2026-10-24T01:31:50Z | `.hyper/tmp/cah/foundation-T006-review/logs/identity.txt` |
| 03B: `go test ./internal/store -run TestReviewerSecretRefsSurviveLoadAndReopen -count=1` (original; blocker reproduced on baseline) | 1, expected failing reproduction | 2026-10-24T01:33:48Z | `.hyper/tmp/cah/foundation-T006-review/logs/secretrefs-repro.txt` |
| 04: `go test -count=1 -v ./internal/domain/ ./internal/store/` (original, at 9870a316; 16 committed PASS) | 0 | 2026-10-24T01:31:50Z | `.hyper/tmp/bul/T006-test/logs/unit.log` |
| 03B: target archive/identity/diff check (focused, at 59d62afd) | 0 | 2026-10-24T01:57:03Z | `.hyper/tmp/cah/foundation-T006-R1-review/logs/identity.txt` |
| 03B: `go test ./internal/store -run '^TestRevisionSecretRefsReadback$' -count=1 -v` (focused) | 0 | 2026-10-24T01:57:33Z | `.hyper/tmp/cah/foundation-T006-R1-review/logs/focused-readback.txt` |
| 04: `go test -count=1 -v ./internal/domain/ ./internal/store/` (focused; 17 committed PASS = 16 retained + 1 new) | 0 | 2026-10-24T01:56:56Z | `.hyper/tmp/bul/T006-R1-test/logs/unit.log` |
| 04: `go vet ./internal/domain/ ./internal/store/` (focused) | 0 | 2026-10-24T01:57:00Z | `.hyper/tmp/bul/T006-R1-test/logs/vet.log` |
| 04: `go test -count=1 -race -v ./internal/domain/ ./internal/store/` (focused; 17 PASS, no data races). The report abbreviates the command as `./…`; bui inspected the actual execution call and confirmed these two explicit package paths — not a whole-product test/build | 0 | 2026-10-24T01:57:01Z | `.hyper/tmp/bul/T006-R1-test/logs/race-v.log` |
| 04: own prior `TestIND04` vectors, including the unchanged formerly failing IND-6: `go test -count=1 -run 'TestIND04' -v ./internal/store/` (7/7 PASS) | 0 | 2026-10-24T01:57:07Z | `.hyper/tmp/bul/T006-R1-test/logs/indep.log` |
| 04: same IND04 vectors under race | 0 | 2026-10-24T01:57:12Z | `.hyper/tmp/bul/T006-R1-test/logs/indep-race.log` |
| 04: unknown-id focused vector | 0 | 2026-10-24T01:57:23Z | `.hyper/tmp/bul/T006-R1-test/logs/narrow.log` |
| bui: acceptance identity assertion — HEAD/parent/tree, report fingerprints, `git diff --check` | 0 | 2026-10-24T01:59:56Z | `.hyper/tmp/bui/T006-R1-handoff/acceptance-identity.txt` |

Author-run records (context only, never substituted for the independent rows above): `.hyper/tmp/cal/t006-final-20261024T012610Z.log`, `.hyper/tmp/cal/t006-precommit-20261024T012658Z.log`, `.hyper/tmp/cal/t006-postcommit-20261024T012710Z.log`, `.hyper/tmp/cal/t006r1-checks-20261024T015414Z.log`, `.hyper/tmp/cal/t006r1-postcommit-20261024T015429Z.log`.

## Explicit exclusions and remaining gates

NOT_RUN for this acceptance: hosted CI execution, whole-product `go build ./...`, product CLI/server/helper processes, UI, HTTP/network/dataplane behavior, power-loss durability (reopen proves committed-state visibility only), T007 secret encryption/key access, T008 auth, T011 compiler/typed full-document validation, T016 actual apply readiness, T021 backup/restore. The synthetic active fixture is not apply proof. G1 runnable and G2–G4 remain OPEN; T004/T005 scoped acceptance is unchanged.

Risks and nonblocking observations recorded without redesign: the public DB accessor and test-only hook seam are a future wiring risk, not permission to redesign in this package; stable reference sorting (`ORDER BY secret_ref`) is read stability, not insertion-order preservation; raw syntax-gated documents are not safe public API payloads and public surfaces must apply their own limits and redaction. IPv6 and all specification guarantees remain in scope. No new user or architecture decision is required to record this already supported acceptance.
