# T003 — synthetic fixture deliverable acceptance

Status: ACCEPTED for the fixture deliverable only after independent 03 semantics/security review and 04 reproduction checks. Foundation remains incomplete. No product behavior or network acceptance is implied.

Target: `fd6c98853a61384c87c022669db3515c362704e1`, parent `930438e97fa29db42c24e15b55e04729c4042f89`. Prerequisite T002 accepted.

## Delivered and independently checked

- 77 files under tests/fixtures: 56 cases, 15 literal input files, six synthetic secret canaries, vendored oracle, generator, verifier, README and manifest.
- Vendored oracle SHA-256: `f9840ab765aff72652843f093633b69b81b2ac6c1631cd1d767ed20edd4dd89f`.
- 03 independently confirmed all case semantics match the oracle, all 13 input expansions are concrete and consistent, synthetic addresses have no live-fetch use, and script inspection found no networking or subprocess execution.
- 04 independently confirmed all 76 manifest-listed hashes, oracle equality, case/canary correspondence and valid synthetic X25519 key derivation. Manifest intentionally excludes its own hash; it is not a signed trust anchor.
- 04 ran inspected scripts in isolated copies, not the working tree. All 73 generated data files reproduced byte-for-byte. README and script sources are not generated; manifest contents depend on whether these files are present.

## Evidence and recorded checks

Local ignored evidence (not bundled into Git):
- `.hyper/tmp/t005a/T003-fixtures-review-REPORT.md` — independent semantics/security PASS, no blockers.
- `.hyper/tmp/bul/t003-fixture-recheck/REPORT.md` — independent consistency and reproduction results.

| command | exitCode | executedAt (UTC) | artifactPath |
|---|---|---|---|
| python3 verify.py (04 isolated iso copy) | 0 | 2026-10-23T23:13:30Z | .hyper/tmp/bul/t003-fixture-recheck/REPORT.md |
| python3 generate.py regen (04 isolated copy) | 0 | 2026-10-23T23:14:05Z | .hyper/tmp/bul/t003-fixture-recheck/REPORT.md |

## Limits and nonblocking follow-ups

All 56 cases retain runtime_status=NOT_RUN and apply_observation=null. Product execution, actual secret-redaction behavior, network fetching and a consuming product test runner are NOT_RUN. Trace counts such as 32/36 or 27/27 are mappings/plans, NOT measured behavioral coverage.

GAP-WGKEY remains explicit: malformed-key stage expectations are not invented; this does not invalidate the valid positive fixture. Fixture acceptance does not resolve that product contract question.

Minor documentation findings from 03 are deferred to the next relevant batch: incorrect RFC 3849 reference for an IPv4 documentation range, inconsistent verifier check count, A-04 title mentioning groups absent from its YAML, and canary exercised_in listing originating cases rather than every reuse. These do not block fixture-deliverable acceptance and do not justify another acceptance cycle.
