# T002 — acceptance of inert build scaffold

Status: ACCEPTED for T002 only by Orchestrator after independent 03 review and 04 execution. Foundation is NOT complete.

## Revisions and scope

- Source scaffold: `2fe69c8f9ad91319e744eddc59ad3a7977d983ee`.
- Independent execution target: `70575e46f4c113a86d20e88d7c26bd9e213added`.
- Final documentation review: `a8d200a182603e32494aa30c390ba2eadd8eaf8a`; source and dependency manifests unchanged relative to execution target, independently compared by 03.
- Accepted: inert Go CLI scaffold, exact dependency manifests, both CLI builds, frontend clean dependency installation and repeatable build on the tested host. This is not product/runtime or cross-platform acceptance.

## Independent evidence

Local ignored evidence (not portable Git artifacts):

- 03 static audit: `.hyper/tmp/t002/T002-audit-code-REPORT.md`.
- 04 Go/CLI/frontend verification: `.hyper/tmp/bul/t002-offline-verify/REPORT.md`, `checks.tsv`, `logs/` (30 PASS, 0 FAIL, 4 NOT_RUN in that round).
- 04 clean-install correction and execution: `.hyper/tmp/bul/t002-cache-repair/REPORT.md`, `checks.tsv`, `logs/`.
- 03 final independent read-only evidence audit: `.hyper/tmp/t005a/T002-final-acceptance-audit-REPORT.md`.

04 reports offline Go builds, vet, module verification and tidy drift checks PASS; CLI version/invalid flag/config rejection checks PASS, synthetic config unchanged. 03 independently reviewed inert source; no host isolation sandbox is claimed.

Clean npm installation used a real new node_modules tree, not a symlink. Recorded checks:

| command | exitCode | executedAt (UTC) | artifactPath (relative to cache-repair directory) |
|---|---|---|---|
| npm ci --offline --ignore-scripts --no-audit --no-fund --cache <out>/cache_ok | 0 | 2026-10-23T21:52:37Z | logs/npm_ci_fixed.log |
| node_modules/.bin/tsc --noEmit | 0 (recorded by 04) | 2026-10-23T21:52:42Z | logs/fe_tsc2.log |
| node_modules/.bin/vite build | 0 | 2026-10-23T21:52:46Z | logs/fe_vite_build2.log |

03 independently rehashed existing bundle and dependency bodies against the lock: MATCH. UI bundle matches prior build byte-for-byte; lock drift absent. Empty tsc log does not itself prove the exit code; that code is recorded by independent executor 04.

## Corrections and limits

- The earlier clean-install ENOTCACHED failure was caused by 04 supplying the wrong cache root. The claim of a missing Vite content blob is RETRACTED; cache-path inspection had omitted content-v2. This was a test setup error, not a scaffold defect.
- One specifically authorized Vite archive download occurred and proved unnecessary. Received body size: 587457 bytes, not a measured total wire transfer. Integrity matched the pinned lock.
- R03 manual comparison-before-fetch ordering is NOT_VERIFIED: recorded comparison time follows fetch time.
- R05 downloaded-body hash matched the lock, but manual verification-before-cache-seeding ordering is NOT_VERIFIED: recorded rehash time follows seed log modification time.
- R17 manual native rehash occurred AFTER execution; a manual pre-execution check is NOT_VERIFIED. npm installation integrity checking and later independent rehash are distinct evidence, not retrospective proof of manual ordering. Original logs/timestamps must remain unchanged.
- Earlier namespace/probe assertions remain author-reported, with no adequate raw evidence; they are not acceptance evidence. No new privileged/network namespace checks were performed for acceptance.
- Xray build, live network behavior, host sandbox isolation and full runtime acceptance: NOT_RUN. G1 runnable and G2–G4 remain OPEN.
- A04 and helper artifact delivery decisions are unaffected. T003/T004 prerequisites are now met; T006 still requires completed T005.
