# T001 — research acceptance

Status: ACCEPTED for T001 research only, by orchestrator after independent 03/04 verification. No runnable or full product acceptance.

## Evidence chain

- Research by 05: initial `521b018`, corrections `4e98e02`, documentation `9dd2b1e`, final package `3746ad23dc7a55d2e4cb3fc784d0f80317fa1379`.
- 03 final static review of `9dd2b1e`: PASS for pins, metadata provenance, licenses and static capability mapping. Report: `.hyper/tmp/t001/T001-review-r3-REPORT.md`.
- 04 independent verification of `3746ad2`: all substantive findings and T-1..4 PASS; explicitly permits closing T001 research. Report: `.hyper/tmp/bul/t001-04r4/REPORT.md`, checks in adjacent `checks.tsv` (22 rows). Earlier independent source verification: `.hyper/tmp/bul/t001-04r2/`.
- 04 noted nonblocking revision-header inconsistencies N-1..3. Orchestrator corrected only the lock header/history in `8313615`: revision 4, accurate historical commits, removed false identical-content claim. Technical pins, matrix, evidence and acceptance scope unchanged. This editorial correction has not received an additional independent check; acceptance relies on 04's explicit nonblocking disposition, not an invented recheck.
- Durable research commands, provenance and dispositions: `docs/verification/T001-research.md`; rounds and retraction: `docs/verification/T001-review-round1.md`. Ignored raw evidence remains local; raw responses and private environment data are not published.

## Scope accepted

Exact selected direct component pins, license information, metadata provenance and static capability matrix with explicit unknowns. Source commit verification is reported by GitHub; not local PGP verification. Published digests are not a completed binary archive integrity check. Previously mistaken historical iproute2 nonexistence claim was withdrawn by 04 and corrected in the documents.

## Checks

Orchestrator: `git diff 9dd2b1e..3746ad2 --check` exit 0; actual parent and two-file scope verified; clean working tree before header normalization. Header normalization: `git diff --check` exit 0 and full seven-line replacement inspected before local commit. These are document hygiene checks, not source authentication or runtime tests. Exact independent command timestamps, exit codes and artifact paths are in the reviewer/tester reports above; no additional execution is claimed here.

## Open gates and next prerequisites

G1 static research evidence is accepted; G1 runnable baseline remains OPEN. G2–G4 remain OPEN. T002 does not inherit PASS: module/npm closure, exact dependency lockfiles, clean builds and drift checks must run independently. Runtime nftset/nft/iproute2, binary archive integrity, local PGP verification and network behavior remain NOT_RUN.

Before affected operations: T005 resolves contract-level unknowns listed in research §3a, including FinalMask, Happy Eyeballs and applicable TLS mapping; A04 session expiry/retention needs concrete reviewed contract parameters before implementation. Kernel pin and package component availability must be checked at authorized provisioning. IPv6 remains in scope. No SSH, deployment, infrastructure or privileged test permission is implied.
