# T004/T005 — scoped CI configuration and machine-contract acceptance

Status: ACCEPTED for the T004 CI-configuration/local-validator deliverable and T005 machine-contract deliverable by Orchestrator after independent 03B review and 04 execution. Foundation remains incomplete. This is not hosted-CI, product-runtime, security-runtime or network acceptance.

## Immutable revisions and scope

Final source target: `5fd8584b58f19fd09c785d7a9954bdc4bb04f4b4`, parent `048f488f05091d8fde4f32fb4534a2b1fa9cc5bf`. Prerequisites T001 and T002 were accepted; T003 fixture acceptance is unchanged.

Delivery chain:
- `c52b9c8463d05f163c3c4cfdf3c54fb648745ea9` — T005 contracts.
- `9691480d3ff130b54ba79fb36dc6746348883756` — T004 CI configuration.
- `8e2a3ac5fd206ba8223bb2e12d5b7416450515d8` — reviewed documentation baseline.
- `048f488f05091d8fde4f32fb4534a2b1fa9cc5bf` — consolidated B1/B2/B3 correction, seven affected files.
- `5fd8584b58f19fd09c785d7a9954bdc4bb04f4b4` — typed Conflict CI guard and always-on CLI correction, only `tools/ci/validate-contracts.py` and `tools/ci/test_validate_contracts.py`.

Both final independent roles froze the exact target with local `git archive`, verified its parent and two-file delta, and reused prior evidence for byte-unchanged contracts, workflow and documentation. The developer's results did not substitute for independent checks. Orchestrator independently confirmed final HEAD, clean tracked worktree, report fingerprints and `git diff --check` before recording this decision; no reset or source change was used for acceptance.

## Accepted deliverables

**T004:** `.github/workflows/verify.yml`, testing instructions and pinned local contract-validation tools are configured. Normal Go/frontend/contract jobs are enabled; network integration remains `if: false`, unprovisioned and limited to a separately authorized disposable environment. Exact action/toolchain/dependency pins, read-only permissions, workflow shell syntax, full OpenAPI 3.1 / Draft 2020-12 validation, profile consistency, and the documentation limits-table check were independently reviewed. Race coverage remains configured, not silently removed.

Actual hosted GitHub Actions execution was not performed. CI targets CPython 3.12.12; local validator checks used the existing isolated CPython 3.12.3 environment. This accepts the configuration and evidenced local validator behavior, not an unexecuted CI environment.

**T005:** machine-readable HTTP/helper contracts and the typed capability profile/schema satisfy the reviewed contract scope. The actual four create operations carry the shared typed Conflict response. All 17 request-body operations declare finite positive integer byte limits and 413, consistent with the documentation table; restore archive base64 text length is distinguished from decoded archive size and the outer JSON body bound. Profile type/default/constraint/dependency consistency is checked through established schema validators and the real CLI instance path. Helper framing/artifact bounds and peer-supplied shell/path prohibitions remain intact. No runtime profile compiler is claimed.

The final CI guard rejects missing, untyped and wrong-reference 409 responses for all four named creates. It runs for every `--openapi` input, including without `--limits-table`; the optional table comparison remains supported. B1, B2, B3 and the follow-up typed409 CI gap are closed for this deliverable.

## Independent evidence

Local ignored evidence is not bundled into Git and is not a portable signed attestation. Historical failing reports are retained rather than rewritten:
- `.hyper/tmp/buk/foundation-T004-T005-review/REPORT.md` — original combined independent review at `8e2a3ac`, three blocker families.
- `.hyper/tmp/bul/combined-T004-T005/REPORT.md` — original combined independent local test stage.
- `.hyper/tmp/cah/foundation-T004-T005-fix-review/REPORT.md` — review at `048f488`: actual B1 contract, B2 and B3 resolved; typed409 assertion gap remained.
- `.hyper/tmp/bul/T004-T005-fix-test/REPORT.md` — independent tests at `048f488`; SHA-256 `56ce0e7e154116757f382b7dc233b3cfe373d014e3a35e7a5ee7afffb39e8c8b`. All 32 tests and final four-document CLI passed; six independent B3 negative classes were rejected with the intended reasons. The same guard gap was confirmed.
- `.hyper/tmp/cah/foundation-T004-T005-typed-conflict-review/REPORT.md` — final 03B verdict READY; SHA-256 `5516dab3c8f0774d8b0361bd95e9d1ba4c618ea9c2893970a67df054e533ab78`. Typed409 and always-on CLI gaps resolved; prior B2/B3 closure preserved.
- `.hyper/tmp/bul/T004-T005-typed-conflict-test/REPORT.md` — final 04 verdict: typed409 gate CLOSED, no true blockers; SHA-256 `f9c7b5f28558bdb0801813cdd1649e944c0267dc43bcea3f877a56be49928fac`.

Final independent check records (UTC on 2026-10-24; artifact paths relative to the repository):

| command | exitCode | executedAt | artifactPath |
|---|---:|---|---|
| 03B: `git archive 5fd8584…`; verify hash/parent/scope; `git diff --check 048f488…5fd8584…` | 0 | 2026-10-24T00:44:55Z | `.hyper/tmp/cah/foundation-T004-T005-typed-conflict-review/logs/identity.txt` |
| 03B: existing venv `validate-contracts.py --bundle frozen/contracts --openapi openapi.yaml`, without limits table | 0 | 2026-10-24T00:45:36Z | `.hyper/tmp/cah/foundation-T004-T005-typed-conflict-review/logs/always-on-cli.txt` |
| 03B: same CLI on synthetic description-only createNode 409 | 1, expected rejection | 2026-10-24T00:45:37Z | `.hyper/tmp/cah/foundation-T004-T005-typed-conflict-review/logs/always-on-cli.txt` |
| 04: existing venv `python -m unittest test_validate_contracts -v` against frozen target | 0; 34 tests OK | 2026-10-24T00:45:04Z | `.hyper/tmp/bul/T004-T005-typed-conflict-test/logs/regress.log` |
| 04: CLI without limits table on missing-key / description-only / wrong-reference mutations for four creates | 12 runs, each 1, expected rejection; 0 accepted | 2026-10-24T00:45:20Z | `.hyper/tmp/bul/T004-T005-typed-conflict-test/logs/cli-create*.log` (individual logs listed by the report) |
| 04: `validate-contracts.py --bundle contracts --openapi openapi.yaml --limits-table docs/engineering/foundation-decisions.md --schema helper.schema.json --schema capability-profile.schema.json --instance capability-profile.schema.json capability-profile.json` | 0; four documents PASS | 2026-10-24T00:45:40Z | `.hyper/tmp/bul/T004-T005-typed-conflict-test/logs/full4.log` |
| 04: authored OpenAPI CLI without limits table | 0 | 2026-10-24T00:46:10Z | `.hyper/tmp/bul/T004-T005-typed-conflict-test/logs/no-table.log` |

Negative rejection is not a failing positive suite. Contract-level limit assertions do not demonstrate enforcement by a running HTTP server.

## Explicit exclusions and remaining gates

Actual hosted CI, Go/frontend product builds or race execution in this package, runtime HTTP 409/413/stream enforcement, helper process, UI behavior, session/auth implementation, secret-store encryption, encrypted restore execution, compiler/JCS conformance, Xray/dataplane behavior and privileged/host-isolation checks remain NOT_RUN. Previously accepted T002 inert-scaffold evidence is not reclassified as product acceptance. G12 canonical-document compiler work stays deferred upstream, not a present contract blocker. G1 runnable and G2–G4 remain OPEN; all specification guarantees, including IPv6, remain in scope.

The repeated cheap semantic check when a limits table is supplied is nonblocking; no cosmetic correction cycle is required. A dependency targeting a secret-classified field is not forbidden by the current specification; the independent observation adds no new cross-class prohibition or user decision requirement. Future runtime consumers must still preserve secret-reference/presence-only boundaries.

## Next dependency boundary

T004 and T005 may be marked complete for these scoped deliverables. T006's T002/T005 prerequisites are now satisfied, but execution still requires a fresh scoped assignment with the actual starting commit. T007, T008 and T009 remain unimplemented/unaccepted; foundation must not be marked complete.
