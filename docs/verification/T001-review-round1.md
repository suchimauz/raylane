# T001 — review round 1

Target: `521b018fcebeba3b74257a1b6b6ec7a1b376fc1b`, base `c21bb12`.
Status: CHANGES_REQUESTED. T001 not Done; G1 OPEN.

## Independent reviewer 03

Reviewer reported independent public HTTPS checks and readonly source inspection on 2026-10-23, 18:47–18:52 UTC. This document summarizes that report; it is not a new reproduction of those checks. Full commands/raw outputs were not attached as durable repository artifacts. Independent tester 04's report remains pending.

| ID | Finding reported by 03 | Required disposition |
|---|---|---|
| H1 | dnsmasq 2.90-4build1 and iproute2 6.1.0-1ubuntu6.2 not found for noble amd64 | Verify available exact packages against official metadata; record repository/pocket and retrieval evidence. |
| H2 | dnsmasq HAVE_NFTSET build claim lacks build evidence | Supply pinned build configuration/log evidence or mark UNVERIFIED. |
| H3 | Selected modernc.org/sqlite has no exact version | Pin and verify direct dependency now; transitive go.sum creation remains T002. |
| H4 | quic-go/yaml/reality pins abbreviated or missing | Record complete reproducible versions and resolve cross-document references. |
| M1 | Categorical claim that upstream publishes no signatures | Restrict to observed assets and mark signature-channel verification NOT_VERIFIED unless independently established. |
| M2 | Go compatibility overstated without build | Separate static toolchain compatibility from NOT_RUN build validation. |
| M3 | grpc capability version absent from lock | Reconcile lock and matrix. |
| M4 | WireGuard FinalMask mapping unsupported by cited paths; noise identifiers not found | Establish actual transport-level mapping from pinned source or mark UNVERIFIED; do not drop FR-008. |
| M5 | Abbreviated commands, missing per-check timestamps and some evidence files | Supply complete reproducible checks and durable redacted evidence references. |
| M6 | Single malformed/404 GitHub URL treated as proof that mirror is absent | Remove unsupported inference; record exact HTTP outcome only. |
| M7 | Go/Node published digests omitted | Record algorithm, artifact identity, published value and origin; archive verification remains distinct. |
| L1 | quic-go repository redirects | Record final canonical source URL. |
| L2 | Release branch HEAD claim lacks evidence | Remove or substantiate. |

Reported subgate results: core provenance confirmed by 03; pins FAIL; capability PARTIAL. No binary integrity or runtime network acceptance is implied. Overall provenance remains subject to complete package evidence and independent verification, not a blanket PASS.

## Orchestrator decisions

- Keep Node 22 family from approved plan; no migration to 24.
- Optional upstream Xray binary download is not accepted as a trusted runnable baseline by this research.
- For Ubuntu package correction, researcher proposes exact official noble/noble-updates/noble-security amd64 versions with pocket, availability date and security/support rationale. Proposal requires review; do not force stale GA versions merely for reproducibility or modify host packages.
- A failure to support FR-008 requires escalation, not silent scope reduction.
- Existing research files stay frozen while 04 checks the same commit. Consolidate both reviews into a bounded correction packet for 05; repeat affected independent checks on the corrected commit.
- Source/dependency downloads remain bounded and unprivileged. Target-machine SSH and privileged network tests are not authorized by this report.

## Checks and evidence status

Orchestrator previously ran `git diff c21bb12..521b018 --check` successfully and confirmed the three-file commit scope and clean tree. Those checks establish document hygiene only. The source claims above are attributed to 03's report, not independently rerun here. Tester 04: PENDING. Binary integrity, builds and runtime/network behavior: NOT_RUN in this review round.

## Update: independent tester 04 completed

04 returned CHANGES_REQUIRED for the same immutable target. Reported bounded run: 30 public GET requests, approximately 705 KB, no executable archives downloaded or executed. Local ignored evidence: `.hyper/tmp/bul/t001-04/REPORT.md`, `checks.tsv`, and `raw/`. These paths are working evidence, not durable public artifacts; the correction must preserve reproducible redacted references.

- F-04-1/2 independently confirm the incorrect dnsmasq/iproute2 package pins.
- F-04-3: GitHub reports the source commit's PGP verification as `verified=true`, `reason=valid`. Record this as provider-reported verification; local cryptographic verification remains NOT_RUN. No signature-like assets observed in a release listing does not establish absence of every upstream signing channel.
- F-04-4/5: correct the quic-go module identity, truncated versions, missing yaml version and missing exact SQLite pin.
- F-04-6: an author scratch response contains HTTP 404; it is not source-version evidence. Use the actual pinned `core/core.go` with a successful response.
- Published digest agreement between `.dgst` and GitHub asset metadata is corroboration within the upstream/provider channel, not independent trust roots. Binary archive integrity remains NOT_RUN.
- 04 reports synthetic verifier mismatch/missing/match checks; these do not substitute for verification of the actual binary archive.

Correction task T001-fix-r1 has been dispatched to 05 against base `d7b75a8`, limited to the original three research files. The earlier freeze is lifted for that writer. 04's result remains attached to `521b018`; no acceptance transfers automatically to a changed revision. Findings from both reviewers must receive explicit dispositions, followed by affected independent checks on the new immutable commit. Node 22 and the existing architecture remain unchanged.


## Round 2 correction to historical findings

Target: `4e98e02910820f92fc6177014c06aef3b602e10e`, actual parent `9566a13`. Both independent reviews confirm the corrected pins and static capability evidence. Reviewer 03: CHANGES_REQUESTED for documentation; tester 04: PASS with a minor documentation finding. T001/G1 remain OPEN pending corrected documentation and independent recheck.

**Retraction:** 04 explicitly withdrew the round-1 claim that iproute2 `6.1.0-1ubuntu6.2` never existed. Its query used Published records and a truncated result page; that did not establish historical absence. Both reviewers now report a noble Updates publication beginning 2025-07-29 and supersession on 2026-04-29. Publication and supersession dates must not be conflated. The earlier H1/F-04-2 summaries above are historical, not the current finding. The invalid dnsmasq `2.90-4build1` finding remains.

Both reviewers found explicit `COPTS += -DHAVE_NFTSET` in dnsmasq debian/rules, conditional on absence of `DEB_BUILD_OPTIONS=nonftset`. This supplies stronger build-configuration evidence than Build-Depends alone; installed runtime behavior remains NOT_RUN.

Remaining documentation dispositions: provider-reported PGP commit verification (local crypto NOT_RUN), successful pinned core/core.go evidence rather than a 404 response, explicit F-04-1..6 dispositions, debian/rules citation, correct package pocket/status dates, complete REALITY version, accurate parent reference, and dnsmasq-base/main versus dnsmasq/universe packaging distinction. A bounded doc-only correction was assigned to 05; the research files remain owned by that writer.

Working evidence for round 2: `.hyper/tmp/t001/T001-review-r2-REPORT.md` (03) and `.hyper/tmp/bul/t001-04r2/REPORT.md` with `checks.tsv` (04). This section records attributed review results, not a new execution of their commands. Binary integrity, local signature verification, builds and network acceptance are not declared PASS.


No task checkbox or gate is closed by this document.
