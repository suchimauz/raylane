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

No task checkbox or gate is closed by this document.
