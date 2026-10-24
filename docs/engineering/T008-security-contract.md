# T008 — Security contract draft (auth, sessions, bootstrap, admission)

**Status: DRAFT — SOURCE IMPLEMENTATION BLOCKED.** Pending independent 03B/04 review of
this document and explicit path/dependency authority. This page is NOT accepted
behavior, NOT a public contract change, NOT an architecture change, and NOT approval of
any candidate below. Nothing here authorizes code, `go.mod`/`go.sum` edits, Go/build/test
execution, listeners, TLS/LAN, or deployment. T008 remains `NOT_IMPLEMENTED`; T009 is
pending; the foundation is ACTIVE.

Baseline cited: `325644898742f4ad6a57d07df78639fc9b1e5e7b` (tree
`e3f1bf62fa097cd082a80bde1262f26ca1875db0`), on top of the T007 accepted-scoped state
(`27270c40…`, record: `docs/verification/T007-acceptance.md`). Readiness basis, read once
and consolidated: 03B report
`.hyper/tmp/cah/foundation-T008-security-readiness/REPORT.md` (SHA256
`02126291b9f46895afc99a5ed6ee9b114c249aa10b3d552cb384e37352f9d1d2`) and 04 report
`.hyper/tmp/bul/T008-readiness/REPORT.md` (SHA256
`0b32e7bebe716960725db1f33ab21c423ee8c6143c9433506f94159675d3aa89`), consolidation
`.hyper/tmp/bui/T008-readiness-consolidation.json`, identity
`.hyper/tmp/bui/T008-readiness-consolidation-identity.txt` (exit 0, 2026-10-24T05:55:00Z).
Specification sources: `specs/001-selected-connections/research.md` R-06, `spec.md`
FR-019/FR-021, `data-model.md` Admin/Session, `contracts/control-plane.md`,
`contracts/openapi.yaml` (auth operations and `components.securitySchemes.sessionCookie`,
which is explicitly a **placeholder**), `docs/engineering/foundation-decisions.md` D5, and
`docs/engineering/A04-contract-proposal.md` (P3/P4/P6/P10 marked PROPOSED there).

## 1. Fixed accepted requirements (authoritative — not candidates)

- Exactly **one admin** account; no roles, shared passwords, or external identity providers.
- **HTTPS same-origin trusted-LAN** management only; no insecure HTTP/LAN fallback.
- **Protected local one-time bootstrap**: token issuance over the already-approved
  protected local channel; consume + admin insert + permanent `bootstrapConsumed` closure
  is one atomic transaction with **exactly one concurrent winner** (per accepted contract
  text for `/bootstrap`).
- **Vetted Argon2id** only (maintained library); no homemade crypto or PHC parsers.
- **Secure / HttpOnly / SameSite session cookie + CSRF/origin checks + rate bounds** —
  directly accepted from `research.md` R-06 ("серверные sessions с Secure/HttpOnly/SameSite
  cookie, CSRF/origin checks, idle/absolute expiry, rate limits") and repeated in the
  accepted OpenAPI `/session` (login) description ("sets a secure, HttpOnly, SameSite
  session cookie"); FR-019/FR-021 give the general auth guarantees but are not the precise
  attribution for these cookie flags. The generic requirement is accepted; the exact
  `SameSite=Strict` value, `Path=/api/v1` and host-only form remain C4 candidates (see §3).
- Session **idle 900 s**; reads, polling and long editing do **not** extend it; **absolute
  43200 s** regardless of activity; control-plane **restart requires login again**.
- **D5**: expiry/re-login/restart never discard unsaved editor state; it stays only in
  page RAM (including freshly typed secrets); no browser storage/cookies/logs/analytics/
  cache/service-worker persistence; saving requires reauthentication, revision re-fetch
  and conflict handling; **no automatic mutation replay**.
- Existing schema/body limits unchanged: `/session` body ≤ 4096 bytes, `/bootstrap` ≤
  8192 bytes, username 1..256, password 1..1024, token 1..256; authentication failures are
  generic, never per-field oracles.
- Prohibited (accepted boundaries): weakened auth, shared passwords, new roles/IdP,
  session persistence across restart, browser storage of edits/secrets, public LAN
  bootstrap, deletion of secrets/history, raw `DB()` escape for auth production, rewrite
  of migrations 1/2.

## 2. NEW explicit Orchestrator candidates — awaiting independent 03B/04 review

These are NEW EXPLICIT CANDIDATES recorded for review. They are NOT historically
user-approved defaults, NOT inherited A04 proposals adopted wholesale, and NOT mandatory
architecture. Reviewer/reviewer-report recommendations are not runtime proof.

| # | Candidate (verbatim substance from the assignment) | Rationale / bounds | Status |
| --- | --- | --- | --- |
| C1 | **KDF**: maintained cached `golang.org/x/crypto/argon2` at EXACT v0.58.0, Argon2id version 0x13; time=3, memory=65536 KiB, parallelism=4, CSPRNG salt=16 bytes, output=32 bytes. Production verifier metadata accepts ONLY this fixed version/parameter set and bounded salt/hash lengths BEFORE expensive work; no attacker-controlled arbitrary-cost verifier; no homemade KDF/PHC parser. Preserve existing username/password schema bounds and exact password bytes — no silent trimming, no new password policy. Constant-time derived-hash comparison using maintained standard facilities. Typed versioned metadata is sufficient; exact encoding must be unambiguous and independently reviewed before code. Parameter-upgrade and password-change APIs are NOT added here. | Matches the cached library's RFC 9106 second recommendation — a reference point, explicitly **not a performance guarantee** (no benchmark has been run; none permitted here). Bounds pre-verification allocation against attacker-supplied metadata. | PENDING_INDEPENDENT_REVIEW |
| C2 | **Work admission**: per actual peer-IP token bucket burst 5 / refill 1 per 60 s, max 1024 peers; ignore untrusted `X-Forwarded-For`. No account-wide unauthenticated lockout. Expired/full-refilled idle entries may be discarded only as ephemeral limiter bookkeeping (no history/secret cleanup). Global Argon verifications **max 2 active, NO waiting queue** (fail-fast instead of growing memory/goroutines); chosen max memory for KDF buffers ≈128 MiB plus measured overhead — **not tested yet**. Established sessions, management and liveness traffic do not pass through the anonymous login limiter. Exhaustion must produce a **generic, non-oracular, contract-compatible** failure. | Bounds CPU/memory per peer and globally; fail-fast avoids queue growth. Peer-IP source avoids header spoofing. | PENDING_INDEPENDENT_REVIEW, except the public failure mapping — see BLOCKED table |
| C3 | **Opaque secrets**: 32 CSPRNG bytes, base64url-no-padding, for session and bootstrap tokens; **SHA256 digest-only** server index/storage; no plaintext in DB/logs/errors. Bootstrap: one active locally issued token, TTL 600 s; reissuance before admin invalidates the old; after admin/consumed flag, no issuance/recovery/reopen. Issuer is the already-approved protected local channel — NOT a new API endpoint/process/channel or request-supplied trust bool. Authenticated consume + durable admin + permanent consumed state must be a **typed atomic store operation**. Bootstrap/session tokens invalid after restart; durable admin/consumed state persists. | 256-bit entropy, digest-only at rest (matches accepted non-claim that mechanics are open, now made explicit for review). 600 s TTL is a candidate, not the A04 P4 default inheritance. | PENDING_INDEPENDENT_REVIEW, except trusted issuance/wiring proof — see BLOCKED table |
| C4 | **Session bounds/cookie**: process-local hash-indexed sessions; expiry checked on every request; equality at either deadline counts as expired; idle 900 / absolute 43200 **unchanged**. Candidate monotonic durations plus effective wall time that never moves backward within the process, **without** silently adopting the proposed persistent watermark/sweep machinery. No automatic persistent 60 s sweep; no restoration of sessions across restart. Candidate to preserve existing cookie name `raylane_session`, Secure/HttpOnly/SameSite=Strict, host-only, Path `/api/v1`, no Domain; no credential in response JSON/query/log. Exact creation/deletion/rotation mechanics and any client-visible differences require review. **Session-storage capacity/admission policy must stay an explicit unresolved bounded-resource choice** — see BLOCKED table; not an invented product limit or active-session eviction. | Process-locality gives restart invalidation by construction; hash-index mirrors C3 storage rule; monotonic+non-retreating clock avoids time-jump extension of idle deadlines. | PENDING_INDEPENDENT_REVIEW with named unresolved capacity choice |
| C5 | **Activity classification**: server-owned `operationId` allowlist, default `NO_ACTIVITY`, never client-supplied. Only accepted successful authenticated state-changing commands may touch the idle deadline, never past the absolute deadline: `createNode`, `updateNode`, `deleteNode`, `createRule`, `updateRule`, `deleteRule`, `createSubscription`, `updateSubscription`, `createRuleSource`, `updateRuleSource`, `refreshSubscription`, `refreshRuleSource`, `applyRevision`, `stopRuntime`, `releaseProtection`, `createBackup`, `restoreBackup` (current contract operationIds — naming them here is NOT implementation of those operations). Require valid session + CSRF/origin/auth before command, and durable commit or 202 acceptance; no refresh on failures. Reads/GET/HEAD/OPTIONS, `validateRevision`, status/operations/liveness, `exportDiagnostics`, and background refresh without an authenticated user command are `NO_ACTIVITY`. Login creates a new session, not resurrection; logout revokes rather than extends. Any future route addition stays `NO_ACTIVITY` until explicitly classified and reviewed. Cross-boundary transaction semantics must be described honestly — no claim of atomic DB+process-memory commit from an unimplemented API. | Keeps the accepted "reads/polling/editing never extend" invariant enforceable by an auditable table instead of middleware timing guesses. | PENDING_INDEPENDENT_REVIEW |
| C6 | **CSRF/TLS**: retain same-origin HTTPS and cookie guarantees. **SECURITY REVIEW CANDIDATE ONLY**: strict configured Origin/Host comparison — reject missing/foreign/null Origin for unsafe browser mutations; never trust arbitrary forwarded host/origin; SameSite=Strict as defense in depth. Independent 03B must decide whether this satisfies approved CSRF protection or whether a synchronizer-token mechanism is required. Do NOT invent a new CSRF header/cookie/endpoint/client delivery scheme or change public responses in this draft. Current responses: login 204/400/401/413; bootstrap 204/400/403/409/413; logout 204/401. TLS candidate: standard-library TLS minimum 1.3, service-supplied cert/key, explicit trusted management origin, no insecure LAN fallback, no automatic real cert/key generation. | Origin/Host + Strict cookie may be sufficient under same-origin HTTPS; only independent security review can conclude that. TLS 1.3 minimum is a config floor, not a listener grant. | CANDIDATE_REVIEWED_NOT_SELF_AUTHORIZED; mappings below BLOCKED |

## 3. BLOCKED rows — decisions this draft must NOT make

**Eight** decision rows below, PLUS one separate pre-existing gate: any future root
`go.mod`/`go.sum` addition of the scoped `golang.org/x/crypto v0.58.0` requires its own
explicit dependency-path authorization (§4.4). That gate is already blocked elsewhere and
is listed here once for bundle clarity — it is NOT a ninth technical decision and this
draft grants nothing. None of the rows is resolved here; several need Chief Architect /
public-contract or deployment authority.

| Row | Why BLOCKED | Smallest decision required | Authority |
| --- | --- | --- | --- |
| Public status/header/schema for limiter exhaustion (C2) | Current OpenAPI login responses are only 204/400/401/413 (bootstrap 204/400/403/409/413; logout 204/401). Adding 429/`Retry-After` or any new status/header/schema changes accepted public contract; the draft must not add or disguise error semantics. | Choose the contract-compatible generic failure mapping (existing 4xx) or amend OpenAPI explicitly. | Chief Architect / public contract |
| CSRF rejection mechanism and delivery | Rejecting missing/foreign Origin for unsafe mutations may need a client-visible scheme (header/cookie/token); inventing one changes the public contract and `sessionCookie` placeholder semantics. | Decide Origin/Host-strict sufficiency vs synchronizer token; if token, define delivery without new endpoint drift. | Independent 03B review + contract authority |
| Trusted local bootstrap issuance proof / wiring (C3) | "Issuer = already-approved protected local channel" is architecturally placed, but the concrete trusted issuance/wiring proof (who writes the token, through what verified path, how a request proves issuance locality) is not specified by currently accepted sources. | Specify the issuance boundary and its verification evidence. | Chief Architect / deployment boundary |
| TLS listener / bind / cert provisioning shape | A TLS minimum-1.3 config constructor is mechanics, but exact listener/bind/certificate provisioning and configuration shape creates a new deployment decision beyond the approved architecture text. | Freeze listener/bind/config/cert-source shape before any `cmd/raylane` wiring path is authorized. | Chief Architect / deployment |
| Session-storage capacity / admission policy (C4) | An upper bound on concurrent process-local sessions is an unresolved bounded-resource choice; any number silently adopted would be an invented product limit or implicit active-session eviction. | Pick an explicit capacity + admission behavior (reject-new vs evict-oldest vs documented unbounded-risk) in a reviewed decision. | Orchestrator after 03B/04 review (bounded-resource choice) |
| KDF encoded-record encoding (C1) | Typed versioned metadata is accepted as sufficient in principle, but the exact unambiguous encoding is explicitly "reviewed before code" and is not fixed by accepted sources. | Review and freeze the encoding format (field layout, lengths, version tag). The encoding must be WRITTEN, FROZEN and independently REVIEWED BEFORE any future KDF source is authorized — including any test-only encoder. No code is authorized now. | Independent 03B/04 review |
| Session cookie creation/deletion/rotation mechanics and client-visible semantics (C4) | Accepted guarantees fix the generic Secure/HttpOnly/SameSite requirement (R-06 + login prose) and the current placeholder name `raylane_session`, but NOT the exact C4 candidates — `SameSite=Strict` value, `Path=/api/v1`, host-only form — nor rotation/delete semantics; any client-visible difference is contract-affecting. | Review the exact C4 attribute candidates and rotation/delete semantics against the placeholder scheme; amend the contract if client-visible. | 03B/04 + contract authority |
| `foundation-execution-decision.md` provenance gap | The current decisions file references `docs/engineering/foundation-execution-decision.md`, which is absent from the repository. Its content is NOT reconstructed or guessed here; the explicit D5 text and accepted OpenAPI invariants remain authoritative. | Restore/locate the referenced decision or amend the reference. | Document owner / Orchestrator bookkeeping |

## 4. Smallest prospective implementation paths (plan only — NOT permission to edit)

Recorded so a future authorization names exact paths; this draft grants nothing.

1. `internal/store/auth_migration.go` + `internal/store/auth.go` — append-only **version 3**
   auth migration registered in `migrate.go`; typed operations only (one admin verifier,
   permanent bootstrap-consumed state, one-transaction/exactly-one-winner bootstrap
   consume). Migrations 1/2 and every existing T006/T007 test stay byte-unchanged. Auth
   code must NOT use `Store.DB()` (existing test-inspection accessor) and no arbitrary raw
   DB or alternate security anchors are added.
2. `internal/api/auth/` — focused files: bounded Argon2id encode/parse/verify (vetted
   `x/crypto`, reject malformed/oversized metadata before expensive allocation, generic
   failure); RAM bootstrap-token manager (hash-only, TTL, one-use) over the typed atomic
   consume; process-local session manager (hash-only, created/last-approved-activity/
   absolute expiry, logout/revocation, restart invalidation by construction); bounded
   admission limiter + global verification concurrency per C2 (fail-fast); request-size
   enforcement, JSON validation, generic errors, CSRF/Origin middleware per reviewed C6;
   TLS config constructor that refuses insecure LAN serving (construction-level check only).
3. Handler integration under explicitly authorized `internal/api` paths plus
   `tests/integration/auth_test.go`; `cmd/raylane` wiring only in a separately authorized
   path once bind/cert/bootstrap-issuance details are frozen (§3).
4. Root `go.mod`/`go.sum` — exact future addition of `golang.org/x/crypto v0.58.0`
   (ziphash `h1:COkYLr4k7nDI4r6QtMML2AfzeIswWHAJthLS6K/M/54=`, BSD-3, pinned in T001;
   `x/sys/cpu v0.49.0` already pinned today, `x/crypto` NOT declared). Requires explicit
   scoped dependency-path authorization; cache presence is not permission and not
   execution proof; never copy/paste crypto.

## 5. Future 15-case focused test matrix (from 04; ALL NOT_RUN — none executed, none may be invented away)

All cases are in-memory only: fake clock (no sleeps), `httptest` `Request` +
`ResponseRecorder`; **no server, listener, socket, real HTTP, or product process**. Cases
dependent on unresolved §3 mechanics are BLOCKED until those decisions exist.

| # | Case | Asserts |
| --- | --- | --- |
| 1 | Bootstrap exactly-one-winner | two concurrent bootstrap requests, same token → exactly one 204, one 409/403; consume+admin+`bootstrapConsumed` atomic; no partial row |
| 2 | Permanent non-reopen | after successful bootstrap every later attempt (same token, new token, restart) refused; closure permanent, not session-scoped |
| 3 | Token expiry/replay refusals | expired → 403; consumed replay refused; unknown → generic error, no oracle |
| 4 | Password hashing | stored value Argon2id with bounded params, per-record salt, hash metadata; constant-time compare; plaintext never in DB/WAL, logs, errors, responses. Plus: malformed/corrupt/unsupported/oversized stored verifier metadata → generic refusal, **no panic**, rejected BEFORE any KDF work; a valid fixed-set record still reaches verification. Enforced by fixed metadata validation against the allowed parameter set — not a custom parser and not a catch-all recover |
| 5 | Negative/generic errors | wrong user vs wrong password indistinguishable 401s; no user-existence oracle |
| 6 | Bounded rate/concurrency | admission limiter bounds concurrent verifications and memory; excess refused generically; no unbounded goroutine/memory growth under N attempts (public mapping per BLOCKED §3) |
| 7 | Token rotation/logout | session delete invalidates; rotation issues new hash-only token, old rejected; tokens stored hash-only |
| 8 | Restart invalidation | process-local sessions invalidated by rebuilding the in-memory store (simulated restart) |
| 9 | Idle 900 s / absolute 43200 s (fake clock) | injected clock expires exactly at boundaries, equality counts expired; no sleeps |
| 10 | Reads/polling do not extend | repeated reads t=0..899 s leave idle deadline unmoved; a classified activity event moves it per accepted rule only |
| 11 | CSRF/Origin | missing/incorrect CSRF material and foreign Origin refused; same-origin + accepted mechanism passes (mechanism per BLOCKED §3) |
| 12 | Cookie attributes | ACCEPTED and asserted: HttpOnly, Secure, SameSite (generic per R-06/login prose). CONDITIONAL on the reviewed C4/cookie decision: exact `SameSite=Strict` value, `Path=/api/v1`, host-only form — not accepted merely from the base URL. No secret material beyond the opaque token; no new cookie/public behavior introduced here |
| 13 | TLS config refusal | insecure LAN/non-TLS world-reachable configuration fails to construct (config-level only) |
| 14 | Body bounds | `/session` 4096 and `/bootstrap` 8192 enforced, 413 beyond, matching contract values |
| 15 | Canary non-leak | canary password/token absent from every response body, error text, and persisted DB/WAL bytes |

Not claimed by these future units: live TLS handshake, real LAN exposure, actual CLI
bootstrap deployment, end-to-end UI flows. Unit tests are never runtime/network acceptance.

## 6. Execution status and NOT_RUN (honest inventory for this document)

No Go/toolchain execution of any kind in this task: no build/vet/test/race, no Argon2 run,
no module resolution, no dependency mutation, no download/network, no HTTP/TLS/LAN probe,
no product/CLI/UI process, no SSH/privilege/host-network, no push/deploy, no real
credentials, no HOME listing/sweep, no T007 evidence re-audit. Only git read/verify
commands touched the repository. Checks for this commit are recorded in author scratch
`.hyper/tmp/agent-qw/…` (local evidence, not hosted CI). Hosted CI, product/helper/
network/dataplane and power-loss acceptance remain NOT_RUN. The unchanged T007 evidence
stays accepted scoped; the baseline committed inventory (41 top-level tests) must remain
undisturbed when implementation is eventually authorized.

Key rotation / multiple-key lifecycle and any persistent counters remain outside T008
scope as documented elsewhere (NOT_IMPLEMENTED, not newly required). IPv6 and all other
approved specification guarantees remain in scope; nothing here narrows or broadens them.

## 7. Reading status of referenced evidence

This draft transcribes the readiness consolidation exactly once and cites both readiness
reports by SHA256; it does not restate their audits. Author-side logs are context only and
are never treated as independent proof. Draft acceptance by 03B/04 would authorize only
moving specific candidate rows into an implementation decision record — it would still not
authorize source code, dependency addition, contract changes or deployment.
