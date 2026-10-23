# T005 — Control-plane OpenAPI: scope, gap matrix and status

Task: **T005** — "Зафиксировать machine-readable API/helper schemas в
contracts/openapi.yaml и contracts/helper.schema.json по feature contracts".

This document accompanies `contracts/openapi.yaml`. The helper half of T005
was delivered separately and is described in
`docs/engineering/T005-helper-schema.md`; its schema is
`contracts/helper.schema.json`.

Artifact: `contracts/openapi.yaml` — an OpenAPI 3.1 description of the
control-plane operations that the feature contracts already define and that
do not depend on the open A04 decision or the blocked backup work.

**This artifact is partial, and T005 is not done.** Downstream implementation
is blocked until the contract is complete and reviewed.

## Status

| Part | State |
|---|---|
| `contracts/openapi.yaml` | **Partial.** 21 operations over 14 paths, covering nodes, revisions validation, operations, runtime state, destination rules and source settings. |
| `contracts/helper.schema.json` | Delivered and reviewed (agent 03, PASS-schema). |
| Authentication, session, bootstrap | **BLOCKED / TODO** — see gap matrix G-01…G-03. |
| Backup, restore, retention, GC | **BLOCKED** — G-04…G-06. |
| Apply operation | **Not represented** — G-10. |
| Release-protection operation | **Not represented** (route removed) — G-07. |
| Per-protocol node field model | **Not represented** — G-11, **blocking**. |
| Placeholder rejection | **Server-side rule, not a schema property** — G-17. |
| Optimistic-revision guard beyond PATCH | **Not specified** — G-18. |
| Any server, route or handler | Does not exist. Nothing was executed. |

No endpoint in `contracts/openapi.yaml` may be treated as implemented. No
server, route, handler, database or network change was made: this task
produced two documents and no code.

**Correction round.** An earlier revision of this artifact (commit
`b953b26`) was reviewed by agent 03 and received three security corrections
(S1, S2, S3) and three consistency corrections (C1, C2, C3). All six are
applied in this revision. The corrections removed five operations, removed
three false security claims, and added two gaps (G-17, G-18). The review
report is in `.hyper/tmp/t005a/T005-openapi-review-REPORT.md` (agent 03's
own ignored scratch).

## Sources

- `specs/001-selected-connections/contracts/control-plane.md` — the API
  interface: operation list, secret handling, error taxonomy, UI states.
- `specs/001-selected-connections/data-model.md` — entities, invariants and
  the state machines (apply phases, update phases, readiness dimensions).
- `specs/001-selected-connections/spec.md` — FR-009, FR-010, FR-011, FR-013,
  FR-014, FR-019, FR-020, FR-021; US-01, US-02, US-03, US-04.
- `specs/001-selected-connections/plan.md` — architecture boundaries.
- `docs/engineering/A04-contract-proposal.md` — the partially accepted
  session policy; read to find out which parts are decided and which are
  open.

## What the OpenAPI artifact encodes

### Operations represented

21 operations over 14 paths.

| Area | Operations |
|---|---|
| Nodes | `listNodes`, `createNode`, `getNode`, `updateNode`, `deleteNode` |
| Revisions | `validateRevision` |
| Operations | `getOperation` |
| Runtime | `getState`, `stopRuntime` |
| Destination rules | `listRules`, `createRule`, `updateRule`, `deleteRule` |
| Sources | `listSubscriptions`, `createSubscription`, `updateSubscription`, `listRuleSources`, `createRuleSource`, `updateRuleSource`, `refreshSubscription`, `refreshRuleSource` |

Paths and methods follow `control-plane.md` exactly, including the item-path
form for `PATCH` on subscriptions and rule sources.

Two groups of operations that an earlier revision of this artifact carried
were **removed** in the 03-review correction round, because the feature
contract's operation table does not name them:

- `getRevision`, `getRule`, `getSubscription`, `getRuleSource` — four item
  GETs that no row of the `control-plane.md` operation table specifies. A
  read-only, redacted GET would have been defensible, but the artifact
  claimed to describe "the operations the feature contracts already
  define", and these four are not among them. The schemas they returned
  (`ConfigRevision`, `DestinationRule`, `SubscriptionSettings`,
  `RuleSourceSettings`) are retained as reference schemas where they are
  still meaningful, and `DestinationRule` / `SubscriptionSettings` /
  `RuleSourceSettings` remain attached to the list operations.
- `releaseProtection` — the route was published in a "declared but not
  usable" state. A declared-but-unusable route is a route that can be
  mistaken for a working one, so the path was removed and
  `ReleaseProtectionRequest` was kept as a clearly-unused reference
  schema. See G-07.

### Security invariants — and what is deliberately NOT claimed

These are structural in the artifact, not merely described in prose:

1. **A read never returns a secret value.** `NodeDraft.secrets` maps to
   `SecretPresence` — a `present` boolean only. No read model
   (`NodeDraft`, `SubscriptionSettings`, `RuleSourceSettings`,
   `DestinationRule`, `RuntimeState`) has a `value` property. The only
   schema with a `value` is `SecretUpdateReplace`, which is write-side.
2. **A read never returns a raw source URL.** `SubscriptionSettings` and
   `RuleSourceSettings` expose `urlPresent` and `urlRedacted`, never `url`.
   A raw URL can carry userinfo credentials, so it is not returned.
3. **A secret update is an explicit union** of `unchanged` /
   `replace(value)` / `clear`, with a discriminator on `op`.
   **This union does not reject a masked placeholder** — see the correction
   below and G-17.
4. **There is no implicit fetch and no implicit apply.** Source settings
   operations state that they never fetch; `validateRevision` states that it
   never applies; a fetch happens only through the explicit `refresh`
   operations.
5. **Stop and release are separate.** `/runtime/stop` carries no release
   field, and there is no release route at all in `paths` — see G-07.
6. **Errors never echo a remote source body.** `ErrorResponse` is closed and
   carries `code`, `message`, optional `fieldErrors`, `requestId` and
   optional `dependencies`. The message is documented as never carrying a
   secret value, a token or a raw source body.
7. **Validation reports not-run as not-run.** `ValidationReport.status`
   includes `not-run` beside `passed` and `failed`.
8. **Standard responses are declared where the contract's taxonomy names
   them.** Every mutation declares `403`; every operation that accepts a
   request body declares `413`. These are response *declarations*; no HTTP
   behaviour is claimed, because no server exists.

Three claims that an earlier revision of this artifact made and that are
now **removed**, because they were not true:

- ~~"A write never accepts a masked placeholder as a value."~~ The
  `SecretUpdate` union accepts any string of 1..4096 characters as a
  `replace` value. A string that looks like the masked placeholder the UI
  displays is schema-valid. The contract states the rule; enforcing it is a
  server-side validation, and the placeholder's literal spelling is not
  specified anywhere. The artifact now says so explicitly and names the
  two missing pieces — a reserved placeholder constant and a typed UI
  unchanged state — as **G-17**. The negative corpus demonstrates the gap
  rather than asserting it away.
- ~~"Every mutation is optimistic-concurrency checked with an expected
  revision."~~ Only the four `PATCH` bodies carry `expectedRevision`. The
  contract's mutation line is broader, and the guard for creates, deletes,
  the runtime stop and the two refreshes is not specified. Choosing one
  would be a concurrency-design decision, so those nine operations carry
  `x-implementation-status: blocked` with a note naming **G-18**.
- ~~"The security-relevant property is preserved regardless: no secret value
  may appear here [in `NodeFields`], and secrets travel only through the
  explicit secret-update union."~~ `NodeFields` is three free-form objects
  with no key, value or depth restriction. A secret nested inside them is
  schema-valid, is stored, and is returned verbatim by the read model —
  bypassing both the presence-only view and the typed union. The artifact no
  longer claims otherwise; it names the two enforcement points that are
  required (a typed capability profile checked on write, and a read-side
  filter) and marks **G-11** as a blocking prerequisite. The same applies
  to `ConfigRevision.canonicalDocument` and **G-12**.

### Consistency with the helper contract

- The generation fields (`RuntimeState.activeGeneration`,
  `ReleaseProtectionRequest.expectedGeneration`) use the same JSON
  safe-integer bound, `9007199254740991`, that the helper envelope now
  carries.
- The operation-phase vocabulary is the data model's vocabulary, including
  `degraded-guarded` and `stopped-guarded`.

## Gap matrix

Each row is a deliberate omission, not an oversight. Gaps that depend on
A04 or on the blocked backup work are marked **BLOCKED**; gaps that are
simply not yet decided by any contract are marked **TODO**; a gap that
blocks any downstream implementation is marked **BLOCKING**. Neither kind
is filled in with an assumption.

**The session gaps and the backup gaps are independent.** G-01..G-03 depend
only on the session part of A04; G-04..G-06 depend only on backup, restore
and garbage collection. A04 does not choose backup A/B, but it does accept
the session policy in part, so the session work is not held hostage by the
backup decision. The session gaps remain BLOCKED on their own open
mechanics, not on the backup choice.

**The A04 session values that are USER-ACCEPTED**, recorded in the artifact
so the implementation has them in one place: idle 15 minutes (polling and
reads do not extend it, and neither does a long edit without saving);
absolute 12 hours regardless of activity; re-login required after a
control-plane restart. The exact activity allowlist, the limiter constants
and the enforcement details stay PROPOSED. One condition attaches to the
accepted expiry: **loss of unsaved edits is not permitted**, so a mechanism
for preserving and restoring unsaved edits across expiry, re-login and
restart must be defined and verified before any UI is built. The accepted
expiry does not choose that mechanism and does not permit storing secrets in
browser storage or in logs.

| ID | Subject | Status | What is missing | Why it is not invented here |
|---|---|---|---|---|
| G-01 | Authentication endpoints (`POST /session`, `DELETE /session`) | BLOCKED | The login/logout endpoints, their bodies and their responses. | A04 has only partial consent: session idle 15 min, absolute 12 h and re-login after restart are USER-ACCEPTED, while the limiter constants, the activity allowlist and the rest remain PROPOSED. A04 is OPEN. The accepted values are recorded in the artifact's `sessionCookie` description as the policy the implementation must honour — recording them does **not** make the session implementation ready, which it is not. |
| G-02 | Bootstrap (`POST /bootstrap`) | BLOCKED | The bootstrap channel, the one-time token and the atomic closing after admin creation. | A04 accepts a local issuance before an admin exists and forbids re-issuance afterwards, but the concrete channel and the error taxonomy are not settled. |
| G-03 | Session mechanics, CSRF and origin checks | BLOCKED | The cookie attributes, the CSRF scheme and the origin policy. | The control-plane contract requires CSRF and origin checks on every mutation, but the mechanism is part of the A04 decision that is still open. The artifact therefore declares a `sessionCookie` security scheme marked **Placeholder** and requires it on every operation, without specifying how the session is established. |
| G-04 | Backup (`POST /backups`) | BLOCKED | The backup endpoint and its envelope. | A04 explicitly does not choose backup A/B: self-contained encrypted export versus persistent backup metadata and pinning. Backup-live schema and GC stay BLOCKED. |
| G-05 | Restore (`POST /restores`) | BLOCKED | The restore endpoint. | Same as G-04, plus the restore-to-draft semantics depend on the secret-import behaviour chosen with the backup alternative. |
| G-06 | Retention and garbage collection | BLOCKED | Any endpoint or field that deletes revisions, drafts, secrets or audit records. | A04 sets all cleanup to OFF: no 30-day compaction, no six-month audit deletion, no secret payload cleanup. Nothing in this artifact deletes anything. |
| G-07 | Release-protection confirmation delivery | TODO | How the expiring confirmation token is issued, delivered to the client and returned. | The contract requires a bound, single-use confirmation, and A04 specifies its binding (session, active generation, protection state) and its 120-second TTL as PROPOSED. But the delivery path and the client-side flow are not decided. **The release route was therefore REMOVED from `paths`** rather than published in a blocked state: a declared-but-unusable route can be mistaken for a working one. `ReleaseProtectionRequest` is kept as a clearly-unused reference schema, with `expectedGeneration` now required. |
| G-08 | Source schedule kinds | TODO | The enum of schedule kinds and their fields. | FR-014 requires manual, after-boot, daily, by-weekday and 1–24-hour interval scheduling, but no contract fixes the wire names. The artifact carries the structure with `automaticEnabled`, `kind`, `time` and `intervalHours` rather than inventing an enum. |
| G-09 | Subscription filter modes | TODO | The exact filter vocabulary and the global-inheritance form. | FR-013 lists off, discard, keep, two priority modes and global inheritance, and the research states that the zero-sample policy is not yet agreed. The artifact carries `mode` (off/discard/keep), an optional `priority` and `globalInherited`, and names the gap. |
| G-10 | Apply operation | TODO | `POST /revisions/{id}/apply` and its operation response. | The control-plane contract lists it, but it is the operation that reaches the privileged helper, and the helper side is blocked on open item 8 of the helper document: the channel that delivers artefact content into helper-owned storage is undefined and the architecture is not chosen. Publishing an apply route now would imply a working path that does not exist. |
| G-11 | Capability profile and per-protocol node fields | **BLOCKING** | The concrete field list per protocol, the typed write-side validation, and the read-side filter. | The data model says each protocol's capability profile fixes the supported fields, defaults and dependencies, but that profile is not written. `NodeFields` therefore carries the *structure* — three bounded free-form objects — rather than a per-protocol field list that would freeze a product decision. **The security-relevant property does NOT hold in the meantime**: the free-form groups accept any key, value and nesting depth, and the read model returns them verbatim, so a secret written there is stored and returned in clear text. Two enforcement points are required and neither exists: a typed capability profile checked on write, and a read-side filter. Until they do, `NodeFields` is unvalidated content and no backend or UI may be built on it. A per-protocol field model is not invented here — that is the capability-profile task's product decision. |
| G-12 | Canonical document shape of a revision | TODO | The shape of `ConfigRevision.canonicalDocument`. | It follows the compiler output, which does not exist yet. Until the compiler exists, the document is a free-form object and the artifact no longer claims it is secret-free — that property belongs to the compiler, not to the schema. `ConfigRevision` itself is kept as a reference schema, since the contract's operation table names no revision-read operation. |
| G-13 | Destination matcher normalisation | TODO | The normalisation rules per matcher kind. | The data model says domain and IP matching is normalised in a documented way, but the rules are not written. The artifact carries the matcher type and value with the gap named. |
| G-14 | Diagnostics export (`POST /diagnostics/export`) | TODO | The endpoint and the allowlisted artefact set. | The contract requires an allowlisted non-secret artefact export, but the allowlist itself is not defined. It is not included rather than being guessed. |
| G-15 | Update-job counters | TODO | The counters an update job reports. | The data model lists counters on `UpdateJob` without fixing them. |
| G-16 | Peer / LAN allowlist for source fetches | TODO | The per-source LAN allowlist field and its administration. | FR-023 and D-061 require a per-source allowlist that only the administrator changes, and forbidden address classes to take priority over it. The mechanism is not fixed, so the field is not invented. |
| G-17 | Masked-placeholder constant and the typed UI unchanged state | TODO | The reserved literal the UI displays in place of a secret, the server-side rule that refuses it, and the client-side state that distinguishes "unchanged" from "replaced". | The contract states that a masked placeholder is not a new value, but the placeholder's literal spelling is specified nowhere, and the read API is presence-only — it cannot tell the client that a field is unchanged. So the `SecretUpdate` union **cannot** reject a placeholder-looking value: `replace.value` accepts any string of 1..4096 characters, and a placeholder-looking string is schema-valid. The artifact now says this plainly instead of claiming the rejection. Two normative prerequisites are named here rather than invented: a reserved, explicitly specified placeholder constant that the server can recognise and refuse, and a typed UI state for "unchanged". A constant is not declared here, because choosing one is a product decision and no contract fixes it. |
| G-18 | Optimistic-revision guard for the mutations that have none | TODO | The concurrency mechanism for creates, deletes, the runtime stop and the two refreshes. | The contract's mutation line says every mutation carries an optimistic revision, but the contract itself names `expectedRevision` only for `PATCH`, and names a 409 for a busy resource and for a dependency conflict — which are concurrency outcomes, not optimistic revision checks. The guard for the remaining nine operations is therefore unspecified. Choosing one here would be a concurrency-design decision, so those operations carry `x-implementation-status: blocked` with a note, instead of the artifact claiming that PATCH alone satisfies the contract. |

## Technical choices made here, and why

These are small, non-substantive choices consistent with the existing
specification. They are listed so that agent 03 can see them rather than
discover them.

| Choice | Rationale |
|---|---|
| Identifier pattern `^[A-Za-z0-9][A-Za-z0-9_-]*$`, max 64 | Same shape as the helper schema's identifier, so the two contracts speak the same language. It excludes path separators, so an identifier cannot express a filesystem path. |
| `Revision` as a non-negative integer | The data model defines optimistic revisions; a counter is the direct reading. |
| Protocol enum `vless, socks5, http, wireguard` | Exactly the four protocols of FR-001, in the contract's own terms. SOCKS4/SOCKS4a and a local public proxy server are outside the selection. |
| Destination rule kind enum `block, direct, proxy` | Exactly the three kinds named in the data model. |
| Matcher type enum `domain, ip, cidr, set` | Exactly the four matcher kinds named in the data model. |
| `SourceAccessMode` enum `auto, direct, proxy` | Exactly the three modes named in FR-014. |
| Free-form objects only for `NodeFields` | G-11. A per-protocol field list would be a product decision. The consequence is now stated rather than hidden: the free-form groups are unvalidated content, and the write-side validation and read-side filter are named as prerequisites. |
| `X-Request-Id` header plus a `requestId` body field | The control-plane contract names `requestId` in the error body. The header is the conventional way to correlate it with logs, and it is echoed on every response. |
| `not-run` in the validation status enum | The helper contract and the data model both require that a check that was not executed is never reported as passed. |
| The `stopped-guarded` phase in `OperationPhase` | FR-020 names the stopped-but-still-protected state; the data model names it as a distinct state from `active`. |
| Sizes on free-form objects and arrays (256 / 512 / 16 / 32) | Technical bounds in the same spirit as the helper schema's bounds, and marked as such. |

## Checks

All checks are offline and use only the locally installed **PyYAML 6.0.1**
(`/usr/lib/python3/dist-packages/yaml`). No OpenAPI validator is installed on
this machine — `openapi_spec_validator` is absent — so **full OpenAPI
conformance validation is NOT_RUN**, and the checks below are the structural
and invariant checks that could be performed with what is available. The
corpus is synthetic and lives in the ignored scratch directory
`.hyper/tmp/buj/t005corr/`; it is not committed, because the task's allowed
files are the OpenAPI artifact and this document.

| Check | Result | Command |
|---|---|---|
| YAML parses | PASS | `yaml.safe_load(open('contracts/openapi.yaml'))` → exit 0 |
| OpenAPI version is 3.1.x | PASS | `openapi: 3.1.0` |
| All `$ref` targets resolve | PASS | 45 refs, 0 unresolved |
| Every operation has an `operationId` | PASS | 21 operations |
| `operationId`s are unique | PASS | 21 unique |
| Every operation declares `responses` | PASS | 21/21 |
| Every operation requires the session scheme | PASS | 21/21 declare `sessionCookie` |
| No read model exposes a raw secret value | PASS | `SecretPresence` has only `present` |
| Secret write union is explicit and closed | PASS | `unchanged` / `replace` / `clear`, `additionalProperties: false` |
| Every update body requires `expectedRevision` | PASS | 4/4 |
| Generation fields use the safe-integer bound | PASS | `maximum: 9007199254740991` |
| Read models are closed | PASS | 6/6 `additionalProperties: false` |
| Release-protection route absent | PASS | no `/runtime/release-protection` in `paths` |
| `expectedGeneration` required | PASS | `ReleaseProtectionRequest.required = [confirmation, expectedGeneration]` |
| The four item GETs are absent | PASS | no `getRevision` / `getRule` / `getSubscription` / `getRuleSource` |
| The nine unguarded mutations are marked | PASS | 9 × `x-implementation-status: blocked`, each naming G-18 |
| `403` on every mutation | PASS | 14/14 |
| `413` on every body-accepting operation | PASS | 8/8 |
| Response code lists in numeric order | PASS | 21/21 |
| The three false claims are gone | PASS | no "no secret value may appear here", no "Writes never accept a masked placeholder", no "Every mutation is optimistic-concurrency checked" |
| Correction corpus | PASS | 73 cases, 0 failures, exit 0 |
| Component schemas are valid JSON Schema (Draft 2020-12) | PASS | 35/35 `Draft202012Validator.check_schema` |
| Full OpenAPI conformance validation | **NOT_RUN** | no OpenAPI validator installed; none was installed |

The correction corpus covers the structure and the invariants, and its
**negative part demonstrates the gaps instead of asserting them away**:

- a secret nested four levels deep inside the free-form `NodeFields`
  groups is schema-valid, and the read model returns the groups verbatim —
  the artifact no longer claims otherwise, and names the write-side
  validation and the read-side filter as prerequisites (G-11);
- a placeholder-looking string (`••••••••`, `********`, `«hidden»`, `***`)
  is schema-valid as a `SecretUpdate` `replace` value, because the value is
  only length-bounded and the placeholder's literal spelling is unspecified
  — the artifact no longer claims the union rejects it, and names the
  reserved constant and the typed UI unchanged state as prerequisites
  (G-17);
- the release-protection route and the four item GETs are absent from
  `paths`;
- the nine mutations without a revision guard carry an explicit
  implementation-status marker rather than being silently covered by the
  PATCH bodies (G-18);
- the accepted A04 session values (idle 15 min, absolute 12 h, re-login
  after restart) are recorded, the prohibition on losing unsaved edits is
  recorded with them, and the session gaps are stated to be independent of
  the backup A/B choice.

**What the corpus does not do:** it is not an OpenAPI conformance check.
It uses a small purpose-built structural validator, not a JSON Schema or
OpenAPI implementation, so it makes no claim about specification
conformance.

## Not decided here

- Storage architecture, backup A/B, and secret persistence in the browser.
- Whether any of the A04 PROPOSED constants become defaults.
- The apply operation, until the helper's artefact-delivery channel is
  decided.
- The capability profile, and therefore the concrete node fields, the
  write-side validation and the read-side filter (G-11, **blocking**).
- The masked-placeholder constant and the typed UI unchanged state (G-17).
- The optimistic-revision guard for creates, deletes, the runtime stop and
  the refreshes (G-18).
- The release-protection operation and its confirmation delivery (G-07).
- Every gap listed above.

## What agent 03 should check in this revision

This revision exists to answer the previous review round, so the checks are
narrow:

- **S1** — that the "no secret value may appear here" claim is gone from
  `NodeFields`, that the write-side capability validation and the read-side
  filter are named as prerequisites, and that G-11 is marked **blocking**
  rather than TODO. That no per-protocol field model was invented.
- **S2** — that the artifact no longer claims the union rejects a masked
  placeholder, that the negative corpus demonstrates the gap rather than
  asserting it away, and that no placeholder constant was invented.
  That G-17 names both the reserved constant and the typed UI unchanged
  state.
- **S3** — that the release route is gone from `paths`, that
  `ReleaseProtectionRequest` is clearly marked as an unused reference, and
  that `expectedGeneration` is required.
- **C1** — that the four item GETs are gone and that nothing outside the
  feature contract's operation table was added in their place. That
  `ConfigRevision` was not deleted but demoted to a reference schema.
- **C2** — that the nine unguarded mutations carry an explicit
  implementation-status marker naming G-18, that the four PATCH bodies still
  require `expectedRevision`, and that no concurrency design was chosen.
- **C3** — that `403` is on every mutation, that `413` is on every
  body-accepting operation, and that no HTTP behaviour is claimed.
- That the accepted A04 session values are recorded, that the prohibition on
  losing unsaved edits is recorded with them, that the session gaps are
  stated to be independent of the backup A/B choice, and that no claim is
  made that the session implementation is ready.
- That the three removed false claims do not reappear in any other wording.

## Next

- Agent 03 reviews this revision.
- The gaps that block the apply operation are resolved by the Chief
  Architect's decision on artefact delivery, and separately by the A04
  decision.
- G-11, G-17 and G-18 are prerequisites for any downstream implementation
  of this contract.
- Agent 04 runs independent contract checks.
- T005 stays **partial** until the gap matrix is empty enough for the
  downstream implementation to start.
