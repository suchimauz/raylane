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

> **UPDATE — T005 contract batch complete (D1–D8).** This document's gap
> matrix below described the *partial* state before the foundation batch. The
> batch added `contracts/capability-profile.schema.json` +
> `contracts/capability-profile.json` (D1), extended
> `contracts/helper.schema.json` with `StageArtifact` and
> `RegisterReleaseConfirmation` (D2, D6), and completed
> `contracts/openapi.yaml` to 28 operations over 21 paths (apply, auth,
> backup/restore, release-protection, diagnostics, per-source allowlists,
> schedule/filter vocabularies, update counters, matcher normalisation).
> The gap matrix is retained below as the historical record of what each gap
> was; the authoritative rationale and the remaining genuine gaps (G-06 GC,
> G-12 canonical-document shape, JCS/dependency conformance, all runtime
> behaviour) are in `docs/engineering/foundation-decisions.md`. No endpoint
> is implemented; no code was written. Independent 03 review and 04 tests of
> the immutable result are still required for T005 acceptance.

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
| Placeholder rejection | **CLOSED** — reserved sentinel `__RAYLANE_SECRET_UNCHANGED_V1__`, exact-match only — G-17. |
| Optimistic-revision guard beyond PATCH | **Specified for 5 of 9**; the four creates AND both refreshes remain unresolved — G-18. |
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

**Second correction round.** Agent 03 reviewed that revision and passed it
as a document (`PASS-doc`) while finding that the *composition of the
blockers* was stated wrongly: G-17 and G-18 were presented as
architecture-level blockers, when seven of the nine marked mutations
already had a normative guard that only needed wire-coding. This revision
applies the resulting bounded patch: G-17 is closed by the reserved
sentinel 01 fixed, five of the nine markers are removed because their guard
is now written down, and G-18 shrinks to the four creates. G-11, the A04
gaps and the storage/backup gaps are untouched. Agent 03's report is in
`.hyper/tmp/t005a/T005-correction-review-REPORT.md`.

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
   `replace(value)` / `clear`, with a discriminator on `op`. "Leave this
   field alone" is expressed with `op: unchanged` — the client already knows
   whether it edited the field, and the presence-only read API protects the
   VALUE rather than reporting edit state. The one reserved sentinel
   `__RAYLANE_SECRET_UNCHANGED_V1__` is refused: a `replace` carrying
   exactly that string is not schema-valid (`not: {const: ...}`), is
   rejected with 422, and is never stored or echoed. Every other string is
   legitimate, including mask-like strings — a pattern-based rejection
   would refuse legitimate passwords. **G-17 is closed.**
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
  `replace` value. The reserved sentinel `__RAYLANE_SECRET_UNCHANGED_V1__`
  is now excluded by an explicit `not: {const: ...}` rule and is refused
  with 422, and **no other string is refused** — a mask-like string such as
  `••••` or `********` is a legitimate password. The earlier framing was
  wrong twice over: it claimed a "masked placeholder" without ever
  specifying one, and it justified the absence with the claim that the
  presence-only read API "cannot tell the client that a field is
  unchanged". Neither is true — `op: unchanged` is already in the union,
  the client knows its own edit state, and the concurrent-change case is
  covered by `expectedRevision`. **G-17 is closed.**
- ~~"Every mutation is optimistic-concurrency checked with an expected
  revision."~~ The guard is now specified for every mutation **except the
  four creates and the two refreshes**. The four `PATCH` bodies require
  `expectedRevision`; the two DELETEs carry a required `expectedRevision`
  query parameter; and the runtime stop carries a required
  `expectedGeneration` body. Six operations remain marked
  `x-implementation-status: blocked`: the four creates, because a create
  has no prior revision to compare against and the domain model has no
  collection-level revision entity; and the two refreshes, because the
  client-side guard for them is not defined by any normative source and
  the two candidate sources disagree — see **G-18**.
- ~~"The security-relevant property is preserved regardless: no secret value
  may appear here [in `NodeFields`], and secrets travel only through the
  explicit secret-update union."~~ `NodeFields` is three free-form objects
  with no key, value or depth restriction. A secret nested inside them is
  schema-valid, is stored, and is returned verbatim by the read model —
  bypassing both the presence-only view and the typed union. The artifact no
  longer claims otherwise; it names the two enforcement points that are
  required (a typed capability profile checked on write, and a read-side
  filter) and marks **G-11** as a blocking prerequisite. The same applies
  to `ConfigRevision.canonicalDocument` and **G-12**. **This gap is
  untouched by the latest patch.**

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
| G-17 | Reserved sentinel for "leave this secret unchanged" | **CLOSED** | — | The one missing piece was the spelling of the reserved value, and 01 has now fixed it: the reserved sentinel is `__RAYLANE_SECRET_UNCHANGED_V1__`. The rule is exact equality only — a `replace` whose value equals the sentinel exactly is not schema-valid (`not: {const: ...}`) and is rejected with 422 and a field error; the sentinel is never stored and never echoed. Every other string stays a legitimate value, including mask-like strings such as `••••` or `********`, because a pattern-based rejection would refuse legitimate passwords. The earlier framing of this gap was wrong on two counts and is corrected here: the "typed UI unchanged state" is NOT missing — `op: unchanged` is already in the union — and the presence-only read API does NOT need to report edit state, because it protects the VALUE while the client already knows whether it edited the field. The concurrent-change case is covered separately by `expectedRevision`. |
| G-18 | Optimistic-revision guard for the four creates and the two refreshes | TODO | (a) For a create: whether it is unguarded, or is guarded against a collection-level revision. (b) For a refresh: which normative reading governs, and which field anchors the client revision. | **This gap covers six operations: the four creates and the two refreshes.**

For the **four creates**, the guard is genuinely undetermined. A create adds a new
object and overwrites nothing, so there is no prior revision of that object to
compare against, and the domain model has NO collection-level revision entity to
compare against either — the per-entity revisions (Node, Subscription,
DestinationRule) belong to the object being created, and `ConfigRevision` is the
immutable applied revision. Both readings — unguarded, or collection-revision —
are consistent with the contracts, and choosing one would be a concurrency-design
decision, so the four creates stay marked `x-implementation-status: blocked`. They
are NOT resolved by assuming the unguarded reading.

For the **two refreshes**, an earlier revision of this artifact removed the
marker on the grounds that the data model already specifies the guard for an
update job. That was wrong, and agent 03's review rejected it. The two
normative sources **disagree**:

- `data-model.md` L3 and `control-plane.md` L3 are **blanket**: every mutation
  requires `expectedRevision`, with no exception for the refresh;
- `control-plane.md` L16 names the refresh's outcome as "202 job; busy 409;
  never apply" and does **not** name `expectedRevision`.

The single-running-job rule and the captured-`Revision` commit check that the
data model states for an `UpdateJob` are **server-side commit discipline** — they
stop a job from committing over a concurrent change. They are not a
client-supplied guard: a refresh request carries no client view of the source
state that could be stale. Clearing the marker would therefore have silently
picked the weaker reading and weakened the blanket norm **without changing the
norm** — which is exactly what the task forbids. The markers are back, and the
two readings are named for 01:

- **R1** — scope the blanket lines to state-changing entity mutations
  (PATCH/DELETE), leaving the refresh guarded by the job rule. The wire does not
  change.
- **R2** — carry a required client `expectedRevision`. For a subscription this
  can anchor on its revision field; for a rule source it **cannot** — see below.

**An additional pre-existing inconsistency.** If R2 is chosen, the rule-source
refresh has no anchor for the client revision, and neither does the PATCH on that
same entity, which already requires `expectedRevision`. The `RuleSetSource`
entity in `data-model.md` carries `draftVersion` and `activeVersion`, which are
versions of the **fetched set content**, not a revision of the source's
settings; it has no settings revision at all. This is not introduced by this
artifact — it is already there — and it is deliberately **not** resolved by
binding `expectedRevision` to `draftVersion`: that is the wrong field, and
binding to it would be a silent redefinition of what the field means. The data
model has to supply the anchor, or the norm has to be scoped, and neither is this
artifact's call. It is recorded here so that the R1/R2 decision is made with the
inconsistency in view.
| G-17 is closed | PASS | reserved sentinel fixed by 01; the "typed UI unchanged state" premise removed |
| `403` on every mutation | PASS | 14/14 |
| `413` on every body-accepting operation | PASS | 8/8 |
| Response code lists in numeric order | PASS | 21/21 |
| The three false claims are gone | PASS | no "no secret value may appear here", no "Writes never accept a masked placeholder", no "Every mutation is optimistic-concurrency checked" |
| Correction corpus (previous round, updated to the new expected state) | PASS | 75 cases, 0 failures, exit 0 |
| Patch corpus (this round) | PASS | 104 cases, 0 failures, exit 0 |
| Component schemas are valid JSON Schema (Draft 2020-12) | PASS | 36/36 `Draft202012Validator.check_schema` |
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
- the four creates carry an explicit implementation-status marker rather
  than being silently covered by the PATCH bodies, and the other five
  mutations carry a written-down guard (G-18);
- the reserved sentinel is refused while near-miss and mask-like strings
  are accepted, checked with a real JSON Schema validator rather than in
  prose (G-17, closed);
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
- The optimistic-revision guard for the four creates (G-18). G-17 is
  closed: the reserved sentinel is fixed.
- The release-protection operation and its confirmation delivery (G-07).
- Every gap listed above.

## What agent 03 should check in this revision

This revision exists to answer the previous review round, so the checks are
narrow:

- **S1** — that the "no secret value may appear here" claim is gone from
  `NodeFields`, that the write-side capability validation and the read-side
  filter are named as prerequisites, and that G-11 is marked **blocking**
  rather than TODO. That no per-protocol field model was invented.
- **S2** — that the reserved sentinel `__RAYLANE_SECRET_UNCHANGED_V1__` is
  excluded from `replace.value` by an explicit `not: {const: ...}` rule,
  that the refusal is EXACT equality only, and that mask-like strings stay
  legitimate. That the previous "typed UI unchanged state" premise and the
  previous "the read API cannot tell the client" premise are both gone.
  That G-17 is closed.
- **S3** — that the release route is gone from `paths`, that
  `ReleaseProtectionRequest` is clearly marked as an unused reference, and
  that `expectedGeneration` is required.
- **C1** — that the four item GETs are gone and that nothing outside the
  feature contract's operation table was added in their place. That
  `ConfigRevision` was not deleted but demoted to a reference schema.
- **C2** — that the four creates carry an explicit implementation-status
  marker naming G-18, that the five resolved mutations carry a written-down
  guard, that the four PATCH bodies still require `expectedRevision`, and
  that no concurrency design was chosen.
- **C3** — that `403` is on every mutation, that `413` is on every
  body-accepting operation, and that no HTTP behaviour is claimed.
- **P2** — that the two DELETEs take a REQUIRED `expectedRevision` query
  parameter, that the parameter carries no secret, and that 409 covers the
  stale-revision case.
- **P3** — that the runtime stop takes a REQUIRED `expectedGeneration` body
  with the safe-integer bound, that 409 covers the generation mismatch, and
  that the stop carries NO release field and does not depend on the release
  flow (G-07).
- **P4** — that the two refreshes still carry the normative job guard — one
  running job per source (busy 409) and the captured-revision commit check
  — and that the artifact does NOT claim this busy lock alone satisfies the
  contract's all-mutations rule; the settings themselves are guarded by
  their own PATCH.
- **P5** — that the create note names the unresolved scope precisely
  (unguarded vs collection revision), that it states the domain model has no
  collection-level revision entity, and that it does NOT resolve the choice
  by assuming the unguarded reading.
- **Counters** — that the document's counts are right: 2 deletes + 1 stop = 3
  resolved, 4 creates + 2 refreshes = 6 still marked, 9 in total.
- **Refresh** — that both refreshes carry the implementation-status marker
  again, that the note names the normative conflict (blanket `data-model`
  L3 / `control-plane` L3 against the operation table's `busy 409` in
  `control-plane` L16), that it states the job rule is SERVER-side commit
  discipline and not a client-supplied guard, and that it names both
  readings (R1, R2) without choosing one.
- **Rule-source anchor** — that the pre-existing inconsistency is recorded:
  `RuleSetSource` has `draftVersion`/`activeVersion` (fetched-set content
  versions) and no settings revision, that the PATCH on the same entity
  already has this missing anchor, and that `expectedRevision` is NOT
  quietly bound to `draftVersion`.
- **Stop responses** — that the stop declares both 400 and 413, so every
  body-accepting operation declares 413 again.
- **Normative layer** — that the sentinel literal
  `__RAYLANE_SECRET_UNCHANGED_V1__` appears in `control-plane.md` with the
  exact-match-only rule, the 422 rejection, and the no-store/no-echo
  property, so the reserved value belongs to the normative layer and not
  only to the OpenAPI artifact.
- That G-11, the A04 gaps and the storage/backup gaps are untouched by this
  patch.
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
- G-11 and G-18 are the remaining prerequisites for any downstream
  implementation of this contract. G-17 is closed.
- Agent 04 runs independent contract checks.
- T005 stays **partial** until the gap matrix is empty enough for the
  downstream implementation to start.
