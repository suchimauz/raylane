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
| `contracts/openapi.yaml` | **Partial.** 26 operations over 16 paths, covering nodes, revisions, validation, operations, runtime state, destination rules and source settings. |
| `contracts/helper.schema.json` | Delivered and reviewed (agent 03, PASS-schema). |
| Authentication, session, bootstrap | **BLOCKED / TODO** — see gap matrix G-01…G-03. |
| Backup, restore, retention, GC | **BLOCKED** — G-04…G-06. |
| Apply operation | **Not represented** — G-10. |
| Any server, route or handler | Does not exist. Nothing was executed. |

No endpoint in `contracts/openapi.yaml` may be treated as implemented. No
server, route, handler, database or network change was made: this task
produced two documents and no code.

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

| Area | Operations |
|---|---|
| Nodes | `listNodes`, `createNode`, `getNode`, `updateNode`, `deleteNode` |
| Revisions | `getRevision`, `validateRevision` |
| Operations | `getOperation` |
| Runtime | `getState`, `stopRuntime`, `releaseProtection` (declared but BLOCKED) |
| Destination rules | `listRules`, `createRule`, `getRule`, `updateRule`, `deleteRule` |
| Sources | `listSubscriptions`, `createSubscription`, `getSubscription`, `updateSubscription`, `listRuleSources`, `createRuleSource`, `getRuleSource`, `updateRuleSource`, `refreshSubscription`, `refreshRuleSource` |

Paths and methods follow `control-plane.md` exactly, including the item-path
form for `PATCH` on subscriptions and rule sources.

### Security invariants

These are structural in the artifact, not merely described in prose:

1. **A read never returns a secret value.** `NodeDraft.secrets` maps to
   `SecretPresence` — a `present` boolean only. No read model
   (`NodeDraft`, `SubscriptionSettings`, `RuleSourceSettings`,
   `DestinationRule`, `RuntimeState`) has a `value` property. The only
   schema with a `value` is `SecretUpdateReplace`, which is write-side.
2. **A read never returns a raw source URL.** `SubscriptionSettings` and
   `RuleSourceSettings` expose `urlPresent` and `urlRedacted`, never `url`.
   A raw URL can carry userinfo credentials, so it is not returned.
3. **A write never accepts a masked placeholder as a value.** `SecretUpdate`
   is a closed union of `unchanged` / `replace(value)` / `clear`, with a
   discriminator on `op`. A placeholder is not one of the three.
4. **Every mutation is optimistic-concurrency checked.** All four update
   bodies require `expectedRevision`; a mismatch is 409 and does not
   overwrite a newer state.
5. **There is no implicit fetch and no implicit apply.** Source settings
   operations state that they never fetch; `validateRevision` states that it
   never applies; a fetch happens only through the explicit `refresh`
   operations.
6. **Stop and release are separate.** `/runtime/stop` carries no release
   field; `/runtime/release-protection` is the only release path and is
   marked BLOCKED in its own description.
7. **Errors never echo a remote source body.** `ErrorResponse` is closed and
   carries `code`, `message`, optional `fieldErrors`, `requestId` and
   optional `dependencies`. The message is documented as never carrying a
   secret value, a token or a raw source body.
8. **Validation reports not-run as not-run.** `ValidationReport.status`
   includes `not-run` beside `passed` and `failed`.

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
simply not yet decided by any contract are marked **TODO**. Neither kind is
filled in with an assumption.

| ID | Subject | Status | What is missing | Why it is not invented here |
|---|---|---|---|---|
| G-01 | Authentication endpoints (`POST /session`, `DELETE /session`) | BLOCKED | The login/logout endpoints, their bodies and their responses. | A04 has only partial consent: session idle 15 min, absolute 12 h and re-login after restart are user-accepted, while the limiter constants, the activity allowlist and the rest remain PROPOSED. A04 is OPEN. |
| G-02 | Bootstrap (`POST /bootstrap`) | BLOCKED | The bootstrap channel, the one-time token and the atomic closing after admin creation. | A04 accepts a local issuance before an admin exists and forbids re-issuance afterwards, but the concrete channel and the error taxonomy are not settled. |
| G-03 | Session mechanics, CSRF and origin checks | BLOCKED | The cookie attributes, the CSRF scheme and the origin policy. | The control-plane contract requires CSRF and origin checks on every mutation, but the mechanism is part of the A04 decision that is still open. The artifact therefore declares a `sessionCookie` security scheme marked **Placeholder** and requires it on every operation, without specifying how the session is established. |
| G-04 | Backup (`POST /backups`) | BLOCKED | The backup endpoint and its envelope. | A04 explicitly does not choose backup A/B: self-contained encrypted export versus persistent backup metadata and pinning. Backup-live schema and GC stay BLOCKED. |
| G-05 | Restore (`POST /restores`) | BLOCKED | The restore endpoint. | Same as G-04, plus the restore-to-draft semantics depend on the secret-import behaviour chosen with the backup alternative. |
| G-06 | Retention and garbage collection | BLOCKED | Any endpoint or field that deletes revisions, drafts, secrets or audit records. | A04 sets all cleanup to OFF: no 30-day compaction, no six-month audit deletion, no secret payload cleanup. Nothing in this artifact deletes anything. |
| G-07 | Release-protection confirmation delivery | TODO | How the expiring confirmation token is issued, delivered to the client and returned. | The contract requires a bound, single-use confirmation, and A04 specifies its binding (session, active generation, protection state) and its 120-second TTL as PROPOSED. But the delivery path and the client-side flow are not decided, so the endpoint is declared and marked BLOCKED rather than given a working shape. |
| G-08 | Source schedule kinds | TODO | The enum of schedule kinds and their fields. | FR-014 requires manual, after-boot, daily, by-weekday and 1–24-hour interval scheduling, but no contract fixes the wire names. The artifact carries the structure with `automaticEnabled`, `kind`, `time` and `intervalHours` rather than inventing an enum. |
| G-09 | Subscription filter modes | TODO | The exact filter vocabulary and the global-inheritance form. | FR-013 lists off, discard, keep, two priority modes and global inheritance, and the research states that the zero-sample policy is not yet agreed. The artifact carries `mode` (off/discard/keep), an optional `priority` and `globalInherited`, and names the gap. |
| G-10 | Apply operation | TODO | `POST /revisions/{id}/apply` and its operation response. | The control-plane contract lists it, but it is the operation that reaches the privileged helper, and the helper side is blocked on open item 8 of the helper document: the channel that delivers artefact content into helper-owned storage is undefined and the architecture is not chosen. Publishing an apply route now would imply a working path that does not exist. |
| G-11 | Capability profile and per-protocol node fields | TODO | The concrete field list per protocol. | The data model says each protocol's capability profile fixes the supported fields, defaults and dependencies, but that profile is not written. `NodeFields` therefore carries the *structure* — three bounded free-form objects — rather than a per-protocol field list that would freeze a product decision. The security-relevant property holds regardless: secrets travel only through the explicit union. |
| G-12 | Canonical document shape of a revision | TODO | The shape of `ConfigRevision.canonicalDocument`. | It follows the compiler output, which does not exist yet. |
| G-13 | Destination matcher normalisation | TODO | The normalisation rules per matcher kind. | The data model says domain and IP matching is normalised in a documented way, but the rules are not written. The artifact carries the matcher type and value with the gap named. |
| G-14 | Diagnostics export (`POST /diagnostics/export`) | TODO | The endpoint and the allowlisted artefact set. | The contract requires an allowlisted non-secret artefact export, but the allowlist itself is not defined. It is not included rather than being guessed. |
| G-15 | Update-job counters | TODO | The counters an update job reports. | The data model lists counters on `UpdateJob` without fixing them. |
| G-16 | Peer / LAN allowlist for source fetches | TODO | The per-source LAN allowlist field and its administration. | FR-023 and D-061 require a per-source allowlist that only the administrator changes, and forbidden address classes to take priority over it. The mechanism is not fixed, so the field is not invented. |

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
| Free-form objects only for `NodeFields` | G-11. A per-protocol field list would be a product decision; the structure preserves the security property either way. |
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
`.hyper/tmp/buj/t005openapi/`; it is not committed, because the task's
allowed files are the OpenAPI artifact and this document.

| Check | Result | Command |
|---|---|---|
| YAML parses | PASS | `yaml.safe_load(open('contracts/openapi.yaml'))` → exit 0 |
| OpenAPI version is 3.1.x | PASS | `openapi: 3.1.0` |
| All `$ref` targets resolve | PASS | 46 refs, 0 unresolved |
| Every operation has an `operationId` | PASS | 26 operations |
| `operationId`s are unique | PASS | 26 unique |
| Every operation declares `responses` | PASS | 26/26 |
| Every operation requires the session scheme | PASS | 26/26 declare `sessionCookie` |
| No read model exposes a raw secret value | PASS | `SecretPresence` has only `present` |
| Secret write union is explicit and closed | PASS | `unchanged` / `replace` / `clear`, `additionalProperties: false` |
| Every update body requires `expectedRevision` | PASS | 4/4 |
| Generation fields use the safe-integer bound | PASS | `maximum: 9007199254740991` |
| Read models are closed | PASS | 6/6 `additionalProperties: false` |
| Synthetic corpus | PASS | 36 cases, 0 failures, exit 0 |
| Full OpenAPI conformance validation | **NOT_RUN** | no OpenAPI validator installed; none was installed |

The synthetic corpus covers: the presence of each covered operation group;
the **absence** of login, bootstrap, backup, restore, retention/GC and apply
endpoints; presence-only secret reads; redacted URLs; the closed secret
union; `expectedRevision` on every update; stop and release as separate
operations with release marked BLOCKED; explicit-only refresh; no implicit
fetch or apply; the error body shape; the phase vocabulary; `not-run` in the
validation status; the generation bound; and the placeholder marking of the
security scheme.

## Not decided here

- Storage architecture, backup A/B, and secret persistence in the browser.
- Whether any of the A04 PROPOSED constants become defaults.
- The apply operation, until the helper's artefact-delivery channel is
  decided.
- The capability profile, and therefore the concrete node fields.
- Every gap listed above.

## What agent 03 should check

- That the represented operations match `control-plane.md` exactly, and that
  nothing outside the allowed subset was added.
- That no gap was silently closed with an invented field, enum or route —
  in particular G-08, G-09, G-11 and G-13, where a plausible-looking enum
  would have been the easy wrong answer.
- That the security invariants hold structurally and not only in prose.
- That the two BLOCKED endpoints (`releaseProtection`, and the absent apply)
  are marked as such in a way that cannot be mistaken for a working path.
- Whether the technical choices listed above are acceptable, or should be
  recorded as separate gaps.

## Next

- Agent 03 reviews this document and `contracts/openapi.yaml`.
- The gaps that block the apply operation are resolved by the Chief
  Architect's decision on artefact delivery, and separately by the A04
  decision.
- Agent 04 runs independent contract checks after T002.
- T005 stays **partial** until the gap matrix is empty enough for the
  downstream implementation to start.
