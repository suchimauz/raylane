# T005 — Machine-readable helper contract

Task: **T005** — "Зафиксировать machine-readable API/helper schemas в
contracts/openapi.yaml и contracts/helper.schema.json по feature contracts; 03
проверяет отсутствие arbitrary shell/path и secret-read".

This document covers the **helper** half of that task only. The
control-plane half (`contracts/openapi.yaml`) is **not** delivered here and
T005 is therefore **not complete** — see [Status](#status).

Artifact: `contracts/helper.schema.json` — a declarative JSON Schema
(2020-12) for a single request envelope sent by the control plane to the
restricted privileged helper.

Scope of this artifact: **the request shape only**. It is not a helper
implementation, not a network design, and not a dataplane specification. No
helper, no socket, no nftables rule and no privilege was exercised.

## Status

| Part | State |
|---|---|
| `contracts/helper.schema.json` | Delivered in this task; offline contract checks pass. |
| `contracts/openapi.yaml` (control-plane API) | **NOT delivered.** Out of the scope of this task packet, which named only the helper schema. |
| Helper implementation | Not started, and not in scope here. |
| Runtime behaviour of any command | **NOT_RUN.** The schema was never sent to a helper; no socket exists. |

T005 is **not** fully done and is **not** claimed as done. The remaining part
of the task (the control-plane OpenAPI schema) and the independent review by
agent 03 are outstanding.

## Sources

The schema is a direct transcription of the already-agreed contracts, not a
new design:

- `specs/001-selected-connections/contracts/network-agent.md` — the helper
  contract: envelope fields, the nine commands, the typed manifest of
  permitted objects, ownership rules, the apply protocol, required negative
  tests.
- `specs/001-selected-connections/contracts/control-plane.md` — framing:
  optimistic revision, `409` on conflict, `422` on semantic validation,
  `413` on limits, the separation of *stop* from *release protection*, and the
  requirement that endpoints are fixed machine-readably before parallel
  UI/backend work.
- `specs/001-selected-connections/spec.md` — FR-009, FR-010 (save ≠ apply),
  FR-019 (secrets), FR-020 (IPv6 TProxy off by default; stop keeps protection),
  FR-021 (single admin role, rollback attempt, degraded state), US-02
  (separate saving from the running state), US-05 (LAN traffic direction).
- `specs/001-selected-connections/data-model.md` — `ActiveState`
  (revisionId, manifestHash, generation, readiness), `ApplyJournal`
  (previousActive, candidate, state, helperOperationId).
- `docs/engineering/A04-contract-proposal.md` — the A04 session policy
  consent. Read for boundaries only: it decides session parameters and
  explicitly does **not** decide backup A/B, does not authorise deletion, and
  leaves backup-live schema and GC **BLOCKED**. Nothing from it is encoded
  here.
- `specs/001-selected-connections/tasks.md` — the T005 line and its
  prerequisite (T001, accepted).

## What the schema fixes

### Envelope

Required on every request, closed (`additionalProperties: false` at envelope
level):

| Field | Type | Meaning |
|---|---|---|
| `protocolVersion` | `"1"` | Wire format. A mismatch is a hard rejection, never best-effort. |
| `operationId` | UUID v4, lowercase | Idempotency key together with `payloadHash`. |
| `expectedGeneration` | integer ≥ 0 | The generation state the control plane believes is current. |
| `command` | closed enum of 9 | The operation to perform. |
| `payloadHash` | SHA-256 hex, lowercase | Part of the idempotency key. |
| `payload` | command-specific object | Typed, closed per command. |

`expectedGeneration` is the request-side half of the generation check: the
helper compares it with its own state and rejects a request prepared against a
stale view. It is **not** a lock — concurrent requests are still possible, so
the helper must serialise its own operations.

### Commands

The enum is exactly the nine commands of the helper contract: `Inspect`,
`ValidateManifest`, `PrepareGeneration`, `EngageGuard`, `ActivateGeneration`,
`VerifyGeneration`, `RestoreGeneration`, `StopGuarded`, `ReleaseProtection`.

There is deliberately **no** generic `Execute`/`Run` command and **no** command
that persists a configuration. Saving a draft is a control-plane concern and
must never reach the privileged helper — this is the schema-level expression
of FR-009/US-02 (`save != apply`).

Each command selects one closed payload variant through conditional subschemas,
so a payload carrying another command's fields is rejected rather than ignored.

### Manifest of permitted objects

`ValidateManifest` and `PrepareGeneration` carry a `manifest` with:
`generationId`, `listenerPorts`, `approvedInterfaces`, `destinationSets`,
`policyRefs`, `engineArtifacts`, `dnsArtifacts`, `ipv6TProxyEnabled`.

Everything is an identifier, a hash, a port or an interface name:

- Artefacts, destination sets and policies are referenced as
  `{ id, sha256 }` — **never** as a path. The helper resolves the identifier
  against storage it owns and verifies the content hash, so the control plane
  cannot tell the helper *where* to read from.
- There is no field for a command line, an executable, an environment
  variable, a raw filesystem path, an nftables rule text or a secret value.

### Why traversal and shell text are not representable

Identifiers use `^[A-Za-z0-9][A-Za-z0-9_-]*$`, interface names
`^[A-Za-z0-9][A-Za-z0-9_.-]*$` bounded to 15 characters (the Linux
`IFNAMSIZ` limit). Neither admits `.` or `/` in a leading position, a path
separator, whitespace, `;`, `$`, backticks or parentheses.

This matters for the review: `../../etc/passwd`, `/usr/bin/xray`,
`gen-0001; rm -rf /`, `gen-0001$(id)` and `$HOME` are not merely *rejected* by
a rule — they are **not expressible** in the schema. The contract's "запрет
traversal/symlink escape" is therefore enforced at the type level for the
request, and the residual risk moves to identifier *resolution* at runtime,
which the schema cannot cover (see [Not promised](#not-promised-by-this-schema)).

### Save ≠ apply, and StopGuarded ≠ ReleaseProtection

Both separations are structural rather than advisory:

- **StopGuarded** carries an empty payload (`maxProperties: 0`). It cannot
  carry a confirmation token, a target generation or a release instruction.
  Stopping therefore cannot remove protection by construction.
- **ReleaseProtection** is the only command that can remove protection, and it
  requires both `protectedGenerationId` and a `confirmationToken`. The control
  plane binds that token to the session, the active generation and the current
  protection state; the helper checks the binding and the one-time use.

`RestoreGeneration` is a **rollback to a previous generation of the network
configuration**, not a restore of a backup archive. It carries no backup
envelope, no passphrase and no secret material.

### Generation binding

`EngageGuard` and `ActivateGeneration` both carry `manifestHash`, so the
guard and the switch are bound to exactly the manifest that was validated. A
manifest hash that does not match the prepared or guarded generation is a
rejection, not a partial switch.

## Not promised by this schema

These are runtime obligations of the helper and the control plane. The schema
constrains the request; it does not implement any of them, and no reader
should treat a schema-valid request as an authorised or safe one.

| Concern | Why the schema cannot cover it |
|---|---|
| Peer credentials | Unix socket credential checking is a transport property. The schema has no notion of who sent the request. |
| Socket path, permissions, group separation | Deployment concern, not request shape. |
| Symlink escape | The schema forbids expressing a path at all, but the helper's own storage may contain symlinks. Resolving them safely is the helper's job. |
| Generation replay protection | `expectedGeneration` is an expectation, not an atomic compare-and-swap. The helper must serialise operations and compare state itself. |
| Idempotency enforcement | `operationId` + `payloadHash` define the key. Detecting a replay and refusing a same-id/different-payload reuse is runtime behaviour. |
| Confirmation-token validity and one-time use | The schema only requires a token-shaped value of sufficient length. Binding and single use are checked by the helper. |
| Allowed interface / port allowlists | The schema bounds the *shape*; which interfaces and ports are approved is environment knowledge the helper holds. |
| IPv6 profile proof | `ipv6TProxyEnabled` records intent only. A schema-valid `true` is not evidence that an IPv6 profile is proven; the helper must reject an unproven enable and must never apply it partially. |
| `payloadHash` correctness | The canonical serialisation that the hash covers is **not yet fixed** by the contracts. See [Open items](#open-items). |

## Bounds and their rationale

All bounds are **technical proposals for review by agent 03**, not accepted
product defaults, and not user-facing configuration.

| Bound | Value | Rationale |
|---|---|---|
| `listenerPorts` | ≤ 32 items, unique, 1–65535 | A generation needs a handful of listeners; the cap bounds the nft batch and the manifest size. Port 0 is excluded because it means "any port" and is never a real listener. |
| `approvedInterfaces` | ≤ 16 items, unique | One NIC is the baseline target; the cap leaves room without allowing an unbounded interface set into a kernel transaction. |
| `destinationSets` / `policyRefs` | ≤ 512 items each | Large enough for real rule sets, small enough to keep the manifest bounded. The plan's own baseline mentions 1000 nodes / 10 sources, so these are not silently restrictive for the stated baseline. |
| `engineArtifacts` / `dnsArtifacts` | ≤ 16 items each | The generation needs one engine and one DNS artefact set, not an arbitrary supply chain. |
| `interfaceName` length | ≤ 15 | Linux `IFNAMSIZ` limit; a longer name cannot exist, so accepting it would mean accepting an unsatisfiable request. |
| `identifier` length | ≤ 64 | Bounded key size for helper-side storage references. |
| `confirmationToken` length | 32–512 | Wide enough for a random token, bounded so the field cannot carry a document. |
| `sha256` | exactly 64 lowercase hex | The contract names SHA-256 explicitly; uppercase is rejected so the digest has one canonical form. |
| `operationId` | UUID v4, lowercase | RFC 4122 v4 via an explicit pattern, because `format` is annotation-only in most validators and would not reject a malformed value. |

## Negative vectors covered

The offline corpus exercises 53 cases — 9 positive (one per command) and 44
negative. The negative set covers the vectors the task named:

| Vector | Cases |
|---|---|
| Unknown command | `ExecuteShell` |
| Unknown keys | extra envelope key, extra payload key, extra manifest key (`rawNftRules`) |
| Missing required fields | envelope field, manifest field, manifest itself, release confirmation, release generation |
| Oversized bounds | 33 ports, 17 interfaces, 513 destination sets, 513 policy refs, 17 engine artefacts, 16-character interface name |
| Malformed hashes / IDs | `NOTAHASH`, 62-hex hash, uppercase hash, non-UUID operation id, non-v4 UUID, uppercase UUID, artefact or set missing its hash |
| Wrong payload variant | extra key in a variant, variant of a different command, payload on `Inspect`, missing manifest on `ValidateManifest` |
| Traversal / unapproved strings | `../../etc/passwd`, `/usr/bin/xray`, `; rm -rf /`, `$(id)`, `$HOME`, `eth0/../../tmp`, `eth 0` |
| Release generation binding | release without confirmation token, short token, token containing whitespace, release without generation id, malformed manifest hash on activate, restore without target |
| Type errors | non-integer generation, string IPv6 flag, negative and zero and >65535 ports, duplicate ports |

## Checks

All checks are offline. No network request, no download, no install, no
product execution, no system probe, no namespace, no privilege.

The validator used is the one already installed on this machine:
`jsonschema` 4.10.3 (`/usr/lib/python3/dist-packages/jsonschema`), used through
both its Python API (`Draft202012Validator`) and its CLI (`jsonschema -V
Draft202012Validator`). The CLI's `-V` argument needs the full class name —
`draft202012` is not a registered alias in this version and raises
`AttributeError`.

| Check | Result | Command |
|---|---|---|
| Schema is a valid Draft 2020-12 schema | PASS | `Draft202012Validator.check_schema(...)` → exit 0 |
| `contracts/helper.schema.json` parses as JSON | PASS | `python3 -c "import json; json.load(...)"` → exit 0 |
| Contract corpus via the Python validator API | PASS | `check_helper_schema.py` → 53 cases, 0 failures, exit 0 |
| Contract corpus via the `jsonschema` CLI (independent path) | PASS | 53 cases, 0 mismatches |
| Every command has one positive case | PASS | 9 positive cases, one per command |
| Envelope is closed | PASS | `additionalProperties: false` at envelope level |
| Payload variants are closed | PASS | `additionalProperties: false` in every variant |
| No path/exec/env/secret field exists | PASS | no such property name in the schema |

Artefacts of the corpus live in the ignored scratch directory
`.hyper/tmp/buj/t005/` (generator, checker, generated cases, one JSON file
per case). They are deliberately **not** committed: they are test scaffolding
for this task, and the task's allowed files are the schema and this document.

## Open items — not decided here

These are recorded rather than invented. Each blocks a part of T005 or a
later task.

1. **Canonical serialisation for `payloadHash`.** The contract requires the
   idempotency key `operationId` + `payloadHash`, but does not define the
   serialisation the hash is taken over (JSON with sorted keys? canonical
   form? over the payload object only?). Until this is fixed, two
   implementations can compute different hashes for the same request, and
   idempotency cannot be tested. **Blocks** the idempotency contract check in
   T005's own test set.
2. **Approved-interface and port allowlists.** The schema can bound the shape
   but not express "these are the approved interfaces of this machine".
   The helper's allowlist is environment knowledge.
3. **IPv6 profile proof.** FR-020 and the helper contract both require that an
   IPv6 TProxy enable is refused unless the profile is proven. The schema
   carries the intent flag only; the proof is a runtime and stand-level
   matter, still **NOT_RUN** (G2).
4. **Backup A/B and retention/GC.** A04 explicitly leaves backup-live schema
   and GC **BLOCKED**, and this schema does not touch them. `RestoreGeneration`
   here is a network-generation rollback and must not be read as a backup
   restore.
5. **Control-plane OpenAPI schema.** `contracts/openapi.yaml` is the other
   half of T005 and is **not delivered here**.
6. **Marker/table allocation.** The helper contract requires unique
   mark/table allocation checked at preflight rather than copying 999/255 by
   chance. That is a runtime allocation rule; it is not representable as a
   request field and is not encoded.
7. **Error taxonomy.** The control-plane contract defines `{code, message,
   fieldErrors?, requestId}` for the API. The corresponding helper-side error
   taxonomy is not fixed by any contract and is **not** invented here.

## What agent 03 should check

- No arbitrary shell, executable, environment, command text or raw path can be
  expressed in any payload — including through identifier-like fields.
- No secret value can be expressed in any payload.
- The nine commands match the helper contract exactly, and no command permits
  saving or applying configuration.
- `StopGuarded` cannot remove protection, and `ReleaseProtection` requires a
  bound confirmation.
- The proposed bounds in [Bounds and their rationale](#bounds-and-their-rationale)
  are reasonable, and the two open items that block correctness (canonical
  serialisation, allowlists) are correctly marked as open rather than papered
  over.

## Next

- Agent 03 reviews this document and the schema.
- Agent 04 runs independent offline contract checks.
- The control-plane half of T005 (`contracts/openapi.yaml`) remains to be
  written under its own task packet.
