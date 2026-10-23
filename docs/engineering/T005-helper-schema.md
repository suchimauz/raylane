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

Review status: agent 03 reviewed the schema at `6f10cce` and returned
**PASS-schema** with no blockers, accepting the helper half of T005 as a
partial acceptance and adding four open items plus two format proposals. Those
additions and proposals are incorporated below.

> **UPDATE — helper schema extended (D2, D6).** The schema now carries two
> additional closed commands beyond the original nine: `StageArtifact` (D2,
> bounded inline artefact byte delivery on the existing authenticated socket —
> closes open item 8 at the contract level) and `RegisterReleaseConfirmation`
> (D6, helper-issued single-use release confirmation with a bounded pending
> registration). The `payloadHash` canonical serialisation remains RFC 8785
> payload-only UTF-8 SHA-256 with duplicate-key rejection; the vetted-library
> conformance evidence is still outstanding (separate authorization, D8). The
> open items and status table below describe the pre-batch state and are
> retained as history; authoritative rationale is in
> `docs/engineering/foundation-decisions.md`.

## Status

| Part | State |
|---|---|
| `contracts/helper.schema.json` | Delivered; reviewed by agent 03 (PASS-schema) and offline-checked. |
| `contracts/openapi.yaml` (control-plane API) | **NOT delivered.** Out of the scope of this task packet, which named only the helper schema. |
| Helper implementation | Not started, and not in scope here. |
| Runtime behaviour of any command | **NOT_RUN.** The schema was never sent to a helper; no socket exists. |
| Delivery of artefact content into helper-owned storage | **NOT defined** — see [open item 8](#open-items--not-decided-here). |

T005 is **not** fully done and is **not** claimed as done. The remaining part
of the task (the control-plane OpenAPI schema) and the independent runtime
checks are outstanding.

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

## Canonical payload serialisation — technical proposal for protocolVersion 1

**Status: RECOMMENDED proposal, pending review.** This section answers open
item 1. It is a technical proposal at the same level of strictness as the
schema itself; it is not an accepted product decision and not a user-facing
setting.

### Definition

For `protocolVersion` 1, `payloadHash` is defined as:

```
payloadHash = lowercase_hex( SHA-256( UTF8( JCS( payload ) ) ) )
```

where `JCS` is the JSON Canonicalization Scheme of **RFC 8785**, applied to
the **`payload` object only** — never to the envelope, never to the
`payloadHash` field itself, and never to any sibling field.

Required accompanying rules:

1. **Duplicate keys are rejected at JSON-parse time, before hashing.** A
   request whose `payload` contains a duplicate member name is rejected, not
   normalised. RFC 8785 and I-JSON both require this, and it is what stops two
   different byte strings from hashing to the same digest.
2. **The hash covers the payload only.** The envelope fields
   (`operationId`, `expectedGeneration`, `command`, `protocolVersion`) are
   outside the hash. `operationId` and `payloadHash` together form the
   idempotency key, per the helper contract.
3. **I-JSON conformance.** The payload must be I-JSON: no duplicate member
   names, and every number must be a finite IEEE 754 double or an integer
   that a double represents exactly — no NaN, no Infinity, and no integer
   outside the safe range. I-JSON constrains the *value* of a number, not
   its lexical spelling: `1` and `1.0` are both I-JSON-valid and denote the
   same number.
4. **UTF-8 encoding.** The canonical form is serialised as UTF-8. Non-ASCII
   characters are emitted literally, not `\u`-escaped (RFC 8785 requires this;
   it is the opposite of the `ensure_ascii=True` default in many JSON
   libraries).
5. **Any change to this definition is a `protocolVersion` bump.** A silent
   change of serialisation, hashing algorithm or covered region would break
   idempotency across mixed-version deployments, so it is forbidden.

### Why this is tractable for the current payload type

The payload type is deliberately narrow, and that is what makes the
canonicalisation easy rather than delicate. Measured over the schema's
payload variants, the reachable value types are: regex-bounded strings,
booleans, arrays, objects with fixed ASCII member names, and exactly **one**
numeric *field* — `listenerPorts` items, `integer` with `minimum: 1` and
`maximum: 65535` (it occurs in two payload variants, `ValidateManifest` and
`PrepareGeneration`, but it is one field with one bounded range). There are
**no** float-typed or `number`-typed fields anywhere inside the payload, so
the hard part of RFC 8785 — the ECMAScript number-formatting rules for
doubles, exponents and `-0` — never applies to this type.

The **string values** are constrained as well, not only the member names.
Every string-typed field in the payload is bounded by a pattern whose
character class is printable ASCII:

| Field | Pattern |
|---|---|
| `sha256` | `^[0-9a-f]{64}$` |
| `confirmationToken` | `^[A-Za-z0-9._~+/=-]+$` |
| `identifier` (and `generationId`, `artifactId`, `setId`, `policyId`, …) | `^[A-Za-z0-9][A-Za-z0-9_-]*$` |
| `interfaceName` | `^[A-Za-z0-9][A-Za-z0-9_.-]*$` |

No other string field exists in the payload. Because these classes exclude
every non-ASCII code point, the JCS string-escaping corners — `\u` escapes,
surrogate pairs, non-BMP characters — **cannot arise** in a payload value.
The member names are ASCII literals fixed by the schema, so the UTF-16
code-unit ordering that JCS specifies does not need to be emulated either.

**This is an equivalence argument, not a conformance claim.** It says that
for *this* payload type a local approximation happens to agree with RFC 8785,
because the cases where the two could differ are excluded by construction.
It does **not** mean the approximation satisfies RFC 8785 in general, and it
does not make any implementation conformant. Conformance requires a
**vetted RFC 8785 library** together with the **RFC 8785 test vectors** —
neither is installed here, and installing them is outside this task. See
[Open tooling gap](#open-tooling-gap).

### Numeric corner: the one number that is *not* covered by the hash

`expectedGeneration` lives in the **envelope**, so it is **not** covered by
`payloadHash`. It is therefore the only place where a numeric corner can
reach the helper, and it needs its own rule.

In JSON Schema, `"type": "integer"` means *a number with zero fractional
part*; it is **not** a bounded machine integer and does **not** imply a
64-bit range. Before this correction the schema bounded `expectedGeneration`
only from below (`minimum: 0`), and the installed validator accepted values
of `2^53`, `2^53 + 1`, `2^63`, `2^64` and `10^30`.

That matters because a JSON parser in a double-precision runtime silently
rounds such values: parsing `9007199254740993` (`2^53 + 1`) through a
double-precision `JSON.parse` yields `9007199254740992` (`2^53`). Two
implementations could therefore disagree about the generation number of the
same request while both accepted it as schema-valid.

**Applied rule for `protocolVersion` 1:** `expectedGeneration` is bounded to
`[0, 9007199254740991]` — the JSON safe-integer range — by
`"maximum": 9007199254740991` in the schema. Within that range every
conforming JSON parser represents the value exactly, so the comparison the
helper performs is well-defined.

**On the two spellings of the same integer.** `1` and `1.0` are **both**
valid against the schema and **both** valid under I-JSON: I-JSON constrains
the *range* of a number, not how it is spelled, and a value with zero
fractional part is an integer regardless of its lexical form. Under RFC 8785
both canonicalise to `1`, so they produce the **same** `payloadHash`. There
is therefore no reason to reject a fractional *spelling* of an integer, and
this document does not propose one. If an implementation wanted to
canonicalise the lexical form itself, that would be a **transport-decoder**
rule of its own — not a schema rule, not an I-JSON rule, and not required
for correctness. Within the safe range, `1` and `1.0` also parse to the same
value in any conforming parser, so `expectedGeneration` is unaffected either
way.

The schema bound above is now **applied**, not merely proposed. The
remaining numeric open item is closed at the schema level; see
[open item 9](#open-items--not-decided-here).

### Negative vectors for the canonicalisation

These belong in the contract test set once the proposal is accepted:

| Vector | Expected outcome |
|---|---|
| Same payload, member names in a different order | Identical `payloadHash` — canonicalisation is order-independent. |
| Same payload, different whitespace between tokens | Identical `payloadHash`. |
| Same payload, `\uXXXX`-escaped vs literal non-ASCII | Identical `payloadHash` — UTF-8 output is literal, not escaped. In the current payload type this vector is not reachable: every string value is constrained to printable ASCII, so no non-ASCII value can occur. |
| Same payload, an ASCII character written as a `\uXXXX` escape rather than literally | Identical `payloadHash`. The escape is a *transport* representation: after parsing, a literal `A` and the escape sequence `\u0041` denote the same character, so the parsed values are equal and the canonical form is the same. This holds for the ASCII range **as well as** for non-ASCII characters — the difference is that an ASCII character has a literal form in the canonical output, while a non-ASCII one does not. It is not a case of "the escape is preserved": the escape is resolved before the hash is computed. |
| `1` vs `1.0` in an integer-valued position | Both are schema-valid and I-JSON-valid; JCS canonicalises both to `1`, so the `payloadHash` is identical. No rejection on lexical form is required. |
| Duplicate member name in `payload` | Rejected before hashing, at parse time. |
| `expectedGeneration` at `2^53`, `2^53 + 1`, `2^63`, `10^30` | Rejected — outside the schema's safe-integer bound. |
| `expectedGeneration` written as `7.0` | Accepted — a valid I-JSON and schema spelling of the integer 7; it denotes the same generation as `7`. |
| Same `operationId` with a different `payloadHash` | Rejected — the helper contract's "same ID, different payload is rejected". |
| Same `operationId` and same `payloadHash`, sent again | A **replay**, not a second application: the helper returns the original outcome and does not re-apply. |

### Open tooling gap

No RFC 8785 implementation is installed on this machine: neither a `jcs` nor
an `rfc8785` Python package is present, and no JCS library was found in the
local Bun or Go module caches. The canonicalisation could therefore be
**approximated** offline with `json.dumps(payload, sort_keys=True,
separators=(",", ":"), ensure_ascii=False)`, which is equivalent for this
payload type, but that approximation is **not** a conformance check against
RFC 8785 and was not used as one.

The prerequisite for the idempotency contract check is therefore:

1. a **vetted RFC 8785 library** — for example a maintained Go
   implementation, a Node package, or a Python package, chosen on its
   maintenance and correctness record rather than installed opportunistically;
2. the **RFC 8785 test vectors**, run against that library, as the
   conformance evidence.

Neither is selected or installed by this task, and nothing was downloaded.
Until both exist, the idempotency contract check and any JCS conformance
claim remain **NOT_RUN**.

### Alternative to the UUIDv4 restriction

`operationId` is currently constrained to UUID v4 (lowercase). The helper
contract only requires a unique identifier, so the v4 restriction is a
**protocol proposal**, not a product requirement.

A time-sortable UUID v7 would remain compatible. Its millisecond timestamp
would be a **diagnostic aid** for correlating logs and operations in
rough order — and nothing more:

- it is **not** a proof of operation order. A timestamp is not a total
  order: the clock can be skewed, and two operations can share a
  millisecond;
- it is **not** an authorisation mechanism;
- it is **not** a generation guarantee. That is the job of
  `expectedGeneration` together with `manifestHash`, which bind a request to
  a specific state and a specific manifest.

The schema currently uses v4 and is **unchanged** by that observation;
switching to v7 would be a `protocolVersion` bump plus a schema revision, and
the choice is a protocol decision rather than a product one.

## Error taxonomy — technical proposal

**Status: proposal, pending review.** This answers open item 7.

The control-plane contract fixes `{code, message, fieldErrors?, requestId}` for
the HTTP API. A Unix socket has no HTTP status codes, and **no transport
contract for the helper socket exists yet**, so it would be wrong to promise
HTTP status numbers here. What can be proposed is the *shape* of a helper
error and the *meaning* of its codes.

Proposed response shapes, mirroring the control-plane separation of outcomes
from states:

```
success: { helperOperationId, state? }
failure: { code, message, fieldErrors?, helperOperationId, state? }
```

`helperOperationId` echoes the request's `operationId` so a failure can be
correlated with the operation that caused it. `state` is **separate from**
`code`: a response can carry an error code *and* a state, and the state
describes where the helper stands, not what went wrong.

Proposed error codes, mirroring the control-plane taxonomy where an
equivalent exists:

| Code | Meaning | Control-plane analogue |
|---|---|---|
| `INVALID_REQUEST` | The envelope is malformed or unparsable. | 400 |
| `SCHEMA_VIOLATION` | The request is well-formed but violates the schema or a capability profile. | 422 |
| `STATE_CONFLICT` | `expectedGeneration` does not match the helper's state. | 409 |
| `LIMIT_EXCEEDED` | A declared bound was exceeded. | 413 |
| `CONFIRMATION_INVALID` | The release confirmation is absent, malformed, not bound to this state, or already consumed. | 403 |
| `ARTIFACT_HASH_MISMATCH` | A referenced artefact's content hash does not match. | — (helper-specific) |
| `INTERFACE_NOT_APPROVED` | A requested interface is not in the helper's allowlist. | — (helper-specific) |
| `IPV6_PROFILE_UNPROVEN` | An IPv6 TProxy enable was requested without a proven profile. | — (422-class) |
| `SYSTEM_PROCESS_ERROR` | A system process (nftables or another invoked binary) failed or reported an error. | — (helper-specific) |
| `ROLLBACK_FAILED` | A `RestoreGeneration` did not succeed; the helper is degraded-guarded. | — (helper-specific) |

Two points of separation matter and are stated explicitly:

- **A degraded state is not an error code.** `DEGRADED_GUARDED` is a
  *state*, reported in the response's `state` field, not one of the error
  codes. A failed rollback reports `ROLLBACK_FAILED` **and**
  `state: degraded-guarded` together. The state is never reported as a
  completed operation, and a rollback that did not happen is never reported
  as a successful restore — the emergency state and the preserved protection
  against direct bypass are what the caller must see (FR-021).
- **System-process failures are not swallowed.** `SYSTEM_PROCESS_ERROR` is
  its own code, never folded into a generic success path — the helper
  contract requires that nftables and system-process errors are not masked as
  success. The `message` is **redacted**: it states what failed and in which
  phase, without carrying raw command output, paths or secret material into
  anything that leaves the helper (FR-019).

The proposed `state` values are the ones the control-plane contract already
names: `prepared`, `guarded`, `active`, `stopped-guarded`, `degraded-guarded`.

**No HTTP status codes are introduced.** A Unix socket has no status codes,
and **no transport contract for the helper socket exists yet**, so promising
HTTP semantics here would be wrong. The code names above mirror the
control-plane taxonomy for *consistency of meaning*; they are not status
numbers and imply no transport mapping. The concrete response format, the
transport that carries it and the code set are an **approved technical
draft** to be settled before any future schema or implementation work — see
[open item 7](#open-items--not-decided-here). Nothing here is claimed as
agreed.

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
| Confirmation-token handling in full | The token is **opaque**: it must never be interpreted as a path, never be interpolated into a SQL statement, and never be written to a log. It is compared in constant time by the helper. The schema can constrain its character set; it cannot enforce any of that. |
| Allowed interface / port allowlists | The schema bounds the *shape*; which interfaces and ports are approved is environment knowledge the helper holds. |
| IPv6 profile proof | `ipv6TProxyEnabled` records intent only. A schema-valid `true` is not evidence that an IPv6 profile is proven; the helper must reject an unproven enable and must never apply it partially. |
| `payloadHash` correctness | The canonical serialisation that the hash covers is **not yet fixed** by the contracts. See the [canonical payload serialisation proposal](#canonical-payload-serialisation--technical-proposal-for-protocolversion-1) and [open item 1](#open-items--not-decided-here). |

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
| `expectedGeneration` | `[0, 9007199254740991]` (**applied in the schema**) | The JSON safe-integer range, so every conforming JSON parser represents the value exactly and the helper's generation comparison is well-defined. JSON Schema's `integer` does not imply this on its own — see [Numeric corner](#numeric-corner-the-one-number-that-is-not-covered-by-the-hash). |

A note on the `operationId` restriction: it is a **protocol proposal**, not a
product requirement. The helper contract only asks for a unique identifier, so
a time-sortable UUID v7 would remain compatible; see
[Alternative to the UUIDv4 restriction](#alternative-to-the-uuidv4-restriction).

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
| Numeric types reachable inside payload | PASS | resolved `$ref`s: only `listenerPorts` items are numeric (`integer`, 1–65535); **0** float/`number` fields and **0** unbounded integers inside payload |
| String values inside payload are ASCII-constrained | PASS | four string patterns, all character classes printable ASCII; no other string field exists in the payload |
| `expectedGeneration` bound applied | PASS | schema carries `"maximum": 9007199254740991`; boundary vectors 0 / max / max+1 / large / −1 / `1.0` behave as documented |
| `1` and `1.0` are both valid | PASS | both accepted by the installed validator; both are I-JSON-valid; no lexical-form rejection is proposed |
| Double-precision parsing rounds a large integer | PASS (observed) | `JSON.parse("9007199254740993")` yields `9007199254740992` |
| RFC 8785 implementation available locally | **NOT_RUN** | no `jcs` / `rfc8785` Python package, none in the local Bun or Go module caches; the stdlib approximation (`sort_keys=True`, `separators=(",",":")`, `ensure_ascii=False`) is equivalent for this payload type but is **not** a conformance check and was not used as one. Conformance requires a vetted RFC 8785 library plus the RFC test vectors — neither selected nor installed |

Artefacts of the corpus live in the ignored scratch directory
`.hyper/tmp/buj/t005/` (generator, checker, generated cases, one JSON file
per case). They are deliberately **not** committed: they are test scaffolding
for this task, and the task's allowed files are the schema and this document.

## Open items — not decided here

These are recorded rather than invented. Each blocks a part of T005 or a
later task.

1. **Canonical serialisation for `payloadHash`.** The contract requires the
   idempotency key `operationId` + `payloadHash`, but does not define the
   serialisation the hash is taken over. A concrete proposal now exists —
   RFC 8785 (JCS) over the payload object only, UTF-8, SHA-256, lowercase
   hex, with duplicate keys rejected before hashing — see
   [Canonical payload serialisation](#canonical-payload-serialisation--technical-proposal-for-protocolversion-1).
   It is a proposal pending review, and no conforming RFC 8785 implementation
   is installed on this machine, so the idempotency contract check remains
   **NOT_RUN** and **blocks** that part of T005's test set.
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
   taxonomy is not fixed by any contract. A proposal now exists — see
   [Error taxonomy](#error-taxonomy--technical-proposal): a response shape of
   `success {helperOperationId, state?}` /
   `failure {code, message, fieldErrors?, helperOperationId, state?}`, with
   the degraded state kept **separate from** the error codes, `SYSTEM_PROCESS_ERROR`
   and `ROLLBACK_FAILED` named explicitly, and redacted messages. It remains
   a proposal: no HTTP status semantics are promised, and the response
   format and the transport that would carry it are an approved technical
   draft to be settled before any future schema or implementation work.
8. **Delivery of artefact content into helper-owned storage.** The manifest
   references engine artefacts, DNS artefacts and canonical destination sets
   as `{id, sha256}` only. **No command in the schema carries the content of
   any of them**: there is no upload command, no inline-content field, and no
   path by which the bytes reach the helper. Neither the helper contract nor
   the schema defines that channel — the contract mentions only that
   root-owned engine artefacts have minimal permissions.

   This is a real gap, not a presentational one. Until it is defined,
   `PrepareGeneration` and `ValidateManifest` promise the helper will verify
   the content hash of objects whose origin the helper cannot obtain, and
   the helper contract's own "helper verifies the profile and the permitted
   paths and ports" step has nothing to verify against. The schema is honest
   about this — it carries no delivery mechanism and does not pretend to.

   **The delivery architecture is deliberately not chosen here.** It is an
   architectural decision (shared directory with ownership and permission
   rules, a separate content-transfer channel, a content-addressed store, or
   something else) and belongs to the Chief Architect, not to a schema
   follow-up. Until it is decided, the corresponding runtime implementation
   is **blocked**: a helper cannot honestly implement artefact verification
   without a defined source for the bytes.

9. **`expectedGeneration` numeric range — closed at the schema level.** The
   schema's `integer` type does not bound the value, and a double-precision
   JSON parser silently rounds integers beyond `2^53`. The bound
   `[0, 9007199254740991]` is now **applied** in the schema
   (`"maximum": 9007199254740991`), so a request outside the safe-integer
   range is rejected by validation rather than silently reinterpreted. The
   reasoning is in
   [Numeric corner](#numeric-corner-the-one-number-that-is-not-covered-by-the-hash).
   No further schema change is outstanding for this item.
10. **`ipv6TProxyEnabled` — synchronisation done.** The helper contract listed
    the manifest without the IPv6 flag while the schema carried it. A
    synchronisation line has now been added to
    `specs/001-selected-connections/contracts/network-agent.md`: the flag is
    part of the typed manifest, defaults to false, records **intent only**,
    is not proof of a proven IPv6 profile and is not permission to enable
    IPv6 interception. The contract and the schema agree again. The
    underlying requirement — refusing an IPv6 enable without a proven
    profile — is unchanged and remains **NOT_RUN** (G2).

## What agent 03 should check next

The schema at `6f10cce` was reviewed by agent 03 (PASS-schema, no blockers),
and the canonical protocol detail was reviewed separately in
`.hyper/tmp/t005a/T005-protocol-detail-review-REPORT.md`. The corrections
C1–C5 from that review are applied in this commit. What remains for the next
review round:

- The [canonical serialisation](#canonical-payload-serialisation--technical-proposal-for-protocolversion-1):
  RFC 8785 over the payload only, duplicate keys rejected before hashing,
  I-JSON number rules, UTF-8 literal output, and a `protocolVersion` bump on
  any change. The RFC 8785 conformance evidence (a vetted library plus the
  RFC test vectors) is still outstanding — it is **NOT_RUN**.
- The [applied `expectedGeneration` bound](#numeric-corner-the-one-number-that-is-not-covered-by-the-hash):
  `"maximum": 9007199254740991` is now in the schema, and the boundary
  vectors are in the contract corpus.
- The [error taxonomy proposal](#error-taxonomy--technical-proposal): the
  proposed code set with `SYSTEM_PROCESS_ERROR` and `ROLLBACK_FAILED` named,
  the degraded state kept separate from the codes, and no HTTP status
  semantics introduced.
- The [open item 8](#open-items--not-decided-here) wording: that the delivery
  gap is stated as a blocker for the runtime implementation, and that the
  architecture is left to the Chief Architect.
- The [open item 10](#open-items--not-decided-here) note about
  `ipv6TProxyEnabled`: the synchronisation line has now been added to the
  helper contract, so the schema and the contract agree again.

Unchanged from the earlier review rounds, and still to hold: no arbitrary
shell, executable, environment, command text or raw path can be expressed in
any payload; no secret value can be expressed; the nine commands match the
helper contract exactly and no command permits saving or applying
configuration; `StopGuarded` cannot remove protection and `ReleaseProtection`
requires a bound confirmation.

## Next

- Agent 03 reviews this follow-up.
- Agent 04 runs independent offline contract checks; the idempotency checks
  stay **NOT_RUN** until a conforming RFC 8785 implementation exists.
- The control-plane half of T005 (`contracts/openapi.yaml`) remains to be
  written under its own task packet.
- The artefact-delivery architecture (open item 8) needs a Chief Architect
  decision before the corresponding runtime work can start.
