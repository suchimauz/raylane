# v4-US1-T012 atomic saveable secure draft repair — scoped verification note

Status: five coherent pre-HTTP storage security/faithfulness repairs COMPLETE
(domain/store increment). NOT HTTP/API/profile/version/migration/strict-codec-
guard/key-rotation/compiler/apply/network/full-parent-closure. Parent tasks
T010/T011/T012/T013/US1/Foundation remain OPEN until their separate criteria are
met. Prior accepted 7417c9e + bde816a receipts are preserved historical
evidence, not retro-deleted/relabelled.

## The five repaired findings (FR-009/FR-019 + D1, faithful atomic persistence)

1. V4-T012-ATOMIC-DERIVED-PLAINTEXT-PERSISTENCE (SECURITY): the derived
   nodes.doc no longer copies the raw active/inactive maps. `buildDerivedDoc`
   now reuses the SAME closed authority projection (`ProjectNodeFields`) over
   the canonical decoded buckets, so only allowlisted safe known scalars (or
   fixed value-free metadata) persist in plaintext. Smuggled plaintext secret
   fields, undeclared names, unknown-bucket values, and opaque-object private
   leaves NEVER reach nodes.doc. An EXISTING ACTIVE known object renders as a
   FIXED name-only marker (`{}`) — the historical fact that it was present,
   never its nested content, never promoted from inactive. Unknown protocol /
   malformed / duplicate / colliding envelopes keep EMPTY derived maps +
   empty-or-known protocol (raw protocol never persisted outside ciphertext).

2. V4-T012-ATOMIC-SENTINEL-VALUE-ACCEPTED: a `replace` whose VALUE equals the
   reserved sentinel `__RAYLANE_SECRET_UNCHANGED_V1__` exactly is refused with
   the static `ErrSecretOp` (zero writes across all seven managed tables). The
   check is by EXACT VALUE equality (OpenAPI `not: {const: ...}`), never a
   substring/pattern match, so mask-like and other non-exact strings stay
   legitimate values. Complements the existing FIELD/purpose guard.

3. V4-T012-ATOMIC-SAVEABLE-NUMBER-GATE: the fields component gate is now
   STRUCTURAL/raw (`map[string]json.RawMessage`, non-nil) with NO float64
   conversion. Huge canonical numbers (1E400, very large integers, tiny
   1e-400, long fractions) reach the actual validator, which owns the faithful
   semantic verdict, instead of being refused before it. Null / non-object /
   malformed / trailing remain a static zero-write refusal. Exact original
   component bytes are sealed unchanged (no float loss, no reserialization).

4. V4-T012-ATOMIC-SEMANTIC-ENVELOPE-ABORT: a syntactically valid but
   non-canonical envelope (inner duplicate keys at any level, ambiguous
   buckets) is a SEMANTIC refusal, not a syntax error. The store now accepts
   ONLY `errors.Is(err, nodes.ErrNotANodeEnvelope)` with its faithful actual
   preserved Invalid/notApplicable AdapterResult and SAVES the draft (exact
   original bytes sealed; ambiguous derived maps empty so nothing is
   laundered; known protocol preserved for cold-read typed-secret ownership /
   presence). All other adapter errors (incl. malformed syntax / trailing)
   still refuse with zero writes. No generic ignore-error, invented result, or
   revalidation of sanitized fields.

5. V4-T012-ATOMIC-EMPTY-LABEL-REFUSED: the optional label has maxLength 256
   and NO minLength, so the empty string is accepted EXACTLY. Absence (nil) and
   explicit JSON null stay distinguishable: null / non-string / >256 runes are
   a static zero-write refusal. The null token is detected explicitly so it is
   not silently coerced by a string unmarshal.

## Verification performed (author; independent acceptance controls closure)

- TDD semantic RED on an immutable snapshot of the accepted base bde816a (real
  product APIs, compiles, secure 0755 .hyper/.hyper/tmp ancestry): all five
  failed for the exact parent-stated reason (plaintext leak / sentinel accepted
  / float-gate refusal / envelope abort / empty-label refusal) — NOT a
  SETUPERROR.
- GREEN after the five repairs: all five pass, plus the FULL store suite
  (atomic A1-A7, B1-B3 cold reads, mux-vision store integration, opaque-object
  name-only Unsupported) and every affected package.
- Full gates: affected + race (no DATA RACE) + full-Go 11 ok + build + vet +
  contracts validator + selftest(34) + gofmt + diff-check all rc=0.
- Preserved: sealed-original-bytes, whole-history (cold read does not recompute
  the historical verdict), current-presence, rollback, and all prior
  guards (strict decoder, direct target-protocol secret-name lookup, four-
  protocol shared-secret-name, real v4→v5 upgrade rollback).

## Changes (bounded; NO contract/profile/OpenAPI/deps/migration/crypto/keytrust)

- internal/store/node_compose.go: structural fields gate (no float64); label
  empty-accept + null-refuse; sentinel exact-VALUE refuse; ErrNotANodeEnvelope
  SAVE; projection-derived safe nodes.doc with fixed {} name-only object
  markers; safeProjectionDecoded surfaces active-object markers as Unsupported.
- internal/capability/projection.go: object fields render name-only Unsupported
  for a real submitted object or a persisted fixed {} marker, never a value.
- NEW internal/store/node_repair_test.go: five maintained-behavior tests.

## Honest limits / NOT_RUN

No HTTP/API/profile/version/migration/strict-codec-guard/key-rotation/compiler/
apply/network change. Engine/handshake/readiness remains a SEPARATE named OPEN
concern. Zero/absent engine branches remain source-backed against pinned
1b1647cd, not re-executed. Future HTTP routes remain absent.
