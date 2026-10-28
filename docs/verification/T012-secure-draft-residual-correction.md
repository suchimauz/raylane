# v4-US1-T012 secure-draft residual correction — scoped verification note

Status: forward correction of RETURN 8307e8a COMPLETE. 8307e8a is RETURN,
NOT accepted; last accepted is bde816a. This is ONE coherent functional
correction, not HTTP work or replay. Parent tasks T010/T011/T012/T013/US1/
Foundation remain OPEN until their separate criteria are met.

## The five corrected residuals (FR-009/FR-019 + D1)

1. CROSS-BUCKET COLLISION LAUNDER: a name present in more than one of the
   active/inactive/unknown buckets is ambiguous. `buildDerivedDoc` now excludes
   EVERY cross-bucket colliding name from BOTH derived maps before the authority
   projection (its value never reaches nodes.doc plaintext), while UNRELATED
   safe known fields in the same node are preserved. Covers active+inactive and
   active+unknown (quarantine) collisions.

2. DUPLICATE CANONICAL FIELDS LAST-WINS: a syntactically valid envelope with a
   DUPLICATE canonical key (inside active/inactive/unknown, an escaped-decoded
   duplicate, or a duplicate top-level bucket) is NON-CANONONICAL. The adapter
   yields its faithful `malformedEnvelope` Invalid draft (SAVEABLE), and the
   derived active/inactive maps are now EMPTY — `canonicalDerivedBuckets`
   rejects any duplicate (via the neutral `jsonscan.FullValue` scanner at the
   fields level and inside each bucket object) so last-key-wins never launders
   ambiguity into safe content. Known captured protocol is preserved.

3. LABEL UTF-8 / SURROGATE COERCION: the typed label gate now validates the
   DECODED INNER string BYTES for strict UTF-8 scalar validity. Go's JSON
   decoder lossily replaces invalid UTF-8 (including the CESU-8-style surrogate
   encodings) with U+FFFD, so a decoded-string check alone was insufficient.
   Invalid raw UTF-8 and unpaired/wrong-order surrogate halves are refused with
   zero writes; a legal U+FFFD literal, an escaped `\ufffd`, and a valid
   surrogate PAIR (a real scalar such as U+10000) all remain acceptable — a
   scalar-validity check on the wire bytes, not a blanket replacement-char ban.
   Absence / "" / 256 runes stay accepted exactly; null / non-string / >256 /
   malformed / trailing stay refused inside the store.

4. PROTOCOL NULL COERCION: the protocol component must be an EXPLICIT JSON
   string. A JSON null (previously decoded into the empty string) or any
   non-string is a static zero-write component refusal — never coerced into an
   empty-string protocol that would SAVE. A legal unknown/nonempty JSON STRING
   still flows to the faithful validator (Invalid SAVE), never this shape gate.

5. OBJECT-NAME PROJECTION REGRESSION: restored the exact pre-repair
   (bde816a) `ProjectNodeFields` behavior — a PRESENT declared known-object
   field (any submitted value: {} / null / string / [] / a real object) yields
   exactly one name-only Unsupported fact, never a value, never an assertion it
   was a valid object; an ABSENT object key surfaces nothing. Removed the store
   inactive-marker hack. The store builds a fixed `{}` value-free marker ONLY
   for a projector-Unsupported name originally in ACTIVE and not ambiguous; an
   original INACTIVE object stays omitted (not promoted, no new Unsupported).
   Cold keyless read reproduces the same name-only fact.

## Verified (author; independent acceptance controls closure)

- TDD semantic RED on immutable 8307e8a (real product APIs, compiles, secure
  0755 ancestry -> NOT SETUPERROR): all five failed for the exact parent-stated
  reason. GREEN after the corrections: all five pass.
- Parent independent acceptance suites (bui_secure_draft / bui_saveability /
  bui_object_compatibility / reserved-value / numbers-and-envelopes) all PASS
  against the corrected source (5 suites, rc=0), reproducing the parent's
  oracle exactly.
- Full gates: affected + race (no DATA RACE) + full-Go 11 ok + build + vet +
  contracts validator + selftest(34) + gofmt + diff-check all rc=0.
- Preserved already-improved behavior: exact sentinel-VALUE refusal (zero
  writes), raw structural fields gate (no float64), ErrNotANodeEnvelope SAVE,
  empty-label accept, whole-history cold read, current presence, rollback, and
  all prior guards.

## Changes (bounded; NO registry/profile/API/schema/migration/crypto/strictcodec/keytrust/HTTP/compiler/apply/network)

- internal/store/node_compose.go: cross-bucket collision exclusion; duplicate-
  canonical detection (jsonscan at fields + bucket levels); label inner-byte
  UTF-8 validity; protocol explicit-JSON-string gate; fixed {} object marker
  restricted to unambiguous active projector-Unsupported names; removed the
  inactive-marker hack.
- internal/capability/projection.go: restored unconditional present-object
  name-only Unsupported; removed the empty-object/inactive-flag gate.
- NEW internal/store/node_residual_test.go: five maintained-behavior tests.

## Honest limits / NOT_RUN

Storage security/faithfulness correction only; NOT HTTP/API/profile/version/
migration/strict-codec-guard/key-rotation/compiler/apply/network. Engine/
handshake/readiness remains a SEPARATE named OPEN concern. Zero/absent engine
branches remain source-backed against pinned 1b1647cd, not re-executed.
