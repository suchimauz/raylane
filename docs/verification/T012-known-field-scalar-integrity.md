# v4-US1-T012-known-field-scalar-integrity — scoped verification note

Status: focused correction COMPLETE. Forward off base 4abc949 (prior label
assignment accepted scoped; not restarted). Closes known-field scalar
integrity; parent tasks T010/T011/T012/T013/US1/Foundation remain OPEN.

## The corrected defect

After existing JSON syntax acceptance, a non-scalar string/key anywhere in the
protocol/fields (at any nesting depth, as a value or an object key) must save
as a NON-CANONICAL SEMANTIC envelope: actual `ErrNotANodeEnvelope` /
`ValidationInvalid` / `Result.Invalid` / `Applicable=false`, the ONE existing
static `malformedEnvelope@envelope` issue, the EXACT original bytes sealed, and
BOTH derived maps empty. A lossy `Valid` must never be certified, and a
malformed payload must never be re-labelled a syntax/component zero-write.

## Root cause

Go's `encoding/json` decoder — including raw `Token()` mode — lossily maps an
invalid `\uXXXX` escape (a lone/­mis-ordered surrogate) and invalid raw UTF-8
to U+FFFD. So a decoded token string cannot reveal that the source was
malformed; checking the decoded string certifies a lossy `Valid` and launders
the replacement into the derived doc.

## The fix (additive, dependency-neutral)

Added a RAW lexical string-content scan `jsonscan.StringScalar(raw []byte)`
that walks the wire bytes directly (not the lossy decoder), validating every
JSON string token — value or object key at any depth — for: valid UTF-8,
well-formed `\uXXXX`, valid high+low surrogate PAIRING, recognized two-char
escapes, and no raw control byte. It returns a new typed `ErrNonScalar`
(content-free). Existing `UniqueKeys` / `FullValue` keep their EXACT
structural contracts and all existing callers are unchanged; `StringScalar` is
a separate, additive capability (no new dependency/framework/AST analyzer).

Wiring (scoped to the node adapter + store derivation/protocol guards ONLY;
profile parser / result codec / config / other consumers untouched):
- `internal/domain/nodes/adapter.go`: after the syntax gate and the duplicate
  scan, a non-scalar envelope is rejected via the existing
  `envelopeRejected(doc, IssueMalformedEnvelope)` → `ErrNotANodeEnvelope`,
  exact raw preserved.
- `internal/store/node_compose.go`:
  - `canonicalDerivedBuckets` returns ok=false when `StringScalar(fields)` is
    non-nil → BOTH derived maps stay EMPTY (no U+FFFD laundering), even with
    unrelated known values present.
  - `decodeProtocolString` retains the protocol ONLY when its own raw token is
    scalar — a non-scalar protocol is never kept, but a KNOWN protocol on a
    fields-non-scalar envelope is independently scalar-safe and stays.
- The typed-label private scan (`validJSONStringContent`/`hexQuad`) is left
  intact (accepted label behavior + static refusal preserved); no second
  divergent UTF16 rule is introduced — both use the same jsonscan capability.

## Verified (author; independent acceptance controls closure)

- TDD semantic RED on immutable 4abc949 (real `ValidateDocument` +
  `CreateNodeAtomic`, compiles, secure 0755 ancestry → NOT SETUPERROR): all 11
  oracle cases failed (lossy `Valid`, no `malformedEnvelope`, derived maps
  non-empty). GREEN after the fix: all 11 pass.
- All four parent oracles (`bui_saveability` / `bui_secure_draft` /
  `bui_object_compatibility` / `bui_label_unicode`) PASS; the frozen
  functional oracle `TestBuiScalarEnvelopeNoncanonical` (11 cases, full
  7-table CONTENT survivor + exact-preservation + cold-keyless, not counts)
  PASSES against the corrected source.
- Full gates: affected + race (no DATA RACE) + full-Go 11 ok + build + vet +
  contracts validator + selftest(34) + gofmt + diff-check all rc=0.

## Changes (bounded; NO HTTP/API/profile/schema/migration/v1/crypto/keytrust/strictreadguard/network/UI/compilerapply)

- internal/jsonscan/scan.go: `ErrNonScalar` + `StringScalar` + raw-byte
  helpers (`scanRawValue`/`scanRawString`/`skipWS`/`isWS`/`stringScalar`/
  `hexQuad`). Additive; `UniqueKeys`/`FullValue` contracts unchanged.
- internal/domain/nodes/adapter.go: scalar-integrity canonicality gate.
- internal/store/node_compose.go: scalar-aware `canonicalDerivedBuckets` +
  `decodeProtocolString`; `stringScalarJSON` helper.

## Controls preserved (no behavior change)

Legal literal U+FFFD, escaped `\ufffd`, a valid surrogate pair, BMP, an escaped
backslash (`\\ud800`), ordinary escapes, legal unknown protocol strings,
duplicate-key semantics, and extreme `UseNumber` number spellings all keep
their prior outcomes. Ordinary non-scalar-free semantic invalid/inactive/
unknown drafts retain prior domain semantics; the legal unknown bucket still
quarantines Invalid without this malformedEnvelope gate. Existing cold-keyless
`ReadNodeSafe`, strict persisted codec, authority digest, owner/purpose AAD,
keytrust, and current-presence guards are UNCHANGED; no retroactive row
cleanup/revalidation; no read-guard relaxation.
