# v4-US1-T012-label-scalar-integrity — scoped verification note

Status: focused correction of RETURN f002ccc COMPLETE. Base f002ccc is RETURN
(NOT accepted); last accepted bde816a. Forward off f002ccc, no rewrite. Closes
only typed LABEL scalar integrity; parent tasks T010/T011/T012/T013/US1/
Foundation remain OPEN.

## The corrected defect

The typed store must accept exact legal Unicode label JSON and atomically
refuse malformed Unicode scalar escape sequences BEFORE any write, so a lossy
replacement is never silently accepted as validation.

WHY the previous attempt failed:
- `utf8.Valid(inner)` checks UTF-8 bytes only. ASCII JSON escapes such as
  `"\ud800"` are VALID UTF-8 bytes but encode an UNPAIRED UTF-16 surrogate —
  not a valid scalar — and `encoding/json.Unmarshal` lossily maps them to
  U+FFFD, so checking the decoded Go string cannot recover that the source was
  malformed.
- The maintained test supplied CESU-8 invalid bytes (ed a0 80), not the ASCII
  `\uD800` escape input; its "valid pair" case supplied literal U+10000 UTF-8
  bytes, not a two-escape pair. So the claimed escape branch was never
  exercised.

## The fix (focused, label-scoped)

Added a smallest store-private raw JSON-string-content scan,
`validJSONStringContent`, applied to the typed label component ONLY — BEFORE
the lossy decode — alongside the retained pre-decode `utf8.Valid(inner)` raw
UTF-8 check. It does NOT expand jsonscan or any other path.

The scan enforces, on the inner wire bytes:
- every `\` introduces a recognized two-char escape (`" \ / b f n r t`) or a
  well-formed `\uXXXX` (exactly four hex digits);
- every UTF-16 surrogate escape is PART of a valid high+low PAIR (unpaired or
  wrongly-ordered → invalid scalar → refuse);
- no raw control byte (0x00..0x1F) unescaped.

Accepted (still legal): literal U+FFFD, escaped `\ufffd`, a valid surrogate
pair escape `\ud83d\ude00` (real scalar U+1F600), the escaped-backslash form
`\\ud800` (backslash + "ud800", NOT a surrogate escape), ordinary BMP content,
and absence / "" / 256 runes. Refused with zero writes: `"\ud800"` (lone high),
`"\udc00"` (lone low), `"\ud800\u0041"` (high then non-surrogate),
`"\ud800\ud801"` (two highs), `"\ude00\ud83d"` (reversed), raw invalid UTF-8
bytes, raw control bytes, >256 runes, null/non-string.

## Verified (author; independent acceptance controls closure)

- TDD semantic RED on immutable f002ccc (real product APIs, compiles, secure
  0755 ancestry → NOT SETUPERROR): all five unpaired-escape negatives failed
  ("invalid label accepted / partial outcome; refusal changed seven-table
  content"). GREEN after the fix.
- Frozen parent oracle `bui_label_unicode_test.go` (full 7-table CONTENT
  survivor + exact-preservation + cold-keyless, not counts) PASSES against the
  corrected source (rc=0). Positive U+FFFD / pairs / backslash / 256 / 257
  exact preservation and cold history all pass.
- All other parent suites (bui_secure_draft / saveability / object_compat /
  reserved-value / numbers-and-envelopes) PASS; no other regression.
- Full gates: affected + race (no DATA RACE) + full-Go 11 ok + build + vet +
  contracts validator + selftest(34) + gofmt + diff-check all rc=0.

## Changes (bounded; NO registry/profile/API/schema/migration/crypto/keytrust/strictreadguard/network/UI/compilerapply)

- internal/store/node_compose.go: label gate now runs the raw-string escape
  scan + retained raw UTF-8 byte check before the lossy decode; added the
  `validJSONStringContent` + `hexQuad` store-private helpers (label-scoped).
- internal/store/node_residual_test.go: corrected `TestCorrect_LabelStrictUnicode`
  to use REAL ASCII-escape negatives (`\ud800`, `\udc00`, `\ud800\ud801`,
  `\ude00\ud83d`, `\ud800\u0041`) and a REAL two-escape pair positive
  (`\ud83d\ude00`), removing the misleading CESU-8/literal pair claims.

## Preserved / NOT claimed fixed (tracked followups)

- bul C3b protocol/fields escaped-surrogate examples stay saved with numeric
  status 0 == nodes.Invalid (NOT Valid); fields-sni derived doc holds U+FFFD;
  exact raw source preserved sealed. Unknown-protocol-string Invalid save is
  allowed; raw original protocol not proved derived echo. This contract does
  NOT claim that fixed — known-field lossy projection remains a tracked,
  explicitly-scoped followup.
- NOT touched: HTTP/API/profile/schema/migration/v1/crypto/keytrust/strictread-
  guard/network/UI/compiler/apply. Historical HOME/PID/CDP untouched.
