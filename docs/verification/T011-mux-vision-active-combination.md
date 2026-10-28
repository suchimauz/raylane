# v4-US1-T011 mux-vision ACTIVE combination — scoped verification note

Status: domain/validation increment COMPLETE (this note); engine compatibility /
readiness remains a SEPARATE named OPEN concern (`V4-FR003-MUX-FLOW-DIRECTION-
COMPATIBILITY`). Parent tasks T010/T011/T012/T013/US1/Foundation remain OPEN
until their separate criteria are met. This is a structural validator fact,
NOT an engine/handshake/readiness certification.

## Settled rule (parent decisions FINAL, pure vless VALIDATION only)

When an otherwise-valid VLESS draft has, ALL in ACTIVE:
- `muxEnabled`: eligible declared boolean (known/nonsecret, supported-not-false,
  exact type `boolean`), actual bool `true`;
- `flow`: eligible declared enum (known, supported-not-false, exact type
  `enum`), actual string admitted by its OWN `allowedValues`, exactly
  `xtls-rprx-vision` OR `xtls-rprx-vision-udp443`;
- `concurrency`: eligible declared integer (known, supported-not-false, exact
  type `integer`), passes its OWN ordinary shape+bounds (existing `valueOK` /
  `asInt`, no new parser / float conversion), exact integer `>= 0`;

the draft is refused for apply with EXACTLY ONE existing static value-free
`dependencyIncompatible` on the declared `concurrency` path. The Validate tail
then yields Invalid / notApplicable and preserves the exact input/raw document
and maps (no reset/default/auto-toggle/flow rewrite/invented value).

Rationale (pinned upstream `1b1647cd`, D-016): ordinary concurrency is a Go
`int16`; when a mux block is ENABLED, an ordinary concurrency of zero
(including an omitted scalar in an enabled emitted block) defaults upstream to
8, and a positive value constructs an ordinary manager — both unsafe for an
active Vision flow. An exact integer `>= 0` therefore cannot be faithfully
emitted as a safe enabled Vision mux.

## Silent controls (each participant's OWN bad value/declaration suppresses
only THIS rule; ordinary diagnostics and existing aggregates still apply)

- `muxEnabled` false / absent / inactive-only / wrong-type / ineligible;
- `flow` empty / absent / inactive-only / outside own enum / ineligible;
- `concurrency` absent / inactive-only / wrong shape / out of bounds / negative
  (negative is ordinarily legal and disables) / ineligible;
- any actual non-vless protocol (even a custom trusted profile reusing all
  names) never receives this product-specific rule;
- `xudpConcurrency` is NOT part of this condition (no positive-only
  requirement, no zero/negative prohibition, no invented dependency); it keeps
  its independent signed-int16 generic domain.

No new IssueCode / status / readiness aggregate / API / default / dependency /
profile version / dependency package. No automatic mux enable/disable, no flow
rewrite, no invented `concurrency=-1`, no hidden default insertion.

## Local-vs-future-compiler boundary (tracked, NOT this scope)

Locally ABSENT ordinary concurrency stays absent and this narrow rule is
silent. That is NOT a safety claim for a future emitted enabled mux block: a
future compiler/apply increment must NEVER emit a Vision mux with `enabled:true`
and ordinary concurrency absent OR `0` OR positive; unresolved faithful safe
emission must BLOCK compile/apply while still allowing exact draft SAVE. The
compiler/apply implementation is OUT OF SCOPE here.

## Verification performed (author; independent acceptance controls closure)

- Semantic RED on immutable `7417c9e` (accepted baseline, real APIs, compiles):
  A1 forbidden pair yielded `Valid` / `issues=[]` (rule absent) — red_a1.log
  rc=1. Not a SETUPERROR (fixture/perms verified, assertions reached product
  behavior).
- GREEN after implementing `checkMuxVisionRules`: A1 (numeric matrix incl
  `0,1,8,257,32767`, both Vision spellings, canonical exact-integral
  `8e0`/`0.0`/`-0` json.Number; negative `-32768,-1` stay Valid; fraction /
  out-of-range get their ordinary issue with NO conditional duplicate), A2
  (switch/flow/presence silent controls; XUDP independence incl unrelated-
  invalid-field no-suppression), A3 (per-participant custom-authority guards +
  non-vless never receives the rule + narrowed-bounds + flow-enum-subset),
  A4 (envelope semantic refusal preserves exact raw; safe projection keeps
  known scalars; closed result noecho; malformed/trailing still syntax-refused),
  A5 (store integration: forbidden pair SAVED Invalid; close/reopen keyless
  reader returns the historical fact + safe scalar/presence without credential
  echo; exact preservation bytes intact; negative control stays Valid).
- Full gates: affected + race (no DATA RACE) + full-Go 11 ok + build + vet +
  contracts validator + selftest(34) + gofmt + diff-check all rc=0.
- Preserved regressions: existing mux numeric suite (`mux=true`/`8`/absent/
  empty flow stays Valid; XUDP independent; no cross-field refusal; no
  auto-toggle) and the atomic A1-A7 / B1-B3 cold-read suite.

## Source-backed NOT_RUN (not fake executed PASS)

Zero/absent engine branches and the broader transport/REALITY/UDP443 matrix are
SOURCE-BACKED against pinned upstream `1b1647cd`; the runtime engine matrix was
NOT re-run here. Other transports / REALITY / UDP443 traffic / full compiler /
UI / apply are NOT_RUN. No engine readiness is claimed.
