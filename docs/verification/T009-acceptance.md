# T009 — same-origin HTTPS sign-in/status shell: accepted scoped record

This document records the **external** acceptance of the scoped T009 deliverable. The
Orchestrator accepted it only after ALL THREE independent roles — security/correctness
review (cah), browser/designer behavior (cmw), and full-gates QA execution (bul) —
returned ACCEPT on the same immutable candidate. It is **not** author self-acceptance.
T009 acceptance is scoped to the runnable same-origin HTTPS sign-in / status / error /
re-auth / dirty-exit UI shell and is **not** UI-node editor, compiler, apply, network
engine/dataplane, backup/restore, full FR-021, hosted CI, or Foundation acceptance.

## Decision

**ACCEPT the scoped T009 outcome** at commit `3d7b3429002406c9e4fbea0e808c542adcad6baa`,
tree `7aace8a9c5708209c1baf8d5f17092be2c0d28f8` (base `472dc57`, parent of that base
`f85e0cb`). All three independent roles returned ACCEPT on this exact candidate:
review **ACCEPT_FOCUSED_DELTA**, designer **ACCEPT_FOCUSED**, QA **ACCEPT**. The
canonical **V4-T009-MODAL-FOCUS (F7)** is CLOSED, and with it all nine actual T009
findings are closed. Status: **T009 COMPLETE / EXTERNALLY ACCEPTED**; **Foundation and
G1–G4 remain OPEN.**

## What T009 delivered (working behavior)

- A same-origin HTTPS shell over the accepted T008 runtime: sign-in / sign-out, runtime
  status presentation, truthful error, in-place re-auth, and a dirty-exit guard.
- Truthful status evidence: absent or unrecognized optional values render UNKNOWN /
  "Not reported", never an invented saved/active state; malformed `activeGeneration`
  (negative, fractional, non-finite, or unsafe) is UNKNOWN retained, never a bogus row.
- Native modal dirty-exit boundary: background genuinely inert and AX-excluded,
  Tab/Shift+Tab contained, Escape == Stay (RAM preserved), deliberate Discard sends
  exactly one DELETE; **keyboard focus returns to the visible Sign-out invoker after
  cancel** (the final F7 sub-case).
- Unicode-correct login bounds (codepoint, not UTF-16 length) with a separate
  serialized-body byte bound, explicit accessible validation, and no input mutation on
  rejection.

**Production has NO test child or editor.** The test-only stateful child is compiled out
of the production bundle entirely; it is enabled explicitly and only in the isolated
test build to exercise RAM/identity checks across the auth boundary.

## Finding closure chain (nine stable findings)

The nine findings were closed across three immutable increments; none is open.

| Finding | Closed at |
|---|---|
| F1 STATIC-ARTIFACT-MEMBERSHIP | `f85e0cb` |
| F3 PRODUCTION-TEST-CANARY | `f85e0cb` |
| F4 UNICODE-TRUNCATION | `f85e0cb` |
| F8 REAUTH-RELOAD-ADVICE | `f85e0cb` |
| F9 LOGOUT-FAILURE-COPY | `f85e0cb` |
| F2 INCOMPLETE-BUNDLE-STARTUP | `472dc57` |
| F5 STATUS-EVIDENCE | `472dc57` |
| F6 LOGIN-FOCUS | `472dc57` |
| F7 MODAL-FOCUS (canonical) | `3d7b342` |

## Verification on the accepted candidate (independent roles, newly executed)

- **QA (bul):** install / typecheck / web-build-before-Go / `go build` all exit 0; full
  browser suite **112/0** in **88790 ms**; independent original-identity **25/25** in
  **57448 ms**; native containment **13/13** in **13629 ms**.
- **Review (cah):** final private original + expected-next oracle **113/0** in
  **85.496 s**; an earlier 113/0 run is also preserved (two reviewer runs occurred and
  are both retained, not collapsed into one).
- **Designer (cmw):** focused review **30 observations / 0 failed** in **28418 ms**,
  covering visible keyboard focus, AX, RAM preservation, exactly one DELETE on Discard,
  and 320px dark + reduced-motion; ten screenshots captured and read.
- Environment: pinned Node 22.23.4 / Go 1.27.3 / Chrome for Testing 156.0.8078.4, own
  trust store and browser profile, real sandbox, no certificate bypass.

## Carried forward — NOT newly executed

The prior immutable `472dc57` backend/security evidence is unchanged by the
frontend-only two-file delta (`web/src/App.tsx`, `web/e2e/auth-shell.spec.mjs`) and is
carried forward, not re-run: full `go test` (84330 ms), `go test -race` (354752 ms,
0 data races), contracts validation, modules/formatting/prerequisites, startup
regular-kind proof, genuine reachable trusted-chain wrong-SAN and untrusted-issuer
controls, positive TLS, and sandbox proof. F2/F5/F6 were closed at `472dc57`; the five
earlier findings at `f85e0cb`. No duplicate unchanged backend gates were re-executed for
this frontend-only correction.

## Honest limits and preserved history

- **F7 remainder history preserved:** the original defect (synchronous `focus()` during
  the still-open inert modal dropped focus to `<body>`) and the author's first faulty
  oracle (a `/sign out/i` page-text substring that passes on `<body>`) are retained as
  evidence. The author's replacement (BUTTON + text match) is **not** DOM object
  identity; the independent roles supplied saved-original-handle equality and the
  expected native successor as the strict oracle.
- **QA history preserved:** QA's own first wrong initial-focus expectation, the absent
  Playwright accessibility driver, and the corrected CDP probe history are retained.
- No device screen reader was attached and no whole-WCAG conformance is claimed; focus
  identity is proven in the DOM accessibility tree.
- Future UI-node editor, compiler, apply, backup/restore, network engine/dataplane,
  hosted CI, remote LAN, full FR-021, and Foundation remain future work — they are NOT
  accepted by implication.

## Status reconciliation

- **T009: COMPLETE / EXTERNALLY ACCEPTED** (this document records the decision).
- **T008: COMPLETE / ACCEPTED** (ancestor `2f49948`; see [T008 acceptance](T008-acceptance.md)).
- **Next US1 dependencies:** T010 (after T003/T005) and T011 (after T006/T007/T010) are
  the next dependency-ready work; they remain UNCHECKED / UNFINISHED.
- **Foundation / G1–G4: OPEN.** No Foundation, network, apply, backup, or production
  acceptance is implied by T009.
