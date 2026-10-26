# T008 — runnable auth runtime: accepted scoped record

This document records the EXTERNAL acceptance of the scoped T008 deliverable: the
Orchestrator accepted it only after BOTH independent review and independent execution
closed every actual finding. It is not author self-acceptance. T008 acceptance is scoped
to the runnable same-process HTTPS auth runtime and is **not** UI, network-engine,
dataplane, backup/apply, full FR-021 or Foundation acceptance.

## Decision

ACCEPT the scoped T008 outcome at commit `2f49948b571a7ff1321418c9910d52b1cfb77f17`,
tree `16a36aba963194086a208eb90e24e318b0dc5fa4` (base `eead001`). Both independent
roles (security/correctness review and behavior/full-gates execution) returned ACCEPT;
no blocking finding remained; two INFO items are advisory only. Status:
**V4-T008-RUNTIME-SEMANTIC-BOUNDARY CLOSED by both**.

## What T008 delivered (working behavior)

- One Raylane Go process serving a configured trusted-HTTPS management origin and a
  separate owner-only Unix control socket; TLS mandatory (no insecure fallback).
- Local username/password identity with no shared default; Argon2 admission, CSRF
  Origin check on unsafe methods, strict `Secure`/`HttpOnly`/`SameSite=Strict`
  host-only cookie, RAM-only opaque session tokens.
- Bootstrap issuance/redemption ONLY on the owner-only Unix socket; the LAN has no
  bootstrap route — unknown LAN paths and the absent bootstrap route answer the SAME
  generic 403 (no existence oracle), with fresh request IDs and configured-Origin
  priority. The Unix socket mux is physically separate.
- Truthful runtime state (`phase: not-running`, management-only readiness); sign-in /
  sign-out / restart semantics (sessions invalidate on restart).
- Exact idle 900s / absolute 43200s / non-activity / capacity-1024-reject-new session
  timing; per-peer burst login limiter with optional integer `Retry-After`.
- A runtime composition boundary guard: the management handler authorizes only exact
  selected field objects (the four approved clocks and the bounded gate release), not
  owner-HAS-a-clock; unknown/indirect selections fail closed.

## Verification (both independent roles, all exit 0)

go build, go vet, go test (6 pkgs), `-race` (0 data races, 6 pkgs), `go mod verify`,
`go mod tidy -diff` (empty), gofmt (clean), web typecheck, web build, contracts
validation (34 regression tests + full validator PASS). Exact argv/cwd/exit/elapsed/raw
logs are retained in the task evidence stores, not here.

## Honest limits

- Hosted CI: provisioned but the run was NOT executed locally with the hosted Python
  3.12.12 (local interpreter differs); CI itself is a gate definition, not a local run.
- Web unit / e2e were absent at the accepted commit; real remote LAN and a compiled
  UI/browser run were NOT_RUN at that commit. Those are addressed by the later T009
  increment, not by T008.

## Status reconciliation

- **T008: COMPLETE / ACCEPTED** (by both independent roles; this doc records it).
- **T009: COMPLETE / EXTERNALLY ACCEPTED** (updated 2026-10-26, after this T008 record
  was written). T009 delivered the same-origin HTTPS sign-in/status shell on top of the
  accepted T008 runtime and was accepted by independent review/designer/QA at
  `3d7b342`; see [T009 acceptance](T009-acceptance.md). The historical T008 limits below
  are unchanged.
- **Foundation: OPEN.** No foundation acceptance is implied by T008 or T009.
