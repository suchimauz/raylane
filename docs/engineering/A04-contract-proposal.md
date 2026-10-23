# A04 — contract proposal: bounded session / confirmation / retention parameters

Status: PROPOSED (nothing here is CONFIRMED; product/architecture decisions remain with
01 and, where marked, require a user decision). Author: agent 05 (Researcher).
Date: 2026-10-23. Base: 5774d00. Doc-only research; network 0 requests; no sessions,
secrets, GC or code created/executed.
Scope: FR-019/FR-021, US2; data-model entities Admin/Session/SecretRef/ConfigRevision;
analysis item A04; research R-06; contracts control-plane.md / network-agent.md.
Closes the A04 gap "retention policy and session expiry described without concrete
durations" — as a proposal for 03 review, then 01 decides whether a user decision is
needed. This document changes no product decision and no contract/schema/code/tasks.

## 1. Parameter table (all values PROPOSED)

Units: seconds unless stated. "nonconfigurable" = hard constant in code, no admin
setting (reason given). Configurable parameters live in the security contract schema
(T005/T007/T008 area), validated to stay within [min, max].

| # | Parameter | Default | Min | Max | Configurable? | Scope / expiry boundary | Rationale |
|---|---|---|---|---|---|---|---|
| P1 | Session idle expiry | 900 s (15 min) | 300 s | 86 400 s | yes (admin) | Sliding: any authenticated request that passes CSRF/origin resets the idle deadline; idle deadline is per-session, stored server-side | Single admin on trusted LAN; 15 min matches common admin-console practice; short enough to bound an abandoned unlocked session, long enough for config work |
| P2 | Session absolute expiry | 43 200 s (12 h) | 3 600 s | 604 800 s (7 d) | yes (admin) | Fixed at login; NOT extended by activity; on expiry the session is invalid regardless of idle state | Bounds stolen-cookie lifetime even under continuous use; 12 h covers a work day without re-login friction |
| P3 | Session cookie/token | 128-bit random, stored as SHA-256 hash server-side; cookie Secure/HttpOnly/SameSite=Strict | nonconfigurable | — | no (reason: cryptographic floor, not a policy knob) | Token value never stored plaintext, never logged; rotation on privilege-relevant change (password change, release-protection grant) | R-06: sessions and secret transfer protected; hash-at-rest limits DB-read impact |
| P4 | Bootstrap one-time token TTL | 600 s (10 min) | 300 s | 3 600 s | yes (admin at bootstrap issuance only) | From issuance over the authorized local (loopback) channel; single-use: consumed atomically with admin creation; expiry or consumption closes bootstrap permanently (no re-open without new local issuance) | FR-021: protected initial setup, no shared factory password; short TTL bounds an unattended console window |
| P5 | Release-protection confirmation token TTL | 120 s | 60 s | 600 s | no (reason: safety-critical destructive action; fixed short window avoids policy drift) | Bound to: admin session id, target state hash (active revision id + protection state), single use; replay or state change invalidates; re-authorization (password) required at issuance (control-plane.md:14) | Stale-confirmation replay must fail; binding to state hash prevents confirm-A-apply-B |
| P6 | Login rate limit | 5 failures / 300 s per source IP AND per account, lockout 300 s | lockout min 60 s | max 3 600 s | lockout configurable; attempt count nonconfigurable (reason: brute-force floor) | Failure counters decay after window; successful login clears per-IP counter, NOT the per-account counter during lockout | LAN-only exposure but compromised-LAN-device scenario exists |
| P7 | SecretRef retention (unused secrets) | no time-based deletion; reference-counted only | — | — | nonconfigurable (reason: time-based secret GC can destroy rollback capability — see §3) | A SecretRef is deletable ONLY when referenced by: no active revision, no current draft, no in-flight apply/rollback journal entry, no retained revision (P8), no retained backup metadata. Deletion is a transaction: mark-deleted → verify zero refs in same tx → delete payload | data-model.md:33: cleanup only after absence of all live revision/backup-retention refs |
| P8 | ConfigRevision retention | keep ALL active+rollback chain; non-active, non-rollback drafts older than 2 592 000 s (30 d) may be compacted | 7 d | unlimited ("keep forever" = compaction off) | yes (admin); compaction = delete draft metadata but KEEP an audit stub (id, timestamp, actor, result) | Never deletes: the active revision; the last-known-good rollback revision; any revision referenced by an in-flight operation or retained backup | R-05: immutable revisions; failure analysis needs history; bounded growth |
| P9 | Audit log retention | 15 768 000 s (≈6 months) | 30 d | unlimited | yes (admin) | Time-based; deletion in chronological batches in one transaction per batch; secrets never in audit (FR-019) so audit deletion loses history only | Audit supports security review of release-protection and admin actions; unbounded growth on a router-class device is a real constraint |
| P10 | Session storage cleanup sweep interval | 60 s | 30 s | 600 s | no (reason: internal hygiene, not policy) | Expired sessions removed lazily on access AND by sweep; sweep failure never blocks request path (log + retry next tick) | Prevents unbounded session-table growth |

## 2. Semantics and edge cases (expected results for future tests)

### 2.1 Session expiry (P1/P2)
- Idle vs absolute are independent deadlines: session valid iff now < min(idle_deadline,
  absolute_deadline) and not revoked.
- Expired session request → 401, cookie cleared, generic response (no "expired vs
  invalid" distinction to unauthenticated caller).
- Revoked session (logout, password change, admin-triggered revocation) → same 401;
  revocation is immediate (server-side check every request; no cache window).
- Parallel sessions: allowed (single admin may use two browsers); each has its own
  deadlines; password change revokes ALL sessions except the one performing the change.
- Time jump (clock moved forward/backward): expiry comparisons use the monotonic
  server clock for durations where available; stored deadlines are wall-clock UTC.
  Forward jump past deadlines → sessions expire (fail-closed, acceptable). Backward
  jump → sessions live LONGER than intended (fail-open risk): mitigation = store
  last-observed wall clock; on backward jump > 300 s, treat all sessions as expired
  (fail-closed) and log audit event. PROPOSED; needs user decision only if product
  wants fail-open instead (recommend fail-closed).
- Server restart: sessions persist in SQLite; restart does NOT extend deadlines;
  on boot, expired rows swept. Management path after restart = fresh login (no
  recovery backdoor).

### 2.2 Bootstrap (P4)
- Token valid iff: unconsumed AND now < issued+TTL AND channel is the authorized
  local channel. Any other use → generic failure, audit event, counter incremented.
- After successful admin creation, bootstrap endpoint permanently disabled for the
  instance lifetime (DB flag in same transaction as admin insert).
- Expired unused token → bootstrap returns "not available"; re-issuance requires the
  local channel again (no remote recovery — fail-closed).

### 2.3 Release-protection confirmation (P5)
- Token = HMAC or random 128-bit bound to (session id, active revision id, current
  protection state, expiry). Stored hashed; single use.
- Stale confirmation replay (same token twice) → 409/410, audit event, no state change.
- State change between issuance and use (new revision applied by parallel session) →
  token invalid → 409 with reason "state changed".
- Expired token → 410-style failure; operator must re-confirm (re-authorize).

### 2.4 Retention / cleanup (P7–P10)
- Cleanup ordering (atomicity): all retention deletions run as
  (a) compute candidate set, (b) inside ONE SQLite transaction: re-verify references
  under the write lock, (c) delete payloads, (d) insert audit stub. Crash between (c)
  and (d) is safe: worst case is an unreferenced payload re-collected next sweep —
  never a referenced payload deleted, because re-verification happens in-transaction.
- Reference race: a draft created concurrently referencing a SecretRef that is a
  deletion candidate → the draft insert takes the write lock first (or fails
  validation); the cleanup transaction re-checks references under the same lock, so
  the race resolves to "secret kept" (fail-safe direction).
- Pinned references are NEVER deleted: active revision, current draft, in-flight
  apply/rollback journal, rollback revision, backup-related live refs. This is a hard
  rule, not a parameter.
- Crash cleanup: on boot, reconciliation marks interrupted in-flight operations
  failed (R-05 journal); their SecretRefs/refs return to normal retention evaluation
  — no special "crash GC".
- What retention does NOT do (needs separate product decision if wanted):
  deleting backup FILES from admin-managed storage; deleting audit stubs of compacted
  drafts; any history-loss feature ("forget that revision existed"). These lose
  history/backups and are OUT of this proposal — explicit user decision required.

### 2.5 Negative-test vectors (to be implemented as tests in T007/T008; NOT_RUN now)
1. Expired idle session used after 901 s of inactivity → 401; same session with
   activity at 899 s → 200 and idle deadline slid.
2. Absolute expiry: continuous activity for 12 h + 1 s → 401 despite activity.
3. Revoked session: logout then reuse cookie → 401; parallel second session still
   valid until its own expiry; password change kills both except initiator.
4. Clock: wall clock set +1 h → all sessions expired (fail-closed); wall clock set
   -1 h (> 300 s backward) → all sessions expired + audit event.
5. Bootstrap: token at TTL+1 s → rejected; token reused after success → rejected;
   token used from non-local channel → rejected; bootstrap after admin exists →
   permanently disabled.
6. Release protection: confirmation token replayed → rejected + audit; token used
   after intervening apply (state hash mismatch) → 409; token at TTL+1 s → rejected.
7. Retention race: delete-candidate SecretRef + concurrent draft referencing it →
   secret survives; SecretRef referenced only by a compacted draft's audit stub →
   stub is NOT a live ref → payload deletable ONLY if no other live ref (audit stubs
   hold no payload references by design — flagged for 03 review).
8. Crash: kill between payload delete and audit stub insert → next sweep re-collects
   candidate safely; no referenced payload lost (property test over op orderings).
9. Login rate limit: 6th failure within window → lockout; success during lockout from
   same IP still rejected until lockout expiry; counters don't leak via timing
   (constant-time response shape).
10. Restore/backup: restore creates draft only (FR-021); restored draft's SecretRefs
    count as live refs → retention must not collect them while draft exists.

## 3. Design rationale highlights

- Reference-counted (not time-based) secret retention: time-based deletion can break
  rollback (old-but-pinned revision references a secret) and backups. The cost is
  storage of unused secrets until last reference drops — acceptable at this scale.
- Fail-closed on clock anomalies and bootstrap: every ambiguity resolves to
  "re-authenticate / re-issue locally", never to extended trust.
- Nonconfigurable floors: token entropy, attempt counts, confirmation TTL bounds —
  safety parameters are code constants so a misconfiguration cannot weaken them.
- Management path on any failure: local console remains able to issue bootstrap /
  inspect state; no remote recovery path exists by design (FR-021 LAN-only).

## 4. Explicitly out of scope / open for 01

- Backup file lifecycle (deletion of old backups) — product decision, loses history.
- Whether admin may configure P1/P2/P9 at all vs fixed defaults — currently PROPOSED
  configurable within bounds; 01 may simplify to fixed.
- Audit stub reference semantics (vector 7) — needs 03 confirmation that audit stubs
  holding no payload refs matches the intended data-model.
- Exact lockout/backoff curve beyond the stated window — implementation detail,
  bounded by P6.

## 5. Checks

| command | exitCode | executedAt | artifactPath |
|---|---|---|---|
| `git log --oneline -2; git status --porcelain` | 0 | 2026-10-23T19:40Z | (stdout) base 5774d00, tree clean |
| `grep -n A04 specs/001-selected-connections/analysis.md` | 0 | 2026-10-23T19:40Z | (stdout) A04 requirement text |
| `grep session/retention data-model.md, research.md, contracts/*, spec.md` | 0 | 2026-10-23T19:41Z | (stdout) source requirements cited above |
| test commands | NOT_RUN | — | — | no tests exist yet (T007/T008 will implement); per instructions, vectors listed in §2.5 only |

## 6. Risks

- If 03 finds audit stubs SHOULD hold references, P8/vector 7 change (storage cost up).
- Backward-clock fail-closed may surprise during VM snapshots; documented, admin
  re-login is the recovery.
- All durations are design proposals; load testing may tighten P1/P6.

## 7. Questions for 01

1. P1/P2/P9 configurable-within-bounds or fixed constants? (proposal: configurable)
2. Confirm fail-closed on backward clock jump > 300 s.
3. Backup file lifecycle: keep out of scope (proposal) or add a separate user
   decision item?

A04 NOT closed by this document; awaits 03 review, then 01 decision routing.
