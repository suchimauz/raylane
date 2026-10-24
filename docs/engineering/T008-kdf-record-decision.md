# T008 — KDF stored-verifier record: proposed internal decision

**Status:** the logical field layout and validation order of this record were FROZEN
SCOPED by the Orchestrator after both independent focused reviews
(`.hyper/tmp/bui/T008-kdf-logical-format-frozen-decision.json`, consolidation
`.hyper/tmp/bui/T008-kdf-record-independent-consolidation.json`) — a logical subdecision
only; it does NOT close all encoding/source acceptance gates nor globally approve C1–C6.
The K1/K2 boundary-clarification delta in §2/§5 is PENDING FOCUSED INDEPENDENT REVIEW;
retrieval/type/snapshot implementation proof is NOT_RUN; SOURCE AND DEPENDENCY
IMPLEMENTATION NOT AUTHORIZED (no `go.mod`/`go.sum`, no source paths, no Go
resolution/typecheck/runtime, no download). T008 remains `NOT_IMPLEMENTED`; T009 pending;
foundation ACTIVE.

Base cited: `625e3495089e94b07384158285fb1fa30b5d8124` (tree
`8b7e36eef79402d2f239048e4c8dcd252bddb30a`), on the accepted-fidelity security contract
(D1/D2/T1/G1 closed by both independents; consolidation
`.hyper/tmp/bui/T008-contract-correction-independent-consolidation.json`, identity check
exit 0 at 2026-10-24T06:27:00Z). Authorities: accepted `research.md` R-06 (Argon2id via a
proven library), reviewed candidate **C1** and corrected **case 4** of the security
contract, and the exact base above. This document must be reviewed and frozen BEFORE any
future KDF source — including any test-only encoder — is authorized.

## 1. Private fixed typed storage record, version 1 (not a PHC/text wire format)

A private, future, logical record contract mapped by a FUTURE typed store operation to
SQLite integer/BLOB columns. No JSON, base64/hex string serialization, delimiter/PHC
parser, arbitrary map, dynamic algorithm selector, raw SQL/`DB()` escape, or new public
schema/endpoint. Exact table/column identifiers and migration code belong to a later
explicitly scoped package.

| Logical field | Future storage/read boundary type | Exact permitted value |
| --- | --- | --- |
| `formatVersion` | signed 64-bit integer, read before narrowing | `1` — implies ONLY Argon2id for this private format |
| `argon2Version` | signed 64-bit integer | `19` / `0x13` |
| `timeCost` | signed 64-bit integer | `3` |
| `memoryKiB` | signed 64-bit integer | `65536` |
| `parallelism` | signed 64-bit integer | `4` |
| `salt` | raw BLOB, bounded bytes | exactly 16 bytes from standard-library CSPRNG at creation |
| `derivedKey` | raw BLOB, bounded bytes | exactly 32 bytes of maintained Argon2id output |

Algorithm is fixed by `formatVersion=1`, never guessed from input. Output length 32 is
fixed, not an attacker-controlled cost field. Admin identity/username and permanent
bootstrap state are separate existing model concerns — not embedded in or concatenated
with the password/KDF record. Password exact bytes unchanged: no trim, no Unicode
normalization, no new password policy; no plaintext in the verifier record, DB, logs or
errors. No generic parser or future-algorithm compatibility is promised.

## 2. Validation order and resource boundary (BEFORE any KDF, copy, or narrowing)

At the typed storage boundary, in this order:

1. **Type/NULL check** every field; wrong storage type or NULL → reject.
2. **Range check on the signed 64-bit read** — out-of-range numerics rejected before any
   narrowing; no wrap/truncation conversions.
3. **Exact-value check** of all version/parameter fields against the fixed allowlist above.
4. **Exact-length check** of `salt` (16) and `derivedKey` (32) BLOBs BEFORE copying or
   allocating anything based on untrusted lengths.
5. Only after 1–4 pass, invoke the maintained `x/crypto` Argon2id (version 0x13, time 3,
   memory 65536 KiB, parallelism 4, salt 16, output 32) with **trusted fixed constants** —
   never casts of unchecked storage values — then the standard constant-time derived-key
   comparison. This is not an alternative KDF, and the small fixed metadata checks are not
   license for a custom PHC/general parser.

Bounded retrieval requirement, made precise (K1): the future typed store read must check
SQLite storage class (`typeof` integer/blob — no affinity, text or numeric coercion), the
exact fixed integer values, and the exact salt/hash byte lengths **at the storage boundary,
BEFORE projecting, retrieving, or materializing BLOB bytes in Go**. A guarded typed read
returning at most one logical verifier and the fixed 16+32 bytes is a permitted future
strategy; no query or code implementation is described or proven now. A plain `Scan` into
`[]byte` followed by Go `len` is NOT acceptable bounded-read evidence — materialization
would already have happened — and a row `LIMIT` alone is not a BLOB byte bound. Write-side
constraints on newly written rows do NOT replace independent guarded read validation of
malformed/corrupt stored data. No SQL/query/memory behavior was executed or measured; the
requirement is stated, not satisfied. Reviewers: flag honestly any unresolved proof of this
bounded retrieval before future code.

One consistent snapshot, same immutable record (K2): metadata/type/length checks and byte
retrieval must observe ONE consistent row snapshot; the validator and the verifier consume
the SAME immutable retrieved record. No unchecked second fetch between validation and KDF
use, no check/fetch race. Prefer one guarded typed read; if a future implementation obtains
metadata and bytes separately, both must sit inside one stable transaction/snapshot with
consistency demonstrated and be passed on as one immutable record. This introduces no SQL
implementation, concurrency framework, or new service/process/architecture. Trusted fixed
crypto constants remain the interface — database values are never cast into KDF costs.

## 3. Failure semantics — private, generic, fail-closed

Malformed/corrupt/unsupported/oversized verifier → generic authentication refusal/error.
No panic. No KDF invocation. No silent fallback, coercion, truncation, defaulting,
re-hash, or repair. Missing/unavailable storage is never represented as successful
authentication. Private error detail must not disclose password/token/verifier/username
existence through logs or errors. No public HTTP response/status/header is selected or
amended here. C2 admission and global max-2-KDF/no-queue remain reviewed CANDIDATES in
the security contract — neither implemented nor approved by this record. No invented KDF
timing compensation for malformed records; public timing/equivalence proof remains
NOT_RUN.

A well-formed fixed-set record MUST reach verification (positive control) — a
reject-everything stub cannot pass.

## 4. Creation uses only maintained facilities

Future implementation: fresh 16-byte salt from the standard CSPRNG per verifier; 32-byte
derivation through the maintained pinned `x/crypto` v0.58.0; no copying of crypto source.
Random/DB/KDF failure → no partial admin record, no bootstrap success claim; typed
transaction boundaries stay intact. KDF version/parameter changes and any future format
migration require a separately documented and reviewed version — never acceptance of
arbitrary metadata, never rewriting legacy migrations. No password-change/reset/upgrade
endpoint and no auto-rehash is added.

## 5. Focused future tests (ALL NOT_RUN — nothing was executed or written here)

Aligned with (and referenced from, not edited into) security-contract case 4:

| # | Future case | Asserts |
| --- | --- | --- |
| 1 | Valid record + correct password | well-formed exact record reaches maintained verification and succeeds |
| 2 | Wrong password | fails via generic constant-time derived-hash comparison |
| 3 | Unknown versions / NULL / wrong types | refuse pre-KDF |
| 4 | Numeric mismatch on every field | zero, negative, huge/out-of-range rejected before narrowing or KDF; no wrap/truncation |
| 5 | Salt/hash lengths 0/15/17 and 0/31/33, wrong types, oversized metadata | refuse without unbounded retrieval/copy or KDF; oversized/wrong-storage-class input must be rejected BEFORE Go BLOB materialization or KDF — ordinary Scan-then-len and row LIMIT alone are not positive proof |
| 6 | Malformed/corrupt records | never panic, never invoke the KDF (private test seam/counter must not expose a production bypass, raw DB access, or alternate security anchor). Same-snapshot/same-record acceptance: a future concurrent row-change/check-fetch test at the actual typed boundary must show a record different from the validated one never reaches verification; no injected race window or production bypass is implied |
| 7 | Valid fixed-set positive control | DOES reach verification — rejects the reject-everything stub |
| 8 | Fresh verifier creation | distinct random salts; no plaintext persisted; no claim that randomness/performance ran now |
| 9 | Storage/random failure | no partial successful admin/bootstrap state; no unrelated HTTP/issuer/listener/deployment acceptance claim |

Source-inspection plausibility is explicitly separated from future executable tests:
unit tests can validate exact compare-API use, but cannot prove whole-system constant-time
timing under deployment. Cases 5–6 boundary/snapshot assertions are mandatory FUTURE
implementation tests/inspection requirements — all NOT_RUN; future IDKey arguments use the
maintained API's own types (`uint32` time/memory/keyLen, `uint8` threads) with unchecked
storage casts forbidden.

## 6. Gates and other decisions explicitly untouched

- **Dependency gate (separate, unresolved):** `golang.org/x/crypto` v0.58.0 is physically
  cached (ziphash `h1:COkYLr4k7nDI4r6QtMML2AfzeIswWHAJthLS6K/M/54=`, BSD-3); `x/sys`
  v0.49.0 is already pinned; root manifests do not declare `x/crypto`. Cache presence is
  neither permission nor resolution proof. This document grants NO `go.mod`/`go.sum` or
  source-path authorization; the actual addition needs a separate scoped package.
- The other eight decision rows of the security contract stay as currently unresolved:
  public login/saturation/admission mapping, session capacity, cookie mechanics, exact
  Origin/CSRF mechanism, TLS shape, local issuer proof, KDF row closes only after this
  document passes focused review, provenance gap. No new listener/channel/public API/
  recovery architecture, no capacity/cookie/Origin/public-error/TLS/issuer decisions here.
- Prohibited and NOT_RUN for this task: source/dependency/Go/module/typecheck/Argon/test/
  vet/race/build/network/install/download/cache mutation, product HTTP/TLS/listener/socket,
  SSH/privilege/host network, push/deploy, destructive cleanup, real credentials, HOME
  enumeration, new agents/models/fees/settings/provider actions. Only git read/verify
  commands touched the repository; logs live in author scratch (local evidence, not CI).
