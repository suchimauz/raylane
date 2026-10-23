# Foundation decisions — T005 contract batch (D1–D8)

**Status:** authoritative rationale for the single T005 contract batch.
**Source:** `docs/engineering/foundation-execution-decision.md` (01), after the
independent 03 risk review (`.hyper/tmp/t005a/execution-baseline-review-REPORT.md`).
**Scope:** contract/schema/normative only. No server, route, handler, helper or
kernel change was made; no runtime behaviour is specified or implied. This
records decisions, NOT completed implementation or foundation acceptance.

These decisions are the normative basis for `contracts/openapi.yaml`,
`contracts/helper.schema.json`, `contracts/capability-profile.schema.json`,
`contracts/capability-profile.json`, and the synced feature contracts and data
model. 02's proposals (`.hyper/tmp/buj/t003/execution-baseline-short.md`) and
03's review informed them; where 01 corrected 02 (D4, D5) this document follows
01. Gaps that remain open are listed at the end; nothing here marks a gap
closed merely by adding prose or a permissive schema.

## D1 — one typed capability source
`contracts/capability-profile.json` (schema `contracts/capability-profile.schema.json`)
is the single source of per-protocol field truth for VLESS, SOCKS5, HTTP and
WireGuard. Each field has a type, classification (`known` / `secret`), required
flag, default, allowed values and dependencies. The write schema and the
allowlisted read projection are both derived from it. Unknown fields are
quarantined encrypted (`unknownFieldsEncrypted`), never rendered, never
compiled, and excluded from reads; a node carrying them is invalid-draft and
not applicable. Secret fields are `SecretRef`, presence-only on read, and never
appear in any read/export/report/log outside the encrypted backup envelope
(D4). A declared-but-unsupported field is preserved inactive and prevents
apply. Semantic-invalid drafts remain saveable; malformed JSON cannot replace
saved state. Closes G-11 at the contract level; the runtime enforcement
(write validation + read-side filter) is an implementation obligation.

## D2 — actual byte delivery on the existing authenticated Unix socket
A closed `StageArtifact` helper command delivers artefact bytes inline over the
existing peer-authenticated Unix socket. Envelope carries a typed `artifactKind`
(engineConfig / dnsConfig / destinationSet / policy), `declaredSize`,
`declaredSha256` and `contentBase64`; there is no peer-supplied file path, name,
command or environment. Peer credentials are authenticated before any byte is
read; framing is bounded before allocation and the decoded size is validated
before materialising large data. The helper generates the staging identity,
recomputes SHA-256, validates the permitted artefact profile and atomically
finalises into helper-owned storage; no partial artefact becomes referenceable.
Limits: per-object ≤ 1 MiB decoded, per-generation aggregate ≤ 16 MiB,
object-count ≤ 64 per generation. Bounded pre-apply staging failures may remove
their own partial writes but do not authorise retention/secret/history cleanup.
Generated artefacts may contain secrets and are never logged or public-read.
Unblocks G-10 (the apply operation now has a defined delivery path).

## D3 — strong explicit concurrency guards
`RuleSetSource` gains a distinct settings `revision`; `draftVersion`/
`activeVersion` retain content meaning. Every mutation class has an explicit
guard (the blanket "all mutations require expectedRevision" line is narrowed by
an explicit operation-class table in `control-plane.md`, not weakened):
entity mutations (PATCH/DELETE) require a client `expectedRevision` (409 on
mismatch); refreshes require a client `expectedRevision` on the settings
revision plus a server-side `capturedRevision` commit-check (the two protect
different races); creates carry no revision guard and are instead protected
transactionally by target-absence and uniqueness-key checks (duplicate → 409,
never overwrite); immutable-revision operations (validate) and generation-bound
runtime operations (`expectedGeneration`) have their own guards. No
`expectedRevision` is ever bound to `draftVersion`/`activeVersion`. Resolves
G-18.

## D4 — self-contained encrypted backup (A), draft-only atomic restore
The backup is a self-contained encrypted export the administrator holds; the
product keeps no permanent backup registry. The encrypted payload carries
sufficient configuration AND secret values to restore to a clean target,
including encrypted-quarantined fields. It contains no master key, sessions,
admin credentials, release/bootstrap tokens, raw audit logs or passphrase. The
envelope uses standard supported KDF/AEAD libraries with versioned, bounded
parameters; no custom cryptography. Restore authenticates/decrypts and
validates format/version/bounds before creating state; it recreates
secret-store records under the target key and remaps references consistently in
the same transaction as the new draft. Failure exposes no partial
draft/secret records; the active state is unchanged and no implicit apply
occurs. A missing reference in a purportedly complete archive is an error.
No permanent catalogue or backup-driven retention entity; P7/P8/P9 cleanup
remain OFF. Resolves G-04/G-05; G-06 stays BLOCKED (cleanup off by decision).

## D5 — preserve the page editor through reauthentication
Session constants are unchanged: idle 900 s (polling/reads do not extend),
absolute 43200 s, re-login after control-plane restart. The still-open page
retains unsaved editor data, INCLUDING newly typed secret fields, in page RAM
through expiration/re-login/control-plane restart; it reauthenticates before
any save, re-fetches the revision and resolves conflicts rather than
overwriting. It does not silently clear the editor on 401/expiry/restart and
does not replay a mutation. No localStorage/sessionStorage/IndexedDB/cache/
cookie/log/analytics/service-worker persistence of edit or secret data.
Retained secret input is cleared only after an acknowledged save, explicit
discard or destruction of the page. Browser restart/tab crash/explicit
navigation destroy page RAM — an honest physical limitation the UI documents,
with save/discard warnings where possible, not a new permission to lose edits
during same-page reauth. Expiry is not weakened to preserve edits. This is a UI
implementation gate; a schema cannot prove it. Resolves G-01/G-02/G-03 at the
contract level.

## D6 — concrete release authorization, not a trusted root oracle
The control plane owns session authentication, CSRF/origin, user confirmation
and public issuance. A closed helper `RegisterReleaseConfirmation` operation on
the existing peer-authenticated socket — separate from `ReleaseProtection` —
issues the confirmation. The helper generates an opaque CSPRNG nonce and stores
a bounded pending entry with the token digest, a session identifier (not the
cookie), the target generation, the protection-state identity/resource and its
own monotonic expiry (≤ 120 s). The CP returns the token only to the
authorized session; submission revalidates session/CSRF/origin and forwards the
matching authorization. The helper validates local binding, expiry and single
use and atomically consumes before the release action. No signature scheme or
cross-process clock comparison is invented. Helper restart invalidates all
prior pending confirmations (fresh boot epoch), even if the generation is
unchanged; a protection-state/generation change also invalidates them. The
helper re-verifies the confirmation against its own state — it trusts the CP
for who owns the session, not for whether the confirmation is valid. Audit
records issuance and attempts without values/digests. Same
operationId+payloadHash may return a prior terminal result but never re-executes
release; a fresh operation with a consumed token fails. Resolves G-07.

## D7 — both fetch sources, both address families
`Subscription` and `RuleSetSource` each carry a per-source
`lanAllowlistCIDRs`, administrator-controlled and not settable by any import.
Forbidden address classes are evaluated first and always win over the
allowlist, for every resolution, actual connection and redirect, for IPv4 and
IPv6 (including IPv4-mapped IPv6): loopback, link-local, multicast,
unspecified, metadata/link-local-metadata. Evaluation order is
forbidden-class → allowlist-membership → remaining policy; a forbidden-class
refusal names the class, distinct from "not in allowlist". Redirects are
re-evaluated per hop; mixed A/AAAA results and safe destination
pinning/connection verification are accounted for. A remote-proxy resolution
that cannot enforce this fails closed, not direct retry. Management/local
exclusions are preserved; the UI explains the reason without a secret URL.
Resolves G-16.

## D8 — standard engineering prerequisites, not shortcuts
Race checks are kept and the compiler/cgo prerequisites are defined. RFC 8785
(JCS) payload-only UTF-8 SHA-256 with duplicate-key rejection remains fixed,
implemented by a vetted, widely-used library pinned with the RFC's own test
vectors as acceptance proof; no homegrown JCS, crypto or general parser. No
IPv6-ready/runnable-CI claim is made without actual evidence. Researcher 05
owns read-only upstream metadata/artifact retrieval and the proposed pinned
toolchain separately; the dependency downloads and the network read are their
own explicit authorizations, not bundled here.

## Remaining genuine gaps (not closed by this batch)
- **G-06 retention / GC:** cleanup stays OFF by decision (D4); no deletion
  endpoint exists.
- **G-12 canonical document shape:** follows the compiler, which does not exist
  yet; `ConfigRevision.canonicalDocument` is free-form and not guaranteed
  secret-free until then.
- **JCS / dependency conformance:** the vetted RFC 8785 library and the pinned
  YAML/OpenAPI validators must still be downloaded and verified (separate
  authorization, D8); the idempotency check stays NOT_RUN until then.
- **Runtime behaviour:** no helper, socket, nftables rule, dataplane or UI was
  built or executed. Contracts and tests are not proof of runtime behaviour.

Independent 03 review and 04 tests of the immutable result are still required
for T005 acceptance.
