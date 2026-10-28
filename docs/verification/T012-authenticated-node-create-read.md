# v4-US1-T012-authenticated-node-create-read — scoped verification note

Forward off base 499c46fd2d892f163fd545b15581906a95156fa0/tree d6b226f8 (cal's WIP,
15 dirty files preserved, no reset/checkout/stash). Completes the real-process
create/read slice; T010/T011 already independently accepted (not replayed);
T012–T014/Foundation remain OPEN.

## Outcome (real behavior, not httptest-handler-only)

An operator starts the real HTTPS service with an explicit trusted node key,
authenticates via the accepted local-Unix bootstrap + real login (actual
session cookie + Origin), POSTs a draft to `/api/v1/nodes`, then GETs
`/api/v1/nodes/{nodeId}`. The same atomic writer preserves exact original
components + separate typed secrets and the actual historical verdict; the
same keyless reader returns only the safe projection plus current secret
presence. Saving never applies/starts an engine.

## What was missing (gap closed here)

cal's smoke fixture was in-process `httptest` handler-only: it did NOT
establish real TLS, real process, cold keyless read, or actual cookie+Origin
against a running server. The existing `TestT008EndToEndRealProcess` did real
TLS + local bootstrap + real cookie + Origin, but never POSTed/GET a node
(there was no way to configure a node key on `serve`). This correction adds
the missing real-process node create/read path.

## Changes

- `cmd/raylane/serve.go`: optional `nodeKey` in the strict operator config
  (omitted stays keyless; a NONEMPTY path is shape-validated then opened once
  at composition — a configured-but-unusable key is a hard no-downgrade refusal
  before the LAN listener binds). Wires `NodeKeyPath` into `authhttp.Config`.
- `internal/store/secrets.go`: narrow production `SecretStore.OpenPreservation`
  readback — resolves the node's (ref,purpose) from the owner/link metadata
  and authenticates the sealed blob with the trusted key, returning the exact
  operator-submitted bytes. This is the trusted management-side readback the
  keyless safe reader never exposes; no HTTP surface reaches it.
- `cmd/raylane/serve_t012_node_test.go`: `TestT012AuthenticatedNodeCreateReadRealProcess`
  — real TLS rooted at the owned test CA, local-Unix bootstrap, real login
  (actual cookie + Origin), keyed POST → 201 (server-generated id, revision 1,
  no secret/quarantine leak), safe GET → 200 (same id/revision, safe
  projection, `uuid` present:true, a declared-but-absent secret present:false,
  sealed-only label omitted, validation `valid-draft`/applicable), exact
  preservation decrypt, keyless cold reader same whole-history verdict +
  presence, and a semantic-invalid (unknown-quarantine) save→read that returns
  the SAME actual `invalid-draft`/notApplicable without revalidation or leak.

## Verified (author; controls closure)

- New real-process test: PASS. Affected suites (store, capability, domain,
  jsonscan, tests/contract, authhttp, cmd/raylane): all ok. Full Go: 11 ok 0
  fail. build/vet/gofmt/diff-check/contracts-validator + 34 selftests: rc 0.
- Race: store + cmd/raylane clean; authhttp under `-race` completes in ~326s
  (>300s) with NO DATA RACE — the 300s timeout was suite duration, not a race.
- No HTTP API/schema/profile/v1/crypto/keytrust/readguard change beyond the one
  narrow production readback used only by the management-side test. Sealed
  preservation guarantee, whole-history, current-presence, rollback, strict
  decoder, and keyless safe-read boundary are unchanged.

## Boundaries

No HTTP route semantics beyond the two accepted node paths; no full CRUD /
list / PATCH / DELETE / editor / UI; no engine apply/start. The label remains
SEALED-only (no lossless read path yet) and is omitted rather than decrypted.
Independent acceptance by bul + cah against the same immutable candidate.
