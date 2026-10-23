# T003 — synthetic fixture corpus

Tracked fixtures for the 56 synthetic protocol cases defined by the T003
oracle. Every file under this directory is **synthetic**. Nothing here was
fetched, executed, or observed from a running product.

**Nothing in this corpus has been executed.** `runtime_status` is `NOT_RUN`
for all 56 cases and `apply_observation` is `null` for all 56. The
`expect` block in each case is the **expected policy** derived from the
spec, not a result. A fixture that says `expect.apply = "BLOCKED"` states
what the product *should* do; it does not state that anything was observed
to do it. See "Runtime status" below.

> **Status of this corpus: `MAPPED / PLANNED`, execution count 0.**
> The cases are mapped to the requirements they exercise and the inputs are
> concrete, but no test runner consumes them yet. See "Coverage — three
> different numbers" for exactly what is and is not claimed.

## Layout

| Path | What it is |
|---|---|
| `oracle/T003-oracle.json` | The T003 oracle, vendored verbatim from 04's artifact. It is the **only** source of expected semantics in this corpus. |
| `cases/<ID>.json` | One file per case: the concrete input, the expected stages, the requirement trace, the runtime markers. |
| `inputs/<ID>.<ext>` | Literal payload files for the cases whose input is a byte string (URI, URL, YAML, base64, `.conf`). |
| `canaries/registry.json` | The 6 synthetic canaries, with raw bytes and the rule that keeps them out of reports, exports and logs. |
| `generate.py` | The deterministic generator. Re-running it reproduces the corpus byte-for-byte. |
| `verify.py` | Consistency checks over the corpus itself (38 checks). It executes no product and validates no product behaviour. |
| `manifest.json` | sha256 of every file above, plus counts, coverage and the open gaps. |

Regenerate and check with:

```sh
cd tests/fixtures && python3 generate.py .   # rewrites the corpus
python3 tests/fixtures/verify.py             # 38 checks, exit 0
```

Both steps are offline and touch nothing outside this directory.

The generator reads `oracle/T003-oracle.json` and **derives** everything
else. It adds no expected outcome of its own: every `expect` block, every
`trace` tag, every `cap` string and every runtime marker is copied from the
oracle byte-for-byte. What it *does* add is a concrete synthetic input for
each case, and it records what it added in `input.expansion_note`.

## Reading a case

```json
{
  "id": "B-11",
  "family": "protocol",
  "expect": {"parse": "OK", "validate": "VALID", "compile": "PRODUCES_OUTBOUND",
             "apply": "BLOCKED_PENDING_APPLY_STAGE"},
  "expect_apply_policy": "BLOCKED_PENDING_APPLY_STAGE",
  "expect_apply_is_policy_not_observation": true,
  "runtime_status": "NOT_RUN",
  "apply_observation": null,
  "trace": ["FR-001", "FR-008", "data-model:Secret"]
}
```

`input.payload` is either an inline structured object (a node, a candidate
list, a scenario) or a reference to a file under `inputs/`. `input.oracle_value`
carries the oracle's own value string verbatim, so a reviewer can always
compare the fixture against the source it was derived from.

`input.expansion_note` appears only where the oracle's value was a
placeholder or a prose label rather than a concrete protocol input. There
are 13 such cases:

| Case | Oracle value | What the fixture contains |
|---|---|---|
| A-03 | `BASE64(SYNTH-LIST-3-URIS)` | Real base64 of a three-URI list; the decoded plain list is kept beside it as `inputs/A-03.subscription-list.txt`. |
| A-04 | `proxies: [VLESS], rules: [...], dns: {...}` | A real Clash/Mihomo document carrying all three sections, so the "proxies only, rules/DNS not transferred" expectation is actually exercisable. |
| B-13 | `[Interface]\nPrivateKey=...` | A real `.conf` document. |
| G-03 | `vless://...&allowInsecure=1` | A full VLESS URI carrying the flag. |
| E-01…E-05 | prose (`empty list`, `valid, BROKEN, valid`, …) | Concrete candidate lists: the empty list, the three-node list whose middle node is broken, the list missing the node an active rule references, the two nodes with one keyed fingerprint, the renamed node keeping its stable id. |
| J-01…J-04 | prose (`3 nodes, none match`, …) | Concrete candidate lists the filters are applied to, plus the active node J-03 protects. |

Every other case uses the oracle's exact value with no expansion.

## Stages

- **parse** — syntax of the format (URI / base64 / YAML / JSON). An error
  means the save is rejected and the previously stored value is intact.
- **validate** — semantics against the capability profile. An error means
  the save is permitted but apply is blocked (FR-009).
- **compile** — building the canonical document / outbound. Not reached when
  validate is not `VALID`.
- **apply** — changing active state. **Not invoked in any case.** The
  `expect.apply` value is the expected product *policy* for that stage.

## Runtime status

| Field | Value | Meaning |
|---|---|---|
| `runtime_status` | `NOT_RUN` (all 56) | No scenario was executed. There is no product, no network and no runtime. |
| `apply_observation` | `null` (all 56) | No observation of the apply stage exists. |
| `expect.apply` | varies | The **expected policy** for apply, derived from the spec. Not a result. |

The vocabulary of `expect.apply` values in use: `NOT_INVOKED` (33),
`BLOCKED` (17), `NOT_REACHED` (3), `BLOCKED_PENDING_APPLY_STAGE` (1),
`BLOCK_NEW_CONNECTIONS` (1), `STOPPED_GUARDED` (1).

`NOT_RUN` is not `PASS`, and `UNVERIFIED` is not `supported`.

## Coverage — three different numbers, not to be mixed

These come from the oracle's own `coverage` block and are reproduced here
unchanged.

- **Syntactic trace coverage: `32/36`.** The requirement tag appears in at
  least one case. **This does not mean the behaviour is verified by a
  fixture** — it means the tag is mentioned. The four requirements with no
  tag are FR-016, FR-017, FR-018 and SC-007.
- **Fixture-verifiable: `27/27`.** Every requirement that is *in principle*
  verifiable by a fixture carries a tag.
- **Not fixture-testable: 9.** FR-014 (real download route), FR-015 (real
  HTTP/TLS/proxy fetch), FR-016 (LAN network/routing), FR-017 (architectural
  constraint), FR-018 (visual criteria), FR-020 (runtime routing / DNS /
  readiness), FR-021 (login/sessions/backup), FR-023 (real credential
  transfer across a redirect), SC-007 (manual recovery). These need a stand
  or a working product; a fixture can only encode the expected policy.
  **None of these 9 is claimed as covered.**

The denominator is `spec.md` (authoritative): FR-001..FR-024 = 24,
US-01..US-05 = 5, SC-001..SC-007 = 7, total 36. An earlier count of 38
(22 FR + 10 US + 6 SC) is not reproducible — `spec.md` contains exactly five
`### US-xx` headings — so 36 is used.

## Open gap

### GAP-WGKEY — malformed WireGuard key

**Stage: `UNKNOWN`. Not covered, and deliberately not covered.**

FR-009 normalises only the explicit case ("semantic invalidity blocks
apply, invalid JSON is a rejection"). The *form* of a WireGuard key
(base64, 32 bytes) has no normative source in `spec.md`, `data-model.md`,
`contracts/` or `capabilities.md` — grep finds no match. A malformed key
therefore cannot be assigned to parse (reject the save) or to validate
(save as an invalid draft) without a norm: a JSON document whose key is
merely a string of the wrong form is syntactically correct, so "invalid
JSON" does not apply.

B-12 covers the *length* of `Reserved`, which is a validate-stage
value-contract with the "saved as an invalid draft" policy. A malformed key
is a different problem: it does not parse as a key at all. Adding a case
with an invented expected outcome would be fabrication — it would force an
unapproved rejection policy onto the implementation.

To close: a norm in the spec saying whether the WG key form is part of
import syntax (parse) or field semantics (validate). Until then: `UNKNOWN`.

This gap does **not** block the valid positives.

## Canaries

Six canaries, copied verbatim from the oracle's registry. Each is unique,
synthetic, and marked `DO-NOT-USE`. None resembles a real secret.

| ID | Case | Field | Form |
|---|---|---|---|
| CAN-0001 | B-07 | `password` | literal text |
| CAN-0002 | B-11 | `privateKey` | 32 raw bytes, base64, 44 chars |
| CAN-0003 | B-11 | `presharedKey` | 32 raw bytes, base64, 44 chars |
| CAN-0004 | C-02 | diagnostic export | literal text |
| CAN-0005 | C-01 | URL userinfo password | literal text |
| CAN-0006 | C-03 | unknown imported value | literal text |

CAN-0002 and CAN-0003 are base64 of fixed ASCII seeds
(`RAYLANE-SYNTH-WG-PRIV-0002------` and `RAYLANE-SYNTH-WG-PSK--0003------`),
so the raw bytes are reproducible and are recorded as `raw_hex` in the
registry.

The WireGuard **public** key in B-11 is not a canary and is not a secret.
It is the real Curve25519 public key derived from CAN-0002's private seed,
so the positive case is internally consistent rather than merely
label-shaped. Its derivation was reproduced independently (RFC 7748
X25519) and matches byte-for-byte. Minimisation: it is not logged or
exported as a matter of course, and there is no normative requirement to
log it.

Per the oracle's policy, a canary **must not appear in**: a validation
report, a diagnostic export, logs, or an API read of secret values.

## Safety of the synthetic data

- **No real credentials.** Every secret-shaped string is a clearly marked
  synthetic token. No private key, token or certificate from a real system
  appears here.
- **Reserved address space only.** Hosts are `*.example.test` (RFC 6761).
  IP addresses are RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`), RFC 3849 (`198.51.100.0/24`), RFC 2606 (`127.0.0.1`,
  `0.0.0.0`) and the link-local metadata address `169.254.169.254`.
- **Never fetched.** No fixture is ever to be fetched over the network; the
  URLs are documentation addresses only.
- The `0.0.0.0/0` in `inputs/B-13.wireguard.conf` is a WireGuard
  `AllowedIPs` value inside a `.conf` that the product rejects on import
  (case B-13, `.conf` import is out of scope) — it is not a route.

## Invariants the corpus encodes

- `save != apply`: no save/import/update scenario changes active state.
- No implicit fetch: saving and validating initiate no network load.
- `NOT_RUN` is not `PASS`; `UNVERIFIED` is not passed off as supported.
- `expect.apply` is expected policy, not observation.
- An unknown *field* is not an unknown *format* and not an unsupported
  *protocol*.
- A rejected update does not change the previous nodes or their markers.
- Secrets do not reach reports, exports or logs.

## What this corpus does not do

- It does not execute anything. There is no runner wired to it yet.
- It does not establish product behaviour. `expect` is a specification of
  intent, verified against the spec and the capability matrix, not against a
  running system.
- It does not close GAP-WGKEY.
- It does not claim coverage of the 9 requirements that need a stand.
- It is **not** an acceptance of T003. It is the author's work, pending
  independent review (03) and recheck (04).

## Provenance

| Artifact | SHA-256 |
|---|---|
| `oracle/T003-oracle.json` | `f9840ab765aff72652843f093633b69b81b2ac6c1631cd1d767ed20edd4dd89f` |
| `generate.py` | `2ef224c6528524b060808c6272a8adb477fde53fa61bb7b8b8cd6e553601fef5` |

`manifest.json` carries the sha256 of every file in the corpus, including
`README.md` and `verify.py`, so any drift in the tracked tree is visible
without re-running the generator.

The oracle is 04's artifact (`T003-synthetic-fixture-oracle`, base
`b953b2605eb0d67a38b4432866f33f4d8203b0ba`), vendored byte-for-byte; its
generator reproduces it byte-for-byte. 03 reviewed the oracle and passed
R1–R4 independently, including its own X25519 derivation. `manifest.json`
carries the sha256 of every file in the corpus.
