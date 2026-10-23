# Raylane — capability matrix (T001, G1)

Status: RESEARCH v1, verified 2026-10-23 against Xray-core source at commit
`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74` (tag v26.10.21) and PassWall research in
docs/discovery/. Runtime acceptance: NOT_RUN for every row (no code executed, no
network/host changes — per task constraints). Values: SUPPORTED (present in pinned
source, static evidence cited), UNVERIFIED (plausible but not proven in this pass),
UNSUPPORTED (evidence of absence at this baseline), BLOCKED (cannot be established
within budget → escalate to 01).

Sources: XRAY_TRANSPARENT_CONTRACT.md, PASSWALL_RESEARCH.md, SETTINGS_REFERENCE.md,
CONNECTION_GAPS.md (fixed commit 1b1647cd), live re-checks of the same files via
raw.githubusercontent.com on 2026-10-23.

## FR-001 — node types VLESS / SOCKS5 / HTTP-proxy / WireGuard

| Capability | Status | Evidence |
|---|---|---|
| VLESS outbound | SUPPORTED | infra/conf/vless.go; proxy/vless/outbound @1b1647cd |
| SOCKS5 outbound (no-auth + user/pass) | SUPPORTED | proxy/socks/client.go @1b1647cd (SETTINGS_REFERENCE.md:128) |
| HTTP outbound (plain + TLS) | SUPPORTED | infra/conf transport_internet/http outbound + proxy/http |
| WireGuard outbound (in-engine) | SUPPORTED | golang.zx2c4.com/wireguard pinned in go.mod; infra/conf/wireguard.go (SETTINGS_REFERENCE.md:128). FR-008 scope (single peer, no .conf import) is a product constraint, engine is not the limiter. |

## FR-002 — VLESS transports / security / flow

| Capability | Status | Evidence |
|---|---|---|
| raw (tcp) | SUPPORTED | transport_internet config |
| mkcp | SUPPORTED | transport_internet config (kcp) |
| ws | SUPPORTED | gorilla/websocket v1.5.3; transport ws |
| grpc | SUPPORTED | transport/internet/grpc tree @1b1647cd; module google.golang.org/grpc v1.84.0 pinned in Xray go.mod (Origin: grpc/grpc-go tag v1.84.0, hash e84aa5ab15d1d2b29d54f838312ad490cb7551a8, proxy.golang.org .info 200, 2026-10-23) |
| httpupgrade | SUPPORTED | transport_internet.go |
| xhttp | SUPPORTED | XHTTP present at baseline (CONNECTION_GAPS / XR tree) |
| TLS | SUPPORTED | infra/conf transport_internet TLSConfig |
| REALITY | SUPPORTED | xtls/reality pinned v0.0.0-20261014101318-83f621788ca8 (complete version; proxy.golang.org Origin hash 83f621788ca88b83179810b12baa7ae518aacb83); infra conf |
| flow "" | SUPPORTED | outbound.go normalization (SETTINGS_REFERENCE.md:149) |
| flow xtls-rprx-vision | SUPPORTED | proxy/vless/outbound/outbound.go L246-275 @1b1647cd |
| flow xtls-rprx-vision-udp443 | SUPPORTED (with documented UDP/443 rejection semantics for plain vision) | same source; vision-udp443 sets allowUDP443 |
| Arbitrary combination validity | UNSUPPORTED BY DESIGN | FR-002 itself: options ≠ all combos valid (D-009–012); validation matrix is a T006+ task, not a source capability. |

## FR-003 — VLESS extras

| Capability | Status | Evidence |
|---|---|---|
| XHTTP Extra | SUPPORTED | XHTTP (splithttp) tree present at baseline: transport/internet/splithttp/* @1b1647cd; Extra options surfaced via splithttp config (contract test T005) |
| FinalMask (stream-level masks) | SUPPORTED (mechanism exists at streamSettings level) | transport/internet/finalmask/* tree present @1b1647cd (verified via git trees API 2026-10-23: subdirs filter, fragment, header, mkcp, noise, realm, salamander, sudoku, udphop, xdns, xicmp, xmc); JSON surface: `streamSettings.finalmask {tcp:[], udp:[], quicParams:{}}` — infra/conf/transport_internet.go L56/L242–270 and infra/conf/transport_finalmask.go L1303–1307 (`type FinalMask struct`). Per-mask config JSON shape for each mask type: UNVERIFIED in detail (contract test T005). |
| ALPN | SUPPORTED | TLSConfig alpn |
| uTLS / fingerprint | SUPPORTED | refraction-networking/utls v1.8.3-… pinned; TLSConfig fingerprint |
| chain SHA256 pin | SUPPORTED | TLSConfig pinnedPeerCertChainSha256 (SETTINGS_REFERENCE) |
| verify name / PEM | SUPPORTED | TLSConfig serverName / certificate PEM checks |
| cipher suites | SUPPORTED | TLSConfig cipherSuites |
| ECH | SUPPORTED | ech config in TLSConfig at baseline (26.x) |
| REALITY ML-DSA-65 | SUPPORTED | mldsa65 verify keys in REALITY config (26.8+ feature, present in v26.10.21) |
| Mux / concurrency / XUDP concurrency | SUPPORTED | infra/conf MuxConfig (enabled/concurrency/xudpConcurrency) |
| allowInsecure passthrough from subscription | UNVERIFIED | PASSWALL_RESEARCH.md:66 — PassWall UI promises it; no direct equivalent confirmed in read Xray forms; engine supports allowInsecure in TLS settings, but semantic parity with PassWall flag NOT proven. Flagged open question; not a blocker for engine baseline (we generate our own configs). |

## FR-004 — per-node DNS of node name (Auto/TCP/UDP/DoH; strategies; Happy Eyeballs)

| Capability | Status | Evidence |
|---|---|---|
| Outbound domain resolver / domainStrategy | SUPPORTED | transport internet DomainStrategy (AsIs/UseIP/UseIPv4/UseIPv6…) and freedom/outbound resolver settings at baseline |
| TCP/UDP/DoH query types for node DNS | SUPPORTED | Xray internal DNS config supports tcp/udp/doh servers (dns conf) |
| Strategy Auto / IPv4-first / IPv6-first / v4-only / v6-only | SUPPORTED | domainStrategy variants incl. ForceIP/UseIPv4v6 |
| Happy Eyeballs (RFC 8305 interleaving) | UNVERIFIED | Xray has TryIP/UseIPv4v6 concurrent-dial behavior (happy eyeballs-like) but exact RFC 8305 parity and the "manual strategy disabled when HE on" product rule are OUR validation layer; engine-side mapping must be verified at contract test time (T005+). Not a baseline blocker. |

## FR-005 — TFO / MPTCP

| Capability | Status | Evidence |
|---|---|---|
| TCP Fast Open socket option | SUPPORTED | transport_internet sockopt tcpFastOpen (config.proto/transport settings) |
| MPTCP socket option | SUPPORTED | sockopt mptcp present in 26.x transport config |
| Kernel auto-provisioning | UNSUPPORTED BY DESIGN | FR-005: off by default, no automatic kernel/interface/route setup (D-021/D-048). Helper may expose explicit, admin-confirmed sysctl actions later — separate gated task. |
| Runtime effect on Ubuntu 24.04 kernel 6.8 | UNVERIFIED | design-level only; TPROXY path test task (not this one). |

## FR-006 — chain modes (off / pre-node / landing / outbound interface; one extra layer)

| Capability | Status | Evidence |
|---|---|---|
| Outbound chaining via proxySettings / dialerProxy | SUPPORTED | proxyman outbound proxySettings tag chaining (1 extra layer enforceable in our config generator) |
| sendThrough / outbound interface binding | SUPPORTED | transport internet sendThrough / sockopt interface at baseline |
| Cycle/reference validation | OUR LAYER | engine rejects broken references at start; semantic cycle detection is T006 domain logic. SUPPORTED to implement. |

## FR-007 — SOCKS5/HTTP auth & HTTP TLS extras

| Capability | Status | Evidence |
|---|---|---|
| SOCKS5 noauth + password | SUPPORTED | socks client accounts |
| HTTP proxy noauth + basic | SUPPORTED | http outbound accounts |
| HTTP over TLS (SNI, ALPN, uTLS, chain pin, verify name, PEM, cipher suites, ECH) | SUPPORTED | same TLSConfig surface as FR-003 applied to http outbound streamSettings |
| REALITY for HTTP outbound | UNSUPPORTED BY PRODUCT | FR-007/D-045: not approved; engine wouldn't forbid, our validator must reject. |

## FR-008 — WireGuard single-peer fields

| Capability | Status | Evidence |
|---|---|---|
| endpoint, pub/priv keys, optional PSK, local addresses, MTU, reserved, keepalive | SUPPORTED | infra/conf/wireguard.go fields at baseline |
| FinalMask JSON (off by default) | SUPPORTED — mapping established from pinned source (M4 fix) | WireGuard outbound applies stream-level FinalMask to its UDP dial: proxy/wireguard/client.go L149–150 @1b1647cd (`if streamSettings.FinalMask != nil { conn, err := streamSettings.FinalMask.DialUDP(ctx, dest) }`). Stream-level FinalMask JSON is `streamSettings.finalmask{tcp,udp,quicParams}` (infra/conf/transport_internet.go L56, infra/conf/transport_finalmask.go L1303–1307); mask implementations live in transport/internet/finalmask/{noise,realm,salamander,sudoku,xmc,xicmp,xdns,filter,fragment,header,mkcp,udphop}. FR-008's "FinalMask JSON, off by default" maps to: our WireGuard node model emits `streamSettings.finalmask.udp` entries only when the admin enables it (default: absent → plain UDP dial, client.go L156 fallback). NOTE: round-1's cited "noisetls/noiseqq" identifiers were NOT found in the pinned source and are removed (M4). Which specific mask types are semantically valid for WireGuard UDP: UNVERIFIED beyond `DialUDP` presence — per-mask validation is a T005 contract test. |
| System WireGuard / .conf import | UNSUPPORTED BY PRODUCT | D-049–051. |

## FR-017 / FR-019 (subscription & list prerequisites relevant to capabilities)

| Capability | Status | Evidence |
|---|---|---|
| Engine has no subscription fetcher | BY DESIGN | fetching is our control-plane (R-07/D-061 policy); engine only consumes generated config. SUPPORTED to implement. |
| socks5h-style proxy fetch without direct fallback (D-060) | SUPPORTED | our fetcher policy; engine freedom/socks dialers support it where a proxy fetch is allowed. |

## FR-020 prerequisites (dataplane)

| Capability | Status | Evidence |
|---|---|---|
| nft tproxy in userspace nftables 1.0.9 + kernel 6.8 (noble) | SUPPORTED (design) | tproxy statement long-stable; runtime NOT_RUN |
| Xray transparent inbound: dokodemo-door/tunnel with tproxy sockopt | SUPPORTED | transport config.proto TProxyMode (off/TProxy/Redirect); dokodemo FollowRedirect→ReceiveOriginalDestination; sniffing config present (re-verified 2026-10-23, infra/conf/xray.go) |
| dnsmasq 2.90 nftset | SUPPORTED (package-level); runtime re-check `dnsmasq --version` pending on stand | versions.lock §5 |
| IPv6 profile | BLOCKED → gate open | R-03: IPv6 transit/profile unproven; this research adds no evidence. Enabling remains rejected-with-reason until synthetic stand proof. Escalation path per 01. |

## FR-021 prerequisites (security/storage stack)

| Capability | Status | Evidence |
|---|---|---|
| AEAD secret storage in Go (x/crypto chacha20poly1305 / aes-gcm) | SUPPORTED | golang.org/x/crypto v0.58.0 license BSD-3-Clause |
| SQLite single-file store (modernc.org/sqlite v1.61.0) | SUPPORTED (static) | versions.lock §4 — exact pin v1.61.0, gitlab commit 4df1ebea0f1cf0cd6ec3245b26f5fec4234ce738, BSD-3-Clause-style license, go 1.26.0 directive compatible with go1.27.3; build/integration NOT_RUN (T002) |
| TLS-terminating LAN UI (Go net/http) | SUPPORTED | stdlib |

## Summary of gates

- Pre-existing open gates: IPv6 profile (R-03), upstream binary as trusted path (REJECTED by 01 round-1; build-from-source only), npm closure (T002), Happy Eyeballs exact parity (contract tests), allowInsecure parity (UNRESOLVED).
- Revision-1 gaps now CLOSED: exact SQLite pin (v1.61.0), exact Ubuntu noble package versions with pockets (dnsmasq 2.91-0ubuntu0.24.04.2, nftables 1.0.9-1ubuntu0.1, iproute2 6.1.0-1ubuntu6.4), complete pseudo-versions for utls/reality/quic-go/ghodss-yaml, grpc in lock, FinalMask→FR-008 mapping from pinned source, dnsmasq nftset build-config evidence.
- UNVERIFIED rows above are scheduled checks (T002/T005+/stand), not promises.
- No unsupported ENGINE capability found for the FR-001–008 in-scope surface at baseline v26.10.21; product-level rejections (REALITY for HTTP, system WireGuard, arbitrary chain length) are by design and enforced in our validation layer.
- Static toolchain compatibility only: Xray go.mod requires `go 1.27`, upstream builds with 1.27.x, pinned toolchain go1.27.3 ≥ requirement. An actual build was NOT performed (M2) — build validation is a T002 gate and remains NOT_RUN.
- Open gaps (honest list, not "no blockers"): exact per-mask FinalMask JSON semantics for WireGuard UDP (UNVERIFIED, T005), allowInsecure parity (UNRESOLVED), Happy Eyeballs RFC parity (UNVERIFIED), IPv6 profile (BLOCKED→gate), runtime dnsmasq/nft stand checks (NOT_RUN), our own dependency closure (OPEN, T002).
