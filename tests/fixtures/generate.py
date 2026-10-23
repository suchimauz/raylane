#!/usr/bin/env python3
"""Deterministic generator for tests/fixtures/** (T003).

Derives the tracked fixture corpus from the vendored T003 oracle
(oracle/T003-oracle.json).  The oracle is the ONLY source of expected
semantics.  This generator adds nothing to it: every `expect` block, every
`trace` tag, every `cap` and every runtime marker is copied verbatim.

What this generator DOES add is a concrete, deterministic synthetic INPUT
for each of the 56 case ids.  Where the oracle's `input.value` is already
a concrete protocol input, that exact value is used.  Where it is a
placeholder or a prose description, it is EXPANDED here into a concrete
payload and the expansion is recorded in the case file so a reviewer can
see exactly what was added and why.

No network, no product runtime, no real credentials.  Every host is
.example.test (RFC 6761) or an RFC 5737 / 3849 / 2606 documentation
address.  Every secret-shaped string is a clearly marked synthetic token.

Usage:  python3 generate.py [OUTPUT_DIR]
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# The oracle lives next to the generator once it is vendored into
# tests/fixtures/.  In this scratch build it is read from the tracked copy.
ORACLE_PATH = next(
    (p for p in (HERE / "oracle" / "T003-oracle.json",
                 HERE.parent.parent.parent.parent.parent / "tests" / "fixtures" / "oracle" / "T003-oracle.json")
     if p.exists()),
    None,
)
if ORACLE_PATH is None:
    raise SystemExit("oracle/T003-oracle.json not found")

# --- synthetic constants (identical to the oracle's) ----------------------
WG_PRIV_B64 = "UkFZTEFORS1TWU5USC1XRy1QUklWLTAwMDItLS0tLS0="
WG_PUB_B64 = "936MaZHZsLaibKy96xJ1DQvbqAYZyC2r8LVb5gOma0Q="
WG_PSK_B64 = "UkFZTEFORS1TWU5USC1XRy1QU0stLTAwMDMtLS0tLS0="

# --- concrete expansions for the placeholder oracle inputs ----------------
# A-03: "BASE64(SYNTH-LIST-3-URIS)" -> a real base64 payload of 3 URIs.
SUB_LIST_PLAIN = "\n".join([
    "vless://11111111-2222-3333-4444-555555555555@node1.example.test:443"
    "?type=raw&security=tls&sni=cdn.example.test#SynthNodeA",
    "vless://22222222-3333-4444-5555-666666666666@node2.example.test:443"
    "?type=ws&security=tls&path=%2Fsynth&sni=cdn.example.test#SynthNodeB",
    "vless://33333333-4444-5555-6666-777777777777@node3.example.test:443"
    "?type=grpc&security=tls&sni=cdn.example.test#SynthNodeC",
]) + "\n"
SUB_LIST_B64 = base64.b64encode(SUB_LIST_PLAIN.encode("utf-8")).decode("ascii")

# A-04: "proxies: [VLESS], rules: [...], dns: {...}" -> a real Clash/Mihomo
# YAML document that carries all three sections.
CLASH_YAML = """# SYNTHETIC fixture input -- not a real subscription, never fetched.
proxies:
  - name: SynthNodeA
    type: vless
    server: node1.example.test
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    network: ws
    tls: true
    servername: cdn.example.test
    ws-opts:
      path: /synth
  - name: SynthNodeB
    type: socks5
    server: node2.example.test
    port: 1080
rules:
  - DOMAIN-SUFFIX,example.test,DIRECT
  - IP-CIDR,198.51.100.0/24,DIRECT,no-resolve
  - MATCH,PROXY
dns:
  enable: true
  ipv6: false
  nameserver:
    - 198.51.100.53
"""

# G-03: "vless://...&allowInsecure=1" -> a full VLESS URI carrying that flag.
VLESS_ALLOWINSECURE_URI = (
    "vless://11111111-2222-3333-4444-555555555555@node1.example.test:443"
    "?type=raw&security=tls&sni=cdn.example.test&allowInsecure=1#SynthNodeA"
)

# B-13: "[Interface]\\nPrivateKey=..." -> a real (synthetic) .conf document.
WG_CONF = """[Interface]
PrivateKey = UkFZTEFORS1TWU5USC1XRy1QUklWLTAwMDItLS0tLS0=
Address = 192.0.2.2/32
DNS = 198.51.100.53

[Peer]
PublicKey = 936MaZHZsLaibKy96xJ1DQvbqAYZyC2r8LVb5gOma0Q=
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0
"""

# --- concrete node templates used to fill the "manual" oracle inputs -----
VLESS_UUID = "11111111-2222-3333-4444-555555555555"


def vless_node(**over):
    n = {
        "protocol": "vless",
        "label": "SynthNodeA",
        "endpoint": "node1.example.test:443",
        "uuid": VLESS_UUID,
        "transport": "raw",
        "security": "tls",
        "sni": "cdn.example.test",
        "flow": "",
        "tls": {
            "serverName": "cdn.example.test",
            "allowInsecure": False,
            "alpn": ["h2", "http/1.1"],
        },
    }
    n.update(over)
    return n


def socks_node(**over):
    n = {
        "protocol": "socks5",
        "label": "SynthNodeSocks",
        "endpoint": "node2.example.test:1080",
        "auth": "none",
    }
    n.update(over)
    return n


def http_node(**over):
    n = {
        "protocol": "http",
        "label": "SynthNodeHttp",
        "endpoint": "node3.example.test:8080",
        "security": "none",
        "tls": False,
    }
    n.update(over)
    return n


def wg_node(**over):
    n = {
        "protocol": "wireguard",
        "label": "SynthNodeWg",
        "endpoint": "203.0.113.10:51820",
        "publicKey": WG_PUB_B64,
        "privateKey": WG_PRIV_B64,
        "presharedKey": WG_PSK_B64,
        "localAddresses": ["192.0.2.2/32"],
        "mtu": 1420,
        "reserved": [0, 0, 0],
        "keepAlive": 25,
        "finalMask": None,
    }
    n.update(over)
    return n


# --- candidate lists for the E / J families -------------------------------
def cand(label, fid, source_id="sub-0001", stable_id=None, broken=False):
    n = {
        "label": label,
        "protocol": "vless",
        "endpoint": f"{label.lower()}.example.test:443",
        "uuid": VLESS_UUID,
        "sourceId": source_id,
        "keyedFingerprint": fid,
    }
    if stable_id is not None:
        n["sourceStableId"] = stable_id
    if broken:
        n["endpoint"] = ""
        n["uuid"] = "not-a-uuid"
    return n


CAND_E01 = []
CAND_E02 = [
    cand("SynthNodeA", "fp-0001"),
    cand("SynthNodeB", "fp-0002", broken=True),
    cand("SynthNodeC", "fp-0003"),
]
CAND_E03 = [cand("SynthNodeB", "fp-0002"), cand("SynthNodeC", "fp-0003")]
CAND_E04 = [cand("SynthNodeA", "fp-dup"), cand("SynthNodeB", "fp-dup")]
CAND_E05 = [cand("SynthNodeA-renamed", "fp-0001", stable_id="stable-0001")]
CAND_J01 = [cand("SynthNodeA", "fp-0001"), cand("SynthNodeB", "fp-0002"),
            cand("SynthNodeC", "fp-0003")]
CAND_J02 = list(CAND_J01)
CAND_J03 = list(CAND_J01)
CAND_J04 = [
    cand("SynthNodeA", "fp-0001"),
    cand("SynthNodeB", "fp-0002"),
    cand("drop-SynthNodeD", "fp-0004"),
    cand("SynthNodeE", "fp-0005"),
]

# --- the fixture table ----------------------------------------------------
# fixture_kind:
#   literal    -> bytes live in inputs/<ID>.<ext>; payload is the file path
#   structured -> payload is an inline JSON object (node / candidate / action)
#   scenario   -> payload is an inline JSON object of concrete parameters
# assertion:
#   exact     -> oracle input.value must equal the file content
#   contains  -> every token must appear in the file content
#   fields    -> every oracle input key (except "kind") must match exactly
E = "exact"
C = "contains"
F = "fields"

FIX = {
    # ---------------- A. parse / format ----------------
    "A-01": dict(kind="literal", ext="txt", name="vless-uri", assertion=E),
    "A-02": dict(kind="literal", ext="json", name="malformed", assertion=E),
    "A-03": dict(kind="literal", ext="b64", name="subscription-list",
                 assertion=C, tokens=[], decoded_tokens=["vless://"],
                 expansion="placeholder 'BASE64(SYNTH-LIST-3-URIS)' replaced by the real base64 of a three-URI list"),
    "A-04": dict(kind="literal", ext="yaml", name="clash", assertion=C,
                 tokens=["proxies:", "rules:", "dns:"],
                 expansion="placeholder 'proxies: [VLESS], rules: [...], dns: {...}' replaced by a real Clash/Mihomo document carrying all three sections"),
    "A-05": dict(kind="literal", ext="txt", name="unknown-format", assertion=E),
    # ---------------- B. protocols and fields ----------------
    "B-01": dict(kind="structured", assertion=F,
                 payload=vless_node(transport="ws", wsPath="/synth",
                                    flow="xtls-rprx-vision")),
    "B-02": dict(kind="structured", assertion=F,
                 payload=vless_node(transport="quic-legacy")),
    "B-03": dict(kind="structured", assertion=F,
                 payload=vless_node(flow="")),
    "B-04": dict(kind="structured", assertion=F,
                 payload=vless_node(flow="xtls-rprx-direct")),
    "B-05": dict(kind="structured", assertion=F,
                 payload=vless_node(transport="xhttp", security="reality",
                                    flow="xtls-rprx-vision")),
    "B-06": dict(kind="structured", assertion=F,
                 payload=socks_node(auth="none")),
    "B-07": dict(kind="structured", assertion=F,
                 payload=socks_node(auth="userpass", username="",
                                    password="SYNTH-CANARY-0001-DO-NOT-USE")),
    "B-08": dict(kind="structured", assertion=F,
                 payload=socks_node(auth="userpass", username="synthuser",
                                    password="")),
    "B-09": dict(kind="structured", assertion=F,
                 payload=http_node(tls=True, ech=True,
                                   alpn=["h2", "http/1.1"])),
    "B-10": dict(kind="structured", assertion=F,
                 payload=http_node(security="reality")),
    "B-11": dict(kind="structured", assertion=F, payload=wg_node()),
    "B-12": dict(kind="structured", assertion=F,
                 payload=wg_node(reserved=[0, 0])),
    "B-13": dict(kind="literal", ext="conf", name="wireguard", assertion=C,
                 tokens=["[Interface]", "PrivateKey"],
                 expansion="placeholder '[Interface]\\nPrivateKey=...' replaced by a real .conf document"),
    "B-14": dict(kind="literal", ext="txt", name="trojan-uri", assertion=E),
    # ---------------- C. secrets and redaction ----------------
    "C-01": dict(kind="literal", ext="txt", name="subscription-url", assertion=E),
    "C-02": dict(kind="structured", assertion=F,
                 payload={"action": "diagnostic-export",
                          "artifact": "diagnostics",
                          "format": "json",
                          "required_absent": ["SYNTH-CANARY-0004-DO-NOT-USE"]}),
    "C-03": dict(kind="structured", assertion=F,
                 payload=vless_node(unknownField="SYNTH-CANARY-0006-DO-NOT-USE")),
    # ---------------- D. fetch and network policy ----------------
    "D-01": dict(kind="scenario", assertion=F,
                 payload={"request": {"method": "GET",
                                      "url": "https://subs.example.test/list.txt",
                                      "headers": {"Authorization": "Bearer SYNTH-AUTH-TOKEN-DO-NOT-USE",
                                                  "Cookie": "session=SYNTH-SESSION-DO-NOT-USE"}},
                          "response": {"status": 302,
                                        "location": "https://other.example.test/x"},
                          "carried_credentials": ["Authorization", "Cookie"]}),
    "D-02": dict(kind="literal", ext="txt", name="loopback-url", assertion=E),
    "D-03": dict(kind="literal", ext="txt", name="link-local-url", assertion=E),
    "D-04": dict(kind="literal", ext="txt", name="private-lan-url", assertion=E),
    "D-05": dict(kind="scenario", assertion=F,
                 payload={"request": {"method": "GET",
                                      "url": "https://subs.example.test/list.txt"},
                          "response": {"status": 302,
                                        "location": "http://plain.example.test/list.txt"},
                          "final_url": "http://plain.example.test/list.txt"}),
    "D-06": dict(kind="scenario", assertion=F,
                 payload={"request": {"method": "GET",
                                      "url": "https://subs.example.test/list.txt",
                                      "viaProxy": {"scheme": "http",
                                                   "endpoint": "203.0.113.10:3128"}},
                          "transport_error": "connection refused"}),
    "D-07": dict(kind="scenario", assertion=F,
                 payload={"accessMode": "auto", "serviceRouteRef": None}),
    "D-08": dict(kind="structured", assertion=F,
                 payload={"action": "save node", "subject": vless_node()}),
    "D-09": dict(kind="literal", ext="txt", name="loopback-allowlisted", assertion=F),
    "D-10": dict(kind="literal", ext="txt", name="public-outside-allowlist", assertion=F),
    # ---------------- E. reconciliation ----------------
    "E-01": dict(kind="structured", assertion=C,
                 payload={"candidate": CAND_E01}, tokens=[],
                 expansion="prose 'empty list' replaced by the concrete empty candidate list"),
    "E-02": dict(kind="structured", assertion=C,
                 payload={"candidate": CAND_E02}, tokens=[],
                 expansion="prose 'valid, BROKEN, valid' replaced by a concrete three-node candidate whose middle node is broken"),
    "E-03": dict(kind="structured", assertion=C,
                 payload={"candidate": CAND_E03,
                          "activeRuleReferences": "SynthNodeA"},
                 tokens=[],
                 expansion="prose 'node disappeared, referenced by active rule' replaced by a concrete candidate missing that node plus the active rule that references it"),
    "E-04": dict(kind="structured", assertion=C,
                 payload={"candidate": CAND_E04}, tokens=[],
                 expansion="prose 'two nodes same fingerprint' replaced by a concrete candidate with two identical keyed fingerprints"),
    "E-05": dict(kind="structured", assertion=C,
                 payload={"candidate": CAND_E05}, tokens=[],
                 expansion="prose 'same sourceStableId, new label' replaced by a concrete candidate carrying that stable id under a new label"),
    # ---------------- F. state and apply semantics ----------------
    "F-01": dict(kind="structured", assertion=F,
                 payload={"action": "save invalid node",
                          "subject": vless_node(transport="quic-legacy")}),
    "F-02": dict(kind="structured", assertion=F,
                 payload={"action": "save then read active",
                          "subject": vless_node(),
                          "readTarget": "active"}),
    "F-03": dict(kind="structured", assertion=F,
                 payload=vless_node(chain="cycle")),
    "F-04": dict(kind="structured", assertion=F,
                 payload={"protocol": "vless", "chain": "3 layers"}),
    "F-05": dict(kind="structured", assertion=F,
                 payload={"action": "delete referenced node",
                          "subject": {"label": "SynthNodeA",
                                      "referencedBy": "active rule"}}),
    # ---------------- G. capability gates / UNVERIFIED ----------------
    "G-01": dict(kind="structured", assertion=F,
                 payload=vless_node(dns={"happyEyeballs": True,
                                        "strategy": "ipv4-only"})),
    "G-02": dict(kind="structured", assertion=F,
                 payload=wg_node(finalMask={"udp": [{"type": "synth"}]})),
    "G-03": dict(kind="literal", ext="txt", name="allowinsecure-uri",
                 assertion=C, tokens=["vless://", "allowInsecure=1"],
                 expansion="placeholder 'vless://...&allowInsecure=1' replaced by a full VLESS URI carrying that flag"),
    "G-04": dict(kind="structured", assertion=F,
                 payload=vless_node(endpoint="[2001:db8::10]:443")),
    # ---------------- H. field edge cases ----------------
    "H-01": dict(kind="structured", assertion=F,
                 payload=wg_node(mtu=99999)),
    "H-02": dict(kind="structured", assertion=F,
                 payload=vless_node(tfo=None, mptcp=None)),
    "H-03": dict(kind="structured", assertion=F,
                 payload=vless_node(inactiveFields={"sni": "inactive.example.test"})),
    # ---------------- I. rules (FR-020) ----------------
    "I-01": dict(kind="structured", assertion=F,
                 payload={"rules": ["block example.test", "direct example.test",
                                    "proxy example.test"]}),
    "I-02": dict(kind="scenario", assertion=F,
                 payload={"classification": "not ready",
                          "affectedClients": ["192.0.2.2"]}),
    "I-03": dict(kind="scenario", assertion=F,
                 payload={"operation": "stop", "mode": "normal"}),
    # ---------------- J. filters (FR-013) ----------------
    "J-01": dict(kind="structured", assertion=F,
                 payload={"candidate": CAND_J01,
                          "filter": {"mode": "keep", "pattern": "nomatch-*"}},
                 tokens=[],
                 expansion="prose '3 nodes, none match' replaced by the concrete candidate the filter is applied to"),
    "J-02": dict(kind="structured", assertion=F,
                 payload={"candidate": CAND_J02,
                          "filter": {"mode": "keep", "pattern": ""}},
                 tokens=[],
                 expansion="prose '3 nodes' replaced by the concrete candidate the filter is applied to"),
    "J-03": dict(kind="structured", assertion=F,
                 payload={"candidate": CAND_J03,
                          "filter": {"mode": "discard", "pattern": "SynthNodeA"},
                          "activeNode": "SynthNodeA"},
                 tokens=[],
                 expansion="prose 'active node matches' replaced by the concrete candidate plus the active node it names"),
    "J-04": dict(kind="structured", assertion=F,
                 payload={"candidate": CAND_J04,
                          "filter": {"mode": "both", "keep": "*", "discard": "drop-*"}},
                 tokens=[],
                 expansion="prose '4 nodes' replaced by the concrete candidate the filter is applied to"),
}

# --- literal file contents for the expanded placeholders ------------------
LITERAL_FILES = {
    "A-03": {"inputs/A-03.subscription-list.b64": SUB_LIST_B64,
             "inputs/A-03.subscription-list.txt": SUB_LIST_PLAIN},
    "A-04": {"inputs/A-04.clash.yaml": CLASH_YAML},
    "B-13": {"inputs/B-13.wireguard.conf": WG_CONF},
    "G-03": {"inputs/G-03.allowinsecure-uri.txt": VLESS_ALLOWINSECURE_URI},
}

# --- canary registry (6 exact canaries from the oracle) -------------------
# The values, raw_hex and forms are copied byte-for-byte from the oracle.
# `exercised_in` records every case whose fixture carries the value; the
# oracle names one case per canary, the fixture may exercise it in more.
# The registry is copied from the oracle verbatim: 6 canaries, one case
# each, exactly as 04 registered them.  Nothing here re-registers a canary
# under a field it was not registered for.
EXTRA_EXERCISED = {}


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def build(out: Path) -> int:
    oracle = json.loads(ORACLE_PATH.read_text(encoding="utf-8"))
    cases = {c["id"]: c for c in oracle["cases"]}
    missing = sorted(set(cases) - set(FIX))
    extra = sorted(set(FIX) - set(cases))
    if missing or extra:
        raise SystemExit(f"fixture table mismatch: missing={missing} extra={extra}")

    (out / "oracle").mkdir(parents=True, exist_ok=True)
    (out / "inputs").mkdir(parents=True, exist_ok=True)
    (out / "cases").mkdir(parents=True, exist_ok=True)
    (out / "canaries").mkdir(parents=True, exist_ok=True)

    # 1. vendored oracle, byte-identical to the artifact 04 published.
    dst = out / "oracle" / "T003-oracle.json"
    dst.write_bytes(ORACLE_PATH.read_bytes())

    # 2. literal input files.
    written = set()
    for cid, spec in FIX.items():
        if spec["kind"] != "literal":
            continue
        oc = cases[cid]
        value = oc["input"]["value"]
        if cid in LITERAL_FILES:
            for rel, content in LITERAL_FILES[cid].items():
                (out / rel).write_text(content, encoding="utf-8")
                written.add(rel)
            # the primary file is the one the case references; it is the
            # first entry of LITERAL_FILES, declared in the same order as
            # the fixture table.
            spec["_primary"] = sorted(LITERAL_FILES[cid])[0]
        else:
            rel = f"inputs/{cid}.{spec['ext']}"
            (out / rel).write_text(value, encoding="utf-8")
            written.add(rel)
            spec["_primary"] = rel

    # 3. canary registry.
    registry = []
    for can in oracle["canary_registry"]:
        entry = dict(can)
        exercised = [can["case"]] + EXTRA_EXERCISED.get(can["id"], [])
        entry["oracle_case"] = can["case"]
        entry["exercised_in"] = exercised
        entry["do_not_use"] = True
        registry.append(entry)
    (out / "canaries" / "registry.json").write_text(
        json.dumps({"prefix": oracle["canary_policy"]["prefix"],
                    "rule": oracle["canary_policy"]["rule"],
                    "must_not_appear_in": oracle["canary_policy"]["must_not_appear_in"],
                    "canaries": registry},
                   ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 4. case files.
    for cid in sorted(FIX):
        spec = FIX[cid]
        oc = cases[cid]
        oracle_input = oc["input"]
        payload = spec.get("payload")
        if spec["kind"] == "literal":
            rel = spec["_primary"]
            content = (out / rel).read_text(encoding="utf-8")
            payload_block = {"kind": "file", "path": rel, "encoding": "utf-8"}
            for k, v in oracle_input.items():
                if k in ("kind", "value"):
                    continue
                payload_block[k] = v
            if spec["assertion"] == E:
                if content != oracle_input["value"]:
                    raise SystemExit(f"{cid}: literal content != oracle value")
            elif spec["assertion"] == F:
                for k, v in oracle_input.items():
                    if k in ("kind", "value"):
                        continue
                    if payload_block.get(k) != v:
                        raise SystemExit(
                            f"{cid}: oracle field {k}={v!r} != payload {payload_block.get(k)!r}")
            else:
                for tok in spec["tokens"]:
                    if tok not in content:
                        raise SystemExit(f"{cid}: token {tok!r} missing")
                for tok in spec.get("decoded_tokens", []):
                    try:
                        dec = base64.b64decode(content, validate=True).decode("utf-8")
                    except Exception as exc:
                        raise SystemExit(f"{cid}: not valid base64: {exc}")
                    if tok not in dec:
                        raise SystemExit(f"{cid}: decoded token {tok!r} missing")
            # payload_block carries every structured oracle key (e.g. the
            # per-source allowlist): dropping one would drop the very
            # thing the case tests.
            input_block = {"kind": oracle_input["kind"],
                           "payload": payload_block,
                           "oracle_value": oracle_input["value"],
                           "concrete": True}
        else:
            input_block = {"kind": oracle_input["kind"],
                           "payload": payload,
                           "oracle_value": oracle_input.get("value"),
                           "concrete": True}
            if spec["assertion"] == F:
                # Compare only the oracle keys that carry STRUCTURED data.
                # The oracle's "value" is a prose label for these cases
                # ("save node", "3 layers", ...) and is carried verbatim in
                # oracle_value; it is not a payload field.
                for k, v in oracle_input.items():
                    if k in ("kind", "value"):
                        continue
                    if payload.get(k) != v:
                        raise SystemExit(
                            f"{cid}: oracle field {k}={v!r} != payload {payload.get(k)!r}")
            elif spec["assertion"] == C:
                for tok in spec.get("tokens", []):
                    if tok not in json.dumps(payload, ensure_ascii=False):
                        raise SystemExit(f"{cid}: token {tok!r} missing from payload")

        rec = {
            "id": cid,
            "family": oc["family"],
            "title": oc["title"],
            "klass": oc["klass"],
            "fail_closed": oc["fail_closed"],
            "unsupported": oc["unsupported"],
            "cap": oc["cap"],
            "trace": oc["trace"],
            "outcome": oc["outcome"],
            "fixture_kind": spec["kind"],
            "input": input_block,
            "expect": oc["expect"],
            "expect_apply_policy": oc["expect"]["apply"],
            "expect_apply_is_policy_not_observation": True,
            "runtime_status": oc["runtime_status"],
            "apply_observation": oc["apply_observation"],
            "canaries": oc["canaries"],
            "oracle_ref": {"file": "oracle/T003-oracle.json", "case": cid},
            "synthetic": True,
            "never_fetch": True,
        }
        if "expansion" in spec:
            rec["input"]["expansion_note"] = spec["expansion"]
        (out / "cases" / f"{cid}.json").write_text(
            json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    return len(FIX)


def manifest(out: Path) -> dict:
    oracle = json.loads(ORACLE_PATH.read_text(encoding="utf-8"))
    files = {}
    for p in sorted(out.rglob("*")):
        # manifest.json is excluded: it carries these digests.
        if p.is_file() and p.name != "manifest.json":
            files[str(p.relative_to(out))] = sha256_file(p)
    return {
        "task": "T003",
        "generator": "generate.py",
        "generator_sha256": sha256_file(HERE / "generate.py"),
        "oracle": {
            "file": "oracle/T003-oracle.json",
            "sha256": sha256_file(out / "oracle" / "T003-oracle.json"),
            "author": oracle["author"],
            "status": oracle["status"],
        },
        "counts": {
            "cases": len(list((out / "cases").glob("*.json"))),
            "canaries": len(json.loads((out / "canaries" / "registry.json").read_text())["canaries"]),
            "input_files": len(list((out / "inputs").glob("*"))),
        },
        "coverage": oracle["coverage"],
        "known_gaps": oracle["known_gaps"],
        "runtime_status": {"all_cases": "NOT_RUN",
                           "apply_observation": None,
                           "execution_count": 0},
        "files": files,
    }


if __name__ == "__main__":
    target = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else HERE
    n = build(target)
    (target / "manifest.json").write_text(
        json.dumps(manifest(target), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    print(f"cases written: {n}")
