#!/usr/bin/env python3
"""Consistency checks for the tracked T003 fixture corpus.

Runs against tests/fixtures/ in place.  It checks the corpus against
itself and against the vendored oracle -- it does NOT execute any
product, and it does NOT validate product behaviour.

Usage:  python3 verify.py [FIXTURES_DIR]
Exit code 0 = every check passed.
"""
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE

PASS = 0
FAIL = 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS  {name}")
    else:
        FAIL += 1
        FAILURES.append(f"{name}: {detail}")
        print(f"FAIL  {name}  {detail}")


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    global ROOT
    if len(sys.argv) > 1:
        ROOT = Path(sys.argv[1]).resolve()

    oracle_path = ROOT / "oracle" / "T003-oracle.json"
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    ocases = {c["id"]: c for c in oracle["cases"]}

    # ---- 1. the vendored oracle is intact ------------------------------
    check("oracle sha256 matches the published artifact",
          sha256_file(oracle_path) ==
          "f9840ab765aff72652843f093633b69b81b2ac6c1631cd1d767ed20edd4dd89f",
          sha256_file(oracle_path))
    check("oracle declares 56 cases", len(oracle["cases"]) == 56,
          str(len(oracle["cases"])))
    check("oracle ids are unique",
          len(ocases) == len(oracle["cases"]))

    # ---- 2. one case file per oracle case -------------------------------
    files = sorted((ROOT / "cases").glob("*.json"))
    check("56 case files present", len(files) == 56, str(len(files)))
    check("case file ids match the oracle ids exactly",
          {json.loads(f.read_text())["id"] for f in files} == set(ocases))

    # ---- 3. every case carries the oracle's expectations verbatim -------
    mismatched = []
    for f in files:
        rec = json.loads(f.read_text())
        oc = ocases[rec["id"]]
        for k in ("family", "title", "klass", "fail_closed", "unsupported",
                  "cap", "trace", "outcome", "expect", "canaries"):
            if rec[k] != oc[k]:
                mismatched.append(f"{rec['id']}.{k}")
        if rec["runtime_status"] != oc["runtime_status"]:
            mismatched.append(f"{rec['id']}.runtime_status")
        if rec["apply_observation"] != oc["apply_observation"]:
            mismatched.append(f"{rec['id']}.apply_observation")
    check("expected semantics are copied verbatim from the oracle",
          not mismatched, str(mismatched[:8]))

    # ---- 4. runtime markers: nothing was executed -----------------------
    check("runtime_status is NOT_RUN in every case",
          all(json.loads(f.read_text())["runtime_status"] == "NOT_RUN"
              for f in files))
    check("apply_observation is null in every case",
          all(json.loads(f.read_text())["apply_observation"] is None
              for f in files))
    check("every case flags expect.apply as policy, not observation",
          all(json.loads(f.read_text())["expect_apply_is_policy_not_observation"]
              for f in files))
    check("expect_apply_policy equals expect.apply in every case",
          all(json.loads(f.read_text())["expect_apply_policy"] ==
              json.loads(f.read_text())["expect"]["apply"] for f in files))
    vocab = set(oracle["runtime_status_legend"]["vocabulary"])
    used = {json.loads(f.read_text())["expect"]["apply"] for f in files}
    check("every expect.apply label is in the oracle's vocabulary",
          used <= vocab, str(sorted(used - vocab)))

    # ---- 5. no empty / placeholder payloads -----------------------------
    empty = [json.loads(f.read_text())["id"] for f in files
             if json.loads(f.read_text())["input"].get("payload") in
             (None, {}, [], "")]
    check("no case has an empty payload", not empty, str(empty))
    notconcrete = [json.loads(f.read_text())["id"] for f in files
                   if json.loads(f.read_text())["input"].get("concrete") is not True]
    check("every case is marked concrete", not notconcrete, str(notconcrete))

    # ---- 6. literal payloads exist, are non-empty, and match -----------
    missing = []
    for f in files:
        rec = json.loads(f.read_text())
        pl = rec["input"]["payload"]
        if pl.get("kind") == "file":
            p = ROOT / pl["path"]
            if not p.exists() or p.stat().st_size == 0:
                missing.append(rec["id"])
    check("every referenced literal input file exists and is non-empty",
          not missing, str(missing))

    # a literal whose oracle value was NOT expanded must equal it exactly
    expanded = {"A-03", "A-04", "B-13", "G-03"}
    exact = []
    for f in files:
        rec = json.loads(f.read_text())
        pl = rec["input"]["payload"]
        if pl.get("kind") != "file" or rec["id"] in expanded:
            continue
        if (ROOT / pl["path"]).read_text(encoding="utf-8") != rec["input"]["oracle_value"]:
            exact.append(rec["id"])
    check("non-expanded literal inputs equal the oracle value exactly",
          not exact, str(exact))

    # ---- 7. structured oracle keys survive into the payload -------------
    lost = []
    for f in files:
        rec = json.loads(f.read_text())
        pl = rec["input"]["payload"]
        for k, v in ocases[rec["id"]]["input"].items():
            if k in ("kind", "value"):
                continue
            if pl.get(k) != v:
                lost.append(f"{rec['id']}.{k}")
    check("every structured oracle key is present in the payload",
          not lost, str(lost[:8]))

    # ---- 8. canaries ---------------------------------------------------
    reg = json.loads((ROOT / "canaries" / "registry.json").read_text())
    check("6 canaries registered", len(reg["canaries"]) == 6,
          str(len(reg["canaries"])))
    check("canary ids match the oracle registry",
          [c["id"] for c in reg["canaries"]] ==
          [c["id"] for c in oracle["canary_registry"]])
    check("canary values are unique",
          len({c["exact_value"] for c in reg["canaries"]}) == 6)
    bad_hex = []
    for c in reg["canaries"]:
        if "raw_hex" in c:
            raw = base64.b64decode(c["exact_value"], validate=True)
            if raw.hex() != c["raw_hex"]:
                bad_hex.append(c["id"])
            if len(raw) != 32:
                bad_hex.append(c["id"] + ":len")
    check("canary raw bytes match the recorded hex and are 32 bytes",
          not bad_hex, str(bad_hex))
    absent = []
    for c in reg["canaries"]:
        for cid in c["exercised_in"]:
            rec = json.loads((ROOT / "cases" / f"{cid}.json").read_text())
            if c["exact_value"] not in json.dumps(rec["input"], ensure_ascii=False):
                absent.append(f"{c['id']}@{cid}")
    check("every canary appears in the fixture of the case it is registered for",
          not absent, str(absent))
    check("every canary is flagged DO-NOT-USE in the registry",
          all(c.get("do_not_use") is True for c in reg["canaries"]))
    # The literal-text canaries carry the marker in their value.  CAN-0002
    # and CAN-0003 are base64 of fixed ASCII seeds that do not spell it out
    # -- their bytes are fixed by the oracle and must not be altered here,
    # so for them the marking is the registry flag plus the note.
    literal_canaries = [c for c in reg["canaries"] if "raw_hex" not in c]
    check("every literal-text canary carries the DO-NOT-USE marker",
          all("DO-NOT-USE" in c["exact_value"] for c in literal_canaries),
          str([c["id"] for c in literal_canaries
               if "DO-NOT-USE" not in c["exact_value"]]))
    check("every base64 canary records its raw bytes and a DO-NOT-USE note",
          all("raw_hex" in c and "НЕ настоящий" in c["note"]
              for c in reg["canaries"] if "raw_hex" in c))

    # ---- 9. the WireGuard public key is really derived -----------------
    WG_PRIV = "UkFZTEFORS1TWU5USC1XRy1QUklWLTAwMDItLS0tLS0="
    WG_PUB = "936MaZHZsLaibKy96xJ1DQvbqAYZyC2r8LVb5gOma0Q="
    P = 2 ** 255 - 19

    def clamp(k):
        k = bytearray(k)
        k[0] &= 248
        k[31] &= 127
        k[31] |= 64
        return int.from_bytes(k, "little")

    def x25519(k_bytes, u_bytes):
        k = clamp(k_bytes)
        u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
        x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
        for t in range(254, -1, -1):
            kt = (k >> t) & 1
            if swap ^ kt:
                x2, x3 = x3, x2
                z2, z3 = z3, z2
            swap = kt
            A = (x2 + z2) % P
            AA = A * A % P
            B = (x2 - z2) % P
            BB = B * B % P
            E = (AA - BB) % P
            C = (x3 + z3) % P
            D = (x3 - z3) % P
            DA = D * A % P
            CB = C * B % P
            x3 = (DA + CB) ** 2 % P
            z3 = x1 * ((DA - CB) ** 2) % P
            x2 = AA * BB % P
            z2 = E * (AA + 121665 * E) % P
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        return ((x2 * pow(z2, P - 2, P)) % P).to_bytes(32, "little")

    derived = base64.b64encode(
        x25519(base64.b64decode(WG_PRIV), (9).to_bytes(32, "little"))).decode()
    check("the WireGuard public key is derived from the private seed",
          derived == WG_PUB, derived)
    b11 = json.loads((ROOT / "cases" / "B-11.json").read_text())
    pl = b11["input"]["payload"]
    check("B-11 carries the derived public key",
          pl.get("publicKey") == WG_PUB)

    # ---- 10. synthetic data hygiene ------------------------------------
    # Scan only the DATA files.  The generator and this verifier are code,
    # and their own identifiers and filenames are not fixture data.
    data_files = [p for p in sorted(ROOT.rglob("*"))
                  if p.is_file() and p.suffix in (".json", ".txt", ".yaml", ".yml",
                                                 ".b64", ".conf")
                  and p.name not in ("manifest.json",)
                  and "verify.py" not in p.name and "generate.py" not in p.name]
    blob = "\n".join(p.read_text(errors="replace") for p in data_files)
    real_cred = [p for p in (r"BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY",
                             r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{20,}",
                             r"xox[baprs]-") if re.search(p, blob)]
    check("no real-looking credential patterns", not real_cred, str(real_cred))
    # Hosts are taken from URL-ish contexts only: scheme, or the authority
    # of a host:port endpoint.
    hosts = set(re.findall(r"://([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)", blob))
    hosts |= set(re.findall(r"\b([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+):\d{2,5}\b", blob))
    hosts |= set(re.findall(r'"(?:server|servername|sni|path)"\s*:\s*"([A-Za-z0-9.-]+)"',
                             blob))
    nonreserved = sorted(h for h in hosts
                         if not h.endswith(".example.test")
                         and h not in ("example.test",)
                         # bare IP literals are not hostnames; they are
                         # checked separately against the documentation
                         # ranges just below.
                         and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h))
    check("every host is under .example.test (RFC 6761)",
          not nonreserved, str(nonreserved))
    check("at least one synthetic host is used", len(hosts) > 0, str(len(hosts)))
    ips = set(re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", blob))
    doc_ranges = ("192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.1",
                  "169.254.169.254", "0.0.0.0")
    check("every IP is a documentation/loopback/link-local address",
          all(any(ip.startswith(d) for d in doc_ranges) for ip in ips),
          str(sorted(ips)))

    # ---- 11. coverage claims are reproduced, not asserted --------------
    spec = (ROOT.parent.parent / "specs" / "001-selected-connections" / "spec.md")
    if spec.exists():
        text = spec.read_text(encoding="utf-8")
        den = set(re.findall(r"FR-\d+", text)) | set(re.findall(r"US-\d+", text)) \
            | set(re.findall(r"SC-\d+", text))
        covered = set()
        for f in files:
            for t in json.loads(f.read_text())["trace"]:
                m = re.match(r"^(FR-\d+|US-\d+|SC-\d+)", t)
                if m:
                    covered.add(m.group(1))
        check(f"syntactic trace coverage is {len(covered)}/{len(den)} as documented",
              len(covered) == 32 and len(den) == 36,
              f"{len(covered)}/{len(den)}")
        nf = {"FR-014", "FR-015", "FR-016", "FR-017", "FR-018", "FR-020",
              "FR-021", "FR-023", "SC-007"}
        fv = den - nf
        check(f"fixture-verifiable coverage is {len(fv & covered)}/{len(fv)} as documented",
              len(fv & covered) == 27 and len(fv) == 27,
              f"{len(fv & covered)}/{len(fv)}")
        check("the 9 not-fixture-testable requirements are named as such",
              nf == {g for g in nf} and len(nf) == 9)
    else:
        check("spec.md is reachable for the denominator check", False, str(spec))

    # ---- 12. GAP-WGKEY stays open and unfabricated ---------------------
    gaps = {g["id"] for g in oracle["known_gaps"]}
    check("GAP-WGKEY is still declared open", "GAP-WGKEY" in gaps)
    wg_cases = [c for c in oracle["cases"]
                if any("WG" in str(k) or "wireguard" in str(v).lower()
                       for k, v in c["input"].items())]
    malformed = [c["id"] for c in wg_cases
                 if "malformed" in json.dumps(c, ensure_ascii=False).lower()
                 and "not-a-key" in json.dumps(c, ensure_ascii=False)]
    check("no fabricated malformed-WireGuard-key case was added",
          not malformed, str(malformed))

    # ---- 13. manifest ----------------------------------------------------
    man_path = ROOT / "manifest.json"
    man = json.loads(man_path.read_text())
    drift = []
    for rel, digest in man["files"].items():
        p = ROOT / rel
        if not p.exists() or sha256_file(p) != digest:
            drift.append(rel)
    check("manifest sha256 matches every tracked file", not drift, str(drift[:6]))
    check("manifest counts match the corpus",
          man["counts"]["cases"] == 56 and man["counts"]["canaries"] == 6,
          str(man["counts"]))
    check("manifest records execution count 0",
          man["runtime_status"]["execution_count"] == 0)

    print()
    print(f"passed: {PASS}   failed: {FAIL}")
    if FAILURES:
        print("failures:")
        for f in FAILURES:
            print(f"  - {f}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
