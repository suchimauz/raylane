package nodes

// This file holds the FR008 typed public WireGuard field rule (T010/T011
// FR008/D049, FR009/019). It runs as an explicit post-pass inside Validate,
// after the per-field generic shape checks, because it validates the CONTENT
// of two independently-eligible declared known/non-secret/supported ACTIVE
// fields — publicKey (string) and localAddresses (array of string) — that the
// generic type/bounds/pattern/array rules cannot express.
//
// It is protocol-scoped to wireguard ONLY: vless.publicKey is the REALITY key
// and is untouched. It reuses the closed IssueCode vocabulary (no new codes):
//   - publicKey       -> IssuePatternViolation  ("a field value has an invalid format")
//   - localAddresses  -> IssueArrayItemViolation ("an array element is invalid")
// Each field is checked INDEPENDENTLY: an ineligible/invalid publicKey never
// suppresses localAddresses checking (and vice versa), and no early return
// couples the two. The typed check runs ONLY for a field whose SAME-field
// generic checks (type/bounds/pattern/array items) already passed, so no
// duplicate ordinary issue is produced and the other eligible field is still
// checked even when an unrelated field is invalid.
//
// It never rewrites, trims, masks, canonicalizes, or drops a submitted value;
// the exact operator bytes are preserved (the caller owns the raw document).
// No secret value is read (privateKey/preSharedKey bytes are never in Input);
// no metadata/profile/pin/API/IssueCode change; stdlib only.
//
// Honest limit: this is a pure FORMAT check. publicKey verifies the pinned
// ParseWireGuardKey decode grammar (hex-64 or base64 std/url, padded/raw, at
// most one trailing '=') AND that the decoded bytes are exactly 32 (the
// WireGuard/Curve25519 key shape handed to the userspace device). It is NOT a
// curve-point check, NOT a keypair match, NOT an engine/handshake claim.
// localAddresses verifies netip.ParseAddr-or-ParsePrefix acceptance (bare
// IP/CIDR, IPv4/IPv6, host bits, zone, mapped) — no OS lookup, no interface
// resolution, no normalization.

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"

	"github.com/suchimauz/raylane/internal/capability"
)

// validWireGuardPublicKey mirrors the pinned ParseWireGuardKey decode grammar
// (xray-wireguard.go) plus the explicit 32-byte length requirement:
//
//	len(s)==64 and hex-decodes            -> valid (case-insensitive hex branch)
//	else: trim AT MOST one trailing '='; choose RawStd when '+' or '/' present,
//	      else RawURL; decode; valid iff decoded length == 32.
//
// No TrimSpace and no Strict decoder are introduced: the stdlib Raw decoders
// already ignore CR/LF (preserving the pinned decoder's CRLF tolerance), and
// spaces/other characters fail decode. A 16-byte hex (32 chars) decodes
// successfully in the pinned parser but is NOT 32 bytes, so it is rejected by
// the explicit length check.
func validWireGuardPublicKey(s string) bool {
	if len(s) == 64 {
		if _, err := hex.DecodeString(s); err == nil {
			return true
		}
	}
	key := s
	if len(key) > 0 && key[len(key)-1] == '=' {
		key = key[:len(key)-1] // trim at most one trailing '='
	}
	var (
		dat []byte
		err error
	)
	if strings.ContainsAny(key, "+/") {
		dat, err = base64.RawStdEncoding.DecodeString(key)
	} else {
		dat, err = base64.RawURLEncoding.DecodeString(key)
	}
	return err == nil && len(dat) == 32
}

// validWireGuardAddress reports whether s is accepted by netip.ParseAddr OR
// netip.ParsePrefix: a bare IPv4/IPv6 literal (zone allowed) or a CIDR prefix
// (host bits allowed), IPv4-mapped forms included. Exactly what the parser
// allows — no masking, no zone stripping, no trimming.
func validWireGuardAddress(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	return false
}

// wgTypedEligible reports whether a declared field may receive the FR008 typed
// content check: DECLARED, classification known (non-secret), supported-not-
// false, and the correct declared type. Mirrors transportEligible/dnsEligible —
// the declaration guard prevents inventing an authority the profile does not
// actually declare. A secret/unsupported/wrong-type declaration is inert (the
// ordinary per-field validator already reported its own finding).
func wgTypedEligible(f capability.Field, wantType string) bool {
	if f.Classification != "known" {
		return false
	}
	if f.HasSupported && !f.Supported {
		return false
	}
	return f.Type == wantType
}

// checkWireGuardTypedRules applies the FR008 typed public-field rule to the
// effective ACTIVE values of publicKey and localAddresses. It runs after the
// per-field generic checks; for each field it first confirms the SAME field's
// generic valueOK passed (so no duplicate ordinary issue), then applies the
// typed content check. The two fields are independent — one never gates the
// other — and neither is gated by any unrelated field's validity. It never
// mutates the maps and never echoes a byte.
func checkWireGuardTypedRules(res *Result, declared map[string]capability.Field, active map[string]any) {
	checkKey(res, declared, active)
	checkAddrs(res, declared, active)
}

// checkKey typed-checks publicKey (independently of localAddresses).
func checkKey(res *Result, declared map[string]capability.Field, active map[string]any) {
	f, isDecl := declared["publicKey"]
	if !isDecl || !wgTypedEligible(f, "string") {
		return
	}
	raw, present := active["publicKey"]
	if !present {
		return // absent: no inactive promotion, no fallback/default
	}
	s, isStr := raw.(string)
	if !isStr {
		return // active non-string: typeMismatch already emitted
	}
	// Same-field generic gate: run the exact generic check; only if it passed
	// (correct type, in-bounds length, no declared-pattern violation) add the
	// typed format finding, so a generic failure is not duplicated.
	if ok, _ := valueOK(f, raw); !ok {
		return
	}
	if !validWireGuardPublicKey(s) {
		addIssue(res, IssuePatternViolation, "publicKey")
	}
}

// checkAddrs typed-checks localAddresses (independently of publicKey).
func checkAddrs(res *Result, declared map[string]capability.Field, active map[string]any) {
	f, isDecl := declared["localAddresses"]
	if !isDecl || !wgTypedEligible(f, "array") {
		return
	}
	raw, present := active["localAddresses"]
	if !present {
		return
	}
	arr, isArr := raw.([]any)
	if !isArr {
		return // active non-array: typeMismatch already emitted
	}
	// Same-field generic gate: only if the array's generic shape/item checks
	// passed (count bounds + all items are strings) add typed item findings, so
	// a generic item failure is not duplicated per item.
	if ok, _ := valueOK(f, raw); !ok {
		return
	}
	for _, el := range arr {
		s, isStr := el.(string)
		if !isStr {
			continue // generic already owns non-string items
		}
		if !validWireGuardAddress(s) {
			addIssue(res, IssueArrayItemViolation, "localAddresses")
			return // one issue per offending field, not per item
		}
	}
}
