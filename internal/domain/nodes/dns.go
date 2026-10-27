package nodes

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// This file implements the FR-004 node-host DNS Auto/TCP/UDP/DoH grammar and
// the value-conditional cross-field rules (D-019/D-020/D-046) for VLESS/SOCKS5/
// HTTP. It reuses the closed IssueCode vocabulary (no new codes) and never
// echoes a submitted value. The profile pattern is the generic projection's
// bounded shape allowlist; these functions apply precise semantic grammar
// (netip/url) and cross-field applicability that a regex cannot express.

// dnsServerOK validates the closed dnsServer grammar: one ASCII hostname /
// IPv4 literal / bracketed IPv6 literal, optional colon decimal port 1..65535.
// Brackets are required for IPv6. Returns only a boolean; the value is never
// echoed.
func dnsServerOK(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	host, port, hasPort := splitHostPort(s)
	if hasPort {
		if !validPort(port) {
			return false
		}
	}
	// Strip the IPv6 brackets that splitHostPort preserved; dnsHostOK validates
	// the bare address and requires brackets to have been present for IPv6.
	wasBracketed := strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]")
	inner := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.Contains(inner, ":") && !wasBracketed {
		return false // IPv6 must be bracketed in this field
	}
	if inner == "" {
		return false
	}
	return dnsHostOK(inner, true)
}

// dnsServerUrlOK validates the closed https DoH URL grammar: one nonempty
// host (same hostname/IPv4/bracketed-IPv6 semantics), optional explicit port
// 1..65535, optional path. No userinfo, no query, no fragment (including
// empty ? / #), https scheme only, no backslash or control/whitespace.
func dnsServerUrlOK(s string) bool {
	if s == "" || len(s) > 2048 {
		return false
	}
	// Reject backslash and any whitespace/control up front.
	if strings.ContainsAny(s, "\\\t\n\r ") {
		return false
	}
	// Raw delimiter check: this grammar forbids ANY query or fragment, so a
	// raw '?' or '#' — including the empty "https://h/p?" and "https://h/p#"
	// markers that net/url would otherwise normalize away — is rejected before
	// parsing. Percent-encoded %3F/%23 in a legal path are path data, not raw
	// markers, and pass. This keeps the precise layer correct even under a
	// pattern-free profile with no regex gate.
	if strings.ContainsAny(s, "?#") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	// No userinfo (authority 'user@' / 'user:pass@'). Query and fragment are
	// forbidden entirely and were already rejected by the raw delimiter check
	// above (which catches the empty '?' / '#' markers net/url would drop).
	if u.User != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	// Explicit empty authority port: "https://host:/path". net/url's Port()
	// returns "" for it, losing the bare ':' — detect it in the authority
	// ourselves, distinguishing it from the colons in a bracketed IPv6 literal.
	if bareEmptyPort(u.Host) {
		return false
	}
	if port := u.Port(); port != "" {
		if !validPort(port) {
			return false
		}
	}
	// The host must satisfy the same hostname/IP grammar; url.Parse already
	// rejects malformed escapes in the authority. Brackets required for IPv6.
	if !dnsHostOK(host, false) {
		return false
	}
	return true
}

// bareEmptyPort reports whether the URL authority carries an explicit empty
// port (a bare ':' with nothing after it, e.g. "host:" or "[v6]:").
// net/url's Port() returns "" for this case, losing the presence of the
// delimiter, so we inspect the authority text directly. The colon(s) inside a
// bracketed IPv6 literal are not a port delimiter and are ignored.
func bareEmptyPort(authority string) bool {
	host := authority
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		host = authority[i+1:]
	}
	// Bracketed IPv6: only a ':' AFTER the closing bracket is a port delimiter.
	if strings.HasPrefix(host, "[") {
		end := strings.Index(host, "]")
		if end < 0 {
			return false // unbalanced; dnsHostOK rejects elsewhere
		}
		rest := host[end+1:]
		return rest == ":" // "[v6]:" => empty port; "[v6]:853" => not empty
	}
	// Non-bracketed: a trailing ':' means an empty port ("host:"). A ':'
	// followed by digits is a real port; multiple colons mean an unbracketed
	// IPv6, which dnsHostOK rejects as a host anyway.
	if strings.Count(host, ":") == 1 {
		return strings.HasSuffix(host, ":")
	}
	return false
}

// dnsHostOK validates a bare host with no port and no brackets: hostname
// label chain (optional trailing dot), IPv4 literal, or IPv6 literal. The
// caller is responsible for requiring brackets where the grammar demands them
// (dnsServer requires brackets for IPv6; url.Hostname already strips them).
func dnsHostOK(host string, _ bool) bool {
	if host == "" {
		return false
	}
	// IPv6 literal (colons present).
	if strings.Contains(host, ":") {
		addr, err := netip.ParseAddr(host)
		return err == nil && addr.Is6()
	}
	// IPv4 literal: route the dotted-quad shape to netip for real octet checks.
	if isIPv4Shape(host) {
		addr, err := netip.ParseAddr(host)
		return err == nil && addr.Is4()
	}
	// Hostname label chain.
	return hostnameOK(host)
}

// hostnameOK validates a DNS hostname: labels 1..63 chars, ASCII alphanumeric
// with internal hyphens, no leading/trailing hyphen, optional trailing dot.
func hostnameOK(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	// Optional single trailing dot (FQDN root).
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return false
	}
	labels := strings.Split(h, ".")
	for _, lbl := range labels {
		if !labelOK(lbl) {
			return false
		}
	}
	return true
}

// labelOK validates one hostname label: 1..63 chars, ASCII alphanumeric with
// internal hyphen, no leading/trailing hyphen.
func labelOK(l string) bool {
	n := len(l)
	if n < 1 || n > 63 {
		return false
	}
	for i := 0; i < n; i++ {
		c := l[i]
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlnum && c != '-' {
			return false
		}
		if (i == 0 || i == n-1) && c == '-' {
			return false
		}
	}
	return true
}

// isIPv4Shape reports whether s looks like a dotted quad (digits and dots) so
// dnsHostOK can route it to netip for real octet validation. A hostname never
// has all-numeric dotted labels in this grammar.
func isIPv4Shape(s string) bool {
	dots := 0
	digits := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c == '.':
			dots++
		default:
			return false
		}
	}
	return dots == 3 && digits > 0
}

// splitHostPort splits a dnsServer value into host and optional port. Bracketed
// IPv6 ([addr] or [addr]:port) is handled first so the colon inside the
// brackets is not mistaken for a port separator. hasPort reports whether a
// well-formed :port suffix was present.
func splitHostPort(s string) (host, port string, hasPort bool) {
	// Bracketed IPv6: [ ... ] with optional :port after the close bracket.
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return s, "", false // unbalanced; dnsHostOK will reject
		}
		host = s[:end+1]
		rest := s[end+1:]
		if rest == "" {
			return host, "", false
		}
		if strings.HasPrefix(rest, ":") {
			return host, rest[1:], true
		}
		return s, "", false // garbage after bracket
	}
	// Non-bracketed: a single trailing :port is allowed (hostname or IPv4).
	// More than one colon means an unbracketed IPv6 -> reject.
	if strings.Count(s, ":") == 1 {
		i := strings.LastIndex(s, ":")
		return s[:i], s[i+1:], true
	}
	if strings.Count(s, ":") > 1 {
		return s, "", false // unbracketed IPv6
	}
	return s, "", false
}

// validPort reports whether s is a decimal port in 1..65535.
func validPort(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	// Reject leading-plus, leading zeros are fine, but must be pure digits.
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return n >= 1 && n <= 65535
}
