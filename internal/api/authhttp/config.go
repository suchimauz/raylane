// Package authhttp is the V4 runtime composition boundary (DECISION.md §3):
// the narrow, reviewed exported surface that hosts the admin HTTP handlers
// (login, logout, truthful /state, local bootstrap) over the accepted
// internal/api/auth primitives and the internal/store persistence. It owns the
// session cookie, Origin CSRF, the anonymous login rate limiter and the local
// Unix-socket bootstrap token issuer. It exposes NO raw store handle, NO
// secret value, NO arbitrary callback and NO hook.
//
// The seam rules (go/types classifier) apply package-wide to this composition
// package as well as to the primitives: a direct method call on a concrete
// receiver is fine; a function-typed field/call target or an interface-dispatch
// call is a seam the guard rejects. net/http handler registration uses the
// concrete *http.ServeMux and http.HandlerFunc adapter boundary, which the
// contract accepts as a necessary typed protocol interface.
package authhttp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/suchimauz/raylane/internal/store"
)

// Configuration validation and runtime tuning constants. The session cookie,
// CSRF, limiter and bootstrap policies are fixed by the wire contract and are
// NOT operator-tunable except where explicitly noted.
const (
	// Session cookie.
	sessionCookieName = "raylane_session"
	sessionTokenBytes = 32 // opaque CSPRNG token, base64url no padding

	// Session lifetime: idle 900 s, absolute 43200 s. Reads/polling do NOT
	// extend the idle timer; login always creates a NEW session.
	sessionIdleSeconds     = 900
	sessionAbsoluteSeconds = 43200

	// Session capacity: reject-new at 1024 concurrent sessions, no eviction
	// (evicting would be a DoS vector against the single admin).
	maxSessions = 1024

	// Login rate limiter: per actual socket peer IP, burst 5, refill 1 per
	// 60 s, max 1024 peers (reject-new); global max 2 active Argon2
	// verifications, fail-fast, no queue.
	limitBurst         = 5
	limitRefillSeconds = 60
	limitMaxPeers      = 1024
	limitGlobalArgon2  = 2

	// Bootstrap token: TTL 300 s from issuance, at most one live token,
	// invalid after restart.
	bootstrapTokenTTL = 300 * time.Second
)

// Config is the explicit operator configuration for the runtime. Every field
// is validated before Serve; there are no defaults that silently weaken the
// security posture.
type Config struct {
	// ManagementListen is the LAN HTTPS listen address for the management API.
	ManagementListen string
	// TrustedOrigin is the EXACT configured management origin used for the
	// strict-Origin CSRF check (scheme + host + port, e.g.
	// "https://manage.example:8443"). It is never derived from a request.
	TrustedOrigin string
	// TLSCertPath and TLSKeyPath are the TLS certificate and private-key paths
	// for the management listener.
	TLSCertPath string
	TLSKeyPath  string
	// DBPath is the SQLite database path.
	DBPath string
	// UnixSocketDir is the owner-only parent directory (0700) holding the
	// owner-only local bootstrap socket (0600). The serving process owns it.
	UnixSocketDir string
	// NodeKeyPath is the OPTIONAL operator-configured path to the trusted
	// node master key. Omitted/empty keeps the runtime keyless: the safe
	// node reader still works and the authenticated node create answers a
	// static 503 — never a silent downgrade of a NONEMPTY path, which must
	// open successfully or the process refuses to start. Validate checks the
	// PATH SHAPE only (the pure rules shared with store.NewKeyStore); the key
	// itself is opened exactly once at composition, not here.
	NodeKeyPath string
}

// Validate reports whether every required field is present, well-formed and
// SAFE. Beyond presence it rejects configurations that would weaken the
// security posture. Existence/ownership of the TLS/DB/socket paths is
// verified at bind time, not here.
//
// Bind policy (net/netip, no name resolution): ManagementListen must be a
// NUMERIC IP literal plus a concrete port 1..65535 (an ephemeral :0 bind is
// refused — the CSRF origin would not be knowable). The address must be
// inside the reviewed private scope: loopback (127/8, ::1) or a private LAN
// range (10/8, 172.16/12, 192.168/16, fc00::/7). Unspecified/wildcard,
// link-local, multicast, shared-address (CGNAT), benchmarking, public
// addresses, IPv4-mapped IPv6 literals and zoned literals are all refused.
//
// Origin policy: TrustedOrigin must be EXACTLY the canonical rendering
// https://<bind-IP>[:port] of the configured bind — 443 written portless,
// IPv6 bracketed and compressed, ports in canonical decimal. A hostname
// origin, credentials, a path, query or fragment, leading zeros, or any
// non-matching spelling is rejected, never rewritten: the CSRF comparison
// must not be able to diverge from the address actually served.
func (c Config) Validate() error {
	if c.ManagementListen == "" {
		return errors.New("authhttp: management listen address is required")
	}
	if c.TrustedOrigin == "" {
		return errors.New("authhttp: trusted origin is required")
	}
	if c.TLSCertPath == "" {
		return errors.New("authhttp: TLS certificate path is required")
	}
	if c.TLSKeyPath == "" {
		return errors.New("authhttp: TLS private-key path is required")
	}
	if c.DBPath == "" {
		return errors.New("authhttp: database path is required")
	}
	if c.UnixSocketDir == "" {
		return errors.New("authhttp: unix socket directory is required")
	}
	// The optional node key path carries SHAPE validation only — a pure
	// canonical-absolute-nonroot path check with zero filesystem IO, so a
	// well-shaped path to a missing key validates here and fails (hard,
	// no downgrade) later at the single composition-time key open.
	if c.NodeKeyPath != "" {
		if _, err := store.ValidateKeyPathShape(c.NodeKeyPath); err != nil {
			return err
		}
	}
	bindAddr, bindPort, err := parseListen(c.ManagementListen)
	if err != nil {
		return err
	}
	if !allowedManagementAddr(bindAddr) {
		return fmt.Errorf("authhttp: management listen %q must be a loopback or private-LAN IP literal (not wildcard, link-local, shared, benchmarking or public)", c.ManagementListen)
	}
	// The origin must be the canonical rendering of the very bind above.
	want := canonicalOrigin(bindAddr, bindPort)
	if c.TrustedOrigin != want {
		if _, _, oerr := parseTrustedOrigin(c.TrustedOrigin); oerr != nil {
			return fmt.Errorf("authhttp: trusted origin %q: %w", c.TrustedOrigin, oerr)
		}
		return fmt.Errorf("authhttp: trusted origin %q must be exactly the management bind origin %q", c.TrustedOrigin, want)
	}
	return nil
}

// splitHostPort splits a listen string into host and port. It delegates to
// net.SplitHostPort, which handles the bracketed IPv6 form; a host without a
// port ("127.0.0.1", "::1") is an error, not a default.
func splitHostPort(s string) (host, port string, err error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", "", fmt.Errorf("authhttp: listen address %q is not host:port: %w", s, err)
	}
	return h, p, nil
}

// parseListen parses a management listen address into a numeric address and a
// concrete port. A hostname (anything netip cannot parse as an IP literal), a
// zoned or IPv4-mapped IPv6 literal, port 0 and a non-canonical port spelling
// are all rejected.
func parseListen(s string) (netip.Addr, uint16, error) {
	host, portStr, err := splitHostPort(s)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("authhttp: management listen %q host is not a numeric IP literal (hostnames are not resolved)", s)
	}
	if addr.Zone() != "" {
		return netip.Addr{}, 0, fmt.Errorf("authhttp: management listen %q must not carry an IPv6 zone", s)
	}
	if addr.Is4In6() {
		return netip.Addr{}, 0, fmt.Errorf("authhttp: management listen %q must use a plain IPv4 literal, not an IPv4-mapped IPv6 one", s)
	}
	port, err := parseCanonicalPort(portStr)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("authhttp: management listen %q: %w", s, err)
	}
	return addr, port, nil
}

// parseCanonicalPort parses a decimal port in 1..65535 written canonically:
// leading zeros ("08443") are rejected so one address has exactly one
// spelling, and port 0 (ephemeral) is rejected because the trusted origin
// could then never be known.
func parseCanonicalPort(s string) (uint16, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("port %q is not a decimal port in 1..65535", s)
	}
	if p == 0 {
		return 0, errors.New("port 0 (ephemeral) is not allowed: the trusted origin would not be knowable")
	}
	if strconv.FormatUint(p, 10) != s {
		return 0, fmt.Errorf("port %q is not canonical decimal (no leading zeros)", s)
	}
	return uint16(p), nil
}

// allowedManagementAddr reports whether addr is inside the reviewed private
// scope for a management listener: loopback or a private LAN range. It is a
// positive allowlist — anything else (unspecified/wildcard, link-local,
// multicast, CGNAT/shared, benchmarking, every public address) is refused.
func allowedManagementAddr(addr netip.Addr) bool {
	return addr.IsLoopback() || addr.IsPrivate()
}

// canonicalOrigin renders the exact origin string a browser would show for a
// listener bound to addr on port: https:// + IP literal, port 443 omitted,
// IPv6 bracketed. This is the ONE accepted spelling.
func canonicalOrigin(addr netip.Addr, port uint16) string {
	host := addr.String()
	if addr.Is6() {
		host = "[" + host + "]"
	}
	if port == 443 {
		return "https://" + host
	}
	return "https://" + host + ":" + strconv.Itoa(int(port))
}

// parseTrustedOrigin strictly parses an origin into a numeric address and
// port, accepting only the exact shape https://<ip>[:port] (IPv6 bracketed,
// port omitted meaning 443) and rejecting credentials, any path/query/
// fragment character, hostnames, zones and IPv4-mapped literals. It explains
// WHY a candidate origin is not acceptable instead of only that it differs.
func parseTrustedOrigin(origin string) (netip.Addr, uint16, error) {
	rest, ok := strings.CutPrefix(origin, "https://")
	if !ok {
		if strings.HasPrefix(origin, "http://") {
			return netip.Addr{}, 0, errors.New("must use https, not http")
		}
		return netip.Addr{}, 0, errors.New("must start with https://")
	}
	if rest == "" {
		return netip.Addr{}, 0, errors.New("has no host")
	}
	if strings.Contains(rest, "@") {
		return netip.Addr{}, 0, errors.New("must not carry credentials (userinfo)")
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		return netip.Addr{}, 0, errors.New("must not carry a path, query or fragment")
	}
	hostStr, portStr := rest, "443"
	if strings.HasPrefix(rest, "[") {
		close := strings.Index(rest, "]")
		if close < 0 {
			return netip.Addr{}, 0, errors.New("IPv6 literal is missing its closing bracket")
		}
		hostStr = rest[1:close]
		tail := rest[close+1:]
		switch {
		case tail == "":
			// portless: 443
		case strings.HasPrefix(tail, ":"):
			portStr = tail[1:]
		default:
			return netip.Addr{}, 0, errors.New("has trailing characters after the IPv6 literal")
		}
	} else if i := strings.LastIndex(rest, ":"); i >= 0 {
		hostStr, portStr = rest[:i], rest[i+1:]
	}
	addr, err := netip.ParseAddr(hostStr)
	if err != nil {
		return netip.Addr{}, 0, errors.New("host is not a numeric IP literal (hostnames are not accepted)")
	}
	if addr.Zone() != "" {
		return netip.Addr{}, 0, errors.New("must not carry an IPv6 zone")
	}
	if addr.Is4In6() {
		return netip.Addr{}, 0, errors.New("must use a plain IPv4 literal, not an IPv4-mapped IPv6 one")
	}
	port, err := parseCanonicalPort(portStr)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return addr, port, nil
}

// String returns a redacted description (never a secret) for logs. The node
// key path is reported only as a set/unset flag — a key location is operator
// secret-adjacent configuration and is never echoed.
func (c Config) String() string {
	nodeKey := "unset"
	if c.NodeKeyPath != "" {
		nodeKey = "set"
	}
	return fmt.Sprintf("authhttp.Config{listen=%s origin=%s cert=%s key=%s db=%s sockdir=%s nodeKey=%s}",
		c.ManagementListen, c.TrustedOrigin, c.TLSCertPath, c.TLSKeyPath, c.DBPath, c.UnixSocketDir, nodeKey)
}

// UnixSocketPath returns the path of the owner-only local bootstrap socket
// inside the 0700 socket directory. The serving process creates and removes
// it; the CLI clients connect to it.
func (c Config) UnixSocketPath() string {
	return c.UnixSocketDir + "/control.sock"
}
