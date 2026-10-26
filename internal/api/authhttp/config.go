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
	"net/url"
	"time"
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
}

// Validate reports whether every required field is present, well-formed and
// SAFE. Beyond presence it rejects configurations that would weaken the
// security posture: a wildcard/unspecified or non-loopback management listen
// address, a non-HTTPS trusted origin, and an origin whose host/port does not
// match the management listen address. Existence/ownership of the TLS/DB/
// socket paths is verified at bind time, not here.
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
	// Management listen must be a specific loopback address, never a wildcard
	// (0.0.0.0 / ::) or a public interface: the management API must not be
	// exposed beyond the local machine by an unsafe operator config.
	listenHost, listenPort, err := net.SplitHostPort(c.ManagementListen)
	if err != nil {
		return fmt.Errorf("authhttp: management listen address %q is not host:port: %w", c.ManagementListen, err)
	}
	listenIP := net.ParseIP(listenHost)
	if listenIP == nil || !listenIP.IsLoopback() {
		return fmt.Errorf("authhttp: management listen %q must be a loopback address (not wildcard or public)", c.ManagementListen)
	}
	// Trusted origin must be HTTPS, and its port must match the management
	// listen port (when the listen port is known — a non-zero port; an
	// ephemeral :0 listener defers the real port to bind time). A mismatched
	// port would make the CSRF origin check diverge from the served origin.
	u, err := url.Parse(c.TrustedOrigin)
	if err != nil {
		return fmt.Errorf("authhttp: trusted origin %q is not a valid URL: %w", c.TrustedOrigin, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("authhttp: trusted origin %q must use https", c.TrustedOrigin)
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("authhttp: trusted origin %q has no host", c.TrustedOrigin)
	}
	if listenPort != "0" {
		originPort := u.Port()
		if originPort == "" {
			originPort = "443" // default https port when omitted
		}
		if originPort != listenPort {
			return fmt.Errorf("authhttp: trusted origin %q port does not match management listen %q", c.TrustedOrigin, c.ManagementListen)
		}
	}
	return nil
}

// String returns a redacted description (never a secret) for logs.
func (c Config) String() string {
	return fmt.Sprintf("authhttp.Config{listen=%s origin=%s cert=%s key=%s db=%s sockdir=%s}",
		c.ManagementListen, c.TrustedOrigin, c.TLSCertPath, c.TLSKeyPath, c.DBPath, c.UnixSocketDir)
}

// UnixSocketPath returns the path of the owner-only local bootstrap socket
// inside the 0700 socket directory. The serving process creates and removes
// it; the CLI clients connect to it.
func (c Config) UnixSocketPath() string {
	return c.UnixSocketDir + "/control.sock"
}
