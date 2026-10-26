package authhttp

import (
	"net/netip"
	"testing"
)

// G3 policy tests: Validate() must be a real SAFE-ADDRESS check, not a
// hostname string comparison.
//
// Bind side — ManagementListen must be host:port where host is a NUMERIC IP
// literal (never a resolvable hostname) inside the reviewed private scope:
// loopback 127/8 and ::1, or a private LAN range (10/8, 172.16/12, 192.168/16,
// fc00::/7). Wildcard/unspecified, link-local, multicast, CGNAT, benchmarking
// and every public address are refused, and so is an ephemeral :0 port, an
// IPv6 zone and an IPv4-mapped IPv6 literal.
//
// Origin side — TrustedOrigin must be EXACTLY the canonical rendering of the
// configured bind: https://<bind-IP>[:port] with port 443 written portless,
// IPv6 bracketed and compressed, decimal ports without leading zeros, and no
// userinfo, path, query or fragment. A non-canonical or non-matching spelling
// is rejected rather than rewritten, so the CSRF comparison and the served
// address can never diverge.

func validConfig(listen, origin string) Config {
	return Config{
		ManagementListen: listen,
		TrustedOrigin:    origin,
		TLSCertPath:      "cert.pem",
		TLSKeyPath:       "key.pem",
		DBPath:           "state.db",
		UnixSocketDir:    "/tmp/raylane",
	}
}

func TestBujG3ValidLoopbackAndPrivateLANAccepted(t *testing.T) {
	for _, tc := range []struct{ name, listen, origin string }{
		{"loopback v4", "127.0.0.1:8443", "https://127.0.0.1:8443"},
		{"loopback v4 other octet", "127.200.3.4:9443", "https://127.200.3.4:9443"},
		{"loopback v6", "[::1]:8443", "https://[::1]:8443"},
		{"private 10/8", "10.1.2.3:8443", "https://10.1.2.3:8443"},
		{"private 172.16/12 low", "172.16.0.1:8443", "https://172.16.0.1:8443"},
		{"private 172.16/12 high", "172.31.255.254:8443", "https://172.31.255.254:8443"},
		{"private 192.168/16", "192.168.50.2:8443", "https://192.168.50.2:8443"},
		{"private v6 fc00::/7 low", "[fc00::1]:8443", "https://[fc00::1]:8443"},
		{"private v6 fd00::/8", "[fd12:3456:789a::1]:8443", "https://[fd12:3456:789a::1]:8443"},
		{"port 443 origin portless v4", "10.0.0.5:443", "https://10.0.0.5"},
		{"port 443 origin portless v6", "[::1]:443", "https://[::1]"},
		{"high port", "127.0.0.1:65535", "https://127.0.0.1:65535"},
		{"port 1", "127.0.0.1:1", "https://127.0.0.1:1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validConfig(tc.listen, tc.origin).Validate(); err != nil {
				t.Fatalf("safe configuration rejected: %v", err)
			}
		})
	}
}

func TestBujG3UnsafeBindRefused(t *testing.T) {
	for _, tc := range []struct{ name, listen string }{
		{"wildcard v4", "0.0.0.0:8443"},
		{"wildcard v6", "[::]:8443"},
		{"public v4", "8.8.8.8:8443"},
		{"public v6", "[2001:db8::1]:8443"},
		{"link-local v4", "169.254.1.1:8443"},
		{"link-local v6", "[fe80::1]:8443"},
		{"multicast v4", "224.0.0.1:8443"},
		{"multicast v6", "[ff02::1]:8443"},
		{"cgnat 100.64/10 low", "100.64.0.1:8443"},
		{"cgnat 100.64/10 high", "100.127.255.254:8443"},
		{"benchmark 198.18/15 low", "198.18.0.1:8443"},
		{"benchmark 198.18/15 high", "198.19.255.254:8443"},
		{"just outside 172.16/12 low", "172.15.255.254:8443"},
		{"just outside 172.16/12 high", "172.32.0.1:8443"},
		{"non-routable 192.0.2.1", "192.0.2.1:8443"},
		{"hostname", "manage.example:8443"},
		{"localhost name", "localhost:8443"},
		{"ipv4-mapped v6", "[::ffff:127.0.0.1]:8443"},
		{"ipv4-mapped v6 public", "[::ffff:8.8.8.8]:8443"},
		{"zone id", "[fe80::1%eth0]:8443"},
		{"ephemeral port zero", "127.0.0.1:0"},
		{"port over range", "127.0.0.1:65536"},
		{"no port", "127.0.0.1"},
		{"empty host", ":8443"},
		{"garbage", "not an address"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The origin is the canonical rendering of the SAME address where
			// one exists, so the refusal can only come from the bind policy.
			origin := "https://127.0.0.1:8443"
			if tc.listen != "" {
				if host, port, err := splitForOrigin(tc.listen); err == nil {
					origin = canonicalOrigin(host, port)
				}
			}
			if err := validConfig(tc.listen, origin).Validate(); err == nil {
				t.Fatalf("unsafe bind accepted: %q", tc.listen)
			}
		})
	}
}

// splitForOrigin builds the matching canonical origin for a listen string
// that parses, using the same package policy helpers Validate itself uses.
func splitForOrigin(listen string) (netip.Addr, uint16, error) {
	host, port, err := splitHostPort(listen)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	p, err := parseCanonicalPort(port)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return addr, p, nil
}

func TestBujG3OriginMustExactlyMatchCanonicalBind(t *testing.T) {
	for _, tc := range []struct{ name, listen, origin string }{
		{"different host same scope", "127.0.0.1:8443", "https://127.0.0.2:8443"},
		{"different port", "127.0.0.1:8443", "https://127.0.0.1:9443"},
		{"http scheme", "127.0.0.1:8443", "http://127.0.0.1:8443"},
		{"hostname origin", "127.0.0.1:8443", "https://manage.example:8443"},
		{"localhost origin", "127.0.0.1:8443", "https://localhost:8443"},
		{"trailing slash", "127.0.0.1:8443", "https://127.0.0.1:8443/"},
		{"path", "127.0.0.1:8443", "https://127.0.0.1:8443/api"},
		{"query", "127.0.0.1:8443", "https://127.0.0.1:8443?x=1"},
		{"fragment", "127.0.0.1:8443", "https://127.0.0.1:8443#f"},
		{"userinfo", "127.0.0.1:8443", "https://user:pw@127.0.0.1:8443"},
		{"port leading zeros", "127.0.0.1:8443", "https://127.0.0.1:08443"},
		{"443 written with port", "127.0.0.1:443", "https://127.0.0.1:443"},
		{"non-443 written portless", "127.0.0.1:8443", "https://127.0.0.1"},
		{"ipv4 leading zeros", "127.0.0.1:8443", "https://010.000.000.001:8443"},
		{"v6 uncompressed", "[::1]:8443", "https://[0:0:0:0:0:0:0:1]:8443"},
		{"v6 uppercase", "[fd12::1]:8443", "https://[FD12::1]:8443"},
		{"v6 unbracketed", "::1", "https://::1:8443"},
		{"v6 mapped", "127.0.0.1:8443", "https://[::ffff:127.0.0.1]:8443"},
		{"empty origin", "127.0.0.1:8443", ""},
		{"just scheme", "127.0.0.1:8443", "https://"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validConfig(tc.listen, tc.origin).Validate(); err == nil {
				t.Fatalf("non-matching/non-canonical origin accepted: %q vs bind %q", tc.origin, tc.listen)
			}
		})
	}
}

func TestBujG3RequiredFieldsStillRefused(t *testing.T) {
	base := validConfig("127.0.0.1:8443", "https://127.0.0.1:8443")
	for name, clear := range map[string]func(*Config){
		"listen":     func(c *Config) { c.ManagementListen = "" },
		"origin":     func(c *Config) { c.TrustedOrigin = "" },
		"cert":       func(c *Config) { c.TLSCertPath = "" },
		"key":        func(c *Config) { c.TLSKeyPath = "" },
		"db":         func(c *Config) { c.DBPath = "" },
		"socket_dir": func(c *Config) { c.UnixSocketDir = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			clear(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("missing %s accepted", name)
			}
		})
	}
}
