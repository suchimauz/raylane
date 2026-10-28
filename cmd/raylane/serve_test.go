package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/suchimauz/raylane/internal/webui"
)

// buildBinary compiles the real raylane binary once per test run into
// TestDir and returns its path. The integration tests below drive the REAL
// process (exec + signals + exits), not the in-process run() function.
func buildBinary(t *testing.T) string {
	t.Helper()
	return buildSharedBinary(t)
}

var sharedBinary struct {
	path string
	err  error
	done bool
}

func buildSharedBinary(t *testing.T) string {
	t.Helper()
	if !sharedBinary.done {
		dir, err := os.MkdirTemp("", "raylane-cli-build")
		if err != nil {
			sharedBinary.err = err
		} else {
			bin := filepath.Join(dir, "raylane")
			cmd := exec.Command("go", "build", "-o", bin, ".")
			out, err := cmd.CombinedOutput()
			if err != nil {
				sharedBinary.err = fmt.Errorf("go build: %v\n%s", err, out)
			} else {
				sharedBinary.path = bin
			}
		}
		sharedBinary.done = true
	}
	if sharedBinary.err != nil {
		t.Fatalf("build raylane: %v", sharedBinary.err)
	}
	return sharedBinary.path
}

// syncBuf is a goroutine-safe bytes.Buffer. The child process's stdout/stderr
// are written by an os/exec copy goroutine while the readiness loop reads
// them, so a plain bytes.Buffer races (this is harness synchronization, not
// detector suppression).
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type harness struct {
	t        *testing.T
	bin      string
	dir      string
	sockDir  string
	cfgPath  string
	certPath string
	caPool   *x509.CertPool
	stdout   *syncBuf
	stderr   *syncBuf
	cmd      *exec.Cmd
	env      []string
	lanURL   string
	lanHost  string
	lanPort  int
	origin   string
}

// startServe picks a free loopback port, generates its OWN isolated TLS
// material (the product never mints certificates), writes the strict JSON
// operator config, and launches the real binary with --config, waiting for
// the "raylane: management" line.
func startServe(t *testing.T) *harness {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()
	h := &harness{
		t:       t,
		bin:     buildBinary(t),
		dir:     t.TempDir(),
		sockDir: filepath.Join(t.TempDir(), "run"),
		stdout:  &syncBuf{},
		stderr:  &syncBuf{},
	}
	h.lanHost = "127.0.0.1"
	h.lanPort = addr.Port
	// The cert covers localhost and 127.0.0.1; the Origin below uses the same
	// host:port as the client sees it.
	h.lanURL = fmt.Sprintf("https://%s:%d", h.lanHost, h.lanPort)
	h.origin = h.lanURL

	// Own isolated test TLS material (never server-minted).
	certPath := filepath.Join(h.dir, "tls", "management.crt")
	keyPath := filepath.Join(h.dir, "tls", "management.key")
	if err := ensureSelfSignedTLS(certPath, keyPath, []string{"localhost", "127.0.0.1"}); err != nil {
		t.Fatalf("generate test TLS material: %v", err)
	}
	h.certPath = certPath
	// Trust ONLY the test CA (positive trust anchor) — never InsecureSkipVerify.
	caCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read test CA: %v", err)
	}
	h.caPool = x509.NewCertPool()
	if !h.caPool.AppendCertsFromPEM(caCert) {
		t.Fatal("append test CA to pool")
	}

	// Strict JSON operator config.
	cfgPath := filepath.Join(h.dir, "serve-config.json")
	cfgJSON := fmt.Sprintf(`{"db":%q,"listen":%q,"origin":%q,"socketDir":%q,"tlsCert":%q,"tlsKey":%q}`,
		filepath.Join(h.dir, "state.db"),
		fmt.Sprintf("%s:%d", h.lanHost, h.lanPort),
		h.origin,
		h.sockDir,
		certPath,
		keyPath,
	)
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o600); err != nil {
		t.Fatalf("write serve config: %v", err)
	}
	h.cfgPath = cfgPath

	h.cmd = exec.Command(h.bin, "serve", "--config", cfgPath)
	h.cmd.Stdout = h.stdout
	h.cmd.Stderr = h.stderr
	if err := h.cmd.Start(); err != nil {
		t.Fatalf("start serve: %v", err)
	}
	t.Cleanup(h.stopAll)
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(h.stdout.String(), "raylane: management") {
		if h.cmd.ProcessState != nil && h.cmd.ProcessState.Exited() {
			t.Fatalf("serve exited early: stdout=%s stderr=%s", h.stdout, h.stderr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve never became ready: stdout=%s stderr=%s", h.stdout, h.stderr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return h
}

func (h *harness) stopAll() {
	if h.cmd != nil && h.cmd.Process != nil && h.cmd.ProcessState == nil {
		h.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- h.cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			h.cmd.Process.Kill()
		}
	}
}

// runWithStdin runs one CLI invocation of the real binary with the given
// stdin and returns its exit code plus combined output.
func (h *harness) runWithStdin(stdin string, args ...string) (int, string) {
	h.t.Helper()
	cmd := exec.Command(h.bin, args...)
	cmd.Env = append(os.Environ(), h.env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errorsAs(err, &ee) {
			h.t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return code, string(out)
}

// run is runWithStdin with no stdin (the process inherits the test's stdin,
// which for these non-interactive subcommands is never read).
func (h *harness) run(args ...string) (int, string) {
	return h.runWithStdin("", args...)
}

func errorsAs(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

// bootstrapCredentialsJSON is a valid stdin credential body for tests.
const bootstrapCredentialsJSON = `{"username":"admin","password":"correct horse battery staple"}`

// bootstrap runs the local bootstrap subcommand feeding the credential JSON
// on stdin (credentials are never passed via env/argv). credsJSON overrides
// the default valid body.
func (h *harness) bootstrap(credsJSON string) (int, string) {
	h.t.Helper()
	if credsJSON == "" {
		credsJSON = bootstrapCredentialsJSON
	}
	return h.runWithStdin(credsJSON, "bootstrap", "--socket-dir", h.sockDir)
}

func (h *harness) socketExists() bool {
	st, err := os.Stat(filepath.Join(h.sockDir, "control.sock"))
	return err == nil && st.Mode()&os.ModeSocket != 0
}

func (h *harness) socketMode() os.FileMode {
	st, err := os.Stat(filepath.Join(h.sockDir, "control.sock"))
	if err != nil {
		return 0
	}
	return st.Mode().Perm()
}

func (h *harness) dirMode() os.FileMode {
	st, err := os.Stat(h.sockDir)
	if err != nil {
		return 0
	}
	return st.Mode().Perm()
}

func (h *harness) tlsKeyMode() os.FileMode {
	st, err := os.Stat(filepath.Join(h.dir, "tls", "management.key"))
	if err != nil {
		return 0
	}
	return st.Mode().Perm()
}

// client returns an HTTPS client that trusts ONLY the test CA (a positive
// trust anchor with the correct SAN) — never InsecureSkipVerify.
func (h *harness) client() *http.Client {
	return h.clientTrusting(h.caPool)
}

// clientTrusting returns an HTTPS client rooted at the supplied pool. A nil
// or unrelated pool exercises the trust NEGATIVE (unknown CA / wrong SAN).
func (h *harness) clientTrusting(pool *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

func (h *harness) login(username, password, origin string) *http.Response {
	h.t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req, err := http.NewRequest(http.MethodPost, h.lanURL+"/api/v1/session", bytes.NewReader(body))
	if err != nil {
		t_fatal(h.t, err)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := h.client().Do(req)
	if err != nil {
		h.t.Fatalf("LAN login: %v (stderr=%s)", err, h.stderr)
	}
	return resp
}

func t_fatal(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func cookieOf(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == "raylane_session" {
			return c
		}
	}
	return nil
}

func readAll(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestT008TLSTrustNegatives: the management listener is reached over REAL
// TLS with a positive trust anchor; an unrelated CA, a wrong-SAN certificate
// and a plain-HTTP request are all refused. The client never uses
// InsecureSkipVerify (that would be a trust bypass, not a test shortcut).
func TestT008TLSTrustNegatives(t *testing.T) {
	h := startServe(t)

	// Positive: trusting the test CA with the right SAN succeeds (login
	// reaches the server: 401 for unknown user, proving TLS + routing work).
	resp := h.login("nobody", "nothing", h.origin)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("trusted-CA login = %d, want 401 (TLS handshake + handler reached)", resp.StatusCode)
	}
	readAll(t, resp)

	// Negative 1: a DIFFERENT CA (unknown to the server cert) must refuse the
	// handshake. Build an unrelated self-signed CA.
	otherDir := t.TempDir()
	otherCert := filepath.Join(otherDir, "other.crt")
	otherKey := filepath.Join(otherDir, "other.key")
	if err := ensureSelfSignedTLS(otherCert, otherKey, []string{"other.example"}); err != nil {
		t.Fatalf("generate unrelated CA: %v", err)
	}
	otherCAPEM, err := os.ReadFile(otherCert)
	if err != nil {
		t.Fatal(err)
	}
	otherPool := x509.NewCertPool()
	otherPool.AppendCertsFromPEM(otherCAPEM)
	if _, err := h.clientTrusting(otherPool).Get(h.lanURL + "/api/v1/state"); err == nil {
		t.Fatal("unknown-CA handshake was accepted (trust bypass?)")
	}

	// Negative 2: the test CA is trusted but the cert SAN does not cover the
	// requested host. Connect by a hostname the cert does not name (the cert
	// covers localhost and 127.0.0.1, not "wronghost").
	wrongHostURL := fmt.Sprintf("https://wronghost:%d/api/v1/state", h.lanPort)
	wrongHostClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// Trust the real CA but dial 127.0.0.1 for host "wronghost", so the
			// SAN check (not name resolution) is what must fail.
			TLSClientConfig: &tls.Config{RootCAs: h.caPool, ServerName: "wronghost", MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", h.lanPort))
			},
		},
	}
	if _, err := wrongHostClient.Get(wrongHostURL); err == nil {
		t.Fatal("wrong-SAN certificate was accepted (SAN check bypassed?)")
	}

	// Negative 3: plain HTTP to the TLS port must not yield a usable response.
	// The TLS listener cannot complete a plaintext handshake; at most the server
	// answers a malformed-request 400 — never a real 200 state (no insecure
	// HTTP fallback).
	plain := &http.Client{Timeout: 5 * time.Second}
	plainResp, err := plain.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/state", h.lanPort))
	if err == nil {
		if plainResp.StatusCode == http.StatusOK {
			t.Fatal("plain-HTTP request received a real 200 (insecure fallback serving data?)")
		}
		plainResp.Body.Close()
	}
}

// TestT008ServeScaffoldPreserved: the pre-existing scaffold readout and exit
// codes are unchanged next to the new subcommands.
func TestT008ServeScaffoldPreserved(t *testing.T) {
	h := &harness{t: t, bin: buildBinary(t)}
	if code, out := h.run("--version"); code != 0 || !strings.Contains(out, `"version": "0.0.0-scaffold"`) {
		t.Fatalf("--version code=%d out=%s", code, out)
	}
	if code, _ := h.run(); code != 0 {
		t.Fatalf("no-args code=%d, want 0 (scaffold behaviour)", code)
	}
	if code, out := h.run("bogus"); code != 2 || !strings.Contains(out, "unsupported argument") {
		t.Fatalf("bogus code=%d out=%s, want 2 + scaffold message", code, out)
	}
	if code, out := h.run("--config", "/nonexistent-raylane-conf"); code != 1 || !strings.Contains(out, "does not exist") {
		t.Fatalf("--config code=%d out=%s, want 1 + scaffold error", code, out)
	}
}

// TestT008CLIBootstrapErrorsUseDistinctExitCodes: usage/credential mistakes
// exit 2, refused bootstrap exits 1 (observed on the real process).
func TestT008CLIBootstrapErrorsUseDistinctExitCodes(t *testing.T) {
	h := &harness{t: t, bin: buildBinary(t)}
	if code, _ := h.run("bootstrap"); code != 2 {
		t.Fatalf("bootstrap without --socket-dir code=%d, want 2", code)
	}
	// No credential JSON on stdin (inherited non-redirected stdin) is refused
	// with exit 2 and a stdin hint, never an env hint.
	if code, out := h.run("bootstrap", "--socket-dir", t.TempDir()); code != 2 || !strings.Contains(out, "stdin") {
		t.Fatalf("bootstrap without stdin credentials code=%d out=%s, want 2 + stdin hint", code, out)
	}
	if code, _ := h.run("serve"); code != 2 {
		t.Fatalf("serve without flags code=%d, want 2", code)
	}
	// Malformed credential JSON on stdin is a usage error (exit 2).
	if code, out := h.runWithStdin(`{"username":"a"}`, "bootstrap", "--socket-dir", t.TempDir()); code != 2 {
		t.Fatalf("bootstrap with malformed stdin code=%d out=%s, want 2", code, out)
	}
	// The stderr never contains any credential material.
	code, out := h.runWithStdin(`{"username":"x","password":"hunter2secret"}`, "bootstrap", "--socket-dir", t.TempDir())
	_ = code
	if strings.Contains(out, "hunter2secret") {
		t.Fatal("credential echoed by the CLI")
	}
}

// TestT008EndToEndRealProcess: REAL process lifecycle over REAL TLS and the
// REAL Unix socket: start → local bootstrap (CLI exit codes) → LAN login
// (cookie attributes) → state 200 → CSRF negative → logout → restart (old
// cookie and token dead) → login again.
func TestT008EndToEndRealProcess(t *testing.T) {
	h := startServe(t)
	if !h.socketExists() {
		t.Fatal("control socket absent after ready line")
	}
	if h.dirMode() != 0o700 {
		t.Fatalf("socket dir mode = %o, want 700", h.dirMode())
	}
	if h.socketMode() != 0o600 {
		t.Fatalf("socket mode = %o, want 600", h.socketMode())
	}
	if h.tlsKeyMode() != 0o600 {
		t.Fatalf("tls key mode = %o, want 600", h.tlsKeyMode())
	}

	// Bootstrap without redirected stdin credentials is refused before
	// touching the socket (exit 2), and never echoes them.
	code, out := h.run("bootstrap", "--socket-dir", h.sockDir)
	if code != 2 {
		t.Fatalf("bootstrap without stdin creds code=%d out=%s, want 2", code, out)
	}

	code, out = h.bootstrap("")
	if code != 0 || !strings.Contains(out, "permanently closed") {
		t.Fatalf("bootstrap code=%d out=%s stderr=%s, want 0 + success line", code, out, h.stderr)
	}
	// Second bootstrap: issuance of a NEW token is possible, but redeeming it
	// hits the permanent store closure — CLI exits 1 with the generic problem.
	code, out = h.bootstrap("")
	if code != 1 {
		t.Fatalf("second bootstrap code=%d out=%s, want 1", code, out)
	}
	// Neither stdout nor the server logs contain the password or the token.
	combined := h.stdout.String() + h.stderr.String() + out
	if strings.Contains(combined, "correct horse battery staple") {
		t.Fatal("password leaked into process output")
	}

	// LAN login through REAL TLS.
	resp := h.login("admin", "correct horse battery staple", h.origin)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("login = %d, want 204; stderr=%s", resp.StatusCode, h.stderr)
	}
	c := cookieOf(resp)
	if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/api/v1" || c.Domain != "" {
		t.Fatalf("cookie = %+v, want settled attributes", c)
	}
	// Wrong password: generic 401 problem.
	resp = h.login("admin", "wrong password", h.origin)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login = %d, want 401", resp.StatusCode)
	}
	body := string(readAll(t, resp))
	if !strings.Contains(body, `"invalid_credentials"`) || !strings.Contains(body, `"requestId"`) {
		t.Fatalf("bad login body = %s", body)
	}
	// CSRF negative over the wire: missing Origin → 403.
	resp = h.login("admin", "correct horse battery staple", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no-Origin login = %d, want 403", resp.StatusCode)
	}
	readAll(t, resp)

	// Authenticated state over the wire, truthful body.
	req, _ := http.NewRequest(http.MethodGet, h.lanURL+"/api/v1/state", nil)
	req.AddCookie(c)
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("state = %d, want 200", resp.StatusCode)
	}
	var state map[string]any
	if err := json.Unmarshal(readAll(t, resp), &state); err != nil {
		t.Fatal(err)
	}
	if state["phase"] != "not-running" {
		t.Fatalf("state phase = %v, want not-running (no engine/apply; no dataplane guard engaged)", state["phase"])
	}
	rd, _ := state["readiness"].(map[string]any)
	if rd["management"] != true || rd["dns"] != false || rd["engine"] != false || rd["classification"] != false {
		t.Fatalf("state readiness = %v", state["readiness"])
	}

	// LAN /bootstrap stays a generic 403 through the real listener (the
	// settled V4 contract: no existence oracle via 404).
	post, _ := http.NewRequest(http.MethodPost, h.lanURL+"/api/v1/bootstrap", strings.NewReader(`{}`))
	post.Header.Set("Origin", h.origin)
	resp, err = h.client().Do(post)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("LAN /bootstrap = %d, want 403", resp.StatusCode)
	}
	readAll(t, resp)

	// Logout kills the session.
	req, _ = http.NewRequest(http.MethodDelete, h.lanURL+"/api/v1/session", nil)
	req.Header.Set("Origin", h.origin)
	req.AddCookie(c)
	resp, err = h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", resp.StatusCode)
	}
	readAll(t, resp)
	req, _ = http.NewRequest(http.MethodGet, h.lanURL+"/api/v1/state", nil)
	req.AddCookie(c)
	resp, err = h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("state after logout = %d, want 401", resp.StatusCode)
	}
	readAll(t, resp)

	// SIGTERM: graceful exit 0, socket file removed.
	if err := h.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- h.cmd.Wait() }()
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("SIGTERM exit = %v (stderr=%s), want clean 0", err, h.stderr)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("serve did not exit after SIGTERM; stderr=%s", h.stderr)
	}
	if _, err := os.Stat(filepath.Join(h.sockDir, "control.sock")); !os.IsNotExist(err) {
		t.Fatal("control socket not removed on shutdown")
	}

	// RESTART: old cookie is dead, the previous bootstrap token is dead, a
	// fresh local bootstrap token cannot reopen the closed bootstrap.
	h2 := &harness{t: t, bin: h.bin, dir: h.dir, sockDir: h.sockDir, cfgPath: h.cfgPath, certPath: h.certPath, caPool: h.caPool, stdout: &syncBuf{}, stderr: &syncBuf{}, lanHost: h.lanHost, lanPort: h.lanPort, lanURL: h.lanURL, origin: h.origin}
	// The config file (DB path, TLS cert/key) from the first run is REUSED:
	// same admin DB, same cert/key pair, same socket dir — a real restart.
	h2.cmd = exec.Command(h2.bin, "serve", "--config", h2.cfgPath)
	h2.cmd.Stdout = h2.stdout
	h2.cmd.Stderr = h2.stderr
	if err := h2.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h.cmd = nil // stopAll must not double-kill
	t.Cleanup(h2.stopAll)
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(h2.stdout.String(), "raylane: management") {
		if time.Now().After(deadline) {
			t.Fatalf("restart not ready: stdout=%s stderr=%s", h2.stdout, h2.stderr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	req, _ = http.NewRequest(http.MethodGet, h2.lanURL+"/api/v1/state", nil)
	req.AddCookie(c)
	resp, err = h2.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old cookie after restart = %d, want 401 (sessions are RAM-only)", resp.StatusCode)
	}
	readAll(t, resp)
	code, _ = h2.bootstrap("")
	if code != 1 {
		t.Fatalf("bootstrap after restart code=%d, want 1 (store closure permanent)", code)
	}
	// Re-login works with the same credentials.
	resp = h2.login("admin", "correct horse battery staple", h2.origin)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("post-restart login = %d, want 204", resp.StatusCode)
	}
	readAll(t, resp)
}

// TestT009ShellAndAssetsServedSameOrigin verifies, against the REAL compiled
// process over REAL HTTPS on the SAME origin as the management API, that:
//   - GET/HEAD the exact root serves the shell (no-store, strict CSP, nosniff,
//     no-referrer, request-id) — never a redirect, never HTML on errors;
//   - the referenced content-hashed assets are served with immutable caching
//     and their own strict headers (the browser can actually load the UI);
//   - unknown paths, the API subtree boundary and every LAN bootstrap variant
//     still answer the SAME generic 403 — never the shell, no existence oracle.
func TestT009ShellAndAssetsServedSameOrigin(t *testing.T) {
	h := startServe(t)
	client := h.client()

	get := func(target string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, h.lanURL+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v (stderr=%s)", target, err, h.stderr)
		}
		return resp
	}

	// Shell at exact root.
	root := get("/")
	if root.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", root.StatusCode)
	}
	if ct := root.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("GET / Content-Type=%q", ct)
	}
	if cc := root.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("GET / Cache-Control=%q, want no-store", cc)
	}
	csp := root.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("GET / missing CSP")
	}
	for _, banned := range []string{"unsafe-inline", "unsafe-eval", "data:", "http://", "https://"} {
		if strings.Contains(csp, banned) {
			t.Fatalf("GET / CSP contains banned %q: %s", banned, csp)
		}
	}
	for _, want := range []string{"script-src 'self'", "style-src 'self'", "connect-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("GET / CSP missing %q: %s", want, csp)
		}
	}
	if root.Header.Get("X-Content-Type-Options") != "nosniff" || root.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("GET / missing nosniff/no-referrer")
	}
	html := string(readAll(t, root))
	if !strings.Contains(html, `<div id="root">`) || !strings.Contains(html, `/assets/`) {
		t.Fatalf("GET / body is not the built shell: %q", html)
	}

	// HEAD root: headers, empty body.
	req, _ := http.NewRequest(http.MethodHead, h.lanURL+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD / = %d, want 200", resp.StatusCode)
	}
	if b := readAll(t, resp); len(b) != 0 {
		t.Fatalf("HEAD / body len=%d, want 0", len(b))
	}

	// The shell references a content-hashed JS bundle: fetch it by parsing the
	// reference out of the served HTML (the browser-visible asset path).
	jsPath := extractAsset(t, html, ".js")
	js := get(jsPath)
	if js.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 (browser must load the real bundle)", jsPath, js.StatusCode)
	}
	if ct := js.Header.Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Fatalf("GET %s Content-Type=%q", jsPath, ct)
	}
	if cc := js.Header.Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Fatalf("GET %s Cache-Control=%q, want immutable content-hash caching", jsPath, cc)
	}
	jsBody := readAll(t, js)
	if len(jsBody) == 0 || !strings.Contains(string(jsBody), "Raylane") {
		t.Fatalf("GET %s did not return the real built bundle (len=%d)", jsPath, len(jsBody))
	}

	// No SPA catch-all + settled 403 preservation over the wire.
	for _, target := range []string{"/login", "/settings", "/index.html", "/a/b/c"} {
		r := get(target)
		if r.StatusCode != http.StatusForbidden {
			t.Fatalf("GET %s = %d, want generic 403 (no SPA catch-all)", target, r.StatusCode)
		}
		if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "text/html") {
			t.Fatalf("GET %s returned HTML; unknown paths must never serve the shell", target)
		}
		// The 403 fall-through goes through authhttp, so it carries a fresh
		// request id (the settled request-identity invariant on errors).
		if r.Header.Get("X-Request-Id") == "" {
			t.Fatalf("GET %s missing X-Request-Id", target)
		}
		readAll(t, r)
	}
	post, _ := http.NewRequest(http.MethodPost, h.lanURL+"/api/v1/bootstrap", strings.NewReader(`{}`))
	post.Header.Set("Origin", h.origin)
	resp, err = client.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("LAN /bootstrap = %d, want 403", resp.StatusCode)
	}
	readAll(t, resp)

	// A source map / unexpected file under assets is NOT served even if present
	// in the build tree: the allowlist rejects .map (and the others) with a
	// plain 404, never HTML.
	for _, target := range []string{"/assets/index-Ab3.js.map", "/assets/app.db", "/assets/config.yaml"} {
		r := get(target)
		if r.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404 (allowlist reject)", target, r.StatusCode)
		}
		if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "text/html") {
			t.Fatalf("GET %s returned HTML", target)
		}
		readAll(t, r)
	}
}

// extractAsset pulls the first /assets/... reference ending in ext out of the
// served shell HTML (the path the browser will actually request).
func extractAsset(t *testing.T, html, ext string) string {
	t.Helper()
	i := strings.Index(html, "/assets/")
	if i < 0 {
		t.Fatalf("shell HTML has no /assets/ reference: %q", html)
	}
	rest := html[i:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("unterminated asset reference: %q", rest)
	}
	ref := rest[:end]
	if !strings.HasSuffix(ref, ext) {
		t.Fatalf("first asset ref %q does not end in %s", ref, ext)
	}
	return ref
}

// TestT009ComposeLANRouting unit-tests the router with the REAL webui handler
// over a fixture bundle: shell/assets are answered by webui; everything else
// falls through to the API handler (which owns the generic 403). This pins the
// composition contract without a process.
func TestT009ComposeLANRouting(t *testing.T) {
	bundle := fstest.MapFS{
		"index.html":              &fstest.MapFile{Data: []byte("<shell/>")},
		".vite/manifest.json":     &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/index-Ab3.js","css":["assets/index-Ab3.css"]}}`)},
		"assets/index-Ab3.js":     &fstest.MapFile{Data: []byte("bundle")},
		"assets/index-Ab3.css":    &fstest.MapFile{Data: []byte("css")},
		"assets/index-Ab3.js.map": &fstest.MapFile{Data: []byte("{}")},
		"assets/leaked.db":        &fstest.MapFile{Data: []byte("SQLite")},
		"assets/stray-unref.js":   &fstest.MapFile{Data: []byte("x")},
	}
	shell, err := webui.New(bundle)
	if err != nil {
		t.Fatalf("webui.New: %v", err)
	}
	var apiHits int
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHits++
		w.WriteHeader(http.StatusForbidden)
	})
	h := composeLAN(shell, api)

	// Shell + allowlisted assets are served by webui (API not touched).
	for _, target := range []string{"/", "/assets/index-Ab3.js", "/assets/index-Ab3.css"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200 from shell", target, rec.Code)
		}
	}
	if apiHits != 0 {
		t.Fatalf("api hits=%d, want 0 for shell/asset requests", apiHits)
	}

	// Disallowed-under-assets are a webui 404 (handled, NOT fall-through 403):
	// source maps, databases, and UNREFERENCED allowlisted-extension files (the
	// build manifest is the membership, not the extension).
	for _, target := range []string{"/assets/index-Ab3.js.map", "/assets/leaked.db", "/assets/stray-unref.js"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404 allowlist reject", target, rec.Code)
		}
	}
	if apiHits != 0 {
		t.Fatalf("api hits=%d, want 0 (webui handles its own rejects)", apiHits)
	}

	// Unknown paths, API subtree, unsafe methods on root fall through to the
	// API handler (the generic 403 owner).
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/login"},
		{http.MethodGet, "/index.html"},
		{http.MethodGet, "/api/v1/state"},
		{http.MethodPost, "/api/v1/bootstrap"},
		{http.MethodPost, "/"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s = %d, want 403 from API", tc.method, tc.target, rec.Code)
		}
	}
	if apiHits != 5 {
		t.Fatalf("api hits=%d, want 5 (every non-shell request falls through)", apiHits)
	}
}

// TestT009WrongKindBundleFailsClosedAtStartup proves the INCOMPLETE-BUNDLE
// preflight on the REAL compiled serve path: an embedded bundle whose
// index.html or a manifest-declared asset exists but is a DIRECTORY (wrong
// kind — fs.Stat alone succeeds on it) makes `raylane serve` exit non-zero
// with one actionable error BEFORE the state DB is created/opened, before the
// control socket is bound and before the management listener is bound or
// readiness advertised. The isolated binary is built from a copied module
// snapshot with a crafted dist; the shared production dist is never touched.
func TestT009WrongKindBundleFailsClosedAtStartup(t *testing.T) {
	moduleDir := copyModuleForBundleTest(t)
	dist := filepath.Join(moduleDir, "web", "dist")
	// Craft a valid-looking dist, then corrupt one entry into a directory.
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(dist, rel)
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	mkdir := func(rel string) {
		t.Helper()
		full := filepath.Join(dist, rel)
		if err := os.RemoveAll(full); err != nil {
			t.Fatalf("remove %s: %v", rel, err)
		}
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		// A directory is only visible to go:embed when it is non-empty (embed
		// records directories implicitly from their files); give it a child so
		// the wrong-kind entry is actually embedded and Stat sees a directory.
		if err := os.WriteFile(filepath.Join(full, ".keep"), []byte("x"), 0o644); err != nil {
			t.Fatalf("seed dir %s: %v", rel, err)
		}
	}
	manifest := `{"index.html":{"file":"assets/index-D0S6vb5b.js","css":["assets/index-D3b3cTyl.css"]}}`
	seed := func() {
		if err := os.RemoveAll(dist); err != nil {
			t.Fatalf("reset dist: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(dist, "assets"), 0o755); err != nil {
			t.Fatalf("mkdir assets: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(dist, ".vite"), 0o755); err != nil {
			t.Fatalf("mkdir .vite: %v", err)
		}
		write("index.html", "<!doctype html><div id=root></div>")
		write(".vite/manifest.json", manifest)
		write("assets/index-D0S6vb5b.js", "console.log(1)")
		write("assets/index-D3b3cTyl.css", "body{margin:0}")
	}

	cases := map[string]func() string{
		"directory index": func() string {
			seed()
			mkdir("index.html")
			return "index.html"
		},
		"directory js asset": func() string {
			seed()
			mkdir("assets/index-D0S6vb5b.js")
			return "index.html" // index is fine; the JS asset is the directory
		},
		"directory css asset": func() string {
			seed()
			mkdir("assets/index-D3b3cTyl.css")
			return "index.html"
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			keptIndex := corrupt()
			bin := filepath.Join(moduleDir, "bin-wrongkind")
			build := exec.Command("go", "build", "-o", bin, "./cmd/raylane")
			build.Dir = moduleDir
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build isolated binary: %v\n%s", err, out)
			}

			runDir := t.TempDir()
			sockDir := filepath.Join(runDir, "run")
			// A real, knowable loopback port (ephemeral :0 is refused by config
			// validation before the bundle preflight, so it cannot be used here).
			pl, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("pick port: %v", err)
			}
			port := pl.Addr().(*net.TCPAddr).Port
			pl.Close()
			origin := fmt.Sprintf("https://127.0.0.1:%d", port)
			cfgPath := filepath.Join(runDir, "cfg.json")
			cfgJSON := fmt.Sprintf(`{"db":%q,"listen":%q,"origin":%q,"socketDir":%q,"tlsCert":%q,"tlsKey":%q}`,
				filepath.Join(runDir, "state.db"),
				fmt.Sprintf("127.0.0.1:%d", port),
				origin,
				sockDir,
				filepath.Join(runDir, "tls.crt"),
				filepath.Join(runDir, "tls.key"),
			)
			if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o600); err != nil {
				t.Fatalf("write cfg: %v", err)
			}
			// The TLS material paths need not exist: the bundle preflight runs
			// BEFORE the cert is loaded, so a fail-closed bundle never reaches it.
			cmd := exec.Command(bin, "serve", "--config", cfgPath)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			runErr := cmd.Run()
			if runErr == nil {
				t.Fatalf("serve exited 0 on a wrong-kind bundle (index=%s); stdout=%s stderr=%s", keptIndex, stdout.String(), stderr.String())
			}
			if ee, ok := runErr.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
				t.Fatalf("serve err=%v want exit 1; stderr=%s", runErr, stderr.String())
			}
			// Actionable, names the wrong kind, fails closed.
			combined := stdout.String() + stderr.String()
			if !strings.Contains(combined, "directory") {
				t.Fatalf("error should name the wrong kind 'directory': %s", combined)
			}
			if !strings.Contains(combined, "npm --prefix web run build") {
				t.Fatalf("error not actionable: %s", combined)
			}
			// No startup side effects: no state DB created/opened, no control
			// socket bound, no readiness line.
			if _, err := os.Stat(filepath.Join(runDir, "state.db")); !os.IsNotExist(err) {
				t.Fatalf("state.db created despite fail-closed bundle (err=%v)", err)
			}
			if entries, _ := os.ReadDir(sockDir); len(entries) != 0 {
				t.Fatalf("control socket dir not empty after bundle refusal: %v", entries)
			}
			if strings.Contains(stdout.String(), "raylane: management") {
				t.Fatalf("readiness advertised despite fail-closed bundle: %s", stdout.String())
			}
		})
	}
}

// copyModuleForBundleTest copies the Go module source needed to build
// cmd/raylane into a fresh temp dir (never the shared tree), so a crafted
// web/dist can be embedded without touching the production bundle. It copies
// go.mod/go.sum, cmd/, internal/, and web/embed.go; web/dist is created empty
// for the caller to seed.
func copyModuleForBundleTest(t *testing.T) string {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	dst := t.TempDir()
	copyFile := func(rel string, mode os.FileMode) {
		t.Helper()
		src := filepath.Join(repoRoot, rel)
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		target := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(rel), err)
		}
		if err := os.WriteFile(target, data, mode); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	copyDir := func(rel string) {
		t.Helper()
		err := filepath.WalkDir(filepath.Join(repoRoot, rel), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relToRepo, err := filepath.Rel(repoRoot, p)
			if err != nil {
				return err
			}
			target := filepath.Join(dst, relToRepo)
			if d.IsDir() {
				return os.MkdirAll(target, 0o755)
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			return os.WriteFile(target, data, 0o644)
		})
		if err != nil {
			t.Fatalf("copy dir %s: %v", rel, err)
		}
	}
	copyFile("go.mod", 0o644)
	copyFile("go.sum", 0o644)
	copyDir("cmd")
	copyDir("contracts")
	copyDir("internal")
	copyFile("web/embed.go", 0o644)
	// Fresh empty dist for the caller to seed (never copy the production dist).
	if err := os.MkdirAll(filepath.Join(dst, "web", "dist"), 0o755); err != nil {
		t.Fatalf("mkdir dist: %v", err)
	}
	return dst
}

// TestT008ServeRejectsSecondInstance: while a live server owns the socket,
// a second `serve` exits non-zero WITHOUT touching the live one.
func TestT008ServeRejectsSecondInstance(t *testing.T) {
	h := startServe(t)
	// A second instance on a DIFFERENT port (so the config is valid) but the
	// SAME socket dir reuses the first instance's TLS material; it must be
	// refused by the live-socket ownership check (exit 1), not bind over it.
	secondPort := h.lanPort + 1
	secondCfgPath := filepath.Join(h.dir, "serve-config-second.json")
	secondCfgJSON := fmt.Sprintf(`{"db":%q,"listen":%q,"origin":%q,"socketDir":%q,"tlsCert":%q,"tlsKey":%q}`,
		filepath.Join(h.dir, "state.db"),
		fmt.Sprintf("127.0.0.1:%d", secondPort),
		fmt.Sprintf("https://127.0.0.1:%d", secondPort),
		h.sockDir,
		h.certPath,
		filepath.Join(h.dir, "tls", "management.key"),
	)
	if err := os.WriteFile(secondCfgPath, []byte(secondCfgJSON), 0o600); err != nil {
		t.Fatalf("write second serve config: %v", err)
	}
	second := exec.Command(h.bin, "serve", "--config", secondCfgPath)
	out2 := &bytes.Buffer{}
	second.Stdout = io.Discard
	second.Stderr = out2
	err := second.Run()
	if err == nil {
		t.Fatal("second serve exited 0 while the first owns the socket")
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
		t.Fatalf("second serve err=%v out=%s, want exit 1", err, out2)
	}
	if !strings.Contains(out2.String(), "another live raylane") {
		t.Fatalf("second serve stderr = %s, want live-socket refusal", out2)
	}
	// The live server is untouched.
	resp := h.login("nobody", "nothing", h.origin)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("live server responded %d after rejected second instance", resp.StatusCode)
	}
	readAll(t, resp)
}
