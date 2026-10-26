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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
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
