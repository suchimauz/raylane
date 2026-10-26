package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

type harness struct {
	t       *testing.T
	bin     string
	dir     string
	sockDir string
	stdout  *bytes.Buffer
	stderr  *bytes.Buffer
	cmd     *exec.Cmd
	env     []string
	lanURL  string
	lanHost string
	lanPort int
	origin  string
}

// startServe picks a free loopback port, launches the real binary with
// --tls-generate-self-signed and waits for the "raylane: management" line.
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
		stdout:  &bytes.Buffer{},
		stderr:  &bytes.Buffer{},
	}
	h.lanHost = "127.0.0.1"
	h.lanPort = addr.Port
	// The cert covers localhost and 127.0.0.1; the Origin below uses the same
	// host:port as the client sees it.
	h.lanURL = fmt.Sprintf("https://%s:%d", h.lanHost, h.lanPort)
	h.origin = h.lanURL
	h.cmd = exec.Command(h.bin, "serve",
		"--db", filepath.Join(h.dir, "state.db"),
		"--listen", fmt.Sprintf("%s:%d", h.lanHost, h.lanPort),
		"--origin", h.origin,
		"--socket-dir", h.sockDir,
		"--tls-generate-self-signed",
		"--tls-dir", h.dir,
		"--tls-generate-for", "localhost,127.0.0.1",
	)
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

// exitCode runs one CLI invocation of the real binary and returns its exit
// code plus combined output.
func (h *harness) run(args ...string) (int, string) {
	h.t.Helper()
	cmd := exec.Command(h.bin, args...)
	cmd.Env = append(os.Environ(), h.env...)
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

func errorsAs(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

func (h *harness) bootstrap(credsEnv ...string) (int, string) {
	h.t.Helper()
	extra := append([]string{}, credsEnv...)
	saved := h.env
	h.env = append(saved, extra...)
	defer func() { h.env = saved }()
	code, out := h.run("bootstrap", "--socket-dir", h.sockDir)
	return code, out
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

func (h *harness) client() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test-only cert
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
	if code, out := h.run("bootstrap", "--socket-dir", t.TempDir()); code != 2 || !strings.Contains(out, "environment") {
		t.Fatalf("bootstrap without env credentials code=%d out=%s, want 2 + env hint", code, out)
	}
	if code, _ := h.run("serve"); code != 2 {
		t.Fatalf("serve without flags code=%d, want 2", code)
	}
	// The stderr never contains any credential material.
	code, out := h.run("bootstrap", "--socket-dir", t.TempDir())
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

	// Bootstrap without credentials in env is refused before touching the
	// socket (exit 2), and never echoes them.
	code, out := h.run("bootstrap", "--socket-dir", h.sockDir)
	if code != 2 {
		t.Fatalf("bootstrap without env creds code=%d out=%s, want 2", code, out)
	}

	creds := []string{"RAYLANE_BOOTSTRAP_USERNAME=admin", "RAYLANE_BOOTSTRAP_PASSWORD=correct horse battery staple"}
	code, out = h.bootstrap(creds...)
	if code != 0 || !strings.Contains(out, "permanently closed") {
		t.Fatalf("bootstrap code=%d out=%s stderr=%s, want 0 + success line", code, out, h.stderr)
	}
	// Second bootstrap: issuance of a NEW token is possible, but redeeming it
	// hits the permanent store closure — CLI exits 1 with the generic problem.
	code, out = h.bootstrap(creds...)
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
	h2 := &harness{t: t, bin: h.bin, dir: h.dir, sockDir: h.sockDir, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, lanHost: h.lanHost, lanPort: h.lanPort, lanURL: h.lanURL, origin: h.origin}
	h2.cmd = exec.Command(h2.bin, "serve",
		"--db", filepath.Join(h2.dir, "state.db"),
		"--listen", fmt.Sprintf("%s:%d", h2.lanHost, h2.lanPort),
		"--origin", h2.origin,
		"--socket-dir", h2.sockDir,
		"--tls-generate-self-signed",
		"--tls-dir", h2.dir,
	) // the cert/key pair from the first run is REUSED (no overwrite)
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
	code, _ = h2.bootstrap(creds...)
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
	second := exec.Command(h.bin, "serve",
		"--db", filepath.Join(h.dir, "state.db"),
		"--listen", fmt.Sprintf("127.0.0.1:%d", h.lanPort+1),
		"--origin", fmt.Sprintf("https://127.0.0.1:%d", h.lanPort+1),
		"--socket-dir", h.sockDir,
		"--tls-cert", filepath.Join(h.dir, "tls", "management.crt"),
		"--tls-key", filepath.Join(h.dir, "tls", "management.key"),
	)
	second.Stdout = io.Discard
	second.Stderr = io.Discard
	second.Stdout = nil
	out2 := &bytes.Buffer{}
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
