package main

// T012 authenticated managed-node create/read over the REAL process: real TLS
// rooted at the owned test CA, local-Unix bootstrap, a REAL login (actual
// session cookie + Origin), then keyed POST /api/v1/nodes → 201 and a safe
// GET /api/v1/nodes/{id} → 200, plus a keyless cold reader over the SAME DB
// returning the same whole-history verdict + current presence. This closes the
// real-process / real-cookie / cold-keyless gap the in-process httptest fixture
// could not establish. It reuses the harness TLS material generator, the
// compiled profile, and the production SecretStore readback; no test-only
// decrypt and no new production getter beyond the narrow SecretStore method.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/suchimauz/raylane/contracts"
	"github.com/suchimauz/raylane/internal/domain/nodes"
	"github.com/suchimauz/raylane/internal/store"
)

const t012RealNodeBody = `{"protocol":"vless","label":"edge-real-1","fields":{` +
	`"active":{"server":"v.example","serverPort":443,"transport":"ws","security":"tls"},` +
	`"inactive":{"muxEnabled":false},` +
	`"unknown":{}},` +
	`"secrets":{"uuid":{"op":"replace","value":"t012-real-uuid-CANARY"}}}`

// t012FixtureBase returns a trusted 0700 fixture root in the repo's ignored
// .hyper/tmp area. The production "/"-anchored key trust chain rejects the
// 1777 system temp (t.TempDir with unset TMPDIR), so trusted fixtures live
// here: every ancestor is real, non-group/world-writable, euid-owned.
func t012FixtureBase(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join(".", ".hyper", "tmp", "serve-t012-fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		t.Fatal(err)
	}
	return abs
}

// t012TrustedDir returns a fresh 0700 fixture directory in the trusted chain.
func t012TrustedDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp(t012FixtureBase(t), "d")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// startKeyedServe launches the real process ONCE with a trusted node key
// configured (nodeKey) so the authenticated create composes a keyed atomic
// writer. The trusted 0600 key and the operator config live under the
// harness's owned (0700-ancestry) temp dir; a fresh loopback port avoids the
// second-instance guard. Bootstrap and login then run once on this keyed store.
func startKeyedServe(t *testing.T) (*harness, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()
	trusted := t012TrustedDir(t)
	h := &harness{
		t:       t,
		bin:     buildBinary(t),
		dir:     trusted,
		sockDir: filepath.Join(trusted, "run"),
		stdout:  &syncBuf{},
		stderr:  &syncBuf{},
	}
	h.lanHost = "127.0.0.1"
	h.lanPort = addr.Port
	h.lanURL = fmt.Sprintf("https://%s:%d", h.lanHost, h.lanPort)
	h.origin = h.lanURL

	certPath := filepath.Join(h.dir, "tls", "management.crt")
	keyPath := filepath.Join(h.dir, "tls", "management.key")
	if err := ensureSelfSignedTLS(certPath, keyPath, []string{"localhost", "127.0.0.1"}); err != nil {
		t.Fatalf("generate test TLS material: %v", err)
	}
	h.certPath = certPath
	caCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	h.caPool = x509.NewCertPool()
	if !h.caPool.AppendCertsFromPEM(caCert) {
		t.Fatal("append test CA to pool")
	}

	nodeKeyPath := filepath.Join(h.dir, "node-master.key")
	nodeKey := make([]byte, 32)
	for i := range nodeKey {
		nodeKey[i] = byte(i + 1)
	}
	if err := os.WriteFile(nodeKeyPath, nodeKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nodeKeyPath, 0o600); err != nil {
		t.Fatal(err)
	}

	h.cfgPath = filepath.Join(h.dir, "serve-config.json")
	cfgJSON := fmt.Sprintf(`{"db":%q,"listen":%q,"origin":%q,"socketDir":%q,"tlsCert":%q,"tlsKey":%q,"nodeKey":%q}`,
		filepath.Join(h.dir, "state.db"),
		fmt.Sprintf("%s:%d", h.lanHost, h.lanPort),
		h.origin,
		h.sockDir,
		certPath,
		keyPath,
		nodeKeyPath,
	)
	if err := os.WriteFile(h.cfgPath, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	h.cmd = exec.Command(h.bin, "serve", "--config", h.cfgPath)
	h.cmd.Stdout = h.stdout
	h.cmd.Stderr = h.stderr
	if err := h.cmd.Start(); err != nil {
		t.Fatalf("start keyed serve: %v", err)
	}
	t.Cleanup(h.stopAll)
	waitServeReady(t, h)
	return h, nodeKeyPath
}

func waitServeReady(t *testing.T, h *harness) {
	t.Helper()
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
}

func TestT012AuthenticatedNodeCreateReadRealProcess(t *testing.T) {
	h, nodeKeyPath := startKeyedServe(t)

	// Local-Unix bootstrap, then a REAL login (actual cookie + Origin).
	code, _ := h.bootstrap("")
	if code != 0 {
		t.Fatalf("bootstrap code=%d", code)
	}
	resp := h.login("admin", "correct horse battery staple", h.origin)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("login=%d want 204; stderr=%s", resp.StatusCode, h.stderr)
	}
	c := cookieOf(resp)
	if c == nil {
		t.Fatal("no session cookie")
	}

	// Keyed POST → 201 NodeDraft (server-generated id, revision 1).
	cr, err := t012RealPost(t, h, c, t012RealNodeBody)
	if err != nil {
		t.Fatalf("POST node: %v", err)
	}
	if cr.StatusCode != http.StatusCreated {
		t.Fatalf("create=%d want 201; body=%s", cr.StatusCode, readAll(t, cr))
	}
	created := readAll(t, cr)
	for _, canary := range []string{"t012-real-uuid-CANARY"} {
		if strings.Contains(string(created), canary) {
			t.Fatalf("201 leaked %q", canary)
		}
	}
	var draft struct {
		ID       string `json:"id"`
		Protocol string `json:"protocol"`
		Revision int64  `json:"revision"`
	}
	if err := json.Unmarshal(created, &draft); err != nil {
		t.Fatalf("decode 201: %v", err)
	}
	if draft.ID == "" || draft.Protocol != "vless" || draft.Revision != 1 {
		t.Fatalf("201 draft mismatch: %+v", draft)
	}
	id := draft.ID

	// Safe GET → 200: same id/revision, safe projection, current presence, no leak.
	gr := t012RealGet(t, h, c, id)
	if gr.StatusCode != http.StatusOK {
		t.Fatalf("read=%d want 200; body=%s", gr.StatusCode, readAll(t, gr))
	}
	raw := readAll(t, gr)
	if strings.Contains(string(raw), "t012-real-uuid-CANARY") {
		t.Fatalf("GET leaked secret value")
	}
	var got struct {
		ID         string `json:"id"`
		Protocol   string `json:"protocol"`
		Revision   int64  `json:"revision"`
		Label      string `json:"label"`
		Validation struct {
			State      string           `json:"state"`
			Applicable bool             `json:"applicable"`
			Errors     []map[string]any `json:"errors"`
		} `json:"validation"`
		Secrets map[string]struct {
			Present bool `json:"present"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if got.ID != id || got.Protocol != "vless" || got.Revision != 1 {
		t.Fatalf("GET identity/revision mismatch: %+v", got)
	}
	// The label is SEALED-only at this increment: omitted, not decrypted.
	if got.Label != "" {
		t.Fatalf("label must be omitted until a lossless read path exists, got %q", got.Label)
	}
	if got.Validation.State != "valid-draft" || !got.Validation.Applicable {
		t.Fatalf("GET validation mismatch: %+v errors=%v", got.Validation, got.Validation.Errors)
	}
	if len(got.Secrets) == 0 || !got.Secrets["uuid"].Present {
		t.Fatalf("uuid must read present:true, got %+v", got.Secrets)
	}
	anyFalse := false
	for _, s := range got.Secrets {
		if !s.Present {
			anyFalse = true
		}
	}
	if !anyFalse {
		t.Fatalf("declared-but-absent secrets must read present:false: %+v", got.Secrets)
	}

	// Exact components are sealed: decrypt the preservation container over the
	// SAME DB with the trusted key (production SecretStore readback).
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(h.dir, "state.db"))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer st.Close()
	ss, err := store.OpenSecretStore(st, nodeKeyPath)
	if err != nil {
		t.Fatalf("open secret store: %v", err)
	}
	plain, err := ss.OpenPreservation(ctx, id)
	if err != nil {
		t.Fatalf("preservation: %v", err)
	}
	want := []byte(`{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"ws","security":"tls"},"inactive":{"muxEnabled":false},"unknown":{}},"label":"edge-real-1"}`)
	if !bytes.Equal(plain, want) {
		t.Fatalf("preservation must hold EXACT original components\n got: %s\nwant: %s", plain, want)
	}
	if bytes.Contains(plain, []byte("t012-real-uuid-CANARY")) {
		t.Fatal("typed secret value leaked into preservation")
	}

	// Keyless cold reader over the SAME DB: same whole-history verdict + presence.
	auth, err := store.OpenNodeAuthority(contracts.ProfileBytes())
	if err != nil {
		t.Fatal(err)
	}
	coldReader, err := store.OpenNodeReader(st, auth)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := coldReader.ReadNodeSafe(ctx, id)
	if err != nil {
		t.Fatalf("cold keyless read: %v", err)
	}
	if snap.Validation.Status != nodes.Valid || !snap.SecretPresence["uuid"] {
		t.Fatalf("cold read mismatch: status=%v presence=%+v", snap.Validation.Status, snap.SecretPresence)
	}

	// Semantic-invalid (unknown quarantine) SAVES as an Invalid draft, and the
	// GET returns the SAME actual Invalid + findings (never revalidated).
	quarantineBody := `{"protocol":"vless","fields":{"active":{"server":"v.example","serverPort":443,"transport":"ws","security":"tls"},"inactive":{},"unknown":{"flow":"quarantine-canary-value"}},"secrets":{"uuid":{"op":"replace","value":"t012-quar-uuid-CANARY"}}}`
	qr, err := t012RealPost(t, h, c, quarantineBody)
	if err != nil {
		t.Fatal(err)
	}
	if qr.StatusCode != http.StatusCreated {
		t.Fatalf("quarantine create=%d want 201; body=%s", qr.StatusCode, readAll(t, qr))
	}
	qCreated := readAll(t, qr)
	if strings.Contains(string(qCreated), "t012-quar-uuid-CANARY") || strings.Contains(string(qCreated), "quarantine-canary-value") {
		t.Fatal("quarantine 201 leaked a secret/quarantined value")
	}
	var qDraft struct {
		ID         string `json:"id"`
		Validation struct {
			State      string           `json:"state"`
			Applicable bool             `json:"applicable"`
			Errors     []map[string]any `json:"errors"`
		} `json:"validation"`
	}
	if err := json.Unmarshal(qCreated, &qDraft); err != nil {
		t.Fatal(err)
	}
	if qDraft.Validation.State != "invalid-draft" || qDraft.Validation.Applicable {
		t.Fatalf("quarantine must save invalid-draft/notApplicable: %+v", qDraft.Validation)
	}
	qGet := t012RealGet(t, h, c, qDraft.ID)
	if qGet.StatusCode != http.StatusOK {
		t.Fatalf("quarantine read=%d want 200", qGet.StatusCode)
	}
	qRaw := readAll(t, qGet)
	if strings.Contains(string(qRaw), "quarantine-canary-value") || strings.Contains(string(qRaw), "t012-quar-uuid-CANARY") {
		t.Fatal("quarantine GET leaked a quarantined/secret value")
	}
	var qGot struct {
		Validation struct {
			State      string `json:"state"`
			Applicable bool   `json:"applicable"`
		} `json:"validation"`
	}
	if err := json.Unmarshal(qRaw, &qGot); err != nil {
		t.Fatal(err)
	}
	if qGot.Validation.State != "invalid-draft" || qGot.Validation.Applicable {
		t.Fatalf("quarantine GET must reproduce invalid-draft/notApplicable, got %+v", qGot.Validation)
	}
}

func t012RealGet(t *testing.T, h *harness, c *http.Cookie, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.lanURL+"/api/v1/nodes/"+id, nil)
	req.Header.Set("Origin", h.origin)
	req.AddCookie(c)
	r, err := h.client().Do(req)
	if err != nil {
		t.Fatalf("GET node: %v", err)
	}
	return r
}

func t012RealPost(t *testing.T, h *harness, c *http.Cookie, body string) (*http.Response, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.lanURL+"/api/v1/nodes", strings.NewReader(body))
	req.Header.Set("Origin", h.origin)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(c)
	return h.client().Do(req)
}
