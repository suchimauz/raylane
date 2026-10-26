package authhttp

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Serve the real local handler on an isolated owner-temp Unix socket, not
// the LAN route, and call the already settled unversioned issuance path.
func TestBuiRemainingLocalIssuerWirePath(t *testing.T) {
	srv, _ := newTestServer(t, "")
	sock := filepath.Join(t.TempDir(), "control.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.ManagementHandler()}
	done := make(chan error, 1)
	go func() { done <- hs.Serve(ln) }()
	defer func() { hs.Close(); <-done }()
	transport := &http.Transport{Dial: func(_, _ string) (net.Conn, error) { return net.Dial("unix", sock) }}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	resp, err := client.Post("http://unix/bootstrap-token", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("settled local POST /bootstrap-token: want200 got%d", resp.StatusCode)
	}
}

// Holding the SAME private runtime's global semaphore avoids timing guesses:
// if bootstrap still succeeds it has performed real Argon2/store work while
// the global two-slot admission gate was already fully occupied.
func TestBuiRemainingBootstrapHonorsGlobalKDFAdmission(t *testing.T) {
	srv, _ := newTestServer(t, "")
	for i := 0; i < cap(srv.limiter.argon2); i++ {
		srv.limiter.argon2 <- struct{}{}
	}
	defer func() {
		for len(srv.limiter.argon2) > 0 {
			<-srv.limiter.argon2
		}
	}()
	token, _, err := srv.issuer.Issue()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]string{"token": token, "username": "bui-isolated-admin", "password": "bui-isolated-password"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://unix/api/v1/bootstrap", strings.NewReader(string(raw)))
	rec := httptest.NewRecorder()
	start := time.Now()
	srv.ManagementHandler().ServeHTTP(rec, req)
	t.Logf("globalSlots=%d status=%d elapsed=%s", len(srv.limiter.argon2), rec.Code, time.Since(start))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatal(fmt.Sprintf("saturated global KDF gate must refuse bootstrap before work: want429 got%d", rec.Code))
	}
}
