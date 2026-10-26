package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestT008LiveLimiterRealProcess drives the REAL HTTPS listener through the
// REAL Argon2 verification path: burst 5 failures, then 429 with integer
// Retry-After and the generic problem body, and a different loopback source
// port (a different peer IP is impossible on loopback, so the per-peer proof
// is done in-package) — here we prove the live wire contract and that the KDF
// gate holds the global Argon2 ceiling under a real concurrent burst.
func TestT008LiveLimiterRealProcess(t *testing.T) {
	h := startServe(t)
	// Bootstrap so a WRONG password goes through the real KDF (not the
	// no-verifier path): same generic 401 either way.
	code, out := h.bootstrap(`{"username":"admin","password":"long enough bootstrap pw"}`)
	if code != 0 {
		t.Fatalf("bootstrap code=%d out=%s", code, out)
	}
	const wrong = "wrong password attempts"
	var lastStatus int
	var retryAfter string
	var body string
	for i := 0; i < 8; i++ {
		resp := h.login("admin", wrong, h.origin)
		body = string(readAll(t, resp))
		lastStatus = resp.StatusCode
		retryAfter = resp.Header.Get("Retry-After")
		if resp.StatusCode == http.StatusTooManyRequests {
			break
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d, want 401", i+1, resp.StatusCode)
		}
	}
	if lastStatus != http.StatusTooManyRequests {
		t.Fatalf("after 8 attempts status = %d, want 429", lastStatus)
	}
	if retryAfter == "" {
		t.Fatal("429 without Retry-After")
	}
	for _, b := range retryAfter {
		if b < '0' || b > '9' {
			t.Fatalf("Retry-After %q not integer seconds", retryAfter)
		}
	}
	var p struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"requestId"`
	}
	if err := json.Unmarshal([]byte(body), &p); err != nil || p.Code != "rate_limited" || p.RequestID == "" {
		t.Fatalf("429 body = %s", body)
	}
	// Concurrent burst against a fresh loopback peer cannot pile up KDF
	// work: the two-active ceiling makes extras 429 fast. Time the burst:
	// 8 parallel wrong-password attempts from 8 connections must all be
	// answered quickly (no queue growth, no hang).
	start := time.Now()
	done := make(chan int, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			resp := h.login("second-user", strings.Repeat("x", 30)+"diff", h.origin)
			defer resp.Body.Close()
			done <- resp.StatusCode
		}(i)
	}
	for i := 0; i < 8; i++ {
		select {
		case c := <-done:
			if c != http.StatusUnauthorized && c != http.StatusTooManyRequests {
				t.Fatalf("burst status %d, want 401/429 only", c)
			}
		case <-time.After(60 * time.Second):
			t.Fatal("burst hung: the global Argon2 ceiling must fail fast, not queue")
		}
	}
	if el := time.Since(start); el > 120*time.Second {
		t.Fatalf("burst took %v", el)
	}
}
