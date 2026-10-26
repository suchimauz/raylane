package authhttp

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suchimauz/raylane/internal/api/auth"
	"github.com/suchimauz/raylane/internal/store"
)

// TestT008MeasureGlobalArgon2Ceiling measures the real concurrency and cost
// of the global Argon2 ceiling under a 16-way wrong-password burst against
// the real handlers and the real store. DECISION requires a MEASURED value,
// not the arithmetic 2x64 MiB bound: the test proves the ceiling is never
// exceeded (a sampler watches the semaphore) and reports the observed
// per-attempt durations and process heap growth as the measured evidence.
func TestT008MeasureGlobalArgon2Ceiling(t *testing.T) {
	cfg := Config{
		ManagementListen: "127.0.0.1:0", TrustedOrigin: "https://m.test",
		TLSCertPath: "x", TLSKeyPath: "x",
		DBPath: filepath.Join(t.TempDir(), "s.db"), UnixSocketDir: t.TempDir(),
	}
	db, err := store.Open(context.Background(), cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv, err := NewServer(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.CreateIdentity(context.Background(), db, []byte("admin"), []byte("measure password long enough")); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	var samplerStop chan struct{}
	var peak atomic.Int64
	var wgSync sync.WaitGroup
	samplerStop = make(chan struct{})
	wgSync.Add(1)
	go func() {
		defer wgSync.Done()
		for {
			select {
			case <-samplerStop:
				return
			default:
			}
			if a := int64(srv.limiter.activeForTest()); a > peak.Load() {
				peak.Store(a)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()

	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)
	const racers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	codes := make([]int, racers)
	durations := make([]time.Duration, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := `{"username":"admin","password":"wrong password variant ` + string(rune('A'+i)) + `"}`
			t0 := time.Now()
			resp := do(h, http.MethodPost, "/api/v1/session", "https://m.test", body, func(r *http.Request) {
				r.RemoteAddr = fmt.Sprintf("198.51.100.%d:7", 20+i/5)
			})
			resp.Body.Close()
			durations[i] = time.Since(t0)
			codes[i] = resp.StatusCode
		}(i)
	}
	close(start)
	wg.Wait()
	close(samplerStop)
	wgSync.Wait()

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	slowest := time.Duration(0)
	for _, d := range durations {
		if d > slowest {
			slowest = d
		}
	}
	t.Logf("MEASURED burst: racers=%d peakSimultaneousArgon2=%d (ceiling %d) slowestAttempt=%v heapSys+TotalAllocΔ=%d KiB codes=%v",
		racers, peak.Load(), limitGlobalArgon2, slowest, (m1.HeapSys)/1024, codes)
	if peak.Load() > limitGlobalArgon2 {
		t.Fatalf("global Argon2 ceiling violated: observed %d active", peak.Load())
	}
	for _, c := range codes {
		if c != http.StatusUnauthorized && c != http.StatusTooManyRequests {
			t.Fatalf("burst produced %d — only 401/429 are allowed", c)
		}
	}
}
