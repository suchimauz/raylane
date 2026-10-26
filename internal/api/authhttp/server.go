package authhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/suchimauz/raylane/internal/api/auth"
	"github.com/suchimauz/raylane/internal/store"
)

// loginBodyLimit and bootstrapBodyLimit bound the JSON request bodies (the
// settled contract: 4096 and 8192 bytes).
const (
	loginBodyLimit     = 4096
	bootstrapBodyLimit = 8192
)

// credentialsJSON mirrors the SessionCredentials body: exact decoded strings,
// length counted in code points by the schema. We decode raw bytes and
// validate UTF-8 + code-point length ourselves (never trim/normalize).
type credentialsJSON struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Server is the runtime composition boundary. It hosts the management HTTP
// handlers over the accepted auth primitives and store. It exposes NO raw
// store handle, NO secret and NO callback; the store and primitives are
// private fields used only inside the handlers.
type Server struct {
	cfg     Config
	store   *store.Store
	sess    *sessionManager
	limiter *loginLimiter
	issuer  *bootstrapIssuer
	now     func() time.Time
}

// NewServer validates cfg and returns a ready Server bound to an already-open
// store. The store ownership stays with the caller (Close closes the HTTP
// listeners, not the store).
func NewServer(cfg Config, st *store.Store) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errors.New("authhttp: store is required")
	}
	s := &Server{
		cfg:   cfg,
		store: st,
		now:   time.Now,
	}
	// The session manager, the limiter and the token issuer all read the
	// SERVER's clock field through this closure, so a test that replaces
	// s.now drives every timed component from ONE seam.
	clock := func() time.Time { return s.now() }
	s.sess = newSessionManagerAt(clock)
	s.limiter = newLoginLimiterAt(clock)
	s.issuer = newBootstrapIssuerAt(clock)
	return s, nil
}

// Handler returns the LAN management HTTP handler: request identity first,
// then CSRF on unsafe methods. The /state and /session paths live here;
// /bootstrap and /bootstrap-token are NOT on this LAN handler (they are
// served only on the local Unix transport) and every unregistered LAN path
// answers the generic 403 (settled contract: no existence oracle).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/state", s.handleState)
	mux.HandleFunc("/api/v1/session", s.handleSession)
	mux.HandleFunc("/", notFoundHandler)
	// The LAN handler is the OUTER layer, so it is the one that applies the
	// no-store response policy for every management response (the local
	// handler is a different server instance and sets it on its issuance
	// response explicitly).
	return requestIdentity(requireOrigin(s.cfg.TrustedOrigin, noStore(mux)))
}

// noStore stamps the settled response policy on every management response:
// no caching intermediaries and no MIME sniffing.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// ManagementHandler returns the local Unix-socket handler: it ADDS the
// bootstrap issuance and redemption routes, which are physically ABSENT from
// the LAN handler. Locality is decided by WHICH listener accepted the
// connection; no Origin/CSRF check applies here because a browser origin
// cannot exist over the owner-only Unix socket, and locality is exactly the
// trusted-channel decision (DECISION.md §5).
func (s *Server) ManagementHandler() http.Handler {
	return requestIdentity(s.managementMux())
}

// managementMux is the local Unix-socket handler: it ADDS the bootstrap
// issuance and redemption routes, which are physically ABSENT from the LAN
// handler. The settled local issuance path is the UNVERSIONED
// POST /bootstrap-token; redemption stays POST /api/v1/bootstrap. Locality is
// decided by WHICH listener accepted the connection.
func (s *Server) managementMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/state", s.handleState)
	mux.HandleFunc("/api/v1/session", s.handleSession)
	mux.HandleFunc("/bootstrap-token", s.handleBootstrapToken)
	mux.HandleFunc("/api/v1/bootstrap", s.handleBootstrap)
	mux.HandleFunc("/", notFoundHandler)
	return mux
}

// sessionCookie builds the session cookie with the EXACT settled attributes:
// Secure, HttpOnly, SameSite=Strict, host-only (no Domain), Path=/api/v1.
//
// Go's http.Cookie.MaxAge semantics: >0 emits "Max-Age=n", ==0 OMITS the
// attribute (a session cookie with no explicit expiry), and <0 emits
// "Max-Age=0" (delete immediately). Login therefore uses maxAge==0 (a live
// session cookie, NO Max-Age attribute); logout expiry uses maxAge<0.
func sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/api/v1",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// --- handlers ---

// handleState implements GET /state: the session auth probe and the truthful
// runtime state. It requires a valid session (401 otherwise).
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r.Context())
	if r.Method != http.MethodGet {
		writeProblem(w, http.StatusMethodNotAllowed, codeBadRequest, msgBadRequest, requestID)
		return
	}
	if !s.authenticated(r) {
		writeProblem(w, http.StatusUnauthorized, codeInvalidCredentials, msgInvalidCredentials, requestID)
		return
	}
	// Truthful state: no engine or dataplane guard exists, so the phase is
	// "not-running" (NOT active/verifying/switching/stopped-guarded, which
	// would claim a guard that is not engaged). Management readiness reflects
	// that the management API actually serves (it does, here); dns/engine/
	// classification are FALSE because none of those subsystems exists. No
	// draft/active revision or generation is invented.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"phase": "not-running",
		"readiness": map[string]bool{
			"management":     true,
			"dns":            false,
			"engine":         false,
			"classification": false,
		},
	})
}

// handleSession routes POST (login) and DELETE (logout) on /session.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleLogin(w, r)
	case http.MethodDelete:
		s.handleLogout(w, r)
	default:
		writeProblem(w, http.StatusMethodNotAllowed, codeBadRequest, msgBadRequest, requestIDFrom(r.Context()))
	}
}

// handleLogin implements POST /session. It checks Origin (via the outer CSRF
// middleware) before session validation, enforces the anonymous limiter,
// verifies the identity, and on success sets the session cookie with the EXACT
// attributes and returns 204. Every mismatch (missing identity, wrong
// username, wrong password, malformed verifier) is the SAME 401
// invalid_credentials; the missing-admin response is byte-identical.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r.Context())
	// Read and strictly decode the body BEFORE any limiter/KDF work: a
	// non-conforming or invalid-UTF-8 credential is rejected with the generic
	// 401 category without spending a token or touching Argon2, uniformly on
	// login (and identically-shaped requests on bootstrap).
	body, err := readBounded(r, loginBodyLimit)
	if err != nil {
		writeProblem(w, http.StatusRequestEntityTooLarge, codeBadRequest, msgBadRequest, requestID)
		return
	}
	var creds credentialsJSON
	if err := decodeStrictJSON(body, &creds); err != nil {
		writeProblem(w, http.StatusUnauthorized, codeInvalidCredentials, msgInvalidCredentials, requestID)
		return
	}
	if !auth.ValidUsername([]byte(creds.Username)) || !auth.ValidPassword([]byte(creds.Password)) {
		// A length/UTF-8-invalid credential never reaches the KDF; same generic
		// 401, no per-field oracle.
		writeProblem(w, http.StatusUnauthorized, codeInvalidCredentials, msgInvalidCredentials, requestID)
		return
	}
	// Anonymous login limiter on the actual socket peer IP, consulted only
	// for well-formed attempts.
	permitted, retryAfter, release := s.limiter.Allow(peerIP(r.RemoteAddr))
	if !permitted {
		// Retry-After is emitted ONLY when a concrete per-peer retry delay is
		// computable (retryAfter > 0, a positive integer); when the global
		// Argon2 ceiling is the blocker the limiter reports -1 and the header
		// is OMITTED rather than fabricated.
		if retryAfter > 0 {
			w.Header().Set("Retry-After", itoa(retryAfter))
		}
		writeProblem(w, http.StatusTooManyRequests, codeRateLimited, msgRateLimited, requestID)
		return
	}
	defer release()
	// Validate exact decoded bytes (valid UTF-8, code-point length) before any
	// KDF work; a malformed credential is the same generic 401 category as a
	// wrong one (never a per-field oracle). On success a FRESH session is
	// issued (POST /session always replaces the caller's session).
	ok, err := auth.VerifyIdentity(r.Context(), s.store, auth.Credentials{
		Username: []byte(creds.Username),
		Password: []byte(creds.Password),
	})
	if err != nil || !ok {
		// Missing admin, wrong username, wrong password and storage failure are
		// ALL the same generic 401: identical status/code/message/shape, only
		// the fresh per-request requestId differs (the contract requires it).
		writeProblem(w, http.StatusUnauthorized, codeInvalidCredentials, msgInvalidCredentials, requestID)
		return
	}
	raw, err := s.sess.Create()
	if err != nil {
		// Session capacity reached: surface as the generic limiter category.
		w.Header().Set("Retry-After", intHeader(limitRefillSeconds))
		writeProblem(w, http.StatusTooManyRequests, codeRateLimited, msgRateLimited, requestID)
		return
	}
	// Live session cookie: NO Max-Age attribute (maxAge==0 omits it), Secure,
	// HttpOnly, SameSite=Strict, host-only, Path=/api/v1.
	http.SetCookie(w, sessionCookie(raw, 0))
	w.WriteHeader(http.StatusNoContent)
}

// handleLogout implements DELETE /session: bad Origin is already rejected by
// the outer CSRF middleware (403 first). With no valid session it is 401; with
// a valid session it revokes and returns 204 (idempotent — re-logout is 401
// because the session is gone).
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	raw, err := r.Cookie(sessionCookieName)
	if err != nil || !s.sess.Lookup(raw.Value) {
		writeProblem(w, http.StatusUnauthorized, codeInvalidCredentials, msgInvalidCredentials, requestIDFrom(r.Context()))
		return
	}
	s.sess.Revoke(raw.Value)
	// Expire: empty value + Max-Age=0 (maxAge<0 serializes as Max-Age=0) + the
	// SAME attributes (Secure, HttpOnly, SameSite=Strict, host-only, Path).
	http.SetCookie(w, sessionCookie("", -1))
	w.WriteHeader(http.StatusNoContent)
}

// authenticated reports whether the request carries a valid session cookie.
func (s *Server) authenticated(r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return s.sess.Lookup(c.Value)
}

// --- local-only bootstrap handlers (Unix transport only) ---

// handleBootstrapToken implements POST /bootstrap-token on the LOCAL Unix
// transport only: it issues the one-time token (TTL 300 s, at most one live)
// and prints it to the response. On this socket there is no browser origin,
// so no Origin/CSRF check applies (locality IS the trusted-channel decision,
// made by WHICH listener accepted the connection). The token appears only in
// this local response; it is never logged or emitted elsewhere.
func (s *Server) handleBootstrapToken(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r.Context())
	if r.Method != http.MethodPost {
		writeProblem(w, http.StatusMethodNotAllowed, codeBadRequest, msgBadRequest, requestID)
		return
	}
	raw, ttl, err := s.issuer.Issue()
	if err != nil {
		// A live token already exists (reissuance rejected while one is live).
		writeProblem(w, http.StatusConflict, codeForbidden, msgForbidden, requestID)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"token":     raw,
		"expiresIn": int(ttl / time.Second),
	})
}

// handleBootstrap implements POST /bootstrap on the LOCAL Unix transport
// only: it redeems the token and creates the admin atomically. Token
// redemption, identity creation and the permanent closure commit together;
// exactly one concurrent request wins (409 for the rest).
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r.Context())
	if r.Method != http.MethodPost {
		writeProblem(w, http.StatusMethodNotAllowed, codeBadRequest, msgBadRequest, requestID)
		return
	}
	body, err := readBounded(r, bootstrapBodyLimit)
	if err != nil {
		writeProblem(w, http.StatusRequestEntityTooLarge, codeBadRequest, msgBadRequest, requestID)
		return
	}
	var req struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeStrictJSON(body, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, codeBadRequest, msgBadRequest, requestID)
		return
	}
	// Redeem the token BEFORE the expensive work: this is the
	// anti-brute-force gate — a wrong password burns the one-time token, so
	// offline guessing over the local channel is impossible. Then acquire the
	// SAME global Argon2 admission that login uses (shared max-2, fail-fast,
	// no queue) BEFORE any KDF/DB commit: a saturated gate is a bounded
	// capacity refusal that consumed the one-time token (single-winner
	// policy; no reusable credential survives a refusal) and fabricates no
	// Retry-After. Every token failure (expired/consumed/unknown/mismatched)
	// is the SAME generic 403 (no expiry/existence oracle). A shape-rejected
	// credential therefore also reports 403, never a field-specific 400.
	if !s.issuer.Redeem(req.Token) {
		writeProblem(w, http.StatusForbidden, codeForbidden, msgForbidden, requestID)
		return
	}
	if !s.limiter.TryAdmitKDF() {
		writeProblem(w, http.StatusTooManyRequests, codeRateLimited, msgRateLimited, requestID)
		return
	}
	defer s.limiter.ReleaseKDF()
	if !auth.ValidUsername([]byte(req.Username)) || !auth.ValidPassword([]byte(req.Password)) {
		// The token is already burned; the client must issue a new one.
		writeProblem(w, http.StatusForbidden, codeForbidden, msgForbidden, requestID)
		return
	}
	if err := auth.CreateIdentity(r.Context(), s.store, []byte(req.Username), []byte(req.Password)); err != nil {
		// Bootstrap already consumed (admin exists) or storage conflict: 409.
		writeProblem(w, http.StatusConflict, codeForbidden, msgForbidden, requestID)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

// readBounded reads the body up to limit+1 bytes; a larger body is a 413.
func readBounded(r *http.Request, limit int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// decodeStrictJSON decodes a JSON object, rejecting trailing garbage and
// unknown shapes by using a strict decoder. A syntax or trailing-data error is
// reported as an error (the caller maps it to 400).
func decodeStrictJSON(body []byte, dst interface{}) error {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// Reject trailing data after the top-level object.
	if dec.More() {
		return errors.New("authhttp: trailing data after JSON body")
	}
	return nil
}

// intHeader formats a non-negative integer for a header value.
func intHeader(n int) string {
	if n <= 0 {
		return "0"
	}
	return itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// writeJSON writes a JSON body with the given status.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ensure net is referenced (peerIP uses net.SplitHostPort).
var _ = net.SplitHostPort

// ServeManagement runs the LAN HTTPS listener until ctx is cancelled. It is a
// thin wrapper the CLI drives; TLS termination uses the configured cert/key.
func (s *Server) ServeManagement(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.ManagementListen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	err := srv.ListenAndServeTLS(s.cfg.TLSCertPath, s.cfg.TLSKeyPath)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeLocal runs the owner-only local Unix-socket listener until ctx is
// cancelled. It OWNS the socket lifecycle: the parent directory is created
// 0700, a stale socket file from a previous crashed run is replaced, the
// socket is bound 0600, and both are removed on shutdown. Local trust is
// decided by WHICH listener accepted the connection — never by a header.
func (s *Server) ServeLocal(ctx context.Context) error {
	sockDir := s.cfg.UnixSocketDir
	// Establish the owner-only 0700 directory WITHOUT following a path alias:
	// every component must be a real directory owned by the current uid; a
	// symlinked or foreign component is refused BEFORE mkdir/chmod, so a
	// symlink target's metadata/content is never touched.
	uid := os.Getuid()
	abs, err := filepath.Abs(sockDir)
	if err != nil {
		return fmt.Errorf("authhttp: local socket dir: %w", err)
	}
	if err := proveNoForeignSymlinkComponent(abs, uid); err != nil {
		return err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return fmt.Errorf("authhttp: local socket dir: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("authhttp: local socket dir stat: %w", err)
	}
	if st.Sys().(*syscall.Stat_t).Uid != uint32(uid) {
		return fmt.Errorf("authhttp: local socket dir %s is owned by another uid", abs)
	}
	if st.Mode().Perm()&^0o700 != 0 {
		if err := os.Chmod(abs, 0o700); err != nil {
			return fmt.Errorf("authhttp: local socket dir mode: %w", err)
		}
		st, err = os.Stat(abs)
		if err != nil {
			return fmt.Errorf("authhttp: local socket dir stat: %w", err)
		}
	}
	if st.Mode().Perm() != 0o700 {
		return fmt.Errorf("authhttp: local socket dir %s has mode %o, want 700", abs, st.Mode().Perm())
	}
	sockPath := filepath.Join(abs, "control.sock")
	if err := ensureLocalSocketPath(sockPath); err != nil {
		return err
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("authhttp: local socket listen: %w", err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("authhttp: local socket mode: %w", err)
	}
	srv := &http.Server{
		Handler:           s.ManagementHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
		os.Remove(sockPath)
	}()
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// proveNoForeignSymlinkComponent refuses any symlink component of abs whose
// resolved target is not a directory owned by uid, and any non-directory or
// foreign-owned real component. It is pure inspection: nothing is created or
// chmod'ed, so refusing leaves every touched path's metadata unchanged.
func proveNoForeignSymlinkComponent(abs string, uid int) error {
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	cur := "/"
	for _, part := range parts {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		lst, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // remaining components do not exist yet
			}
			return fmt.Errorf("authhttp: local socket dir: lstat %s: %w", cur, err)
		}
		if lst.Mode()&os.ModeSymlink != 0 {
			// Never follow a path alias just to make it appear safe: refuse the
			// symlink component outright, before touching anything.
			return fmt.Errorf("authhttp: local socket dir: symlink component %s is refused", cur)
		}
		if !lst.IsDir() {
			return fmt.Errorf("authhttp: local socket dir: component %s exists and is not a directory", cur)
		}
	}
	return nil
}

// ensureLocalSocketPath refuses to overwrite a live socket of another live
// process and clears a stale socket file from a dead one (connect fails on a
// stale socket). A non-socket file at the path is a hard error.
func ensureLocalSocketPath(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("authhttp: local socket stat: %w", err)
	}
	if st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("authhttp: local socket path %s exists and is not a socket", path)
	}
	c, derr := net.Dial("unix", path)
	if derr == nil {
		c.Close()
		return fmt.Errorf("authhttp: another live local server owns %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("authhttp: remove stale local socket: %w", err)
	}
	return nil
}
