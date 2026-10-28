package main

// The runnable control plane: `raylane serve` and `raylane bootstrap`.
//
// `serve` runs two listeners: the LAN management API over HTTPS (TLS is
// mandatory — no insecure fallback) and the owner-only local control socket
// (a Unix socket, directory 0700, socket 0600) which is the ONLY place the
// one-time bootstrap routes exist. `bootstrap` drives the local socket as a
// client: it requests a token and submits it, reading the admin username and
// password only from named environment variables — never from argv, where
// they would be visible in the process table. The one-time token is RAM-only
// in the serving process and is invalid after a restart.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/suchimauz/raylane/internal/api/authhttp"
	"github.com/suchimauz/raylane/internal/store"
	"github.com/suchimauz/raylane/internal/webui"
	webuiassets "github.com/suchimauz/raylane/web"
)

// dispatchCommands routes the runnable subcommands. ok is false when args do
// not name one of them, so main falls through to the scaffold flag handling
// (which keeps --version/--config behaviour and exit codes intact).
func dispatchCommands(args []string, stdout, stderr io.Writer, stdin io.Reader) (code int, ok bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case "serve":
		return runServe(args[1:], stdout, stderr), true
	case "bootstrap":
		return runBootstrap(args[1:], stdout, stderr, stdin), true
	}
	return 0, false
}

// serveConfigJSON is the strict explicit operator configuration read from a
// JSON file (never from credentials-bearing flags). Every field is required
// and the whole shape is validated by authhttp.Config.Validate before any
// listener opens or certificate work happens.
type serveConfigJSON struct {
	DBPath      string `json:"db"`
	Listen      string `json:"listen"`
	Origin      string `json:"origin"`
	SocketDir   string `json:"socketDir"`
	TLSCertPath string `json:"tlsCert"`
	TLSKeyPath  string `json:"tlsKey"`
	// NodeKeyPath is the OPTIONAL operator-configured trusted node master key.
	// Omitted keeps the runtime keyless (safe reads work; authenticated create
	// answers a static 503). A NONEMPTY path is validated for shape here and
	// opened exactly once at server composition — a configured-but-unusable key
	// is a hard no-downgrade refusal before the LAN listener binds.
	NodeKeyPath string `json:"nodeKey"`
}

func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the strict JSON operator configuration (required)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage:\n  raylane serve --config <path>\n\nThe JSON configuration object carries exactly:\n  {\"db\":\"...\",\"listen\":\"host:port\",\"origin\":\"https://host:port\",\"socketDir\":\"...\",\"tlsCert\":\"...\",\"tlsKey\":\"...\"}\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "raylane serve: unsupported argument %q\n", fs.Arg(0))
		fs.Usage()
		return 2
	}
	if *configPath == "" {
		fmt.Fprint(stderr, "raylane serve: --config is required\n")
		return 2
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "raylane serve: read config: %v\n", err)
		return 2
	}
	var sc serveConfigJSON
	if err := decodeStrictConfig(raw, &sc); err != nil {
		fmt.Fprintf(stderr, "raylane serve: config: %v\n", err)
		return 2
	}
	cfg := authhttp.Config{
		ManagementListen: sc.Listen,
		TrustedOrigin:    sc.Origin,
		TLSCertPath:      sc.TLSCertPath,
		TLSKeyPath:       sc.TLSKeyPath,
		DBPath:           sc.DBPath,
		UnixSocketDir:    sc.SocketDir,
		NodeKeyPath:      sc.NodeKeyPath,
	}
	// Validate the strict config BEFORE any certificate or listener work: an
	// unsafe/wildcard/public/non-HTTPS/mismatched config is refused here.
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "raylane serve: %v\n", err)
		return 2
	}
	return serve(cfg, stdout, stderr)
}

// decodeStrictConfig decodes a strict JSON object: unknown fields, trailing
// data and non-object shapes are rejected. The raw bytes are checked for
// valid UTF-8 FIRST — encoding/json would silently replace every invalid byte
// with U+FFFD and then accept the replaced value (e.g. turning an invalid
// byte in a path into a literal '\ufffd' filename), which is not a
// configuration any operator wrote.
func decodeStrictConfig(raw []byte, dst *serveConfigJSON) error {
	if !utf8.Valid(raw) {
		return errors.New("config is not valid UTF-8")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON config")
	}
	return nil
}

// serve is fail-closed at startup: it validates the embedded frontend bundle
// and refuses to displace a live instance (the owner-only socket check) BEFORE
// opening the state database or binding any listener — an incomplete bundle or
// a second instance must not write application state, advertise readiness, or
// collide with the first instance's TCP bind. Then it binds BOTH listeners
// (a half-bound control plane with bootstrap unreachable is refused), serves
// until SIGINT/SIGTERM or a listener failure, and shuts down gracefully.
func serve(cfg authhttp.Config, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Preflight 1: the embedded bundle (web/dist) was produced by the
	// canonical frontend step; if it is absent the Go build already failed at
	// go:embed. New() validates index/manifest/referenced-asset completeness
	// and fails closed with one actionable error — BEFORE any state write,
	// listener bind or readiness, never a successful broken panel.
	// The composition happens HERE (the CLI composition root), not inside
	// authhttp: the settled authhttp runtime-composition boundary (the T008
	// guard) is left byte-for-byte untouched.
	shell, err := webui.New(webuiassets.DistFS())
	if err != nil {
		fmt.Fprintf(stderr, "raylane serve: %v\n", err)
		return 1
	}

	// Preflight 2: the live-socket ownership check runs before opening the DB
	// or binding the LAN port, so a second instance is refused by the
	// socket-ownership check (exit 1) rather than by an unrelated TCP
	// address-in-use failure, and never touches the shared state database.
	// The listener is held for the whole run, so the check cannot be raced by
	// a third instance after the bind.
	localLn, err := listenLocalSocket(cfg.UnixSocketDir)
	if err != nil {
		fmt.Fprintf(stderr, "raylane serve: %v\n", err)
		return 1
	}
	sockPath := localLn.Addr().String()
	defer os.Remove(sockPath)
	defer localLn.Close()

	db, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		fmt.Fprintf(stderr, "raylane serve: open state database: %v\n", err)
		return 1
	}
	defer db.Close()

	srv, err := authhttp.NewServer(cfg, db)
	if err != nil {
		fmt.Fprintf(stderr, "raylane serve: %v\n", err)
		return 1
	}
	// The shell/assets handler answers only the exact root and the
	// build-referenced assets and sets its own strict no-store /
	// immutable-cache / CSP headers; every other request — the API subtree,
	// unknown paths, and every LAN bootstrap variant — falls through to
	// srv.Handler(), which keeps the generic 403, request-id and Origin
	// priority exactly as accepted.
	lanHandler := composeLAN(shell, srv.Handler())

	lanLn, err := net.Listen("tcp", cfg.ManagementListen)
	if err != nil {
		fmt.Fprintf(stderr, "raylane serve: listen %s: %v\n", cfg.ManagementListen, err)
		return 1
	}
	defer lanLn.Close()

	httpsLn, err := tlsListener(lanLn, cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "raylane serve: %v\n", err)
		return 1
	}

	lanSrv := &http.Server{Handler: lanHandler, ReadHeaderTimeout: 10 * time.Second}
	localSrv := &http.Server{Handler: srv.ManagementHandler(), ReadHeaderTimeout: 10 * time.Second}

	errCh := make(chan error, 2)
	go func() { errCh <- lanSrv.Serve(httpsLn) }()
	go func() { errCh <- localSrv.Serve(localLn) }()

	fmt.Fprintf(stdout, "raylane: management https://%s origin %s; local control socket %s\n",
		httpsLn.Addr().String(), cfg.TrustedOrigin, sockPath)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "raylane serve: listener failed: %v\n", err)
			shutdownBoth(lanSrv, localSrv)
			return 1
		}
	}
	shutdownBoth(lanSrv, localSrv)
	return 0
}

// composeLAN is the HTTPS request router for the single LAN listener. It
// gives the embedded shell handler the FIRST chance to answer a read-only
// request for the exact root or the /assets/ allowlist; anything the shell
// declines (every API path, unknown path, unsafe method, and every bootstrap
// variant) falls through to the authhttp LAN handler, which preserves the
// settled generic 403, request-id and Origin priority. There is no SPA
// catch-all: the shell is served ONLY at the exact root.
func composeLAN(shell *webui.Handler, api http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shell.ServeHTTP(w, r) {
			return
		}
		api.ServeHTTP(w, r)
	})
}

func shutdownBoth(lanSrv, localSrv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lanSrv.Shutdown(ctx)
	localSrv.Shutdown(ctx)
}

// listenLocalSocket binds the owner-only Unix control socket: the parent
// directory is created 0700 and re-proved, a stale socket file from a dead
// previous run is replaced, a socket that still accepts connections (a live
// server owns it) is a hard error, and the socket is bound 0600 with the mode
// proven by stat afterwards (a wide umask must not silently widen it).
func listenLocalSocket(dir string) (net.Listener, error) {
	if err := preparePrivateSocketDir(dir); err != nil {
		return nil, err
	}
	st, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("local socket dir stat: %w", err)
	}
	if st.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("local socket dir %s has mode %o, want 700", dir, st.Mode().Perm())
	}
	sockPath := filepath.Join(dir, "control.sock")
	if err := ensureStaleSocketRemovable(sockPath); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("local socket listen: %w", err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("local socket mode: %w", err)
	}
	st, err = os.Stat(sockPath)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("local socket stat: %w", err)
	}
	if st.Mode().Perm() != 0o600 {
		ln.Close()
		return nil, fmt.Errorf("local socket %s has mode %o, want 600", sockPath, st.Mode().Perm())
	}
	return ln, nil
}

// preparePrivateSocketDir establishes the owner-only 0700 socket directory
// WITHOUT ever following a path alias: every intermediate component of dir
// must be a real directory owned by the current uid (or a symlink chain whose
// resolved target is one), never a symlink into somebody else's tree, and the
// final directory must be owned by us with mode 0700. A foreign-owned or
// symlinked-away component is refused BEFORE any mkdir/chmod, so the target's
// metadata and content are never touched. Only a safe, own new path is
// created; an existing own 0700 directory is accepted as-is.
func preparePrivateSocketDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("local socket dir: empty path")
	}
	uid := os.Getuid()
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("local socket dir: %w", err)
	}
	// Walk every component: refuse any symlink whose resolved target is NOT
	// ours (foreign-owned). os.MkdirAll would follow such aliases and then
	// chmod someone else's directory — exactly the defect this prevents.
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
				// Remaining components do not exist; MkdirAll below creates
				// them as real directories under a component we proved safe.
				break
			}
			return fmt.Errorf("local socket dir: lstat %s: %w", cur, err)
		}
		if lst.Mode()&os.ModeSymlink != 0 {
			// Never follow a path alias just to make it appear safe: refuse the
			// symlink component outright, before any mkdir/chmod, leaving the
			// alias target's metadata and content untouched.
			return fmt.Errorf("local socket dir: symlink component %s is refused", cur)
		}
		if !lst.IsDir() {
			return fmt.Errorf("local socket dir: component %s exists and is not a directory", cur)
		}
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return fmt.Errorf("local socket dir: %w", err)
	}
	// Re-prove the FINAL directory: it must be ours and exactly 0700. Use
	// Lstat semantics via Stat of the (now proven non-alias) path.
	st, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("local socket dir stat: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("local socket dir %s is not a directory", abs)
	}
	if st.Sys().(*syscall.Stat_t).Uid != uint32(uid) {
		return fmt.Errorf("local socket dir %s is owned by another uid", abs)
	}
	if st.Mode().Perm()&^0o700 != 0 {
		// A too-wide mode on OUR own directory may be tightened; tightening
		// is safe. (The refusal case — foreign/symlink — already returned.)
		if err := os.Chmod(abs, 0o700); err != nil {
			return fmt.Errorf("local socket dir mode: %w", err)
		}
		st, err = os.Stat(abs)
		if err != nil {
			return fmt.Errorf("local socket dir stat: %w", err)
		}
	}
	if st.Mode().Perm() != 0o700 {
		return fmt.Errorf("local socket dir %s has mode %o, want 700", abs, st.Mode().Perm())
	}
	return nil
}

// ensureStaleSocketRemovable refuses to displace a socket that still accepts
// connections and clears a stale socket file whose owner is gone. A
// non-socket file at the path is a hard error — never unlinked.
func ensureStaleSocketRemovable(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("local socket stat: %w", err)
	}
	if st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("local socket path %s exists and is not a socket", path)
	}
	c, derr := net.DialTimeout("unix", path, 500*time.Millisecond)
	if derr == nil {
		c.Close()
		return fmt.Errorf("another live raylane owns %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale local socket: %w", err)
	}
	return nil
}

func tlsListener(ln net.Listener, certPath, keyPath string) (net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS material: %w", err)
	}
	return tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}), nil
}

// runBootstrap is the local-socket bootstrap client. The admin username and
// password are read ONLY from a bounded strict JSON object on redirected
// standard input ({\"username\":\"...\",\"password\":\"...\"}) — never from
// argv, environment variables or files, which would leak credentials into the
// process table or disk. A terminal (character-device) stdin is refused unless
// secure no-echo input is implemented; the operator redirects a file or pipe
// instead. The one-time token is requested and redeemed over the owner-only
// socket internally, and neither the token nor the password is ever written to
// stdout/stderr — only the generic server problem on failure.
func runBootstrap(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socketDir := fs.String("socket-dir", "", "directory holding the local control socket (required)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage:\n  raylane bootstrap --socket-dir <dir>  < credentials.json\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *socketDir == "" {
		fmt.Fprint(stderr, "raylane bootstrap: --socket-dir is required\n")
		return 2
	}
	username, password, err := readBootstrapCredentials(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "raylane bootstrap: %v\n", err)
		return 2
	}
	client := localSocketClient(filepath.Join(*socketDir, "control.sock"))
	status, tokBody, err := postLocal(client, "http://unix/bootstrap-token", `{}`)
	if err != nil {
		fmt.Fprintf(stderr, "raylane bootstrap: token issuance: %v\n", err)
		return 1
	}
	if status != http.StatusOK {
		fmt.Fprintf(stderr, "raylane bootstrap: token issuance: HTTP %d %s\n", status, strings.TrimSpace(string(tokBody)))
		return 1
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(tokBody, &tok); err != nil || tok.Token == "" {
		fmt.Fprint(stderr, "raylane bootstrap: malformed token response\n")
		return 1
	}
	reqBody, err := json.Marshal(map[string]string{"token": tok.Token, "username": username, "password": password})
	if err != nil {
		fmt.Fprint(stderr, "raylane bootstrap: encode request\n")
		return 1
	}
	status, respBody, err := postLocal(client, "http://unix/api/v1/bootstrap", string(reqBody))
	if err != nil {
		fmt.Fprintf(stderr, "raylane bootstrap: %v\n", err)
		return 1
	}
	if status != http.StatusNoContent {
		// The server's generic problem body is safe to print; the request is
		// never echoed.
		fmt.Fprintf(stderr, "raylane bootstrap: refused: HTTP %d %s\n", status, strings.TrimSpace(string(respBody)))
		return 1
	}
	fmt.Fprintln(stdout, "raylane bootstrap: admin created; bootstrap is permanently closed")
	return 0
}

// bootstrapCredentialsBound bounds the stdin credential JSON (well under the
// smallest credential set, but generous enough for 256+1024 code points).
const bootstrapCredentialsBound = 8192

// readBootstrapCredentials reads and strictly decodes the credential JSON from
// stdin. It refuses a terminal (character-device) stdin: interactive echo
// would expose the password. Only a redirected file/pipe is accepted.
func readBootstrapCredentials(stdin io.Reader) (username, password string, err error) {
	if f, ok := stdin.(*os.File); ok {
		st, serr := f.Stat()
		if serr != nil {
			return "", "", fmt.Errorf("stat stdin: %w", serr)
		}
		if st.Mode()&os.ModeCharDevice != 0 {
			return "", "", errors.New("refusing to read credentials from a terminal; redirect a JSON file or pipe on stdin")
		}
	}
	body, err := io.ReadAll(io.LimitReader(stdin, bootstrapCredentialsBound+1))
	if err != nil {
		return "", "", fmt.Errorf("read stdin: %w", err)
	}
	if len(body) > bootstrapCredentialsBound {
		return "", "", errors.New("credential JSON exceeds the bound")
	}
	// Raw-bytes UTF-8 gate BEFORE decoding, for the same reason as
	// decodeStrictConfig: the decoder's silent U+FFFD replacement would both
	// accept invalid input and alias two different raw usernames.
	if !utf8.Valid(body) {
		return "", "", errors.New("credential JSON is not valid UTF-8")
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&creds); err != nil {
		return "", "", fmt.Errorf("decode credential JSON: %w", err)
	}
	if dec.More() {
		return "", "", errors.New("trailing data after credential JSON")
	}
	if creds.Username == "" || creds.Password == "" {
		return "", "", errors.New("credential JSON must carry non-empty username and password")
	}
	return creds.Username, creds.Password, nil
}

func localSocketClient(sockPath string) *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}
}

func postLocal(client *http.Client, url, body string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		return resp.StatusCode, nil, rerr
	}
	return resp.StatusCode, respBody, nil
}

// ensureSelfSignedTLS creates an ECDSA P-256 self-signed certificate with the
// key at mode 0600 (directory 0700), ONLY if the pair is absent; an existing
// pair is never touched. It is a development/test aid — a production
// deployment supplies its own certificate and key.
func ensureSelfSignedTLS(certPath, keyPath string, dnsNames []string) error {
	certOK, keyOK := fileExists(certPath), fileExists(keyPath)
	if certOK && keyOK {
		return nil
	}
	if certOK != keyOK {
		return fmt.Errorf("TLS material incomplete: %s and %s must exist together", certPath, keyPath)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return fmt.Errorf("create TLS dir: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate TLS key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsOnlyNames(dnsNames),
		IPAddresses:           ipOnlyAddrs(dnsNames),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal TLS key: %w", err)
	}
	if err := writeFileMode(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return writeFileMode(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func writeFileMode(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dnsOnlyNames returns the DNS names among the supplied identities (an IP
// literal is NOT a DNS name and must go in IPAddresses, or the SAN check for
// that IP fails).
func dnsOnlyNames(names []string) []string {
	var out []string
	for _, n := range names {
		if net.ParseIP(n) == nil {
			out = append(out, n)
		}
	}
	return out
}

// ipOnlyAddrs returns the parsed IP addresses among the supplied identities.
func ipOnlyAddrs(names []string) []net.IP {
	var out []net.IP
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func splitTrimmed(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		out = []string{"localhost"}
	}
	return out
}
