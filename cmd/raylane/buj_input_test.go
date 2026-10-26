package main

import (
	"strings"
	"testing"
)

// G1 at the CLI boundary: every strict JSON entry point (the operator config
// and the bootstrap credential document) must refuse RAW invalid UTF-8 before
// decoding, instead of letting encoding/json silently replace each invalid
// byte with U+FFFD and then accept the replaced value.
func TestBujG1ConfigRejectsRawInvalidUTF8(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"lone continuation ff", "\xff"},
		{"lone continuation fe", "\xfe"},
		{"lone continuation 80", "\x80"},
		{"truncated 2-byte lead c3", "adm\xc3"},
		{"3-byte lead over ASCII e2 71", "u\xe2q"},
		{"over-long NUL c0 80", "u\xc0\x80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{"db":"/tmp/r` + tc.raw + `.db","listen":"127.0.0.1:8443","origin":"https://127.0.0.1:8443","socketDir":"/tmp/run","tlsCert":"c","tlsKey":"k"}`
			var sc serveConfigJSON
			if err := decodeStrictConfig([]byte(raw), &sc); err == nil {
				t.Fatalf("raw invalid-UTF-8 config accepted and transformed to %q", sc.DBPath)
			}
		})
	}
}

func TestBujG1ConfigValidMultibyteStillDecodes(t *testing.T) {
	// Positive control: legal multibyte (including a literal U+FFFD and an
	// astral pair) must still decode with exact bytes preserved.
	raw := "{\"db\":\"/tmp/состояние\xef\xbf\xbd𝄞.db\",\"listen\":\"127.0.0.1:8443\",\"origin\":\"https://127.0.0.1:8443\",\"socketDir\":\"/tmp/run\",\"tlsCert\":\"c\",\"tlsKey\":\"k\"}"
	var sc serveConfigJSON
	if err := decodeStrictConfig([]byte(raw), &sc); err != nil {
		t.Fatalf("valid multibyte config rejected: %v", err)
	}
	if !strings.Contains(sc.DBPath, "\xef\xbf\xbd") || !strings.Contains(sc.DBPath, "𝄞") {
		t.Fatalf("multibyte config value not preserved exactly: %q", sc.DBPath)
	}
}

func TestBujG1BootstrapCredentialsRejectRawInvalidUTF8(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"lone continuation ff", "\xff"},
		{"lone continuation fe", "\xfe"},
		{"lone continuation 80", "\x80"},
		{"truncated 2-byte lead c3", "adm\xc3"},
		{"3-byte lead over ASCII e2 71", "u\xe2q"},
		{"over-long NUL c0 80", "u\xc0\x80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := `{"username":"adm` + tc.raw + `in","password":"p"}`
			if _, _, err := readBootstrapCredentials(strings.NewReader(doc)); err == nil {
				t.Fatal("raw invalid-UTF-8 bootstrap credentials accepted by readBootstrapCredentials")
			}
		})
	}
}

func TestBujG1BootstrapCredentialsValidMultibyteStillAccepted(t *testing.T) {
	doc := "{\"username\":\"операторሴ\",\"password\":\"пароль\"}"
	u, p, err := readBootstrapCredentials(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("valid multibyte credentials rejected: %v", err)
	}
	if u != "операторሴ" {
		t.Fatalf("username not preserved exactly: %q", u)
	}
	if p != "пароль" {
		t.Fatalf("password not preserved exactly: %q", p)
	}
}
