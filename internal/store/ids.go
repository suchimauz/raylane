package store

import (
	"crypto/rand"
	"encoding/hex"
)

// newID returns a random UUIDv4 string: local identity per the data model.
// (No UUID dependency is added: crypto/rand + encoding/hex are stdlib.)
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("store: entropy source failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	dst := make([]byte, 32)
	hex.Encode(dst, b[:])
	s := make([]byte, 0, 36)
	s = append(s, dst[0:8]...)
	s = append(s, '-')
	s = append(s, dst[8:12]...)
	s = append(s, '-')
	s = append(s, dst[12:16]...)
	s = append(s, '-')
	s = append(s, dst[16:20]...)
	s = append(s, '-')
	s = append(s, dst[20:32]...)
	return string(s)
}
