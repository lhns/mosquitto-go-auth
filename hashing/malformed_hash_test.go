package hashing

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A malformed stored hash never matches and never panics. This test uses only the public API.
func TestMalformedStoredHash(t *testing.T) {
	pbkdf2 := NewPBKDF2Hasher(16, 1000, SHA512, Base64, 32)
	argon2 := NewArgon2IDHasher(8, 1, 32, 64, 1)

	for name, c := range map[string]struct {
		h    HashComparer
		hash string
	}{
		"pbkdf2 checksum not standard base64": {pbkdf2, "pbkdf2-sha512$i=1000,l=64$c2FsdA$-AAAAAAA"},
		"pbkdf2 empty hash":                   {pbkdf2, ""},
		"pbkdf2 l absent":                     {pbkdf2, "pbkdf2-sha512$i=1000$c2FsdA$AAAA"},
		"pbkdf2 parameter without value":      {pbkdf2, "pbkdf2-sha512$i=1000,l$c2FsdA$AAAA"},
		"pbkdf2 missing field":                {pbkdf2, "PBKDF2$sha512$1000$c2FsdA=="},
		"argon2id t zero":                     {argon2, "$argon2id$v=19$m=64,t=0,p=1$c2FsdHNhbHQ$q8xf6lwhDBCcgC3rk+NDxXxW7kzMEwhauOIJ+P8uReY"},
		"argon2id p zero":                     {argon2, "$argon2id$v=19$m=64,t=1,p=0$c2FsdHNhbHQ$q8xf6lwhDBCcgC3rk+NDxXxW7kzMEwhauOIJ+P8uReY"},
		"argon2id empty key":                  {argon2, "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$"},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Compare panicked: %v", r)
				}
			}()
			assert.False(t, c.h.Compare("other", c.hash))
		})
	}
}
