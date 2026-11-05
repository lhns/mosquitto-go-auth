package hashing

import (
	"fmt"
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

// Compare logs fixed messages. A value from the stored hash never appears in a log entry.
func TestCompareLogsNoHashValues(t *testing.T) {
	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)
	h := NewPBKDF2Hasher(16, 1000, SHA512, Base64, 32)
	a := NewArgon2IDHasher(8, 1, 32, 64, 1)

	for _, hash := range []string{
		"PBKDF2$sha512$MARKER123$c2FsdA==$" + k512,
		"PBKDF2$sha512$1000$c2FsdA==$MARKER123!",
		"PBKDF2$sha512$1000$MARKER123!$" + k512,
		"PBKDF2$sha512$1000$c2FsdA==$" + k512 + "$MARKER123",
		"pbkdf2-sha512$i=MARKER123,l=32$c2FsdA$x",
		"pbkdf2-sha512$MARKER123=1,l=32$c2FsdA$x",
		"pbkdf2-sha512$i=1000,l=32$c2FsdA$MARKER123!",
		"pbkdf2-sha512$i=1000,l=32$MARKER123!$x",
		"MARKER123$x",
	} {
		hook.Reset()
		assert.False(t, h.Compare(testPassword, hash))
		assert.NotEmpty(t, hook.AllEntries(), hash)
		for _, e := range hook.AllEntries() {
			assert.NotContains(t, fmt.Sprint(e.Message, e.Data), "MARKER", hash)
		}
	}
	for _, hash := range []string{
		"$argon2id$v=MARKER$m=64,t=1,p=1$c2FsdHNhbHQ$x",
		"$argon2id$v=19$m=MARKER123,t=1,p=1$c2FsdHNhbHQ$x",
		"$argon2id$v=19$m=64,t=1,p=1$MARKER123!$x",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$MARKER123!",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$x$MARKER123",
		"$argon2id$v=18$m=64,t=1,p=1$c2FsdHNhbHQ$x",
		"$MARKER123$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$x",
	} {
		hook.Reset()
		assert.False(t, a.Compare(testPassword, hash))
		assert.NotEmpty(t, hook.AllEntries(), hash)
		for _, e := range hook.AllEntries() {
			assert.NotContains(t, fmt.Sprint(e.Message, e.Data), "MARKER", hash)
		}
	}
}
