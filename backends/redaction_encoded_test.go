package backends

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// percentEncodeAll encodes every byte of s as %XX.
func percentEncodeAll(s string, upper bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if upper {
			fmt.Fprintf(&b, "%%%02X", s[i])
		} else {
			fmt.Fprintf(&b, "%%%02x", s[i])
		}
	}
	return b.String()
}

// percentEncodeMixed encodes two of every three bytes, so no plain run is 16 characters long.
func percentEncodeMixed(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i%3 == 0 {
			b.WriteByte(s[i])
		} else {
			fmt.Fprintf(&b, "%%%02X", s[i])
		}
	}
	return b.String()
}

// A token that a client library quotes percent-encoded in every byte has no 16 plain characters,
// so it must be found after decoding.
func TestRedaction_PercentEncodedToken(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjo5OTk5OTk5OTk5fQ.c2lnbmF0dXJlLXNpZ25hdHVyZS1zaWduYXR1cmU"

	forms := map[string]string{
		"fully encoded":      percentEncodeAll(token, true),
		"fully lower hex":    percentEncodeAll(token, false),
		"mixed":              percentEncodeMixed(token),
		"double encoded":     percentEncodeAll(percentEncodeAll(token, true), true),
		"double mixed":       percentEncodeMixed(percentEncodeMixed(token)),
		"encoded then plain": percentEncodeAll(token[:60], true) + token[60:],
	}

	for name, form := range forms {
		t.Run(name, func(t *testing.T) {
			require.NotContains(t, form, token[:16])

			text := "Get \"http://auth/user?t=" + form + "\": connection refused"
			hidden := hideText(text, token)
			require.NotContains(t, hidden, form, "the encoded token is left in the text")
			require.NotContains(t, hidden, form[:30])

			err := hideToken(true, errors.New(text), token)
			require.NotContains(t, err.Error(), form[:30])

			// Without a jwt backend nothing changes.
			require.Equal(t, errors.New(text), hideToken(false, errors.New(text), token))
		})
	}

	// Text that holds no part of the token, encoded or not, is kept as it is.
	other := "Get \"http://auth/user?t=" + percentEncodeAll("some other value that is long enough", true) + "\": refused 100%"
	require.Equal(t, other, hideText(other, token))
}
