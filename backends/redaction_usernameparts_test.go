package backends

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// referenceHoldsUsernamePart is the first version of the check: it scans the text once per window.
func referenceHoldsUsernamePart(text, username string) bool {
	if len(username) < truncatedTokenMinLen {
		return false
	}
	for i := 0; i+truncatedTokenWindowLen <= len(username); i++ {
		if strings.Contains(text, username[i:i+truncatedTokenWindowLen]) {
			return true
		}
	}
	return false
}

func randomText(r *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

// The window set gives the same answer as the scan, for random texts, near misses and edge lengths.
func TestUsernameWindowsMatchesReference(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	// A small alphabet makes windows collide often, a large one makes hits rare.
	for _, alphabet := range []string{"ab", "abcd", "abcdefghijklmnopqrstuvwxyz0123456789-_."} {
		for i := 0; i < 3000; i++ {
			username := randomText(r, alphabet, r.Intn(80))
			var text string
			switch r.Intn(4) {
			case 0:
				text = randomText(r, alphabet, r.Intn(120))
			case 1: // a slice of the username inside noise
				if len(username) > 0 {
					from := r.Intn(len(username))
					to := from + r.Intn(len(username)-from+1)
					text = randomText(r, alphabet, r.Intn(10)) + username[from:to] + randomText(r, alphabet, r.Intn(10))
				}
			case 2: // a near miss: a slice with one byte changed
				if len(username) > 0 {
					from := r.Intn(len(username))
					part := []byte(username[from:])
					if len(part) > 0 {
						part[r.Intn(len(part))] ^= 1
					}
					text = "x" + string(part) + "y"
				}
			default:
				text = username
			}
			require.Equal(t, referenceHoldsUsernamePart(text, username), newUsernameWindows(username).in(text),
				"username %q text %q", username, text)
		}
	}

	// Lengths around the limits.
	for _, n := range []int{0, 15, 16, 17, 31, 32, 33} {
		username := strings.Repeat("a", n)
		for _, m := range []int{0, 15, 16, 17, 40} {
			text := strings.Repeat("a", m)
			require.Equal(t, referenceHoldsUsernamePart(text, username), newUsernameWindows(username).in(text), "%d %d", n, m)
		}
	}
}

// A long username against a long text is one pass over the text, with no match found.
func TestHideTextLargeNearMiss(t *testing.T) {
	username := strings.Repeat("abcdefghijklmnop", 4096) // 64 KB
	text := strings.Repeat("abcdefghijklmnoX", 4096)
	require.Equal(t, text, hideText(text, username))
}

func BenchmarkHideTextNearMiss64K(b *testing.B) {
	username := randomText(rand.New(rand.NewSource(2)), "abcdefghijklmnopqrstuvwxyz0123456789", 64*1024)
	text := randomText(rand.New(rand.NewSource(3)), "abcdefghijklmnopqrstuvwxyz0123456789", 64*1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hideText(text, username)
	}
}

// The first version, for comparison with BenchmarkHideTextNearMiss64K.
func BenchmarkReferenceNearMiss64K(b *testing.B) {
	username := randomText(rand.New(rand.NewSource(2)), "abcdefghijklmnopqrstuvwxyz0123456789", 64*1024)
	text := randomText(rand.New(rand.NewSource(3)), "abcdefghijklmnopqrstuvwxyz0123456789", 64*1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		referenceHoldsUsernamePart(text, username)
	}
}
