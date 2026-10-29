package hashing

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/argon2"
)

const testPassword = "test-password"

// compare fails the test instead of crashing the run when Compare panics.
func compare(t *testing.T, h HashComparer, password, hash string) bool {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Compare panicked: %v", r)
		}
	}()
	return h.Compare(password, hash)
}

// Vectors are the output of the previous implementation (password test-password, salt "salt").
const (
	k512     = "g0mpBBa7fR3NyIBBX1ZnA9j8wZ+TckAdbTlt+xo215c="
	k256     = "dfc8dvK1Xk9DgITBDJYf6j2o6hNBDLfpqAfFeRIKMVw="
	k512l64  = "g0mpBBa7fR3NyIBBX1ZnA9j8wZ+TckAdbTlt+xo215eSNYUhGlIV+igXMg6Pl5J5aloTG0KQ2FN7UNK6M3Pjsg=="
	k256Over = "Z/LPwvMzxrB/jqTT4tc0XyLfoWpily9leHlxtukUanw=" // 5000001 iterations
)

// phcHash builds a PHC hash for the test password with the real derivation. Use small iterations.
func phcHash(t *testing.T, salt []byte, iterations, keyLen int) string {
	t.Helper()
	k, err := pbkdf2.Key(sha512.New, testPassword, salt, iterations, keyLen)
	assert.NoError(t, err)
	return fmt.Sprintf("pbkdf2-sha512$i=%d,l=%d$%s$%s", iterations, keyLen,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(k))
}

// argonHash builds an Argon2id hash for the test password. Use small memory.
func argonHash(salt []byte, memory uint32, iterations int, parallelism uint8, keyLen int) string {
	k := argon2.IDKey([]byte(testPassword), salt, uint32(iterations), memory, parallelism, uint32(keyLen)) //nolint:gosec // test values are small
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(k))
}

func TestPBKDF2Compare(t *testing.T) {
	b64 := NewPBKDF2Hasher(16, 1000, SHA512, Base64, 32)
	utf8 := NewPBKDF2Hasher(16, 1000, SHA512, UTF8, 32)
	raw512 := k512[:len(k512)-1]
	raw512l64 := k512l64[:len(k512l64)-2]

	valid := []struct {
		name string
		h    HashComparer
		hash string
	}{
		{"legacy sha512", b64, "PBKDF2$sha512$1000$c2FsdA==$" + k512},
		{"legacy sha256", b64, "PBKDF2$sha256$1000$c2FsdA==$" + k256},
		{"legacy sha512 key 64", b64, "PBKDF2$sha512$1000$c2FsdA==$" + k512l64},
		{"legacy utf8 salt", utf8, "PBKDF2$sha512$1000$salt$" + k512},
		// An unknown algorithm label uses SHA-512, as before.
		{"legacy unknown algorithm", b64, "PBKDF2$md5$1000$c2FsdA==$" + k512},
		// Padding on the PHC checksum was accepted before, so it still is.
		{"phc padded key", b64, "pbkdf2-sha512$i=1000,l=32$c2FsdA$" + k512},
		{"phc raw base64", b64, "pbkdf2-sha512$i=1000,l=32$c2FsdA$" + raw512},
		{"phc parameters swapped", b64, "pbkdf2-sha512$l=32,i=1000$c2FsdA$" + raw512},
		{"phc key 64", b64, "pbkdf2-sha512$i=1000,l=64$c2FsdA$" + raw512l64},
		{"phc utf8 salt", utf8, "pbkdf2-sha512$i=1000,l=32$salt$" + raw512},
	}
	for _, c := range valid {
		t.Run("valid "+c.name, func(t *testing.T) {
			assert.True(t, compare(t, c.h, testPassword, c.hash))
			assert.False(t, compare(t, c.h, "other", c.hash))
		})
	}

	invalid := map[string]string{
		"phc garbage key":             "pbkdf2-sha512$i=1000,l=32$c2FsdA$!!!",
		"empty hash":                  "",
		"only prefix":                 "pbkdf2-sha512",
		"missing field":               "pbkdf2-sha512$i=1000,l=32$c2FsdA",
		"l absent":                    "pbkdf2-sha512$i=1000$c2FsdA$" + raw512,
		"i absent":                    "pbkdf2-sha512$l=32$c2FsdA$" + raw512,
		"repeated key":                "pbkdf2-sha512$i=1000,i=1000,l=32$c2FsdA$" + raw512,
		"unknown key":                 "pbkdf2-sha512$i=1000,l=32,x=1$c2FsdA$" + raw512,
		"empty key":                   "pbkdf2-sha512$i=1000,l=32$c2FsdA$",
		"l too short for key":         "pbkdf2-sha512$i=1000,l=16$c2FsdA$" + raw512,
		"l too long for key":          "pbkdf2-sha512$i=1000,l=64$c2FsdA$" + raw512,
		"l zero":                      "pbkdf2-sha512$i=1000,l=0$c2FsdA$",
		"l negative":                  "pbkdf2-sha512$i=1000,l=-1$c2FsdA$" + raw512,
		"l over limit":                phcHash(t, []byte("salt"), 1, maxKeyLen+1),
		"salt over limit":             phcHash(t, make([]byte, maxSaltLen+1), 1, 32),
		"legacy empty algorithm":      "PBKDF2$$1000$c2FsdA==$" + k512,
		"phc extra field":             "pbkdf2-sha512$i=1000,l=32$c2FsdA$" + raw512 + "$x",
		"iterations not a number":     "PBKDF2$sha512$abc$c2FsdA==$" + k512,
		"iterations zero":             "PBKDF2$sha512$0$c2FsdA==$" + k512,
		"iterations negative":         "PBKDF2$sha512$-1$c2FsdA==$" + k512,
		"iterations over limit":       "PBKDF2$sha256$5000001$c2FsdA==$" + k256Over,
		"phc iterations over limit":   "pbkdf2-sha512$i=5000001,l=32$c2FsdA$03r2ngb25O3IfRd512bHdJjEhfaClpUbwSVt4BfoT0U", // 5000001 iterations
		"phc iterations zero":         "pbkdf2-sha512$i=0,l=32$c2FsdA$" + raw512,
		"legacy unpadded key":         "PBKDF2$sha512$1000$c2FsdA==$" + raw512,
		"legacy bad salt":             "PBKDF2$sha512$1000$!!!$" + k512,
		"phc checksum bad first char": "pbkdf2-sha512$i=1000,l=64$c2FsdA$-AAAAAAA", // not accepted by the raw decoder
		"phc checksum padding only":   "pbkdf2-sha512$i=1000,l=32$c2FsdA$==",
		"phc checksum A=":             "pbkdf2-sha512$i=1000,l=32$c2FsdA$A=",
		"legacy missing field":        "PBKDF2$sha512$1000$c2FsdA==",
		"legacy empty key":            "PBKDF2$sha512$1000$c2FsdA==$",
		"unknown format":              "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$q8xf6lwhDBCcgC3rk+NDxXxW7kzMEwhauOIJ+P8uReY",
		"too long":                    "PBKDF2$" + strings.Repeat("x", maxEncodedHashLen) + "$1000$c2FsdA==$" + k512, // unknown label, valid in all other ways
	}
	for name, hash := range invalid {
		t.Run("invalid "+name, func(t *testing.T) {
			assert.False(t, compare(t, b64, "other", hash))
			assert.False(t, compare(t, b64, testPassword, hash))
		})
	}
}

func TestArgon2IDCompare(t *testing.T) {
	h := NewArgon2IDHasher(8, 1, 32, 64, 1)
	const key = "q8xf6lwhDBCcgC3rk+NDxXxW7kzMEwhauOIJ+P8uReY"
	const vec = "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$" + key
	// m=0 is raised to the minimum by the library.
	const vecM0 = "$argon2id$v=19$m=0,t=2,p=2$c2FsdHNhbHQ$FG45OBO43wyStBVTBDvhkw"

	for name, hash := range map[string]string{"vector": vec, "m zero and short key": vecM0} {
		t.Run("valid "+name, func(t *testing.T) {
			assert.True(t, compare(t, h, testPassword, hash))
			assert.False(t, compare(t, h, "other", hash))
		})
	}

	invalid := map[string]string{
		"empty hash":       "",
		"empty key":        "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$",
		"t zero":           "$argon2id$v=19$m=64,t=0,p=1$c2FsdHNhbHQ$" + key,
		"p zero":           "$argon2id$v=19$m=64,t=1,p=0$c2FsdHNhbHQ$" + key,
		"m negative":       "$argon2id$v=19$m=-1,t=1,p=1$c2FsdHNhbHQ$" + key,
		"t over limit":     "$argon2id$v=19$m=64,t=33,p=1$c2FsdHNhbHQ$8cfFEjlXY60Cyp4agkqVCCO90EotKIsKR55x8Rme2SM",
		"p over limit":     "$argon2id$v=19$m=64,t=1,p=65$c2FsdHNhbHQ$fSYJYeSlonS1fDH+peZd0qAZtf1OTuU9fKwk197xp2M",
		"key over limit":   argonHash([]byte("saltsalt"), 64, 1, 1, maxKeyLen+1),
		"salt over limit":  argonHash(make([]byte, maxSaltLen+1), 64, 1, 1, 32),
		"extra parameter":  "$argon2id$v=19$m=64,t=1,p=1,x=1$c2FsdHNhbHQ$" + key,
		"trailing garbage": "$argon2id$v=19$m=64,t=1,p=1x$c2FsdHNhbHQ$" + key,
		"version prefix":   "$argon2id$19$m=64,t=1,p=1$c2FsdHNhbHQ$" + key,
		"leading field":    "x$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$" + key,
		"bad key":          "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$!!!",
		"padded key":       "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$" + key + "=",
		"too long":         "$argon2id$v=" + strings.Repeat("0", maxEncodedHashLen) + "19$m=64,t=1,p=1$c2FsdHNhbHQ$" + key, // leading zeros keep the version valid
	}
	for name, hash := range invalid {
		t.Run("invalid "+name, func(t *testing.T) {
			assert.False(t, compare(t, h, "other", hash))
			assert.False(t, compare(t, h, testPassword, hash))
		})
	}
}

func TestArgon2IDRoundTrip(t *testing.T) {
	for name, h := range map[string]HashComparer{
		"default": NewArgon2IDHasher(defaultArgon2IDSaltSize, defaultArgon2IDIterations, defaultArgon2IDKeyLen, defaultArgon2IDMemory, defaultArgon2IDParallelism),
		"custom":  NewArgon2IDHasher(8, 2, 16, 128, 4),
		"limits":  NewArgon2IDHasher(maxSaltLen, maxArgon2Iterations, maxKeyLen, 64, maxArgon2Parallelism),
	} {
		t.Run(name, func(t *testing.T) {
			hash, err := h.Hash(testPassword)
			assert.NoError(t, err)
			assert.True(t, compare(t, h, testPassword, hash))
			assert.False(t, compare(t, h, "other", hash))
		})
	}
}

func TestPBKDF2LimitBoundary(t *testing.T) {
	assert.True(t, pbkdf2InLimits(maxPBKDF2Iterations, maxKeyLen, maxSaltLen))
	assert.False(t, pbkdf2InLimits(maxPBKDF2Iterations+1, 32, 16))
	assert.False(t, pbkdf2InLimits(0, 32, 16))
}

func TestArgon2IDLimitBoundary(t *testing.T) {
	assert.True(t, argon2InLimits(maxArgon2Memory, maxArgon2Iterations, maxArgon2Parallelism, maxKeyLen, maxSaltLen))
	assert.False(t, argon2InLimits(maxArgon2Memory+1, 1, 1, 32, 16))
	// The README documents 4 GiB (4194304 KiB) as the upper bound, 1 GiB on 32-bit builds.
	assert.True(t, argon2InLimits(1048576, 1, 1, 32, 16))
	assert.Equal(t, strconv.IntSize == 64, argon2InLimits(4194304, 1, 1, 32, 16))
}

// Hash refuses parameters that Compare would refuse, and never panics.
func TestHashInvalidParameters(t *testing.T) {
	for name, h := range map[string]HashComparer{
		"argon2id iterations 0":    NewArgon2IDHasher(16, 0, 32, 64, 1),
		"argon2id parallelism 0":   NewArgon2IDHasher(16, 1, 32, 64, 0),
		"argon2id keylen 0":        NewArgon2IDHasher(16, 1, 0, 64, 1),
		"argon2id keylen over":     NewArgon2IDHasher(16, 1, maxKeyLen+1, 64, 1),
		"argon2id memory over":     NewArgon2IDHasher(16, 1, 32, maxArgon2Memory+1, 1),
		"argon2id iterations over": NewArgon2IDHasher(16, maxArgon2Iterations+1, 32, 64, 1),
		"argon2id salt over":       NewArgon2IDHasher(maxSaltLen+1, 1, 32, 64, 1),
		"pbkdf2 iterations 0":      NewPBKDF2Hasher(16, 0, SHA512, Base64, 32),
		"pbkdf2 iterations over":   NewPBKDF2Hasher(16, maxPBKDF2Iterations+1, SHA512, Base64, 32),
		"pbkdf2 keylen 0":          NewPBKDF2Hasher(16, 1000, SHA512, Base64, 0),
		"pbkdf2 keylen over":       NewPBKDF2Hasher(16, 1000, SHA512, Base64, maxKeyLen+1),
		"pbkdf2 salt over":         NewPBKDF2Hasher(maxSaltLen+1, 1000, SHA512, Base64, 32),
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Hash panicked: %v", r)
				}
			}()
			_, err := h.Hash(testPassword)
			assert.Error(t, err)
		})
	}
}
