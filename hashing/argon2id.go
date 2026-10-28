package hashing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/argon2"
)

type argon2IDHasher struct {
	saltSize    int
	iterations  int
	keyLen      int
	memory      uint32
	parallelism uint8
}

func NewArgon2IDHasher(saltSize int, iterations int, keylen int, memory uint32, parallelism uint8) HashComparer {
	return argon2IDHasher{
		saltSize:    saltSize,
		iterations:  iterations,
		keyLen:      keylen,
		memory:      memory,
		parallelism: parallelism,
	}
}

// Hash generates a hashed password using Argon2ID.
func (h argon2IDHasher) Hash(password string) (string, error) {
	// The library panics on these values.
	if h.iterations < 1 || h.parallelism < 1 || h.keyLen < 0 {
		return "", errors.New("invalid argon2id parameters")
	}

	salt := make([]byte, h.saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", errors.Wrap(err, "read random bytes error")
	}

	return h.hashWithSalt(password, salt, h.memory, h.iterations, h.parallelism, h.keyLen), nil
}

// Compare checks that an argon2 generated password matches the password hash.
// A stored hash that is malformed or outside the limits (see maxArgon2Memory
// and the related constants) is refused before any key derivation.
func (h argon2IDHasher) Compare(password string, passwordHash string) bool {
	if len(passwordHash) > maxEncodedHashLen {
		log.Errorf("invalid argon2id hash supplied, too long")
		return false
	}

	hashSplit := strings.Split(passwordHash, "$")

	if len(hashSplit) != 6 {
		log.Errorf("invalid argon2id hash supplied, unexpected number of elements")
		return false
	}

	if hashSplit[0] != "" || hashSplit[1] != "argon2id" {
		log.Errorf("unknown hash format")
		return false
	}

	version, err := strconv.ParseUint(strings.TrimPrefix(hashSplit[2], "v="), 10, 32)
	if err != nil || !strings.HasPrefix(hashSplit[2], "v=") {
		log.Errorf("argon2id version parse error")
		return false
	}

	if version != argon2.Version {
		log.Errorf("unknown argon2id version")
		return false
	}

	params := strings.Split(hashSplit[3], ",")
	if len(params) != 3 {
		log.Errorf("argon2id parameters parse error")
		return false
	}
	var values [3]uint64
	for i, name := range [3]string{"m=", "t=", "p="} {
		bits := 32
		if name == "p=" {
			bits = 8
		}
		values[i], err = strconv.ParseUint(strings.TrimPrefix(params[i], name), 10, bits)
		if err != nil || !strings.HasPrefix(params[i], name) {
			log.Errorf("argon2id parameters parse error")
			return false
		}
	}
	memory, iterations, parallelism := uint32(values[0]), uint32(values[1]), uint8(values[2]) //nolint:gosec // ParseUint limited each value to 32 or 8 bits

	salt, err := base64.RawStdEncoding.DecodeString(hashSplit[4])
	if err != nil {
		log.Errorf("invalid argon2id hash supplied, bad salt encoding")
		return false
	}

	extractedHash, err := base64.RawStdEncoding.DecodeString(hashSplit[5])
	if err != nil {
		log.Errorf("invalid argon2id hash supplied, bad key encoding")
		return false
	}

	// The limits are checked before any key derivation work.
	if !argon2InLimits(memory, int(iterations), parallelism, len(extractedHash), len(salt)) {
		log.Errorf("invalid argon2id hash supplied, parameters are outside the limits")
		return false
	}

	newHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(extractedHash))) //nolint:gosec // length is at most maxKeyLen here

	return subtle.ConstantTimeCompare(newHash, extractedHash) == 1
}

// argon2InLimits reports whether the parameters are in the range that Compare accepts.
func argon2InLimits(memory uint32, iterations int, parallelism uint8, keyLen, saltLen int) bool {
	return memory <= maxArgon2Memory &&
		iterations >= 1 && iterations <= maxArgon2Iterations &&
		parallelism >= 1 && parallelism <= maxArgon2Parallelism &&
		keyLen >= 1 && keyLen <= maxKeyLen &&
		saltLen >= 0 && saltLen <= maxSaltLen
}

func (h argon2IDHasher) hashWithSalt(password string, salt []byte, memory uint32, iterations int, parallelism uint8, keylen int) string {

	hashedPassword := argon2.IDKey([]byte(password), salt, uint32(iterations), memory, parallelism, uint32(keylen))

	b64salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hashedPassword)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, h.memory, h.iterations, h.parallelism, b64salt, b64Hash)
}
