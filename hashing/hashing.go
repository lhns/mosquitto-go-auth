package hashing

import (
	"fmt"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	// algorithms
	SHA512     = "sha512"
	SHA256     = "sha256"
	SHA256Size = 32
	SHA512Size = 64

	// encodings
	UTF8   = "utf-8"
	Base64 = "base64"

	// hashers
	Pbkdf2Opt   = "pbkdf2"
	Argon2IDOpt = "argon2id"
	BcryptOpt   = "bcrypt"

	// defaults
	defaultBcryptCost = 10

	defaultArgon2IDSaltSize           = 16
	defaultArgon2IDMemory      uint32 = 4096
	defaultArgon2IDIterations         = 3
	defaultArgon2IDParallelism uint8  = 2
	defaultArgon2IDKeyLen             = 32

	defaultPBKDF2SaltSize   = 16
	defaultPBKDF2Iterations = 100000
	defaultPBKDF2KeyLen     = 32
	defaultPBKDF2Algorithm  = SHA512
)

// Limits for hashes. Compare refuses a stored hash outside these limits before
// it does any key derivation, and Hash refuses the same parameters.
const (
	maxEncodedHashLen   = 4096    // bytes of the whole stored hash string
	maxKeyLen           = 512     // bytes of the derived key
	maxSaltLen          = 512     // bytes of the decoded salt
	maxPBKDF2Iterations = 5000000 // about 8 times the OWASP value for PBKDF2-HMAC-SHA256

	// KiB: 4 GiB, or 1 GiB on 32-bit builds where 4 GiB cannot be allocated.
	maxArgon2Memory      = 1 << (20 + 2*(strconv.IntSize/32-1))
	maxBcryptCost        = 16
	maxArgon2Iterations  = 32
	maxArgon2Parallelism = 64
)

var saltEncodings = map[string]struct{}{
	UTF8:   {},
	Base64: {},
}

type HashComparer interface {
	Hash(password string) (string, error)
	Compare(password, passwordHash string) bool
}

func preferredEncoding(saltEncoding string) string {
	preferredEncoding := Base64
	if _, ok := saltEncodings[saltEncoding]; ok {
		preferredEncoding = saltEncoding
	}
	return preferredEncoding
}

// Process hash opts:

// Empty backend: use whatever plugin wise hashing options are present by returning whole opts.
// Backend present: check if there's a backend_hasher option:
// 	- Yes: return a new map with whatever hashing options are present for the given backend and hasher
//		   (defaults will be used for missing options).
//	- No: use whatever plugin wise hashing options are present by returning whole opts.
func processHashOpts(authOpts map[string]string, backend string) map[string]string {

	// Return authOpts if no backend given.
	if backend == "" {
		return authOpts
	}
	// Return authOpts if no hasher was passed for the backend.
	if _, ok := authOpts[fmt.Sprintf("%s_hasher", backend)]; !ok {
		return authOpts
	}
	// Extract specific backend options.
	hashOpts := make(map[string]string)
	for k, v := range authOpts {
		if strings.Contains(k, backend) {
			hashOpts[strings.TrimPrefix(k, backend+"_")] = v
		}
	}
	return hashOpts
}

// NewHasher returns a hasher depending on the given options.
func NewHasher(authOpts map[string]string, backend string) HashComparer {
	opts := processHashOpts(authOpts, backend)

	switch opts["hasher"] {
	case BcryptOpt:
		log.Debugf("new hasher: %s", BcryptOpt)
		cost, err := strconv.Atoi(opts["hasher_cost"])
		if err != nil {
			return NewBcryptHashComparer(defaultBcryptCost)
		}
		return NewBcryptHashComparer(cost)
	case Argon2IDOpt:
		log.Debugf("new hasher: %s", Argon2IDOpt)
		saltSize := defaultArgon2IDSaltSize
		if v, err := strconv.Atoi(opts["hasher_salt_size"]); err == nil {
			saltSize = v
		}
		memory := defaultArgon2IDMemory
		if v, err := strconv.ParseUint(opts["hasher_memory"], 10, 32); err == nil {
			memory = uint32(v)
		}
		iterations := defaultArgon2IDIterations
		if v, err := strconv.Atoi(opts["hasher_iterations"]); err == nil {
			iterations = v
		}
		parallelism := defaultArgon2IDParallelism
		if v, err := strconv.ParseUint(opts["hasher_parallelism"], 10, 8); err == nil {
			parallelism = uint8(v)
		}
		keyLen := defaultArgon2IDKeyLen
		if v, err := strconv.Atoi(opts["hasher_keylen"]); err == nil {
			keyLen = v
		}
		return NewArgon2IDHasher(saltSize, iterations, keyLen, memory, parallelism)
	case Pbkdf2Opt:
		log.Debugf("new hasher: %s", Pbkdf2Opt)
	default:
		log.Warnln("unknown or empty hasher, defaulting to PBKDF2")
	}

	saltSize := defaultPBKDF2SaltSize
	if v, err := strconv.Atoi(opts["hasher_salt_size"]); err == nil {
		saltSize = v
	}

	iterations := defaultPBKDF2Iterations
	if v, err := strconv.Atoi(opts["hasher_iterations"]); err == nil {
		iterations = v
	}
	keyLen := defaultPBKDF2KeyLen
	if v, err := strconv.Atoi(opts["hasher_keylen"]); err == nil {
		keyLen = v
	}
	algorithm := defaultPBKDF2Algorithm
	if opts["hasher_algorithm"] == "sha256" {
		algorithm = SHA256
	}

	saltEncoding := opts["hasher_salt_encoding"]
	return NewPBKDF2Hasher(saltSize, iterations, algorithm, saltEncoding, keyLen)
}
