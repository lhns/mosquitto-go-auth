package hashing

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type pbkdf2Hasher struct {
	saltSize     int
	iterations   int
	algorithm    string
	saltEncoding string
	keyLen       int
}

func NewPBKDF2Hasher(saltSize int, iterations int, algorithm string, saltEncoding string, keyLen int) HashComparer {
	return pbkdf2Hasher{
		saltSize:     saltSize,
		iterations:   iterations,
		algorithm:    algorithm,
		saltEncoding: preferredEncoding(saltEncoding),
		keyLen:       keyLen,
	}
}

/*
* PBKDF2 methods are adapted from github.com/brocaar/chirpstack-application-server, some comments included.
 */

// Hash function generates a hash of the supplied password. The hash
// can then be stored directly in the database. The return hash will
// contain options according to the PHC String format found at
// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
func (h pbkdf2Hasher) Hash(password string) (string, error) {
	// Same limits as Compare, so that Hash never makes a hash that Compare refuses.
	if !pbkdf2InLimits(h.iterations, h.keyLen, h.saltSize) {
		return "", errors.New("invalid pbkdf2 parameters")
	}

	// Generate a random salt value with the given salt size.
	salt := make([]byte, h.saltSize)
	_, err := rand.Read(salt)

	// We need to ensure that salt doesn't contain $, which is 36 in decimal,
	// because $ is used as the field separator in the stored hash string.
	// Replace every $ byte with a random byte in 0-34. This is far from ideal,
	// but should be good enough with a reasonable salt size.
	for i := 0; i < len(salt); i++ {
		if salt[i] == 36 {
			n, err := rand.Int(rand.Reader, big.NewInt(35))
			if err != nil {
				return "", fmt.Errorf("read random byte error: %s", err)
			}
			salt[i] = byte(n.Int64())
		}
	}
	if err != nil {
		return "", fmt.Errorf("read random bytes error: %s", err)
	}

	return h.hashWithSalt(password, salt, h.iterations, h.algorithm, h.keyLen)
}

// Compare verifies that passed password hashes to the same value as the
// passed passwordHash. A stored hash that is malformed or outside the limits
// (see maxPBKDF2Iterations and the related constants) is refused.
// Reference: https://github.com/brocaar/chirpstack-application-server/blob/master/internal/storage/user.go#L458.
// Parsing reference: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
func (h pbkdf2Hasher) Compare(password string, passwordHash string) bool {
	if len(passwordHash) > maxEncodedHashLen {
		log.Errorf("invalid PBKDF2 hash supplied, too long")
		return false
	}

	var (
		algorithm  string
		iterations int
		keyLen     int
		salt       []byte
		stored     []byte
		saltField  string
		err        error
	)

	// A leading separator is allowed, as in the PHC string format.
	fields := strings.Split(strings.TrimPrefix(passwordHash, "$"), "$")
	switch {
	case len(fields) == 5 && fields[0] == "PBKDF2":
		algorithm = fields[1]
		if algorithm == "" {
			log.Errorf("invalid PBKDF2 hash supplied, empty algorithm")
			return false
		}
		iterations, err = strconv.Atoi(fields[2])
		if err != nil {
			log.Errorf("invalid PBKDF2 hash supplied, bad iterations")
			return false
		}
		saltField = fields[3]
		stored, err = base64.StdEncoding.DecodeString(fields[4])
		if err != nil {
			log.Errorf("invalid PBKDF2 hash supplied, bad key encoding")
			return false
		}
		keyLen = len(stored)
		if h.saltEncoding != UTF8 {
			salt, err = base64.StdEncoding.DecodeString(saltField)
		}
	case len(fields) == 4 && fields[0] == "pbkdf2-sha512":
		algorithm = SHA512
		var seenI, seenL bool
		for _, opt := range strings.Split(fields[1], ",") {
			key, val, ok := strings.Cut(opt, "=")
			n, convErr := strconv.Atoi(val)
			if !ok || convErr != nil {
				log.Errorf("invalid PBKDF2 hash parameters")
				return false
			}
			switch {
			case key == "i" && !seenI:
				iterations, seenI = n, true
			case key == "l" && !seenL:
				keyLen, seenL = n, true
			default:
				log.Errorf("unknown or repeated options key in PBKDF2 hash parameters")
				return false
			}
		}
		if !seenI || !seenL {
			log.Errorf("missing options key in PBKDF2 hash parameters")
			return false
		}
		saltField = fields[2]
		// Padding is accepted on the checksum, as before; the length is still checked against l.
		stored, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(fields[3], "="))
		if err != nil {
			log.Errorf("invalid PBKDF2 hash supplied, bad key encoding")
			return false
		}
		if h.saltEncoding != UTF8 {
			salt, err = base64.RawStdEncoding.DecodeString(saltField)
		}
	default:
		log.Errorf("invalid PBKDF2 hash supplied, unrecognized format")
		return false
	}
	if err != nil {
		log.Errorf("invalid PBKDF2 hash supplied, bad salt encoding")
		return false
	}
	if h.saltEncoding == UTF8 {
		salt = []byte(saltField)
	}

	// The limits are checked before any key derivation work.
	if !pbkdf2InLimits(iterations, keyLen, len(salt)) || len(stored) != keyLen {
		log.Errorf("invalid PBKDF2 hash supplied, parameters are outside the limits")
		return false
	}

	derived, err := h.key(password, salt, iterations, algorithm, keyLen)
	if err != nil {
		log.Errorf("PBKDF2 key derivation error")
		return false
	}

	return subtle.ConstantTimeCompare(derived, stored) == 1
}

// pbkdf2InLimits reports whether the parameters are in the range that Compare accepts.
func pbkdf2InLimits(iterations, keyLen, saltLen int) bool {
	return iterations >= 1 && iterations <= maxPBKDF2Iterations &&
		keyLen >= 1 && keyLen <= maxKeyLen &&
		saltLen >= 0 && saltLen <= maxSaltLen
}

func (h pbkdf2Hasher) key(password string, salt []byte, iterations int, algorithm string, keylen int) ([]byte, error) {
	shaHash := sha512.New
	if algorithm == SHA256 {
		shaHash = sha256.New
	}
	return pbkdf2.Key(shaHash, password, salt, iterations, keylen)
}

// Reference: https://github.com/brocaar/chirpstack-application-server/blob/master/internal/storage/user.go#L432.
func (h pbkdf2Hasher) hashWithSalt(password string, salt []byte, iterations int, algorithm string, keylen int) (string, error) {
	// Generate the hashed password. This should be a little painful, adjust ITERATIONS
	// if it needs performance tweaking.  Greatly depends on the hardware.
	// NOTE: We store these details with the returned hashed, so changes will not
	// affect our ability to do password compares.
	hashed, err := h.key(password, salt, iterations, algorithm, keylen)
	if err != nil {
		return "", fmt.Errorf("pbkdf2 error: %s", err)
	}

	var buffer bytes.Buffer

	buffer.WriteString("PBKDF2$")
	buffer.WriteString(fmt.Sprintf("%s$", algorithm))
	buffer.WriteString(strconv.Itoa(iterations))
	buffer.WriteString("$")

	switch h.saltEncoding {
	case UTF8:
		buffer.WriteString(string(salt))
	default:
		buffer.WriteString(base64.StdEncoding.EncodeToString(salt))
	}

	buffer.WriteString("$")
	buffer.WriteString(base64.StdEncoding.EncodeToString(hashed))

	return buffer.String(), nil
}
