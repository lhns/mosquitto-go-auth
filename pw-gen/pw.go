package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/iegomez/mosquitto-go-auth/hashing"
)

func main() {

	var hasher = flag.String("h", "pbkdf2", "hasher: pbkdf2, argon2id or bcrypt")
	var algorithm = flag.String("a", "sha512", "algorithm: sha256 or sha512")
	var iterations = flag.Int("i", 0, "hash iterations: defaults to 100000 for pbkdf2 and 3 for argon2")
	var password = flag.String("p", "", "password")
	var saltSize = flag.Int("s", 16, "salt size")
	var saltEncoding = flag.String("e", "base64", "salt encoding")
	var keylen = flag.Int("l", 0, "key length, recommended values are 32 for sha256 and 64 for sha512")
	var cost = flag.Int("c", 10, "bcrypt ost param")
	var memory = flag.Int("m", 4096, "memory for argon2 hash")
	var parallelism = flag.Int("pl", 2, "parallelism for argon2")

	flag.Parse()

	shaSize := *keylen

	if shaSize == 0 {
		switch *algorithm {
		case hashing.SHA256:
			shaSize = hashing.SHA256Size
		case hashing.SHA512:
			shaSize = hashing.SHA512Size
		default:
			fmt.Fprintln(os.Stderr, "invalid password hash algorithm:", *algorithm)
			os.Exit(1)
		}
	}

	// One default does not fit both: argon2id iterations are passes over memory, a few are enough.
	if *iterations == 0 {
		*iterations = 100000
		if *hasher == hashing.Argon2IDOpt {
			*iterations = 3
		}
	}

	var hashComparer hashing.HashComparer

	switch *hasher {
	case hashing.Argon2IDOpt:
		hashComparer = hashing.NewArgon2IDHasher(*saltSize, *iterations, shaSize, uint32(*memory), uint8(*parallelism))
	case hashing.BcryptOpt:
		hashComparer = hashing.NewBcryptHashComparer(*cost)
	case hashing.Pbkdf2Opt:
		hashComparer = hashing.NewPBKDF2Hasher(*saltSize, *iterations, *algorithm, *saltEncoding, shaSize)
	default:
		fmt.Fprintln(os.Stderr, "invalid hasher option:", *hasher)
		os.Exit(1)
	}

	pwHash, err := hashComparer.Hash(*password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	fmt.Println(pwHash)

}
