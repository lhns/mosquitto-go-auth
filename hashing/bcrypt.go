package hashing

import (
	"errors"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type bcryptHasher struct {
	cost int
}

func NewBcryptHashComparer(cost int) HashComparer {
	return bcryptHasher{
		cost: cost,
	}
}

func bcryptInLimits(cost int) bool {
	return cost <= maxBcryptCost
}

// Hash generates a hashed password using bcrypt.
func (h bcryptHasher) Hash(password string) (string, error) {
	if !bcryptInLimits(h.cost) {
		return "", errors.New("bcrypt cost is over the limit")
	}
	generated, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	return string(generated), err
}

// Compare checks that a bcrypt generated password matches the password hash.
func (h bcryptHasher) Compare(password, passwordHash string) bool {
	cost, err := bcrypt.Cost([]byte(passwordHash))
	if err != nil {
		log.Errorf("invalid bcrypt hash supplied: %s", err)
		return false
	}
	if !bcryptInLimits(cost) {
		log.Errorf("invalid bcrypt hash supplied, cost is outside the limits")
		return false
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return false
	}
	return true
}
