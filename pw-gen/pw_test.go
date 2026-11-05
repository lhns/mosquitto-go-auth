package main

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckArgon2Args(t *testing.T) {
	assert.NoError(t, checkArgon2Args(4096, 2))
	assert.NoError(t, checkArgon2Args(1, 255))
	assert.Error(t, checkArgon2Args(0, 2))
	assert.Error(t, checkArgon2Args(-1, 2))
	assert.Error(t, checkArgon2Args(4096, 0))
	assert.Error(t, checkArgon2Args(4096, 256))
	assert.Error(t, checkArgon2Args(4096, 257)) // wrapped to 1 before
	if strconv.IntSize == 64 {
		over := int64(1) << 32
		assert.Error(t, checkArgon2Args(int(over), 2))
	}
}
