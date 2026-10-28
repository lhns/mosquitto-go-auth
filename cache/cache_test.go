package cache

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExpirationWithJitter(t *testing.T) {
	/* Since expirationWithJitter randomizes the expirtaion time, do test
	multiple times and check that result is within expected range
	*/
	for n := 0; n < 1000; n++ {
		expiration := 100 * time.Millisecond

		jitter := 10 * time.Millisecond

		got := expirationWithJitter(expiration, jitter)
		assert.True(t, expiration-jitter <= got)
		assert.True(t, got <= expiration+jitter)

		jitter = 150 * time.Millisecond

		got = expirationWithJitter(expiration, jitter)
		assert.True(t, 0 <= got)
		assert.True(t, got <= expiration+jitter)
	}
}

func TestExpirationWithoutJitter(t *testing.T) {
	// jitter to 0 disable randomization
	jitter := 0 * time.Millisecond
	expiration := 100 * time.Millisecond

	got := expirationWithJitter(expiration, jitter)
	assert.Equal(t, expiration, got)
}

func TestGoStore(t *testing.T) {
    t.Skip("Skipping flaky test")

	authExpiration := 100 * time.Millisecond
	aclExpiration := 100 * time.Millisecond
	authJitter := 10 * time.Millisecond
	aclJitter := 10 * time.Millisecond
	refreshExpiration := false

	store := NewGoStore(authExpiration, aclExpiration, authJitter, aclJitter, refreshExpiration)

	ctx := context.Background()

	assert.Equal(t, authExpiration, store.authExpiration)
	assert.Equal(t, aclExpiration, store.aclExpiration)
	assert.Equal(t, authJitter, store.authJitter)
	assert.Equal(t, aclJitter, store.aclJitter)

	assert.True(t, store.Connect(ctx, false))

	username := "test-user"
	password := "test-password"
	topic := "test/topic"
	acc := 1

	// Test granted access.
	err := store.SetAuthRecord(ctx, username, password, "client", "true")
	assert.Nil(t, err)

	present, granted := store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.True(t, granted)

	// Wait for it to expire.
	time.Sleep(150 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.False(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "true")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.True(t, granted)

	// Wait for it to expire.
	time.Sleep(150 * time.Millisecond)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.False(t, present)
	assert.False(t, granted)

	// Test not granted access.
	err = store.SetAuthRecord(ctx, username, password, "client", "false")
	assert.Nil(t, err)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.False(t, granted)

	// Wait for it to expire.
	time.Sleep(150 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.False(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "false")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.False(t, granted)

	// Wait for it to expire.
	time.Sleep(150 * time.Millisecond)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.False(t, present)
	assert.False(t, granted)

	// Check expiration is refreshed.
	store = NewGoStore(authExpiration, aclExpiration, authExpiration, aclJitter, true)

	// Test granted access.
	err = store.SetAuthRecord(ctx, username, password, "client", "true")
	assert.Nil(t, err)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.True(t, granted)

	// Check again within expiration time.
	time.Sleep(50 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.True(t, granted)

	// Expiration should have been refreshed.
	time.Sleep(65 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.True(t, granted)
}

// legacyKey builds a key as earlier versions wrote it: base64 of the text plus SHA-1 of the empty input.
func legacyKey(text string) string {
	empty := sha1.Sum(nil)
	return base64.StdEncoding.EncodeToString(append([]byte(text), empty[:]...))
}

func TestIsLegacyKey(t *testing.T) {
	assert.True(t, isLegacyKey(legacyKey("auth-a-b")))
	assert.True(t, isLegacyKey(legacyKey("acl-a-b-c-1")))
	assert.False(t, isLegacyKey(legacyKey("other-a-b")))
	assert.False(t, isLegacyKey(base64.RawStdEncoding.EncodeToString([]byte("auth-a-b"))))
	assert.False(t, isLegacyKey("mga:v5:auth:3a73e8bc64e84e4fe5196a1f0eb1531a6ed014d8921f639340527cc6fcfc8c3e"))
}
