package cache

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestRedisKeyNamespace(t *testing.T) {
	store := NewSingleRedisStore("localhost", "6379", "", "", 3, time.Minute, time.Minute, 0, 0, false)
	ctx := context.Background()
	assert.True(t, store.Connect(ctx, false))
	defer store.Close()

	assert.NoError(t, store.SetAuthRecord(ctx, "u", "p", "client", "true"))
	assert.NoError(t, store.SetACLRecord(ctx, "u", "t/1", "c", 1, "true"))

	keys := []string{
		"mga:v5:auth:fe9e3695616028c061b57e241969d2a81fcc6c6b88f9d93067f99481c0a86b70",
		"mga:v5:acl:f8af8bf8397413ae2f2a9407d952a2ee4997082a37da0d3137fa5acad5aa6a89",
	}
	for _, k := range keys {
		v, err := store.client.Get(ctx, k).Result()
		assert.NoError(t, err)
		assert.Equal(t, "true", v)
	}
}

func TestRedisSingleStore(t *testing.T) {
	authExpiration := 1000 * time.Millisecond
	aclExpiration := 1000 * time.Millisecond
	authJitter := 100 * time.Millisecond
	aclJitter := 100 * time.Millisecond
	refreshExpiration := false

	store := NewSingleRedisStore("localhost", "6379", "", "", 3, authExpiration, aclExpiration, authJitter, aclJitter, refreshExpiration)

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

	// Wait for it to expire. For Redis we do this just once since the package used (or Redis itself, not sure) doesn't
	// support less than 1s expiration times: "specified duration is 100ms, but minimal supported value is 1s"
	time.Sleep(1150 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.False(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "true")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.True(t, granted)

	// Test not granted access.
	err = store.SetAuthRecord(ctx, username, password, "client", "false")
	assert.Nil(t, err)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "false")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.False(t, granted)

	// Check expiration is refreshed.
	store = NewSingleRedisStore("localhost", "6379", "", "", 3, authExpiration, aclExpiration, authJitter, aclJitter, true)

	// Test granted access.
	err = store.SetAuthRecord(ctx, username, password, "client", "true")
	assert.Nil(t, err)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.True(t, granted)

	// Check it again within expiration time.
	time.Sleep(500 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.True(t, granted)

	// Expiration should have been refreshed.
	time.Sleep(800 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.True(t, granted)
}

func TestRedisClusterStore(t *testing.T) {
	authExpiration := 1000 * time.Millisecond
	aclExpiration := 1000 * time.Millisecond
	authJitter := 100 * time.Millisecond
	aclJitter := 100 * time.Millisecond
	refreshExpiration := false

	addresses := []string{"localhost:7000", "localhost:7001", "localhost:7002"}
	store := NewRedisClusterStore("", "", addresses, authExpiration, aclExpiration, authJitter, aclJitter, refreshExpiration)

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

	// Wait for it to expire. For Redis we do this just once since the package used (or Redis itself, not sure) doesn't
	// support less than 1s expiration times: "specified duration is 100ms, but minimal supported value is 1s"
	time.Sleep(1150 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.False(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "true")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.True(t, granted)

	// Test not granted access.
	err = store.SetAuthRecord(ctx, username, password, "client", "false")
	assert.Nil(t, err)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "false")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.False(t, granted)

	store = NewRedisClusterStore("", "", addresses, authExpiration, aclExpiration, authJitter, aclJitter, true)

	// Test granted access.
	err = store.SetAuthRecord(ctx, username, password, "client", "true")
	assert.Nil(t, err)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.True(t, granted)

	// Check it again within expiration time.
	time.Sleep(500 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.True(t, granted)

	// Expiration should have been refreshed.
	time.Sleep(800 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password, "client")

	assert.True(t, present)
	assert.True(t, granted)
}

// legacyKey builds a key as earlier versions wrote it: base64 of the text plus SHA-1 of the empty input.
func legacyKey(text string) string {
	empty := sha1.Sum(nil)
	return base64.StdEncoding.EncodeToString(append([]byte(text), empty[:]...))
}

// The sweep that the constructor starts deletes legacy keys (which hold the password) and nothing
// else: a key with the right prefix but another suffix, a foreign key and a current key stay.
func testSweepLegacyKeys(t *testing.T, newStore func() *redisStore, legacy []string) {
	ctx := context.Background()

	decoy := base64.StdEncoding.EncodeToString([]byte("auth-legacy-user-legacy-pass-not-a-sha1-suffix"))
	keep := []string{decoy, "foreign:key", "mga:v5:auth:abc"}

	seed := newStore()
	<-seed.sweepDone
	for _, k := range append(append([]string{}, legacy...), keep...) {
		assert.NoError(t, seed.client.Set(ctx, k, "true", time.Minute).Err())
	}
	seed.Close()

	store := newStore()
	defer store.Close()
	<-store.sweepDone

	for _, k := range legacy {
		_, err := store.client.Get(ctx, k).Result()
		assert.Error(t, err, "legacy key %q must be deleted", k)
	}
	for _, k := range keep {
		_, err := store.client.Get(ctx, k).Result()
		assert.NoError(t, err, "key %q must be kept", k)
	}
}

func TestRedisSweepLegacyKeys(t *testing.T) {
	testSweepLegacyKeys(t, func() *redisStore {
		return NewSingleRedisStore("localhost", "6379", "", "", 3, time.Minute, time.Minute, 0, 0, false)
	}, []string{legacyKey("auth-legacy-user-legacy-pass"), legacyKey("acl-u-t/1-c-1")})
}

func TestRedisClusterSweepLegacyKeys(t *testing.T) {
	addresses := []string{"localhost:7000", "localhost:7001", "localhost:7002", "localhost:7003", "localhost:7004", "localhost:7005"}
	newStore := func() *redisStore {
		return NewRedisClusterStore("", "", addresses, time.Minute, time.Minute, 0, 0, false)
	}

	// Pick two legacy keys that live on different masters, so the test fails if the sweep
	// only scans one of them.
	probe := newStore()
	<-probe.sweepDone
	var legacy []string
	var firstMaster string
	for i := 0; i < 1000 && len(legacy) < 2; i++ {
		key := legacyKey(fmt.Sprintf("auth-legacy-user-%d-legacy-pass", i))
		master, err := probe.client.(*goredis.ClusterClient).MasterForKey(context.Background(), key)
		require.NoError(t, err)
		if len(legacy) == 0 {
			legacy, firstMaster = append(legacy, key), master.Options().Addr
		} else if master.Options().Addr != firstMaster {
			legacy = append(legacy, key)
		}
	}
	probe.Close()
	require.Len(t, legacy, 2, "legacy fixtures must be on two different masters")

	testSweepLegacyKeys(t, newStore, legacy)
}

func TestIsLegacyKey(t *testing.T) {
	assert.True(t, isLegacyKey(legacyKey("auth-a-b")))
	assert.True(t, isLegacyKey(legacyKey("acl-a-b-c-1")))
	assert.False(t, isLegacyKey(legacyKey("other-a-b")))
	assert.False(t, isLegacyKey(base64.RawStdEncoding.EncodeToString([]byte("auth-a-b"))))
	assert.False(t, isLegacyKey("mga:v5:auth:fe9e3695616028c061b57e241969d2a81fcc6c6b88f9d93067f99481c0a86b70"))
}
