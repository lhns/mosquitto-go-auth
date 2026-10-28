package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

// plain is the keyer of a store without a key (a Redis store with no secret and no password).
var plain keyer

func newTestGoStore() *goStore {
	return NewGoStore(time.Minute, time.Minute, 0, 0, false)
}

func TestAuthRecordFieldBoundaries(t *testing.T) {
	ctx := context.Background()
	pairs := [][2][2]string{
		{{"a-x", "y"}, {"a", "x-y"}},
		{{"a", "x-y"}, {"a-x", "y"}},
	}

	for _, p := range pairs {
		s := newTestGoStore()
		assert.NoError(t, s.SetAuthRecord(ctx, p[0][0], p[0][1], "true"))

		present, _ := s.CheckAuthRecord(ctx, p[0][0], p[0][1])
		assert.True(t, present)

		present, _ = s.CheckAuthRecord(ctx, p[1][0], p[1][1])
		assert.False(t, present, "%v must not match %v", p[1], p[0])
	}
}

func TestACLRecordFieldBoundaries(t *testing.T) {
	ctx := context.Background()
	type acl struct {
		user, topic, client string
		acc                 int
	}
	base := acl{"a-b", "c", "d", 1}
	others := []acl{
		{"a", "b-c", "d", 1},
		{"a", "b", "c-d", 1},
		{"a-b", "c-d", "", 1},
		{"a-b-c", "d", "", 1},
		{"a-b", "c", "d", 2},
	}

	s := newTestGoStore()
	assert.NoError(t, s.SetACLRecord(ctx, base.user, base.topic, base.client, base.acc, "true"))

	present, granted := s.CheckACLRecord(ctx, base.user, base.topic, base.client, base.acc)
	assert.True(t, present)
	assert.True(t, granted)

	for _, o := range others {
		present, _ = s.CheckACLRecord(ctx, o.user, o.topic, o.client, o.acc)
		assert.False(t, present, "%v must not match %v", o, base)
	}
}

func TestAuthAndACLDomainsAreSeparate(t *testing.T) {
	ctx := context.Background()
	s := newTestGoStore()

	assert.NoError(t, s.SetAuthRecord(ctx, "u", "p", "true"))
	present, _ := s.CheckACLRecord(ctx, "u", "p", "", 0)
	assert.False(t, present)
}

// The store does not log the cache keys or the fields, also at debug level.
func TestKeysNotLogged(t *testing.T) {
	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)
	level := log.GetLevel()
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() { log.SetLevel(level) })

	ctx := context.Background()
	s := newTestGoStore()
	assert.NoError(t, s.SetAuthRecord(ctx, "someuser", "s3cr3t-pass", "true"))
	s.CheckAuthRecord(ctx, "someuser", "s3cr3t-pass")
	assert.NoError(t, s.SetACLRecord(ctx, "someuser", "some/topic", "client-77", 1, "true"))
	s.CheckACLRecord(ctx, "someuser", "some/topic", "client-77", 1)

	// A key or its bytes in any form is not logged: the store logs nothing here.
	for _, e := range hook.AllEntries() {
		assert.Fail(t, "unexpected log entry", fmt.Sprint(e.Message, e.Data))
	}
}

// expectedKey builds a key by hand: sha256 over uvarint(len) + bytes for the domain and each field.
// All lengths used here are below 128, so each prefix is a single byte.
func expectedKey(domain string, fields ...string) string {
	var b []byte
	for _, f := range append([]string{domain}, fields...) {
		b = append(b, byte(len(f)%128))
		b = append(b, f...)
	}
	sum := sha256.Sum256(b)
	return "mga:v5:" + domain + ":" + hex.EncodeToString(sum[:])
}

func TestKeyEncoding(t *testing.T) {
	assert.Equal(t, expectedKey("auth", "n", "u", "p"), plain.toAuthRecord("u", "p"))
	assert.Equal(t, expectedKey("auth", "n", "", ""), plain.toAuthRecord("", ""))
	assert.Equal(t, expectedKey("acl", "u", "t/1", "c", "1"), plain.toACLRecord("u", "t/1", "c", 1))

	// Fixed vectors, computed outside the Go code.
	assert.Equal(t, "mga:v5:auth:9ba19bc012f5c559a7d579590a5a2eef1f3de7db8c95ed6bb22ed0f676570b71", plain.toAuthRecord("u", "p"))
	assert.Equal(t, "mga:v5:acl:f8af8bf8397413ae2f2a9407d952a2ee4997082a37da0d3137fa5acad5aa6a89", plain.toACLRecord("u", "t/1", "c", 1))
}

// A keyed digest is HMAC-SHA-256, checked against vectors computed outside the Go code. A different
// key, and no key, give different keys for the same fields.
func TestKeyedDigest(t *testing.T) {
	k := keyer{key: []byte("secret")}
	assert.Equal(t, "mga:v5:auth:2f1ef22a13d47f28efd9a388961d6fe98eeb6e5b1abce55a3aac6d922a659dbf", k.toAuthRecord("u", "p"))
	assert.Equal(t, "mga:v5:acl:16eefc97b83e76c2699be1efe748810137fa90b2b0a99cf226ce0be4fa23ae1c", k.toACLRecord("u", "t/1", "c", 1))

	other := keyer{key: []byte("other")}
	assert.NotEqual(t, k.toAuthRecord("u", "p"), other.toAuthRecord("u", "p"))
	assert.NotEqual(t, k.toAuthRecord("u", "p"), plain.toAuthRecord("u", "p"))
}

// Each Go store has its own random key, so two stores (two processes) do not share keys.
func TestGoStoreKeyIsRandom(t *testing.T) {
	a, b := newTestGoStore(), newTestGoStore()
	assert.Len(t, a.keys.key, sha256.Size)
	assert.NotEqual(t, a.keys.toAuthRecord("u", "p"), b.keys.toAuthRecord("u", "p"))
	assert.NotEqual(t, plain.toAuthRecord("u", "p"), a.keys.toAuthRecord("u", "p"))
}

// The Redis store is keyed by the constructor argument cache_key_secret; no secret keeps the plain digest.
// The same secret in another store gives the same keys: brokers can share a cache.
func TestRedisKeySecret(t *testing.T) {
	newStore := func(secret string) *redisStore {
		s := NewSingleRedisStore("localhost", "6379", "", secret, 3, time.Minute, time.Minute, 0, 0, false)
		t.Cleanup(s.Close)
		return s
	}

	assert.Equal(t, plain.toAuthRecord("u", "p"), newStore("").keys.toAuthRecord("u", "p"))
	assert.Equal(t, keyer{key: []byte("secret")}.toAuthRecord("u", "p"), newStore("secret").keys.toAuthRecord("u", "p"))
	assert.Equal(t, newStore("secret").keys.toAuthRecord("u", "p"), newStore("secret").keys.toAuthRecord("u", "p"))
}
