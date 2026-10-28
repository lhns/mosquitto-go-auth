package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

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

	assert.NotEqual(t, toAuthRecord("u", "p"), toACLRecord("u", "p", "", 0))
}

func TestKeysDoNotContainPlaintext(t *testing.T) {
	user, pass, topic, client := "someuser", "s3cr3t-pass", "some/topic", "client-77"

	for _, k := range []string{toAuthRecord(user, pass), toACLRecord(user, topic, client, 1)} {
		assert.True(t, strings.HasPrefix(k, "mga:v5:"))
		for _, f := range []string{user, pass, topic, client} {
			assert.NotContains(t, k, f)
		}
	}
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
	assert.Equal(t, expectedKey("auth", "n", "u", "p"), toAuthRecord("u", "p"))
	assert.Equal(t, expectedKey("auth", "n", "", ""), toAuthRecord("", ""))
	assert.Equal(t, expectedKey("acl", "u", "t/1", "c", "1"), toACLRecord("u", "t/1", "c", 1))

	// Fixed vectors, computed outside the Go code.
	assert.Equal(t, "mga:v5:auth:9ba19bc012f5c559a7d579590a5a2eef1f3de7db8c95ed6bb22ed0f676570b71", toAuthRecord("u", "p"))
	assert.Equal(t, "mga:v5:acl:f8af8bf8397413ae2f2a9407d952a2ee4997082a37da0d3137fa5acad5aa6a89", toACLRecord("u", "t/1", "c", 1))
}

func TestKeyFormat(t *testing.T) {
	re := regexp.MustCompile(`^mga:v5:(auth|acl):[0-9a-f]{64}$`)
	assert.Regexp(t, re, toAuthRecord("u", "p"))
	assert.Regexp(t, re, toACLRecord("u", "t", "c", 0))
	assert.Regexp(t, `^mga:v5:auth:`, toAuthRecord("", ""))
	assert.Regexp(t, `^mga:v5:acl:`, toACLRecord("", "", "", 0))
}
