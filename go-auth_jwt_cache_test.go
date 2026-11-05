package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	bes "github.com/iegomez/mosquitto-go-auth/backends"
	"github.com/iegomez/mosquitto-go-auth/cache"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// A cached login or ACL result for a JWT must not be used after the token exp.
// The remote server grants a token until its exp. The plugin does not parse the
// token (jwt_parse_token false), and the token algorithm (ES256K) is not
// registered in the JWT library.
func TestCachedJWTResultsEndAtExp(t *testing.T) {
	testCachedJWTResultsEndAtExp(t, false)
}

// In remote mode the server decides about exp, so the skip options do not lift the cap.
func TestCachedJWTResultsEndAtExpWithSkipOptions(t *testing.T) {
	testCachedJWTResultsEndAtExp(t, true)
}

func testCachedJWTResultsEndAtExp(t *testing.T, skip bool) {
	saved, savedLevel := authPlugin, log.GetLevel()
	t.Cleanup(func() {
		authPlugin = saved
		log.SetLevel(savedLevel)
	})

	var expOf sync.Map // token -> exp
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exp, ok := expOf.Load(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if ok && r.URL.Path != "/superuser" && time.Now().Before(exp.(time.Time)) {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)

	authOpts := map[string]string{
		"backends":          "jwt",
		"jwt_mode":          "remote",
		"jwt_host":          host,
		"jwt_port":          port,
		"jwt_getuser_uri":   "/user",
		"jwt_superuser_uri": "/superuser",
		"jwt_aclcheck_uri":  "/acl",
	}
	if skip {
		authOpts["jwt_skip_user_expiration"] = "true"
		authOpts["jwt_skip_acl_expiration"] = "true"
	}
	b, err := bes.Initialize(authOpts, log.ErrorLevel, "2.1.2")
	require.NoError(t, err)
	t.Cleanup(b.Halt)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256K","typ":"JWT"}`))

	for _, refresh := range []bool{false, true} {
		store := cache.NewGoStore(time.Hour, time.Hour, 0, 0, refresh)
		t.Cleanup(store.Close)
		authPlugin = AuthPlugin{backends: b, ctx: context.Background(), useCache: true, cache: store}

		// exp has a resolution of one second.
		exp := time.Now().Add(2 * time.Second).Truncate(time.Second)
		payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"test","exp":%d}`, exp.Unix())))
		token := header + "." + payload + ".c2lnbmF0dXJl"
		expOf.Store(token, exp)

		// The first checks fill the cache, the second checks are cache hits.
		for i := 0; i < 2; i++ {
			ok, err := authUnpwdCheck(token, "password", "id")
			require.NoError(t, err)
			require.True(t, ok, "login before exp, refresh %v", refresh)
			ok, err = authAclCheck("id", token, "a/b", 1)
			require.NoError(t, err)
			require.True(t, ok, "acl before exp, refresh %v", refresh)
		}

		time.Sleep(time.Until(exp) + 100*time.Millisecond)

		ok, _ := authUnpwdCheck(token, "password", "id")
		require.False(t, ok, "login after exp, refresh %v", refresh)
		ok, _ = authAclCheck("id", token, "a/b", 1)
		require.False(t, ok, "acl after exp, refresh %v", refresh)
	}
}

// deadlineBackends reports a fixed cache deadline and counts the backend calls.
type deadlineBackends struct {
	mockBackends
	deadline time.Time
	calls    int
}

func (d *deadlineBackends) CacheDeadline(string, bool) (time.Time, bool) { return d.deadline, true }

func (d *deadlineBackends) AuthUnpwdCheck(context.Context, string, string, string) (bool, error) {
	d.calls++
	return false, nil
}

// A cache entry is not read once the deadline has passed, and a result is not stored.
func TestExpiredDeadlineSkipsCache(t *testing.T) {
	saved := authPlugin
	t.Cleanup(func() { authPlugin = saved })

	store := cache.NewGoStore(time.Hour, time.Hour, 0, 0, false)
	t.Cleanup(store.Close)
	require.NoError(t, store.SetAuthRecord(context.Background(), "user", "pass", "id", "true"))

	backends := &deadlineBackends{deadline: time.Now().Add(-time.Second)}
	authPlugin = AuthPlugin{backends: backends, ctx: context.Background(), useCache: true, cache: store}

	ok, err := authUnpwdCheck("user", "pass", "id")
	require.NoError(t, err)
	require.False(t, ok, "the cached grant must not be used")
	require.Equal(t, 1, backends.calls)

	// The result false was not stored either: a live deadline reads the old entry again.
	backends.deadline = time.Now().Add(time.Hour)
	ok, _ = authUnpwdCheck("user", "pass", "id")
	require.True(t, ok)
	require.Equal(t, 1, backends.calls)
}

// expiringBackends reports a deadline that passes during the cache read.
type expiringBackends struct {
	deadlineBackends
	checks int
}

// The first check (before the cache read) is live, the next ones are expired.
func (e *expiringBackends) CacheDeadline(string, bool) (time.Time, bool) {
	e.checks++
	if e.checks == 1 {
		return time.Now().Add(time.Hour), true
	}
	return time.Now().Add(-time.Second), true
}

func (e *expiringBackends) AuthAclCheck(context.Context, string, string, string, int) (bool, error) {
	e.calls++
	return false, nil
}

// A deadline that passes between the check before the cache read and the cache hit must not
// serve the cached grant.
func TestDeadlinePassingDuringCacheReadSkipsHit(t *testing.T) {
	saved := authPlugin
	t.Cleanup(func() { authPlugin = saved })

	store := cache.NewGoStore(time.Hour, time.Hour, 0, 0, false)
	t.Cleanup(store.Close)
	require.NoError(t, store.SetAuthRecord(context.Background(), "user", "pass", "id", "true"))
	require.NoError(t, store.SetACLRecord(context.Background(), "user", "a/b", "id", 1, "true"))

	backends := &expiringBackends{}
	authPlugin = AuthPlugin{backends: backends, ctx: context.Background(), useCache: true, cache: store}

	ok, err := authUnpwdCheck("user", "pass", "id")
	require.NoError(t, err)
	require.False(t, ok, "the cached login grant must not be used")
	require.Equal(t, 1, backends.calls)

	backends.checks = 0
	ok, err = authAclCheck("id", "user", "a/b", 1)
	require.NoError(t, err)
	require.False(t, ok, "the cached acl grant must not be used")
	require.Equal(t, 2, backends.calls)
}
