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

	b, err := bes.Initialize(map[string]string{
		"backends":          "jwt",
		"jwt_mode":          "remote",
		"jwt_host":          host,
		"jwt_port":          port,
		"jwt_getuser_uri":   "/user",
		"jwt_superuser_uri": "/superuser",
		"jwt_aclcheck_uri":  "/acl",
	}, log.ErrorLevel, "2.1.2")
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
