package main

import (
	"context"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

// A cache time of 0 (or less) means that cache is off: results are neither stored nor read,
// in the memory store and in Redis, and the startup log says so once.
func TestSetCacheZeroSecondsIsOff(t *testing.T) {
	saved := authPlugin
	oldLevel := log.GetLevel()
	oldHooks := log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
	hook := logtest.NewGlobal()
	log.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		authPlugin = saved
		log.SetLevel(oldLevel)
		log.StandardLogger().ReplaceHooks(oldHooks)
	})

	cases := []struct {
		name            string
		authSec, aclSec string
		authOn, aclOn   bool
	}{
		{"auth 0", "0", "30", false, true},
		{"acl 0", "30", "0", true, false},
		{"both 0", "0", "0", false, false},
		{"negative", "-1", "-60", false, false},
		{"both on", "30", "30", true, true},
	}

	for _, cacheType := range []string{"memory", "redis"} {
		for _, tc := range cases {
			t.Run(cacheType+" "+tc.name, func(t *testing.T) {
				hook.Reset()
				opts := map[string]string{
					"cache":              "true",
					"cache_type":         cacheType,
					"cache_key_secret":   "secret",
					"cache_db":           "5",
					"auth_cache_seconds": tc.authSec,
					"acl_cache_seconds":  tc.aclSec,
				}
				authPlugin = AuthPlugin{useCache: true, ctx: context.Background()}
				setCache(opts)
				require.True(t, authPlugin.useCache)
				t.Cleanup(authPlugin.cache.Close)
				c, ctx := authPlugin.cache, context.Background()

				require.NoError(t, c.SetAuthRecord(ctx, "u", "p", "c", "true"))
				require.NoError(t, c.SetACLRecord(ctx, "u", "a/b", "c", 1, "true"))
				present, _ := c.CheckAuthRecord(ctx, "u", "p", "c")
				require.Equal(t, tc.authOn, present, "auth")
				present, _ = c.CheckACLRecord(ctx, "u", "a/b", "c", 1)
				require.Equal(t, tc.aclOn, present, "acl")

				var offLines int
				for _, e := range hook.AllEntries() {
					if e.Level == log.InfoLevel && strings.Contains(e.Message, "cache is off") {
						offLines++
					}
				}
				if tc.authOn && tc.aclOn {
					require.Zero(t, offLines)
				} else {
					require.Equal(t, 1, offLines, "one info line says that cache is off")
				}
			})
		}
	}
}
