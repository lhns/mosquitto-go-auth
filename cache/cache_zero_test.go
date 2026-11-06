package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A cache time of 0 (or less) means do not cache: nothing is stored, nothing is read.
func TestZeroCacheTimeStoresNothing(t *testing.T) {
	ctx := context.Background()

	for _, seconds := range []time.Duration{0, -1 * time.Second} {
		for _, refresh := range []bool{false, true} {
			// The auth time is off and the acl time is on, and the other way around.
			for _, authOff := range []bool{true, false} {
				authExp, aclExp := time.Hour, time.Hour
				if authOff {
					authExp = seconds
				} else {
					aclExp = seconds
				}

				goStore := NewGoStore(authExp, aclExp, 0, 0, refresh)
				fake := newFakeRedis()
				redisStore := &redisStore{
					authExpiration: authExp, aclExpiration: aclExp, refreshExpiration: refresh,
					client: fake, keys: keyerFromSecret("secret"),
				}
				stores := map[string]Store{"go": goStore, "redis": redisStore}

				for name, store := range stores {
					msg := func(s string) string { return name + " " + s }

					require.NoError(t, store.SetAuthRecord(ctx, "u", "p", "c", "true"), msg("set auth"))
					require.NoError(t, store.SetACLRecord(ctx, "u", "a/b", "c", 1, "true"), msg("set acl"))

					present, _ := store.CheckAuthRecord(ctx, "u", "p", "c")
					require.Equal(t, !authOff, present, msg("auth present"))
					present, _ = store.CheckACLRecord(ctx, "u", "a/b", "c", 1)
					require.Equal(t, authOff, present, msg("acl present"))
				}

				// Redis was neither written nor read for the cache that is off.
				wantSets, wantGets := 1, 1
				require.Equal(t, wantSets, fake.sets, "redis sets")
				require.Equal(t, wantGets, fake.gets, "redis gets")
				// Only the hit of the cache that is on may refresh an expiry.
				wantExpires := 0
				if refresh {
					wantExpires = 1
				}
				require.Equal(t, wantExpires, fake.expires, "refresh must not touch an entry of the cache that is off")

				goStore.Close()
			}
		}
	}
}
