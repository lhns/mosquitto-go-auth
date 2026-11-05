package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// The README documents cache_mode cluster with cache_addresses; the code used to check
// cache_mode true and redis_cluster_addresses, so the documented config fell back to a single instance.
func TestSetCacheClusterOptions(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{"cache": "true", "cache_type": "redis"}
	}

	t.Run("cluster without addresses disables the cache", func(t *testing.T) {
		for _, mode := range []string{"cluster", "true"} {
			opts := base()
			opts["cache_mode"] = mode
			authPlugin = AuthPlugin{useCache: true, ctx: context.Background()}
			setCache(opts)
			require.False(t, authPlugin.useCache, mode)
		}
	})

	t.Run("documented addresses option", func(t *testing.T) {
		for _, key := range []string{"cache_addresses", "redis_cluster_addresses"} {
			opts := base()
			opts["cache_mode"] = "cluster"
			opts[key] = "localhost:7000,localhost:7001,localhost:7002"
			opts["cache_port"] = "1" // a fallback to the single instance fails to connect
			authPlugin = AuthPlugin{useCache: true, ctx: context.Background()}
			setCache(opts)
			require.True(t, authPlugin.useCache, key)
			require.NotNil(t, authPlugin.cache, key)
			authPlugin.cache.Close()
		}
	})
}
