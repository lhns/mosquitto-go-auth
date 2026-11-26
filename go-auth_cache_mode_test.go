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

	// cache_reset flushes the cache database: it must never be pointed at the cluster of the Redis backend.
	t.Run("cluster does not use the addresses of the redis backend", func(t *testing.T) {
		opts := base()
		opts["cache_mode"] = "cluster"
		opts["redis_cluster_addresses"] = "localhost:7000,localhost:7001,localhost:7002"
		opts["cache_reset"] = "true"
		authPlugin = AuthPlugin{useCache: true, ctx: context.Background()}
		setCache(opts)
		require.False(t, authPlugin.useCache)
		require.Nil(t, authPlugin.cache)
	})
}
