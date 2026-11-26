//go:build integration

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// The cases of TestSetCacheClusterOptions that connect to the Redis cluster.
func TestSetCacheClusterOptionsRedis(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{"cache": "true", "cache_type": "redis"}
	}

	t.Run("documented addresses option", func(t *testing.T) {
		opts := base()
		opts["cache_mode"] = "cluster"
		opts["cache_addresses"] = "localhost:7000,localhost:7001,localhost:7002"
		opts["cache_port"] = "1" // a fallback to the single instance fails to connect
		authPlugin = AuthPlugin{useCache: true, ctx: context.Background()}
		setCache(opts)
		require.True(t, authPlugin.useCache)
		require.NotNil(t, authPlugin.cache)
		authPlugin.cache.Close()
	})

	// The old spelling cache_mode true read the Redis backend's cluster addresses, and keeps doing so.
	t.Run("old spelling reads redis_cluster_addresses", func(t *testing.T) {
		opts := base()
		opts["cache_mode"] = "true"
		opts["redis_cluster_addresses"] = "localhost:7000,localhost:7001,localhost:7002"
		opts["cache_port"] = "1"
		authPlugin = AuthPlugin{useCache: true, ctx: context.Background()}
		setCache(opts)
		require.True(t, authPlugin.useCache)
		require.NotNil(t, authPlugin.cache)
		authPlugin.cache.Close()
	})
}
