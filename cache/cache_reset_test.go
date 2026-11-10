package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// cache_reset on a cluster cache must empty every master: FLUSHDB on a cluster client only
// reaches one random master before Redis 7.
func TestRedisClusterResetFlushesAllMasters(t *testing.T) {
	ctx := context.Background()
	addresses := []string{"localhost:7000", "localhost:7001", "localhost:7002"}
	store := NewRedisClusterStore("", "secret", addresses, time.Hour, time.Hour, 0, 0, false)
	t.Cleanup(store.Close)
	require.True(t, store.Connect(ctx, false))

	// Many keys, so that every master holds some.
	for i := 0; i < 200; i++ {
		require.NoError(t, store.SetAuthRecord(ctx, fmt.Sprintf("user%d", i), "pass", "client", "true"))
	}

	count := func() (perMaster []int64) {
		require.NoError(t, store.client.ForEachMaster(ctx, func(ctx context.Context, c *goredis.Client) error {
			n, err := c.DBSize(ctx).Result()
			perMaster = append(perMaster, n)
			return err
		}))
		return perMaster
	}

	filled := 0
	for _, n := range count() {
		if n > 0 {
			filled++
		}
	}
	require.GreaterOrEqual(t, filled, 2, "the test needs keys on at least 2 masters")

	require.True(t, store.Connect(ctx, true))

	for i, n := range count() {
		require.Zero(t, n, "master %d still holds keys after the reset", i)
	}
}
