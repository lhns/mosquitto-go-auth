package main

import (
	"context"
	"testing"
	"time"

	"github.com/iegomez/mosquitto-go-auth/cache"
	"github.com/stretchr/testify/require"
)

// crossingBackends has a live deadline until its check has run: the exp passes during the call.
type crossingBackends struct {
	mockBackends
	crossed bool
}

func (c *crossingBackends) CacheDeadline(string, bool) (time.Time, bool) {
	if c.crossed {
		return time.Now().Add(-time.Second), true
	}
	return time.Now().Add(time.Hour), true
}

func (c *crossingBackends) AuthUnpwdCheck(context.Context, string, string, string) (bool, error) {
	c.crossed = true
	return true, nil
}

func (c *crossingBackends) AuthAclCheck(context.Context, string, string, string, int) (bool, error) {
	c.crossed = true
	return true, nil
}

// countingStore counts the writes that reach the cache.
type countingStore struct {
	cache.Store
	sets int
}

func (c *countingStore) SetAuthRecord(ctx context.Context, username, password, clientid, granted string) error {
	c.sets++
	return c.Store.SetAuthRecord(ctx, username, password, clientid, granted)
}

func (c *countingStore) SetACLRecord(ctx context.Context, username, topic, clientid string, acc int, granted string) error {
	c.sets++
	return c.Store.SetACLRecord(ctx, username, topic, clientid, acc, granted)
}

// A backend call that is still running when the exp passes must not store its result.
func TestResultOfCallCrossingExpIsNotStored(t *testing.T) {
	saved := authPlugin
	t.Cleanup(func() { authPlugin = saved })

	inner := cache.NewGoStore(time.Hour, time.Hour, 0, 0, false)
	t.Cleanup(inner.Close)
	store := &countingStore{Store: inner}

	backends := &crossingBackends{}
	authPlugin = AuthPlugin{backends: backends, ctx: context.Background(), useCache: true, cache: store}

	ok, err := authUnpwdCheck("user", "pass", "id")
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, store.sets, "the login result was stored after the exp")

	backends.crossed = false
	ok, err = authAclCheck("id", "user", "a/b", 1)
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, store.sets, "the acl result was stored after the exp")
}
