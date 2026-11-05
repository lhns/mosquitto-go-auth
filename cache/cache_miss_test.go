package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

// A miss is not an error: it is not logged as one. A real error still is.
func TestRedisMissIsNotLogged(t *testing.T) {
	ctx := context.Background()
	oldLevel := log.GetLevel()
	oldHooks := log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
	hook := logtest.NewGlobal()
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		log.SetLevel(oldLevel)
		log.StandardLogger().ReplaceHooks(oldHooks)
	})

	fake := newFakeRedis()
	s := &redisStore{authExpiration: time.Hour, aclExpiration: time.Hour, client: fake, keys: keyerFromSecret("")}

	present, _ := s.CheckAuthRecord(ctx, "u", "p", "c")
	require.False(t, present)
	require.Empty(t, hook.AllEntries(), "a cache miss must not be logged")

	fake.getErr = errors.New("connection refused")
	present, _ = s.CheckAuthRecord(ctx, "u", "p", "c")
	require.False(t, present)
	require.Len(t, hook.AllEntries(), 1)
	require.Contains(t, hook.LastEntry().Message, "connection refused")
}
