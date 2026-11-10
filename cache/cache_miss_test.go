package cache

import (
	"context"
	"errors"
	"strings"
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
	require.Empty(t, cacheErrorLogs(hook), "a cache miss must not be logged")

	fake.getErr = errors.New("connection refused")
	present, _ = s.CheckAuthRecord(ctx, "u", "p", "c")
	require.False(t, present)
	logs := cacheErrorLogs(hook)
	require.Len(t, logs, 1)
	require.Contains(t, logs[0], "connection refused")
}

// cacheErrorLogs gives the cache error messages. Other tests leave goroutines that log too (the
// legacy key sweep of a store), so the hook sees more than this test writes.
func cacheErrorLogs(hook *logtest.Hook) (messages []string) {
	for _, e := range hook.AllEntries() {
		if strings.Contains(e.Message, "cache error") {
			messages = append(messages, e.Message)
		}
	}
	return messages
}
