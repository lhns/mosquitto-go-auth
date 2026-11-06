package cache

import (
	"context"
	"time"

	bes "github.com/iegomez/mosquitto-go-auth/backends"
	goredis "github.com/redis/go-redis/v9"
)

// fakeRedis is a RedisClient in memory that counts the calls that reach Redis.
type fakeRedis struct {
	bes.RedisClient
	values  map[string]string
	getErr  error
	gets    int
	sets    int
	expires int
}

func newFakeRedis() *fakeRedis { return &fakeRedis{values: map[string]string{}} }

func (f *fakeRedis) Get(ctx context.Context, key string) *goredis.StringCmd {
	f.gets++
	cmd := goredis.NewStringCmd(ctx)
	if f.getErr != nil {
		cmd.SetErr(f.getErr)
		return cmd
	}
	v, ok := f.values[key]
	if !ok {
		cmd.SetErr(goredis.Nil)
		return cmd
	}
	cmd.SetVal(v)
	return cmd
}

func (f *fakeRedis) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *goredis.StatusCmd {
	f.sets++
	f.values[key] = value.(string)
	return goredis.NewStatusCmd(ctx)
}

func (f *fakeRedis) Expire(ctx context.Context, key string, expiration time.Duration) *goredis.BoolCmd {
	f.expires++
	return goredis.NewBoolCmd(ctx)
}

func (f *fakeRedis) ReloadState(ctx context.Context) {}
