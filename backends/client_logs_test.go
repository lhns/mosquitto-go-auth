package backends

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	goredis "github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/logging"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const clientLogToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjbGllbnQtbG9nLXRva2VuIn0.Y2xpZW50LWxvZy1zaWduYXR1cmU"

// redisLogCapture is a go-redis logger that keeps what the library logs.
type redisLogCapture struct {
	mu    sync.Mutex
	lines []string
}

func (c *redisLogCapture) Printf(_ context.Context, format string, v ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, v...))
}

func (c *redisLogCapture) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, "\n")
}

// failDialQuoting makes go-redis log a dial error that quotes the token.
func failDialQuoting(token string) {
	client := goredis.NewClient(&goredis.Options{
		Addr:          "127.0.0.1:1",
		DialerRetries: 1,
		MaxRetries:    -1,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial " + token + ": refused")
		},
		DialTimeout: time.Second,
	})
	defer client.Close()
	_ = client.Get(context.Background(), token).Err()
}

// The go-redis library logs its own errors before our hiding runs. With a jwt backend those logs
// are off, without one they stay.
func TestClientLogs_RedisLibraryLogs(t *testing.T) {
	t.Cleanup(logging.Enable)

	for _, withJWT := range []bool{false, true} {
		t.Run(fmt.Sprintf("jwt=%t", withJWT), func(t *testing.T) {
			capture := &redisLogCapture{}
			goredis.SetLogger(capture)

			filesDispatcher(t, withJWT)
			failDialQuoting(clientLogToken)

			if withJWT {
				require.NotContains(t, capture.text(), clientLogToken[:16])
			} else {
				require.Contains(t, capture.text(), clientLogToken, "the trigger no longer reaches the log")
			}
		})
	}
}

// The Mongo driver logs commands, with the filter that holds the username, when MONGODB_LOG_*
// is set in the environment. With a jwt backend nothing of it may reach the log.
func TestClientLogs_MongoDriverLogs(t *testing.T) {
	for _, withJWT := range []bool{false, true} {
		t.Run(fmt.Sprintf("jwt=%t", withJWT), func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "mongo.log")
			t.Setenv("MONGODB_LOG_ALL", "debug")
			t.Setenv("MONGODB_LOG_PATH", logPath)

			authOpts := map[string]string{"backends": "mongo", "mongo_host": "localhost", "mongo_port": "27017", "mongo_dbname": "mosquitto_test"}
			if withJWT {
				authOpts["backends"] = "mongo,jwt"
			}
			m, err := NewMongo(authOpts, log.ErrorLevel, hashing.NewHasher(authOpts, "mongo"))
			require.NoError(t, err)
			_, _ = m.GetUser(clientLogToken, "pw", "cid")

			// With the log off the driver never opens the file.
			data, err := os.ReadFile(logPath)
			if !(withJWT && os.IsNotExist(err)) {
				require.NoError(t, err)
			}
			if withJWT {
				require.NotContains(t, string(data), clientLogToken[:16])
			} else {
				require.Contains(t, string(data), clientLogToken, "the trigger no longer reaches the log")
			}
		})
	}
}
