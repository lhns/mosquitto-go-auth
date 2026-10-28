//go:build integration

package backends

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

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
			// NewMongo sets the global log level.
			oldLevel := log.GetLevel()
			t.Cleanup(func() { log.SetLevel(oldLevel) })
			m, err := NewMongo(authOpts, log.ErrorLevel, hashing.NewHasher(authOpts, "mongo"))
			require.NoError(t, err)
			// A user that does not exist gives (false, nil): an error means the command never ran,
			// and then the test would pass without showing anything.
			ok, err := m.GetUser(clientLogToken, "pw", "cid")
			require.NoError(t, err, "the Mongo server must be reachable for this test")
			require.False(t, ok)

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
