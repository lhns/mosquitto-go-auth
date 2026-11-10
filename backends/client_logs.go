package backends

import (
	"strings"

	"github.com/redis/go-redis/v9/logging"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// The Redis and Mongo client libraries write their own logs, before our hiding runs, and an error
// or a command they log can quote the username, which is a token with a jwt backend. They cannot
// be given the token to hide, so with a jwt backend their logs are turned off.

// jwtInBackends tells if the backends option names the jwt backend.
func jwtInBackends(authOpts map[string]string) bool {
	for _, backend := range strings.Split(strings.ReplaceAll(authOpts["backends"], " ", ""), ",") {
		if backend == jwtBackend {
			return true
		}
	}
	return false
}

// quietRedisLibraryLogs turns off the go-redis library log when a jwt backend is configured. The
// library logger is global, so this also covers the Redis clients of the cache.
func quietRedisLibraryLogs(authOpts map[string]string) {
	if jwtInBackends(authOpts) {
		log.Debug("jwt backend configured: the go-redis library log is off")
		logging.Disable()
	}
}

// discardSink is a log sink of the Mongo driver that drops everything.
type discardSink struct{}

func (discardSink) Info(int, string, ...interface{})    {}
func (discardSink) Error(error, string, ...interface{}) {}

// mongoLoggerOptions gives the logger options of the Mongo client. The driver logs commands, with
// their filter, when a MONGODB_LOG_* variable is set. With a jwt backend that log goes nowhere.
func mongoLoggerOptions(authOpts map[string]string) *options.LoggerOptions {
	if !jwtInBackends(authOpts) {
		return nil
	}
	return options.Logger().SetSink(discardSink{})
}
