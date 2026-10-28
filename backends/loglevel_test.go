package backends

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// The grpc and plugin constructors apply the plugin log level, like the other backends.
func TestGRPCAndPluginConstructorsSetLogLevel(t *testing.T) {
	old := log.GetLevel()
	t.Cleanup(func() { log.SetLevel(old) })

	log.SetLevel(log.PanicLevel)
	_, err := NewGRPC(nil, log.DebugLevel)
	require.ErrorContains(t, err, "host and port")
	require.Equal(t, log.DebugLevel, log.GetLevel())

	log.SetLevel(log.PanicLevel)
	_, err = NewCustomPlugin(map[string]string{"plugin_path": "/nonexistent.so"}, log.WarnLevel)
	require.Error(t, err)
	require.Equal(t, log.WarnLevel, log.GetLevel())
}
