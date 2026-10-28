package backends

import (
	"net"
	"testing"
	"time"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// firstByte starts a Mongo backend against a local listener and returns the first byte the client sends.
func firstByte(t *testing.T, opts map[string]string) byte {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	host, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)
	opts["mongo_host"] = host
	opts["mongo_port"] = port

	m, err := NewMongo(opts, log.ErrorLevel, hashing.NewHasher(opts, "mongo"))
	require.NoError(t, err)
	defer m.Halt()

	require.NoError(t, l.(*net.TCPListener).SetDeadline(time.Now().Add(10*time.Second)))
	conn, err := l.Accept()
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	b := make([]byte, 1)
	_, err = conn.Read(b)
	require.NoError(t, err)
	return b[0]
}

func TestMongoTLSOptions(t *testing.T) {
	const tlsHandshake = 0x16 // first byte of a TLS handshake record

	for _, name := range []string{"mongo_with_tls", "mongo_use_tls"} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, byte(tlsHandshake), firstByte(t, map[string]string{name: "true"}))
		})
	}

	t.Run("no tls", func(t *testing.T) {
		require.NotEqual(t, byte(tlsHandshake), firstByte(t, map[string]string{}))
	})
}
