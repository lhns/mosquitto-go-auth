package backends

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
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

// handshakeResult starts a Mongo backend against a TLS listener with a self-signed certificate
// and returns the server-side handshake error (nil when the client accepted the certificate).
func handshakeResult(t *testing.T, opts map[string]string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	host, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)
	opts["mongo_host"] = host
	opts["mongo_port"] = port
	opts["mongo_with_tls"] = "true"

	m, err := NewMongo(opts, log.ErrorLevel, hashing.NewHasher(opts, "mongo"))
	require.NoError(t, err)
	defer m.Halt()

	require.NoError(t, l.(*net.TCPListener).SetDeadline(time.Now().Add(10*time.Second)))
	conn, err := l.Accept()
	require.NoError(t, err)
	defer conn.Close()

	srv := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	require.NoError(t, srv.SetDeadline(time.Now().Add(10*time.Second)))
	if err := srv.Handshake(); err != nil {
		return err
	}
	// TLS 1.3: a client that rejects the certificate reports it after the server's handshake completes.
	_, err = srv.Read(make([]byte, 1))
	return err
}

func TestMongoTLSVerification(t *testing.T) {
	t.Run("verify by default", func(t *testing.T) {
		// The server sees the client's certificate alert; a timeout or a disconnect would not match.
		err := handshakeResult(t, map[string]string{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "bad certificate")
	})
	t.Run("insecure skip verify", func(t *testing.T) {
		require.NoError(t, handshakeResult(t, map[string]string{"mongo_insecure_skip_verify": "true"}))
	})
}

func TestMongoInsecureSkipVerifyWithoutTLSWarns(t *testing.T) {
	warned := func(opts map[string]string) bool {
		hook := logtest.NewGlobal()
		defer hook.Reset()
		opts["mongo_host"], opts["mongo_port"] = "127.0.0.1", "1"
		m, err := NewMongo(opts, log.WarnLevel, hashing.NewHasher(opts, "mongo"))
		require.NoError(t, err)
		m.Halt()
		for _, e := range hook.AllEntries() {
			if strings.Contains(e.Message, "mongo_insecure_skip_verify is ignored") {
				return true
			}
		}
		return false
	}

	require.True(t, warned(map[string]string{"mongo_insecure_skip_verify": "true"}))
	require.False(t, warned(map[string]string{"mongo_insecure_skip_verify": "true", "mongo_with_tls": "true"}))
	require.False(t, warned(map[string]string{}))
}
