package backends

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(p, b, 0o600))
	return p
}

// writeOtherCA writes a new self-signed CA certificate that did not sign the
// test server certificate. (httptest servers all share one certificate.)
func writeOtherCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "other test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "other.pem")
	require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return p
}

func hostPortOf(t *testing.T, srv *httptest.Server) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	return host, port
}

func countWarn(hook *logtest.Hook, sub string) int {
	n := 0
	for _, e := range hook.AllEntries() {
		if e.Level == log.WarnLevel && strings.Contains(e.Message, sub) {
			n++
		}
	}
	return n
}

func TestRemoteTLSOptions(t *testing.T) {
	// The warning checks need the warn level and a clean hook list, whatever
	// earlier tests set. Restore both at the end.
	oldLevel := log.GetLevel()
	oldHooks := log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
	log.SetLevel(log.WarnLevel)
	t.Cleanup(func() {
		log.SetLevel(oldLevel)
		log.StandardLogger().ReplaceHooks(oldHooks)
	})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	ca := writeCA(t, srv)
	wrongCA := writeOtherCA(t)
	badPEM := filepath.Join(t.TempDir(), "bad.pem")
	require.NoError(t, os.WriteFile(badPEM, []byte("not a certificate"), 0o600))
	host, port := hostPortOf(t, srv)

	for _, prefix := range []string{"http_", "jwt_"} {
		// build returns the check function of one backend with the TLS options kv.
		build := func(kv ...string) (func() (bool, error), error) {
			o := map[string]string{
				prefix + "host": host, prefix + "port": port, prefix + "with_tls": "true",
				prefix + "getuser_uri": "/u", prefix + "aclcheck_uri": "/a",
			}
			for i := 0; i < len(kv); i += 2 {
				o[prefix+kv[i]] = kv[i+1]
			}
			if prefix == "http_" {
				b, err := NewHTTP(o, log.GetLevel(), "test")
				return func() (bool, error) { return b.GetUser("u", "p", "c") }, err
			}
			c, err := NewRemoteJWTChecker(o, tkOptions, "test")
			return func() (bool, error) { return c.GetUser("a.b.c") }, err
		}

		t.Run(prefix+"verify with CA", func(t *testing.T) {
			call, err := build("verify_peer", "true", "ca_cert", ca)
			require.NoError(t, err)
			ok, err := call()
			assert.NoError(t, err)
			assert.True(t, ok)
		})
		t.Run(prefix+"verify without CA fails", func(t *testing.T) {
			call, err := build("verify_peer", "true")
			require.NoError(t, err)
			ok, err := call()
			assert.False(t, ok)
			assert.Error(t, err)
		})
		t.Run(prefix+"verify with wrong CA fails", func(t *testing.T) {
			call, err := build("verify_peer", "true", "ca_cert", wrongCA)
			require.NoError(t, err)
			ok, err := call()
			assert.False(t, ok)
			assert.Error(t, err)
		})
		t.Run(prefix+"verify with CA and host name mismatch fails", func(t *testing.T) {
			// The test certificate covers 127.0.0.1 and not localhost.
			call, err := build("verify_peer", "true", "ca_cert", ca, "host", "localhost")
			require.NoError(t, err)
			ok, err := call()
			assert.False(t, ok)
			assert.Error(t, err)
		})
		t.Run(prefix+"verify off with unrelated CA succeeds", func(t *testing.T) {
			call, err := build("ca_cert", wrongCA)
			require.NoError(t, err)
			ok, err := call()
			assert.NoError(t, err)
			assert.True(t, ok)
		})
		t.Run(prefix+"verify off warns once", func(t *testing.T) {
			hook := logtest.NewGlobal()
			call, err := build()
			require.NoError(t, err)
			ok, err := call()
			assert.NoError(t, err)
			assert.True(t, ok)
			assert.Equal(t, 1, countWarn(hook, prefix+"verify_peer is false"))
			assert.Equal(t, 0, countWarn(hook, "has no effect"))
		})
		t.Run(prefix+"CA with verify off warns, stays unverified", func(t *testing.T) {
			hook := logtest.NewGlobal()
			call, err := build("ca_cert", ca)
			require.NoError(t, err)
			ok, err := call()
			assert.NoError(t, err)
			assert.True(t, ok)
			assert.Equal(t, 1, countWarn(hook, prefix+"verify_peer is false"))
			assert.Equal(t, 1, countWarn(hook, prefix+"ca_cert has no effect"))
		})
		t.Run(prefix+"bad CA file", func(t *testing.T) {
			for _, p := range []string{filepath.Join(t.TempDir(), "missing.pem"), badPEM} {
				_, err := build("verify_peer", "true", "ca_cert", p)
				require.Error(t, err)
				assert.Contains(t, err.Error(), prefix+"ca_cert")
				assert.NotContains(t, err.Error(), "not a certificate")
			}
		})
	}
}
