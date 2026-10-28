package backends

import (
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// tlsProbe accepts one TLS connection, sends the handshake result and closes the connection.
// It is not an LDAP server, so the bind after the handshake fails.
type tlsProbe struct {
	addr   string
	result chan error
}

// startTLSProbe starts a probe with the certificate of httptest (valid for 127.0.0.1, not for
// localhost) and returns the probe and a PEM file with that certificate.
func startTLSProbe(t *testing.T) (*tlsProbe, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	cert := srv.TLS.Certificates[0]
	srv.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	p := &tlsProbe{addr: ln.Addr().String(), result: make(chan error, 1)}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		p.result <- c.(*tls.Conn).Handshake()
		c.Close()
	}()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600))
	return p, caFile
}

func ldapCAOpts(url, caFile string) map[string]string {
	o := map[string]string{
		"ldap_url": url, "ldap_user_dn": "ou=u,dc=x", "ldap_bind_dn": "cn=a,dc=x",
		"ldap_bind_password": "p", "ldap_user_filter": "(uid=%s)",
	}
	if caFile != "" {
		o["ldap_ca_cert"] = caFile
	}
	return o
}

// handshakeOK dials the probe through NewLDAP and returns true if the TLS handshake succeeded.
func handshakeOK(t *testing.T, p *tlsProbe, host, caFile string) bool {
	t.Helper()
	_, port, _ := net.SplitHostPort(p.addr)
	_, err := NewLDAP(ldapCAOpts("ldaps://"+net.JoinHostPort(host, port), caFile), log.InfoLevel)
	require.Error(t, err) // the probe is not an LDAP server
	select {
	case hs := <-p.result:
		return hs == nil
	case <-time.After(5 * time.Second):
		t.Fatal("no connection reached the probe")
		return false
	}
}

func TestLDAPCACert(t *testing.T) {
	t.Run("without the option the private CA is not trusted", func(t *testing.T) {
		p, _ := startTLSProbe(t)
		require.False(t, handshakeOK(t, p, "127.0.0.1", ""))
	})
	t.Run("with the option the private CA is trusted", func(t *testing.T) {
		p, ca := startTLSProbe(t)
		require.True(t, handshakeOK(t, p, "127.0.0.1", ca))
	})
	t.Run("the server name is still checked", func(t *testing.T) {
		p, ca := startTLSProbe(t)
		require.False(t, handshakeOK(t, p, "localhost", ca))
	})
}

func TestLDAPCACertOptionErrors(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	require.NoError(t, os.WriteFile(junk, []byte("not a certificate"), 0o600))
	for name, path := range map[string]string{"missing": filepath.Join(dir, "missing.pem"), "no PEM": junk} {
		t.Run(name, func(t *testing.T) {
			_, err := NewLDAPWithFactory(ldapCAOpts("ldaps://localhost:636", path), log.InfoLevel, nil)
			require.ErrorContains(t, err, "ldap_ca_cert")
		})
	}
}

// With an ldap:// URL the option has no effect and the file is not read.
func TestLDAPCACertPlainLDAP(t *testing.T) {
	_, err := NewLDAPWithFactory(ldapCAOpts("ldap://localhost:389", "/nonexistent.pem"), log.InfoLevel,
		func(LDAP) (LDAPClient, error) { return nil, os.ErrNotExist })
	require.ErrorIs(t, err, os.ErrNotExist) // the factory was called: the CA file was not read
}
