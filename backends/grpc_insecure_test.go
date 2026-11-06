package backends

import (
	"net"
	"strings"
	"testing"

	gs "github.com/iegomez/mosquitto-go-auth/grpc"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestGRPCInsecureOption(t *testing.T) {
	srv := grpc.NewServer()
	gs.RegisterAuthServiceServer(srv, NewAuthServiceAPI())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	_, port, _ := net.SplitHostPort(lis.Addr().String())

	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)
	opts := func(kv ...string) map[string]string {
		m := map[string]string{"grpc_host": "127.0.0.1", "grpc_port": port, "grpc_dial_timeout_ms": "300", "grpc_fail_on_dial_error": "true"}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	warned := func(sub string) bool {
		for _, e := range hook.AllEntries() {
			if e.Level == log.WarnLevel && strings.Contains(e.Message, sub) {
				return true
			}
		}
		return false
	}

	// Not set, no CA: plaintext as before, with a warning.
	hook.Reset()
	g, err := NewGRPC(opts(), log.InfoLevel)
	require.NoError(t, err)
	g.Halt()
	require.True(t, warned("no grpc_ca_cert"))

	// true: plaintext, with a warning.
	hook.Reset()
	g, err = NewGRPC(opts("grpc_insecure", "true"), log.InfoLevel)
	require.NoError(t, err)
	g.Halt()
	require.True(t, warned("grpc_insecure is true"))

	// false: TLS is required, so the dial to a plaintext server fails (system roots, no CA).
	hook.Reset()
	_, err = NewGRPC(opts("grpc_insecure", "false"), log.InfoLevel)
	require.Error(t, err)
	require.False(t, warned("insecure grpc client"))

	// true with a TLS option, or a value that is not true or false: an init error.
	for _, kv := range [][]string{
		{"grpc_insecure", "true", "grpc_ca_cert", "/nonexistent"},
		{"grpc_insecure", "true", "grpc_tls_cert", "/nonexistent"},
		{"grpc_insecure", "true", "grpc_tls_key", "/nonexistent"},
		{"grpc_insecure", "maybe"},
		{"grpc_insecure", ""},
	} {
		_, err = NewGRPC(opts(kv...), log.InfoLevel)
		require.ErrorContains(t, err, "grpc_insecure", kv)
	}
}
