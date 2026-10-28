package backends

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gs "github.com/iegomez/mosquitto-go-auth/grpc"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const remoteToken = "SENTINEL-TOKEN-remote"

// With a jwt backend the backends option holds "jwt": then remote error text is hidden.
var redactionBackendLists = map[string]bool{"jwt,other": true, "other": false}

// requireErrorText checks that the token is in the error and the logs only when it is not hidden.
func requireErrorText(t *testing.T, hidden bool, err error, entries string) {
	t.Helper()
	require.Error(t, err)
	if hidden {
		require.NotContains(t, err.Error(), remoteToken)
		require.NotContains(t, entries, remoteToken)
	} else {
		require.Contains(t, err.Error(), remoteToken, "without a jwt backend the error text stays")
	}
}

func logText(t *testing.T, check func()) string {
	t.Helper()
	hook := captureDebugLogs(t)
	check()
	var b strings.Builder
	for _, e := range hook.AllEntries() {
		b.WriteString(e.Message)
		for k, v := range e.Data {
			b.WriteString(" " + k + "=")
			if s, ok := v.(interface{ Error() string }); ok {
				b.WriteString(s.Error())
			} else if s, ok := v.(string); ok {
				b.WriteString(s)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// echoAuthService fails every call with a status message that echoes the username.
type echoAuthService struct{ *AuthServiceAPI }

func (echoAuthService) GetUser(_ context.Context, req *gs.GetUserRequest) (*gs.AuthResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "unknown user "+req.Username)
}

func (echoAuthService) CheckAcl(_ context.Context, req *gs.CheckAclRequest) (*gs.AuthResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "no acl for "+req.Username)
}

func TestGRPCErrorsHideTokenWithJWT(t *testing.T) {
	srv := grpc.NewServer()
	gs.RegisterAuthServiceServer(srv, echoAuthService{NewAuthServiceAPI()})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	host, port, err := net.SplitHostPort(lis.Addr().String())
	require.NoError(t, err)

	for list, hidden := range redactionBackendLists {
		t.Run(list, func(t *testing.T) {
			g, err := NewGRPC(map[string]string{"backends": list, "grpc_host": host, "grpc_port": port}, log.GetLevel())
			require.NoError(t, err)
			t.Cleanup(func() { _ = g.conn.Close() })

			var userErr, aclErr error
			entries := logText(t, func() {
				_, userErr = g.GetUser(remoteToken, "pw", "cid")
				_, aclErr = g.CheckAcl(remoteToken, "t", "cid", 1)
			})
			requireErrorText(t, hidden, userErr, entries)
			requireErrorText(t, hidden, aclErr, entries)
			if hidden {
				require.Equal(t, "grpc: call failed: PermissionDenied", userErr.Error())
			}
		})
	}
}

func TestJavascriptErrorsHideTokenWithJWT(t *testing.T) {
	script := filepath.Join(t.TempDir(), "script.js")
	require.NoError(t, os.WriteFile(script, []byte("throw new Error('unknown user ' + username);"), 0o600))

	for list, hidden := range redactionBackendLists {
		t.Run(list, func(t *testing.T) {
			b, err := NewJavascript(map[string]string{
				"backends":                 list,
				"js_user_script_path":      script,
				"js_superuser_script_path": script,
				"js_acl_script_path":       script,
			}, log.GetLevel())
			require.NoError(t, err)

			var userErr, aclErr error
			entries := logText(t, func() {
				_, userErr = b.GetUser(remoteToken, "pw", "cid")
				_, aclErr = b.CheckAcl(remoteToken, "t", "cid", 1)
			})
			requireErrorText(t, hidden, userErr, entries)
			requireErrorText(t, hidden, aclErr, entries)
			if hidden {
				require.Equal(t, "js: script error", userErr.Error())
			}
		})
	}
}

func TestHTTPReadErrorsHideTokenWithJWT(t *testing.T) {
	for list, hidden := range redactionBackendLists {
		t.Run(list, func(t *testing.T) {
			b, err := NewHTTP(map[string]string{
				"backends":           list,
				"http_host":          "example.invalid",
				"http_port":          "",
				"http_getuser_uri":   "/user",
				"http_superuser_uri": "/superuser",
				"http_aclcheck_uri":  "/acl",
			}, log.GetLevel(), "test")
			require.NoError(t, err)
			b.Client.Transport = bodyErrorTransport{token: remoteToken}

			var userErr error
			entries := logText(t, func() {
				_, userErr = b.GetUser(remoteToken, "pw", "cid")
			})
			requireErrorText(t, hidden, userErr, entries)
			if hidden {
				require.Equal(t, "http: response could not be read", userErr.Error())
			}
		})
	}
}

func TestHTTPRequestErrorsHideTokenWithJWT(t *testing.T) {
	for list, hidden := range redactionBackendLists {
		t.Run(list, func(t *testing.T) {
			b, err := NewHTTP(map[string]string{
				"backends":           list,
				"http_host":          "example.invalid",
				"http_port":          "",
				"http_getuser_uri":   "/user",
				"http_superuser_uri": "/superuser",
				"http_aclcheck_uri":  "/acl",
			}, log.GetLevel(), "test")
			require.NoError(t, err)
			b.Client.Transport = failingTransport{token: remoteToken}

			var userErr error
			entries := logText(t, func() {
				_, userErr = b.GetUser(remoteToken, "pw", "cid")
			})
			requireErrorText(t, hidden, userErr, entries)
			if hidden {
				require.Equal(t, "http: request failed", userErr.Error())
			}
		})
	}
}
