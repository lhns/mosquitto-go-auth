package backends

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/http"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jwtGo "github.com/golang-jwt/jwt/v5"
	gs "github.com/iegomez/mosquitto-go-auth/grpc"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/jmoiron/sqlx"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	sentinelPW    = "SENTINEL-PW-1234"
	sentinelUser  = "SENTINEL-JWT-user"
	sentinelToken = "SENTINEL-TOKEN-remote"
)

// captureDebugLogs records every log entry at debug level until the test ends.
func captureDebugLogs(t *testing.T) *logtest.Hook {
	t.Helper()
	oldLevel := log.GetLevel()
	oldHooks := log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
	t.Cleanup(func() {
		log.SetLevel(oldLevel)
		log.StandardLogger().ReplaceHooks(oldHooks)
	})
	hook := logtest.NewGlobal()
	log.SetLevel(log.DebugLevel)
	return hook
}

func logsContain(hook *logtest.Hook, text string) bool {
	for _, e := range hook.AllEntries() {
		if strings.Contains(fmt.Sprintf("%s %v", e.Message, e.Data), text) {
			return true
		}
	}
	return false
}

// filesDispatcher gives a dispatcher with the files backend, plus the jwt backend when withJWT is set.
func filesDispatcher(t *testing.T, withJWT bool) *Backends {
	t.Helper()
	opts := map[string]string{"backends": "files", "files_register": "user,acl"}
	hash, err := hashing.NewHasher(opts, "files").Hash(sentinelPW)
	require.NoError(t, err)
	dir := t.TempDir()
	pwPath := filepath.Join(dir, "passwords")
	require.NoError(t, os.WriteFile(pwPath, []byte(sentinelUser+":"+hash+"\n"), 0o600))
	aclPath := filepath.Join(dir, "acls")
	require.NoError(t, os.WriteFile(aclPath, []byte("user "+sentinelUser+"\ntopic readwrite test/topic\n"), 0o600))
	opts["files_password_path"] = pwPath
	opts["files_acl_path"] = aclPath
	if withJWT {
		jwtACLPath, err := filepath.Abs("../test-files/acls")
		require.NoError(t, err)
		opts["backends"] = "files,jwt"
		opts["jwt_mode"] = "files"
		opts["jwt_acl_path"] = jwtACLPath
		opts["jwt_secret"] = "secret"
		opts["jwt_register"] = "user"
	}
	b, err := Initialize(opts, log.GetLevel(), "test")
	require.NoError(t, err)
	t.Cleanup(b.Halt)
	return b
}

// With a JWT backend the username can be a token: the dispatcher and the files backend do not log it.
// Without one the username stays in the logs.
func TestRedaction_DispatcherAndFilesLogs(t *testing.T) {
	for _, withJWT := range []bool{true, false} {
		t.Run(fmt.Sprintf("jwt=%t", withJWT), func(t *testing.T) {
			b := filesDispatcher(t, withJWT)
			hook := captureDebugLogs(t)
			ctx := context.Background()

			ok, err := b.AuthUnpwdCheck(ctx, sentinelUser, sentinelPW, "cid")
			require.NoError(t, err)
			require.True(t, ok)
			if !withJWT {
				// The files warning for a wrong password names the user. A token is never a files
				// user, so only a configured name reaches it.
				ok, err = b.AuthUnpwdCheck(ctx, sentinelUser, "wrong-"+sentinelPW, "cid")
				require.NoError(t, err)
				require.False(t, ok)
			}
			ok, err = b.AuthAclCheck(ctx, "cid", sentinelUser, "test/topic", 1)
			require.NoError(t, err)
			require.True(t, ok)

			require.NotEmpty(t, hook.AllEntries())
			require.Equal(t, !withJWT, logsContain(hook, sentinelUser))
			require.False(t, logsContain(hook, sentinelPW))
		})
	}
}

func remoteJWTForRedaction(t *testing.T, extra map[string]string) *JWT {
	t.Helper()
	opts := map[string]string{
		"jwt_mode": "remote", "jwt_secret": "secret", "jwt_userfield": "Username",
		"jwt_getuser_uri": "/user", "jwt_aclcheck_uri": "/acl", "jwt_port": "",
		"jwt_response_mode": "text", "jwt_params_mode": "form",
	}
	for k, v := range extra {
		opts[k] = v
	}
	// log.GetLevel() keeps the global level: the constructor sets it.
	b, err := NewJWT(opts, log.GetLevel(), hashing.NewHasher(opts, "jwt"), "test")
	require.NoError(t, err)
	return b
}

// The remote JWT backend logs neither the token of an approved check nor the token echoed in a denial,
// but it keeps the rest of the denial text.
func TestRedaction_RemoteJWTLogs(t *testing.T) {
	reply := "ok"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	b := remoteJWTForRedaction(t, map[string]string{"jwt_host": strings.TrimPrefix(srv.URL, "http://")})
	hook := captureDebugLogs(t)

	ok, err := b.GetUser(sentinelToken, "", "cid")
	require.NoError(t, err)
	require.True(t, ok)

	reply = "unknown user " + sentinelToken
	ok, err = b.GetUser(sentinelToken, "", "cid")
	require.NoError(t, err)
	require.False(t, ok)

	require.False(t, logsContain(hook, sentinelToken))
	require.True(t, logsContain(hook, "api error: unknown user <hidden>"))
}

// When no host can be found from the token, the error does not contain the token.
func TestRedaction_RemoteJWTHostError(t *testing.T) {
	// Valid, but iss is not a string, so no host can be found.
	token, err := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, jwtGo.MapClaims{
		"Username": "user", "iss": 123, "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("secret"))
	require.NoError(t, err)
	b := remoteJWTForRedaction(t, map[string]string{"jwt_parse_token": "true", "jwt_host_whitelist": "*"})
	hook := captureDebugLogs(t)

	ok, err := b.GetUser(token, "", "cid")
	require.False(t, ok)
	require.Error(t, err)
	require.NotContains(t, err.Error(), token)
	require.False(t, logsContain(hook, token))
}

// echoDriver is a database driver whose every query fails with an error that quotes the arguments,
// as a driver does for a value it cannot convert (for example a token in a uuid column).
type echoDriver struct{}

type echoConn struct{}

type echoStmt struct{}

func (echoDriver) Open(string) (driver.Conn, error) { return echoConn{}, nil }

func (echoConn) Prepare(string) (driver.Stmt, error) { return echoStmt{}, nil }
func (echoConn) Close() error                        { return nil }
func (echoConn) Begin() (driver.Tx, error)           { return nil, errors.New("no transactions") }

func (echoStmt) Close() error  { return nil }
func (echoStmt) NumInput() int { return -1 }
func (echoStmt) Exec(args []driver.Value) (driver.Result, error) {
	return nil, fmt.Errorf("invalid input syntax: %v", args)
}
func (echoStmt) Query(args []driver.Value) (driver.Rows, error) {
	return nil, fmt.Errorf("invalid input syntax: %v", args)
}

func init() { sql.Register("echo-redaction", echoDriver{}) }

// With a JWT backend the SQL error text has the username replaced, otherwise it is unchanged.
func TestRedaction_SQLErrorEcho(t *testing.T) {
	db, err := sqlx.Open("echo-redaction", "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	for _, hide := range []bool{true, false} {
		t.Run(fmt.Sprintf("hide=%t", hide), func(t *testing.T) {
			pg := Postgres{DB: db, UserQuery: "q", SuperuserQuery: "q", AclQuery: "q", hideToken: hide}
			hook := captureDebugLogs(t)

			_, userErr := pg.GetUser(sentinelToken, "pw", "cid")
			_, superErr := pg.GetSuperuser(sentinelToken)
			_, aclErr := pg.CheckAcl(sentinelToken, "t", "cid", 1)

			for _, err := range []error{userErr, superErr, aclErr} {
				require.Error(t, err)
				require.Contains(t, err.Error(), "invalid input syntax")
				require.Equal(t, !hide, strings.Contains(err.Error(), sentinelToken))
			}
			require.Equal(t, !hide, logsContain(hook, sentinelToken))
		})
	}
}

// A driver may cut the error text: a part of a long username is then hidden by replacing the text.
func TestRedaction_HideTokenTruncated(t *testing.T) {
	token := strings.Repeat("abcdefgh", 8)

	// Whole token: replaced, the rest stays.
	err := hideToken(true, errors.New("bad value "+token+" here"), token)
	require.EqualError(t, err, "bad value <hidden> here")

	// Cut-off token: the whole text goes.
	err = hideToken(true, errors.New("bad value "+token[:40]), token)
	require.EqualError(t, err, hiddenErrorText)
	require.NotContains(t, err.Error(), token[:16])

	// Short username, only a prefix: the text is kept.
	err = hideToken(true, errors.New("bad value abcdefgh"), "abcdefghijklmnopqrstuvwxyz")
	require.EqualError(t, err, "bad value abcdefgh")

	// Whole token and a cut-off copy (a message that quotes the value twice): the whole text goes.
	err = hideToken(true, errors.New("bad value "+token+" near "+token[:40]), token)
	require.EqualError(t, err, hiddenErrorText)

	// Without a jwt backend nothing changes.
	err = hideToken(false, errors.New("bad value "+token[:40]), token)
	require.EqualError(t, err, "bad value "+token[:40])
}

// The reply of an http auth server that echoes the username is logged without it.
func TestRedaction_HTTPAPIErrorLog(t *testing.T) {
	replies := map[string]string{
		"text": "unknown user " + sentinelToken,
		"json": `{"ok":false,"error":"unknown user ` + sentinelToken + `"}`,
	}
	for mode, reply := range replies {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(reply))
		}))
		t.Cleanup(srv.Close)

		for _, hide := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/hide=%t", mode, hide), func(t *testing.T) {
				o := httpForRedaction(t, srv.URL, hide)
				o.ResponseMode = mode
				hook := captureDebugLogs(t)
				ok, err := o.GetUser(sentinelToken, "pw", "cid")
				require.NoError(t, err)
				require.False(t, ok)
				require.Equal(t, !hide, logsContain(hook, sentinelToken))
			})
		}
	}
}

func httpForRedaction(t *testing.T, srvURL string, hide bool) HTTP {
	t.Helper()
	hostPort := strings.TrimPrefix(srvURL, "http://")
	i := strings.LastIndex(hostPort, ":")
	return HTTP{
		Host: hostPort[:i], Port: hostPort[i+1:], ParamsMode: "json", httpMethod: http.MethodPost,
		ResponseMode: "status", Client: &http.Client{Timeout: 2 * time.Second}, hideToken: hide,
	}
}

// The approval log of the http backend shows the username only without a jwt backend.
func TestRedaction_HTTPApprovalLog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	for _, hide := range []bool{true, false} {
		t.Run(fmt.Sprintf("hide=%t", hide), func(t *testing.T) {
			o := httpForRedaction(t, srv.URL, hide)
			hook := captureDebugLogs(t)
			ok, err := o.GetUser(sentinelToken, "pw", "cid")
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, !hide, logsContain(hook, sentinelToken))
		})
	}
}

// A request error of the http backend that quotes the URL does not contain the username.
func TestRedaction_HTTPRequestError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // nothing listens any more

	for _, hide := range []bool{true, false} {
		t.Run(fmt.Sprintf("hide=%t", hide), func(t *testing.T) {
			o := httpForRedaction(t, srv.URL, hide)
			hook := captureDebugLogs(t)
			_, err := o.httpRequest("/user?u="+sentinelToken, sentinelToken, map[string]interface{}{}, nil)
			require.Error(t, err)
			require.Equal(t, !hide, strings.Contains(err.Error(), sentinelToken))
			require.Equal(t, !hide, logsContain(hook, sentinelToken))
		})
	}
}

// The remote JWT backend does not leak the token through a request error, even when the URL holds it.
func TestRedaction_RemoteJWTRequestError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	host := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()
	b := remoteJWTForRedaction(t, map[string]string{"jwt_host": host, "jwt_getuser_uri": "/user?t=" + sentinelToken})
	hook := captureDebugLogs(t)

	ok, err := b.GetUser(sentinelToken, "", "cid")
	require.False(t, ok)
	require.Error(t, err)
	require.NotContains(t, err.Error(), sentinelToken)
	require.False(t, logsContain(hook, sentinelToken))
}

// longToken is a token-like username that is long enough for the cut-off prefix rule.
const longToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJleHAiOjQxMDI0NDQ4MDB9.c2lnbmF0dXJlLXNlbnRpbmVs"

// requireNoTokenLeak checks that no log entry (message or field) and no error holds the token or
// its first 16 or 32 characters.
func requireNoTokenLeak(t *testing.T, hook *logtest.Hook, token string, errs ...error) {
	t.Helper()
	for _, part := range []string{token, token[:32], token[:16]} {
		require.False(t, logsContain(hook, part), "log holds %q", part)
		for _, err := range errs {
			require.Error(t, err)
			require.NotContains(t, err.Error(), part)
		}
	}
}

// echoAuthServer is a gRPC auth server whose errors echo the username, as a backend that
// rejects an unknown user often does.
type echoAuthServer struct {
	gs.UnimplementedAuthServiceServer
}

func (echoAuthServer) GetUser(_ context.Context, req *gs.GetUserRequest) (*gs.AuthResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "unknown user "+req.Username)
}

func (echoAuthServer) GetSuperuser(_ context.Context, req *gs.GetSuperuserRequest) (*gs.AuthResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "unknown user "+req.Username)
}

func (echoAuthServer) CheckAcl(_ context.Context, req *gs.CheckAclRequest) (*gs.AuthResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "unknown user "+req.Username)
}

// With a JWT backend the gRPC error text and the interceptor log do not echo the token. Without
// one they do, which shows that the server really echoes it.
func TestRedaction_GRPCErrorEcho(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	gs.RegisterAuthServiceServer(srv, &echoAuthServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	host, port, err := net.SplitHostPort(lis.Addr().String())
	require.NoError(t, err)

	for _, hide := range []bool{true, false} {
		t.Run(fmt.Sprintf("hide=%t", hide), func(t *testing.T) {
			hook := captureDebugLogs(t)
			g, err := NewGRPC(map[string]string{"grpc_host": host, "grpc_port": port, "grpc_dial_timeout_ms": "1000"}, log.DebugLevel)
			require.NoError(t, err)
			// Initialize sets it after the constructor.
			g.hideToken = hide

			_, userErr := g.GetUser(longToken, "pw", "cid")
			_, superErr := g.GetSuperuser(longToken)
			_, aclErr := g.CheckAcl(longToken, "t", "cid", 1)

			for _, err := range []error{userErr, superErr, aclErr} {
				require.Error(t, err)
				require.Equal(t, !hide, strings.Contains(err.Error(), longToken))
			}
			if hide {
				requireNoTokenLeak(t, hook, longToken, userErr, superErr, aclErr)
				// The call log keeps the code.
				require.True(t, logsContain(hook, "PermissionDenied"))
			} else {
				require.True(t, logsContain(hook, longToken))
			}
		})
	}
}

func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// A script error that quotes the username (a null dereference names the key) does not leak the
// token with a JWT backend, in the js backend and in the js mode of the jwt backend.
func TestRedaction_JSErrorEcho(t *testing.T) {
	dir := t.TempDir()
	// "Cannot access member '<username>' of null" in otto.
	script := writeScript(t, dir, "script.js", "var rules = null; rules[username];")
	jwtScript := writeScript(t, dir, "jwt_script.js", "var rules = null; rules[token];")

	for _, hide := range []bool{true, false} {
		t.Run(fmt.Sprintf("js/hide=%t", hide), func(t *testing.T) {
			hook := captureDebugLogs(t)
			j, err := NewJavascript(map[string]string{
				"js_user_script_path": script, "js_superuser_script_path": script, "js_acl_script_path": script,
			}, log.DebugLevel)
			require.NoError(t, err)
			j.hideToken = hide

			_, userErr := j.GetUser(longToken, "pw", "cid")
			_, superErr := j.GetSuperuser(longToken)
			_, aclErr := j.CheckAcl(longToken, "t", "cid", 1)

			for _, err := range []error{userErr, superErr, aclErr} {
				require.Error(t, err)
				require.Equal(t, !hide, strings.Contains(err.Error(), longToken))
			}
			if hide {
				requireNoTokenLeak(t, hook, longToken, userErr, superErr, aclErr)
			} else {
				require.True(t, logsContain(hook, longToken))
			}
		})
	}

	t.Run("jwt js mode", func(t *testing.T) {
		hook := captureDebugLogs(t)
		checker, err := NewJsJWTChecker(map[string]string{
			"jwt_js_user_script_path": jwtScript, "jwt_js_superuser_script_path": jwtScript, "jwt_js_acl_script_path": jwtScript,
		}, tokenOptions{})
		require.NoError(t, err)

		_, userErr := checker.GetUser(longToken)
		_, superErr := checker.GetSuperuser(longToken)
		_, aclErr := checker.CheckAcl(longToken, "t", "cid", 1)

		requireNoTokenLeak(t, hook, longToken, userErr, superErr, aclErr)
	})
}

// A denial text of the remote JWT server that holds a cut-off token is hidden as a whole.
func TestRedaction_RemoteJWTCutOffReply(t *testing.T) {
	for mode, reply := range map[string]string{
		"text": "bad token " + longToken[:40],
		"json": `{"ok":false,"error":"bad token ` + longToken[:40] + `"}`,
	} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(reply))
			}))
			t.Cleanup(srv.Close)
			b := remoteJWTForRedaction(t, map[string]string{
				"jwt_host": strings.TrimPrefix(srv.URL, "http://"), "jwt_response_mode": mode,
			})
			hook := captureDebugLogs(t)

			ok, err := b.GetUser(longToken, "", "cid")
			require.NoError(t, err)
			require.False(t, ok)
			requireNoTokenLeak(t, hook, longToken)
			require.True(t, logsContain(hook, hiddenErrorText))
		})
	}
}
