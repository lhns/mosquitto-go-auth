package backends

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jwtGo "github.com/golang-jwt/jwt/v5"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

// captureDebugLogs records every log entry at debug level until the test ends. The cleanup
// restores the previous level and hooks.
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

func requireNoTokenInLogs(t *testing.T, hook *logtest.Hook, token string) {
	t.Helper()
	for _, e := range hook.AllEntries() {
		require.NotContains(t, fmt.Sprintf("%s %v", e.Message, e.Data), token)
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

// A remote check that is approved does not log the token.
func TestJWTRemoteApprovalLogHasNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	b := remoteJWTForRedaction(t, map[string]string{"jwt_host": strings.TrimPrefix(srv.URL, "http://")})
	hook := captureDebugLogs(t)

	token := "SENTINEL-TOKEN-approved"
	ok, err := b.GetUser(token, "", "cid")
	require.NoError(t, err)
	require.True(t, ok)
	require.NotEmpty(t, hook.AllEntries())
	requireNoTokenInLogs(t, hook, token)
}

// When no host can be found from the token, the error does not contain the token.
func TestJWTRemoteHostErrorHasNoToken(t *testing.T) {
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
	requireNoTokenInLogs(t, hook, token)
}

// An error of the JWT library becomes a fixed text. The library text can echo a part of the token.
func TestJWTClaimErrorsHaveFixedText(t *testing.T) {
	hook := captureDebugLogs(t)
	opts := tokenOptions{secret: []byte("secret"), userFieldKey: "username"}

	// The payload is not JSON: the library error shows a character of it.
	bad := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.U0VOVElORUw.c2ln"
	_, err := getUsernameForToken(opts, bad, false)
	require.Error(t, err)
	require.Equal(t, "jwt: token is malformed", err.Error())
	require.ErrorIs(t, err, jwtGo.ErrTokenMalformed)

	expired, signErr := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, jwtGo.MapClaims{
		"username": "user", "exp": time.Now().Add(-time.Hour).Unix(),
	}).SignedString([]byte("secret"))
	require.NoError(t, signErr)
	_, err = getUsernameForToken(opts, expired, false)
	require.Equal(t, "jwt: token is expired", err.Error())
	require.ErrorIs(t, err, jwtGo.ErrTokenExpired)

	for _, e := range hook.AllEntries() {
		require.NotContains(t, e.Message, "invalid character")
	}
}

// failingTransport fails every request with an error that holds the URL and the token.
type failingTransport struct{ token string }

func (f failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, errors.New("redirect to https://example.invalid/?access_token=" + f.token)
}

// failingBody fails every read with an error that holds the token.
type failingBody struct{ token string }

func (f failingBody) Read([]byte) (int, error) {
	return 0, errors.New("malformed chunked encoding near " + f.token)
}

func (failingBody) Close() error { return nil }

// bodyErrorTransport answers with a body that cannot be read.
type bodyErrorTransport struct{ token string }

func (b bodyErrorTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: failingBody{token: b.token}, Header: http.Header{}, Request: r}, nil
}

// A response that cannot be read does not log or return the read error, which can hold the token.
func TestJWTRemoteReadErrorHasNoToken(t *testing.T) {
	const token = "SENTINEL-TOKEN-read"
	b := remoteJWTForRedaction(t, map[string]string{"jwt_host": "example.invalid"})
	b.checker.(*remoteJWTChecker).client.Transport = bodyErrorTransport{token: token}
	hook := captureDebugLogs(t)

	ok, err := b.GetUser(token, "", "cid")
	require.False(t, ok)
	require.Error(t, err)
	require.Equal(t, "jwt remote: response could not be read", err.Error())
	require.NotEmpty(t, hook.AllEntries())
	requireNoTokenInLogs(t, hook, token)
}

// A failed remote request does not log or return the error text, which can hold the token.
func TestJWTRemoteRequestErrorHasNoToken(t *testing.T) {
	const token = "SENTINEL-TOKEN-request"
	b := remoteJWTForRedaction(t, map[string]string{"jwt_host": "example.invalid"})
	b.checker.(*remoteJWTChecker).client.Transport = failingTransport{token: token}
	hook := captureDebugLogs(t)

	ok, err := b.GetUser(token, "", "cid")
	require.False(t, ok)
	require.Error(t, err)
	require.Equal(t, "jwt remote: request failed", err.Error())
	require.NotEmpty(t, hook.AllEntries())
	requireNoTokenInLogs(t, hook, token)
}

// A script error does not log or return the text of the exception, which can hold the token.
func TestJWTJavascriptErrorHasNoToken(t *testing.T) {
	const token = "SENTINEL-TOKEN-script"
	dir := t.TempDir()
	script := filepath.Join(dir, "script.js")
	require.NoError(t, os.WriteFile(script, []byte("throw new Error('bad token ' + token);"), 0o600))
	checker, err := NewJsJWTChecker(map[string]string{
		"jwt_js_user_script_path":      script,
		"jwt_js_superuser_script_path": script,
		"jwt_js_acl_script_path":       script,
	}, tokenOptions{})
	require.NoError(t, err)
	hook := captureDebugLogs(t)

	for _, check := range []func() (bool, error){
		func() (bool, error) { return checker.GetUser(token) },
		func() (bool, error) { return checker.GetSuperuser(token) },
		func() (bool, error) { return checker.CheckAcl(token, "t", "cid", 1) },
	} {
		ok, err := check()
		require.False(t, ok)
		require.Error(t, err)
		require.Equal(t, "js: script error", err.Error())
	}
	require.NotEmpty(t, hook.AllEntries())
	requireNoTokenInLogs(t, hook, token)
}

// The local JWT "user not found" message does not show the user name of the claims.
// This test needs the Postgres database of the test container.
func TestJWTLocalUserNotFoundHasNoUsername(t *testing.T) {
	const user = "SENTINEL-CLAIM-user"
	opts := map[string]string{
		"jwt_db":            "postgres",
		"jwt_userquery":     "select null::bigint where $1::text is not null",
		"jwt_pg_host":       "localhost",
		"jwt_pg_port":       "5432",
		"jwt_pg_sslmode":    "disable",
		"jwt_pg_dbname":     "go_auth_test",
		"jwt_pg_user":       "go_auth_test",
		"jwt_pg_password":   "go_auth_test",
		"jwt_pg_superquery": "select count(*) from test_user where username = $1 and is_admin = true",
		"jwt_pg_aclquery":   "select topic from test_acl where false and $1 = $1 and $2 = $2",
	}
	checker, err := NewLocalJWTChecker(opts, log.GetLevel(), hashing.NewHasher(opts, ""), tokenOptions{secret: []byte("secret"), userFieldKey: "username"})
	require.NoError(t, err)
	t.Cleanup(checker.Halt)
	token, err := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, jwtGo.MapClaims{
		"username": user, "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("secret"))
	require.NoError(t, err)
	hook := captureDebugLogs(t)

	ok, err := checker.GetUser(token)
	require.NoError(t, err)
	require.False(t, ok)
	require.NotEmpty(t, hook.AllEntries())
	requireNoTokenInLogs(t, hook, user)
}
