package backends

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const (
	sentinelPW   = "SENTINEL-PW-1234"
	sentinelUser = "SENTINEL-JWT-user"
)

func jwtFilesDispatcher(t *testing.T) *Backends {
	t.Helper()
	opts := map[string]string{"backends": "files,jwt", "files_register": "user,acl"}
	hash, err := hashing.NewHasher(opts, "files").Hash(sentinelPW)
	require.NoError(t, err)
	pwPath := filepath.Join(t.TempDir(), "passwords")
	require.NoError(t, os.WriteFile(pwPath, []byte(sentinelUser+":"+hash+"\n"), 0o600))
	jwtACLPath, err := filepath.Abs("../test-files/acls")
	require.NoError(t, err)
	aclFile := filepath.Join(t.TempDir(), "acls")
	require.NoError(t, os.WriteFile(aclFile, []byte("user "+sentinelUser+"\ntopic readwrite test/topic\n"), 0o600))
	opts["files_password_path"] = pwPath
	opts["files_acl_path"] = aclFile
	opts["jwt_mode"] = "files"
	opts["jwt_acl_path"] = jwtACLPath
	opts["jwt_secret"] = "secret"
	opts["jwt_register"] = "user"
	b, err := Initialize(opts, log.GetLevel(), "test")
	require.NoError(t, err)
	t.Cleanup(b.Halt)
	return b
}

// With a JWT backend the user name can be a token: the dispatcher and the files backend do not log it.
func TestRedaction_DispatcherAndFilesLogs(t *testing.T) {
	b := jwtFilesDispatcher(t)
	hook := captureDebugLogs(t)
	ctx := context.Background()

	ok, err := b.AuthUnpwdCheck(ctx, sentinelUser, sentinelPW, "cid")
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = b.AuthUnpwdCheck(ctx, sentinelUser, "wrong-"+sentinelPW, "cid")
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = b.AuthAclCheck(ctx, "cid", sentinelUser, "test/topic", 1)
	require.NoError(t, err)
	require.True(t, ok)

	require.NotEmpty(t, hook.AllEntries())
	requireNoTokenInLogs(t, hook, sentinelUser)
	requireNoTokenInLogs(t, hook, sentinelPW)
}

// A remote JWT check that is denied does not log the response body.
func TestRedaction_RemoteJWTResponseBody(t *testing.T) {
	const body = "SENTINEL-BODY-5678"
	for _, mode := range []string{"text", "json"} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "json" {
					_, _ = w.Write([]byte(`{"ok":false,"error":"` + body + `"}`))
					return
				}
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(srv.Close)
			b := remoteJWTForRedaction(t, map[string]string{
				"jwt_host":          strings.TrimPrefix(srv.URL, "http://"),
				"jwt_response_mode": mode,
			})
			hook := captureDebugLogs(t)

			ok, err := b.GetUser("SENTINEL-TOKEN-denied", "", "cid")
			require.NoError(t, err)
			require.False(t, ok)
			require.NotEmpty(t, hook.AllEntries())
			requireNoTokenInLogs(t, hook, body)
			requireNoTokenInLogs(t, hook, "SENTINEL-TOKEN-denied")
		})
	}
}

// A denied HTTP check does not log the response body, which can echo the username (a token with
// a jwt backend).
func TestRedaction_HTTPResponseBody(t *testing.T) {
	const token = "SENTINEL-TOKEN-http"
	for _, mode := range []string{"text", "json"} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "json" {
					_, _ = w.Write([]byte(`{"ok":false,"error":"unknown user ` + token + `"}`))
					return
				}
				_, _ = w.Write([]byte("unknown user " + token))
			}))
			t.Cleanup(srv.Close)
			b, err := NewHTTP(map[string]string{
				"http_host":          strings.TrimPrefix(srv.URL, "http://"),
				"http_port":          "",
				"http_getuser_uri":   "/user",
				"http_superuser_uri": "/superuser",
				"http_aclcheck_uri":  "/acl",
				"http_params_mode":   "json",
				"http_response_mode": mode,
			}, log.GetLevel(), "test")
			require.NoError(t, err)
			hook := captureDebugLogs(t)

			ok, err := b.GetUser(token, "pw", "cid")
			require.NoError(t, err)
			require.False(t, ok)
			ok, err = b.CheckAcl(token, "t", "cid", 1)
			require.NoError(t, err)
			require.False(t, ok)
			require.NotEmpty(t, hook.AllEntries())
			requireNoTokenInLogs(t, hook, token)
		})
	}
}
