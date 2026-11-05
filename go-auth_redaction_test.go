package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	bes "github.com/iegomez/mosquitto-go-auth/backends"
	"github.com/iegomez/mosquitto-go-auth/cache"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

const (
	redactUser      = "SENTINEL-JWT-user"
	redactPW        = "SENTINEL-PW-1234"
	tokenAsClientID = "SENTINEL-TOKEN-AS-CLIENTID"
)

// redactionPlugin sets up a real dispatcher with the Go cache on. The files backend knows redactUser.
// The cleanup restores the previous plugin state.
func redactionPlugin(t *testing.T, backendList string) {
	t.Helper()
	saved := authPlugin
	t.Cleanup(func() { authPlugin = saved })
	// The backend constructors set the global log level: save it and the hooks first.
	oldLevel := log.GetLevel()
	oldHooks := make(log.LevelHooks)
	for level, hooks := range log.StandardLogger().Hooks {
		oldHooks[level] = append([]log.Hook(nil), hooks...)
	}
	t.Cleanup(func() {
		log.SetLevel(oldLevel)
		log.StandardLogger().ReplaceHooks(oldHooks)
	})
	opts := map[string]string{"backends": backendList, "files_register": "user,acl"}
	hash, err := hashing.NewHasher(opts, "files").Hash(redactPW)
	require.NoError(t, err)
	pwPath := filepath.Join(t.TempDir(), "passwords")
	require.NoError(t, os.WriteFile(pwPath, []byte(redactUser+":"+hash+"\n"), 0o600))
	jwtACLPath, err := filepath.Abs("test-files/acls")
	require.NoError(t, err)
	aclFile := filepath.Join(t.TempDir(), "acls")
	require.NoError(t, os.WriteFile(aclFile, []byte("user "+redactUser+"\ntopic readwrite test/topic\n"), 0o600))
	opts["files_password_path"] = pwPath
	opts["files_acl_path"] = aclFile
	opts["jwt_mode"] = "files"
	opts["jwt_acl_path"] = jwtACLPath
	opts["jwt_secret"] = "secret"
	opts["jwt_register"] = "user"
	b, err := bes.Initialize(opts, log.DebugLevel, "test")
	require.NoError(t, err)
	t.Cleanup(b.Halt)

	store := cache.NewGoStore(time.Minute, time.Minute, 0, 0, false)
	t.Cleanup(store.Close)
	require.True(t, store.Connect(context.Background(), false))
	authPlugin = AuthPlugin{backends: b, ctx: context.Background(), useCache: true, cache: store}
}

func runChecks(t *testing.T) {
	t.Helper()
	for i := 0; i < 2; i++ { // miss and set, then hit
		_, err := authUnpwdCheck(redactUser, redactPW, "cid")
		require.NoError(t, err)
		_, err = authAclCheck("cid", redactUser, "test/topic", 1)
		require.NoError(t, err)
	}
}

func recordSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	old := otel.GetTracerProvider()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	t.Cleanup(func() {
		otel.SetTracerProvider(old)
		_ = tp.Shutdown(context.Background())
	})
	otel.SetTracerProvider(tp)
	return sr
}

// With a JWT backend the user name can be a token: no log entry shows it.
func TestRedaction_RootLogsWithJWT(t *testing.T) {
	redactionPlugin(t, "files,jwt")
	oldLevel := log.GetLevel()
	oldHooks := log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
	t.Cleanup(func() {
		log.SetLevel(oldLevel)
		log.StandardLogger().ReplaceHooks(oldHooks)
	})
	hook := logtest.NewGlobal()
	log.SetLevel(log.DebugLevel)

	runChecks(t)

	require.NotEmpty(t, hook.AllEntries())
	for _, e := range hook.AllEntries() {
		text := fmt.Sprintf("%s %v", e.Message, e.Data)
		require.NotContains(t, text, redactUser)
		require.NotContains(t, text, redactPW)
	}
}

// With a JWT backend no span exports the user name.
func TestRedaction_SpansWithJWTHideUsername(t *testing.T) {
	redactionPlugin(t, "files,jwt")
	sr := recordSpans(t)
	runChecks(t)

	spans := sr.Ended()
	require.NotEmpty(t, spans)
	for _, s := range spans {
		require.NotContains(t, fmt.Sprint(s.Attributes(), s.Events()), redactUser, s.Name())
	}
}

// Without a JWT backend the spans keep the user name.
func TestRedaction_SpansWithoutJWTKeepUsername(t *testing.T) {
	redactionPlugin(t, "files")
	sr := recordSpans(t)
	runChecks(t)

	found := 0
	for _, s := range sr.Ended() {
		if s.Name() != "auth.unpwd_check" && s.Name() != "auth.acl_check" {
			continue
		}
		for _, kv := range s.Attributes() {
			if string(kv.Key) == "auth.username" {
				require.Equal(t, redactUser, kv.Value.AsString())
				found++
			}
		}
	}
	require.Equal(t, 4, found)
}

func spanText(t *testing.T, check func()) (text string, hasClientID bool) {
	t.Helper()
	sr := recordSpans(t)
	check()
	spans := sr.Ended()
	require.NotEmpty(t, spans)
	for _, s := range spans {
		text += fmt.Sprint(s.Name(), s.Attributes(), s.Events())
		for _, kv := range s.Attributes() {
			if string(kv.Key) == "auth.client_id" {
				hasClientID = true
			}
		}
	}
	return text, hasClientID
}

func runClientIDChecks() {
	_, _ = authUnpwdCheck("ignored", "pw", tokenAsClientID)
	_, _ = authAclCheck(tokenAsClientID, "ignored", "test/topic", 1)
}

// With a JWT backend and use_clientid_as_username the client ID carries the token: no span exports it.
func TestSpansHideClientIDWhenItIsTheJWT(t *testing.T) {
	redactionPlugin(t, "files,jwt")
	authPlugin.useClientidAsUsername = true
	text, has := spanText(t, runClientIDChecks)
	require.NotContains(t, text, tokenAsClientID)
	require.False(t, has, "auth.client_id is not exported")
}

// The client ID stays in spans when it is not the user name, or when no JWT backend exists.
func TestSpansKeepClientIDWhenItIsNotAToken(t *testing.T) {
	for _, tc := range []struct {
		backends string
		asUser   bool
	}{{"files,jwt", false}, {"files", true}, {"files", false}} {
		redactionPlugin(t, tc.backends)
		authPlugin.useClientidAsUsername = tc.asUser
		text, has := spanText(t, runClientIDChecks)
		require.True(t, has, "%+v", tc)
		require.Contains(t, text, tokenAsClientID, "%+v", tc)
	}
}
