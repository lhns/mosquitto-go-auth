package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

type panickingBackends struct{ mockBackends }

func (panickingBackends) AuthUnpwdCheck(ctx context.Context, username, password, clientid string) (bool, error) {
	panic("backend bug")
}

func (panickingBackends) AuthAclCheck(ctx context.Context, clientid, username, topic string, acc int) (bool, error) {
	panic("backend bug")
}

// A panic in a check must deny the request instead of crossing the cgo boundary and stopping the broker.
// The exported callbacks take C strings, so this calls the check the way they do.
func TestPanicInCheckDenies(t *testing.T) {
	authPlugin = AuthPlugin{backends: &panickingBackends{}, ctx: context.Background()}

	result := func() (result uint8) {
		defer recoverCheck("auth", &result, "user", "client")
		if ok, err := authUnpwdCheck("user", "pass", "client"); ok && err == nil {
			return AuthGranted
		}
		return AuthRejected
	}()

	require.Equal(t, uint8(AuthError), result)
}

func TestPanicInAclCheckDenies(t *testing.T) {
	authPlugin = AuthPlugin{backends: &panickingBackends{}, ctx: context.Background()}

	result := func() (result uint8) {
		defer recoverCheck("acl", &result, "user", "client")
		if ok, err := authAclCheck("client", "user", "a/b", 1); ok && err == nil {
			return AuthGranted
		}
		return AuthRejected
	}()

	require.Equal(t, uint8(AuthError), result)
}

// tokenPanicBackends panics with a value that quotes the username, as a bug in a driver can.
type tokenPanicBackends struct {
	mockBackends
	hide bool
}

func (b *tokenPanicBackends) AuthUnpwdCheck(ctx context.Context, username, password, clientid string) (bool, error) {
	panic(fmt.Sprintf("cannot parse %q", username))
}

func (b *tokenPanicBackends) AuthAclCheck(ctx context.Context, clientid, username, topic string, acc int) (bool, error) {
	panic(fmt.Sprintf("cannot parse %q", username))
}

func (b *tokenPanicBackends) LogUsername(username string) string {
	if b.hide {
		return "<hidden>"
	}
	return username
}

// With a jwt backend the username is a token: the panic value, which can quote it, is not logged.
func TestPanicValueQuotingTokenIsNotLogged(t *testing.T) {
	const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwYW5pYyJ9.c2lnbmF0dXJl"
	saved, oldLevel := authPlugin, log.GetLevel()
	oldHooks := log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
	hook := logtest.NewGlobal()
	t.Cleanup(func() {
		authPlugin = saved
		log.SetLevel(oldLevel)
		log.StandardLogger().ReplaceHooks(oldHooks)
	})

	for _, hide := range []bool{true, false} {
		for _, kind := range []string{"auth", "acl"} {
			hook.Reset()
			authPlugin = AuthPlugin{backends: &tokenPanicBackends{hide: hide}, ctx: context.Background()}

			result := func() (result uint8) {
				defer recoverCheck(kind, &result, token, "client")
				if kind == "auth" {
					_, _ = authUnpwdCheck(token, "pass", "client")
				} else {
					_, _ = authAclCheck("client", token, "a/b", 1)
				}
				return AuthGranted
			}()
			require.Equal(t, uint8(AuthError), result)

			var logged strings.Builder
			for _, e := range hook.AllEntries() {
				logged.WriteString(e.Message)
			}
			require.NotEmpty(t, logged.String())
			if hide {
				require.NotContains(t, logged.String(), token[:16], kind)
			} else {
				require.Contains(t, logged.String(), "cannot parse", kind) // without a jwt backend the value stays
			}
		}
	}
}
