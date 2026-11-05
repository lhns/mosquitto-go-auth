package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type panickingBackends struct{ mockBackends }

func (panickingBackends) AuthUnpwdCheck(ctx context.Context, username, password, clientid string) (bool, error) {
	panic("backend bug")
}

// A panic in a check must deny the request instead of crossing the cgo boundary and stopping the broker.
// The exported callbacks take C strings, so this calls the check the way they do.
func TestPanicInCheckDenies(t *testing.T) {
	authPlugin = AuthPlugin{backends: &panickingBackends{}, ctx: context.Background()}

	result := func() (result uint8) {
		defer recoverCheck("auth", &result)
		if ok, err := authUnpwdCheck("user", "pass", "client"); ok && err == nil {
			return AuthGranted
		}
		return AuthRejected
	}()

	require.Equal(t, uint8(AuthError), result)
}
