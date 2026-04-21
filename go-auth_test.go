package main

import (
	"context"
	"errors"
	"testing"
)

type mockBackends struct {
	authResult bool
	authErr    error
}

func (m *mockBackends) AuthUnpwdCheck(ctx context.Context, username, password, clientid string) (bool, error) {
	return m.authResult, m.authErr
}

func (m *mockBackends) AuthAclCheck(ctx context.Context, clientid, username, topic string, acc int) (bool, error) {
	return false, nil
}

func (m *mockBackends) Halt() {}

var errBackendFailure = errors.New("simulated backend failure")

func Test_authUnpwdCheck(t *testing.T) {
	testCases := []struct {
		name         string
		username     string
		password     string
		emptyEnabled bool
		wantOK       bool
		wantErr      bool
		backendErr   error
		backendOk    bool
	}{
		{
			name:         "Missing username",
			username:     "",
			password:     "pass1",
			emptyEnabled: false,
			wantOK:       false,
			wantErr:      true,
			backendErr:   nil,
			backendOk:    true,
		},
		{
			name:         "Missing password",
			username:     "user1",
			password:     "",
			emptyEnabled: false,
			wantOK:       false,
			wantErr:      true,
			backendErr:   nil,
			backendOk:    true,
		},
		{
			name:         "Empty credentials allowed: only username",
			username:     "valid-username",
			password:     "",
			emptyEnabled: true,
			wantOK:       true,
			wantErr:      false,
			backendErr:   nil,
			backendOk:    true,
		},
		{
			name:         "Empty credentials allowed: only password",
			username:     "",
			password:     "valid-password",
			emptyEnabled: true,
			wantOK:       true,
			wantErr:      false,
			backendErr:   nil,
			backendOk:    true,
		},
		{
			name:         "Empty credentials allowed: both empty",
			username:     "",
			password:     "",
			emptyEnabled: true,
			wantOK:       true,
			wantErr:      false,
			backendErr:   nil,
			backendOk:    true,
		},
		{
			name:         "Backend error",
			username:     "user1",
			password:     "pass1",
			emptyEnabled: false,
			wantOK:       false,
			wantErr:      true,
			backendErr:   errBackendFailure, // Simulate a backend error
			backendOk:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authPlugin = AuthPlugin{
				backends:              &mockBackends{authResult: tc.backendOk, authErr: tc.backendErr},
				allowEmptyCredentials: tc.emptyEnabled,
				ctx:                   context.Background(),
			}

			ok, err := authUnpwdCheck(tc.username, tc.password, "client-id")

			if ok != tc.wantOK {
				t.Errorf("Expected ok to be %v, got %v", tc.wantOK, ok)
			}

			if (err != nil) != tc.wantErr {
				t.Errorf("Expected error presence to be %v, got %v", tc.wantErr, err != nil)
			}
		})
	}
}
