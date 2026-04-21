package main

import (
	"context"
	"errors"
	"testing"

	"github.com/iegomez/mosquitto-go-auth/telemetry"
	"github.com/stretchr/testify/require"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
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

// installTestMeter wires package telemetry instruments to a ManualReader and
// returns the reader. Restores no-op instruments on test cleanup.
func installTestMeter(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	telemetry.InstallTestMeterProvider(mp)
	t.Cleanup(func() { telemetry.InstallTestMeterProvider(metricnoop.NewMeterProvider()) })
	return reader
}

func findMetric(t *testing.T, rm metricdata.ResourceMetrics, name string) metricdata.Metrics {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m
			}
		}
	}
	t.Fatalf("metric %q not found", name)
	return metricdata.Metrics{}
}

func resultAttr(m metricdata.Metrics) string {
	h, ok := m.Data.(metricdata.Histogram[float64])
	if !ok || len(h.DataPoints) == 0 {
		return ""
	}
	v, _ := h.DataPoints[0].Attributes.Value("auth.result")
	return v.AsString()
}

func TestAuthUnpwdCheck_EmitsAuthDuration(t *testing.T) {
	reader := installTestMeter(t)

	authPlugin = AuthPlugin{
		backends: &mockBackends{authResult: true},
		ctx:      context.Background(),
	}
	ok, err := authUnpwdCheck("user", "pass", "client")
	require.NoError(t, err)
	require.True(t, ok)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	m := findMetric(t, rm, "auth.unpwd_check.duration")
	require.Equal(t, "s", m.Unit)
	require.Equal(t, "granted", resultAttr(m))
}

func TestAuthUnpwdCheck_ErrorResultLabel(t *testing.T) {
	reader := installTestMeter(t)

	authPlugin = AuthPlugin{
		backends: &mockBackends{authErr: errBackendFailure},
		ctx:      context.Background(),
	}
	_, err := authUnpwdCheck("user", "pass", "client")
	require.Error(t, err)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	require.Equal(t, "error", resultAttr(findMetric(t, rm, "auth.unpwd_check.duration")))
}

func TestAuthAclCheck_EmitsACLDuration(t *testing.T) {
	reader := installTestMeter(t)

	authPlugin = AuthPlugin{
		backends: &mockBackends{},
		ctx:      context.Background(),
	}
	_, err := authAclCheck("client", "user", "topic", 1)
	require.NoError(t, err)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	m := findMetric(t, rm, "auth.acl_check.duration")
	require.Equal(t, "s", m.Unit)
	require.Equal(t, "rejected", resultAttr(m))
}
