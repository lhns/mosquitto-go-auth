package backends

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

func installTestMeter(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	telemetry.InstallTestMeterProvider(mp)
	t.Cleanup(func() { telemetry.InstallTestMeterProvider(metricnoop.NewMeterProvider()) })
	return reader
}

func backendDuration(t *testing.T, rm metricdata.ResourceMetrics) metricdata.Histogram[float64] {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "backend.call.duration" {
				h, ok := m.Data.(metricdata.Histogram[float64])
				require.True(t, ok, "backend.call.duration should be a float64 histogram")
				require.Equal(t, "s", m.Unit)
				return h
			}
		}
	}
	t.Fatal("backend.call.duration metric not found")
	return metricdata.Histogram[float64]{}
}

func TestTraceBackendCall_GrantedEmitsMetric(t *testing.T) {
	reader := installTestMeter(t)

	ok, err := traceBackendCall(context.Background(), "files", "get_user",
		func(ctx context.Context) (bool, error) { return true, nil })
	require.NoError(t, err)
	require.True(t, ok)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	h := backendDuration(t, rm)
	require.Len(t, h.DataPoints, 1)
	attrs := h.DataPoints[0].Attributes
	name, _ := attrs.Value("backend.name")
	op, _ := attrs.Value("backend.op")
	result, _ := attrs.Value("backend.result")
	require.Equal(t, "files", name.AsString())
	require.Equal(t, "get_user", op.AsString())
	require.Equal(t, "granted", result.AsString())
}

func TestTraceBackendCall_RejectedAndErrorLabels(t *testing.T) {
	reader := installTestMeter(t)

	_, _ = traceBackendCall(context.Background(), "files", "check_acl",
		func(ctx context.Context) (bool, error) { return false, nil })
	_, _ = traceBackendCall(context.Background(), "files", "check_acl",
		func(ctx context.Context) (bool, error) { return false, errors.New("boom") })

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	h := backendDuration(t, rm)
	seen := map[string]bool{}
	for _, dp := range h.DataPoints {
		v, _ := dp.Attributes.Value("backend.result")
		seen[v.AsString()] = true
	}
	require.True(t, seen["rejected"], "expected a data point with backend.result=rejected")
	require.True(t, seen["error"], "expected a data point with backend.result=error")
}
