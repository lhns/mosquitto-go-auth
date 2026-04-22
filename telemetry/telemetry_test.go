package telemetry

import (
	"context"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func TestShouldActivate(t *testing.T) {
	// Clear everything we care about first; t.Setenv restores on cleanup.
	for _, k := range []string{
		"OTEL_SDK_DISABLED",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_SERVICE_NAME",
	} {
		t.Setenv(k, "")
	}

	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"no env", nil, false},
		{"service name set", map[string]string{"OTEL_SERVICE_NAME": "x"}, true},
		{"otlp endpoint set", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4317"}, true},
		{"traces endpoint set", map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://collector:4317"}, true},
		{"metrics endpoint set", map[string]string{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://collector:4317"}, true},
		{"sdk disabled overrides service name", map[string]string{"OTEL_SDK_DISABLED": "true", "OTEL_SERVICE_NAME": "x"}, false},
		{"sdk disabled false is not itself a trigger", map[string]string{"OTEL_SDK_DISABLED": "false"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			require.Equal(t, tc.want, shouldActivate())
		})
	}
}

func TestInstrumentsRecordToReader(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	bindInstruments(mp.Meter(meterName))
	t.Cleanup(func() { bindInstruments(metricnoop.NewMeterProvider().Meter(meterName)) })

	ctx := context.Background()
	AuthDuration.Record(ctx, 0.001, metric.WithAttributes(attribute.String("auth.result", "granted")))
	ACLDuration.Record(ctx, 0.002, metric.WithAttributes(attribute.String("auth.result", "rejected")))
	BackendDuration.Record(ctx, 0.003, metric.WithAttributes(
		attribute.String("backend.name", "files"),
		attribute.String("backend.op", "get_user"),
		attribute.String("backend.result", "granted"),
	))
	CacheHits.Add(ctx, 1, metric.WithAttributes(attribute.String("auth.kind", "unpwd")))
	CacheMisses.Add(ctx, 2, metric.WithAttributes(attribute.String("auth.kind", "acl")))

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &rm))

	metrics := map[string]metricdata.Metrics{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			metrics[m.Name] = m
		}
	}

	histCases := []struct {
		name, attrKey, attrVal string
	}{
		{"auth.unpwd_check.duration", "auth.result", "granted"},
		{"auth.acl_check.duration", "auth.result", "rejected"},
		{"backend.call.duration", "backend.result", "granted"},
	}
	for _, tc := range histCases {
		m, ok := metrics[tc.name]
		require.True(t, ok, "histogram %q missing", tc.name)
		require.Equal(t, "s", m.Unit)
		h, ok := m.Data.(metricdata.Histogram[float64])
		require.True(t, ok, "%q should be a float64 histogram", tc.name)
		require.NotEmpty(t, h.DataPoints, "%q has no data points", tc.name)
		v, _ := h.DataPoints[0].Attributes.Value(attribute.Key(tc.attrKey))
		require.Equal(t, tc.attrVal, v.AsString(), "%q missing %s=%s", tc.name, tc.attrKey, tc.attrVal)
	}

	counterCases := []struct {
		name, unit, kind string
		wantVal          int64
	}{
		{"auth.cache.hits", "{hit}", "unpwd", 1},
		{"auth.cache.misses", "{miss}", "acl", 2},
	}
	for _, tc := range counterCases {
		m, ok := metrics[tc.name]
		require.True(t, ok, "counter %q missing", tc.name)
		require.Equal(t, tc.unit, m.Unit)
		s, ok := m.Data.(metricdata.Sum[int64])
		require.True(t, ok, "%q should be an int64 sum", tc.name)
		require.NotEmpty(t, s.DataPoints, "%q has no data points", tc.name)
		require.Equal(t, tc.wantVal, s.DataPoints[0].Value)
		v, _ := s.DataPoints[0].Attributes.Value("auth.kind")
		require.Equal(t, tc.kind, v.AsString())
	}
}

func TestInit_NoEnv(t *testing.T) {
	for _, k := range []string{
		"OTEL_SDK_DISABLED",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_SERVICE_NAME",
	} {
		t.Setenv(k, "")
	}

	shutdown, err := Init(context.Background())
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	require.False(t, Active())

	// Instruments must stay safe to call when telemetry never activated.
	require.NotPanics(t, func() {
		AuthDuration.Record(context.Background(), 0.001,
			metric.WithAttributes(attribute.String("auth.result", "granted")))
		CacheHits.Add(context.Background(), 1,
			metric.WithAttributes(attribute.String("auth.kind", "unpwd")))
	})

	require.NoError(t, shutdown(context.Background()))
}

func TestLogrusHook_AddsTraceAndSpanID(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	ctx, span := tp.Tracer("test").Start(context.Background(), "op")
	defer span.End()

	entry := &log.Entry{Context: ctx}
	require.NoError(t, (&LogrusHook{}).Fire(entry))

	sc := trace.SpanContextFromContext(ctx)
	require.Equal(t, sc.TraceID().String(), entry.Data["trace_id"])
	require.Equal(t, sc.SpanID().String(), entry.Data["span_id"])
}

func TestLogrusHook_NoSpan_NoFields(t *testing.T) {
	entry := &log.Entry{Context: context.Background()}
	require.NoError(t, (&LogrusHook{}).Fire(entry))
	require.Nil(t, entry.Data["trace_id"])
	require.Nil(t, entry.Data["span_id"])
}
