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
	CacheMisses.Add(ctx, 1, metric.WithAttributes(attribute.String("auth.kind", "acl")))

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &rm))

	want := map[string]string{
		"auth.unpwd_check.duration": "s",
		"auth.acl_check.duration":   "s",
		"backend.call.duration":     "s",
		"auth.cache.hits":           "{hit}",
		"auth.cache.misses":         "{miss}",
	}
	got := map[string]string{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			got[m.Name] = m.Unit
		}
	}
	for name, unit := range want {
		require.Equal(t, unit, got[name], "metric %q missing or wrong unit", name)
	}
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
