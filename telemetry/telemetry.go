// Package telemetry provides OpenTelemetry tracing and metrics for the plugin.
//
// Configuration is read entirely from the standard OTEL_* environment variables
// natively supported by the OpenTelemetry Go SDK. No project-specific config
// keys are introduced.
//
// Activation: Init() installs real tracer and meter providers when any of
//   - OTEL_EXPORTER_OTLP_ENDPOINT
//   - OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
//   - OTEL_EXPORTER_OTLP_METRICS_ENDPOINT
//   - OTEL_SERVICE_NAME
//
// is set in the environment, and OTEL_SDK_DISABLED is not "true".
// Otherwise it installs no-op providers and returns a no-op shutdown.
// Callers never need to nil-check Tracer() or the pre-declared metric
// instruments.
package telemetry

import (
	"context"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/sdk/resource"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName         = "github.com/iegomez/mosquitto-go-auth"
	meterName          = "github.com/iegomez/mosquitto-go-auth"
	defaultServiceName = "mosquitto-go-auth"
)

// Pre-declared metric instruments. Initialised to no-op variants so callers
// never need to nil-check, even before Init runs or when telemetry is disabled.
var (
	AuthDuration    metric.Float64Histogram
	ACLDuration     metric.Float64Histogram
	BackendDuration metric.Float64Histogram
	CacheHits       metric.Int64Counter
	CacheMisses     metric.Int64Counter
)

var active bool

func init() {
	// Wire up no-op instruments so the package is safe to use before Init.
	bindInstruments(metricnoop.NewMeterProvider().Meter(meterName))
}

// Active reports whether Init installed real providers.
func Active() bool { return active }

// Tracer returns the tracer used by this package. Always non-nil; returns the
// global tracer provider's tracer, which is a no-op until Init installs a real
// provider.
func Tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}

// Init installs tracer and meter providers. Safe to call once. When no
// OTEL_* activation variable is set, installs no-op providers and returns
// a no-op shutdown function.
func Init(ctx context.Context) (func(context.Context) error, error) {
	if !shouldActivate() {
		active = false
		return noopShutdown, nil
	}

	res, err := buildResource(ctx)
	if err != nil {
		return noopShutdown, err
	}

	traceExp, err := otlptracegrpc.New(ctx)
	if err != nil {
		return noopShutdown, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	metricExp, err := otlpmetricgrpc.New(ctx)
	if err != nil {
		// Trace provider is already installed; tear it down so we don't leave
		// a half-initialised state behind.
		_ = tp.Shutdown(ctx)
		return noopShutdown, err
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	bindInstruments(mp.Meter(meterName))
	active = true

	log.AddHook(&LogrusHook{})

	shutdown := func(ctx context.Context) error {
		tpErr := tp.Shutdown(ctx)
		mpErr := mp.Shutdown(ctx)
		if tpErr != nil {
			return tpErr
		}
		return mpErr
	}

	return shutdown, nil
}

func noopShutdown(context.Context) error { return nil }

func shouldActivate() bool {
	// OTEL_SDK_DISABLED=true forces everything off, per the OTel spec.
	if strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED")), "true") {
		return false
	}
	// Activate when any standard OTel exporter or service-name env is set.
	for _, k := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_SERVICE_NAME",
	} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

func buildResource(ctx context.Context) (*resource.Resource, error) {
	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = defaultServiceName
	}
	return resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(semconv.ServiceName(serviceName)),
	)
}

func bindInstruments(m metric.Meter) {
	AuthDuration, _ = m.Float64Histogram(
		"auth.unpwd_check.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of plugin-level username/password auth checks"),
	)
	ACLDuration, _ = m.Float64Histogram(
		"auth.acl_check.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of plugin-level ACL checks"),
	)
	BackendDuration, _ = m.Float64Histogram(
		"backend.call.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of a single backend call"),
	)
	CacheHits, _ = m.Int64Counter(
		"auth.cache.hits",
		metric.WithUnit("{hit}"),
		metric.WithDescription("Cache hits for auth or ACL decisions"),
	)
	CacheMisses, _ = m.Int64Counter(
		"auth.cache.misses",
		metric.WithUnit("{miss}"),
		metric.WithDescription("Cache misses for auth or ACL decisions"),
	)
}

// LogrusHook injects trace_id and span_id fields into log entries whose
// context carries an active span. Registered automatically by Init.
type LogrusHook struct{}

// Levels returns all levels so correlation is added to every log entry.
func (*LogrusHook) Levels() []log.Level { return log.AllLevels }

// Fire adds trace_id and span_id to the entry when a span is active in
// entry.Context. Silent no-op otherwise.
func (*LogrusHook) Fire(e *log.Entry) error {
	if e.Context == nil {
		return nil
	}
	sc := trace.SpanContextFromContext(e.Context)
	if !sc.IsValid() {
		return nil
	}
	if e.Data == nil {
		e.Data = log.Fields{}
	}
	e.Data["trace_id"] = sc.TraceID().String()
	e.Data["span_id"] = sc.SpanID().String()
	return nil
}
