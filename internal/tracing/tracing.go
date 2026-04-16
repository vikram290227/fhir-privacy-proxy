// Package tracing wires OpenTelemetry into the proxy.
//
// Init() returns a shutdown closure; the exporter it installs depends
// on the environment:
//
//   - If OTEL_EXPORTER_OTLP_ENDPOINT is set, spans are batched and
//     pushed over OTLP/HTTP to that collector (Jaeger, OTel Collector,
//     Tempo, etc.). Both `scheme://host:port` and bare `host:port`
//     forms are accepted.
//   - Otherwise the tracer provider is installed with no exporter so
//     span creation remains cheap but nothing is shipped off-box.
//     This keeps unit tests and local `go run` fast and side-effect
//     free, while `docker-compose up` flips the env var and wires us
//     to Jaeger automatically.
package tracing

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName  = "fhir-privacy-proxy"
	serviceName = "fhir-privacy-proxy"
)

// ServiceVersion is stamped at build time via -ldflags
//
//	-X github.com/vikram290227/fhir-privacy-proxy/internal/tracing.ServiceVersion=<version>
//
// Defaults to "dev" so untagged local builds show up distinctly in
// Jaeger rather than getting collapsed with a real release.
var ServiceVersion = "dev"

// Init installs a global TracerProvider and W3C TraceContext
// propagator. The returned function flushes the exporter and should
// be called on shutdown.
func Init() func(context.Context) error {
	ctx := context.Background()

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(ServiceVersion),
		),
	)
	if err != nil {
		// Falling back to Default is safe — every attribute we set
		// above is optional metadata, not required for correctness.
		res = resource.Default()
	}

	opts := []sdktrace.TracerProviderOption{sdktrace.WithResource(res)}

	if exp, ok := otlpExporter(ctx); ok {
		// Batching is the recommended production configuration:
		// span creation stays non-blocking and the exporter flushes
		// on a fixed cadence or when the queue fills.
		opts = append(opts, sdktrace.WithBatcher(exp))
	}

	tp := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return func(ctx context.Context) error {
		return tp.Shutdown(ctx)
	}
}

// otlpExporter builds an OTLP/HTTP trace exporter if
// OTEL_EXPORTER_OTLP_ENDPOINT is set. Unset or malformed endpoints
// degrade to the no-op path — we'd rather boot than refuse to start
// because telemetry was mis-configured.
func otlpExporter(ctx context.Context) (*otlptrace.Exporter, bool) {
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if endpoint == "" {
		return nil, false
	}

	host, insecure := parseEndpoint(endpoint)
	if host == "" {
		return nil, false
	}

	exporterOpts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(host),
		otlptracehttp.WithTimeout(10 * time.Second),
	}
	if insecure {
		exporterOpts = append(exporterOpts, otlptracehttp.WithInsecure())
	}

	exp, err := otlptracehttp.New(ctx, exporterOpts...)
	if err != nil {
		return nil, false
	}
	return exp, true
}

// parseEndpoint normalises what users typically put into
// OTEL_EXPORTER_OTLP_ENDPOINT: either `http://host:port`,
// `https://host:port`, or a bare `host:port` (in which case we
// default to insecure, matching the OTel spec's default for HTTP
// when no scheme is provided).
func parseEndpoint(raw string) (host string, insecure bool) {
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", false
		}
		return u.Host, u.Scheme != "https"
	}
	return raw, true
}

// Tracer returns the named tracer for this service.
func Tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}

// Middleware adds OpenTelemetry tracing to HTTP handlers.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		tracer := Tracer()
		ctx, span := tracer.Start(ctx, r.Method+" "+r.URL.Path,
			trace.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.url", r.URL.String()),
				attribute.String("http.user_agent", r.UserAgent()),
			),
		)
		defer span.End()

		rw := &tracingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r.WithContext(ctx))

		span.SetAttributes(attribute.Int("http.status_code", rw.statusCode))
	})
}

type tracingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *tracingResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// SpanFromContext returns the current span from context for adding custom attributes.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}
