package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// RequestsTotal counts total HTTP requests handled by the proxy.
	RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fhir_proxy_requests_total",
			Help: "Total number of FHIR proxy requests",
		},
		[]string{"method", "path", "status"},
	)

	// RequestDuration tracks request latency in seconds.
	RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "fhir_proxy_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// UpstreamDuration tracks upstream FHIR server latency.
	UpstreamDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "fhir_proxy_upstream_duration_seconds",
			Help:    "Upstream FHIR server request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "resource_type"},
	)

	// PolicyDecisions counts OPA policy decisions.
	PolicyDecisions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fhir_proxy_policy_decisions_total",
			Help: "Total OPA policy decisions",
		},
		[]string{"decision", "tenant_id"},
	)

	// AuthFailures counts authentication failures.
	AuthFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fhir_proxy_auth_failures_total",
			Help: "Total authentication failures",
		},
		[]string{"reason"},
	)

	// BreakGlassAccesses counts break-glass emergency overrides.
	BreakGlassAccesses = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fhir_proxy_break_glass_total",
			Help: "Total break-glass accesses",
		},
		[]string{"tenant_id", "subject_id"},
	)

	// TokenRevocations counts token revocation events.
	TokenRevocations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fhir_proxy_token_revocations_total",
			Help: "Total token revocations",
		},
		[]string{"tenant_id"},
	)

	// ActiveConnections tracks active connections.
	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "fhir_proxy_active_connections",
			Help: "Number of active connections",
		},
	)

	// PolicyEvalDuration measures the latency of OPA policy evaluation
	// (client-side round trip including network).
	PolicyEvalDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "fhir_proxy_policy_eval_duration_seconds",
			Help:    "OPA policy evaluation latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	// PolicyOutcome counts allow vs deny decisions labelled by tenant
	// and (optionally) the reason string returned by OPA.
	PolicyOutcome = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fhir_proxy_policy_outcome_total",
			Help: "OPA policy allow/deny outcomes",
		},
		[]string{"tenant_id", "outcome", "reason"},
	)

	// RiskScores counts how many scores came back with each label
	// ("normal", "suspicious", "anomalous").
	RiskScores = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fhir_proxy_risk_scores_total",
			Help: "Risk scoring outcomes by label",
		},
		[]string{"label"},
	)

	// RiskScoreDuration tracks the risk service round trip latency.
	RiskScoreDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "fhir_proxy_risk_score_duration_seconds",
			Help:    "Risk scoring service latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	// RateLimitHits counts 429 outcomes from the sliding-window rate
	// limiter. The `window` label is "minute" or "hour" so operators
	// can see which tier is being hit. Subject IDs are included to
	// aid incident response but are inherently high-cardinality — in
	// production you may want to redact or hash them.
	RateLimitHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fhir_proxy_rate_limit_hits_total",
			Help: "Total rate-limit rejections (429) by tenant + subject + window",
		},
		[]string{"tenant", "subject", "window"},
	)

	// MLTimeouts counts requests where the ML risk service exceeded its
	// 15ms hard budget. High values indicate the ONNX-embedded path
	// should be preferred over the FastAPI network-hop approach.
	MLTimeouts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fhir_proxy_ml_timeouts_total",
			Help: "Total risk-scoring calls that exceeded the 15ms deadline (Unavailable=true)",
		},
		[]string{"tenant_id"},
	)

	// AdminRequests counts requests to the /admin/v1 management API.
	// Labelled by endpoint (the chi route pattern, NOT the raw path,
	// so cardinality stays bounded) and HTTP status. Useful for
	// alerting on a spike of 401s (probing) or 5xx (admin handler
	// breakage).
	AdminRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fhir_proxy_admin_requests_total",
			Help: "Total admin API requests by endpoint and HTTP status",
		},
		[]string{"endpoint", "status"},
	)
)

func init() {
	prometheus.MustRegister(
		RequestsTotal,
		RequestDuration,
		UpstreamDuration,
		PolicyDecisions,
		AuthFailures,
		BreakGlassAccesses,
		TokenRevocations,
		ActiveConnections,
		PolicyEvalDuration,
		PolicyOutcome,
		RiskScores,
		RiskScoreDuration,
		RateLimitHits,
		MLTimeouts,
		AdminRequests,
	)
}

// Handler returns the Prometheus metrics HTTP handler.
func Handler() http.Handler {
	return promhttp.Handler()
}

// InstrumentHandler wraps an HTTP handler with request metrics.
func InstrumentHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ActiveConnections.Inc()
		defer ActiveConnections.Dec()

		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start).Seconds()
		path := normalizePath(r.URL.Path)

		RequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(rw.statusCode)).Inc()
		RequestDuration.WithLabelValues(r.Method, path).Observe(duration)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// normalizePath reduces cardinality by replacing IDs with placeholders.
func normalizePath(path string) string {
	// Keep the resource type but replace specific IDs
	// /fhir/r4/Patient/123 -> /fhir/r4/Patient/:id
	// This prevents high-cardinality labels
	parts := splitPath(path)
	if len(parts) >= 4 && parts[0] == "" && parts[1] == "fhir" && parts[2] == "r4" {
		if len(parts) > 4 {
			return "/fhir/r4/" + parts[3] + "/:id"
		}
		return "/fhir/r4/" + parts[3]
	}
	return path
}

func splitPath(path string) []string {
	var parts []string
	current := ""
	for _, c := range path {
		if c == '/' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
