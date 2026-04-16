// Package admin exposes a small management API for the FHIR Privacy
// Proxy. It is mounted at /admin/v1 and gated by a static header API
// key (X-Admin-Key) so it can be locked down behind a separate ingress
// rule from the public /fhir/r4 surface.
//
// Scope:
//
//   - GET  /admin/v1/policy/versions  — list policy bundles + active
//   - POST /admin/v1/policy/activate  — activate a bundle by version
//   - POST /admin/v1/policy/rollback  — pop one rollback step
//   - GET  /admin/v1/tenants          — list tenants (secrets redacted)
//   - GET  /admin/v1/audit/tail?n=50  — tail recent audit events
//   - POST /admin/v1/tokens/revoke    — revoke a JWT by jti
//   - GET  /admin/v1/health/deps      — status of OPA / Redis / FHIR / risk
//
// The package is intentionally light on dependencies — every backend it
// touches (policyversion manager, audit file logger, revocation cache,
// risk client, tenant registry, OPA client) is reached via narrow
// interfaces declared here so tests can inject mocks without spinning
// up the full proxy.
package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/metrics"
	"github.com/vikram290227/fhir-privacy-proxy/internal/tenant"
)

// PolicyManager is the slice of *policyversion.Manager the admin API
// needs. Defined here as an interface so tests can inject a fake
// without pulling in OPA or the filesystem. *policyversion.Manager
// does not satisfy this directly because its List() returns
// []policyversion.Bundle; use WrapPolicyManager to bridge the two.
type PolicyManager interface {
	List() []Bundle
	Active() string
	Activate(version string) error
	Rollback() (string, error)
}

// Bundle is the wire-friendly view of one policy version. Defined
// here (and exported) so callers outside the admin package — most
// notably the adapter in cmd/proxy that wraps *policyversion.Manager
// — can build values of this type when implementing PolicyManager.
type Bundle struct {
	Version string `json:"version"`
	Path    string `json:"path"`
}

// AuditTailer is the slice of the audit logger the admin API needs:
// the path on disk so we can read the last N lines. Implemented by
// *audit.FileLogger via an adapter in cmd/proxy.
type AuditTailer interface {
	Path() string
}

// Revoker is satisfied by *cache.RevocationCache. Decoupled so the
// admin tests can drop in an in-memory revoker without standing up
// Redis.
type Revoker interface {
	Revoke(tenantID, jti string, exp int64) error
}

// HealthCheckable is the interface every dependency exposes for the
// /health/deps endpoint. Implementations should set a hard timeout so
// a stuck dep can't wedge the whole admin response.
type HealthCheckable interface {
	HealthCheck(ctx context.Context) error
}

// Deps is the set of optional collaborators the admin server can
// query. All fields may be nil — endpoints that need a missing
// dependency return 503 with a clear "feature_disabled" error code so
// operators can tell "broken" apart from "not configured".
type Deps struct {
	Policy   PolicyManager
	Tenants  *tenant.Registry
	Audit    AuditTailer
	Revoker  Revoker
	OPA      HealthCheckable
	Redis    HealthCheckable
	Upstream HealthCheckable
	Risk     HealthCheckable
}

// Server is the admin API HTTP handler. Construct with New and either
// mount Router under /admin/v1 on the main proxy or expose it on a
// dedicated port.
type Server struct {
	apiKey string
	deps   Deps
	logger *zap.Logger
	router chi.Router
}

// New constructs a Server. apiKey must be non-empty — the caller
// (cmd/proxy/main.go) is responsible for the ADMIN_API_KEY != "" gate;
// passing an empty key here is treated as a programming error so the
// admin surface cannot accidentally come up without auth.
func New(apiKey string, deps Deps, logger *zap.Logger) *Server {
	if logger == nil {
		logger = zap.NewNop()
	}
	s := &Server{
		apiKey: apiKey,
		deps:   deps,
		logger: logger,
	}
	s.router = s.buildRouter()
	return s
}

// Router returns the underlying chi router. Mount it on the main
// proxy via r.Mount("/admin/v1", server.Router()).
func (s *Server) Router() chi.Router { return s.router }

// ServeHTTP makes Server an http.Handler so callers can use it
// directly without grabbing the router.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) buildRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(s.requireAPIKey)
	r.Use(s.instrument)

	r.Get("/policy/versions", s.handleListVersions)
	r.Post("/policy/activate", s.handleActivate)
	r.Post("/policy/rollback", s.handleRollback)
	r.Get("/tenants", s.handleListTenants)
	r.Get("/audit/tail", s.handleAuditTail)
	r.Post("/tokens/revoke", s.handleRevokeToken)
	r.Get("/health/deps", s.handleHealthDeps)
	return r
}

// requireAPIKey rejects any request whose X-Admin-Key header doesn't
// constant-time-equal the configured key. An unconfigured server (no
// key) always rejects — Server should not even be wired up in that
// case, but defending in depth is cheap.
func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey == "" {
			writeError(w, http.StatusUnauthorized, "admin_disabled", "admin API not configured")
			return
		}
		got := r.Header.Get("X-Admin-Key")
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.apiKey)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid_api_key", "X-Admin-Key missing or incorrect")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// instrument records every admin request in Prometheus, labelled by
// the chi route pattern (NOT the raw path — that would explode label
// cardinality for endpoints like /audit/tail?n=...).
func (s *Server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		endpoint := chi.RouteContext(r.Context()).RoutePattern()
		if endpoint == "" {
			endpoint = r.URL.Path
		}
		metrics.AdminRequests.WithLabelValues(endpoint, strconv.Itoa(rec.status)).Inc()
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.wrote = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status = http.StatusOK
		r.wrote = true
	}
	return r.ResponseWriter.Write(b)
}

// writeJSON emits a JSON body with the given status. Failure to encode
// is logged at debug level and the response is left half-written —
// callers should not use this for partial-success responses.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError emits a {error, message} JSON body. The wire format
// matches the public proxy errors so admin clients have a uniform
// schema to parse.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": message,
	})
}

// readJSON decodes the request body into v. Returns false (and writes
// a 400) on bad input so callers can simply `if !readJSON(...) { return }`.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return false
	}
	return true
}

// withTimeout returns a derived context bounded by d. The admin server
// uses short timeouts on every dependency call so a wedged backend
// can't lock up the management plane.
func withTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}
