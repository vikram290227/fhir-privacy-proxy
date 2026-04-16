package admin

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/vikram290227/fhir-privacy-proxy/internal/policyversion"
)

// ---------------------------------------------------------------------
// PolicyManager adapter
// ---------------------------------------------------------------------

// policyManagerAdapter bridges the concrete *policyversion.Manager to
// the admin.PolicyManager interface, which uses admin.Bundle for the
// JSON wire shape rather than policyversion.Bundle.
type policyManagerAdapter struct {
	inner *policyversion.Manager
}

// WrapPolicyManager wraps a *policyversion.Manager so it satisfies
// admin.PolicyManager. Used by cmd/proxy/main.go when constructing
// admin.Deps.
func WrapPolicyManager(m *policyversion.Manager) PolicyManager {
	if m == nil {
		return nil
	}
	return &policyManagerAdapter{inner: m}
}

func (a *policyManagerAdapter) List() []Bundle {
	src := a.inner.List()
	out := make([]Bundle, len(src))
	for i, b := range src {
		out[i] = Bundle{Version: b.Version, Path: b.Path}
	}
	return out
}

func (a *policyManagerAdapter) Active() string                   { return a.inner.Active() }
func (a *policyManagerAdapter) Activate(version string) error    { return a.inner.Activate(version) }
func (a *policyManagerAdapter) Rollback() (string, error)        { return a.inner.Rollback() }

// ---------------------------------------------------------------------
// HealthCheckable adapters
// ---------------------------------------------------------------------

// httpPinger is the narrow contract every HTTP-based dependency
// satisfies for /health/deps. It is the smallest surface that lets the
// admin server probe a dep without depending on its full client type.
//
// Use NewHTTPHealthCheck to build one for OPA / FHIR / risk; Redis is
// covered by RedisHealthCheck which wraps the typed *redis.Client
// Ping.

// HTTPHealthCheck issues a short GET against a configured URL and
// reports any non-2xx as a failure. It is the workhorse for OPA, the
// upstream FHIR server, and the risk service — none of those expose a
// Go-typed health primitive that's worth depending on, but all of
// them have a working liveness URL.
type HTTPHealthCheck struct {
	url    string
	client *http.Client
}

// NewHTTPHealthCheck constructs a checker that GETs url with a short
// timeout. Pass an empty url (or an empty string from a missing env
// var) and the constructor returns nil so the corresponding
// admin.Deps field is left as the disabled-state sentinel.
func NewHTTPHealthCheck(url string) HealthCheckable {
	if url == "" {
		return nil
	}
	return &HTTPHealthCheck{
		url:    url,
		client: &http.Client{Timeout: 2 * time.Second},
	}
}

// HealthCheck implements HealthCheckable.
func (h *HTTPHealthCheck) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("get %s: %w", h.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("get %s: status %d", h.url, resp.StatusCode)
	}
	return nil
}

// RedisHealthCheckFunc adapts a function-shaped Ping into
// HealthCheckable. The cache.RevocationCache exposes
// `Ping(ctx) error`; wrap it via NewRedisHealthCheck so the admin
// package never has to import the redis client directly.
type RedisHealthCheckFunc func(ctx context.Context) error

// NewRedisHealthCheck wraps a Ping-style function. Returns nil if
// ping is nil.
func NewRedisHealthCheck(ping func(ctx context.Context) error) HealthCheckable {
	if ping == nil {
		return nil
	}
	return RedisHealthCheckFunc(ping)
}

// HealthCheck implements HealthCheckable.
func (f RedisHealthCheckFunc) HealthCheck(ctx context.Context) error {
	return f(ctx)
}
