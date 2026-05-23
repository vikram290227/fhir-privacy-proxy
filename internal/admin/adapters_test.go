package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/vikram290227/fhir-privacy-proxy/internal/policyversion"
)

func makeTempPolicies(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	v1 := filepath.Join(dir, "versions", "v1")
	if err := os.MkdirAll(v1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(v1, "authz.rego"), []byte("package authz_v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestWrapPolicyManager_Nil(t *testing.T) {
	if WrapPolicyManager(nil) != nil {
		t.Error("expected nil for nil input")
	}
}

func TestWrapPolicyManager_NonNil(t *testing.T) {
	dir := makeTempPolicies(t)
	mgr, err := policyversion.New(dir)
	if err != nil {
		t.Fatalf("policyversion.New: %v", err)
	}
	if WrapPolicyManager(mgr) == nil {
		t.Error("expected non-nil wrapped manager")
	}
}

func TestPolicyManagerAdapter_List(t *testing.T) {
	dir := makeTempPolicies(t)
	mgr, _ := policyversion.New(dir)
	wrapped := WrapPolicyManager(mgr)

	bundles := wrapped.List()
	if len(bundles) == 0 {
		t.Error("expected at least one bundle")
	}
	for _, b := range bundles {
		if b.Version == "" {
			t.Error("bundle version should not be empty")
		}
	}
}

func TestPolicyManagerAdapter_Active(t *testing.T) {
	dir := makeTempPolicies(t)
	mgr, _ := policyversion.New(dir)
	wrapped := WrapPolicyManager(mgr)

	if wrapped.Active() == "" {
		t.Error("expected non-empty active version")
	}
}

func TestPolicyManagerAdapter_Activate(t *testing.T) {
	dir := makeTempPolicies(t)
	mgr, _ := policyversion.New(dir)
	wrapped := WrapPolicyManager(mgr)

	if err := wrapped.Activate("v1"); err != nil {
		t.Errorf("Activate v1: unexpected error: %v", err)
	}
	if wrapped.Active() != "v1" {
		t.Errorf("expected active=v1, got %s", wrapped.Active())
	}
}

func TestPolicyManagerAdapter_Rollback(t *testing.T) {
	dir := makeTempPolicies(t)
	mgr, _ := policyversion.New(dir)
	wrapped := WrapPolicyManager(mgr)

	// With only one version, rollback returns an error (no history)
	_, err := wrapped.Rollback()
	if err == nil {
		t.Error("expected error when rolling back with no history")
	}
}

func TestNewHTTPHealthCheck_Empty(t *testing.T) {
	if NewHTTPHealthCheck("") != nil {
		t.Error("expected nil for empty URL")
	}
}

func TestNewHTTPHealthCheck_NonEmpty(t *testing.T) {
	if NewHTTPHealthCheck("http://opa:8181/health") == nil {
		t.Error("expected non-nil for valid URL")
	}
}

func TestHTTPHealthCheck_OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := NewHTTPHealthCheck(server.URL).HealthCheck(context.Background()); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHTTPHealthCheck_500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	if err := NewHTTPHealthCheck(server.URL).HealthCheck(context.Background()); err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestHTTPHealthCheck_Unreachable(t *testing.T) {
	if err := NewHTTPHealthCheck("http://localhost:1/health").HealthCheck(context.Background()); err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestNewRedisHealthCheck_Nil(t *testing.T) {
	if NewRedisHealthCheck(nil) != nil {
		t.Error("expected nil for nil ping func")
	}
}

func TestRedisHealthCheck_OK(t *testing.T) {
	ping := func(ctx context.Context) error { return nil }
	if err := NewRedisHealthCheck(ping).HealthCheck(context.Background()); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRedisHealthCheck_Error(t *testing.T) {
	ping := func(ctx context.Context) error { return errors.New("redis down") }
	if err := NewRedisHealthCheck(ping).HealthCheck(context.Background()); err == nil {
		t.Error("expected error from failing ping")
	}
}
