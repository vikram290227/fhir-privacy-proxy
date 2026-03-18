package tenant

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadRegistry(t *testing.T) {
	yaml := `tenants:
  - issuer_url: "http://localhost:8180/realms/hospital-a"
    tenant_id: "hospital-a"
    jwks_endpoint: "http://keycloak:8181/realms/hospital-a/protocol/openid-connect/certs"
    audience: "fhir-privacy-proxy"
    policy_bundle: "hospital-a"
    allowed_scopes:
      - "patient/Patient.read"
      - "patient/Observation.read"
  - issuer_url: "http://localhost:8180/realms/hospital-b"
    tenant_id: "hospital-b"
    jwks_endpoint: "http://keycloak:8181/realms/hospital-b/protocol/openid-connect/certs"
    audience: "fhir-proxy-b"
    policy_bundle: "hospital-b"
    token_ttl: 30m
    allowed_scopes:
      - "patient/Patient.read"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "tenants.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	reg, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	all := reg.GetAll()
	if len(all) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(all))
	}

	// Test hospital-a
	a, err := reg.GetByIssuer("http://localhost:8180/realms/hospital-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.TenantID != "hospital-a" {
		t.Errorf("expected tenant_id hospital-a, got %s", a.TenantID)
	}
	if a.Audience != "fhir-privacy-proxy" {
		t.Errorf("expected audience fhir-privacy-proxy, got %s", a.Audience)
	}
	if a.TokenTTL != 15*time.Minute {
		t.Errorf("expected default token_ttl 15m, got %v", a.TokenTTL)
	}
	if len(a.AllowedScopes) != 2 {
		t.Errorf("expected 2 allowed scopes, got %d", len(a.AllowedScopes))
	}

	// Test hospital-b with custom TTL
	b, err := reg.GetByIssuer("http://localhost:8180/realms/hospital-b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.TokenTTL != 30*time.Minute {
		t.Errorf("expected token_ttl 30m, got %v", b.TokenTTL)
	}
}

func TestLoadRegistry_FileNotFound(t *testing.T) {
	_, err := LoadRegistry("/nonexistent/path.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadRegistry_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("not: [valid: yaml: {{"), 0644)

	_, err := LoadRegistry(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestGetByIssuer_UnknownIssuer(t *testing.T) {
	yaml := `tenants:
  - issuer_url: "http://localhost:8180/realms/hospital-a"
    tenant_id: "hospital-a"
    jwks_endpoint: "http://keycloak:8181/realms/hospital-a/protocol/openid-connect/certs"
    audience: "fhir-privacy-proxy"
    policy_bundle: "hospital-a"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "tenants.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	reg, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = reg.GetByIssuer("http://unknown-issuer.com")
	if err == nil {
		t.Error("expected error for unknown issuer")
	}
}

func TestLoadRegistry_DefaultTokenTTL(t *testing.T) {
	yaml := `tenants:
  - issuer_url: "http://test"
    tenant_id: "test"
    jwks_endpoint: "http://test/jwks"
    audience: "test"
    policy_bundle: "test"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "tenants.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	reg, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg, _ := reg.GetByIssuer("http://test")
	if cfg.TokenTTL != 15*time.Minute {
		t.Errorf("expected default 15m TTL, got %v", cfg.TokenTTL)
	}
}
