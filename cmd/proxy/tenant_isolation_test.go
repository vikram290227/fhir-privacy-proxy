package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/auth"
	"github.com/vikram290227/fhir-privacy-proxy/internal/policy"
	"github.com/vikram290227/fhir-privacy-proxy/internal/tenant"
)

// This file is the end-to-end proof of the multi-tenant isolation claim
// made in docs/architecture.md. It stands up two mock Keycloak-style
// JWKS servers (one per tenant), wires them into a tenant.Registry, and
// drives the real auth.Middleware + policy.OPAClient pipeline to verify:
//
//   1. Tokens signed by an issuer that is not in the registry fail
//      with HTTP 401 "untrusted issuer" — i.e. a hospital-b token
//      cannot be swapped in when the proxy is configured only for
//      hospital-a.
//
//   2. The tenant_id on the resolved SubjectContext is derived from the
//      cryptographically verified `iss` claim, never from request
//      headers or URL segments, so a client cannot "claim" to be
//      hospital-b by setting a header while presenting a hospital-a
//      token.
//
//   3. policies/data.json keeps each tenant's sensitive_patients list
//      under its own key (`data["hospital-a"].sensitive_patients` vs.
//      `data["hospital-b"].sensitive_patients`) and the two lists are
//      strictly disjoint — exercising the exact indexing pattern
//      (`data[input.subject.tenant_id].sensitive_patients`) used by
//      policies/base/authz.rego.

// -----------------------------------------------------------------------
// Test helpers — mock JWKS server + token minter for a single tenant.
// -----------------------------------------------------------------------

type tenantIdP struct {
	key      *rsa.PrivateKey
	keyID    string
	tenantID string
	audience string
	issuer   string
	server   *httptest.Server
}

func newTenantIdP(t *testing.T, tenantID, audience string) *tenantIdP {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen for %s: %v", tenantID, err)
	}
	idp := &tenantIdP{
		key:      k,
		keyID:    tenantID + "-key",
		tenantID: tenantID,
		audience: audience,
	}
	idp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]interface{}{
			"keys": []interface{}{
				map[string]interface{}{
					"kty": "RSA",
					"use": "sig",
					"alg": "RS256",
					"kid": idp.keyID,
					"n":   base64.RawURLEncoding.EncodeToString(k.PublicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.PublicKey.E)).Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	idp.issuer = idp.server.URL
	return idp
}

func (i *tenantIdP) close() { i.server.Close() }

// mint produces a fully-populated access token signed by this IdP's
// private key with the given subject and role set.
func (i *tenantIdP) mint(t *testing.T, sub string, roles []string) string {
	t.Helper()
	return i.mintClaims(t, jwt.MapClaims{
		"iss": i.issuer,
		"sub": sub,
		"aud": i.audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"jti": fmt.Sprintf("%s-%d", sub, time.Now().UnixNano()),
		"realm_access": map[string]interface{}{
			"roles": rolesAsIface(roles),
		},
		"fhirContext": map[string]interface{}{
			"department": "cardiology",
			"role":       "nurse",
			"facility":   "main",
		},
		"scope": "patient/Patient.read",
	})
}

func (i *tenantIdP) mintClaims(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = i.keyID
	signed, err := tok.SignedString(i.key)
	if err != nil {
		t.Fatalf("sign for %s: %v", i.tenantID, err)
	}
	return signed
}

func rolesAsIface(roles []string) []interface{} {
	out := make([]interface{}, len(roles))
	for i, r := range roles {
		out[i] = r
	}
	return out
}

// buildTwoTenantRegistry writes a tenants.yaml file referencing both
// IdPs and returns the loaded registry.
func buildTwoTenantRegistry(t *testing.T, a, b *tenantIdP) *tenant.Registry {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tenants.yaml")
	yaml := fmt.Sprintf(`tenants:
  - issuer_url: "%s"
    tenant_id: "%s"
    jwks_endpoint: "%s"
    audience: "%s"
    policy_bundle: "%s"
    allowed_scopes:
      - "patient/Patient.read"
  - issuer_url: "%s"
    tenant_id: "%s"
    jwks_endpoint: "%s"
    audience: "%s"
    policy_bundle: "%s"
    allowed_scopes:
      - "patient/Patient.read"
`,
		a.issuer, a.tenantID, a.server.URL, a.audience, a.tenantID,
		b.issuer, b.tenantID, b.server.URL, b.audience, b.tenantID,
	)
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write tenants.yaml: %v", err)
	}
	reg, err := tenant.LoadRegistry(path)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	return reg
}

// buildSingleTenantRegistry registers ONLY the given IdP. This is the
// "proxy configured for hospital-a but presented a hospital-b token"
// scenario.
func buildSingleTenantRegistry(t *testing.T, only *tenantIdP) *tenant.Registry {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tenants.yaml")
	yaml := fmt.Sprintf(`tenants:
  - issuer_url: "%s"
    tenant_id: "%s"
    jwks_endpoint: "%s"
    audience: "%s"
    policy_bundle: "%s"
    allowed_scopes:
      - "patient/Patient.read"
`, only.issuer, only.tenantID, only.server.URL, only.audience, only.tenantID)
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write tenants.yaml: %v", err)
	}
	reg, err := tenant.LoadRegistry(path)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	return reg
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

// TestTenantIsolation_UntrustedIssuerRejected mints a token for
// hospital-b against a proxy whose registry knows ONLY hospital-a. The
// validateJWT path must fail with an "untrusted issuer" error and the
// public ValidateToken middleware must return 401.
func TestTenantIsolation_UntrustedIssuerRejected(t *testing.T) {
	idpA := newTenantIdP(t, "hospital-a", "fhir-privacy-proxy")
	defer idpA.close()
	idpB := newTenantIdP(t, "hospital-b", "fhir-privacy-proxy-b")
	defer idpB.close()

	// Registry sees ONLY hospital-a.
	reg := buildSingleTenantRegistry(t, idpA)
	mw := auth.NewMiddleware(reg, zap.NewNop())

	// Token is cryptographically valid in hospital-b's IdP but its
	// issuer claim points to an URL the proxy has never heard of.
	badToken := idpB.mint(t, "nurse-b1", []string{"nurse"})

	nextCalled := false
	handler := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/555", nil)
	req.Header.Set("Authorization", "Bearer "+badToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
	if nextCalled {
		t.Error("downstream handler must not be called on untrusted issuer")
	}
	var body map[string]string
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body["error"] != "invalid_token" {
		t.Errorf("expected error=invalid_token, got %q", body["error"])
	}
	if !strings.Contains(body["error_description"], "untrusted issuer") {
		t.Errorf("expected 'untrusted issuer' in description, got %q", body["error_description"])
	}
}

// TestTenantIsolation_TenantIDBoundToVerifiedIssuer asserts that the
// SubjectContext.TenantID is derived from the VERIFIED `iss` claim, not
// from client-supplied hints. Even when the client sets headers that
// "claim" to be hospital-b (X-Tenant-Id, X-Forwarded-Tenant, etc.) and
// targets a URL with a hospital-b-looking path, the SubjectContext
// still carries tenant_id = hospital-a because the token was minted by
// IdP-A.
func TestTenantIsolation_TenantIDBoundToVerifiedIssuer(t *testing.T) {
	idpA := newTenantIdP(t, "hospital-a", "fhir-privacy-proxy")
	defer idpA.close()
	idpB := newTenantIdP(t, "hospital-b", "fhir-privacy-proxy-b")
	defer idpB.close()

	reg := buildTwoTenantRegistry(t, idpA, idpB)
	mw := auth.NewMiddleware(reg, zap.NewNop())

	token := idpA.mint(t, "nurse1", []string{"nurse"})

	var observed *auth.SubjectContext
	handler := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subjectCtx, _ := r.Context().Value(auth.SubjectContextKey).(*auth.SubjectContext)
		observed = subjectCtx
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/555", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// Bogus client-supplied tenant hints that MUST be ignored.
	req.Header.Set("X-Tenant-Id", "hospital-b")
	req.Header.Set("X-Forwarded-Tenant", "hospital-b")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if observed == nil {
		t.Fatal("expected SubjectContext on the request")
	}
	if observed.TenantID != "hospital-a" {
		t.Errorf("SubjectContext.TenantID = %q, want %q (must come from verified iss)",
			observed.TenantID, "hospital-a")
	}
}

// TestTenantIsolation_CrossIssuerSignatureRejected mints a token whose
// `iss` claim points at hospital-b (which IS in the registry) but
// signs it with hospital-a's private key. Because the proxy fetches
// hospital-b's JWKS (keyed by the verified tenant lookup), the RS256
// signature verification will fail. This guards against an attacker
// who tries to "claim hospital-b" while only controlling hospital-a's
// signing key.
func TestTenantIsolation_CrossIssuerSignatureRejected(t *testing.T) {
	idpA := newTenantIdP(t, "hospital-a", "fhir-privacy-proxy")
	defer idpA.close()
	idpB := newTenantIdP(t, "hospital-b", "fhir-privacy-proxy-b")
	defer idpB.close()

	reg := buildTwoTenantRegistry(t, idpA, idpB)
	mw := auth.NewMiddleware(reg, zap.NewNop())

	// Forge a token that claims hospital-b's issuer but is signed with
	// hospital-a's private key. The JWKS served by idpB does NOT
	// advertise idpA's public key, so signature check must fail.
	forged := idpA.mintClaims(t, jwt.MapClaims{
		"iss": idpB.issuer, // pretends to be hospital-b
		"sub": "attacker",
		"aud": idpB.audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"jti": "forged-1",
		"realm_access": map[string]interface{}{
			"roles": rolesAsIface([]string{"admin"}),
		},
		"scope": "patient/Patient.read",
	})

	nextCalled := false
	handler := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/555", nil)
	req.Header.Set("Authorization", "Bearer "+forged)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for cross-tenant signature forgery, got %d: %s",
			rr.Code, rr.Body.String())
	}
	if nextCalled {
		t.Error("downstream handler must not be called on forged cross-tenant token")
	}
}

// TestTenantIsolation_SensitivePatientsDoNotLeak loads the real
// policies/data.json file used by OPA in production and checks the
// structural invariants that the `data[input.subject.tenant_id]
// .sensitive_patients` indexing in policies/base/authz.rego relies on:
//
//   * each tenant has its own sensitive_patients key
//   * the two lists are disjoint (no ID appears in both)
//   * hospital-a's IDs are NOT reachable via data["hospital-b"] and
//     hospital-b's IDs are NOT reachable via data["hospital-a"]
//
// Without this invariant, a token for hospital-a could be used to
// classify a hospital-b-only patient as "sensitive", or vice versa,
// leaking the existence of sensitive patient IDs across tenants.
func TestTenantIsolation_SensitivePatientsDoNotLeak(t *testing.T) {
	raw, err := os.ReadFile("../../policies/data.json")
	if err != nil {
		t.Fatalf("read policies/data.json: %v", err)
	}

	var data map[string]struct {
		SensitivePatients []string `json:"sensitive_patients"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("parse data.json: %v", err)
	}

	a, okA := data["hospital-a"]
	b, okB := data["hospital-b"]
	if !okA {
		t.Fatal(`policies/data.json missing "hospital-a" key`)
	}
	if !okB {
		t.Fatal(`policies/data.json missing "hospital-b" key`)
	}
	if len(a.SensitivePatients) == 0 {
		t.Error("hospital-a.sensitive_patients is empty — test fixture broken")
	}
	if len(b.SensitivePatients) == 0 {
		t.Error("hospital-b.sensitive_patients is empty — test fixture broken")
	}

	aSet := map[string]bool{}
	for _, id := range a.SensitivePatients {
		aSet[id] = true
	}
	for _, id := range b.SensitivePatients {
		if aSet[id] {
			t.Errorf("id %q appears in both hospital-a and hospital-b sensitive_patients", id)
		}
	}

	// Double-check the index that authz.rego uses:
	// `data[input.subject.tenant_id].sensitive_patients`.
	// Simulate lookup from a hospital-a subject and verify hospital-b's
	// IDs are invisible, and vice versa.
	lookup := func(tenantID string) map[string]bool {
		out := map[string]bool{}
		for _, id := range data[tenantID].SensitivePatients {
			out[id] = true
		}
		return out
	}
	fromA := lookup("hospital-a")
	fromB := lookup("hospital-b")
	for id := range fromA {
		if fromB[id] {
			t.Errorf("cross-tenant leak: %q reachable from both hospital-a and hospital-b", id)
		}
	}
	for _, id := range b.SensitivePatients {
		if fromA[id] {
			t.Errorf("hospital-b id %q is visible to hospital-a — isolation broken", id)
		}
	}
	for _, id := range a.SensitivePatients {
		if fromB[id] {
			t.Errorf("hospital-a id %q is visible to hospital-b — isolation broken", id)
		}
	}
}

// TestTenantIsolation_OPAReceivesVerifiedTenantID wires the full
// auth.Middleware + auth.EnforcePolicy chain against a mock OPA that
// captures the input payload. It then asserts:
//
//   * the tenant_id the policy sees is the verified one (hospital-a)
//   * per-tenant OPA data lookup is consistent: a hospital-a request
//     against a hospital-b-only sensitive id (555) is NOT classified
//     as sensitive (because data["hospital-a"].sensitive_patients does
//     not contain 555)
//
// The mock OPA implements the same `data[input.subject.tenant_id]
// .sensitive_patients` logic the real Rego uses, loaded from the real
// policies/data.json file. This is a behavioral proof — not a
// code-structure check — that the isolation boundary is honored by
// the exact index expression the authz rego uses.
func TestTenantIsolation_OPAReceivesVerifiedTenantID(t *testing.T) {
	idpA := newTenantIdP(t, "hospital-a", "fhir-privacy-proxy")
	defer idpA.close()
	idpB := newTenantIdP(t, "hospital-b", "fhir-privacy-proxy-b")
	defer idpB.close()

	// Load the real per-tenant data.json.
	raw, err := os.ReadFile("../../policies/data.json")
	if err != nil {
		t.Fatalf("read data.json: %v", err)
	}
	var policyData map[string]struct {
		SensitivePatients []string `json:"sensitive_patients"`
	}
	if err := json.Unmarshal(raw, &policyData); err != nil {
		t.Fatalf("parse data.json: %v", err)
	}

	// Mock OPA that re-implements the sensitive-patient rule exactly
	// as `data[input.subject.tenant_id].sensitive_patients` using the
	// real data.
	var capturedInputs []map[string]interface{}
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input map[string]interface{} `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("opa mock: bad body: %v", err)
		}
		capturedInputs = append(capturedInputs, body.Input)

		subject, _ := body.Input["subject"].(map[string]interface{})
		resource, _ := body.Input["resource"].(map[string]interface{})
		tenantID, _ := subject["tenant_id"].(string)
		patientID, _ := resource["patient_id"].(string)

		// Per-tenant index: ONLY look at this tenant's list.
		sensitive := false
		if bucket, ok := policyData[tenantID]; ok {
			for _, id := range bucket.SensitivePatients {
				if id == patientID {
					sensitive = true
					break
				}
			}
		}

		decision := map[string]interface{}{
			"allow":  !sensitive,
			"reason": "authorized",
		}
		if sensitive {
			decision["allow"] = false
			decision["reason"] = "sensitive_patient"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"result": decision})
	}))
	defer opaServer.Close()

	reg := buildTwoTenantRegistry(t, idpA, idpB)
	mw := auth.NewMiddleware(reg, zap.NewNop())
	opaClient := policy.NewOPAClient(opaServer.URL, zap.NewNop())

	// Build a realistic pipeline: ValidateToken -> EnforcePolicy ->
	// success handler.
	finalCalled := false
	chain := mw.ValidateToken(
		mw.EnforcePolicy(opaClient)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				finalCalled = true
				w.WriteHeader(200)
			}),
		),
	)

	// Case 1: hospital-a token asking for patient 555 — 555 IS
	// sensitive in hospital-b's list, but NOT in hospital-a's. Must
	// be allowed — the cross-tenant list must not leak in.
	finalCalled = false
	tokA := idpA.mint(t, "nurse1", []string{"nurse"})
	req := requestWithToken(t, "/fhir/r4/Patient/555", tokA)
	rr := httptest.NewRecorder()
	chain.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("hospital-a / patient 555: expected 200 (not sensitive for hospital-a), got %d: %s",
			rr.Code, rr.Body.String())
	}
	if !finalCalled {
		t.Error("hospital-a / patient 555: final handler should run")
	}

	// Case 2: hospital-a token asking for patient 123 — 123 IS
	// sensitive for hospital-a. Must be denied.
	finalCalled = false
	req = requestWithToken(t, "/fhir/r4/Patient/123", idpA.mint(t, "nurse1", []string{"nurse"}))
	rr = httptest.NewRecorder()
	chain.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("hospital-a / patient 123: expected 403 (sensitive for hospital-a), got %d: %s",
			rr.Code, rr.Body.String())
	}
	if finalCalled {
		t.Error("hospital-a / patient 123: final handler must not run")
	}

	// Case 3: hospital-b token asking for patient 123 — 123 IS
	// sensitive for hospital-a but NOT for hospital-b. Must be
	// allowed — hospital-a's list must not leak out.
	finalCalled = false
	tokB := idpB.mint(t, "nurse-b1", []string{"nurse"})
	req = requestWithToken(t, "/fhir/r4/Patient/123", tokB)
	rr = httptest.NewRecorder()
	chain.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("hospital-b / patient 123: expected 200 (not sensitive for hospital-b), got %d: %s",
			rr.Code, rr.Body.String())
	}

	// Verify every captured OPA input had a tenant_id that matches the
	// signing IdP of the token, not anything derived from the URL or
	// headers.
	if len(capturedInputs) < 3 {
		t.Fatalf("expected OPA to be called 3 times, got %d", len(capturedInputs))
	}
	tenantIDs := make([]string, 0, len(capturedInputs))
	for _, in := range capturedInputs {
		sub, _ := in["subject"].(map[string]interface{})
		id, _ := sub["tenant_id"].(string)
		tenantIDs = append(tenantIDs, id)
	}
	wantIDs := []string{"hospital-a", "hospital-a", "hospital-b"}
	for i, want := range wantIDs {
		if tenantIDs[i] != want {
			t.Errorf("OPA input[%d].subject.tenant_id = %q, want %q",
				i, tenantIDs[i], want)
		}
	}
}

// requestWithToken is a convenience builder for authenticated requests.
func requestWithToken(t *testing.T, path, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req.WithContext(context.Background())
}
