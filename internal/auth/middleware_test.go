package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vikram290227/fhir-privacy-proxy/internal/policy"
	"github.com/vikram290227/fhir-privacy-proxy/internal/tenant"
	"go.uber.org/zap"
)

func mockTenantConfig() tenant.Config {
	return tenant.Config{
		IssuerURL:    "http://localhost:8180/realms/hospital-a",
		TenantID:     "hospital-a",
		JWKSEndpoint: "http://keycloak:8181/realms/hospital-a/protocol/openid-connect/certs",
		Audience:     "fhir-privacy-proxy",
		PolicyBundle: "hospital-a",
		TokenTTL:     15 * time.Minute,
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{"valid bearer", "Bearer abc123", "abc123"},
		{"empty header", "", ""},
		{"no bearer prefix", "Basic abc123", ""},
		{"bearer only", "Bearer", ""},
		{"extra spaces", "Bearer  abc 123", ""},
		{"lowercase bearer", "bearer abc123", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			got := extractBearerToken(req)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestRespondWithError(t *testing.T) {
	w := httptest.NewRecorder()
	respondWithError(w, 401, "invalid_token", "token expired")

	if w.Code != 401 {
		t.Errorf("expected status 401, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json, got %s", w.Header().Get("Content-Type"))
	}

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "invalid_token" {
		t.Errorf("expected error 'invalid_token', got '%s'", body["error"])
	}
	if body["error_description"] != "token expired" {
		t.Errorf("expected description 'token expired', got '%s'", body["error_description"])
	}
}

func TestContains(t *testing.T) {
	if !contains([]string{"a", "b", "c"}, "b") {
		t.Error("expected true for 'b' in [a,b,c]")
	}
	if contains([]string{"a", "b", "c"}, "d") {
		t.Error("expected false for 'd' in [a,b,c]")
	}
	if contains(nil, "a") {
		t.Error("expected false for nil slice")
	}
	if contains([]string{}, "a") {
		t.Error("expected false for empty slice")
	}
}

func TestGetStringClaim(t *testing.T) {
	claims := map[string]interface{}{
		"azp": "my-client",
		"sub": "user123",
	}

	// mapClaims doesn't have the right type, so we test with the map directly
	// Using jwt.MapClaims which is just map[string]interface{}
	if got := getStringClaim(claims, "azp"); got != "my-client" {
		t.Errorf("expected 'my-client', got '%s'", got)
	}
	if got := getStringClaim(claims, "missing", "azp"); got != "my-client" {
		t.Errorf("expected fallback to azp, got '%s'", got)
	}
	if got := getStringClaim(claims, "missing"); got != "" {
		t.Errorf("expected empty string, got '%s'", got)
	}
}

func TestGetNumericClaim(t *testing.T) {
	claims := map[string]interface{}{
		"iat": float64(1700000000),
		"exp": float64(1700001000),
	}

	if got := getNumericClaim(claims, "iat"); got != 1700000000 {
		t.Errorf("expected 1700000000, got %d", got)
	}
	if got := getNumericClaim(claims, "missing"); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestValidateToken_MissingAuthHeader(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}

	handler := m.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "missing_token" {
		t.Errorf("expected 'missing_token', got '%s'", body["error"])
	}
}

func TestValidateToken_MalformedToken(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}

	handler := m.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestEnforcePolicy_MissingContext(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}
	opaClient := policy.NewOPAClient("http://localhost:1", logger)

	handler := m.EnforcePolicy(opaClient)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestEnforcePolicy_OPAError(t *testing.T) {
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer opaServer.Close()

	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}
	opaClient := policy.NewOPAClient(opaServer.URL, logger)

	handler := m.EnforcePolicy(opaClient)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when OPA returns error")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID: "nurse1",
		TenantID:  "hospital-a",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on OPA error, got %d", w.Code)
	}
}

func TestEnforcePolicy_AccessDenied(t *testing.T) {
	// Mock OPA server that denies
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow":  false,
				"reason": "insufficient privileges",
			},
		})
	}))
	defer opaServer.Close()

	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}
	opaClient := policy.NewOPAClient(opaServer.URL, logger)

	handler := m.EnforcePolicy(opaClient)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when access denied")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID: "nurse1",
		Roles:     []string{"nurse"},
		HasRoles:  true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestEnforcePolicy_AccessAllowed(t *testing.T) {
	// Mock OPA server that allows
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow":  true,
				"reason": "access granted",
				"remove": []string{"identifier"},
				"mask":   []string{"telecom"},
			},
		})
	}))
	defer opaServer.Close()

	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}
	opaClient := policy.NewOPAClient(opaServer.URL, logger)

	handlerCalled := false
	handler := m.EnforcePolicy(opaClient)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		subjectCtx := r.Context().Value(SubjectContextKey).(*SubjectContext)
		if subjectCtx.Policy == nil {
			t.Error("expected policy decision to be set")
		}
		if len(subjectCtx.Policy.Remove) != 1 || subjectCtx.Policy.Remove[0] != "identifier" {
			t.Errorf("expected remove=[identifier], got %v", subjectCtx.Policy.Remove)
		}
		if len(subjectCtx.Policy.Mask) != 1 || subjectCtx.Policy.Mask[0] != "telecom" {
			t.Errorf("expected mask=[telecom], got %v", subjectCtx.Policy.Mask)
		}
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID: "doctor1",
		Roles:     []string{"doctor"},
		HasRoles:  true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !handlerCalled {
		t.Error("next handler should be called when access is allowed")
	}
}

func TestBuildSubjectContext_BasicClaims(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}

	claims := map[string]interface{}{
		"sub": "user-123",
		"azp": "fhir-privacy-proxy",
		"jti": "token-abc",
		"iat": float64(1700000000),
		"exp": float64(1700001000),
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"nurse", "can_break_glass"},
		},
		"fhirContext": map[string]interface{}{
			"department": "cardiology",
			"role":       "nurse",
			"facility":   "main-hospital",
		},
		"scope": "patient/Patient.read patient/Observation.read",
	}

	cfg := mockTenantConfig()
	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)

	ctx, err := m.buildSubjectContext(claims, &cfg, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ctx.SubjectID != "user-123" {
		t.Errorf("expected subject_id user-123, got %s", ctx.SubjectID)
	}
	if ctx.SubjectType != "practitioner" {
		t.Errorf("expected subject_type practitioner, got %s", ctx.SubjectType)
	}
	if len(ctx.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(ctx.Roles))
	}
	if !ctx.HasRoles {
		t.Error("expected HasRoles=true")
	}
	if ctx.FHIRContext.Department != "cardiology" {
		t.Errorf("expected department cardiology, got %s", ctx.FHIRContext.Department)
	}
	if ctx.FHIRContext.Role != "nurse" {
		t.Errorf("expected role nurse, got %s", ctx.FHIRContext.Role)
	}
	if ctx.Client.ID != "fhir-privacy-proxy" {
		t.Errorf("expected client_id fhir-privacy-proxy, got %s", ctx.Client.ID)
	}
	if len(ctx.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(ctx.Scopes))
	}
	if ctx.Session.TokenID != "token-abc" {
		t.Errorf("expected token_id token-abc, got %s", ctx.Session.TokenID)
	}
	if ctx.BreakGlass != nil {
		t.Error("expected no break-glass context")
	}
}

func TestBuildSubjectContext_BreakGlass(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}

	claims := map[string]interface{}{
		"sub": "nurse-1",
		"jti": "token-1",
		"iat": float64(1700000000),
		"exp": float64(1700001000),
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"nurse", "can_break_glass"},
		},
	}

	cfg := mockTenantConfig()
	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	req.Header.Set("X-Break-Glass", "true")
	req.Header.Set("X-Break-Glass-Justification", "Emergency cardiac event")

	ctx, err := m.buildSubjectContext(claims, &cfg, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ctx.BreakGlass == nil {
		t.Fatal("expected break-glass context")
	}
	if !ctx.BreakGlass.Enabled {
		t.Error("expected break-glass enabled")
	}
	if ctx.BreakGlass.Justification != "Emergency cardiac event" {
		t.Errorf("unexpected justification: %s", ctx.BreakGlass.Justification)
	}
}

func TestBuildSubjectContext_BreakGlass_NoPermission(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}

	claims := map[string]interface{}{
		"sub": "nurse-1",
		"jti": "token-1",
		"iat": float64(1700000000),
		"exp": float64(1700001000),
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"nurse"},
		},
	}

	cfg := mockTenantConfig()
	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	req.Header.Set("X-Break-Glass", "true")
	req.Header.Set("X-Break-Glass-Justification", "reason")

	_, err := m.buildSubjectContext(claims, &cfg, req)
	if err == nil {
		t.Error("expected error for break-glass without permission")
	}
}

func TestBuildSubjectContext_BreakGlass_NoJustification(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}

	claims := map[string]interface{}{
		"sub": "nurse-1",
		"jti": "token-1",
		"iat": float64(1700000000),
		"exp": float64(1700001000),
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"nurse", "can_break_glass"},
		},
	}

	cfg := mockTenantConfig()
	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	req.Header.Set("X-Break-Glass", "true")

	_, err := m.buildSubjectContext(claims, &cfg, req)
	if err == nil {
		t.Error("expected error for break-glass without justification")
	}
}

func TestBuildSubjectContext_MissingSub(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}

	claims := map[string]interface{}{
		"jti": "token-1",
	}

	cfg := mockTenantConfig()
	req := httptest.NewRequest("GET", "/", nil)

	_, err := m.buildSubjectContext(claims, &cfg, req)
	if err == nil {
		t.Error("expected error for missing sub claim")
	}
}

func TestBuildSubjectContext_DefaultFHIRContext(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}

	claims := map[string]interface{}{
		"sub": "user-1",
		"jti": "token-1",
		"iat": float64(1700000000),
		"exp": float64(1700001000),
	}

	cfg := mockTenantConfig()
	req := httptest.NewRequest("GET", "/", nil)

	ctx, err := m.buildSubjectContext(claims, &cfg, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ctx.FHIRContext.Department != "UNKNOWN" {
		t.Errorf("expected default department UNKNOWN, got %s", ctx.FHIRContext.Department)
	}
	if ctx.FHIRContext.Role != "unknown" {
		t.Errorf("expected default role unknown, got %s", ctx.FHIRContext.Role)
	}
	if ctx.FHIRContext.Facility != "main-hospital" {
		t.Errorf("expected default facility main-hospital, got %s", ctx.FHIRContext.Facility)
	}
}

type mockRevocationChecker struct {
	revoked bool
	err     error
}

func (m *mockRevocationChecker) IsRevoked(_, _ string, _ int64) (bool, error) {
	return m.revoked, m.err
}

func TestValidateToken_ValidJWT_PassThrough(t *testing.T) {
	h := newJWTHelper(t)
	defer h.close()
	reg := buildRegistry(t, h)
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(reg, logger)

	token := h.sign(t, jwt.MapClaims{
		"iss": h.issuer, "sub": "nurse1", "aud": h.audience,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "jti": "tok-1",
		"realm_access": map[string]interface{}{"roles": []interface{}{"nurse"}},
		"fhirContext":  map[string]interface{}{"department": "cardiology", "role": "nurse"},
		"scope":        "patient/Patient.read",
	})

	called := false
	handler := m.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		sub := r.Context().Value(SubjectContextKey).(*SubjectContext)
		if sub.SubjectID != "nurse1" {
			t.Errorf("expected subject nurse1, got %s", sub.SubjectID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler should be called for valid token")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestValidateToken_RevokedToken(t *testing.T) {
	h := newJWTHelper(t)
	defer h.close()
	reg := buildRegistry(t, h)
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(reg, logger)
	m.SetRevocationChecker(&mockRevocationChecker{revoked: true})

	token := h.sign(t, jwt.MapClaims{
		"iss": h.issuer, "sub": "nurse1", "aud": h.audience,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "jti": "tok-revoked",
		"scope": "patient/Patient.read",
	})

	handler := m.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for revoked token")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked token, got %d", w.Code)
	}
}

func TestValidateToken_RevocationCheckError_FailOpen(t *testing.T) {
	h := newJWTHelper(t)
	defer h.close()
	reg := buildRegistry(t, h)
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(reg, logger)
	m.SetRevocationChecker(&mockRevocationChecker{err: context.DeadlineExceeded})

	token := h.sign(t, jwt.MapClaims{
		"iss": h.issuer, "sub": "nurse1", "aud": h.audience,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "jti": "tok-err",
		"scope": "patient/Patient.read",
	})

	called := false
	handler := m.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler should be called when revocation check errors (fail-open)")
	}
}

func TestValidateToken_InvalidClaims_MissingSub(t *testing.T) {
	h := newJWTHelper(t)
	defer h.close()
	reg := buildRegistry(t, h)
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(reg, logger)

	// Token with no "sub" claim — buildSubjectContext should fail.
	token := h.sign(t, jwt.MapClaims{
		"iss": h.issuer, "aud": h.audience,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"scope": "patient/Patient.read",
	})

	handler := m.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for missing sub")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing sub, got %d", w.Code)
	}
}

func TestValidateToken_InsufficientScope(t *testing.T) {
	h := newJWTHelper(t)
	defer h.close()
	reg := buildRegistry(t, h)
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(reg, logger)

	token := h.sign(t, jwt.MapClaims{
		"iss": h.issuer, "sub": "nurse1", "aud": h.audience,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "jti": "tok-2",
		"scope": "admin/all",
	})

	handler := m.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for insufficient scope")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for insufficient scope, got %d", w.Code)
	}
}

func TestHasValidScope(t *testing.T) {
	tests := []struct {
		name     string
		token    []string
		allowed  []string
		expected bool
	}{
		{"matching scope", []string{"patient/Patient.read"}, []string{"patient/Patient.read", "patient/Observation.read"}, true},
		{"no match", []string{"admin/all"}, []string{"patient/Patient.read"}, false},
		{"empty token scopes", []string{}, []string{"patient/Patient.read"}, false},
		{"empty allowed scopes", []string{"patient/Patient.read"}, []string{}, false},
		{"multiple matches", []string{"patient/Patient.read", "patient/Observation.read"}, []string{"patient/Patient.read"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasValidScope(tt.token, tt.allowed)
			if got != tt.expected {
				t.Errorf("hasValidScope(%v, %v) = %v, want %v", tt.token, tt.allowed, got, tt.expected)
			}
		})
	}
}
