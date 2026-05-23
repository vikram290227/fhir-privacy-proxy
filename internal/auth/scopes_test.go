package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestMethodAction(t *testing.T) {
	tests := map[string]string{
		"GET":    "read",
		"HEAD":   "read",
		"POST":   "write",
		"PUT":    "write",
		"PATCH":  "write",
		"DELETE": "write",
		"BOGUS":  "",
	}
	for m, want := range tests {
		if got := methodAction(m); got != want {
			t.Errorf("methodAction(%q) = %q, want %q", m, got, want)
		}
	}
}

func TestParseScope(t *testing.T) {
	cases := []struct {
		in                    string
		level, resource, act  string
		ok                    bool
	}{
		{"patient/Patient.read", "patient", "Patient", "read", true},
		{"user/Observation.write", "user", "Observation", "write", true},
		{"system/*.read", "system", "*", "read", true},
		{"user/Patient.rs", "user", "Patient", "rs", true},
		{"malformed", "", "", "", false},
		{"/Patient.read", "", "", "", false},
		{"patient/Patient", "", "", "", false},
	}
	for _, c := range cases {
		l, r, a, ok := parseScope(c.in)
		if ok != c.ok || l != c.level || r != c.resource || a != c.act {
			t.Errorf("parseScope(%q) = (%q,%q,%q,%v), want (%q,%q,%q,%v)",
				c.in, l, r, a, ok, c.level, c.resource, c.act, c.ok)
		}
	}
}

func TestScopesAllow(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		resource string
		action   string
		allow    bool
	}{
		{"exact read", []string{"patient/Patient.read"}, "Patient", "read", true},
		{"exact write", []string{"user/Observation.write"}, "Observation", "write", true},
		{"wildcard resource", []string{"system/*.read"}, "Patient", "read", true},
		{"wildcard action", []string{"user/Patient.*"}, "Patient", "write", true},
		{"mismatch resource", []string{"patient/Observation.read"}, "Patient", "read", false},
		{"mismatch action", []string{"patient/Patient.read"}, "Patient", "write", false},
		{"smart v2 read", []string{"user/Patient.rs"}, "Patient", "read", true},
		{"smart v2 write", []string{"user/Patient.cud"}, "Patient", "write", true},
		{"empty scopes", nil, "Patient", "read", false},
		{"garbage", []string{"junk"}, "Patient", "read", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scopesAllow(tt.scopes, tt.resource, tt.action)
			if got != tt.allow {
				t.Errorf("scopesAllow(%v, %q, %q) = %v, want %v",
					tt.scopes, tt.resource, tt.action, got, tt.allow)
			}
		})
	}
}

func TestExtractFhirResourceType(t *testing.T) {
	cases := map[string]string{
		"/fhir/r4/Patient/123":        "Patient",
		"/fhir/r4/Observation":        "Observation",
		"/fhir/r4/Condition/c1/_hist": "Condition",
		"/health":                     "",
		"/":                           "",
	}
	for in, want := range cases {
		if got := extractFhirResourceType(in); got != want {
			t.Errorf("extractFhirResourceType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRequireSmartScope_Allowed(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}

	called := false
	handler := m.RequireSmartScope(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID: "nurse1",
		Scopes:    []string{"patient/Patient.read"},
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected handler to be called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRequireSmartScope_Denied_NoScope(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}

	handler := m.RequireSmartScope(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when scope is missing")
	}))

	req := httptest.NewRequest("POST", "/fhir/r4/Observation", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID: "nurse1",
		Scopes:    []string{"patient/Patient.read"}, // no write scope
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "insufficient_scope" {
		t.Errorf("expected insufficient_scope, got %v", body)
	}
}

func TestRequireSmartScope_NonFhirPath(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}

	called := false
	handler := m.RequireSmartScope(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID: "nurse1",
		Scopes:    nil,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected handler to be called for non-FHIR path")
	}
}

func TestRequireSmartScope_MissingContext(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}

	handler := m.RequireSmartScope(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without subject context")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestScopeCovers_InvalidLevel(t *testing.T) {
	if scopeCovers("admin/Patient.read", "Patient", "read") {
		t.Error("expected false for unsupported level 'admin'")
	}
}

func TestActionMatches_V2Granular_UnknownNeed(t *testing.T) {
	if actionMatches("rs", "delete") {
		t.Error("expected false for v2 granular with unknown need 'delete'")
	}
}

func TestIsV2Granular_EmptyString(t *testing.T) {
	if isV2Granular("") {
		t.Error("expected false for empty string")
	}
}

func TestRequireSmartScope_MethodNotAllowed(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)

	handler := m.RequireSmartScope(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for unsupported method")
	}))

	req := httptest.NewRequest("CONNECT", "/fhir/r4/Patient/1", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID: "nurse1",
		Scopes:    []string{"patient/Patient.read"},
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}
