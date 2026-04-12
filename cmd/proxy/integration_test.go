package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vikram290227/fhir-privacy-proxy/internal/auth"
	"github.com/vikram290227/fhir-privacy-proxy/internal/policy"
	"go.uber.org/zap"
)

// TestProxyFlow_NurseRedacted simulates the full proxy pipeline: a
// SubjectContext is injected into the request (as ValidateToken would
// do), EnforcePolicy runs against a mock OPA that applies
// nurse-like redactions, and the fhirProxyHandler fetches the patient
// from a mock upstream and applies the returned redaction paths.
func TestProxyFlow_NurseRedacted(t *testing.T) {
	// Mock OPA: returns allow + nurse redaction paths.
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"allow":  true,
				"reason": "authorized",
				"remove": []string{"identifier"},
				"mask":   []string{"telecom", "address"},
			},
		})
	}))
	defer opaServer.Close()

	// Mock upstream FHIR: returns a fully populated Patient.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/fhir+json")
		json.NewEncoder(w).Encode(map[string]any{
			"resourceType": "Patient",
			"id":           "123",
			"identifier":   []map[string]string{{"system": "mrn", "value": "A1"}},
			"telecom":      []map[string]string{{"system": "phone", "value": "555-1234"}},
			"address":      []map[string]string{{"city": "NYC"}},
			"name":         []map[string]string{{"family": "Smith"}},
		})
	}))
	defer upstream.Close()

	opaClient := policy.NewOPAClient(opaServer.URL, zap.NewNop())
	authMw := auth.NewMiddleware(nil, zap.NewNop())

	// Build the handler chain: EnforcePolicy -> fhirProxyHandler.
	chain := authMw.EnforcePolicy(opaClient)(http.HandlerFunc(
		fhirProxyHandler(upstream.URL+"/fhir", http.DefaultClient, zap.NewNop(), nil),
	))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	ctx := context.WithValue(req.Context(), auth.SubjectContextKey, &auth.SubjectContext{
		SubjectID: "nurse1",
		Roles:     []string{"nurse"},
		HasRoles:  true,
		FHIRContext: auth.FHIRContext{
			Role:       "nurse",
			Department: "cardiology",
		},
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	chain.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var got map[string]any
	json.NewDecoder(w.Body).Decode(&got)

	if _, exists := got["identifier"]; exists {
		t.Error("nurse should not see identifier")
	}
	if got["telecom"] != "***REDACTED***" {
		t.Errorf("telecom should be masked, got %v", got["telecom"])
	}
	if got["address"] != "***REDACTED***" {
		t.Errorf("address should be masked, got %v", got["address"])
	}
}

// TestProxyFlow_Denied verifies the fhirProxyHandler is never called
// when EnforcePolicy returns deny.
func TestProxyFlow_Denied(t *testing.T) {
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"allow":  false,
				"reason": "sensitive_patient",
			},
		})
	}))
	defer opaServer.Close()

	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	opaClient := policy.NewOPAClient(opaServer.URL, zap.NewNop())
	authMw := auth.NewMiddleware(nil, zap.NewNop())

	chain := authMw.EnforcePolicy(opaClient)(http.HandlerFunc(
		fhirProxyHandler(upstream.URL+"/fhir", http.DefaultClient, zap.NewNop(), nil),
	))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/999", nil)
	ctx := context.WithValue(req.Context(), auth.SubjectContextKey, &auth.SubjectContext{
		SubjectID: "nurse1",
		HasRoles:  true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	chain.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
	if upstreamCalled {
		t.Error("upstream should NOT be called when access denied")
	}
	if !strings.Contains(w.Body.String(), "sensitive_patient") {
		t.Errorf("expected reason in body, got %s", w.Body.String())
	}
}

// TestProxyFlow_BreakGlass verifies break-glass access returns the
// full unredacted resource.
func TestProxyFlow_BreakGlass(t *testing.T) {
	opaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"allow":  true,
				"reason": "break_glass_access",
				// No remove/mask -> full access
			},
		})
	}))
	defer opaServer.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/fhir+json")
		json.NewEncoder(w).Encode(map[string]any{
			"resourceType": "Patient",
			"id":           "999",
			"identifier":   []map[string]string{{"value": "SENS-1"}},
			"telecom":      []map[string]string{{"value": "555"}},
		})
	}))
	defer upstream.Close()

	opaClient := policy.NewOPAClient(opaServer.URL, zap.NewNop())
	authMw := auth.NewMiddleware(nil, zap.NewNop())

	chain := authMw.EnforcePolicy(opaClient)(http.HandlerFunc(
		fhirProxyHandler(upstream.URL+"/fhir", http.DefaultClient, zap.NewNop(), nil),
	))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/999", nil)
	ctx := context.WithValue(req.Context(), auth.SubjectContextKey, &auth.SubjectContext{
		SubjectID: "nurse1",
		HasRoles:  true,
		BreakGlass: &auth.BreakGlassContext{
			Enabled:       true,
			Justification: "Emergency",
			RequestedBy:   "nurse1",
		},
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	chain.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var got map[string]any
	json.NewDecoder(w.Body).Decode(&got)
	if got["identifier"] == nil {
		t.Error("break-glass should preserve identifier")
	}
	if got["telecom"] == "***REDACTED***" {
		t.Error("break-glass should not mask telecom")
	}
}
