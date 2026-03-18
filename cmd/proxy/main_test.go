package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vikram290227/fhir-privacy-proxy/internal/auth"
	"go.uber.org/zap"
)

func TestFhirProxyHandler_NoAuthContext(t *testing.T) {
	handler := fhirProxyHandler("http://localhost:8090/fhir", http.DefaultClient, mustLogger(t), nil)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestFhirProxyHandler_UpstreamUnreachable(t *testing.T) {
	handler := fhirProxyHandler("http://localhost:1", http.DefaultClient, mustLogger(t), nil)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	ctx := context.WithValue(req.Context(), auth.SubjectContextKey, &auth.SubjectContext{
		SubjectID: "nurse1",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", w.Code)
	}
}

func TestFhirProxyHandler_ProxiesAndRedacts(t *testing.T) {
	// Mock upstream FHIR server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/fhir/Patient/123" {
			t.Errorf("unexpected upstream path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/fhir+json")
		w.Header().Set("ETag", `W/"1"`)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"resourceType": "Patient",
			"id":           "123",
			"identifier":   []map[string]string{{"value": "MRN001"}},
			"telecom":      []map[string]string{{"system": "phone", "value": "555-1234"}},
			"address":      []map[string]string{{"city": "NYC"}},
			"name":         []map[string]string{{"family": "Smith"}},
		})
	}))
	defer upstream.Close()

	handler := fhirProxyHandler(upstream.URL+"/fhir", http.DefaultClient, mustLogger(t), nil)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	ctx := context.WithValue(req.Context(), auth.SubjectContextKey, &auth.SubjectContext{
		SubjectID: "nurse1",
		Policy: &auth.PolicyDecision{
			Remove: []string{"identifier"},
			Mask:   []string{"telecom", "address"},
		},
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if w.Header().Get("Content-Type") != "application/fhir+json" {
		t.Errorf("expected application/fhir+json, got %s", w.Header().Get("Content-Type"))
	}
	if w.Header().Get("ETag") != `W/"1"` {
		t.Errorf("expected ETag to be copied, got %s", w.Header().Get("ETag"))
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)

	if _, exists := result["identifier"]; exists {
		t.Error("identifier should be removed")
	}
	if result["telecom"] != "***REDACTED***" {
		t.Errorf("telecom should be masked, got %v", result["telecom"])
	}
	if result["address"] != "***REDACTED***" {
		t.Errorf("address should be masked, got %v", result["address"])
	}
	if result["name"] == nil {
		t.Error("name should be preserved")
	}
}

func TestFhirProxyHandler_NoRedactionPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/fhir+json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"resourceType": "Patient",
			"id":           "123",
			"identifier":   []map[string]string{{"value": "MRN001"}},
		})
	}))
	defer upstream.Close()

	handler := fhirProxyHandler(upstream.URL+"/fhir", http.DefaultClient, mustLogger(t), nil)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	ctx := context.WithValue(req.Context(), auth.SubjectContextKey, &auth.SubjectContext{
		SubjectID: "doctor1",
		// No policy decision = no redaction
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)

	if result["identifier"] == nil {
		t.Error("identifier should be present when no redaction policy")
	}
}

func TestFhirProxyHandler_NonJSONPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	}))
	defer upstream.Close()

	handler := fhirProxyHandler(upstream.URL+"/fhir", http.DefaultClient, mustLogger(t), nil)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/999", nil)
	ctx := context.WithValue(req.Context(), auth.SubjectContextKey, &auth.SubjectContext{
		SubjectID: "nurse1",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
	if w.Body.String() != "Not Found" {
		t.Errorf("expected passthrough body, got %s", w.Body.String())
	}
}

func TestFhirProxyHandler_QueryParams(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "name=Smith" {
			t.Errorf("expected query name=Smith, got %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/fhir+json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"resourceType": "Bundle",
			"type":         "searchset",
			"entry":        []interface{}{},
		})
	}))
	defer upstream.Close()

	handler := fhirProxyHandler(upstream.URL+"/fhir", http.DefaultClient, mustLogger(t), nil)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient?name=Smith", nil)
	ctx := context.WithValue(req.Context(), auth.SubjectContextKey, &auth.SubjectContext{
		SubjectID: "nurse1",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCopyResponseHeaders(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Etag":          []string{`W/"1"`},
			"Last-Modified": []string{"Mon, 01 Jan 2024 00:00:00 GMT"},
			"X-Request-Id":  []string{"abc-123"},
			"Server":        []string{"HAPI"},
		},
	}

	w := httptest.NewRecorder()
	copyResponseHeaders(w, resp)

	if w.Header().Get("ETag") != `W/"1"` {
		t.Errorf("expected ETag to be copied")
	}
	if w.Header().Get("Last-Modified") != "Mon, 01 Jan 2024 00:00:00 GMT" {
		t.Errorf("expected Last-Modified to be copied")
	}
	if w.Header().Get("X-Request-Id") != "abc-123" {
		t.Errorf("expected X-Request-Id to be copied")
	}
	if w.Header().Get("Server") != "" {
		t.Errorf("Server header should not be copied")
	}
}

func TestExtractResourceType(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/fhir/r4/Patient/123", "Patient"},
		{"/fhir/r4/Observation", "Observation"},
		{"/fhir/r4/Condition/456", "Condition"},
		{"/other/path", "unknown"},
		{"/", "unknown"},
	}

	for _, tt := range tests {
		got := extractResourceType(tt.path)
		if got != tt.expected {
			t.Errorf("extractResourceType(%s) = %s, want %s", tt.path, got, tt.expected)
		}
	}
}

func mustLogger(t *testing.T) *zap.Logger {
	t.Helper()
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	return logger
}
