package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vikram290227/fhir-privacy-proxy/internal/audit"
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

func TestMetadataProxyHandler_RewritesURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/fhir/metadata" {
			t.Errorf("unexpected upstream path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/fhir+json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"resourceType": "CapabilityStatement",
			"url":          "http://upstream:8080/fhir",
			"status":       "active",
			"implementation": map[string]interface{}{
				"url":         "http://upstream:8080/fhir",
				"description": "HAPI FHIR",
			},
		})
	}))
	defer upstream.Close()

	handler := metadataProxyHandler(upstream.URL+"/fhir", http.DefaultClient, mustLogger(t))

	req := httptest.NewRequest("GET", "/fhir/r4/metadata", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Type") != "application/fhir+json" {
		t.Errorf("expected application/fhir+json, got %s", w.Header().Get("Content-Type"))
	}

	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)

	expectedURL := "http://example.com/fhir/r4"
	if result["url"] != expectedURL {
		t.Errorf("expected url=%s, got %v", expectedURL, result["url"])
	}
	impl, ok := result["implementation"].(map[string]interface{})
	if !ok {
		t.Fatal("implementation field missing or wrong type")
	}
	if impl["url"] != expectedURL {
		t.Errorf("expected implementation.url=%s, got %v", expectedURL, impl["url"])
	}
}

func TestMetadataProxyHandler_UpstreamUnreachable(t *testing.T) {
	handler := metadataProxyHandler("http://localhost:1", http.DefaultClient, mustLogger(t))

	req := httptest.NewRequest("GET", "/fhir/r4/metadata", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", w.Code)
	}
}

func TestMetadataProxyHandler_NoAuthRequired(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/fhir+json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"resourceType": "CapabilityStatement",
			"status":       "active",
		})
	}))
	defer upstream.Close()

	handler := metadataProxyHandler(upstream.URL+"/fhir", http.DefaultClient, mustLogger(t))

	req := httptest.NewRequest("GET", "/fhir/r4/metadata", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 without any auth context, got %d", w.Code)
	}
}

func TestMetadataProxyHandler_NonJSONPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<CapabilityStatement/>"))
	}))
	defer upstream.Close()

	handler := metadataProxyHandler(upstream.URL+"/fhir", http.DefaultClient, mustLogger(t))

	req := httptest.NewRequest("GET", "/fhir/r4/metadata", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "<CapabilityStatement/>" {
		t.Errorf("expected XML passthrough, got %s", w.Body.String())
	}
}

func TestRewriteCapabilityStatementURL(t *testing.T) {
	input := `{"resourceType":"CapabilityStatement","url":"http://old/fhir","implementation":{"url":"http://old/fhir","description":"Old"}}`
	result := rewriteCapabilityStatementURL([]byte(input), "http://proxy:8080/fhir/r4")

	var cs map[string]interface{}
	json.Unmarshal(result, &cs)

	if cs["url"] != "http://proxy:8080/fhir/r4" {
		t.Errorf("expected url rewritten, got %v", cs["url"])
	}
	impl := cs["implementation"].(map[string]interface{})
	if impl["url"] != "http://proxy:8080/fhir/r4" {
		t.Errorf("expected implementation.url rewritten, got %v", impl["url"])
	}
	if impl["description"] != "Old" {
		t.Errorf("expected description preserved, got %v", impl["description"])
	}
}

func TestRewriteCapabilityStatementURL_InvalidJSON(t *testing.T) {
	input := []byte("not json")
	result := rewriteCapabilityStatementURL(input, "http://proxy/fhir/r4")
	if string(result) != "not json" {
		t.Errorf("expected invalid JSON to pass through unchanged")
	}
}

type mockAuditSink struct {
	events []audit.AuditEvent
}

func (m *mockAuditSink) Log(e audit.AuditEvent) { m.events = append(m.events, e) }

func TestMetadataProxyHandler_HTTPSScheme(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/fhir+json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"resourceType": "CapabilityStatement",
			"implementation": map[string]interface{}{
				"url":         "http://old-server/fhir/r4",
				"description": "Old",
			},
		})
	}))
	defer upstream.Close()

	handler := metadataProxyHandler(upstream.URL+"/fhir", http.DefaultClient, mustLogger(t))
	req := httptest.NewRequest("GET", "/fhir/r4/metadata", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Host = "proxy:8080"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	impl := result["implementation"].(map[string]interface{})
	if impl["url"] != "https://proxy:8080/fhir/r4" {
		t.Errorf("expected https URL, got %v", impl["url"])
	}
}

func TestFhirProxyHandler_AuditLogger_BreakGlass(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/fhir+json")
		json.NewEncoder(w).Encode(map[string]interface{}{"resourceType": "Patient", "id": "123"})
	}))
	defer upstream.Close()

	sink := &mockAuditSink{}
	handler := fhirProxyHandler(upstream.URL+"/fhir", http.DefaultClient, mustLogger(t), sink)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	ctx := context.WithValue(req.Context(), auth.SubjectContextKey, &auth.SubjectContext{
		SubjectID: "nurse1",
		TenantID:  "hospital-a",
		BreakGlass: &auth.BreakGlassContext{
			Enabled:       true,
			Justification: "Emergency",
			RequestedBy:   "nurse1",
		},
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	if sink.events[0].EventType != audit.EventBreakGlass {
		t.Errorf("expected BREAK_GLASS event, got %v", sink.events[0].EventType)
	}
}

func TestFhirProxyHandler_AuditLogger_WithRedaction(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/fhir+json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"resourceType": "Patient", "id": "1",
			"identifier": []map[string]string{{"value": "MRN"}},
		})
	}))
	defer upstream.Close()

	sink := &mockAuditSink{}
	handler := fhirProxyHandler(upstream.URL+"/fhir", http.DefaultClient, mustLogger(t), sink)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	ctx := context.WithValue(req.Context(), auth.SubjectContextKey, &auth.SubjectContext{
		SubjectID: "nurse1",
		TenantID:  "hospital-a",
		Policy:    &auth.PolicyDecision{Remove: []string{"identifier"}},
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(sink.events) != 1 || len(sink.events[0].RedactedPaths) == 0 {
		t.Errorf("expected audit event with redacted paths, got: %+v", sink.events)
	}
}

func TestFhirProxyHandler_MalformedJSON_Passthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/fhir+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json"))
	}))
	defer upstream.Close()

	handler := fhirProxyHandler(upstream.URL+"/fhir", http.DefaultClient, mustLogger(t), nil)
	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	ctx := context.WithValue(req.Context(), auth.SubjectContextKey, &auth.SubjectContext{
		SubjectID: "nurse1",
		Policy:    &auth.PolicyDecision{Remove: []string{"id"}},
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 passthrough for malformed JSON, got %d", w.Code)
	}
	if w.Body.String() != "not valid json" {
		t.Errorf("expected raw body passthrough, got: %s", w.Body.String())
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
