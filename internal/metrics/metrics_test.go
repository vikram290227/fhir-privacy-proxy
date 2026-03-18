package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/fhir/r4/Patient/123", "/fhir/r4/Patient/:id"},
		{"/fhir/r4/Patient", "/fhir/r4/Patient"},
		{"/fhir/r4/Observation/456", "/fhir/r4/Observation/:id"},
		{"/health", "/health"},
		{"/metrics", "/metrics"},
	}

	for _, tt := range tests {
		got := normalizePath(tt.input)
		if got != tt.expected {
			t.Errorf("normalizePath(%s) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}

func TestInstrumentHandler(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	handler := InstrumentHandler(inner)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandler(t *testing.T) {
	handler := Handler()
	if handler == nil {
		t.Error("expected non-nil metrics handler")
	}

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if len(body) == 0 {
		t.Error("expected non-empty metrics output")
	}
}
