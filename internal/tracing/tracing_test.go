package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInit(t *testing.T) {
	shutdown := Init()
	if shutdown == nil {
		t.Error("expected non-nil shutdown function")
	}

	err := shutdown(context.Background())
	if err != nil {
		t.Errorf("unexpected shutdown error: %v", err)
	}
}

func TestTracer(t *testing.T) {
	_ = Init()
	tracer := Tracer()
	if tracer == nil {
		t.Error("expected non-nil tracer")
	}
}

func TestMiddleware(t *testing.T) {
	_ = Init()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span := SpanFromContext(r.Context())
		if span == nil {
			t.Error("expected span in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(inner)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
