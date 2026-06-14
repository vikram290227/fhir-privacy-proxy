package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/risk"
)

func TestScoreRisk_MissingContext(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)
	client := risk.NewClient("http://localhost:1", logger)

	handler := m.ScoreRisk(client)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestScoreRisk_ClientError_FailOpen(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)
	client := risk.NewClient("http://localhost:1", logger)

	called := false
	handler := m.ScoreRisk(client)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		sub := r.Context().Value(SubjectContextKey).(*SubjectContext)
		if sub.Risk == nil {
			t.Error("expected risk decision even on error")
		}
		if sub.Risk.Score != 0 {
			t.Errorf("expected score=0 on error, got %f", sub.Risk.Score)
		}
		if !sub.Risk.Unavailable {
			t.Error("expected Unavailable=true when risk client errors")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID:   "nurse1",
		FHIRContext: FHIRContext{Role: "nurse", Department: "cardiology"},
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler should be called when risk client errors (fail-open)")
	}
}

func TestScoreRisk_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"score":       0.2,
			"label":       "normal",
			"explanation": map[string]float64{"hour": 0.1},
		})
	}))
	defer srv.Close()

	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)
	client := risk.NewClientWithTimeout(srv.URL, 2*time.Second, logger)

	called := false
	handler := m.ScoreRisk(client)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		sub := r.Context().Value(SubjectContextKey).(*SubjectContext)
		if sub.Risk == nil {
			t.Fatal("expected risk decision")
		}
		if sub.Risk.Label != "normal" {
			t.Errorf("expected label=normal, got %s", sub.Risk.Label)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID:   "nurse1",
		FHIRContext: FHIRContext{Role: "nurse", Department: "cardiology"},
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler should be called on successful risk score")
	}
}
