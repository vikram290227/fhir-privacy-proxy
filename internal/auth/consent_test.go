package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/consent"
)

func TestCheckConsent_NilChecker(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)

	called := false
	handler := m.CheckConsent(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler should be called when checker is nil")
	}
}

func TestCheckConsent_MissingSubjectContext(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)

	checker, _ := consent.NewChecker("http://localhost:1", logger, 10, 0)
	handler := m.CheckConsent(checker)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestCheckConsent_NoPatientID(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)

	checker, _ := consent.NewChecker("http://localhost:1", logger, 10, 0)

	called := false
	handler := m.CheckConsent(checker)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	// /fhir/r4/Patient with no ID — no patient-specific consent to look up
	req := httptest.NewRequest("GET", "/fhir/r4/Patient", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID:    "nurse1",
		PurposeOfUse: "TREATMENT",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler should be called when no patient ID in path")
	}
}

func TestCheckConsent_InvalidPurpose(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)

	checker, _ := consent.NewChecker("http://localhost:1", logger, 10, 0)

	handler := m.CheckConsent(checker)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for invalid purpose")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/patient-1", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID:    "nurse1",
		PurposeOfUse: "INVALID_PURPOSE",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCheckConsent_LookupFail_PassThrough(t *testing.T) {
	// Upstream unreachable → fail-open: next handler still called
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)

	checker, _ := consent.NewChecker("http://localhost:1", logger, 10, 0)

	called := false
	handler := m.CheckConsent(checker)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/patient-1", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID:    "nurse1",
		PurposeOfUse: "TREATMENT",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler should be called when consent lookup fails (fail-open)")
	}
}
