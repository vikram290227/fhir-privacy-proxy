package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/ratelimit"
)

type allowRL struct{}

func (a *allowRL) Allow(_ context.Context, _, _ string, minLimit, hourLimit int) (ratelimit.Decision, error) {
	return ratelimit.Decision{
		Allowed:         true,
		LimitMinute:     minLimit,
		LimitHour:       hourLimit,
		RemainingMinute: int64(minLimit - 1),
		RemainingHour:   int64(hourLimit - 1),
	}, nil
}

type denyRL struct{}

func (d *denyRL) Allow(_ context.Context, _, _ string, minLimit, hourLimit int) (ratelimit.Decision, error) {
	return ratelimit.Decision{
		Allowed:     false,
		LimitMinute: minLimit,
		LimitHour:   hourLimit,
		Reason:      "minute",
		RetryAfter:  30 * time.Second,
	}, nil
}

type errRL struct{}

func (e *errRL) Allow(_ context.Context, _, _ string, _, _ int) (ratelimit.Decision, error) {
	return ratelimit.Decision{}, context.DeadlineExceeded
}

func TestRateLimit_NilLimiter(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)

	called := false
	handler := m.RateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler should be called when limiter is nil")
	}
}

func TestRateLimit_MissingSubjectContext(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)
	m.SetRateLimiter(&allowRL{})

	handler := m.RateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called without subject context")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestRateLimit_Allowed(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)
	m.SetRateLimiter(&allowRL{})

	called := false
	handler := m.RateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID: "nurse1",
		TenantID:  "hospital-a",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler should be called when allowed")
	}
	if w.Header().Get("X-RateLimit-Limit-Minute") == "" {
		t.Error("expected X-RateLimit-Limit-Minute header")
	}
}

func TestRateLimit_Denied(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)
	m.SetRateLimiter(&denyRL{})

	handler := m.RateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called when rate limited")
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID: "nurse1",
		TenantID:  "hospital-a",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}
}

func TestRateLimit_LimiterError_FailOpen(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)
	m.SetRateLimiter(&errRL{})

	called := false
	handler := m.RateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/1", nil)
	ctx := context.WithValue(req.Context(), SubjectContextKey, &SubjectContext{
		SubjectID: "nurse1",
		TenantID:  "hospital-a",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("next handler should be called on limiter error (fail-open)")
	}
}

func TestWriteRateLimitHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	d := ratelimit.Decision{
		LimitMinute:     60,
		LimitHour:       600,
		RemainingMinute: 59,
		RemainingHour:   599,
		ResetMinute:     1716000060,
		ResetHour:       1716003600,
	}
	writeRateLimitHeaders(w, d)

	checks := map[string]string{
		"X-RateLimit-Limit-Minute":     "60",
		"X-RateLimit-Limit-Hour":       "600",
		"X-RateLimit-Remaining-Minute": "59",
		"X-RateLimit-Remaining-Hour":   "599",
		"X-RateLimit-Reset-Minute":     "1716000060",
		"X-RateLimit-Reset-Hour":       "1716003600",
	}
	for h, want := range checks {
		if got := w.Header().Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
}

func TestWriteRateLimitHeaders_ZeroResets(t *testing.T) {
	w := httptest.NewRecorder()
	writeRateLimitHeaders(w, ratelimit.Decision{LimitMinute: 10, LimitHour: 100})

	if w.Header().Get("X-RateLimit-Reset-Minute") != "" {
		t.Error("expected no Reset-Minute header when reset=0")
	}
	if w.Header().Get("X-RateLimit-Reset-Hour") != "" {
		t.Error("expected no Reset-Hour header when reset=0")
	}
}

func TestSetRateLimiter(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := NewMiddleware(nil, logger)
	if m.rateLimiter != nil {
		t.Error("expected nil rate limiter by default")
	}
	m.SetRateLimiter(&allowRL{})
	if m.rateLimiter == nil {
		t.Error("expected non-nil rate limiter after set")
	}
}
