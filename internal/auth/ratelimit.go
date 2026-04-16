package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/metrics"
	"github.com/vikram290227/fhir-privacy-proxy/internal/ratelimit"
	"github.com/vikram290227/fhir-privacy-proxy/internal/tenant"
)

// RateLimiter is the narrow interface the auth middleware needs from
// the internal/ratelimit package. Defined here so tests can inject a
// fake without pulling in Redis.
type RateLimiter interface {
	Allow(ctx context.Context, tenantID, subjectID string, minLimit, hourLimit int) (ratelimit.Decision, error)
}

// SetRateLimiter wires in a rate limiter. When nil (default), the
// RateLimit middleware is a no-op.
func (m *Middleware) SetRateLimiter(rl RateLimiter) {
	m.rateLimiter = rl
}

// RateLimit enforces per-(tenant, subject) sliding-window rate limits.
// Must run after ValidateToken (which populates SubjectContext) and
// before ScoreRisk — the risk-scoring call is the most expensive leg
// of the pipeline and should not be incurred for requests that are
// about to be rejected with 429.
//
// When no RateLimiter has been registered (e.g. REDIS_ADDR unset at
// boot) this middleware passes every request through untouched, so the
// ML-based risk layer remains the backstop as before.
func (m *Middleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.rateLimiter == nil {
			next.ServeHTTP(w, r)
			return
		}

		sub, ok := r.Context().Value(SubjectContextKey).(*SubjectContext)
		if !ok || sub == nil {
			respondWithError(w, http.StatusInternalServerError, "internal_error", "missing auth context")
			return
		}

		// Per-tenant limits come from the registry (which applied
		// defaults at load time). If for some reason the tenant is
		// missing or the limits are zero, fall back to the package
		// defaults so we never silently degrade to no-limit.
		minLimit, hourLimit := tenant.DefaultRequestsPerMinute, tenant.DefaultRequestsPerHour
		if m.tenantRegistry != nil {
			if cfg, err := m.tenantRegistry.GetByID(sub.TenantID); err == nil {
				if cfg.RequestsPerMinute > 0 {
					minLimit = cfg.RequestsPerMinute
				}
				if cfg.RequestsPerHour > 0 {
					hourLimit = cfg.RequestsPerHour
				}
			}
		}

		ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
		defer cancel()

		decision, err := m.rateLimiter.Allow(ctx, sub.TenantID, sub.SubjectID, minLimit, hourLimit)
		if err != nil {
			// Fail open on infrastructure errors — rate limiting is a
			// backstop, not a correctness gate. The ML + OPA layers
			// still run. Log loudly so operators notice.
			m.logger.Warn("rate limiter unavailable, allowing request",
				zap.String("tenant", sub.TenantID),
				zap.String("subject", sub.SubjectID),
				zap.Error(err))
			writeRateLimitHeaders(w, ratelimit.Decision{
				LimitMinute:     minLimit,
				LimitHour:       hourLimit,
				RemainingMinute: int64(minLimit),
				RemainingHour:   int64(hourLimit),
			})
			next.ServeHTTP(w, r)
			return
		}

		writeRateLimitHeaders(w, decision)

		if !decision.Allowed {
			metrics.RateLimitHits.WithLabelValues(sub.TenantID, sub.SubjectID, decision.Reason).Inc()
			retry := int(decision.RetryAfter.Seconds())
			if retry < 1 {
				retry = 1
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retry))
			m.logger.Info("rate limit exceeded",
				zap.String("tenant", sub.TenantID),
				zap.String("subject", sub.SubjectID),
				zap.String("window", decision.Reason),
				zap.Int("retry_after_s", retry))
			respondWithError(w, http.StatusTooManyRequests, "rate_limited",
				fmt.Sprintf("rate limit exceeded on %s window; retry after %ds", decision.Reason, retry))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// writeRateLimitHeaders emits the standard X-RateLimit-* headers so
// well-behaved clients can back off proactively instead of spinning.
func writeRateLimitHeaders(w http.ResponseWriter, d ratelimit.Decision) {
	w.Header().Set("X-RateLimit-Limit-Minute", fmt.Sprintf("%d", d.LimitMinute))
	w.Header().Set("X-RateLimit-Limit-Hour", fmt.Sprintf("%d", d.LimitHour))
	w.Header().Set("X-RateLimit-Remaining-Minute", fmt.Sprintf("%d", d.RemainingMinute))
	w.Header().Set("X-RateLimit-Remaining-Hour", fmt.Sprintf("%d", d.RemainingHour))
	if d.ResetMinute > 0 {
		w.Header().Set("X-RateLimit-Reset-Minute", fmt.Sprintf("%d", d.ResetMinute))
	}
	if d.ResetHour > 0 {
		w.Header().Set("X-RateLimit-Reset-Hour", fmt.Sprintf("%d", d.ResetHour))
	}
}
