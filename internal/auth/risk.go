package auth

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/metrics"
	"github.com/vikram290227/fhir-privacy-proxy/internal/risk"
)

// ScoreRisk returns a middleware that calls the AI risk-scoring service
// for the incoming request and attaches the returned score to the
// SubjectContext. It must run after ValidateToken (which populates the
// subject) and before EnforcePolicy (which reads the score).
//
// When the client is disabled (empty URL) this middleware is a no-op
// that records a zero score — so the downstream policy sees a
// deterministic, neutral "no risk signal" decision.
func (m *Middleware) ScoreRisk(client *risk.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sub, ok := r.Context().Value(SubjectContextKey).(*SubjectContext)
			if !ok || sub == nil {
				respondWithError(w, http.StatusInternalServerError, "internal_error", "missing auth context")
				return
			}

			now := time.Now().UTC()
			afterHours := now.Hour() < 6 || now.Hour() >= 22
			sub.IsAfterHours = afterHours

			req := risk.Request{
				UserID:             sub.SubjectID,
				Role:               sub.FHIRContext.Role,
				Department:         sub.FHIRContext.Department,
				PatientID:          extractPatientID(r.URL.Path),
				ResourceType:       extractFhirResourceType(r.URL.Path),
				Action:             methodAction(r.Method),
				Hour:               now.Hour(),
				DayOfWeek:          int(now.Weekday()),
				BreakGlass:         sub.BreakGlass != nil && sub.BreakGlass.Enabled,
				AccessesLastMinute: sub.AccessCounts.LastMinute,
				AccessesLastHour:   sub.AccessCounts.LastHour,
				IsAfterHours:       afterHours,
			}

			start := time.Now()
			resp, err := client.Score(r.Context(), req)
			metrics.RiskScoreDuration.Observe(time.Since(start).Seconds())
			if err != nil {
				m.logger.Warn("risk score failed — Tier 1 rules only", zap.Error(err))
				resp = &risk.Response{Score: 0, Label: "unavailable", Unavailable: true}
			}

			metrics.RiskScores.WithLabelValues(resp.Label).Inc()
			if resp.Unavailable {
				metrics.MLTimeouts.WithLabelValues(sub.TenantID).Inc()
				metrics.RiskServiceUnavailable.WithLabelValues(sub.TenantID).Inc()
				m.logger.Error("risk scoring service unavailable — operating fail-open",
					zap.String("tenant", sub.TenantID),
					zap.String("severity", "CRITICAL"))
			}

			sub.Risk = &RiskDecision{
				Score:       resp.Score,
				Label:       resp.Label,
				Explanation: resp.Explanation,
				Unavailable: resp.Unavailable,
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractPatientID pulls the patient id out of /fhir/r4/Patient/{id}-style
// paths. Returns empty string if the request is not scoped to a patient.
func extractPatientID(path string) string {
	resource := extractFhirResourceType(path)
	if resource != "Patient" {
		return ""
	}
	// /fhir/r4/Patient/{id}
	trimmed := path
	if len(trimmed) > 0 && trimmed[0] == '/' {
		trimmed = trimmed[1:]
	}
	segs := splitPathSegments(trimmed)
	if len(segs) >= 4 && segs[0] == "fhir" && segs[1] == "r4" && segs[2] == "Patient" {
		return segs[3]
	}
	return ""
}

func splitPathSegments(path string) []string {
	var out []string
	current := ""
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			if current != "" {
				out = append(out, current)
			}
			current = ""
			continue
		}
		current += string(path[i])
	}
	if current != "" {
		out = append(out, current)
	}
	return out
}
