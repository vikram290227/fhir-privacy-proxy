package auth

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/consent"
)

// CheckConsent returns a middleware that queries the upstream FHIR
// server for a Consent resource referencing the target patient and
// attaches the result to the SubjectContext.
//
// It must run after ValidateToken (which populates the subject)
// and before EnforcePolicy (which reads input.resource.consent).
//
// When the checker is nil (FHIR_UPSTREAM not configured) or the
// request does not target a specific patient, the middleware is a
// no-op — the OPA policy treats a missing consent block as "no
// consent on file" and defaults to the existing role/risk rules.
func (m *Middleware) CheckConsent(checker *consent.Checker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil {
				next.ServeHTTP(w, r)
				return
			}

			sub, ok := r.Context().Value(SubjectContextKey).(*SubjectContext)
			if !ok || sub == nil {
				respondWithError(w, http.StatusInternalServerError, "internal_error", "missing auth context")
				return
			}

			patientID := extractPatientID(r.URL.Path)
			if patientID == "" {
				next.ServeHTTP(w, r)
				return
			}

			if !consent.ValidPurposes[sub.PurposeOfUse] {
				respondWithError(w, http.StatusBadRequest, "invalid_purpose",
					"X-Purpose-Of-Use must be one of: TREATMENT, PAYMENT, OPERATIONS, EMERGENCY, RESEARCH")
				return
			}

			info, err := checker.Lookup(r.Context(), patientID, sub.PurposeOfUse)
			if err != nil {
				m.logger.Warn("consent lookup failed, proceeding without consent",
					zap.Error(err),
					zap.String("patient_id", patientID))
				next.ServeHTTP(w, r)
				return
			}

			sub.Consent = info
			next.ServeHTTP(w, r)
		})
	}
}
