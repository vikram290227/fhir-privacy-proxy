package admin

import (
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// ---------------------------------------------------------------------
// /policy/versions — list known bundles + the active pointer
// ---------------------------------------------------------------------

type listVersionsResponse struct {
	Active  string   `json:"active"`
	Bundles []Bundle `json:"bundles"`
}

func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request) {
	if s.deps.Policy == nil {
		writeError(w, http.StatusServiceUnavailable, "feature_disabled",
			"policy version manager is not configured")
		return
	}
	writeJSON(w, http.StatusOK, listVersionsResponse{
		Active:  s.deps.Policy.Active(),
		Bundles: s.deps.Policy.List(),
	})
}

// ---------------------------------------------------------------------
// /policy/activate — switch the active bundle and push it to OPA
// ---------------------------------------------------------------------

type activateRequest struct {
	Version string `json:"version"`
}

type activateResponse struct {
	Active string `json:"active"`
}

func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	if s.deps.Policy == nil {
		writeError(w, http.StatusServiceUnavailable, "feature_disabled",
			"policy version manager is not configured")
		return
	}
	var req activateRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Version == "" {
		writeError(w, http.StatusBadRequest, "missing_version", "version field is required")
		return
	}
	if err := s.deps.Policy.Activate(req.Version); err != nil {
		writeError(w, http.StatusBadRequest, "activate_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, activateResponse{Active: s.deps.Policy.Active()})
}

// ---------------------------------------------------------------------
// /policy/rollback — pop one history entry and push the bundle to OPA
// ---------------------------------------------------------------------

type rollbackResponse struct {
	Active   string `json:"active"`
	Previous string `json:"previous"`
}

func (s *Server) handleRollback(w http.ResponseWriter, _ *http.Request) {
	if s.deps.Policy == nil {
		writeError(w, http.StatusServiceUnavailable, "feature_disabled",
			"policy version manager is not configured")
		return
	}
	prev, err := s.deps.Policy.Rollback()
	if err != nil {
		writeError(w, http.StatusConflict, "rollback_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rollbackResponse{
		Active:   s.deps.Policy.Active(),
		Previous: prev,
	})
}

// ---------------------------------------------------------------------
// /tenants — list configured tenants with secrets / lists redacted
// ---------------------------------------------------------------------

// tenantView is the shape returned by /tenants. Anything that could
// leak operational state — full sensitive_patients lists, internal
// rate limit knobs that are still tunable, etc. — is summarised, not
// dumped wholesale.
type tenantView struct {
	TenantID               string   `json:"tenant_id"`
	IssuerURL              string   `json:"issuer_url"`
	JWKSEndpoint           string   `json:"jwks_endpoint"`
	Audience               string   `json:"audience"`
	PolicyBundle           string   `json:"policy_bundle,omitempty"`
	PolicyVersion          string   `json:"policy_version,omitempty"`
	AllowedScopes          []string `json:"allowed_scopes,omitempty"`
	RequestsPerMinute      int      `json:"requests_per_minute"`
	RequestsPerHour        int      `json:"requests_per_hour"`
	SensitivePatientsCount int      `json:"sensitive_patients_count"`
}

type listTenantsResponse struct {
	Tenants []tenantView `json:"tenants"`
}

func (s *Server) handleListTenants(w http.ResponseWriter, _ *http.Request) {
	if s.deps.Tenants == nil {
		writeError(w, http.StatusServiceUnavailable, "feature_disabled",
			"tenant registry is not configured")
		return
	}
	all := s.deps.Tenants.GetAll()
	out := make([]tenantView, 0, len(all))
	for _, t := range all {
		out = append(out, tenantView{
			TenantID:               t.TenantID,
			IssuerURL:              t.IssuerURL,
			JWKSEndpoint:           t.JWKSEndpoint,
			Audience:               t.Audience,
			PolicyBundle:           t.PolicyBundle,
			PolicyVersion:          t.PolicyVersion,
			AllowedScopes:          t.AllowedScopes,
			RequestsPerMinute:      t.RequestsPerMinute,
			RequestsPerHour:        t.RequestsPerHour,
			SensitivePatientsCount: len(t.SensitivePatients),
		})
	}
	// Stable order for deterministic responses (helpful for tests + ops
	// diffing).
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	writeJSON(w, http.StatusOK, listTenantsResponse{Tenants: out})
}

// ---------------------------------------------------------------------
// /audit/tail — return the last N audit lines from the file sink
// ---------------------------------------------------------------------

type auditTailResponse struct {
	Path  string   `json:"path"`
	Count int      `json:"count"`
	Lines []string `json:"lines"`
}

const (
	auditTailDefaultN = 50
	auditTailMaxN     = 1000
)

func (s *Server) handleAuditTail(w http.ResponseWriter, r *http.Request) {
	if s.deps.Audit == nil {
		writeError(w, http.StatusServiceUnavailable, "feature_disabled",
			"file audit sink is not configured (only the file sink supports tail)")
		return
	}
	path := s.deps.Audit.Path()
	if path == "" {
		writeError(w, http.StatusServiceUnavailable, "feature_disabled",
			"audit sink has no on-disk path")
		return
	}

	n := auditTailDefaultN
	if raw := r.URL.Query().Get("n"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "invalid_n", "n must be a positive integer")
			return
		}
		if parsed > auditTailMaxN {
			parsed = auditTailMaxN
		}
		n = parsed
	}

	lines, err := tailFile(path, n)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "tail_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, auditTailResponse{
		Path:  path,
		Count: len(lines),
		Lines: lines,
	})
}

// ---------------------------------------------------------------------
// /tokens/revoke — push a (tenant, jti, exp) tuple into the cache
// ---------------------------------------------------------------------

type revokeRequest struct {
	Tenant string `json:"tenant"`
	JTI    string `json:"jti"`
	Exp    int64  `json:"exp"`
}

type revokeResponse struct {
	Status string `json:"status"`
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if s.deps.Revoker == nil {
		writeError(w, http.StatusServiceUnavailable, "feature_disabled",
			"token revocation cache is not configured (REDIS_ADDR unset)")
		return
	}
	var req revokeRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Tenant == "" || req.JTI == "" {
		writeError(w, http.StatusBadRequest, "missing_field",
			"tenant and jti are required")
		return
	}
	if req.Exp <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_exp",
			"exp must be a positive unix timestamp")
		return
	}
	if err := s.deps.Revoker.Revoke(req.Tenant, req.JTI, req.Exp); err != nil {
		writeError(w, http.StatusInternalServerError, "revoke_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, revokeResponse{Status: "revoked"})
}

// ---------------------------------------------------------------------
// /health/deps — concurrent fan-out across all dependencies
// ---------------------------------------------------------------------

type depStatus struct {
	Status string `json:"status"`           // "ok" | "error" | "disabled"
	Error  string `json:"error,omitempty"`  // only set when Status == "error"
}

type healthDepsResponse struct {
	OK   bool                  `json:"ok"`
	Deps map[string]depStatus `json:"deps"`
}

const depCheckTimeout = 2 * time.Second

func (s *Server) handleHealthDeps(w http.ResponseWriter, r *http.Request) {
	checks := map[string]HealthCheckable{
		"opa":      s.deps.OPA,
		"redis":    s.deps.Redis,
		"upstream": s.deps.Upstream,
		"risk":     s.deps.Risk,
	}

	out := make(map[string]depStatus, len(checks))
	var mu sync.Mutex
	var wg sync.WaitGroup

	ctx, cancel := withTimeout(r.Context(), depCheckTimeout)
	defer cancel()

	for name, check := range checks {
		name, check := name, check
		if check == nil {
			out[name] = depStatus{Status: "disabled"}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := check.HealthCheck(ctx)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				out[name] = depStatus{Status: "error", Error: err.Error()}
				return
			}
			out[name] = depStatus{Status: "ok"}
		}()
	}
	wg.Wait()

	ok := true
	for _, st := range out {
		if st.Status == "error" {
			ok = false
			break
		}
	}

	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, healthDepsResponse{OK: ok, Deps: out})
}
