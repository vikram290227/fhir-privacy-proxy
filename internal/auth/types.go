package auth

import (
	"time"

	"github.com/vikram290227/fhir-privacy-proxy/internal/consent"
)

type SubjectContext struct {
	SubjectID   string   `json:"subject_id"`
	SubjectType string   `json:"subject_type"`
	Roles       []string `json:"roles"`
	HasRoles    bool     `json:"has_roles"`

	FHIRContext  FHIRContext `json:"fhir_context"`
	Client       ClientInfo  `json:"client"`
	Scopes       []string    `json:"scopes"`
	Session      SessionInfo `json:"session"`
	TenantID     string      `json:"tenant_id"`
	PurposeOfUse string      `json:"purpose_of_use,omitempty"`

	BreakGlass *BreakGlassContext `json:"break_glass,omitempty"`
	Policy     *PolicyDecision    `json:"policy,omitempty"`

	// Risk contains the ML-derived anomaly score for this request.
	// It is populated by the ScoreRisk middleware and consumed by OPA
	// via the adaptive authorization policy.
	Risk *RiskDecision `json:"risk,omitempty"`

	// Consent carries the upstream FHIR Consent resource summary for
	// the target patient. Populated by the CheckConsent middleware.
	Consent *consent.ConsentInfo `json:"consent,omitempty"`

	// AccessCounts holds per-window request counts from the Redis rate limiter.
	// Populated by the RateLimit middleware; zero when Redis is unavailable.
	// Passed to OPA as input.subject.access_counts for Tier 1 hard rules.
	AccessCounts AccessCounts `json:"access_counts"`

	// IsAfterHours is true when the request arrives outside 06:00–21:59 UTC.
	// Zero-cost signal set by the ScoreRisk middleware for OPA Tier 1 rules.
	IsAfterHours bool `json:"is_after_hours"`
}

// RiskDecision carries the AI risk assessment for a single request.
type RiskDecision struct {
	Score       float64            `json:"score"`
	Label       string             `json:"label"`
	Explanation map[string]float64 `json:"explanation,omitempty"`
	// Unavailable is true when the ML service did not respond within its
	// timeout budget. OPA must not interpret Score=0 as low-risk in this case;
	// instead it falls back to Tier 1 counter-based rules only.
	Unavailable bool `json:"unavailable,omitempty"`
}

// AccessCounts holds the sliding-window request counts for this subject,
// populated by the RateLimit middleware from Redis counters. Zero values
// mean the rate limiter is disabled; OPA Tier 1 rules treat 0 as "no signal"
// rather than "zero requests".
type AccessCounts struct {
	LastMinute int64 `json:"last_minute"`
	LastHour   int64 `json:"last_hour"`
	LastDay    int64 `json:"last_day"`
}

type FHIRContext struct {
	Department  string `json:"department"`
	Facility    string `json:"facility"`
	Role        string `json:"role"`
	SessionType string `json:"session_type"`
}

type ClientInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type SessionInfo struct {
	TokenID   string    `json:"token_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type BreakGlassContext struct {
	Enabled       bool   `json:"enabled"`
	Justification string `json:"justification"`
	RequestedBy   string `json:"requested_by"`
}

type PolicyDecision struct {
	Remove []string `json:"remove,omitempty"`
	Mask   []string `json:"mask,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

type contextKey string

const SubjectContextKey contextKey = "subject_context"
