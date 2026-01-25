package auth

import "time"

type SubjectContext struct {
	SubjectID   string   `json:"subject_id"`
	SubjectType string   `json:"subject_type"`
	Roles       []string `json:"roles"`
	HasRoles    bool     `json:"has_roles"`

	FHIRContext FHIRContext `json:"fhir_context"`
	Client      ClientInfo  `json:"client"`
	Scopes      []string    `json:"scopes"`
	Session     SessionInfo `json:"session"`
	TenantID    string      `json:"tenant_id"`

	BreakGlass *BreakGlassContext `json:"break_glass,omitempty"`
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

type contextKey string

const SubjectContextKey contextKey = "subject_context"
