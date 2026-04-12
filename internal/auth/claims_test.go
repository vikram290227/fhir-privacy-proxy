package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// TestExtractRoles covers the realm_access.roles path and common
// malformed-claim shapes — the extractor must be tolerant and never
// panic on bad input.
func TestExtractRoles(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
		want   []string
	}{
		{
			name: "valid roles",
			claims: jwt.MapClaims{
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"nurse", "can_break_glass"},
				},
			},
			want: []string{"nurse", "can_break_glass"},
		},
		{
			name:   "missing realm_access",
			claims: jwt.MapClaims{},
			want:   nil,
		},
		{
			name: "realm_access wrong type",
			claims: jwt.MapClaims{
				"realm_access": "not a map",
			},
			want: nil,
		},
		{
			name: "roles wrong type",
			claims: jwt.MapClaims{
				"realm_access": map[string]interface{}{"roles": "nurse"},
			},
			want: nil,
		},
		{
			name: "mixed role types are filtered",
			claims: jwt.MapClaims{
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"nurse", 42, "doctor"},
				},
			},
			want: []string{"nurse", "doctor"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRoles(tt.claims)
			if len(got) != len(tt.want) {
				t.Fatalf("len: got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d]: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractFHIRContext_Defaults(t *testing.T) {
	ctx := extractFHIRContext(jwt.MapClaims{})
	if ctx.Department != "UNKNOWN" {
		t.Errorf("default department = %q, want UNKNOWN", ctx.Department)
	}
	if ctx.Role != "unknown" {
		t.Errorf("default role = %q, want unknown", ctx.Role)
	}
	if ctx.Facility != "main-hospital" {
		t.Errorf("default facility = %q, want main-hospital", ctx.Facility)
	}
	if ctx.SessionType != "clinical" {
		t.Errorf("default session_type = %q, want clinical", ctx.SessionType)
	}
}

func TestExtractFHIRContext_Populated(t *testing.T) {
	claims := jwt.MapClaims{
		"fhirContext": map[string]interface{}{
			"department":   "cardiology",
			"role":         "nurse",
			"facility":     "mercy-hospital",
			"session_type": "research",
		},
	}
	ctx := extractFHIRContext(claims)
	if ctx.Department != "cardiology" {
		t.Errorf("department = %q", ctx.Department)
	}
	if ctx.Role != "nurse" {
		t.Errorf("role = %q", ctx.Role)
	}
	if ctx.Facility != "mercy-hospital" {
		t.Errorf("facility = %q", ctx.Facility)
	}
	if ctx.SessionType != "research" {
		t.Errorf("session_type = %q", ctx.SessionType)
	}
}

func TestExtractScopes(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
		want   []string
	}{
		{
			name:   "space-separated",
			claims: jwt.MapClaims{"scope": "patient/Patient.read patient/Observation.read"},
			want:   []string{"patient/Patient.read", "patient/Observation.read"},
		},
		{
			name:   "extra whitespace collapses",
			claims: jwt.MapClaims{"scope": "  patient/Patient.read   user/*.read  "},
			want:   []string{"patient/Patient.read", "user/*.read"},
		},
		{
			name:   "missing",
			claims: jwt.MapClaims{},
			want:   nil,
		},
		{
			name:   "empty",
			claims: jwt.MapClaims{"scope": ""},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractScopes(tt.claims)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d]: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractClientInfo_FallsBackToClientID(t *testing.T) {
	claims := jwt.MapClaims{"client_id": "fallback-client"}
	info := extractClientInfo(claims)
	if info.ID != "fallback-client" {
		t.Errorf("ID = %q", info.ID)
	}
	if info.Name != "fallback-client" {
		t.Errorf("Name = %q", info.Name)
	}
}

func TestExtractSession(t *testing.T) {
	claims := jwt.MapClaims{
		"jti": "token-xyz",
		"iat": float64(1700000000),
		"exp": float64(1700001000),
	}
	s := extractSession(claims)
	if s.TokenID != "token-xyz" {
		t.Errorf("TokenID = %q", s.TokenID)
	}
	if s.IssuedAt.Unix() != 1700000000 {
		t.Errorf("IssuedAt = %v", s.IssuedAt.Unix())
	}
	if s.ExpiresAt.Unix() != 1700001000 {
		t.Errorf("ExpiresAt = %v", s.ExpiresAt.Unix())
	}
}

// TestResolveBreakGlass_NotRequested ensures no break-glass context is
// created for regular requests.
func TestResolveBreakGlass_NotRequested(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}
	req := httptest.NewRequest("GET", "/", nil)
	bg, err := m.resolveBreakGlass(req, "nurse-1", []string{"nurse"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bg != nil {
		t.Error("expected nil BreakGlass when header absent")
	}
}

func TestResolveBreakGlass_HappyPath(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Break-Glass", "true")
	req.Header.Set("X-Break-Glass-Justification", "Code Blue")
	bg, err := m.resolveBreakGlass(req, "nurse-1", []string{"nurse", "can_break_glass"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bg == nil {
		t.Fatal("expected BreakGlass context")
	}
	if !bg.Enabled {
		t.Error("expected enabled")
	}
	if bg.Justification != "Code Blue" {
		t.Errorf("justification = %q", bg.Justification)
	}
	if bg.RequestedBy != "nurse-1" {
		t.Errorf("RequestedBy = %q", bg.RequestedBy)
	}
}

func TestResolveBreakGlass_MissingRole(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Break-Glass", "true")
	req.Header.Set("X-Break-Glass-Justification", "valid reason")
	_, err := m.resolveBreakGlass(req, "nurse-1", []string{"nurse"})
	if err == nil {
		t.Error("expected error when subject lacks can_break_glass role")
	}
}

func TestResolveBreakGlass_MissingJustification(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := &Middleware{logger: logger}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Break-Glass", "true")
	_, err := m.resolveBreakGlass(req, "nurse-1", []string{"nurse", "can_break_glass"})
	if err == nil {
		t.Error("expected error when justification header missing")
	}
}
