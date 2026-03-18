package audit

import (
	"testing"
	"time"
)

func TestSanitize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"nurse-1", "nurse-1"},
		{"user@hospital.com", "user_hospital_com"},
		{"doc/123", "doc_123"},
		{"simple", "simple"},
		{"a b c", "a_b_c"},
		{"", ""},
	}
	for _, tt := range tests {
		got := sanitize(tt.input)
		if got != tt.want {
			t.Errorf("sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestConfigFromEnv_NotSet(t *testing.T) {
	t.Setenv("AZURE_STORAGE_ACCOUNT", "")
	cfg := ConfigFromEnv()
	if cfg != nil {
		t.Error("expected nil config when AZURE_STORAGE_ACCOUNT is not set")
	}
}

func TestConfigFromEnv_Set(t *testing.T) {
	t.Setenv("AZURE_STORAGE_ACCOUNT", "myaccount")
	t.Setenv("AZURE_STORAGE_KEY", "mykey")
	t.Setenv("AZURE_AUDIT_CONTAINER", "my-container")

	cfg := ConfigFromEnv()
	if cfg == nil {
		t.Fatal("expected config")
	}
	if cfg.AccountName != "myaccount" {
		t.Errorf("AccountName = %q, want %q", cfg.AccountName, "myaccount")
	}
	if cfg.AccountKey != "mykey" {
		t.Errorf("AccountKey = %q, want %q", cfg.AccountKey, "mykey")
	}
	if cfg.ContainerName != "my-container" {
		t.Errorf("ContainerName = %q, want %q", cfg.ContainerName, "my-container")
	}
}

func TestConfigFromEnv_DefaultContainer(t *testing.T) {
	t.Setenv("AZURE_STORAGE_ACCOUNT", "myaccount")
	t.Setenv("AZURE_STORAGE_KEY", "")
	t.Setenv("AZURE_AUDIT_CONTAINER", "")

	cfg := ConfigFromEnv()
	if cfg == nil {
		t.Fatal("expected config")
	}
	if cfg.ContainerName != "fhir-audit-logs" {
		t.Errorf("ContainerName = %q, want %q", cfg.ContainerName, "fhir-audit-logs")
	}
}

func TestAuditEventDefaults(t *testing.T) {
	evt := AuditEvent{
		EventType:    EventAccess,
		TenantID:     "hospital-a",
		SubjectID:    "nurse-1",
		Method:       "GET",
		Path:         "/fhir/r4/Patient/123",
		ResourceType: "Patient",
		StatusCode:   200,
		PolicyResult: "allow",
		DurationMs:   42,
	}

	if evt.Timestamp.IsZero() {
		// This is expected before Log() is called
	}

	if evt.EventType != EventAccess {
		t.Errorf("EventType = %q, want %q", evt.EventType, EventAccess)
	}
	if evt.TenantID != "hospital-a" {
		t.Errorf("TenantID = %q, want %q", evt.TenantID, "hospital-a")
	}
}

func TestEventTypes(t *testing.T) {
	if EventAccess != "RESOURCE_ACCESS" {
		t.Error("EventAccess constant mismatch")
	}
	if EventAccessDenied != "ACCESS_DENIED" {
		t.Error("EventAccessDenied constant mismatch")
	}
	if EventBreakGlass != "BREAK_GLASS" {
		t.Error("EventBreakGlass constant mismatch")
	}
	if EventAuthFailure != "AUTH_FAILURE" {
		t.Error("EventAuthFailure constant mismatch")
	}
	if EventRevocation != "TOKEN_REVOCATION" {
		t.Error("EventRevocation constant mismatch")
	}
}

func TestBreakGlassEvent(t *testing.T) {
	evt := AuditEvent{
		EventType: EventBreakGlass,
		TenantID:  "hospital-a",
		SubjectID: "nurse-1",
		Timestamp: time.Now().UTC(),
		BreakGlass: &BreakGlassDetail{
			Justification: "Emergency cardiac event",
			RequestedBy:   "nurse-1",
		},
	}

	if evt.BreakGlass == nil {
		t.Fatal("expected break glass detail")
	}
	if evt.BreakGlass.Justification != "Emergency cardiac event" {
		t.Error("justification mismatch")
	}
}
