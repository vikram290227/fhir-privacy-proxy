package consent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fhirServer builds a test server that responds to
// GET /Consent?patient=Patient/<id>&... with the given bundle JSON.
func fhirServer(t *testing.T, bundles map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		patientParam := r.URL.Query().Get("patient")
		if body, ok := bundles[patientParam]; ok {
			w.Header().Set("Content-Type", "application/fhir+json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(body))
			return
		}
		// No consent on file — return empty bundle.
		w.Header().Set("Content-Type", "application/fhir+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"resourceType":"Bundle","type":"searchset","total":0,"entry":[]}`))
	}))
}

func activeConsentBundle(status, scope, provisionType string, purposes []string) string {
	purposeJSON := "[]"
	if len(purposes) > 0 {
		pp := make([]map[string]string, len(purposes))
		for i, p := range purposes {
			pp[i] = map[string]string{"code": p}
		}
		b, _ := json.Marshal(pp)
		purposeJSON = string(b)
	}
	return `{
		"resourceType": "Bundle",
		"type": "searchset",
		"total": 1,
		"entry": [{
			"resource": {
				"resourceType": "Consent",
				"status": "` + status + `",
				"scope": {"coding": [{"code": "` + scope + `"}]},
				"provision": {
					"type": "` + provisionType + `",
					"purpose": ` + purposeJSON + `
				}
			}
		}]
	}`
}

func emptyBundle() string {
	return `{"resourceType":"Bundle","type":"searchset","total":0,"entry":[]}`
}

func TestLookup_ActiveConsent(t *testing.T) {
	srv := fhirServer(t, map[string]string{
		"Patient/p1": activeConsentBundle("active", "patient-privacy", "permit", []string{"TREATMENT", "PAYMENT"}),
	})
	defer srv.Close()

	checker, err := NewChecker(srv.URL, zap.NewNop(), 100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	info, err := checker.Lookup(context.Background(), "p1", "TREATMENT")
	if err != nil {
		t.Fatal(err)
	}
	if info == nil {
		t.Fatal("expected consent info, got nil")
	}
	if info.Status != "active" {
		t.Errorf("status = %q, want active", info.Status)
	}
	if info.Scope != "patient-privacy" {
		t.Errorf("scope = %q, want patient-privacy", info.Scope)
	}
	if info.ProvisionType != "permit" {
		t.Errorf("provision_type = %q, want permit", info.ProvisionType)
	}
	if len(info.AllowedPurposes) != 2 {
		t.Errorf("allowed_purposes len = %d, want 2", len(info.AllowedPurposes))
	}
}

func TestLookup_NoConsentOnFile(t *testing.T) {
	srv := fhirServer(t, map[string]string{})
	defer srv.Close()

	checker, err := NewChecker(srv.URL, zap.NewNop(), 100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	info, err := checker.Lookup(context.Background(), "unknown-patient", "TREATMENT")
	if err != nil {
		t.Fatal(err)
	}
	if info != nil {
		t.Errorf("expected nil for unknown patient, got %+v", info)
	}
}

func TestLookup_EmptyPatientID(t *testing.T) {
	srv := fhirServer(t, map[string]string{})
	defer srv.Close()

	checker, err := NewChecker(srv.URL, zap.NewNop(), 100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	info, err := checker.Lookup(context.Background(), "", "TREATMENT")
	if err != nil {
		t.Fatal(err)
	}
	if info != nil {
		t.Error("expected nil for empty patient ID")
	}
}

func TestLookup_CachesResult(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/fhir+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(activeConsentBundle("active", "patient-privacy", "permit", []string{"TREATMENT"})))
	}))
	defer srv.Close()

	checker, err := NewChecker(srv.URL, zap.NewNop(), 100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// First call hits the server.
	_, _ = checker.Lookup(context.Background(), "p1", "TREATMENT")
	// Second call should be cached.
	_, _ = checker.Lookup(context.Background(), "p1", "TREATMENT")

	if calls != 1 {
		t.Errorf("expected 1 upstream call, got %d", calls)
	}
}

func TestLookup_CacheExpiry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/fhir+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(activeConsentBundle("active", "patient-privacy", "permit", []string{"TREATMENT"})))
	}))
	defer srv.Close()

	checker, err := NewChecker(srv.URL, zap.NewNop(), 100, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = checker.Lookup(context.Background(), "p1", "TREATMENT")
	time.Sleep(20 * time.Millisecond)
	_, _ = checker.Lookup(context.Background(), "p1", "TREATMENT")

	if calls != 2 {
		t.Errorf("expected 2 upstream calls after expiry, got %d", calls)
	}
}

func TestLookup_InactiveConsent(t *testing.T) {
	srv := fhirServer(t, map[string]string{
		"Patient/p1": activeConsentBundle("inactive", "patient-privacy", "deny", nil),
	})
	defer srv.Close()

	checker, err := NewChecker(srv.URL, zap.NewNop(), 100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	info, err := checker.Lookup(context.Background(), "p1", "TREATMENT")
	if err != nil {
		t.Fatal(err)
	}
	if info == nil {
		t.Fatal("expected consent info even for inactive status")
	}
	if info.Status != "inactive" {
		t.Errorf("status = %q, want inactive", info.Status)
	}
	if info.ProvisionType != "deny" {
		t.Errorf("provision_type = %q, want deny", info.ProvisionType)
	}
}

func TestLookup_UpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	checker, err := NewChecker(srv.URL, zap.NewNop(), 100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	_, err = checker.Lookup(context.Background(), "p1", "TREATMENT")
	if err == nil {
		t.Error("expected error on upstream 500")
	}
}

func TestLookup_RejectedConsent(t *testing.T) {
	srv := fhirServer(t, map[string]string{
		"Patient/p1": activeConsentBundle("rejected", "patient-privacy", "deny", nil),
	})
	defer srv.Close()

	checker, err := NewChecker(srv.URL, zap.NewNop(), 100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	info, err := checker.Lookup(context.Background(), "p1", "TREATMENT")
	if err != nil {
		t.Fatal(err)
	}
	if info.Status != "rejected" {
		t.Errorf("status = %q, want rejected", info.Status)
	}
}

func TestLookup_Unreachable(t *testing.T) {
	checker, err := NewChecker("http://localhost:1", zap.NewNop(), 100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checker.Lookup(context.Background(), "p1", "TREATMENT")
	if err == nil {
		t.Error("expected error on unreachable server")
	}
}

func TestLookup_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/fhir+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	checker, err := NewChecker(srv.URL, zap.NewNop(), 100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checker.Lookup(context.Background(), "p1", "TREATMENT")
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestLookup_InvalidConsentEntry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/fhir+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"entry":[{"resource": "not-a-json-object"}]}`))
	}))
	defer srv.Close()

	checker, err := NewChecker(srv.URL, zap.NewNop(), 100, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checker.Lookup(context.Background(), "p1", "TREATMENT")
	if err == nil {
		t.Error("expected error for invalid consent resource JSON")
	}
}

func TestValidPurposes(t *testing.T) {
	expected := []string{"TREATMENT", "PAYMENT", "OPERATIONS", "EMERGENCY", "RESEARCH"}
	for _, p := range expected {
		if !ValidPurposes[p] {
			t.Errorf("%q should be a valid purpose", p)
		}
	}
	if ValidPurposes["INVALID"] {
		t.Error("INVALID should not be a valid purpose")
	}
}
