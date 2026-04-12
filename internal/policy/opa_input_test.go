package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

// TestOPAClient_InputConstruction exercises the Evaluate path and
// asserts that every field OPA expects (`subject`, `request`,
// `resource`) is present with the correct values. This guards against
// regressions that silently drop fields and produce surprising policy
// decisions.
func TestOPAClient_InputConstruction(t *testing.T) {
	var captured map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input map[string]any `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		captured = body.Input

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"allow": true, "reason": "ok",
			},
		})
	}))
	defer server.Close()

	client := NewOPAClient(server.URL, zap.NewNop())

	subject := map[string]any{
		"subject_id": "nurse1",
		"roles":      []string{"nurse"},
		"fhir_context": map[string]any{
			"role":       "nurse",
			"department": "cardiology",
		},
		"risk": map[string]any{
			"score": 0.2,
			"label": "normal",
		},
	}

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123?_count=10", nil)

	if _, err := client.Evaluate(context.Background(), subject, req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	// subject
	sub, ok := captured["subject"].(map[string]any)
	if !ok {
		t.Fatalf("subject not present or wrong type: %T", captured["subject"])
	}
	if sub["subject_id"] != "nurse1" {
		t.Errorf("subject_id = %v", sub["subject_id"])
	}
	// risk survived marshaling and is reachable at input.subject.risk
	riskMap, ok := sub["risk"].(map[string]any)
	if !ok {
		t.Fatalf("risk missing from subject: %T", sub["risk"])
	}
	if riskMap["score"] != 0.2 {
		t.Errorf("risk.score = %v", riskMap["score"])
	}

	// request
	rq, ok := captured["request"].(map[string]any)
	if !ok {
		t.Fatal("request missing")
	}
	if rq["method"] != "GET" {
		t.Errorf("method = %v", rq["method"])
	}
	if rq["path"] != "/fhir/r4/Patient/123" {
		t.Errorf("path = %v", rq["path"])
	}
	parts, _ := rq["path_parts"].([]any)
	if len(parts) != 2 || parts[0] != "Patient" || parts[1] != "123" {
		t.Errorf("path_parts = %v", parts)
	}

	// resource
	res, ok := captured["resource"].(map[string]any)
	if !ok {
		t.Fatal("resource missing")
	}
	if res["type"] != "Patient" {
		t.Errorf("resource.type = %v", res["type"])
	}
	if res["patient_id"] != "123" {
		t.Errorf("resource.patient_id = %v", res["patient_id"])
	}
}

// TestOPAClient_InputConstruction_NonPatient verifies that non-Patient
// resources still get the type field populated but patient_id is empty.
func TestOPAClient_InputConstruction_NonPatient(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Input map[string]any }
		json.NewDecoder(r.Body).Decode(&body)
		captured = body.Input
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"allow": true}})
	}))
	defer server.Close()

	client := NewOPAClient(server.URL, zap.NewNop())
	req := httptest.NewRequest("POST", "/fhir/r4/Observation", nil)
	if _, err := client.Evaluate(context.Background(), map[string]any{}, req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	res := captured["resource"].(map[string]any)
	if res["type"] != "Observation" {
		t.Errorf("type = %v", res["type"])
	}
	if res["patient_id"] != "" {
		t.Errorf("patient_id should be empty, got %v", res["patient_id"])
	}
}
