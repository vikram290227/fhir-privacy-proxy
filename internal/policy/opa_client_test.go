package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestOPAClient_Evaluate_Allow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/firewall/decision/result" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Verify request body structure
		var body opaRequest
		json.NewDecoder(r.Body).Decode(&body)
		input := body.Input.(map[string]interface{})
		if input["subject"] == nil {
			t.Error("expected subject in input")
		}
		if input["request"] == nil {
			t.Error("expected request in input")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(opaResponse{
			Result: Decision{
				Allow:  true,
				Reason: "allowed",
				Remove: []string{"identifier"},
				Mask:   []string{"telecom", "address"},
			},
		})
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	client := NewOPAClient(server.URL, logger)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	subject := map[string]string{"subject_id": "nurse1"}

	decision, err := client.Evaluate(context.Background(), subject, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Allow {
		t.Error("expected allow=true")
	}
	if decision.Reason != "allowed" {
		t.Errorf("expected reason 'allowed', got '%s'", decision.Reason)
	}
	if len(decision.Remove) != 1 || decision.Remove[0] != "identifier" {
		t.Errorf("unexpected remove: %v", decision.Remove)
	}
	if len(decision.Mask) != 2 {
		t.Errorf("expected 2 mask fields, got %d", len(decision.Mask))
	}
}

func TestOPAClient_Evaluate_Deny(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(opaResponse{
			Result: Decision{
				Allow:  false,
				Reason: "access denied: insufficient roles",
			},
		})
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	client := NewOPAClient(server.URL, logger)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	decision, err := client.Evaluate(context.Background(), nil, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Allow {
		t.Error("expected allow=false")
	}
}

func TestOPAClient_Evaluate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	client := NewOPAClient(server.URL, logger)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	_, err := client.Evaluate(context.Background(), nil, req)
	if err == nil {
		t.Error("expected error for server error response")
	}
}

func TestOPAClient_Evaluate_Unreachable(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	client := NewOPAClient("http://localhost:1", logger)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	_, err := client.Evaluate(context.Background(), nil, req)
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestSplitFHIRPathParts(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{"patient with id", "/fhir/r4/Patient/123", []string{"Patient", "123"}},
		{"resource type only", "/fhir/r4/Observation", []string{"Observation"}},
		{"search path", "/fhir/r4/Patient/123/Observation", []string{"Patient", "123", "Observation"}},
		{"no fhir prefix", "/api/Patient/123", []string{}},
		{"empty path", "/", []string{}},
		{"fhir root", "/fhir/r4", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := splitFHIRPathParts(tt.path)
			if len(parts) != len(tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, parts)
				return
			}
			for i, p := range parts {
				if p != tt.expected[i] {
					t.Errorf("part %d: expected %s, got %s", i, tt.expected[i], p)
				}
			}
		})
	}
}

func TestOPAClient_Evaluate_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	client := NewOPAClient(server.URL, logger)

	req := httptest.NewRequest("GET", "/fhir/r4/Patient/123", nil)
	_, err := client.Evaluate(context.Background(), nil, req)
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}
