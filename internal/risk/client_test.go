package risk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestClient_Disabled(t *testing.T) {
	c := NewClient("", zap.NewNop())
	if c.Enabled() {
		t.Error("client should report disabled")
	}
	resp, err := c.Score(context.Background(), Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Score != 0 || resp.Label != "normal" {
		t.Errorf("expected zero-score fallback, got %+v", resp)
	}
}

func TestClient_Score_Happy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/score" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		var in Request
		json.NewDecoder(r.Body).Decode(&in)
		if in.UserID != "nurse1" {
			t.Errorf("user_id not sent: %+v", in)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Response{
			Score: 0.82,
			Label: "anomalous",
			Explanation: map[string]float64{
				"hour":      0.4,
				"dept_mismatch": 0.3,
			},
		})
	}))
	defer server.Close()

	c := NewClient(server.URL, zap.NewNop())
	resp, err := c.Score(context.Background(), Request{
		UserID:       "nurse1",
		Role:         "nurse",
		Department:   "cardiology",
		PatientID:    "123",
		ResourceType: "Patient",
		Action:       "read",
		Hour:         3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Score != 0.82 || resp.Label != "anomalous" {
		t.Errorf("unexpected response: %+v", resp)
	}
	if resp.Explanation["hour"] != 0.4 {
		t.Errorf("explanation missing: %+v", resp.Explanation)
	}
}

func TestClient_Score_Unreachable(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", zap.NewNop())
	resp, err := c.Score(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected fallback, got err %v", err)
	}
	if resp.Score != 0 {
		t.Errorf("expected fallback score 0, got %v", resp.Score)
	}
}

func TestClient_Score_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewClient(server.URL, zap.NewNop())
	resp, err := c.Score(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected fallback, got err %v", err)
	}
	if resp.Score != 0 {
		t.Errorf("expected fallback score 0, got %v", resp.Score)
	}
}
