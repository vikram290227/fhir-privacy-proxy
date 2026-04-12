// Package risk is a small HTTP client for the AI risk-scoring service.
//
// The proxy calls the service before OPA evaluation, attaches the
// returned score (0-1) to the subject context, and OPA then uses the
// score to make adaptive authorization decisions. The service is
// optional — if RISK_SERVICE_URL is empty the client returns a zero
// score and the proxy continues normally.
package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Request is the JSON payload sent to the scoring service.
// The schema must match the FastAPI model (see ml/risk_service.py).
type Request struct {
	UserID       string `json:"user_id"`
	Role         string `json:"role"`
	Department   string `json:"department"`
	PatientID    string `json:"patient_id"`
	ResourceType string `json:"resource_type"`
	Action       string `json:"action"`
	Hour         int    `json:"hour"`
	DayOfWeek    int    `json:"day_of_week"`
	BreakGlass   bool   `json:"break_glass"`
}

// Response is returned by the scoring service.
type Response struct {
	Score       float64            `json:"score"`        // 0-1, higher = more anomalous
	Label       string             `json:"label"`        // "normal" | "suspicious" | "anomalous"
	Explanation map[string]float64 `json:"explanation"`  // SHAP-style feature attributions
}

// Client is a thin wrapper over http.Client that knows the risk service
// URL and returns a safe fallback when the service is disabled.
type Client struct {
	baseURL string
	http    *http.Client
	logger  *zap.Logger
}

// NewClient constructs a risk client. If baseURL is empty the client
// is considered disabled and Score always returns a zero response.
func NewClient(baseURL string, logger *zap.Logger) *Client {
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 2 * time.Second},
		logger:  logger,
	}
}

// Enabled reports whether the client has a real endpoint configured.
func (c *Client) Enabled() bool { return c != nil && c.baseURL != "" }

// Score posts a Request to the /score endpoint and returns the parsed
// response. On any error it returns a zero-score response and logs a
// warning so the proxy never fails closed on a missing ML service.
func (c *Client) Score(ctx context.Context, req Request) (*Response, error) {
	if !c.Enabled() {
		return &Response{Score: 0, Label: "normal"}, nil
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("risk: marshal: %w", err)
	}

	url := c.baseURL + "/score"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("risk: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		c.logger.Warn("risk service unreachable, defaulting score=0", zap.Error(err))
		return &Response{Score: 0, Label: "normal"}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.logger.Warn("risk service error, defaulting score=0",
			zap.Int("status", resp.StatusCode))
		return &Response{Score: 0, Label: "normal"}, nil
	}

	var out Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("risk: decode: %w", err)
	}
	return &out, nil
}
