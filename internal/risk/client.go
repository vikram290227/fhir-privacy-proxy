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
	// Tier 1 behavioral signals — populated from Redis counters by the proxy
	// before calling the ML service so the model can use them as features.
	AccessesLastMinute int64 `json:"accesses_last_minute"`
	AccessesLastHour   int64 `json:"accesses_last_hour"`
	IsAfterHours       bool  `json:"is_after_hours"`
}

// Response is returned by the scoring service.
type Response struct {
	Score       float64            `json:"score"`       // 0-1, higher = more anomalous
	Label       string             `json:"label"`       // "normal" | "suspicious" | "anomalous"
	Explanation map[string]float64 `json:"explanation"` // SHAP-style feature attributions
	// Unavailable is true when the score could not be obtained (timeout, service
	// down, decode error). Callers must not treat score=0 as "low risk" when
	// Unavailable is true — fall back to Tier 1 rule-based decisions instead.
	Unavailable bool `json:"unavailable,omitempty"`
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
// ScoreTimeout is the hard deadline for a single /score call. Kept well below
// the OPA evaluation budget (typically <5 ms) so that ML latency never
// dominates the synchronous request path. Callers get Unavailable=true when
// the deadline is exceeded, which triggers Tier 1 rule-only enforcement.
const ScoreTimeout = 15 * time.Millisecond

func NewClient(baseURL string, logger *zap.Logger) *Client {
	return NewClientWithTimeout(baseURL, ScoreTimeout, logger)
}

// NewClientWithTimeout is like NewClient but allows overriding the HTTP
// timeout — useful in tests where loopback latency can exceed ScoreTimeout.
func NewClientWithTimeout(baseURL string, timeout time.Duration, logger *zap.Logger) *Client {
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: timeout},
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
		c.logger.Warn("risk service unreachable — Tier 1 rules only", zap.Error(err))
		return &Response{Score: 0, Label: "unavailable", Unavailable: true}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.logger.Warn("risk service error — Tier 1 rules only",
			zap.Int("status", resp.StatusCode))
		return &Response{Score: 0, Label: "unavailable", Unavailable: true}, nil
	}

	var out Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		c.logger.Warn("risk service decode error — Tier 1 rules only", zap.Error(err))
		return &Response{Score: 0, Label: "unavailable", Unavailable: true}, nil
	}
	return &out, nil
}
