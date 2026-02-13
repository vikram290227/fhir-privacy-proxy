package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

type OPAClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *zap.Logger
}

type Decision struct {
	Allow  bool     `json:"allow"`
	Reason string   `json:"reason"`
	Remove []string `json:"remove,omitempty"`
	Mask   []string `json:"mask,omitempty"`
}

type opaRequest struct {
	Input interface{} `json:"input"`
}

type opaResponse struct {
	Result Decision `json:"result"`
}

func NewOPAClient(baseURL string, logger *zap.Logger) *OPAClient {
	return &OPAClient{
		baseURL:    baseURL,
		httpClient: &http.Client{},
		logger:     logger,
	}
}

func (c *OPAClient) Evaluate(ctx context.Context, subject interface{}, r *http.Request) (*Decision, error) {
	input := map[string]interface{}{
		"subject": subject,
		"request": map[string]interface{}{
			"method": r.Method,
			"path":   r.URL.Path,
		},
	}

	body, err := json.Marshal(opaRequest{Input: input})
	if err != nil {
		return nil, fmt.Errorf("marshaling OPA input: %w", err)
	}

	url := fmt.Sprintf("%s/v1/data/authz/decision", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OPA returned status %d", resp.StatusCode)
	}

	var opaResp opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, fmt.Errorf("decoding OPA response: %w", err)
	}

	return &opaResp.Result, nil
}
