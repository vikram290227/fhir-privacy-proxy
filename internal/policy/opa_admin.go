package policy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
)

// OPAAdmin talks to OPA's policy management API:
//
//	PUT    /v1/policies/{id}   — upload/replace a Rego module
//	DELETE /v1/policies/{id}   — remove a module
//	GET    /v1/policies/{id}   — fetch the currently-loaded source
//
// This is distinct from OPAClient (which hits /v1/data/authz/decision
// to evaluate policy). The admin client is owned by the policyversion
// package so Activate/Rollback can actually swap the bundle OPA is
// running, not just update an in-process pointer.
type OPAAdmin struct {
	baseURL    string
	httpClient *http.Client
	logger     *zap.Logger
}

// NewOPAAdmin constructs an admin client against the same OPA instance
// as OPAClient. baseURL should be the OPA server root, e.g.
// "http://opa:8181" — NOT include /v1.
func NewOPAAdmin(baseURL string, logger *zap.Logger) *OPAAdmin {
	return &OPAAdmin{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		logger:     logger,
	}
}

// PutPolicy uploads (or replaces) the Rego module under the given id.
// OPA treats PUT as idempotent — the id is an opaque key OPA uses to
// track the module for later replace/delete. A 2xx response is the
// only acceptable outcome; anything else surfaces as an error so the
// caller can roll back its in-memory state.
func (a *OPAAdmin) PutPolicy(ctx context.Context, id string, rego []byte) error {
	if id == "" {
		return fmt.Errorf("opaadmin: policy id required")
	}
	if len(rego) == 0 {
		return fmt.Errorf("opaadmin: rego body empty for %s", id)
	}

	u := fmt.Sprintf("%s/v1/policies/%s", a.baseURL, url.PathEscape(id))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(rego))
	if err != nil {
		return fmt.Errorf("opaadmin: build request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("opaadmin: PUT %s: %w", id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("opaadmin: PUT %s returned %d: %s", id, resp.StatusCode, string(body))
	}

	if a.logger != nil {
		a.logger.Info("opa policy uploaded",
			zap.String("id", id),
			zap.Int("bytes", len(rego)))
	}
	return nil
}

// DeletePolicy removes a Rego module previously uploaded via PutPolicy.
// A 404 is treated as success (nothing to delete is the desired
// end-state anyway) so this is safe to call defensively.
func (a *OPAAdmin) DeletePolicy(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("opaadmin: policy id required")
	}

	u := fmt.Sprintf("%s/v1/policies/%s", a.baseURL, url.PathEscape(id))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return fmt.Errorf("opaadmin: build request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("opaadmin: DELETE %s: %w", id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("opaadmin: DELETE %s returned %d: %s", id, resp.StatusCode, string(body))
	}
	return nil
}

// GetPolicy fetches the raw Rego currently loaded under id. Primarily
// useful for diagnostics / tests; production callers drive the store
// from disk via PutPolicy.
func (a *OPAAdmin) GetPolicy(ctx context.Context, id string) ([]byte, error) {
	u := fmt.Sprintf("%s/v1/policies/%s", a.baseURL, url.PathEscape(id))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("opaadmin: build request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opaadmin: GET %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("opaadmin: GET %s returned %d: %s", id, resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}
