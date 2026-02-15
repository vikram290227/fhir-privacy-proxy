package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	//"github.com/vikram290227/fhir-privacy-proxy/internal/auth"
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
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
		},
		logger: logger,
	}
}

func (c *OPAClient) Evaluate(ctx context.Context, subject interface{}, r *http.Request) (*Decision, error) {
	// Split path like /fhir/r4/Patient/123 -> ["Patient","123"]
	parts := splitFHIRPathParts(r.URL.Path)

	resourceType := ""
	patientID := ""
	if len(parts) >= 1 {
		resourceType = parts[0]
	}
	if len(parts) >= 2 && parts[0] == "Patient" {
		patientID = parts[1]
	}

	input := map[string]interface{}{
		"subject": subject,
		"request": map[string]interface{}{
			"method":     r.Method,
			"path":       r.URL.Path,
			"path_parts": parts,
		},
		"resource": map[string]interface{}{
			"type":       resourceType,
			"patient_id": patientID,
			"department": getResourceDeptFromRequest(r),
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

// splitFHIRPathParts extracts the FHIR resource segments from a request path.
// e.g. /fhir/r4/Patient/123 -> ["Patient", "123"]
func splitFHIRPathParts(path string) []string {
	p := strings.Trim(path, "/")
	segs := strings.Split(p, "/")
	if len(segs) >= 3 && segs[0] == "fhir" && segs[1] == "r4" {
		return segs[2:]
	}
	return []string{}
}

// getSubjectDept extracts the department from the subject's FHIR context.
// For the local MVP this makes resource.department match the requester's
// department so valid_department_access passes for non-admin roles.
//
//	func getSubjectDept(subject interface{}) string {
//		if s, ok := subject.(*auth.SubjectContext); ok {
//			if s.FHIRContext.Department != "" {
//				return s.FHIRContext.Department
//			}
//		}
//		return "UNKNOWN"
//	}
func getResourceDeptFromRequest(r *http.Request) string {
	// TEMP for local testing. Later: look up from upstream FHIR or mapping table.
	if d := r.Header.Get("X-Resource-Department"); d != "" {
		return d
	}
	return "UNKNOWN"
}
