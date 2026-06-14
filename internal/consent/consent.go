// Package consent queries the upstream FHIR server for Consent
// resources and caches the result so the OPA policy can enforce
// patient-level consent rules without adding an upstream round-trip
// to every request.
//
// The Checker is injected as middleware between ScoreRisk and
// EnforcePolicy. It extracts the patient ID from the request path,
// looks up the most recent active Consent for that patient, and
// attaches a ConsentInfo to the SubjectContext. OPA reads it via
// input.resource.consent.
package consent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
)

// ValidPurposes is the closed set of purpose-of-use values the proxy
// accepts via the X-Purpose-Of-Use header. Anything else is rejected
// at the middleware layer.
var ValidPurposes = map[string]bool{
	"TREATMENT":  true,
	"PAYMENT":    true,
	"OPERATIONS": true,
	"EMERGENCY":  true,
	"RESEARCH":   true,
}

// ConsentCoding is one coding within a FHIR CodeableConcept.
type ConsentCoding struct {
	System string `json:"system,omitempty"`
	Code   string `json:"code"`
}

// ConsentPurpose wraps one purpose entry as a CodeableConcept so OPA can
// iterate `some coding in concept.coding` and match `coding.code`. Preserving
// the nested structure avoids a flat-string comparison that silently fails
// against real INTEROPen CareConnect / NHS consent profiles.
type ConsentPurpose struct {
	Coding []ConsentCoding `json:"coding"`
}

// ConsentInfo is the subset of a FHIR Consent resource the OPA
// policy needs to make an allow/deny decision. It is serialised as
// `input.resource.consent` in the OPA input.
type ConsentInfo struct {
	Status          string           `json:"status"`
	Scope           string           `json:"scope"`
	AllowedPurposes []ConsentPurpose `json:"allowed_purposes"`
	ProvisionType   string           `json:"provision_type"`
}

// cacheEntry wraps a ConsentInfo with a wall-clock deadline so
// stale entries can be evicted even if the LRU hasn't bumped them.
type cacheEntry struct {
	info      *ConsentInfo
	expiresAt time.Time
}

// cacheKey is (patientID, purposeOfUse) — we cache per purpose
// because different purposes may match different Consent provisions.
type cacheKey struct {
	patientID string
	purpose   string
}

// Checker queries the upstream FHIR server for Consent resources.
type Checker struct {
	fhirBase   string
	httpClient *http.Client
	logger     *zap.Logger

	mu    sync.Mutex
	cache *lru.Cache[cacheKey, *cacheEntry]
	ttl   time.Duration
}

// NewChecker creates a Checker pointed at the given upstream FHIR
// base URL (e.g. "http://fhir:8080/fhir"). Cache size is capped at
// maxEntries and entries expire after ttl.
func NewChecker(fhirBase string, logger *zap.Logger, maxEntries int, ttl time.Duration) (*Checker, error) {
	c, err := lru.New[cacheKey, *cacheEntry](maxEntries)
	if err != nil {
		return nil, fmt.Errorf("consent: creating LRU cache: %w", err)
	}
	return &Checker{
		fhirBase:   fhirBase,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		logger:     logger,
		cache:      c,
		ttl:        ttl,
	}, nil
}

// Lookup returns the ConsentInfo for the given patient+purpose,
// serving from cache when available and fresh. A nil result means
// no Consent resource was found — the OPA policy should treat this
// as "no consent on file" (which may still be allowed depending on
// break-glass or emergency purpose).
func (c *Checker) Lookup(ctx context.Context, patientID, purpose string) (*ConsentInfo, error) {
	if patientID == "" {
		return nil, nil
	}

	key := cacheKey{patientID: patientID, purpose: purpose}

	c.mu.Lock()
	if entry, ok := c.cache.Get(key); ok {
		if time.Now().Before(entry.expiresAt) {
			c.mu.Unlock()
			return entry.info, nil
		}
		c.cache.Remove(key)
	}
	c.mu.Unlock()

	info, err := c.queryFHIR(ctx, patientID)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache.Add(key, &cacheEntry{
		info:      info,
		expiresAt: time.Now().Add(c.ttl),
	})
	c.mu.Unlock()

	return info, nil
}

// fhirBundle is the minimal subset of a FHIR Bundle we need to
// parse from the upstream search response.
type fhirBundle struct {
	Entry []struct {
		Resource json.RawMessage `json:"resource"`
	} `json:"entry"`
}

// fhirConsent is the minimal subset of a FHIR Consent resource.
type fhirConsent struct {
	ResourceType string `json:"resourceType"`
	Status       string `json:"status"`
	Scope        struct {
		Coding []struct {
			Code string `json:"code"`
		} `json:"coding"`
	} `json:"scope"`
	Provision struct {
		Type    string `json:"type"`
		Purpose []struct {
			System string `json:"system"`
			Code   string `json:"code"`
		} `json:"purpose"`
	} `json:"provision"`
}

// queryFHIR searches the upstream FHIR server for Consent resources
// referencing the given patient. Returns nil (not an error) when
// no Consent exists.
func (c *Checker) queryFHIR(ctx context.Context, patientID string) (*ConsentInfo, error) {
	url := fmt.Sprintf("%s/Consent?patient=Patient/%s&status=active&_sort=-_lastUpdated&_count=1",
		c.fhirBase, patientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("consent: building request: %w", err)
	}
	req.Header.Set("Accept", "application/fhir+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("consent: upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("consent: upstream returned %d", resp.StatusCode)
	}

	var bundle fhirBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("consent: decoding bundle: %w", err)
	}

	if len(bundle.Entry) == 0 {
		return nil, nil
	}

	var consent fhirConsent
	if err := json.Unmarshal(bundle.Entry[0].Resource, &consent); err != nil {
		return nil, fmt.Errorf("consent: decoding consent resource: %w", err)
	}

	scope := ""
	if len(consent.Scope.Coding) > 0 {
		scope = consent.Scope.Coding[0].Code
	}

	var purposes []ConsentPurpose
	for _, p := range consent.Provision.Purpose {
		if p.Code != "" {
			purposes = append(purposes, ConsentPurpose{
				Coding: []ConsentCoding{{System: p.System, Code: p.Code}},
			})
		}
	}

	return &ConsentInfo{
		Status:          consent.Status,
		Scope:           scope,
		AllowedPurposes: purposes,
		ProvisionType:   consent.Provision.Type,
	}, nil
}
