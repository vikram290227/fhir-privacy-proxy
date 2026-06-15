package proxy

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestInjectNHSAPIKey_NHSDomain_KeyAdded(t *testing.T) {
	h := &FHIRProxyHandler{nhsAPIKey: "test-key-123", logger: zap.NewNop()}
	req, _ := http.NewRequest("GET", "https://sandbox.api.service.nhs.uk/personal-demographics/FHIR/R4/Patient/9000000009", nil)

	h.injectNHSAPIKey(req)

	require.Equal(t, "test-key-123", req.Header.Get("apikey"))
}

func TestInjectNHSAPIKey_NonNHSDomain_KeyNotAdded(t *testing.T) {
	h := &FHIRProxyHandler{nhsAPIKey: "test-key-123", logger: zap.NewNop()}
	req, _ := http.NewRequest("GET", "http://hapi:8080/fhir/Patient/1", nil)

	h.injectNHSAPIKey(req)

	require.Empty(t, req.Header.Get("apikey"))
}

func TestInjectNHSAPIKey_NHSDomain_NoKeyConfigured_LogsWarning(t *testing.T) {
	h := &FHIRProxyHandler{nhsAPIKey: "", logger: zap.NewNop()}
	req, _ := http.NewRequest("GET", "https://sandbox.api.service.nhs.uk/personal-demographics/FHIR/R4/Patient/1", nil)

	h.injectNHSAPIKey(req) // should not panic

	require.Empty(t, req.Header.Get("apikey"))
}

func TestInjectNHSAPIKey_AuthorizationHeaderStripped(t *testing.T) {
	h := &FHIRProxyHandler{nhsAPIKey: "test-key", logger: zap.NewNop()}
	req, _ := http.NewRequest("GET", "https://sandbox.api.service.nhs.uk/personal-demographics/FHIR/R4/Patient/1", nil)
	req.Header.Set("Authorization", "Bearer some-clinician-jwt")

	// Director runs these in sequence — simulate the full chain.
	req.Header.Del("Authorization")
	h.injectNHSAPIKey(req)

	require.Empty(t, req.Header.Get("Authorization"))
	require.Equal(t, "test-key", req.Header.Get("apikey"))
}
