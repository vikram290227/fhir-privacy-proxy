package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"go.uber.org/zap"
)

const nhsSandboxHost = "sandbox.api.service.nhs.uk"

// FHIRProxyHandler wraps httputil.ReverseProxy and injects NHS API Platform
// credentials in the Director — after upstream routing but before the request
// leaves the process.
type FHIRProxyHandler struct {
	proxy     *httputil.ReverseProxy
	nhsAPIKey string // loaded once at startup, never per-request
	logger    *zap.Logger
}

// NewFHIRProxyHandler creates a reverse-proxy handler for the given upstream
// URL. NHS_API_KEY is read from the environment once at construction time.
func NewFHIRProxyHandler(upstreamURL *url.URL, logger *zap.Logger) *FHIRProxyHandler {
	h := &FHIRProxyHandler{
		nhsAPIKey: os.Getenv("NHS_API_KEY"),
		logger:    logger,
	}

	h.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Rewrite scheme/host to upstream — must happen before
			// injectNHSAPIKey so the host check sees the upstream host.
			req.URL.Scheme = upstreamURL.Scheme
			req.URL.Host = upstreamURL.Host
			req.Host = upstreamURL.Host

			// Strip the client's inbound Authorization header (CIS2/Keycloak JWT)
			// before forwarding — never leak the clinician's bearer token upstream.
			req.Header.Del("Authorization")

			// Inject NHS API Platform key only for NHS-destined requests.
			// Other upstreams (local HAPI, per-tenant FHIR servers) must not
			// receive this header.
			h.injectNHSAPIKey(req)
		},
	}

	return h
}

// injectNHSAPIKey adds the apikey header for requests destined for the NHS
// API Platform domain. This is the Apigee-style gateway key, distinct from
// the clinician's CIS2 bearer token — both can be present, serving different
// purposes (gateway auth vs. user identity).
func (h *FHIRProxyHandler) injectNHSAPIKey(req *http.Request) {
	if !strings.HasSuffix(req.URL.Host, nhsSandboxHost) {
		return
	}

	if h.nhsAPIKey == "" {
		h.logger.Warn("request routed to NHS API Platform but NHS_API_KEY is unset",
			zap.String("host", req.URL.Host),
			zap.String("path", req.URL.Path),
		)
		return
	}

	req.Header.Set("apikey", h.nhsAPIKey)
}

func (h *FHIRProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.proxy.ServeHTTP(w, r)
}
