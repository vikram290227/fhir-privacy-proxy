package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/auth"
	fhirredact "github.com/vikram290227/fhir-privacy-proxy/internal/fhir"
	"github.com/vikram290227/fhir-privacy-proxy/internal/policy"
	"github.com/vikram290227/fhir-privacy-proxy/internal/tenant"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Load tenant registry from YAML
	tenantPath := os.Getenv("TENANTS_CONFIG")
	if tenantPath == "" {
		tenantPath = "configs/tenants.yaml"
	}
	tenantRegistry, err := tenant.LoadRegistry(tenantPath)
	if err != nil {
		logger.Fatal("failed to load tenant registry", zap.Error(err))
	}
	logger.Info("loaded tenant registry", zap.Int("tenant_count", len(tenantRegistry.GetAll())))

	// Initialize OPA client
	opaURL := os.Getenv("OPA_URL")
	if opaURL == "" {
		opaURL = "http://opa:8181"
	}
	opaClient := policy.NewOPAClient(opaURL, logger)

	// Initialize auth middleware
	authMiddleware := auth.NewMiddleware(tenantRegistry, logger)

	// Setup router
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Upstream FHIR server
	fhirUpstream := os.Getenv("FHIR_UPSTREAM")
	if fhirUpstream == "" {
		fhirUpstream = "http://localhost:8090/fhir"
	}
	fhirUpstream = strings.TrimRight(fhirUpstream, "/")

	upstreamClient := &http.Client{Timeout: 30 * time.Second}

	// Protected FHIR endpoints
	r.Route("/fhir/r4", func(r chi.Router) {
		r.Use(authMiddleware.ValidateToken)
		r.Use(authMiddleware.EnforcePolicy(opaClient))

		r.Handle("/*", http.HandlerFunc(fhirProxyHandler(fhirUpstream, upstreamClient, logger)))
	})

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("starting FHIR privacy proxy", zap.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server failed", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("server forced to shutdown", zap.Error(err))
	}

	logger.Info("server exited")
}

func fhirProxyHandler(upstream string, client *http.Client, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subjectCtx, ok := r.Context().Value(auth.SubjectContextKey).(*auth.SubjectContext)
		if !ok || subjectCtx == nil {
			http.Error(w, "missing auth context", http.StatusInternalServerError)
			return
		}

		// Build upstream URL: strip the local /fhir/r4 prefix and append to upstream base
		upstreamPath := strings.TrimPrefix(r.URL.Path, "/fhir/r4")
		upstreamURL := upstream + upstreamPath
		if r.URL.RawQuery != "" {
			upstreamURL += "?" + r.URL.RawQuery
		}

		// Forward the request to the upstream FHIR server
		upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
		if err != nil {
			logger.Error("failed to create upstream request", zap.Error(err))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Copy relevant headers
		for _, h := range []string{"Content-Type", "Accept", "If-None-Match", "If-Modified-Since"} {
			if v := r.Header.Get(h); v != "" {
				upReq.Header.Set(h, v)
			}
		}

		upResp, err := client.Do(upReq)
		if err != nil {
			logger.Error("upstream request failed", zap.String("url", upstreamURL), zap.Error(err))
			http.Error(w, "upstream unreachable", http.StatusBadGateway)
			return
		}
		defer upResp.Body.Close()

		body, err := io.ReadAll(upResp.Body)
		if err != nil {
			logger.Error("failed to read upstream body", zap.Error(err))
			http.Error(w, "upstream read error", http.StatusBadGateway)
			return
		}

		// For non-JSON or non-200 responses, pass through as-is
		ct := upResp.Header.Get("Content-Type")
		if upResp.StatusCode != http.StatusOK || !strings.Contains(ct, "json") {
			copyResponseHeaders(w, upResp)
			w.WriteHeader(upResp.StatusCode)
			w.Write(body)
			return
		}

		// Apply field-level redaction from OPA policy decision
		var remove, mask []string
		if subjectCtx.Policy != nil {
			remove = subjectCtx.Policy.Remove
			mask = subjectCtx.Policy.Mask
		}

		redacted, err := fhirredact.ApplyRedactions(body, remove, mask)
		if err != nil {
			// Redaction failed (e.g. malformed JSON) — pass through unchanged
			logger.Warn("redaction failed, passing through raw body", zap.Error(err))
			redacted = body
		}

		// Write (possibly redacted) response
		copyResponseHeaders(w, upResp)
		w.Header().Set("Content-Type", "application/fhir+json")
		w.WriteHeader(http.StatusOK)
		w.Write(redacted)
	}
}

// copyResponseHeaders copies safe upstream headers to the client response.
func copyResponseHeaders(w http.ResponseWriter, resp *http.Response) {
	for _, h := range []string{"ETag", "Last-Modified", "X-Request-Id"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
}

