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

	"github.com/vikram290227/fhir-privacy-proxy/internal/admin"
	"github.com/vikram290227/fhir-privacy-proxy/internal/audit"
	"github.com/vikram290227/fhir-privacy-proxy/internal/auth"
	"github.com/vikram290227/fhir-privacy-proxy/internal/cache"
	"github.com/vikram290227/fhir-privacy-proxy/internal/consent"
	fhirredact "github.com/vikram290227/fhir-privacy-proxy/internal/fhir"
	"github.com/vikram290227/fhir-privacy-proxy/internal/metrics"
	"github.com/vikram290227/fhir-privacy-proxy/internal/policy"
	"github.com/vikram290227/fhir-privacy-proxy/internal/policyversion"
	"github.com/vikram290227/fhir-privacy-proxy/internal/ratelimit"
	"github.com/vikram290227/fhir-privacy-proxy/internal/risk"
	"github.com/vikram290227/fhir-privacy-proxy/internal/tenant"
	"github.com/vikram290227/fhir-privacy-proxy/internal/tracing"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Initialize OpenTelemetry tracing
	shutdownTracer := tracing.Init()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracer(ctx); err != nil {
			logger.Error("failed to shutdown tracer", zap.Error(err))
		}
	}()

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

	// Initialize Redis revocation cache (optional)
	var revocationCache *cache.RevocationCache
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr != "" {
		revocationCache = cache.NewRevocationCache(redisAddr, logger)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := revocationCache.Ping(ctx); err != nil {
			logger.Warn("redis unavailable, token revocation disabled", zap.Error(err))
			revocationCache = nil
		} else {
			logger.Info("redis connected, token revocation enabled", zap.String("addr", redisAddr))
			authMiddleware.SetRevocationChecker(revocationCache)
		}
		cancel()
	} else {
		logger.Info("REDIS_ADDR not set, token revocation disabled")
	}

	// Initialize sliding-window rate limiter (optional, same Redis).
	// Gated on REDIS_ADDR so the dev-loop without Redis keeps working;
	// when enabled it is the backstop for bulk-extraction abuse that
	// the ML risk scorer alone can't stop (large volume, low novelty).
	var rateLimiter *ratelimit.Limiter
	if redisAddr != "" {
		rl := ratelimit.New(redisAddr, logger)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := rl.Ping(ctx); err != nil {
			logger.Warn("redis unavailable, rate limiting disabled", zap.Error(err))
			_ = rl.Close()
		} else {
			logger.Info("redis connected, rate limiting enabled", zap.String("addr", redisAddr))
			rateLimiter = rl
			authMiddleware.SetRateLimiter(rateLimiter)
		}
		cancel()
	} else {
		logger.Info("REDIS_ADDR not set, rate limiting disabled")
	}

	// Initialize audit logger. The proxy prefers a persistent local
	// file (AUDIT_LOG_FILE) for dev/demo and falls back to Azure Blob
	// Storage when AZURE_STORAGE_ACCOUNT is set. We hold onto the
	// concrete *audit.FileLogger so the admin /audit/tail endpoint can
	// reach back to its on-disk path — the generic audit.Sink interface
	// intentionally exposes no path accessor.
	var (
		auditSink     audit.Sink
		auditFileSink *audit.FileLogger
	)
	if filePath := audit.FileLoggerPath(); filePath != "" {
		fileLogger, fileErr := audit.NewFileLogger(filePath, logger)
		if fileErr != nil {
			logger.Warn("file audit logger init failed, continuing without audit", zap.Error(fileErr))
		} else {
			logger.Info("file audit logger enabled", zap.String("path", filePath))
			defer fileLogger.Close()
			auditSink = fileLogger
			auditFileSink = fileLogger
		}
	} else if auditCfg := audit.ConfigFromEnv(); auditCfg != nil {
		azureLogger, auditErr := audit.NewLogger(auditCfg, logger)
		if auditErr != nil {
			logger.Warn("audit logger init failed, continuing without audit", zap.Error(auditErr))
		} else {
			logger.Info("azure audit logger enabled",
				zap.String("account", auditCfg.AccountName),
				zap.String("container", auditCfg.ContainerName),
			)
			defer azureLogger.Close()
			auditSink = azureLogger
		}
	} else {
		logger.Info("AUDIT_LOG_FILE and AZURE_STORAGE_ACCOUNT not set, audit logging disabled")
	}

	// Initialize the policy version manager and wire it to OPA so
	// /admin/v1/policy/{activate,rollback} can hot-swap the bundle OPA
	// is running. POLICIES_DIR overrides the default "policies" root
	// for tests / non-standard layouts.
	policiesDir := os.Getenv("POLICIES_DIR")
	if policiesDir == "" {
		policiesDir = "policies"
	}
	policyMgr, err := policyversion.New(policiesDir)
	if err != nil {
		logger.Warn("policy version manager unavailable, /admin/v1/policy/* will return 503",
			zap.String("dir", policiesDir),
			zap.Error(err))
		policyMgr = nil
	} else {
		opaAdmin := policy.NewOPAAdmin(opaURL, logger)
		policyMgr.SetOPAAdmin(opaAdmin)
		logger.Info("policy version manager loaded",
			zap.String("dir", policiesDir),
			zap.String("active", policyMgr.Active()))
	}

	// Setup router
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(tracing.Middleware)
	r.Use(metrics.InstrumentHandler)

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Prometheus metrics endpoint
	r.Handle("/metrics", metrics.Handler())

	// Keycloak webhook endpoint for token revocation
	if revocationCache != nil {
		r.Post("/webhook/revoke", revocationCache.HandleWebhook)
	}

	// Upstream FHIR base URL is needed by the router setup *and* by
	// the admin /health/deps probe. Resolve it here so both can share
	// the same value.
	fhirUpstream := os.Getenv("FHIR_UPSTREAM")
	if fhirUpstream == "" {
		fhirUpstream = "http://localhost:8090/fhir"
	}
	fhirUpstream = strings.TrimRight(fhirUpstream, "/")

	// Optional risk scoring client — enabled when RISK_SERVICE_URL is set.
	riskServiceURL := os.Getenv("RISK_SERVICE_URL")
	riskClient := risk.NewClient(riskServiceURL, logger)

	// Consent checker — queries upstream FHIR for Consent resources.
	// Cached with a 5-minute TTL / 1024-entry LRU so consent lookups
	// don't add a round-trip to every request for the same patient.
	var consentChecker *consent.Checker
	if fhirUpstream != "" {
		var err error
		consentChecker, err = consent.NewChecker(fhirUpstream, logger, 1024, 5*time.Minute)
		if err != nil {
			logger.Fatal("failed to create consent checker", zap.Error(err))
		}
		logger.Info("consent checker enabled", zap.String("fhir_upstream", fhirUpstream))
	}

	// Mount the management API at /admin/v1 when ADMIN_API_KEY is set.
	// All endpoints require the X-Admin-Key header to match the env
	// var; an unset key keeps the surface entirely off the wire so
	// operators don't have to tear down a route to disable it.
	if adminKey := os.Getenv("ADMIN_API_KEY"); adminKey != "" {
		var revoker admin.Revoker
		if revocationCache != nil {
			revoker = revocationCache
		}
		var redisHealth admin.HealthCheckable
		if revocationCache != nil {
			redisHealth = admin.NewRedisHealthCheck(revocationCache.Ping)
		}
		var auditTailer admin.AuditTailer
		if auditFileSink != nil {
			auditTailer = auditFileSink
		}
		var riskHealth admin.HealthCheckable
		if riskClient.Enabled() {
			riskHealth = admin.NewHTTPHealthCheck(riskServiceURL + "/health")
		}
		adminSrv := admin.New(adminKey, admin.Deps{
			Policy:   admin.WrapPolicyManager(policyMgr),
			Tenants:  tenantRegistry,
			Audit:    auditTailer,
			Revoker:  revoker,
			OPA:      admin.NewHTTPHealthCheck(opaURL + "/health"),
			Redis:    redisHealth,
			Upstream: admin.NewHTTPHealthCheck(fhirUpstream + "/metadata"),
			Risk:     riskHealth,
		}, logger)
		r.Mount("/admin/v1", adminSrv.Router())
		logger.Info("admin API enabled at /admin/v1")
	} else {
		logger.Info("ADMIN_API_KEY not set, admin API disabled")
	}

	upstreamClient := &http.Client{Timeout: 30 * time.Second}

	// Protected FHIR endpoints
	r.Route("/fhir/r4", func(r chi.Router) {
		r.Use(authMiddleware.ValidateToken)
		r.Use(authMiddleware.RequireSmartScope)
		// RateLimit runs AFTER ValidateToken/RequireSmartScope (needs
		// subject_id + tenant_id from the token) and BEFORE ScoreRisk
		// so we don't spend risk-service round trips on requests that
		// are about to be rejected with 429. No-op when REDIS_ADDR is
		// unset — the ML layer remains the backstop in that case.
		r.Use(authMiddleware.RateLimit)
		r.Use(authMiddleware.ScoreRisk(riskClient))
		r.Use(authMiddleware.CheckConsent(consentChecker))
		r.Use(authMiddleware.EnforcePolicy(opaClient))

		r.Handle("/*", http.HandlerFunc(fhirProxyHandler(fhirUpstream, upstreamClient, logger, auditSink)))
	})

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
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

func fhirProxyHandler(upstream string, client *http.Client, logger *zap.Logger, auditLogger audit.Sink) http.HandlerFunc {
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

		// Add tracing span for upstream call
		ctx, span := tracing.Tracer().Start(r.Context(), "upstream.fhir")
		defer span.End()

		// Forward the request to the upstream FHIR server
		start := time.Now()
		upReq, err := http.NewRequestWithContext(ctx, r.Method, upstreamURL, r.Body)
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

		// Record upstream latency
		resourceType := extractResourceType(r.URL.Path)
		metrics.UpstreamDuration.WithLabelValues(r.Method, resourceType).Observe(time.Since(start).Seconds())

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

		// Emit audit event asynchronously
		if auditLogger != nil {
			durationMs := time.Since(start).Milliseconds()
			evt := audit.AuditEvent{
				EventType:    audit.EventAccess,
				TenantID:     subjectCtx.TenantID,
				SubjectID:    subjectCtx.SubjectID,
				Roles:        subjectCtx.Roles,
				ClientID:     subjectCtx.Client.ID,
				Method:       r.Method,
				Path:         r.URL.Path,
				ResourceType: resourceType,
				StatusCode:   http.StatusOK,
				PolicyResult: "allow",
				DurationMs:   durationMs,
			}
			// Capture redaction details
			if len(remove) > 0 || len(mask) > 0 {
				evt.RedactedPaths = append(remove, mask...)
			}
			// Capture break-glass events
			if subjectCtx.BreakGlass != nil && subjectCtx.BreakGlass.Enabled {
				evt.EventType = audit.EventBreakGlass
				evt.BreakGlass = &audit.BreakGlassDetail{
					Justification: subjectCtx.BreakGlass.Justification,
					RequestedBy:   subjectCtx.BreakGlass.RequestedBy,
				}
			}
			auditLogger.Log(evt)
		}
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

// extractResourceType extracts the FHIR resource type from the request path.
func extractResourceType(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "fhir" && parts[1] == "r4" {
		return parts[2]
	}
	return "unknown"
}
