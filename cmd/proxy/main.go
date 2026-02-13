package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/auth"
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

	// Protected FHIR endpoints
	r.Route("/fhir/r4", func(r chi.Router) {
		r.Use(authMiddleware.ValidateToken)
		r.Use(authMiddleware.EnforcePolicy(opaClient))

		r.Handle("/*", http.HandlerFunc(handleFHIRRequest)) // replacing the individual FHIR routes with a  catch-all handler
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

func handleFHIRRequest(w http.ResponseWriter, r *http.Request) {
	subjectCtx, ok := r.Context().Value(auth.SubjectContextKey).(*auth.SubjectContext)
	if !ok || subjectCtx == nil {
		http.Error(w, "missing auth context", http.StatusInternalServerError)
		return
	}

	reqID := middleware.GetReqID(r.Context())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resourceType": "OperationOutcome",
		"issue": []map[string]any{
			{
				"severity":    "information",
				"code":        "informational",
				"diagnostics": "Request authorized",
				"details": map[string]any{
					"subject":    subjectCtx.SubjectID,
					"department": subjectCtx.FHIRContext.Department,
					"request_id": reqID,
				},
			},
		},
	})
}
