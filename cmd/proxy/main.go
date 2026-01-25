package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"github.com/YOUR_USERNAME/fhir-privacy-proxy/internal/auth"
	"github.com/YOUR_USERNAME/fhir-privacy-proxy/internal/cache"
	"github.com/YOUR_USERNAME/fhir-privacy-proxy/internal/policy"
	"github.com/YOUR_USERNAME/fhir-privacy-proxy/internal/tenant"
)

func main() {
	// Initialize logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Load tenant registry
	tenantRegistry, err := tenant.LoadRegistry("configs/tenants.yaml")
	if err != nil {
		logger.Fatal("failed to load tenant registry", zap.Error(err))
	}

	// Initialize revocation cache
	revocationCache := cache.NewRevocationCache("localhost:6379", logger)

	// Initialize policy engine
	policyEngine, err := policy.NewEngine("policies", logger)
	if err != nil {
		logger.Fatal("failed to initialize policy engine", zap.Error(err))
	}

	// Initialize auth middleware
	authMiddleware := auth.NewMiddleware(tenantRegistry, revocationCache, logger)

	// Setup router
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health check (no auth required)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Revocation webhook endpoint
	r.Post("/api/v1/revocation/events", revocationCache.HandleWebhook)

	// Protected FHIR endpoints
	r.Route("/fhir/r4", func(r chi.Router) {
		r.Use(authMiddleware.ValidateToken)
		r.Use(authMiddleware.EnforcePolicy(policyEngine))

		r.Get("/Patient/{id}", handleFHIRRequest)
		r.Get("/Observation", handleFHIRRequest)
		r.Get("/Condition/{id}", handleFHIRRequest)
		// Add more FHIR resource endpoints as needed
	})

	// Start server
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		logger.Info("starting FHIR privacy proxy", zap.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server failed", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
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
	// This will be implemented to proxy to upstream FHIR server
	// with filtering based on policy decisions
	fmt.Fprintf(w, "FHIR endpoint: %s", r.URL.Path)
}
