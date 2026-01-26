package main

import (
    "context"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "go.uber.org/zap"
    
    "github.com/YOUR_USERNAME/fhir-privacy-proxy/internal/auth"
    "github.com/YOUR_USERNAME/fhir-privacy-proxy/internal/policy"
    "github.com/YOUR_USERNAME/fhir-privacy-proxy/internal/tenant"
)

func main() {
    logger, _ := zap.NewProduction()
    defer logger.Sync()

    // Load tenant registry from YAML
    tenantRegistry, err := tenant.LoadRegistry("configs/tenants.yaml")
    if err != nil {
        logger.Fatal("failed to load tenant registry", zap.Error(err))
    }
    logger.Info("loaded tenant registry", zap.Int("tenant_count", len(tenantRegistry.GetAll())))

    // Initialize OPA client
    opaClient := policy.NewOPAClient("http://opa:8181", logger)

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
        
        r.Get("/Patient/{id}", handleFHIRRequest)
        r.Get("/Observation", handleFHIRRequest)
        r.Post("/Patient", handleFHIRRequest)
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
    // Get subject context from middleware
    subjectCtx := r.Context().Value(auth.SubjectContextKey).(*auth.SubjectContext)
    
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    
    // Mock FHIR response showing context
    w.Write([]byte(`{
  "resourceType": "OperationOutcome",
  "text": {
    "status": "success",
    "div": "Request authorized"
  },
  "issue": [{
    "severity": "information",
    "code": "informational",
    "diagnostics": "Subject: ` + subjectCtx.SubjectID + `, Department: ` + subjectCtx.FHIRContext.Department + `"
  }]
}`))