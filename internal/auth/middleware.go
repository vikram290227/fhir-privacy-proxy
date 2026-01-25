package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/YOUR_USERNAME/fhir-privacy-proxy/internal/cache"
	"github.com/YOUR_USERNAME/fhir-privacy-proxy/internal/tenant"
)

type Middleware struct {
	tenantRegistry  *tenant.Registry
	revocationCache *cache.RevocationCache
	logger          *zap.Logger
}

func NewMiddleware(
	tenantRegistry *tenant.Registry,
	revocationCache *cache.RevocationCache,
	logger *zap.Logger,
) *Middleware {
	return &Middleware{
		tenantRegistry:  tenantRegistry,
		revocationCache: revocationCache,
		logger:          logger,
	}
}

func (m *Middleware) ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract bearer token
		tokenString := extractBearerToken(r)
		if tokenString == "" {
			respondWithError(w, 401, "missing_token", "Authorization header required")
			return
		}

		// Validate JWT and extract claims
		claims, tenantConfig, err := m.validateJWT(tokenString)
		if err != nil {
			m.logger.Error("token validation failed", zap.Error(err))
			respondWithError(w, 401, "invalid_token", err.Error())
			return
		}

		// Check revocation cache
		jti, _ := claims["jti"].(string)
		exp := int64(claims["exp"].(float64))

		revoked, err := m.revocationCache.IsRevoked(tenantConfig.TenantID, jti, exp)
		if err != nil {
			m.logger.Error("revocation check failed", zap.Error(err))
		} else if revoked {
			respondWithError(w, 401, "token_revoked", "Session terminated")
			return
		}

		// Build subject context
		subjectCtx, err := m.buildSubjectContext(claims, tenantConfig, r)
		if err != nil {
			respondWithError(w, 400, "invalid_claims", err.Error())
			return
		}

		// Attach to request context
		ctx := context.WithValue(r.Context(), SubjectContextKey, subjectCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

func respondWithError(w http.ResponseWriter, status int, errorType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error": "%s", "error_description": "%s"}`, errorType, message)
}

func (m *Middleware) validateJWT(tokenString string) (jwt.MapClaims, *tenant.Config, error) {
	// Implementation will be added in jwt_validator.go
	return nil, nil, fmt.Errorf("not implemented")
}

func (m *Middleware) buildSubjectContext(
	claims jwt.MapClaims,
	tenantConfig *tenant.Config,
	r *http.Request,
) (*SubjectContext, error) {
	// Implementation will be added in context_builder.go
	return nil, fmt.Errorf("not implemented")
}
