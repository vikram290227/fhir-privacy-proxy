package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/vikram290227/fhir-privacy-proxy/internal/policy"
	"github.com/vikram290227/fhir-privacy-proxy/internal/tenant"
)

type Middleware struct {
	tenantRegistry *tenant.Registry
	jwksCache      map[string]*keyfunc.JWKS
	jwksMu         sync.Mutex
	logger         *zap.Logger
}

func NewMiddleware(tenantRegistry *tenant.Registry, logger *zap.Logger) *Middleware {
	return &Middleware{
		tenantRegistry: tenantRegistry,
		jwksCache:      make(map[string]*keyfunc.JWKS),
		logger:         logger,
	}
}

func (m *Middleware) ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractBearerToken(r)
		if tokenString == "" {
			respondWithError(w, 401, "missing_token", "Authorization header required")
			return
		}

		claims, tenantConfig, err := m.validateJWT(tokenString)
		if err != nil {
			m.logger.Error("token validation failed", zap.Error(err))
			respondWithError(w, 401, "invalid_token", err.Error())
			return
		}

		subjectCtx, err := m.buildSubjectContext(claims, tenantConfig, r)
		if err != nil {
			respondWithError(w, 400, "invalid_claims", err.Error())
			return
		}

		if !subjectCtx.HasRoles {
			m.logger.Warn("authenticated user has no roles", zap.String("subject", subjectCtx.SubjectID))
		}

		ctx := context.WithValue(r.Context(), SubjectContextKey, subjectCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) validateJWT(tokenString string) (jwt.MapClaims, *tenant.Config, error) {
	// Parse without verification to get issuer
	unverified, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, nil, fmt.Errorf("malformed token: %w", err)
	}

	claims := unverified.Claims.(jwt.MapClaims)
	issuer, ok := claims["iss"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("missing issuer claim")
	}

	// Get tenant config
	tenantConfig, err := m.tenantRegistry.GetByIssuer(issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("untrusted issuer: %s", issuer)
	}

	// Get or create JWKS for this tenant
	jwks, err := m.getJWKS(tenantConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("jwks fetch failed: %w", err)
	}

	// Verify signature, audience, and issuer
	token, err := jwt.Parse(tokenString, jwks.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithAudience(tenantConfig.Audience),
		jwt.WithIssuer(tenantConfig.IssuerURL),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("signature validation failed: %w", err)
	}

	if !token.Valid {
		return nil, nil, fmt.Errorf("invalid token")
	}

	verified := token.Claims.(jwt.MapClaims)

	return verified, tenantConfig, nil
}

func (m *Middleware) getJWKS(config *tenant.Config) (*keyfunc.JWKS, error) {
	m.jwksMu.Lock()
	defer m.jwksMu.Unlock()
	if jwks, ok := m.jwksCache[config.TenantID]; ok {
		return jwks, nil
	}

	jwks, err := keyfunc.Get(config.JWKSEndpoint, keyfunc.Options{
		RefreshInterval: 15 * time.Minute,
	})
	if err != nil {
		return nil, err
	}

	m.jwksCache[config.TenantID] = jwks
	return jwks, nil
}

func (m *Middleware) buildSubjectContext(claims jwt.MapClaims, config *tenant.Config, r *http.Request) (*SubjectContext, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}

	// Extract roles
	var roles []string
	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if rolesList, ok := realmAccess["roles"].([]interface{}); ok {
			for _, role := range rolesList {
				if roleStr, ok := role.(string); ok {
					roles = append(roles, roleStr)
				}
			}
		}
	}

	// Extract FHIR context
	fhirCtx := FHIRContext{
		Department:  "UNKNOWN",
		Facility:    "main-hospital",
		Role:        "unknown",
		SessionType: "clinical",
	}

	if fhirContext, ok := claims["fhirContext"].(map[string]interface{}); ok {
		if dept, ok := fhirContext["department"].(string); ok {
			fhirCtx.Department = dept
		}
		if role, ok := fhirContext["role"].(string); ok {
			fhirCtx.Role = role
		}
		if facility, ok := fhirContext["facility"].(string); ok {
			fhirCtx.Facility = facility
		}
	}

	// Extract scopes
	var scopes []string
	if scopeStr, ok := claims["scope"].(string); ok {
		scopes = strings.Split(scopeStr, " ")
	}

	// Build context
	ctx := &SubjectContext{
		SubjectID:   sub,
		SubjectType: "practitioner",
		Roles:       roles,
		HasRoles:    len(roles) > 0,
		FHIRContext: fhirCtx,
		Client: ClientInfo{
			ID:   getStringClaim(claims, "azp", "client_id"),
			Name: getStringClaim(claims, "azp", "client_id"),
		},
		Scopes: scopes,
		Session: SessionInfo{
			TokenID:   getStringClaim(claims, "jti"),
			IssuedAt:  time.Unix(getNumericClaim(claims, "iat"), 0),
			ExpiresAt: time.Unix(getNumericClaim(claims, "exp"), 0),
		},
		TenantID: config.TenantID,
	}

	// Check for break-glass
	if r.Header.Get("X-Break-Glass") == "true" {
		if !contains(roles, "can_break_glass") {
			return nil, fmt.Errorf("break-glass attempted without permission")
		}

		justification := r.Header.Get("X-Break-Glass-Justification")
		if justification == "" {
			return nil, fmt.Errorf("break-glass requires justification")
		}

		ctx.BreakGlass = &BreakGlassContext{
			Enabled:       true,
			Justification: justification,
			RequestedBy:   sub,
		}

		m.logger.Warn("BREAK_GLASS_ACCESS",
			zap.String("subject", sub),
			zap.String("justification", justification))
	}

	return ctx, nil
}

func (m *Middleware) EnforcePolicy(opaClient *policy.OPAClient) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subjectCtx, ok := r.Context().Value(SubjectContextKey).(*SubjectContext)
			if !ok || subjectCtx == nil {
				respondWithError(w, 500, "internal_error", "missing auth context")
				return
			}

			decision, err := opaClient.Evaluate(r.Context(), subjectCtx, r)
			if err != nil {
				m.logger.Error("policy evaluation failed", zap.Error(err))
				respondWithError(w, 500, "policy_error", "Authorization check failed")
				return
			}

			if !decision.Allow {
				respondWithError(w, 403, "access_denied", decision.Reason)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
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
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorType,
		"error_description": message,
	})
}

func getStringClaim(claims jwt.MapClaims, keys ...string) string {
	for _, key := range keys {
		if val, ok := claims[key].(string); ok {
			return val
		}
	}
	return ""
}

func getNumericClaim(claims jwt.MapClaims, key string) int64 {
	if val, ok := claims[key].(float64); ok {
		return int64(val)
	}
	return 0
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
