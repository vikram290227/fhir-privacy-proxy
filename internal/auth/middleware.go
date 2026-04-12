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

	"github.com/vikram290227/fhir-privacy-proxy/internal/metrics"
	"github.com/vikram290227/fhir-privacy-proxy/internal/policy"
	"github.com/vikram290227/fhir-privacy-proxy/internal/tenant"
)

// RevocationChecker is an interface for checking token revocation.
// This allows the middleware to optionally check Redis for revoked tokens.
type RevocationChecker interface {
	IsRevoked(tenantID, jti string, exp int64) (bool, error)
}

type Middleware struct {
	tenantRegistry     *tenant.Registry
	jwksCache          map[string]*keyfunc.JWKS
	jwksMu             sync.Mutex
	logger             *zap.Logger
	revocationChecker  RevocationChecker
}

func NewMiddleware(tenantRegistry *tenant.Registry, logger *zap.Logger) *Middleware {
	return &Middleware{
		tenantRegistry: tenantRegistry,
		jwksCache:      make(map[string]*keyfunc.JWKS),
		logger:         logger,
	}
}

// SetRevocationChecker enables token revocation checking via Redis.
func (m *Middleware) SetRevocationChecker(rc RevocationChecker) {
	m.revocationChecker = rc
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

		// Check token revocation if checker is configured
		if m.revocationChecker != nil {
			jti := getStringClaim(claims, "jti")
			exp := getNumericClaim(claims, "exp")
			if jti != "" {
				revoked, err := m.revocationChecker.IsRevoked(tenantConfig.TenantID, jti, exp)
				if err != nil {
					m.logger.Warn("revocation check failed, allowing request", zap.Error(err))
				} else if revoked {
					respondWithError(w, 401, "token_revoked", "token has been revoked")
					return
				}
			}
		}

		subjectCtx, err := m.buildSubjectContext(claims, tenantConfig, r)
		if err != nil {
			respondWithError(w, 400, "invalid_claims", err.Error())
			return
		}

		// Validate scopes against tenant's allowed scopes
		if len(tenantConfig.AllowedScopes) > 0 && len(subjectCtx.Scopes) > 0 {
			if !hasValidScope(subjectCtx.Scopes, tenantConfig.AllowedScopes) {
				m.logger.Warn("insufficient scopes",
					zap.String("subject", subjectCtx.SubjectID),
					zap.Strings("scopes", subjectCtx.Scopes),
					zap.Strings("allowed", tenantConfig.AllowedScopes))
				respondWithError(w, 403, "insufficient_scope", "token scopes do not match required scopes")
				return
			}
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

// buildSubjectContext assembles the in-process SubjectContext from a
// set of verified claims and the inbound request. It is a thin
// orchestrator — all claim translation lives in claims.go, which is the
// single source of truth for JWT → domain mapping.
func (m *Middleware) buildSubjectContext(claims jwt.MapClaims, config *tenant.Config, r *http.Request) (*SubjectContext, error) {
	sub := extractSubjectID(claims)
	if sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}

	roles := extractRoles(claims)

	ctx := &SubjectContext{
		SubjectID:   sub,
		SubjectType: "practitioner",
		Roles:       roles,
		HasRoles:    len(roles) > 0,
		FHIRContext: extractFHIRContext(claims),
		Client:      extractClientInfo(claims),
		Scopes:      extractScopes(claims),
		Session:     extractSession(claims),
		TenantID:    config.TenantID,
	}

	bg, err := m.resolveBreakGlass(r, sub, roles)
	if err != nil {
		return nil, err
	}
	ctx.BreakGlass = bg

	return ctx, nil
}

// resolveBreakGlass inspects the X-Break-Glass headers and returns a
// BreakGlassContext when the request is claiming an emergency override.
// The subject must carry the `can_break_glass` role AND provide a
// non-empty justification, otherwise an error is returned and the
// request is denied at the auth layer.
func (m *Middleware) resolveBreakGlass(r *http.Request, sub string, roles []string) (*BreakGlassContext, error) {
	if r.Header.Get("X-Break-Glass") != "true" {
		return nil, nil
	}
	if !contains(roles, "can_break_glass") {
		return nil, fmt.Errorf("break-glass attempted without permission")
	}
	justification := r.Header.Get("X-Break-Glass-Justification")
	if justification == "" {
		return nil, fmt.Errorf("break-glass requires justification")
	}

	m.logger.Warn("BREAK_GLASS_ACCESS",
		zap.String("subject", sub),
		zap.String("justification", justification))

	return &BreakGlassContext{
		Enabled:       true,
		Justification: justification,
		RequestedBy:   sub,
	}, nil
}

func (m *Middleware) EnforcePolicy(opaClient *policy.OPAClient) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subjectCtx, ok := r.Context().Value(SubjectContextKey).(*SubjectContext)
			if !ok || subjectCtx == nil {
				respondWithError(w, 500, "internal_error", "missing auth context")
				return
			}

			start := time.Now()
			decision, err := opaClient.Evaluate(r.Context(), subjectCtx, r)
			metrics.PolicyEvalDuration.Observe(time.Since(start).Seconds())
			if err != nil {
				m.logger.Error("policy evaluation failed", zap.Error(err))
				metrics.PolicyOutcome.WithLabelValues(subjectCtx.TenantID, "error", "policy_error").Inc()
				respondWithError(w, 500, "policy_error", "Authorization check failed")
				return
			}

			if !decision.Allow {
				metrics.PolicyOutcome.WithLabelValues(subjectCtx.TenantID, "deny", decision.Reason).Inc()
				respondWithError(w, 403, "access_denied", decision.Reason)
				return
			}

			metrics.PolicyOutcome.WithLabelValues(subjectCtx.TenantID, "allow", decision.Reason).Inc()

			subjectCtx.Policy = &PolicyDecision{
				Remove: decision.Remove,
				Mask:   decision.Mask,
				Reason: decision.Reason,
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

// hasValidScope checks that at least one token scope matches the tenant's allowed scopes.
func hasValidScope(tokenScopes, allowedScopes []string) bool {
	allowed := make(map[string]bool, len(allowedScopes))
	for _, s := range allowedScopes {
		allowed[s] = true
	}
	for _, s := range tokenScopes {
		if allowed[s] {
			return true
		}
	}
	return false
}
