package auth

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// claims.go is the single source of truth for translating raw JWT claims
// into the domain structures used by the rest of the proxy. Every caller
// that needs to read something out of a verified token MUST go through
// one of these extractors — no ad-hoc type-asserting in handlers or
// middleware.

// extractRoles pulls the list of realm roles from a Keycloak-style JWT.
// Returns nil if realm_access.roles is missing or malformed.
func extractRoles(claims jwt.MapClaims) []string {
	realmAccess, ok := claims["realm_access"].(map[string]interface{})
	if !ok {
		return nil
	}
	rolesList, ok := realmAccess["roles"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(rolesList))
	for _, role := range rolesList {
		if s, ok := role.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// extractFHIRContext pulls the custom `fhirContext` claim (department,
// role, facility) and fills in safe defaults for missing fields.
func extractFHIRContext(claims jwt.MapClaims) FHIRContext {
	ctx := FHIRContext{
		Department:  "UNKNOWN",
		Facility:    "main-hospital",
		Role:        "unknown",
		SessionType: "clinical",
	}
	raw, ok := claims["fhirContext"].(map[string]interface{})
	if !ok {
		return ctx
	}
	if dept, ok := raw["department"].(string); ok && dept != "" {
		ctx.Department = dept
	}
	if role, ok := raw["role"].(string); ok && role != "" {
		ctx.Role = role
	}
	if facility, ok := raw["facility"].(string); ok && facility != "" {
		ctx.Facility = facility
	}
	if sessionType, ok := raw["session_type"].(string); ok && sessionType != "" {
		ctx.SessionType = sessionType
	}
	return ctx
}

// extractScopes splits the space-delimited SMART scope claim into a
// slice. Returns nil if the claim is missing or empty.
func extractScopes(claims jwt.MapClaims) []string {
	s, ok := claims["scope"].(string)
	if !ok || s == "" {
		return nil
	}
	return strings.Fields(s)
}

// extractClientInfo resolves the OAuth client identity for the token,
// preferring the `azp` (authorized party) claim and falling back to
// `client_id`.
func extractClientInfo(claims jwt.MapClaims) ClientInfo {
	id := getStringClaim(claims, "azp", "client_id")
	return ClientInfo{
		ID:   id,
		Name: id,
	}
}

// extractSession pulls the standard JWT session fields: jti, iat, exp.
func extractSession(claims jwt.MapClaims) SessionInfo {
	return SessionInfo{
		TokenID:   getStringClaim(claims, "jti"),
		IssuedAt:  time.Unix(getNumericClaim(claims, "iat"), 0),
		ExpiresAt: time.Unix(getNumericClaim(claims, "exp"), 0),
	}
}

// extractSubjectID returns the `sub` claim. Empty string if missing.
func extractSubjectID(claims jwt.MapClaims) string {
	return getStringClaim(claims, "sub")
}
