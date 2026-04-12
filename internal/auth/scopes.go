package auth

import (
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// SMART-on-FHIR scope enforcement.
//
// SMART scopes follow the shape:
//   <level>/<resourceType>.<action>
// where
//   level        = "patient" | "user" | "system"
//   resourceType = a FHIR resource type (Patient, Observation, ...) or "*"
//   action       = "read" | "write" | "*" (the SMART v1 shorthand)
//
// This middleware maps the HTTP method of the incoming request to the
// required action ("read" for safe methods, "write" for unsafe) and
// verifies that the subject's token carries a scope covering the FHIR
// resource targeted by the request. Requests to non-FHIR paths (e.g.
// /health, /metrics) are allowed through because the parent router
// attaches this middleware only to /fhir/r4/*.

// methodAction maps HTTP methods to the SMART action verb.
func methodAction(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "read"
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return "write"
	}
	return ""
}

// parseScope splits a SMART scope string into its (level, resource, action)
// components. Returns ok=false if the scope doesn't match the SMART format.
func parseScope(scope string) (level, resource, action string, ok bool) {
	slash := strings.IndexByte(scope, '/')
	if slash < 0 {
		return "", "", "", false
	}
	level = scope[:slash]
	rest := scope[slash+1:]
	dot := strings.IndexByte(rest, '.')
	if dot < 0 {
		return "", "", "", false
	}
	resource = rest[:dot]
	action = rest[dot+1:]
	if level == "" || resource == "" || action == "" {
		return "", "", "", false
	}
	return level, resource, action, true
}

// scopeCovers reports whether the granted scope permits the requested
// resource + action. Wildcards ("*") on either resource or action are
// honoured; SMART v2 granular verbs (c/r/u/d/s) are also accepted if
// they include "r" for read or "u"/"c"/"d" for write.
func scopeCovers(grantedScope, needResource, needAction string) bool {
	level, res, act, ok := parseScope(grantedScope)
	if !ok {
		return false
	}
	// The proxy accepts patient/ or user/ scopes equally; callers control
	// the level in OPA policy. "system/" is also accepted.
	switch level {
	case "patient", "user", "system":
	default:
		return false
	}
	if res != "*" && res != needResource {
		return false
	}
	return actionMatches(act, needAction)
}

// actionMatches supports SMART v1 ("read", "write", "*") and v2 granular
// verbs. v2 verbs are a subset of "crudsf" (create/read/update/delete/search/fhir)
// expressed as one or more single characters. We only interpret the
// granted string as v2 when every character is in that set — this
// prevents "read" (v1) from spuriously matching "write" because it
// contains a 'd'.
func actionMatches(granted, need string) bool {
	if granted == "*" {
		return true
	}
	if granted == need {
		return true
	}
	if !isV2Granular(granted) {
		return false
	}
	switch need {
	case "read":
		return strings.ContainsAny(granted, "rs")
	case "write":
		return strings.ContainsAny(granted, "cud")
	}
	return false
}

// isV2Granular reports whether the given action string is made up
// solely of SMART v2 granular verb characters.
func isV2Granular(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch c {
		case 'c', 'r', 'u', 'd', 's':
		default:
			return false
		}
	}
	return true
}

// RequireSmartScope returns a middleware that checks the request against
// the SMART scopes attached to the already-validated SubjectContext.
// It must run AFTER ValidateToken (which populates the subject context).
func (m *Middleware) RequireSmartScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub, ok := r.Context().Value(SubjectContextKey).(*SubjectContext)
		if !ok || sub == nil {
			respondWithError(w, http.StatusInternalServerError, "internal_error", "missing auth context")
			return
		}

		resource := extractFhirResourceType(r.URL.Path)
		if resource == "" {
			// Non-FHIR endpoint, nothing to enforce.
			next.ServeHTTP(w, r)
			return
		}

		action := methodAction(r.Method)
		if action == "" {
			respondWithError(w, http.StatusMethodNotAllowed, "method_not_allowed",
				fmt.Sprintf("method %s not supported", r.Method))
			return
		}

		if !scopesAllow(sub.Scopes, resource, action) {
			m.logger.Warn("scope enforcement failed",
				zap.String("subject", sub.SubjectID),
				zap.Strings("scopes", sub.Scopes),
				zap.String("resource", resource),
				zap.String("action", action),
			)
			respondWithError(w, http.StatusForbidden, "insufficient_scope",
				fmt.Sprintf("token does not grant %s on %s", action, resource))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// scopesAllow returns true if any of the granted scopes satisfies the
// (resource, action) requirement.
func scopesAllow(granted []string, resource, action string) bool {
	for _, s := range granted {
		if scopeCovers(s, resource, action) {
			return true
		}
	}
	return false
}

// extractFhirResourceType pulls the FHIR resource type from paths of the
// shape /fhir/r4/{ResourceType}[/...].
func extractFhirResourceType(path string) string {
	p := strings.Trim(path, "/")
	segs := strings.Split(p, "/")
	if len(segs) >= 3 && segs[0] == "fhir" && segs[1] == "r4" {
		return segs[2]
	}
	return ""
}
