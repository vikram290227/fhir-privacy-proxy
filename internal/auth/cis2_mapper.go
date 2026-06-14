package auth

// cis2_mapper.go translates NHS CIS2 (Care Identity Service 2) token
// claims into the FHIRContext and roles the rest of the proxy uses.
//
// CIS2 produces standard OAuth2 access tokens validated against the
// CIS2 OpenAM JWKS endpoint — the JWT validation layer (JWKS fetch,
// RS256 sig check, audience validation) requires no change. The
// difference from Keycloak is purely claims shape:
//
//	Keycloak: realm_access.roles (array), fhirContext.department (string)
//	CIS2:     nhsid_nrbac_roles (array of SDS role objects),
//	          nhsid_org_members (array of ODS org objects)
//
// NHS RBAC reference:
//
//	https://digital.nhs.uk/developer/guides-and-documentation/
//	        security-and-authorisation/user-restricted-restful-apis-nhs-cis2
//	SDS role codes: https://digital.nhs.uk/services/spine/rbac
import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// cis2NRBACRole mirrors one element of the nhsid_nrbac_roles claim.
// The role_code is a colon-delimited triple:
//
//	<activity_set>:<job_category>:<role_R-code>
//
// e.g. "S0080:G0450:R0100" = Registered Nurse.
type cis2NRBACRole struct {
	PersonRoleID string
	OrgCode      string
	RoleName     string
	RoleCode     string
}

// rCodeToRole maps the terminal SDS R-code to the proxy's internal role
// strings. Codes not in this map fall back to "unknown". Reference:
// NHS RBAC Activity/Job code lists (NHS Digital, June 2024 edition).
var rCodeToRole = map[string]string{
	"R0100": "nurse",  // Registered Nurse
	"R0120": "nurse",  // Health Visitor
	"R0200": "doctor", // Healthcare Professional
	"R0203": "doctor", // Midwife
	"R8000": "doctor", // Consultant Physician
	"R8001": "doctor", // Medical Officer
	"R8003": "doctor", // Specialist Registrar
	"R0260": "admin",  // Administrative Officer
	"R0300": "admin",  // Clinical Administrator
	"R0400": "admin",  // Executive / Governance
	"R9200": "admin",  // System Administrator
}

// extractCIS2Roles derives proxy role strings from the active NRBAC role.
// When selected_roleid is set only the matching role object contributes;
// otherwise all roles are unioned (OPA enforces least-privilege).
func extractCIS2Roles(claims jwt.MapClaims) []string {
	roles := parseCIS2NRBACRoles(claims)
	if len(roles) == 0 {
		return nil
	}
	selectedID := getStringClaim(claims, "selected_roleid")
	seen := make(map[string]bool)
	var out []string

	addIfNew := func(rCode string) {
		if mapped, ok := rCodeToRole[terminalRCode(rCode)]; ok && !seen[mapped] {
			out = append(out, mapped)
			seen[mapped] = true
		}
	}

	for _, r := range roles {
		if selectedID == "" || r.PersonRoleID == selectedID {
			addIfNew(r.RoleCode)
		}
	}
	// Fallback: selected_roleid present but nothing matched → union all.
	if len(out) == 0 {
		for _, r := range roles {
			addIfNew(r.RoleCode)
		}
	}
	return out
}

// extractCIS2FHIRContext builds a FHIRContext from CIS2 ODS and NRBAC
// claims. Mapping:
//
//	Facility   = ODS org name of the first org member
//	Department = ODS org code of the active role (proxy for department;
//	             fine-grained workgroup resolution requires a live SDS
//	             lookup outside the token — tracked as future work)
//	Role       = internal role string from rCodeToRole
func extractCIS2FHIRContext(claims jwt.MapClaims) FHIRContext {
	ctx := FHIRContext{
		Department:  "UNKNOWN",
		Facility:    "UNKNOWN",
		Role:        "unknown",
		SessionType: "clinical",
	}
	if name := firstCIS2OrgName(claims); name != "" {
		ctx.Facility = name
	}
	selectedID := getStringClaim(claims, "selected_roleid")
	for _, r := range parseCIS2NRBACRoles(claims) {
		if selectedID != "" && r.PersonRoleID != selectedID {
			continue
		}
		if mapped, ok := rCodeToRole[terminalRCode(r.RoleCode)]; ok {
			ctx.Role = mapped
		}
		if r.OrgCode != "" {
			ctx.Department = r.OrgCode
		}
		break
	}
	return ctx
}

// extractCIS2SubjectID returns the NHS SDS UID (nhsid_useruid) falling
// back to the standard sub claim.
func extractCIS2SubjectID(claims jwt.MapClaims) string {
	if uid := getStringClaim(claims, "nhsid_useruid"); uid != "" {
		return uid
	}
	return getStringClaim(claims, "sub")
}

// ─── private helpers ─────────────────────────────────────────────────────────

func parseCIS2NRBACRoles(claims jwt.MapClaims) []cis2NRBACRole {
	raw, ok := claims["nhsid_nrbac_roles"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]cis2NRBACRole, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		r := cis2NRBACRole{
			PersonRoleID: cis2StringField(m, "person_roleid"),
			OrgCode:      cis2StringField(m, "org_code"),
			RoleName:     cis2StringField(m, "role_name"),
			RoleCode:     cis2StringField(m, "role_code"),
		}
		if r.RoleCode != "" {
			out = append(out, r)
		}
	}
	return out
}

// terminalRCode extracts the R-code segment from "S0080:G0450:R0100" → "R0100".
func terminalRCode(full string) string {
	parts := strings.Split(full, ":")
	return parts[len(parts)-1]
}

func firstCIS2OrgName(claims jwt.MapClaims) string {
	raw, ok := claims["nhsid_org_members"].([]interface{})
	if !ok || len(raw) == 0 {
		return ""
	}
	m, ok := raw[0].(map[string]interface{})
	if !ok {
		return ""
	}
	return cis2StringField(m, "org_name")
}

func cis2StringField(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}
