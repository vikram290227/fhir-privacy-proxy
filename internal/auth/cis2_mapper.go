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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

// ErrMalformedIdentityClaims is returned when the CIS2 token carries no
// recognised SDS role assertion. Under DSPT a proxy must never invent
// authorisation context — a missing or unrecognised role must hard-fail
// with HTTP 401, not silently default to any role.
var ErrMalformedIdentityClaims = errors.New("cis2: malformed or missing role assertion in identity claims")

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

// rCodeToRole is the active R-code → role mapping. Seeded at startup by
// NewCIS2Mapper; falls back to an empty map so all R-codes are rejected
// until the YAML is loaded (fail-safe: no silent role assignment).
var rCodeToRole = map[string]string{}

// rbacMappingFile is the YAML structure for configs/rbac_mapping.yaml.
type rbacMappingFile struct {
	Mappings map[string]string `yaml:"mappings"`
}

// LoadRBACMapping reads an rbac_mapping.yaml file and returns the R-code map.
func LoadRBACMapping(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cis2: open rbac mapping %q: %w", path, err)
	}
	defer f.Close()

	var cfg rbacMappingFile
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("cis2: decode rbac mapping %q: %w", path, err)
	}
	if len(cfg.Mappings) == 0 {
		return nil, fmt.Errorf("cis2: rbac mapping %q has no entries", path)
	}
	return cfg.Mappings, nil
}

// NewCIS2Mapper loads the RBAC mapping from path and installs it as the
// active rCodeToRole table. Call once at startup before serving requests.
func NewCIS2Mapper(path string) error {
	m, err := LoadRBACMapping(path)
	if err != nil {
		return err
	}
	rCodeToRole = m
	return nil
}

// extractCIS2Roles derives proxy role strings from the active NRBAC role.
// When selected_roleid is set only the matching role object contributes;
// otherwise all roles are unioned (OPA enforces least-privilege).
func extractCIS2Roles(claims jwt.MapClaims) ([]string, error) {
	roles := parseCIS2NRBACRoles(claims)
	if len(roles) == 0 {
		return nil, fmt.Errorf("%w: nhsid_nrbac_roles absent or empty", ErrMalformedIdentityClaims)
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
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no recognised SDS R-codes in role profile", ErrMalformedIdentityClaims)
	}
	return out, nil
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
