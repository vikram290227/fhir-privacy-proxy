package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func makeCIS2Claims(uid, selectedRoleID string, roles []map[string]interface{}, orgs []map[string]interface{}) jwt.MapClaims {
	c := jwt.MapClaims{
		"sub":             uid,
		"nhsid_useruid":   uid,
		"selected_roleid": selectedRoleID,
	}
	if roles != nil {
		raw := make([]interface{}, len(roles))
		for i, r := range roles {
			raw[i] = r
		}
		c["nhsid_nrbac_roles"] = raw
	}
	if orgs != nil {
		raw := make([]interface{}, len(orgs))
		for i, o := range orgs {
			raw[i] = o
		}
		c["nhsid_org_members"] = raw
	}
	return c
}

func TestExtractCIS2Roles_Nurse(t *testing.T) {
	claims := makeCIS2Claims("787807429511", "role-001", []map[string]interface{}{
		{"person_roleid": "role-001", "org_code": "RCB", "role_code": "S0080:G0450:R0100"},
	}, nil)
	roles := extractCIS2Roles(claims)
	if len(roles) != 1 || roles[0] != "nurse" {
		t.Errorf("expected [nurse], got %v", roles)
	}
}

func TestExtractCIS2Roles_Doctor(t *testing.T) {
	claims := makeCIS2Claims("123", "role-doc", []map[string]interface{}{
		{"person_roleid": "role-doc", "org_code": "RJE", "role_code": "S0080:G0060:R8001"},
	}, nil)
	roles := extractCIS2Roles(claims)
	if len(roles) != 1 || roles[0] != "doctor" {
		t.Errorf("expected [doctor], got %v", roles)
	}
}

func TestExtractCIS2Roles_Admin(t *testing.T) {
	claims := makeCIS2Claims("456", "role-adm", []map[string]interface{}{
		{"person_roleid": "role-adm", "org_code": "RCB", "role_code": "S0080:G0100:R0260"},
	}, nil)
	roles := extractCIS2Roles(claims)
	if len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("expected [admin], got %v", roles)
	}
}

func TestExtractCIS2Roles_UnknownRCode(t *testing.T) {
	claims := makeCIS2Claims("789", "", []map[string]interface{}{
		{"person_roleid": "r1", "org_code": "RCB", "role_code": "S0001:G0001:R9999"},
	}, nil)
	if got := extractCIS2Roles(claims); len(got) != 0 {
		t.Errorf("expected no roles for unknown R-code, got %v", got)
	}
}

func TestExtractCIS2Roles_SelectedRoleOnly(t *testing.T) {
	claims := makeCIS2Claims("111", "role-nurse", []map[string]interface{}{
		{"person_roleid": "role-nurse", "org_code": "RCB", "role_code": "S0080:G0450:R0100"},
		{"person_roleid": "role-admin", "org_code": "RCB", "role_code": "S0080:G0100:R0260"},
	}, nil)
	roles := extractCIS2Roles(claims)
	if len(roles) != 1 || roles[0] != "nurse" {
		t.Errorf("expected only [nurse] from selected role, got %v", roles)
	}
}

func TestExtractCIS2Roles_NoSelectedRoleUnionsAll(t *testing.T) {
	claims := makeCIS2Claims("222", "", []map[string]interface{}{
		{"person_roleid": "r1", "org_code": "RCB", "role_code": "S0080:G0450:R0100"},
		{"person_roleid": "r2", "org_code": "RCB", "role_code": "S0080:G0060:R8001"},
	}, nil)
	if got := extractCIS2Roles(claims); len(got) != 2 {
		t.Errorf("expected 2 roles from union, got %v", got)
	}
}

func TestExtractCIS2Roles_Empty(t *testing.T) {
	claims := jwt.MapClaims{"sub": "x"}
	if got := extractCIS2Roles(claims); got != nil {
		t.Errorf("expected nil when nhsid_nrbac_roles absent, got %v", got)
	}
}

func TestExtractCIS2FHIRContext_FacilityAndRole(t *testing.T) {
	claims := makeCIS2Claims("333", "role-001", []map[string]interface{}{
		{"person_roleid": "role-001", "org_code": "RCB", "role_code": "S0080:G0450:R0100"},
	}, []map[string]interface{}{
		{"org_code": "RCB", "org_name": "RCB UNIVERSITY HOSPITAL NHS TRUST"},
	})
	ctx := extractCIS2FHIRContext(claims)
	if ctx.Facility != "RCB UNIVERSITY HOSPITAL NHS TRUST" {
		t.Errorf("expected facility from org_name, got %q", ctx.Facility)
	}
	if ctx.Role != "nurse" {
		t.Errorf("expected role=nurse, got %q", ctx.Role)
	}
	if ctx.Department != "RCB" {
		t.Errorf("expected department=ODS code RCB, got %q", ctx.Department)
	}
}

func TestExtractCIS2FHIRContext_NoOrgs(t *testing.T) {
	claims := makeCIS2Claims("444", "role-001", []map[string]interface{}{
		{"person_roleid": "role-001", "org_code": "RJE", "role_code": "S0080:G0060:R8001"},
	}, nil)
	ctx := extractCIS2FHIRContext(claims)
	if ctx.Facility != "UNKNOWN" {
		t.Errorf("expected UNKNOWN facility, got %q", ctx.Facility)
	}
	if ctx.Role != "doctor" {
		t.Errorf("expected role=doctor, got %q", ctx.Role)
	}
}

func TestExtractCIS2SubjectID_NHSUserUID(t *testing.T) {
	claims := jwt.MapClaims{"sub": "fallback", "nhsid_useruid": "787807429511"}
	if got := extractCIS2SubjectID(claims); got != "787807429511" {
		t.Errorf("expected nhsid_useruid, got %q", got)
	}
}

func TestExtractCIS2SubjectID_FallsBackToSub(t *testing.T) {
	claims := jwt.MapClaims{"sub": "fallback-sub"}
	if got := extractCIS2SubjectID(claims); got != "fallback-sub" {
		t.Errorf("expected sub fallback, got %q", got)
	}
}

func TestTerminalRCode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"S0080:G0450:R0100", "R0100"},
		{"R0100", "R0100"},
		{"A:B:C:R9200", "R9200"},
	}
	for _, c := range cases {
		if got := terminalRCode(c.in); got != c.want {
			t.Errorf("terminalRCode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
