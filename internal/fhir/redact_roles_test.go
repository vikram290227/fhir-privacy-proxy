package fhir

import (
	"encoding/json"
	"testing"
)

// roleRedactTestCase models a table-driven test for role-based redaction.
// remove/mask are the paths that the OPA policy would return for the role.
type roleRedactTestCase struct {
	name           string
	role           string
	remove         []string
	mask           []string
	input          string
	wantRemoved    []string // top-level keys that must NOT exist
	wantMasked     map[string]string
	wantPreserved  []string // top-level keys that must still exist
}

// TestApplyRedactions_ByRole exercises masking/removal combinations for
// the three supported roles (nurse, doctor, admin) against both single
// resources and Bundles containing mixed resource types.
func TestApplyRedactions_ByRole(t *testing.T) {
	patient := `{
		"resourceType": "Patient",
		"id": "p1",
		"identifier": [{"system": "mrn", "value": "A1"}],
		"telecom":    [{"system": "phone", "value": "555-1234"}],
		"address":    [{"city": "NYC"}],
		"name":       [{"family": "Smith"}]
	}`

	tests := []roleRedactTestCase{
		{
			name:          "nurse: identifier removed, telecom+address masked",
			role:          "nurse",
			remove:        []string{"identifier"},
			mask:          []string{"telecom", "address"},
			input:         patient,
			wantRemoved:   []string{"identifier"},
			wantMasked:    map[string]string{"telecom": redactedValue, "address": redactedValue},
			wantPreserved: []string{"resourceType", "id", "name"},
		},
		{
			name:          "doctor: address masked, identifier retained",
			role:          "doctor",
			remove:        nil,
			mask:          []string{"address"},
			input:         patient,
			wantRemoved:   nil,
			wantMasked:    map[string]string{"address": redactedValue},
			wantPreserved: []string{"resourceType", "id", "identifier", "telecom", "name"},
		},
		{
			name:          "admin: no redactions",
			role:          "admin",
			remove:        nil,
			mask:          nil,
			input:         patient,
			wantRemoved:   nil,
			wantMasked:    nil,
			wantPreserved: []string{"resourceType", "id", "identifier", "telecom", "address", "name"},
		},
		{
			name:          "nurse (break-glass): no redactions",
			role:          "nurse_breakglass",
			remove:        nil,
			mask:          nil,
			input:         patient,
			wantPreserved: []string{"resourceType", "id", "identifier", "telecom", "address", "name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := ApplyRedactions([]byte(tt.input), tt.remove, tt.mask)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var got map[string]any
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("unmarshal redacted: %v", err)
			}

			for _, k := range tt.wantRemoved {
				if _, ok := got[k]; ok {
					t.Errorf("%s: field %q should have been removed", tt.name, k)
				}
			}
			for k, want := range tt.wantMasked {
				if got[k] != want {
					t.Errorf("%s: field %q should be masked (%q), got %v", tt.name, k, want, got[k])
				}
			}
			for _, k := range tt.wantPreserved {
				if _, ok := got[k]; !ok {
					t.Errorf("%s: field %q should be preserved", tt.name, k)
				}
			}
		})
	}
}

// TestApplyRedactions_Bundle_MixedResources verifies that a Bundle with
// Patient + Observation + Condition entries gets redaction applied on
// every entry and that non-target keys remain intact.
func TestApplyRedactions_Bundle_MixedResources(t *testing.T) {
	input := `{
		"resourceType": "Bundle",
		"type": "searchset",
		"entry": [
			{
				"resource": {
					"resourceType": "Patient",
					"id": "p1",
					"identifier": [{"value": "A1"}],
					"telecom": [{"value": "555"}]
				}
			},
			{
				"resource": {
					"resourceType": "Observation",
					"id": "o1",
					"identifier": [{"value": "OBS-1"}],
					"code": {"text": "blood pressure"},
					"subject": {"reference": "Patient/p1"}
				}
			},
			{
				"resource": {
					"resourceType": "Condition",
					"id": "c1",
					"identifier": [{"value": "COND-1"}],
					"code": {"text": "hypertension"}
				}
			}
		]
	}`

	out, err := ApplyRedactions([]byte(input), []string{"identifier"}, []string{"telecom"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	entries, ok := got["entry"].([]any)
	if !ok || len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %v", got["entry"])
	}

	for i, e := range entries {
		res := e.(map[string]any)["resource"].(map[string]any)
		if _, ok := res["identifier"]; ok {
			t.Errorf("entry %d (%v): identifier should be removed", i, res["resourceType"])
		}
		if _, ok := res["id"]; !ok {
			t.Errorf("entry %d: id should be preserved", i)
		}
	}

	// Patient telecom should be masked
	patient := entries[0].(map[string]any)["resource"].(map[string]any)
	if patient["telecom"] != redactedValue {
		t.Errorf("patient telecom should be masked, got %v", patient["telecom"])
	}

	// Observation code should be intact
	obs := entries[1].(map[string]any)["resource"].(map[string]any)
	if obs["code"] == nil {
		t.Error("observation.code should be preserved")
	}

	// Condition code should be intact
	cond := entries[2].(map[string]any)["resource"].(map[string]any)
	if cond["code"] == nil {
		t.Error("condition.code should be preserved")
	}
}

// TestApplyRedactions_NestedBundle verifies that redactions still apply
// when a Bundle contains an inner Bundle as an entry resource.
func TestApplyRedactions_NestedBundle(t *testing.T) {
	input := `{
		"resourceType": "Bundle",
		"type": "searchset",
		"entry": [
			{
				"resource": {
					"resourceType": "Bundle",
					"type": "collection",
					"entry": [
						{
							"resource": {
								"resourceType": "Patient",
								"id": "p1",
								"identifier": [{"value": "A1"}],
								"telecom": [{"value": "555"}]
							}
						}
					]
				}
			}
		]
	}`

	out, err := ApplyRedactions([]byte(input), []string{"identifier"}, []string{"telecom"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got map[string]any
	json.Unmarshal(out, &got)

	outer := got["entry"].([]any)[0].(map[string]any)["resource"].(map[string]any)
	inner := outer["entry"].([]any)[0].(map[string]any)["resource"].(map[string]any)

	if _, ok := inner["identifier"]; ok {
		t.Error("nested bundle: identifier should have been removed")
	}
	if inner["telecom"] != redactedValue {
		t.Errorf("nested bundle: telecom should be masked, got %v", inner["telecom"])
	}
}
