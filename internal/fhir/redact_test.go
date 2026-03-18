package fhir

import (
	"encoding/json"
	"testing"
)

func TestApplyRedactions_NoOps(t *testing.T) {
	input := `{"resourceType":"Patient","id":"123","name":[{"family":"Smith"}]}`
	out, err := ApplyRedactions([]byte(input), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != input {
		t.Errorf("expected unchanged output, got %s", out)
	}
}

func TestApplyRedactions_RemoveField(t *testing.T) {
	input := `{"resourceType":"Patient","id":"123","identifier":[{"system":"mrn","value":"A1"}],"name":[{"family":"Smith"}]}`
	out, err := ApplyRedactions([]byte(input), []string{"identifier"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(out, &result)

	if _, exists := result["identifier"]; exists {
		t.Error("identifier should have been removed")
	}
	if result["id"] != "123" {
		t.Error("id should remain")
	}
	if result["resourceType"] != "Patient" {
		t.Error("resourceType should remain")
	}
}

func TestApplyRedactions_MaskField(t *testing.T) {
	input := `{"resourceType":"Patient","id":"123","telecom":[{"system":"phone","value":"555-1234"}]}`
	out, err := ApplyRedactions([]byte(input), nil, []string{"telecom"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(out, &result)

	if result["telecom"] != redactedValue {
		t.Errorf("telecom should be masked, got %v", result["telecom"])
	}
}

func TestApplyRedactions_RemoveAndMask(t *testing.T) {
	input := `{"resourceType":"Patient","id":"123","identifier":[{"value":"A1"}],"telecom":[{"value":"555"}],"address":[{"city":"NYC"}]}`
	out, err := ApplyRedactions([]byte(input), []string{"identifier"}, []string{"telecom", "address"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(out, &result)

	if _, exists := result["identifier"]; exists {
		t.Error("identifier should have been removed")
	}
	if result["telecom"] != redactedValue {
		t.Error("telecom should be masked")
	}
	if result["address"] != redactedValue {
		t.Error("address should be masked")
	}
}

func TestApplyRedactions_Bundle(t *testing.T) {
	input := `{
		"resourceType": "Bundle",
		"type": "searchset",
		"entry": [
			{
				"resource": {
					"resourceType": "Patient",
					"id": "1",
					"identifier": [{"value": "A1"}],
					"telecom": [{"value": "555"}]
				}
			},
			{
				"resource": {
					"resourceType": "Patient",
					"id": "2",
					"identifier": [{"value": "A2"}],
					"telecom": [{"value": "666"}]
				}
			}
		]
	}`

	out, err := ApplyRedactions([]byte(input), []string{"identifier"}, []string{"telecom"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(out, &result)

	entries := result["entry"].([]any)
	for i, entry := range entries {
		res := entry.(map[string]any)["resource"].(map[string]any)
		if _, exists := res["identifier"]; exists {
			t.Errorf("entry %d: identifier should be removed", i)
		}
		if res["telecom"] != redactedValue {
			t.Errorf("entry %d: telecom should be masked", i)
		}
		if res["id"] == nil {
			t.Errorf("entry %d: id should remain", i)
		}
	}
}

func TestApplyRedactions_NestedPath(t *testing.T) {
	input := `{"resourceType":"Patient","name":[{"family":"Smith","given":["John"]}]}`
	out, err := ApplyRedactions([]byte(input), nil, []string{"name.family"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(out, &result)

	names := result["name"].([]any)
	nameObj := names[0].(map[string]any)
	if nameObj["family"] != redactedValue {
		t.Errorf("name.family should be masked, got %v", nameObj["family"])
	}
}

func TestApplyRedactions_MissingField(t *testing.T) {
	input := `{"resourceType":"Patient","id":"123"}`
	out, err := ApplyRedactions([]byte(input), []string{"nonexistent"}, []string{"alsoMissing"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(out, &result)

	if result["id"] != "123" {
		t.Error("existing fields should be preserved")
	}
}

func TestApplyRedactions_InvalidJSON(t *testing.T) {
	_, err := ApplyRedactions([]byte("not json"), []string{"id"}, nil)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestApplyRedactions_EmptyBundle(t *testing.T) {
	input := `{"resourceType":"Bundle","type":"searchset","entry":[]}`
	out, err := ApplyRedactions([]byte(input), []string{"identifier"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(out, &result)

	entries := result["entry"].([]any)
	if len(entries) != 0 {
		t.Error("empty bundle should remain empty")
	}
}
