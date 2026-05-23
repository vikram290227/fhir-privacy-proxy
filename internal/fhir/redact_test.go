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

func TestDeleteAtPath_ArrayElements(t *testing.T) {
	resource := map[string]any{
		"name": []any{
			map[string]any{"family": "Smith", "given": []any{"John"}},
			map[string]any{"family": "Doe", "given": []any{"Jane"}},
		},
	}
	deleteAtPath(resource, []string{"name", "family"})
	names := resource["name"].([]any)
	for _, n := range names {
		nm := n.(map[string]any)
		if _, exists := nm["family"]; exists {
			t.Error("family should be deleted from all array elements")
		}
	}
}

func TestDeleteAtPath_MissingKey(t *testing.T) {
	resource := map[string]any{"id": "123"}
	deleteAtPath(resource, []string{"nonexistent", "nested"})
	if resource["id"] != "123" {
		t.Error("existing fields should be unaffected")
	}
}

func TestDeleteAtPath_EmptyParts(t *testing.T) {
	resource := map[string]any{"id": "123"}
	deleteAtPath(resource, []string{})
	if resource["id"] != "123" {
		t.Error("empty path should be a no-op")
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

func TestApplyRedactions_EmptyStringPaths(t *testing.T) {
	input := `{"resourceType":"Patient","id":"123","name":[{"family":"Smith"}]}`
	out, err := ApplyRedactions([]byte(input), []string{""}, []string{""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	json.Unmarshal(out, &result)
	if result["id"] != "123" {
		t.Error("empty path should be no-op; id should remain")
	}
}

func TestApplyRedactions_Bundle_NonArrayEntry(t *testing.T) {
	// entry is a string, not an array — should be a no-op
	input := `{"resourceType":"Bundle","entry":"not-an-array","identifier":[{"value":"X"}]}`
	out, err := ApplyRedactions([]byte(input), []string{"identifier"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	json.Unmarshal(out, &result)
	// Since entry is not []any, redactAny returns early — identifier on Bundle itself stays
	if result["resourceType"] != "Bundle" {
		t.Error("resourceType should be Bundle")
	}
}

func TestApplyRedactions_Bundle_NonMapEntryElement(t *testing.T) {
	// entry contains a non-map element — should be skipped
	input := `{"resourceType":"Bundle","entry":["not-a-map",{"resource":{"resourceType":"Patient","id":"1","identifier":[{"value":"A"}]}}]}`
	out, err := ApplyRedactions([]byte(input), []string{"identifier"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]any
	json.Unmarshal(out, &result)
	entries := result["entry"].([]any)
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestRedactAny_Nil(t *testing.T) {
	// Should be a no-op and not panic.
	redactAny(nil, []string{"id"}, nil)
}

func TestDeleteAtPath_NestedMap(t *testing.T) {
	resource := map[string]any{
		"meta": map[string]any{"versionId": "1", "lastUpdated": "2024-01-01"},
	}
	deleteAtPath(resource, []string{"meta", "versionId"})
	meta := resource["meta"].(map[string]any)
	if _, exists := meta["versionId"]; exists {
		t.Error("versionId should be deleted from nested map")
	}
	if meta["lastUpdated"] != "2024-01-01" {
		t.Error("lastUpdated should remain")
	}
}

func TestMaskAtPath_EmptyParts(t *testing.T) {
	resource := map[string]any{"id": "123"}
	maskAtPath(resource, []string{})
	if resource["id"] != "123" {
		t.Error("empty parts should be a no-op")
	}
}

func TestMaskAtPath_MissingKey(t *testing.T) {
	resource := map[string]any{"id": "123"}
	maskAtPath(resource, []string{"nonexistent", "nested"})
	if resource["id"] != "123" {
		t.Error("existing fields should be unaffected")
	}
}

func TestMaskAtPath_NestedMap(t *testing.T) {
	resource := map[string]any{
		"meta": map[string]any{"versionId": "1"},
	}
	maskAtPath(resource, []string{"meta", "versionId"})
	meta := resource["meta"].(map[string]any)
	if meta["versionId"] != redactedValue {
		t.Errorf("nested versionId should be masked, got %v", meta["versionId"])
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
