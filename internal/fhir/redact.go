package fhir

import (
	"encoding/json"
	"fmt"
	"strings"
)

const redactedValue = "***REDACTED***"

// ApplyRedactions takes raw JSON bytes and applies field-level redaction.
// - remove: dot-separated paths whose keys are deleted entirely
// - mask:   dot-separated paths whose values are replaced with "***REDACTED***"
// Handles both single FHIR resources and Bundles (redacts each entry's resource).
// Returns the modified JSON bytes.
func ApplyRedactions(jsonBytes []byte, remove, mask []string) ([]byte, error) {
	if len(remove) == 0 && len(mask) == 0 {
		return jsonBytes, nil
	}

	var resource map[string]any
	if err := json.Unmarshal(jsonBytes, &resource); err != nil {
		return nil, fmt.Errorf("redact: unmarshal: %w", err)
	}

	// If this is a Bundle, redact each entry's resource individually
	if resource["resourceType"] == "Bundle" {
		if entries, ok := resource["entry"].([]any); ok {
			for _, entry := range entries {
				if entryMap, ok := entry.(map[string]any); ok {
					if res, ok := entryMap["resource"].(map[string]any); ok {
						redactResource(res, remove, mask)
					}
				}
			}
		}
	} else {
		redactResource(resource, remove, mask)
	}

	out, err := json.Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("redact: marshal: %w", err)
	}
	return out, nil
}

// redactResource applies remove and mask operations to a single FHIR resource map.
func redactResource(resource map[string]any, remove, mask []string) {
	for _, path := range remove {
		deleteAtPath(resource, strings.Split(path, "."))
	}
	for _, path := range mask {
		maskAtPath(resource, strings.Split(path, "."))
	}
}

// deleteAtPath removes the leaf key from a nested map/slice structure.
func deleteAtPath(obj map[string]any, parts []string) {
	if len(parts) == 0 {
		return
	}

	key := parts[0]

	// Leaf — delete the key
	if len(parts) == 1 {
		delete(obj, key)
		return
	}

	val, ok := obj[key]
	if !ok {
		return
	}

	rest := parts[1:]
	switch v := val.(type) {
	case map[string]any:
		deleteAtPath(v, rest)
	case []any:
		for _, elem := range v {
			if em, ok := elem.(map[string]any); ok {
				deleteAtPath(em, rest)
			}
		}
	}
}

// maskAtPath replaces the leaf value with the redacted sentinel.
func maskAtPath(obj map[string]any, parts []string) {
	if len(parts) == 0 {
		return
	}

	key := parts[0]

	// Leaf — mask the value
	if len(parts) == 1 {
		if _, exists := obj[key]; exists {
			obj[key] = redactedValue
		}
		return
	}

	val, ok := obj[key]
	if !ok {
		return
	}

	rest := parts[1:]
	switch v := val.(type) {
	case map[string]any:
		maskAtPath(v, rest)
	case []any:
		for _, elem := range v {
			if em, ok := elem.(map[string]any); ok {
				maskAtPath(em, rest)
			}
		}
	}
}
