package fhir

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const redactedValue = "***REDACTED***"

// ApplyRedactions takes raw JSON bytes and applies field-level redaction.
// - remove: dot-separated paths whose keys are deleted entirely
// - mask:   dot-separated paths whose values are replaced with "***REDACTED***"
//
// The function handles:
//   - Single FHIR resources (any resourceType)
//   - FHIR Bundle resources (redacts every Bundle.entry[].resource)
//   - Nested Bundles (Bundles whose entries contain Bundles)
//   - Mixed resource types inside a single Bundle
//
// Returns the modified JSON bytes. If remove and mask are both empty the
// original bytes are returned unchanged.
// ApplyRedactions dispatches to RedactStream (default) or the legacy
// map-based implementation, selected by REDACTION_ENGINE=stream|map.
// Set REDACTION_ENGINE=map during rollout to A/B benchmark both engines
// against the same fixture; revert to "stream" once validated.
func ApplyRedactions(jsonBytes []byte, remove, mask []string) ([]byte, error) {
	if os.Getenv("REDACTION_ENGINE") == "map" {
		return redactMapBased(jsonBytes, remove, mask)
	}
	return RedactStream(jsonBytes, remove, mask)
}

// redactMapBased is the original full-deserialise implementation kept as a
// fallback reference behind REDACTION_ENGINE=map. It allocates a full
// map[string]any tree (~164 MB at 15 MB input) which is the dominant cost
// at the p50 target bundle sizes.
func redactMapBased(jsonBytes []byte, remove, mask []string) ([]byte, error) {
	if len(remove) == 0 && len(mask) == 0 {
		return jsonBytes, nil
	}

	var resource map[string]any
	if err := json.Unmarshal(jsonBytes, &resource); err != nil {
		return nil, fmt.Errorf("redact: unmarshal: %w", err)
	}

	redactAny(resource, remove, mask)

	out, err := json.Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("redact: marshal: %w", err)
	}
	return out, nil
}

// redactAny is the recursive entry point: if the object is a Bundle it
// descends into every entry's resource (which may itself be a Bundle),
// otherwise it applies the remove/mask paths directly to the resource.
func redactAny(resource map[string]any, remove, mask []string) {
	if resource == nil {
		return
	}

	if resource["resourceType"] == "Bundle" {
		entries, ok := resource["entry"].([]any)
		if !ok {
			return
		}
		for _, entry := range entries {
			entryMap, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if inner, ok := entryMap["resource"].(map[string]any); ok {
				// Recurse — handles nested Bundles and mixed resource types.
				redactAny(inner, remove, mask)
			}
		}
		return
	}

	redactResource(resource, remove, mask)
}

// redactResource applies remove and mask operations to a single FHIR resource map.
func redactResource(resource map[string]any, remove, mask []string) {
	for _, path := range remove {
		if path == "" {
			continue
		}
		deleteAtPath(resource, strings.Split(path, "."))
	}
	for _, path := range mask {
		if path == "" {
			continue
		}
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
