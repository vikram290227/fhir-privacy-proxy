package fhir

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/buger/jsonparser"
)

// RedactStream performs field removal and masking on a JSON byte slice without
// full deserialization into map[string]any. It uses buger/jsonparser for
// targeted byte-level operations.
//
// For FHIR Bundle resources the function rebuilds the entry array in a single
// O(n) pass and replaces it with one jsonparser.Set call — avoiding the O(n²)
// cost of patching the full blob once per entry.
func RedactStream(jsonBytes []byte, remove, mask []string) ([]byte, error) {
	if len(remove) == 0 && len(mask) == 0 {
		return jsonBytes, nil
	}

	if !json.Valid(jsonBytes) {
		return nil, fmt.Errorf("redact: invalid JSON input")
	}

	resourceType, _, _, _ := jsonparser.Get(jsonBytes, "resourceType")
	if string(resourceType) == "Bundle" {
		return redactBundleStream(jsonBytes, remove, mask)
	}
	return redactSingleStream(jsonBytes, remove, mask)
}

// redactSingleStream applies remove/mask paths to one non-Bundle FHIR resource.
// Multi-segment paths descend into objects and iterate arrays at intermediate
// segments, matching the behaviour of deleteAtPath/maskAtPath.
func redactSingleStream(data []byte, remove, mask []string) ([]byte, error) {
	for _, path := range remove {
		if path == "" {
			continue
		}
		data = deleteAtPathStream(data, strings.Split(path, "."))
	}
	for _, path := range mask {
		if path == "" {
			continue
		}
		data = maskAtPathStream(data, strings.Split(path, "."))
	}
	return data, nil
}

// redactBundleStream rebuilds Bundle.entry[] in one O(n) pass:
//  1. ArrayEach iterates every entry — for each, extract resource bytes,
//     apply RedactStream (recurses for nested Bundles), set back into the
//     entry object.
//  2. Assemble modified entries into a new JSON array.
//  3. ONE jsonparser.Set replaces the entry array in the bundle.
//
// This avoids the O(n²) cost of calling Set on the full bundle blob per entry.
func redactBundleStream(data []byte, remove, mask []string) ([]byte, error) {
	entryVal, dataType, _, err := jsonparser.Get(data, "entry")
	if err != nil || dataType != jsonparser.Array {
		// No array-typed entry key — fall through to single-resource path.
		return redactSingleStream(data, remove, mask)
	}

	var modifiedEntries [][]byte
	anyChanged := false
	var iterErr error

	jsonparser.ArrayEach(entryVal, func(entryValue []byte, dt jsonparser.ValueType, _ int, err error) {
		if iterErr != nil {
			return
		}
		if err != nil || dt != jsonparser.Object {
			// ArrayEach strips string quotes — re-encode so the rebuilt array is
			// valid JSON regardless of the element type.
			modifiedEntries = append(modifiedEntries, reencodeJSONValue(entryValue, dt))
			return
		}

		resource, rdt, _, rerr := jsonparser.Get(entryValue, "resource")
		if rerr != nil || rdt == jsonparser.NotExist || len(resource) == 0 {
			modifiedEntries = append(modifiedEntries, entryValue)
			return
		}

		// Recurse so nested Bundles are handled correctly.
		modified, rerr := RedactStream(resource, remove, mask)
		if rerr != nil {
			iterErr = rerr
			return
		}

		if bytes.Equal(resource, modified) {
			modifiedEntries = append(modifiedEntries, entryValue)
			return
		}

		newEntry, serr := jsonparser.Set(entryValue, modified, "resource")
		if serr != nil {
			iterErr = fmt.Errorf("redact stream: set resource in entry: %w", serr)
			return
		}
		modifiedEntries = append(modifiedEntries, newEntry)
		anyChanged = true
	})

	if iterErr != nil {
		return nil, iterErr
	}
	if !anyChanged {
		return data, nil
	}

	newArray := buildJSONArray(modifiedEntries)
	result, serr := jsonparser.Set(data, newArray, "entry")
	if serr != nil {
		return nil, fmt.Errorf("redact stream: replacing entry array: %w", serr)
	}
	return result, nil
}

// deleteAtPathStream removes the leaf key at parts. If an intermediate
// segment is a JSON array, deletion is applied to every object element.
func deleteAtPathStream(data []byte, parts []string) []byte {
	if len(parts) == 0 {
		return data
	}
	if len(parts) == 1 {
		return jsonparser.Delete(data, parts[0])
	}

	val, dataType, _, err := jsonparser.Get(data, parts[0])
	if err != nil {
		return data
	}

	switch dataType {
	case jsonparser.Object:
		modified := deleteAtPathStream(val, parts[1:])
		if bytes.Equal(val, modified) {
			return data
		}
		if result, serr := jsonparser.Set(data, modified, parts[0]); serr == nil {
			return result
		}

	case jsonparser.Array:
		newArray, changed := applyToArrayElements(val, func(elem []byte) []byte {
			return deleteAtPathStream(elem, parts[1:])
		})
		if !changed {
			return data
		}
		if result, serr := jsonparser.Set(data, newArray, parts[0]); serr == nil {
			return result
		}
	}
	return data
}

// maskAtPathStream replaces the leaf value at parts with the redacted sentinel.
// If an intermediate segment is a JSON array, masking is applied to every
// object element.
func maskAtPathStream(data []byte, parts []string) []byte {
	if len(parts) == 0 {
		return data
	}
	if len(parts) == 1 {
		result, err := jsonparser.Set(data, []byte(`"`+redactedValue+`"`), parts[0])
		if err != nil {
			return data
		}
		return result
	}

	val, dataType, _, err := jsonparser.Get(data, parts[0])
	if err != nil {
		return data
	}

	switch dataType {
	case jsonparser.Object:
		modified := maskAtPathStream(val, parts[1:])
		if bytes.Equal(val, modified) {
			return data
		}
		if result, serr := jsonparser.Set(data, modified, parts[0]); serr == nil {
			return result
		}

	case jsonparser.Array:
		newArray, changed := applyToArrayElements(val, func(elem []byte) []byte {
			return maskAtPathStream(elem, parts[1:])
		})
		if !changed {
			return data
		}
		if result, serr := jsonparser.Set(data, newArray, parts[0]); serr == nil {
			return result
		}
	}
	return data
}

// applyToArrayElements iterates a JSON array, applies fn to each object
// element, and returns the reconstructed array bytes plus a changed flag.
func applyToArrayElements(arrayData []byte, fn func([]byte) []byte) ([]byte, bool) {
	var elements [][]byte
	changed := false

	jsonparser.ArrayEach(arrayData, func(elem []byte, dataType jsonparser.ValueType, _ int, err error) {
		if err != nil || dataType != jsonparser.Object {
			elements = append(elements, elem)
			return
		}
		modified := fn(elem)
		if !bytes.Equal(elem, modified) {
			changed = true
		}
		elements = append(elements, modified)
	})

	if !changed {
		return arrayData, false
	}
	return buildJSONArray(elements), true
}

// reencodeJSONValue restores the JSON wire form of a value returned by
// jsonparser.ArrayEach. ArrayEach strips string quotes and unescapes string
// values, so strings must be re-marshalled to produce valid JSON.
func reencodeJSONValue(value []byte, dt jsonparser.ValueType) []byte {
	if dt == jsonparser.String {
		b, _ := json.Marshal(string(value))
		return b
	}
	return value
}

func buildJSONArray(elements [][]byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, elem := range elements {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(elem)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}
