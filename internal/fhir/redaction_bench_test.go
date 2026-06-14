package fhir

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// benchRemove / benchMask mirror the field paths the OPA policy returns for an
// elevated-risk user (risk_score >= 0.6) — the worst-case redaction workload.
var (
	benchRemove = []string{"telecom"}
	benchMask   = []string{"identifier", "address", "birthDate"}
)

// resourceTypes cycles through realistic FHIR resource types for Bundle entries.
var resourceTypes = []string{
	"Observation", "Observation", "Observation", // 30 %
	"Encounter", "Encounter",                    // 20 %
	"MedicationRequest", "MedicationRequest",    // 20 %
	"DiagnosticReport",                          // 10 %
	"Condition",                                 // 10 %
	"Patient",                                   // 10 % — has telecom/identifier/address/birthDate
}

// generateSyntheticBundle builds a FHIR Bundle of approximately targetSize bytes
// with realistic nesting depth (3–5 levels) and mixed resource types.
// Patient entries carry the fields targeted by benchRemove/benchMask so
// redaction has real work to do on each iteration.
func generateSyntheticBundle(targetSize int) []byte {
	type entryWrapper struct {
		FullURL  string         `json:"fullUrl"`
		Resource map[string]any `json:"resource"`
	}

	entries := make([]entryWrapper, 0, targetSize/900+1)
	patientSeq := 0

	for i := 0; ; i++ {
		rt := resourceTypes[i%len(resourceTypes)]
		var res map[string]any

		switch rt {
		case "Patient":
			patientSeq++
			res = map[string]any{
				"resourceType": "Patient",
				"id":           fmt.Sprintf("pat-%d", patientSeq),
				"meta": map[string]any{
					"versionId":   "1",
					"lastUpdated": "2024-03-01T00:00:00Z",
					"profile":     []any{"http://hl7.org/fhir/us/core/StructureDefinition/us-core-patient"},
				},
				"identifier": []any{
					map[string]any{
						"use":    "official",
						"system": "urn:oid:2.16.840.1.113883.4.1",
						"value":  fmt.Sprintf("MRN-%08d", patientSeq),
					},
					map[string]any{
						"use":    "secondary",
						"system": "http://example.org/mrn",
						"value":  fmt.Sprintf("ALT-%06d", patientSeq),
					},
				},
				"name": []any{
					map[string]any{
						"use":    "official",
						"family": fmt.Sprintf("Family%d", patientSeq),
						"given":  []any{fmt.Sprintf("Given%d", patientSeq), "MiddleName"},
					},
				},
				"telecom": []any{
					map[string]any{
						"system": "phone",
						"value":  fmt.Sprintf("555-%04d", patientSeq%9999),
						"use":    "home",
					},
					map[string]any{
						"system": "email",
						"value":  fmt.Sprintf("patient%d@example.com", patientSeq),
					},
				},
				"gender":    "unknown",
				"birthDate": fmt.Sprintf("19%02d-%02d-%02d", (patientSeq%80)+1, (patientSeq%12)+1, (patientSeq%28)+1),
				"address": []any{
					map[string]any{
						"use":        "home",
						"line":       []any{fmt.Sprintf("%d Main Street", patientSeq*7+100)},
						"city":       fmt.Sprintf("City%d", patientSeq%50),
						"state":      "MA",
						"postalCode": fmt.Sprintf("%05d", patientSeq%99999),
						"country":    "US",
					},
				},
			}

		case "Observation":
			pRef := 1
			if patientSeq > 0 {
				pRef = (i % patientSeq) + 1
			}
			res = map[string]any{
				"resourceType": "Observation",
				"id":           fmt.Sprintf("obs-%d", i),
				"status":       "final",
				"meta":         map[string]any{"versionId": "1", "lastUpdated": "2024-03-01T00:00:00Z"},
				"code": map[string]any{
					"coding": []any{
						map[string]any{
							"system":  "http://loinc.org",
							"code":    fmt.Sprintf("%05d-4", i%99999),
							"display": fmt.Sprintf("Lab measurement %d", i),
						},
					},
					"text": fmt.Sprintf("Measurement %d", i),
				},
				"subject": map[string]any{"reference": fmt.Sprintf("Patient/pat-%d", pRef)},
				"effectiveDateTime": "2024-03-01T10:30:00Z",
				"valueQuantity": map[string]any{
					"value":  float64(i%200) + 0.5,
					"unit":   "mg/dL",
					"system": "http://unitsofmeasure.org",
					"code":   "mg-dL",
				},
				"interpretation": []any{
					map[string]any{
						"coding": []any{
							map[string]any{
								"system":  "http://terminology.hl7.org/CodeSystem/v3-ObservationInterpretation",
								"code":    "N",
								"display": "Normal",
							},
						},
					},
				},
				"performer": []any{
					map[string]any{"reference": fmt.Sprintf("Practitioner/prac-%d", i%50)},
				},
			}

		case "Encounter":
			pRef := 1
			if patientSeq > 0 {
				pRef = (i % patientSeq) + 1
			}
			res = map[string]any{
				"resourceType": "Encounter",
				"id":           fmt.Sprintf("enc-%d", i),
				"status":       "finished",
				"class": map[string]any{
					"system":  "http://terminology.hl7.org/CodeSystem/v3-ActCode",
					"code":    "AMB",
					"display": "ambulatory",
				},
				"subject":           map[string]any{"reference": fmt.Sprintf("Patient/pat-%d", pRef)},
				"period":            map[string]any{"start": "2024-03-01T08:00:00Z", "end": "2024-03-01T09:30:00Z"},
				"participant": []any{
					map[string]any{
						"individual": map[string]any{"reference": fmt.Sprintf("Practitioner/prac-%d", i%50)},
						"type": []any{
							map[string]any{
								"coding": []any{
									map[string]any{"code": "PPRF", "display": "primary performer"},
								},
							},
						},
					},
				},
				"reasonCode": []any{map[string]any{"text": fmt.Sprintf("Visit reason %d", i)}},
			}

		case "MedicationRequest":
			pRef := 1
			if patientSeq > 0 {
				pRef = (i % patientSeq) + 1
			}
			res = map[string]any{
				"resourceType": "MedicationRequest",
				"id":           fmt.Sprintf("medrx-%d", i),
				"status":       "active",
				"intent":       "order",
				"medicationCodeableConcept": map[string]any{
					"coding": []any{
						map[string]any{
							"system":  "http://www.nlm.nih.gov/research/umls/rxnorm",
							"code":    fmt.Sprintf("%06d", i%999999),
							"display": fmt.Sprintf("Medication %d 10 MG oral tablet", i),
						},
					},
				},
				"subject":   map[string]any{"reference": fmt.Sprintf("Patient/pat-%d", pRef)},
				"requester": map[string]any{"reference": fmt.Sprintf("Practitioner/prac-%d", i%50)},
				"dosageInstruction": []any{
					map[string]any{
						"text": fmt.Sprintf("Take 1 tablet daily for condition %d", i),
						"timing": map[string]any{
							"repeat": map[string]any{"frequency": 1, "period": 1, "periodUnit": "d"},
						},
					},
				},
			}

		case "DiagnosticReport":
			pRef := 1
			if patientSeq > 0 {
				pRef = (i % patientSeq) + 1
			}
			res = map[string]any{
				"resourceType": "DiagnosticReport",
				"id":           fmt.Sprintf("dr-%d", i),
				"status":       "final",
				"code": map[string]any{
					"coding": []any{
						map[string]any{"system": "http://loinc.org", "code": "58410-2", "display": "Complete blood count panel"},
					},
				},
				"subject":           map[string]any{"reference": fmt.Sprintf("Patient/pat-%d", pRef)},
				"effectiveDateTime": "2024-03-01T12:00:00Z",
				"issued":            "2024-03-01T14:00:00Z",
				"result": []any{
					map[string]any{"reference": fmt.Sprintf("Observation/obs-%d", i-1)},
					map[string]any{"reference": fmt.Sprintf("Observation/obs-%d", i-2)},
				},
				"conclusion": fmt.Sprintf("Results within normal limits for patient %d", i),
			}

		default: // Condition
			pRef := 1
			if patientSeq > 0 {
				pRef = (i % patientSeq) + 1
			}
			res = map[string]any{
				"resourceType": "Condition",
				"id":           fmt.Sprintf("cond-%d", i),
				"clinicalStatus": map[string]any{
					"coding": []any{
						map[string]any{
							"system":  "http://terminology.hl7.org/CodeSystem/condition-clinical",
							"code":    "active",
							"display": "Active",
						},
					},
				},
				"code": map[string]any{
					"coding": []any{
						map[string]any{
							"system":  "http://snomed.info/sct",
							"code":    fmt.Sprintf("%09d", i),
							"display": fmt.Sprintf("Condition %d", i),
						},
					},
					"text": fmt.Sprintf("Clinical condition %d", i),
				},
				"subject":       map[string]any{"reference": fmt.Sprintf("Patient/pat-%d", pRef)},
				"onsetDateTime": "2020-01-01",
			}
		}

		entries = append(entries, entryWrapper{
			FullURL:  fmt.Sprintf("urn:uuid:entry-%d", i),
			Resource: res,
		})

		// Check payload size every 200 entries to decide when to stop.
		if len(entries)%200 == 0 {
			probe, _ := json.Marshal(map[string]any{
				"resourceType": "Bundle",
				"type":         "searchset",
				"total":        len(entries),
				"entry":        entries,
			})
			if len(probe) >= targetSize {
				break
			}
		}
	}

	bundle := map[string]any{
		"resourceType": "Bundle",
		"type":         "searchset",
		"total":        len(entries),
		"entry":        entries,
	}
	out, _ := json.Marshal(bundle)
	return out
}

// loadOrGenerateFixture loads a pre-built fixture from testdata/ if present
// (built by scripts/generate_bench_fixtures.sh from real Synthea output),
// falling back to a synthetically generated Bundle of the given target size.
func loadOrGenerateFixture(b *testing.B, name string, targetSize int) []byte {
	b.Helper()
	path := filepath.Join("testdata", name)
	if data, err := os.ReadFile(path); err == nil {
		b.Logf("loaded Synthea fixture %s (%d bytes, %d entries)", path, len(data), bundleEntryCount(data))
		return data
	}
	b.Logf("fixture %s not found — generating synthetic bundle (~%d KB)", name, targetSize/1024)
	data := generateSyntheticBundle(targetSize)
	b.Logf("generated synthetic bundle: %d bytes, %d entries", len(data), bundleEntryCount(data))
	return data
}

// bundleEntryCount returns the number of entries in a serialised FHIR Bundle
// for logging only — not in the benchmark hot-path.
func bundleEntryCount(data []byte) int {
	var b struct {
		Entry []json.RawMessage `json:"entry"`
	}
	_ = json.Unmarshal(data, &b)
	return len(b.Entry)
}

// --- benchmarks ---------------------------------------------------------------

func BenchmarkRedaction_500KB(b *testing.B) {
	data := loadOrGenerateFixture(b, "bundle_500KB.json", 512*1024)
	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		if _, err := ApplyRedactions(data, benchRemove, benchMask); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRedaction_2MB(b *testing.B) {
	data := loadOrGenerateFixture(b, "bundle_2MB.json", 2*1024*1024)
	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		if _, err := ApplyRedactions(data, benchRemove, benchMask); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRedaction_5MB(b *testing.B) {
	data := loadOrGenerateFixture(b, "bundle_5MB.json", 5*1024*1024)
	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		if _, err := ApplyRedactions(data, benchRemove, benchMask); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRedaction_15MB(b *testing.B) {
	data := loadOrGenerateFixture(b, "bundle_15MB.json", 15*1024*1024)
	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		if _, err := ApplyRedactions(data, benchRemove, benchMask); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRedaction_NoOp_5MB measures the cost of the early-exit path when
// remove and mask are both empty, isolating payload I/O from redaction work.
func BenchmarkRedaction_NoOp_5MB(b *testing.B) {
	data := loadOrGenerateFixture(b, "bundle_5MB.json", 5*1024*1024)
	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		if _, err := ApplyRedactions(data, nil, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRedaction_SinglePatient baselines the overhead for a single Patient
// resource (no Bundle) to provide per-resource context for Bundle numbers.
func BenchmarkRedaction_SinglePatient(b *testing.B) {
	patient := map[string]any{
		"resourceType": "Patient",
		"id":           "bench-patient",
		"identifier":   []any{map[string]any{"system": "mrn", "value": "MRN-12345", "use": "official"}},
		"name":         []any{map[string]any{"family": "Smith", "given": []any{"John"}}},
		"telecom":      []any{map[string]any{"system": "phone", "value": "555-1234"}},
		"gender":       "male",
		"birthDate":    "1975-06-15",
		"address":      []any{map[string]any{"city": "Boston", "state": "MA"}},
	}
	data, _ := json.Marshal(patient)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ApplyRedactions(data, benchRemove, benchMask); err != nil {
			b.Fatal(err)
		}
	}
}
