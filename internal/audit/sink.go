package audit

// Sink is the minimal contract the FHIR proxy needs from any audit
// backend. Implementations must be safe for concurrent use.
//
// The package ships two implementations:
//   - FileLogger: local newline-delimited JSON file (dev / air-gapped).
//   - Logger:     Azure Blob Storage (managed, cloud-native).
//
// Both satisfy this interface, so `cmd/proxy/main.go` can hold a single
// `Sink` value without caring which backend is active.
type Sink interface {
	Log(event AuditEvent)
}

// Compile-time assertion that both concrete types implement Sink.
var (
	_ Sink = (*Logger)(nil)
	_ Sink = (*FileLogger)(nil)
)
