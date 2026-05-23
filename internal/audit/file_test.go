package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFileLogger_WriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.ndjson")

	fl, err := NewFileLogger(path, nil)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer fl.Close()

	events := []AuditEvent{
		{
			EventType: EventAccess,
			TenantID:  "hospital-a",
			SubjectID: "nurse1",
			Method:    "GET",
			Path:      "/fhir/r4/Patient/123",
		},
		{
			EventType: EventBreakGlass,
			TenantID:  "hospital-a",
			SubjectID: "nurse1",
			Method:    "GET",
			Path:      "/fhir/r4/Patient/999",
			BreakGlass: &BreakGlassDetail{
				Justification: "Emergency cardiac arrest",
				RequestedBy:   "nurse1",
			},
		},
	}
	for _, e := range events {
		fl.Log(e)
	}

	// Read back the file and ensure both events are on disk.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	var read []AuditEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		read = append(read, e)
	}
	if len(read) != 2 {
		t.Fatalf("expected 2 events on disk, got %d", len(read))
	}
	if read[0].EventType != EventAccess {
		t.Errorf("event 0: want RESOURCE_ACCESS, got %v", read[0].EventType)
	}
	if read[1].EventType != EventBreakGlass {
		t.Errorf("event 1: want BREAK_GLASS, got %v", read[1].EventType)
	}
	if read[1].BreakGlass == nil || read[1].BreakGlass.Justification != "Emergency cardiac arrest" {
		t.Errorf("break-glass justification missing on disk: %+v", read[1].BreakGlass)
	}
	if read[0].Timestamp.IsZero() {
		t.Error("timestamp should be auto-filled")
	}
}

func TestFileLogger_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.ndjson")

	fl, err := NewFileLogger(path, nil)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer fl.Close()

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			fl.Log(AuditEvent{
				EventType: EventAccess,
				SubjectID: "user",
				Timestamp: time.Now().UTC(),
			})
		}(i)
	}
	wg.Wait()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := 0
	for _, c := range b {
		if c == '\n' {
			lines++
		}
	}
	if lines != N {
		t.Errorf("expected %d lines, got %d", N, lines)
	}
}

func TestFileLogger_MissingPath(t *testing.T) {
	if _, err := NewFileLogger("", nil); err == nil {
		t.Error("expected error on empty path")
	}
}

func TestFileLogger_Path(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.ndjson")
	fl, err := NewFileLogger(path, nil)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer fl.Close()
	if fl.Path() != path {
		t.Errorf("Path() = %q, want %q", fl.Path(), path)
	}
}

func TestFileLogger_Close_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.ndjson")
	fl, err := NewFileLogger(path, nil)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	if err := fl.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := fl.Close(); err != nil {
		t.Errorf("second Close should be a no-op, got: %v", err)
	}
}

func TestFileLoggerPath_Env(t *testing.T) {
	t.Setenv("AUDIT_LOG_FILE", "/var/log/audit.ndjson")
	if got := FileLoggerPath(); got != "/var/log/audit.ndjson" {
		t.Errorf("FileLoggerPath = %q", got)
	}
	t.Setenv("AUDIT_LOG_FILE", "")
	if got := FileLoggerPath(); got != "" {
		t.Errorf("FileLoggerPath should be empty, got %q", got)
	}
}
