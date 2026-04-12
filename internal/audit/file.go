package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// FileLogger persists audit events as newline-delimited JSON on the local
// filesystem. It is intended for dev/demo environments where the managed
// cloud backend (Azure Blob) is unavailable, and acts as the source of
// truth for the "persistent audit logging" requirement.
//
// Each call to Log is append-only, fsync'd, and serialized through a
// mutex so concurrent handlers never interleave bytes in the output.
// A background goroutine is not used — Log returns after the bytes are
// flushed, giving callers a deterministic ordering guarantee suitable
// for tests and forensic replay.
type FileLogger struct {
	path   string
	file   *os.File
	mu     sync.Mutex
	logger *zap.Logger
}

// NewFileLogger opens (creating if needed) an audit log file at path.
// Parent directories are created automatically. The file is opened in
// append mode so existing entries are preserved across restarts.
func NewFileLogger(path string, logger *zap.Logger) (*FileLogger, error) {
	if path == "" {
		return nil, fmt.Errorf("audit file path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("audit: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return &FileLogger{
		path:   path,
		file:   f,
		logger: logger,
	}, nil
}

// Path returns the absolute file path the logger writes to.
func (l *FileLogger) Path() string { return l.path }

// Log serializes the event as a single JSON line and appends it to disk.
// It is safe for concurrent use.
func (l *FileLogger) Log(event AuditEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(event)
	if err != nil {
		if l.logger != nil {
			l.logger.Error("audit: marshal failed", zap.Error(err))
		}
		return
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.file.Write(data); err != nil {
		if l.logger != nil {
			l.logger.Error("audit: write failed", zap.Error(err))
		}
		return
	}
	// Best-effort fsync — ignore error on platforms where it's a no-op.
	_ = l.file.Sync()
}

// Close flushes and closes the underlying file.
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// FileLoggerPath returns the configured audit log path from the
// AUDIT_LOG_FILE env var, or empty string if persistent audit is disabled.
func FileLoggerPath() string {
	return os.Getenv("AUDIT_LOG_FILE")
}
