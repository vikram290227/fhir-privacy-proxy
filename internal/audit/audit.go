package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"go.uber.org/zap"
)

// EventType categorizes the audit event.
type EventType string

const (
	EventAccess        EventType = "RESOURCE_ACCESS"
	EventAccessDenied  EventType = "ACCESS_DENIED"
	EventBreakGlass    EventType = "BREAK_GLASS"
	EventAuthFailure   EventType = "AUTH_FAILURE"
	EventRevocation    EventType = "TOKEN_REVOCATION"
)

// AuditEvent is a structured audit log entry written to Azure Blob Storage.
type AuditEvent struct {
	Timestamp     time.Time         `json:"timestamp"`
	EventType     EventType         `json:"event_type"`
	TenantID      string            `json:"tenant_id"`
	SubjectID     string            `json:"subject_id"`
	Roles         []string          `json:"roles,omitempty"`
	ClientID      string            `json:"client_id,omitempty"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	ResourceType  string            `json:"resource_type,omitempty"`
	StatusCode    int               `json:"status_code"`
	PolicyResult  string            `json:"policy_result,omitempty"`
	RedactedPaths []string          `json:"redacted_paths,omitempty"`
	BreakGlass    *BreakGlassDetail `json:"break_glass,omitempty"`
	Reason        string            `json:"reason,omitempty"`
	DurationMs    int64             `json:"duration_ms"`
}

// BreakGlassDetail captures emergency access details.
type BreakGlassDetail struct {
	Justification string `json:"justification"`
	RequestedBy   string `json:"requested_by"`
}

// Logger writes audit events to Azure Blob Storage asynchronously.
type Logger struct {
	client    *azblob.Client
	container string
	events    chan AuditEvent
	logger    *zap.Logger
	done      chan struct{}
}

// Config holds Azure Blob Storage configuration.
type Config struct {
	// AccountName is the Azure Storage account name.
	AccountName string
	// AccountKey is the Azure Storage account key (optional if using DefaultAzureCredential).
	AccountKey string
	// ContainerName is the blob container for audit logs.
	ContainerName string
	// BufferSize is the channel buffer size for async writes.
	BufferSize int
}

// ConfigFromEnv reads audit config from environment variables.
func ConfigFromEnv() *Config {
	acct := os.Getenv("AZURE_STORAGE_ACCOUNT")
	if acct == "" {
		return nil
	}
	container := os.Getenv("AZURE_AUDIT_CONTAINER")
	if container == "" {
		container = "fhir-audit-logs"
	}
	return &Config{
		AccountName:   acct,
		AccountKey:    os.Getenv("AZURE_STORAGE_KEY"),
		ContainerName: container,
		BufferSize:    1000,
	}
}

// NewLogger creates a new audit logger backed by Azure Blob Storage.
func NewLogger(cfg *Config, logger *zap.Logger) (*Logger, error) {
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", cfg.AccountName)

	var client *azblob.Client
	var err error

	if cfg.AccountKey != "" {
		// Use shared key credential
		cred, credErr := azblob.NewSharedKeyCredential(cfg.AccountName, cfg.AccountKey)
		if credErr != nil {
			return nil, fmt.Errorf("invalid storage key: %w", credErr)
		}
		client, err = azblob.NewClientWithSharedKeyCredential(serviceURL, cred, nil)
	} else {
		// Use DefaultAzureCredential (managed identity, CLI, etc.)
		cred, credErr := azidentity.NewDefaultAzureCredential(nil)
		if credErr != nil {
			return nil, fmt.Errorf("azure credential error: %w", credErr)
		}
		client, err = azblob.NewClient(serviceURL, cred, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create blob client: %w", err)
	}

	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = 1000
	}

	al := &Logger{
		client:    client,
		container: cfg.ContainerName,
		events:    make(chan AuditEvent, bufSize),
		logger:    logger,
		done:      make(chan struct{}),
	}

	go al.processEvents()
	return al, nil
}

// Log enqueues an audit event for async writing to Azure Blob Storage.
func (l *Logger) Log(event AuditEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	select {
	case l.events <- event:
	default:
		l.logger.Warn("audit event buffer full, dropping event",
			zap.String("event_type", string(event.EventType)),
			zap.String("subject_id", event.SubjectID),
		)
	}
}

// Close drains remaining events and shuts down the logger.
func (l *Logger) Close() {
	close(l.events)
	<-l.done
}

// processEvents reads from the channel and writes each event as a JSON blob.
func (l *Logger) processEvents() {
	defer close(l.done)
	for event := range l.events {
		l.writeEvent(event)
	}
}

// writeEvent uploads a single audit event as a JSON blob.
func (l *Logger) writeEvent(event AuditEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		l.logger.Error("failed to marshal audit event", zap.Error(err))
		return
	}

	// Blob path: {tenant}/{date}/{timestamp}_{subject}_{event_type}.json
	blobName := fmt.Sprintf("%s/%s/%s_%s_%s.json",
		event.TenantID,
		event.Timestamp.Format("2006/01/02"),
		event.Timestamp.Format("150405.000"),
		sanitize(event.SubjectID),
		event.EventType,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = l.client.UploadBuffer(ctx, l.container, blobName, data, nil)
	if err != nil {
		l.logger.Error("failed to upload audit event",
			zap.String("blob", blobName),
			zap.Error(err),
		)
		return
	}

	l.logger.Debug("audit event written", zap.String("blob", blobName))
}

// batchAndUpload collects events over a short window and uploads as a single NDJSON blob.
// This is an alternative to per-event uploads for high-throughput scenarios.
func (l *Logger) batchAndUpload(events []AuditEvent) {
	if len(events) == 0 {
		return
	}

	var buf bytes.Buffer
	for _, e := range events {
		data, err := json.Marshal(e)
		if err != nil {
			l.logger.Error("failed to marshal audit event in batch", zap.Error(err))
			continue
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	now := time.Now().UTC()
	tenant := events[0].TenantID
	blobName := fmt.Sprintf("%s/%s/batch_%s.ndjson",
		tenant,
		now.Format("2006/01/02"),
		now.Format("150405.000"),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := l.client.UploadBuffer(ctx, l.container, blobName, buf.Bytes(), nil)
	if err != nil {
		l.logger.Error("failed to upload audit batch",
			zap.String("blob", blobName),
			zap.Int("count", len(events)),
			zap.Error(err),
		)
	}
}

// sanitize replaces characters that are invalid in blob names.
func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			out = append(out, c)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}
