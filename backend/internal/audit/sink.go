package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"go.uber.org/zap"
)

var fileWriteMu sync.Mutex

type JSONLWriteResult struct {
	FilePath   string
	FileOffset int64
	LineBytes  int64
}

type IndexRecord struct {
	AuditID                 string
	RequestID               string
	ClientRequestID         string
	UserID                  int64
	APIKeyID                int64
	AccountID               int64
	GroupID                 int64
	Platform                string
	Model                   string
	InboundEndpoint         string
	UpstreamEndpoint        string
	Method                  string
	Path                    string
	StatusCode              int
	ErrorType               string
	InputHash               string
	OutputHash              string
	InputSize               int64
	OutputSize              int64
	InputTruncated          bool
	OutputTruncated         bool
	DurationMs              int64
	TimeToFirstTokenMs      int64
	AttemptCount            int
	HasFailover             bool
	FirstUpstreamStatusCode int
	FinalUpstreamStatusCode int
	CaptureMode             string
	Sampled                 bool
	FilePath                string
	FileOffset              int64
	LineBytes               int64
	CreatedAt               time.Time
}

type RetentionCleaner interface {
	CleanupAuditRetention(ctx context.Context, cutoff time.Time) error
}

func WriteEvent(ctx context.Context, cfg config.GatewayAuditConfig, event *Event) (*JSONLWriteResult, error) {
	if event == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var result *JSONLWriteResult
	if cfg.FileEnabled {
		var fileErr error
		result, fileErr = writeJSONL(cfg.FilePath, event)
		if fileErr != nil {
			metrics.jsonlWriteFailedTotal.Add(1)
			logger.FromContext(ctx).Warn("gateway.audit.jsonl_write_failed", zap.Error(fileErr))
			logger.WriteSinkEvent("warn", "gateway.audit", MetricAuditJSONLWriteFailedTotal, map[string]any{
				"audit_id":  event.AuditID,
				"file_path": cfg.FilePath,
				"error":     fileErr.Error(),
			})
			return nil, fileErr
		}
	}
	if cfg.OpsIndexEnabled {
		writeOpsIndex(event)
	}
	if cfg.IndexAsyncEnabled {
		record := buildIndexRecord(cfg, event, result)
		if dispatcher := CurrentDispatcher(); dispatcher != nil {
			dispatcher.Enqueue(ctx, IndexJob{Record: record})
		} else {
			logger.FromContext(ctx).Warn("gateway.audit.index_dispatcher_unavailable",
				zap.String("audit_id", record.AuditID),
				zap.String("file_path", record.FilePath),
				zap.Int64("file_offset", record.FileOffset),
			)
		}
	}
	return result, nil
}

func writeJSONL(path string, event *Event) (*JSONLWriteResult, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("audit file path is empty")
	}
	path = jsonlShardPath(path, event.Timestamp)
	line, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	line = append(line, '\n')

	fileWriteMu.Lock()
	defer fileWriteMu.Unlock()

	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	offset := info.Size()
	if _, err = f.Write(line); err != nil {
		return nil, err
	}
	return &JSONLWriteResult{FilePath: path, FileOffset: offset, LineBytes: int64(len(line))}, nil
}

func cleanupJSONL(path string, cutoff time.Time) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	prefix, suffix := jsonlShardNameParts(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	cutoffDate := cutoff.In(time.Local).Format("2006-01-02")
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		date, ok := jsonlShardDate(name, prefix, suffix)
		if !ok || date >= cutoffDate {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if info, err := os.Stat(path); err == nil && !info.IsDir() && info.ModTime().Before(cutoff) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func retentionCutoffDate(now time.Time, retentionDays int) time.Time {
	cutoff := now.AddDate(0, 0, -retentionDays).In(time.Local)
	return time.Date(cutoff.Year(), cutoff.Month(), cutoff.Day(), 0, 0, 0, 0, time.Local)
}

func jsonlShardPath(path string, ts time.Time) string {
	if ts.IsZero() {
		ts = time.Now()
	}
	dir := filepath.Dir(path)
	prefix, suffix := jsonlShardNameParts(path)
	return filepath.Join(dir, prefix+ts.In(time.Local).Format("2006-01-02")+suffix)
}

func jsonlShardNameParts(path string) (string, string) {
	name := filepath.Base(strings.TrimSpace(path))
	ext := filepath.Ext(name)
	if ext == "" {
		ext = ".jsonl"
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	if base == "" || base == "." {
		base = "audit"
	}
	return base + "-", ext
}

var jsonlShardDatePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func jsonlShardDate(name, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return "", false
	}
	date := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	if !jsonlShardDatePattern.MatchString(date) {
		return "", false
	}
	return date, true
}

func writeOpsIndex(event *Event) {
	fields := map[string]any{
		"request_id":        event.RequestID,
		"client_request_id": event.ClientRequestID,
		"user_id":           event.UserID,
		"api_key_id":        event.APIKeyID,
		"group_id":          event.GroupID,
		"account_id":        event.AccountID,
		"platform":          event.Platform,
		"model":             event.Model,
		"path":              event.Path,
		"inbound_endpoint":  event.InboundEndpoint,
		"upstream_endpoint": event.UpstreamEndpoint,
		"status_code":       event.StatusCode,
		"duration_ms":       event.DurationMs,
	}
	if event.Input != nil {
		fields["input_sha256"] = event.Input.SHA256
		fields["input_size_bytes"] = event.Input.SizeBytes
		fields["input_truncated"] = event.Input.Truncated
	}
	if event.Output != nil {
		fields["output_sha256"] = event.Output.SHA256
		fields["output_size_bytes"] = event.Output.SizeBytes
		fields["output_truncated"] = event.Output.Truncated
	}
	logger.WriteSinkEvent("info", "gateway.audit", "gateway audit completed", fields)
}

func buildIndexRecord(cfg config.GatewayAuditConfig, event *Event, result *JSONLWriteResult) *IndexRecord {
	record := &IndexRecord{
		AuditID:                 strings.TrimSpace(event.AuditID),
		RequestID:               strings.TrimSpace(event.RequestID),
		ClientRequestID:         strings.TrimSpace(event.ClientRequestID),
		UserID:                  event.UserID,
		APIKeyID:                event.APIKeyID,
		AccountID:               event.AccountID,
		GroupID:                 event.GroupID,
		Platform:                strings.TrimSpace(event.Platform),
		Model:                   strings.TrimSpace(event.Model),
		InboundEndpoint:         strings.TrimSpace(event.InboundEndpoint),
		UpstreamEndpoint:        strings.TrimSpace(event.UpstreamEndpoint),
		Method:                  strings.TrimSpace(event.Method),
		Path:                    strings.TrimSpace(event.Path),
		StatusCode:              event.StatusCode,
		ErrorType:               strings.TrimSpace(event.ErrorType),
		DurationMs:              event.DurationMs,
		TimeToFirstTokenMs:      event.TimeToFirstTokenMs,
		AttemptCount:            len(event.Attempts),
		HasFailover:             hasFailover(event.Attempts),
		FirstUpstreamStatusCode: firstAttemptStatusCode(event.Attempts),
		FinalUpstreamStatusCode: finalAttemptStatusCode(event.Attempts),
		CaptureMode:             normalizeCaptureMode(cfg.InputCaptureMode) + "/" + normalizeCaptureMode(cfg.OutputCaptureMode),
		Sampled:                 true,
		CreatedAt:               event.Timestamp,
	}
	if result != nil {
		record.FilePath = result.FilePath
		record.FileOffset = result.FileOffset
		record.LineBytes = result.LineBytes
	}
	if event.Input != nil {
		record.InputHash = event.Input.SHA256
		record.InputSize = event.Input.SizeBytes
		record.InputTruncated = event.Input.Truncated
	}
	if event.Output != nil {
		record.OutputHash = event.Output.SHA256
		record.OutputSize = event.Output.SizeBytes
		record.OutputTruncated = event.Output.Truncated
	}
	return record
}

func hasFailover(attempts []AttemptRecord) bool {
	if len(attempts) > 1 {
		return true
	}
	for _, attempt := range attempts {
		if strings.EqualFold(strings.TrimSpace(attempt.Result), "failover") {
			return true
		}
	}
	return false
}

func firstAttemptStatusCode(attempts []AttemptRecord) int {
	for _, attempt := range attempts {
		if attempt.StatusCode > 0 {
			return attempt.StatusCode
		}
	}
	return 0
}

func finalAttemptStatusCode(attempts []AttemptRecord) int {
	for i := len(attempts) - 1; i >= 0; i-- {
		if attempts[i].StatusCode > 0 {
			return attempts[i].StatusCode
		}
	}
	return 0
}
