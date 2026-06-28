package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

func TestCleanupJSONLDeletesExpiredDateShardsOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	oldPath := filepath.Join(dir, "audit-2026-01-01.jsonl")
	freshPath := filepath.Join(dir, "audit-2026-01-04.jsonl")
	legacyPath := filepath.Join(dir, "audit.jsonl")
	for _, item := range []struct {
		path string
		body string
	}{
		{oldPath, `{"request_id":"old"}` + "\n"},
		{freshPath, `{"request_id":"fresh"}` + "\n"},
		{legacyPath, `{"request_id":"legacy"}` + "\n"},
	} {
		if err := os.WriteFile(item.path, []byte(item.body), 0o640); err != nil {
			t.Fatal(err)
		}
	}

	cutoff := time.Date(2026, 1, 3, 0, 0, 0, 0, time.Local)
	if err := cleanupJSONL(path, cutoff); err != nil {
		t.Fatalf("cleanupJSONL: %v", err)
	}

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("old shard should be deleted, stat err=%v", err)
	}
	for _, keep := range []string{freshPath, legacyPath} {
		if _, err := os.Stat(keep); err != nil {
			t.Fatalf("expected %s to remain: %v", keep, err)
		}
	}
}

func TestWriteEventIndexesJSONLLocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writer := &recordingIndexWriter{}
	SetIndexWriter(writer)
	defer SetIndexWriter(nil)

	event := &Event{
		Timestamp:  time.Date(2026, 6, 29, 12, 0, 0, 0, time.Local),
		Event:      eventGatewayRequestCompleted,
		AuditID:    "aud_test",
		RequestID:  "req_test",
		APIKeyID:   42,
		StatusCode: 200,
		Input:      &BodyRecord{SHA256: "in", SizeBytes: 12},
		Output:     &BodyRecord{SHA256: "out", SizeBytes: 34, Truncated: true},
	}
	cfg := config.GatewayAuditConfig{
		FileEnabled:       true,
		FilePath:          path,
		OpsIndexEnabled:   false,
		InputCaptureMode:  "preview",
		OutputCaptureMode: "preview",
	}
	if err := WriteEvent(context.Background(), cfg, event); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	if writer.record == nil {
		t.Fatal("expected index record")
	}
	wantPath := filepath.Join(filepath.Dir(path), "audit-2026-06-29.jsonl")
	if writer.record.FilePath != wantPath || writer.record.FileOffset != 0 || writer.record.LineBytes <= 0 {
		t.Fatalf("bad jsonl location: %#v", writer.record)
	}
	if writer.record.AuditID != "aud_test" || writer.record.RequestID != "req_test" || writer.record.OutputTruncated != true {
		t.Fatalf("bad index metadata: %#v", writer.record)
	}
}

func TestWriteJSONLDateShardPreservesOffsets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	first := &Event{
		Timestamp: time.Date(2026, 6, 29, 9, 0, 0, 0, time.Local),
		Event:     eventGatewayRequestCompleted,
		AuditID:   "aud_first",
		RequestID: "req_first",
	}
	second := &Event{
		Timestamp: time.Date(2026, 6, 29, 10, 0, 0, 0, time.Local),
		Event:     eventGatewayRequestCompleted,
		AuditID:   "aud_second",
		RequestID: "req_second",
	}

	firstResult, err := writeJSONL(path, 0, first)
	if err != nil {
		t.Fatalf("write first: %v", err)
	}
	secondResult, err := writeJSONL(path, 0, second)
	if err != nil {
		t.Fatalf("write second: %v", err)
	}

	if firstResult.FilePath != secondResult.FilePath {
		t.Fatalf("expected same date shard, got %q and %q", firstResult.FilePath, secondResult.FilePath)
	}
	if secondResult.FileOffset != firstResult.LineBytes {
		t.Fatalf("second offset = %d, want first line bytes %d", secondResult.FileOffset, firstResult.LineBytes)
	}
	raw, err := os.ReadFile(firstResult.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), "\n"); got != 2 {
		t.Fatalf("line count = %d, raw=%s", got, string(raw))
	}
}

func TestBuildIndexRecordCapturesAttemptSummary(t *testing.T) {
	event := &Event{
		Timestamp: time.Date(2026, 6, 29, 11, 0, 0, 0, time.Local),
		Event:     eventGatewayRequestCompleted,
		AuditID:   "aud_attempts",
		Attempts: []AttemptRecord{
			{Attempt: 1, StatusCode: 503, Result: "failover"},
			{Attempt: 2, StatusCode: 200, Result: "completed"},
		},
	}

	record := buildIndexRecord(config.GatewayAuditConfig{}, event, nil)
	if record.AttemptCount != 2 {
		t.Fatalf("attempt_count = %d, want 2", record.AttemptCount)
	}
	if !record.HasFailover {
		t.Fatal("expected has_failover")
	}
	if record.FirstUpstreamStatusCode != 503 || record.FinalUpstreamStatusCode != 200 {
		t.Fatalf("bad upstream statuses: first=%d final=%d", record.FirstUpstreamStatusCode, record.FinalUpstreamStatusCode)
	}
}

type recordingIndexWriter struct {
	record *IndexRecord
}

func (w *recordingIndexWriter) InsertAuditIndex(_ context.Context, record *IndexRecord) error {
	w.record = record
	return nil
}
