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
	dispatcher := NewDispatcherWithWait(1, 0)
	SetDispatcher(dispatcher)
	defer SetDispatcher(nil)

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
		IndexAsyncEnabled: true,
	}
	result, err := WriteEvent(context.Background(), cfg, event)
	if err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	if result == nil {
		t.Fatal("expected JSONL result")
	}
	var record *IndexRecord
	select {
	case job := <-dispatcher.Jobs():
		record = job.Record
	default:
		t.Fatal("expected queued index job")
	}
	wantPath := filepath.Join(filepath.Dir(path), "audit-2026-06-29.jsonl")
	if record.FilePath != wantPath || record.FileOffset != 0 || record.LineBytes <= 0 {
		t.Fatalf("bad jsonl location: %#v", record)
	}
	if record.AuditID != "aud_test" || record.RequestID != "req_test" || record.OutputTruncated != true {
		t.Fatalf("bad index metadata: %#v", record)
	}
}

func TestWriteEventQueueFullDoesNotFailJSONLWrite(t *testing.T) {
	resetMetricsForTest()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	dispatcher := NewDispatcherWithWait(1, 0)
	SetDispatcher(dispatcher)
	defer SetDispatcher(nil)

	if ok := dispatcher.Enqueue(context.Background(), IndexJob{Record: &IndexRecord{AuditID: "queued"}}); !ok {
		t.Fatal("test setup should fill queue")
	}

	event := &Event{
		Timestamp: time.Date(2026, 6, 29, 13, 0, 0, 0, time.Local),
		Event:     eventGatewayRequestCompleted,
		AuditID:   "aud_queue_full",
		RequestID: "req_queue_full",
	}
	cfg := config.GatewayAuditConfig{
		FileEnabled:       true,
		FilePath:          path,
		OpsIndexEnabled:   false,
		InputCaptureMode:  "preview",
		OutputCaptureMode: "preview",
		IndexAsyncEnabled: true,
	}

	result, err := WriteEvent(context.Background(), cfg, event)
	if err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	if result == nil || result.LineBytes <= 0 {
		t.Fatalf("expected JSONL result, got %#v", result)
	}
	wantPath := filepath.Join(filepath.Dir(path), "audit-2026-06-29.jsonl")
	raw, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read audit jsonl: %v", err)
	}
	if !strings.Contains(string(raw), `"audit_id":"aud_queue_full"`) {
		t.Fatalf("expected JSONL to contain audit event, raw=%s", string(raw))
	}
	if got := SnapshotMetrics().IndexQueueFullTotal; got != 1 {
		t.Fatalf("queue full metric = %d, want 1", got)
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

	firstResult, err := writeJSONL(path, first)
	if err != nil {
		t.Fatalf("write first: %v", err)
	}
	secondResult, err := writeJSONL(path, second)
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
