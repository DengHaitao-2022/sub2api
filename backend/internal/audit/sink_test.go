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

func TestCleanupJSONLRemovesExpiredEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	old := `{"ts":"2026-01-01T00:00:00Z","event":"gateway.request.completed","request_id":"old"}`
	fresh := `{"ts":"2026-01-04T00:00:00Z","event":"gateway.request.completed","request_id":"fresh"}`
	invalid := `not-json`
	if err := os.WriteFile(path, []byte(old+"\n"+fresh+"\n"+invalid+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	cutoff := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	if err := cleanupJSONL(path, cutoff); err != nil {
		t.Fatalf("cleanupJSONL: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	if strings.Contains(out, `"request_id":"old"`) {
		t.Fatalf("old event was not removed: %s", out)
	}
	if !strings.Contains(out, `"request_id":"fresh"`) {
		t.Fatalf("fresh event was removed: %s", out)
	}
	if !strings.Contains(out, invalid) {
		t.Fatalf("invalid legacy line should be retained: %s", out)
	}
}

func TestWriteEventIndexesJSONLLocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writer := &recordingIndexWriter{}
	SetIndexWriter(writer)
	defer SetIndexWriter(nil)

	event := &Event{
		Timestamp:  time.Now(),
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
	if writer.record.FilePath != path || writer.record.FileOffset != 0 || writer.record.LineBytes <= 0 {
		t.Fatalf("bad jsonl location: %#v", writer.record)
	}
	if writer.record.AuditID != "aud_test" || writer.record.RequestID != "req_test" || writer.record.OutputTruncated != true {
		t.Fatalf("bad index metadata: %#v", writer.record)
	}
}

type recordingIndexWriter struct {
	record *IndexRecord
}

func (w *recordingIndexWriter) InsertAuditIndex(_ context.Context, record *IndexRecord) error {
	w.record = record
	return nil
}
