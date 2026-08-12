package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

func TestBackfillScannerContinuesFromOffsetAfterRestart(t *testing.T) {
	resetMetricsForTest()
	path := t.TempDir() + "/audit.jsonl"
	cfg := config.GatewayAuditConfig{
		FileEnabled:       true,
		FilePath:          path,
		InputCaptureMode:  "preview",
		OutputCaptureMode: "preview",
		BackfillBatchSize: 2,
	}
	repo := newMemoryBackfillRepo()

	first := mustWriteAuditEvent(t, path, "aud_restart_1", time.Date(2026, 6, 29, 10, 0, 0, 0, time.Local))
	second := mustWriteAuditEvent(t, path, "aud_restart_2", time.Date(2026, 6, 29, 10, 1, 0, 0, time.Local))
	scanner := NewBackfillScanner(cfg, repo)
	if err := scanner.ScanOnce(context.Background()); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if got := repo.CountByFile(first.FilePath); got != 2 {
		t.Fatalf("indexed after first scan = %d, want 2", got)
	}
	if got := repo.Offset(first.FilePath); got != first.LineBytes+second.LineBytes {
		t.Fatalf("offset after first scan = %d, want %d", got, first.LineBytes+second.LineBytes)
	}

	third := mustWriteAuditEvent(t, path, "aud_restart_3", time.Date(2026, 6, 29, 10, 2, 0, 0, time.Local))
	restarted := NewBackfillScanner(cfg, repo)
	if err := restarted.ScanOnce(context.Background()); err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if got := repo.CountByFile(third.FilePath); got != 3 {
		t.Fatalf("indexed after restart = %d, want 3", got)
	}
	if !repo.HasAuditID(third.FilePath, "aud_restart_3") {
		t.Fatal("third event was not indexed")
	}
	if got := SnapshotMetrics().BackfillIndexedTotal; got != 3 {
		t.Fatalf("backfill indexed metric = %d, want 3", got)
	}
}

func TestBackfillScannerRebuildsIndexWhenGatewayAuditIndexCleared(t *testing.T) {
	path := t.TempDir() + "/audit.jsonl"
	cfg := config.GatewayAuditConfig{
		FileEnabled:       true,
		FilePath:          path,
		InputCaptureMode:  "preview",
		OutputCaptureMode: "preview",
		BackfillBatchSize: 10,
	}
	repo := newMemoryBackfillRepo()

	first := mustWriteAuditEvent(t, path, "aud_rebuild_1", time.Date(2026, 6, 29, 11, 0, 0, 0, time.Local))
	mustWriteAuditEvent(t, path, "aud_rebuild_2", time.Date(2026, 6, 29, 11, 1, 0, 0, time.Local))
	scanner := NewBackfillScanner(cfg, repo)
	if err := scanner.ScanOnce(context.Background()); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if got := repo.CountByFile(first.FilePath); got != 2 {
		t.Fatalf("indexed before clear = %d, want 2", got)
	}

	repo.ClearIndex()
	if got := repo.Offset(first.FilePath); got == 0 {
		t.Fatal("test setup expected offset to remain after clearing index")
	}
	if err := scanner.ScanOnce(context.Background()); err != nil {
		t.Fatalf("rebuild scan: %v", err)
	}
	if got := repo.CountByFile(first.FilePath); got != 2 {
		t.Fatalf("indexed after rebuild = %d, want 2", got)
	}
	if !repo.HasAuditID(first.FilePath, "aud_rebuild_1") || !repo.HasAuditID(first.FilePath, "aud_rebuild_2") {
		t.Fatal("rebuild did not restore all audit ids")
	}
}

func mustWriteAuditEvent(t *testing.T, path, auditID string, ts time.Time) *JSONLWriteResult {
	t.Helper()
	result, err := writeJSONL(path, &Event{
		Timestamp:  ts,
		Event:      eventGatewayRequestCompleted,
		AuditID:    auditID,
		RequestID:  "req_" + auditID,
		StatusCode: 200,
	})
	if err != nil {
		t.Fatalf("writeJSONL %s: %v", auditID, err)
	}
	return result
}

type memoryBackfillRepo struct {
	mu      sync.Mutex
	offsets map[string]int64
	records map[string]map[string]*IndexRecord
}

func newMemoryBackfillRepo() *memoryBackfillRepo {
	return &memoryBackfillRepo{
		offsets: make(map[string]int64),
		records: make(map[string]map[string]*IndexRecord),
	}
}

func (r *memoryBackfillRepo) BatchInsertAuditIndex(_ context.Context, records []*IndexRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, record := range records {
		if record == nil || record.AuditID == "" {
			continue
		}
		if r.records[record.FilePath] == nil {
			r.records[record.FilePath] = make(map[string]*IndexRecord)
		}
		cp := *record
		r.records[record.FilePath][record.AuditID] = &cp
	}
	return nil
}

func (r *memoryBackfillRepo) GetAuditIndexerOffset(_ context.Context, filePath string) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.offsets[filePath], nil
}

func (r *memoryBackfillRepo) UpsertAuditIndexerOffset(_ context.Context, filePath string, nextOffset int64, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.offsets[filePath] = nextOffset
	return nil
}

func (r *memoryBackfillRepo) CountAuditIndexByFile(_ context.Context, filePath string) (int64, error) {
	return int64(r.CountByFile(filePath)), nil
}

func (r *memoryBackfillRepo) CountByFile(filePath string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records[filePath])
}

func (r *memoryBackfillRepo) Offset(filePath string) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.offsets[filePath]
}

func (r *memoryBackfillRepo) HasAuditID(filePath, auditID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.records[filePath][auditID]
	return ok
}

func (r *memoryBackfillRepo) ClearIndex() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = make(map[string]map[string]*IndexRecord)
}
