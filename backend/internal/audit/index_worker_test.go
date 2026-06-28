package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestIndexWorkerRetriesDBFailure(t *testing.T) {
	resetMetricsForTest()
	dispatcher := NewDispatcherWithWait(4, 0)
	writer := &retryBatchWriter{
		failuresBeforeSuccess: 2,
		successCh:             make(chan struct{}, 1),
	}
	worker := NewIndexWorkerPoolWithOptions(dispatcher, writer, IndexWorkerOptions{
		WorkerCount:    1,
		BatchSize:      1,
		FlushInterval:  10 * time.Millisecond,
		WriteTimeout:   100 * time.Millisecond,
		RetryBaseDelay: time.Millisecond,
		MaxAttempts:    4,
	})
	worker.Start()
	defer worker.Stop()

	if ok := dispatcher.Enqueue(context.Background(), IndexJob{Record: &IndexRecord{AuditID: "aud_retry"}}); !ok {
		t.Fatal("enqueue failed")
	}

	select {
	case <-writer.successCh:
	case <-time.After(time.Second):
		t.Fatal("worker did not retry to success")
	}
	if got := writer.Attempts(); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
	if got := SnapshotMetrics().IndexBatchFlushTotal; got != 1 {
		t.Fatalf("flush metric = %d, want 1", got)
	}
}

func TestIndexWorkerBatchUpsertSuccess(t *testing.T) {
	resetMetricsForTest()
	dispatcher := NewDispatcherWithWait(8, 0)
	writer := &retryBatchWriter{successCh: make(chan struct{}, 1)}
	worker := NewIndexWorkerPoolWithOptions(dispatcher, writer, IndexWorkerOptions{
		WorkerCount:    1,
		BatchSize:      3,
		FlushInterval:  time.Second,
		WriteTimeout:   100 * time.Millisecond,
		RetryBaseDelay: time.Millisecond,
		MaxAttempts:    2,
	})
	worker.Start()
	defer worker.Stop()

	for _, id := range []string{"aud_batch_1", "aud_batch_2", "aud_batch_3"} {
		if ok := dispatcher.Enqueue(context.Background(), IndexJob{Record: &IndexRecord{AuditID: id}}); !ok {
			t.Fatalf("enqueue %s failed", id)
		}
	}

	select {
	case <-writer.successCh:
	case <-time.After(time.Second):
		t.Fatal("worker did not flush batch")
	}
	batches := writer.Batches()
	if len(batches) != 1 {
		t.Fatalf("batch count = %d, want 1", len(batches))
	}
	if len(batches[0]) != 3 {
		t.Fatalf("batch size = %d, want 3", len(batches[0]))
	}
	if got := SnapshotMetrics().IndexBatchFlushTotal; got != 1 {
		t.Fatalf("flush metric = %d, want 1", got)
	}
}

type retryBatchWriter struct {
	mu                    sync.Mutex
	failuresBeforeSuccess int
	attempts              int
	batches               [][]*IndexRecord
	successCh             chan struct{}
}

func (w *retryBatchWriter) BatchInsertAuditIndex(_ context.Context, records []*IndexRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.attempts++
	if w.attempts <= w.failuresBeforeSuccess {
		return errors.New("db down")
	}
	cp := make([]*IndexRecord, len(records))
	copy(cp, records)
	w.batches = append(w.batches, cp)
	if w.successCh != nil {
		select {
		case w.successCh <- struct{}{}:
		default:
		}
	}
	return nil
}

func (w *retryBatchWriter) Attempts() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.attempts
}

func (w *retryBatchWriter) Batches() [][]*IndexRecord {
	w.mu.Lock()
	defer w.mu.Unlock()
	cp := make([][]*IndexRecord, len(w.batches))
	copy(cp, w.batches)
	return cp
}
