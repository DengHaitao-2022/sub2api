package audit

import "sync/atomic"

const (
	MetricAuditJSONLWriteFailedTotal = "audit_jsonl_write_failed_total"
	MetricAuditIndexQueueSize        = "audit_index_queue_size"
	MetricAuditIndexQueueFullTotal   = "audit_index_queue_full_total"
	MetricAuditIndexBatchFlushTotal  = "audit_index_batch_flush_total"
	MetricAuditIndexBatchFailedTotal = "audit_index_batch_failed_total"
	MetricAuditBackfillLagSeconds    = "audit_backfill_lag_seconds"
	MetricAuditBackfillIndexedTotal  = "audit_backfill_indexed_total"
)

type MetricsSnapshot struct {
	JSONLWriteFailedTotal int64
	IndexQueueSize        int64
	IndexQueueFullTotal   int64
	IndexBatchFlushTotal  int64
	IndexBatchFailedTotal int64
	BackfillLagSeconds    int64
	BackfillIndexedTotal  int64
}

var metrics auditMetrics

type auditMetrics struct {
	jsonlWriteFailedTotal atomic.Int64
	indexQueueSize        atomic.Int64
	indexQueueFullTotal   atomic.Int64
	indexBatchFlushTotal  atomic.Int64
	indexBatchFailedTotal atomic.Int64
	backfillLagSeconds    atomic.Int64
	backfillIndexedTotal  atomic.Int64
}

func SnapshotMetrics() MetricsSnapshot {
	return MetricsSnapshot{
		JSONLWriteFailedTotal: metrics.jsonlWriteFailedTotal.Load(),
		IndexQueueSize:        metrics.indexQueueSize.Load(),
		IndexQueueFullTotal:   metrics.indexQueueFullTotal.Load(),
		IndexBatchFlushTotal:  metrics.indexBatchFlushTotal.Load(),
		IndexBatchFailedTotal: metrics.indexBatchFailedTotal.Load(),
		BackfillLagSeconds:    metrics.backfillLagSeconds.Load(),
		BackfillIndexedTotal:  metrics.backfillIndexedTotal.Load(),
	}
}

func resetMetricsForTest() {
	metrics.jsonlWriteFailedTotal.Store(0)
	metrics.indexQueueSize.Store(0)
	metrics.indexQueueFullTotal.Store(0)
	metrics.indexBatchFlushTotal.Store(0)
	metrics.indexBatchFailedTotal.Store(0)
	metrics.backfillLagSeconds.Store(0)
	metrics.backfillIndexedTotal.Store(0)
}
