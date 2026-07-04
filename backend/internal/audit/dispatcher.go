package audit

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"go.uber.org/zap"
)

const defaultIndexEnqueueWait = 5 * time.Millisecond

type IndexJob struct {
	Record *IndexRecord
}

type Dispatcher struct {
	jobs        chan IndexJob
	enqueueWait time.Duration
}

func NewDispatcher(queueSize int) *Dispatcher {
	return NewDispatcherWithWait(queueSize, defaultIndexEnqueueWait)
}

func NewDispatcherWithWait(queueSize int, enqueueWait time.Duration) *Dispatcher {
	if queueSize <= 0 {
		queueSize = 1
	}
	return &Dispatcher{
		jobs:        make(chan IndexJob, queueSize),
		enqueueWait: enqueueWait,
	}
}

func (d *Dispatcher) Enqueue(ctx context.Context, job IndexJob) bool {
	if d == nil || d.jobs == nil || job.Record == nil || strings.TrimSpace(job.Record.AuditID) == "" {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if d.enqueueWait <= 0 {
		select {
		case d.jobs <- job:
			metrics.indexQueueSize.Store(int64(len(d.jobs)))
			return true
		default:
			d.recordQueueFull(ctx, job)
			return false
		}
	}

	timer := time.NewTimer(d.enqueueWait)
	defer timer.Stop()
	select {
	case d.jobs <- job:
		metrics.indexQueueSize.Store(int64(len(d.jobs)))
		return true
	case <-timer.C:
		d.recordQueueFull(ctx, job)
		return false
	}
}

func (d *Dispatcher) Jobs() <-chan IndexJob {
	if d == nil {
		return nil
	}
	return d.jobs
}

func (d *Dispatcher) Len() int {
	if d == nil || d.jobs == nil {
		return 0
	}
	return len(d.jobs)
}

func (d *Dispatcher) Cap() int {
	if d == nil || d.jobs == nil {
		return 0
	}
	return cap(d.jobs)
}

func (d *Dispatcher) recordQueueFull(ctx context.Context, job IndexJob) {
	metrics.indexQueueSize.Store(int64(d.Len()))
	metrics.indexQueueFullTotal.Add(1)
	logger.FromContext(ctx).Warn("gateway.audit.index_queue_full",
		zap.String("audit_id", job.Record.AuditID),
		zap.String("file_path", job.Record.FilePath),
		zap.Int64("file_offset", job.Record.FileOffset),
		zap.Int("queue_size", d.Len()),
		zap.Int("queue_capacity", d.Cap()),
	)
	logger.WriteSinkEvent("warn", "gateway.audit", MetricAuditIndexQueueFullTotal, map[string]any{
		"audit_id":                job.Record.AuditID,
		"file_path":               job.Record.FilePath,
		"file_offset":             job.Record.FileOffset,
		MetricAuditIndexQueueSize: d.Len(),
		"queue_capacity":          d.Cap(),
	})
}

var dispatcherState = struct {
	sync.RWMutex
	dispatcher *Dispatcher
}{}

func CurrentDispatcher() *Dispatcher {
	dispatcherState.RLock()
	defer dispatcherState.RUnlock()
	return dispatcherState.dispatcher
}

func SetDispatcher(dispatcher *Dispatcher) {
	dispatcherState.Lock()
	defer dispatcherState.Unlock()
	dispatcherState.dispatcher = dispatcher
}
