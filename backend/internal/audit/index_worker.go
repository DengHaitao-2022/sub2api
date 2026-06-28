package audit

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"go.uber.org/zap"
)

const (
	defaultIndexWorkerCount    = 2
	defaultIndexBatchSize      = 200
	defaultIndexFlushInterval  = 200 * time.Millisecond
	defaultIndexWriteTimeout   = 2 * time.Second
	defaultIndexRetryBaseDelay = 50 * time.Millisecond
	defaultIndexMaxAttempts    = 4
)

type BatchIndexWriter interface {
	BatchInsertAuditIndex(ctx context.Context, records []*IndexRecord) error
}

type IndexWorkerOptions struct {
	WorkerCount    int
	BatchSize      int
	FlushInterval  time.Duration
	WriteTimeout   time.Duration
	RetryBaseDelay time.Duration
	MaxAttempts    int
}

type IndexWorkerPool struct {
	dispatcher *Dispatcher
	writer     BatchIndexWriter
	options    IndexWorkerOptions

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func NewIndexWorkerPool(dispatcher *Dispatcher, writer BatchIndexWriter, cfg config.GatewayAuditConfig) *IndexWorkerPool {
	return NewIndexWorkerPoolWithOptions(dispatcher, writer, IndexWorkerOptions{
		WorkerCount:   cfg.IndexWorkerCount,
		BatchSize:     cfg.IndexBatchSize,
		FlushInterval: durationFromMs(cfg.IndexFlushIntervalMs),
		WriteTimeout:  durationFromMs(cfg.IndexWriteTimeoutMs),
	})
}

func NewIndexWorkerPoolWithOptions(dispatcher *Dispatcher, writer BatchIndexWriter, options IndexWorkerOptions) *IndexWorkerPool {
	options = normalizeIndexWorkerOptions(options)
	return &IndexWorkerPool{
		dispatcher: dispatcher,
		writer:     writer,
		options:    options,
		stopCh:     make(chan struct{}),
	}
}

func normalizeIndexWorkerOptions(options IndexWorkerOptions) IndexWorkerOptions {
	if options.WorkerCount <= 0 {
		options.WorkerCount = defaultIndexWorkerCount
	}
	if options.BatchSize <= 0 {
		options.BatchSize = defaultIndexBatchSize
	}
	if options.FlushInterval <= 0 {
		options.FlushInterval = defaultIndexFlushInterval
	}
	if options.WriteTimeout <= 0 {
		options.WriteTimeout = defaultIndexWriteTimeout
	}
	if options.RetryBaseDelay <= 0 {
		options.RetryBaseDelay = defaultIndexRetryBaseDelay
	}
	if options.MaxAttempts <= 0 {
		options.MaxAttempts = defaultIndexMaxAttempts
	}
	return options
}

func durationFromMs(ms int) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func (p *IndexWorkerPool) Start() {
	if p == nil || p.dispatcher == nil || p.writer == nil {
		return
	}
	jobs := p.dispatcher.Jobs()
	if jobs == nil {
		return
	}
	for i := 0; i < p.options.WorkerCount; i++ {
		p.wg.Add(1)
		go p.runWorker(i, jobs)
	}
}

func (p *IndexWorkerPool) Stop() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})
	p.wg.Wait()
}

func (p *IndexWorkerPool) runWorker(workerID int, jobs <-chan IndexJob) {
	defer p.wg.Done()

	batch := make([]*IndexRecord, 0, p.options.BatchSize)
	timer := time.NewTimer(p.options.FlushInterval)
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		p.flushBatch(workerID, batch)
		for i := range batch {
			batch[i] = nil
		}
		batch = batch[:0]
	}

	for {
		select {
		case job := <-jobs:
			metrics.indexQueueSize.Store(int64(p.dispatcher.Len()))
			if record := normalizeIndexJob(job); record != nil {
				batch = append(batch, record)
				if len(batch) >= p.options.BatchSize {
					flush()
					resetTimer(timer, p.options.FlushInterval)
				}
			}
		case <-timer.C:
			flush()
			resetTimer(timer, p.options.FlushInterval)
		case <-p.stopCh:
			p.drainAvailable(jobs, &batch)
			flush()
			return
		}
	}
}

func (p *IndexWorkerPool) drainAvailable(jobs <-chan IndexJob, batch *[]*IndexRecord) {
	for {
		select {
		case job := <-jobs:
			if record := normalizeIndexJob(job); record != nil {
				*batch = append(*batch, record)
				if len(*batch) >= p.options.BatchSize {
					p.flushBatch(-1, *batch)
					for i := range *batch {
						(*batch)[i] = nil
					}
					*batch = (*batch)[:0]
				}
			}
		default:
			if p.dispatcher != nil {
				metrics.indexQueueSize.Store(int64(p.dispatcher.Len()))
			}
			return
		}
	}
}

func normalizeIndexJob(job IndexJob) *IndexRecord {
	if job.Record == nil || strings.TrimSpace(job.Record.AuditID) == "" {
		return nil
	}
	return job.Record
}

func resetTimer(timer *time.Timer, interval time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(interval)
}

func (p *IndexWorkerPool) flushBatch(workerID int, records []*IndexRecord) {
	records = compactIndexRecords(records)
	if len(records) == 0 {
		return
	}

	var lastErr error
	for attempt := 1; attempt <= p.options.MaxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), p.options.WriteTimeout)
		err := p.writer.BatchInsertAuditIndex(ctx, records)
		cancel()
		if err == nil {
			metrics.indexBatchFlushTotal.Add(1)
			logger.WriteSinkEvent("info", "gateway.audit", MetricAuditIndexBatchFlushTotal, map[string]any{
				"worker_id":  workerID,
				"batch_size": len(records),
				"attempt":    attempt,
			})
			return
		}
		lastErr = err
		if attempt < p.options.MaxAttempts {
			time.Sleep(p.options.RetryBaseDelay * time.Duration(1<<(attempt-1)))
		}
	}

	metrics.indexBatchFailedTotal.Add(1)
	logger.L().Warn("gateway.audit.index_batch_failed",
		zap.Error(lastErr),
		zap.Int("worker_id", workerID),
		zap.Int("batch_size", len(records)),
		zap.Int("attempts", p.options.MaxAttempts),
	)
	logger.WriteSinkEvent("warn", "gateway.audit", MetricAuditIndexBatchFailedTotal, map[string]any{
		"worker_id":  workerID,
		"batch_size": len(records),
		"attempts":   p.options.MaxAttempts,
		"error":      errorString(lastErr),
	})
}

func compactIndexRecords(records []*IndexRecord) []*IndexRecord {
	out := records[:0]
	for _, record := range records {
		if record == nil || strings.TrimSpace(record.AuditID) == "" {
			continue
		}
		out = append(out, record)
	}
	return out
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
