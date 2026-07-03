package audit

import (
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

type RuntimeRepository interface {
	BackfillRepository
	RetentionCleaner
	SyncIndexWriter
}

type Runtime struct {
	cfg config.GatewayAuditConfig

	indexWriter SyncIndexWriter
	dispatcher  *Dispatcher
	worker      *IndexWorkerPool
	backfill    *BackfillScanner
	retention   *RetentionScheduler

	startOnce sync.Once
	stopOnce  sync.Once
}

type RuntimeStatus struct {
	Started                         bool   `json:"started"`
	Enabled                         bool   `json:"enabled"`
	IndexEnabled                    bool   `json:"index_enabled"`
	IndexAsyncEnabled               bool   `json:"index_async_enabled"`
	DispatcherEnabled               bool   `json:"dispatcher_enabled"`
	WorkerEnabled                   bool   `json:"worker_enabled"`
	BackfillEnabled                 bool   `json:"backfill_enabled"`
	RetentionEnabled                bool   `json:"retention_enabled"`
	FilePath                        string `json:"file_path,omitempty"`
	WorkerCount                     int    `json:"worker_count"`
	QueueCapacity                   int    `json:"queue_capacity"`
	QueueSize                       int    `json:"queue_size"`
	BatchSize                       int    `json:"batch_size"`
	FlushIntervalMs                 int    `json:"flush_interval_ms"`
	WriteTimeoutMs                  int    `json:"write_timeout_ms"`
	BackfillIntervalMs              int    `json:"backfill_interval_ms"`
	BackfillBatchSize               int    `json:"backfill_batch_size"`
	RetentionCleanupIntervalMinutes int    `json:"retention_cleanup_interval_minutes"`
}

func NewRuntime(cfg config.GatewayAuditConfig, repo RuntimeRepository) *Runtime {
	rt := &Runtime{cfg: cfg}
	if repo == nil {
		return rt
	}
	rt.indexWriter = repo
	if !cfg.Enabled {
		return rt
	}
	if cfg.IndexEnabled && cfg.IndexAsyncEnabled {
		rt.dispatcher = NewDispatcher(cfg.IndexQueueSize)
		rt.worker = NewIndexWorkerPool(rt.dispatcher, repo, cfg)
	}
	if cfg.IndexEnabled && cfg.BackfillEnabled && cfg.FileEnabled {
		rt.backfill = NewBackfillScanner(cfg, repo)
	}
	rt.retention = NewRetentionScheduler(cfg, repo)
	return rt
}

func (r *Runtime) Start() {
	if r == nil {
		return
	}
	r.startOnce.Do(func() {
		SetIndexWriter(r.indexWriter)
		if r.dispatcher != nil {
			SetDispatcher(r.dispatcher)
		}
		if r.worker != nil {
			r.worker.Start()
		}
		if r.backfill != nil {
			r.backfill.Start()
		}
		if r.retention != nil {
			r.retention.Start()
		}
		SetRuntimeStatus(r.status(true))
	})
}

func (r *Runtime) Stop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		if r.backfill != nil {
			r.backfill.Stop()
		}
		if r.retention != nil {
			r.retention.Stop()
		}
		if r.worker != nil {
			r.worker.Stop()
		}
		if CurrentDispatcher() == r.dispatcher {
			SetDispatcher(nil)
		}
		SetIndexWriter(nil)
		SetRuntimeStatus(r.status(false))
	})
}

func (r *Runtime) status(started bool) RuntimeStatus {
	if r == nil {
		return RuntimeStatus{}
	}
	options := normalizeIndexWorkerOptions(IndexWorkerOptions{
		WorkerCount:   r.cfg.IndexWorkerCount,
		BatchSize:     r.cfg.IndexBatchSize,
		FlushInterval: durationFromMs(r.cfg.IndexFlushIntervalMs),
		WriteTimeout:  durationFromMs(r.cfg.IndexWriteTimeoutMs),
	})
	status := RuntimeStatus{
		Started:                         started,
		Enabled:                         r.cfg.Enabled,
		IndexEnabled:                    r.cfg.IndexEnabled,
		IndexAsyncEnabled:               r.cfg.IndexAsyncEnabled,
		DispatcherEnabled:               r.dispatcher != nil,
		WorkerEnabled:                   r.worker != nil,
		BackfillEnabled:                 r.backfill != nil && r.cfg.FileEnabled,
		RetentionEnabled:                r.retention != nil && r.cfg.RetentionDays > 0,
		FilePath:                        r.cfg.FilePath,
		WorkerCount:                     options.WorkerCount,
		BatchSize:                       options.BatchSize,
		FlushIntervalMs:                 int(options.FlushInterval / 1_000_000),
		WriteTimeoutMs:                  int(options.WriteTimeout / 1_000_000),
		BackfillIntervalMs:              r.cfg.BackfillIntervalMs,
		BackfillBatchSize:               r.cfg.BackfillBatchSize,
		RetentionCleanupIntervalMinutes: r.cfg.RetentionCleanupIntervalMinutes,
	}
	if r.dispatcher != nil {
		status.QueueCapacity = r.dispatcher.Cap()
		status.QueueSize = r.dispatcher.Len()
	}
	if r.backfill != nil {
		status.BackfillIntervalMs = int(r.backfill.interval / 1_000_000)
		status.BackfillBatchSize = r.backfill.batchSize
	}
	if r.retention != nil {
		status.RetentionCleanupIntervalMinutes = int(r.retention.interval / 60_000_000_000)
	}
	return status
}

var runtimeStatusState = struct {
	sync.RWMutex
	status RuntimeStatus
}{}

func SnapshotRuntimeStatus() RuntimeStatus {
	runtimeStatusState.RLock()
	defer runtimeStatusState.RUnlock()
	status := runtimeStatusState.status
	if dispatcher := CurrentDispatcher(); dispatcher != nil {
		status.QueueCapacity = dispatcher.Cap()
		status.QueueSize = dispatcher.Len()
	}
	return status
}

func SetRuntimeStatus(status RuntimeStatus) {
	runtimeStatusState.Lock()
	defer runtimeStatusState.Unlock()
	runtimeStatusState.status = status
}
