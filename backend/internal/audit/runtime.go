package audit

import (
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

type RuntimeRepository interface {
	BackfillRepository
	RetentionCleaner
}

type Runtime struct {
	cfg config.GatewayAuditConfig

	dispatcher *Dispatcher
	worker     *IndexWorkerPool
	backfill   *BackfillScanner
	retention  *RetentionScheduler

	startOnce sync.Once
	stopOnce  sync.Once
}

func NewRuntime(cfg config.GatewayAuditConfig, repo RuntimeRepository) *Runtime {
	rt := &Runtime{cfg: cfg}
	if repo == nil {
		return rt
	}
	if cfg.IndexAsyncEnabled {
		rt.dispatcher = NewDispatcher(cfg.IndexQueueSize)
		rt.worker = NewIndexWorkerPool(rt.dispatcher, repo, cfg)
	}
	if cfg.BackfillEnabled {
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
	})
}
