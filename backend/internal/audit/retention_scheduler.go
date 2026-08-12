package audit

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"go.uber.org/zap"
)

const defaultRetentionCleanupInterval = time.Hour

type RetentionScheduler struct {
	cfg      config.GatewayAuditConfig
	cleaner  RetentionCleaner
	interval time.Duration

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func NewRetentionScheduler(cfg config.GatewayAuditConfig, cleaner RetentionCleaner) *RetentionScheduler {
	interval := time.Duration(cfg.RetentionCleanupIntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = defaultRetentionCleanupInterval
	}
	return &RetentionScheduler{
		cfg:      cfg,
		cleaner:  cleaner,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (s *RetentionScheduler) Start() {
	if s == nil || !s.cfg.Enabled || s.cfg.RetentionDays <= 0 {
		return
	}
	s.wg.Add(1)
	go s.run()
}

func (s *RetentionScheduler) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.wg.Wait()
}

func (s *RetentionScheduler) run() {
	defer s.wg.Done()
	s.cleanupAndLog(context.Background())

	for {
		timer := time.NewTimer(s.interval)
		select {
		case <-timer.C:
			s.cleanupAndLog(context.Background())
		case <-s.stopCh:
			timer.Stop()
			return
		}
	}
}

func (s *RetentionScheduler) cleanupAndLog(ctx context.Context) {
	if err := CleanupRetentionOnce(ctx, s.cfg, s.cleaner); err != nil {
		logger.FromContext(ctx).Warn("gateway.audit.retention_cleanup_failed", zap.Error(err))
	}
}

func CleanupRetentionOnce(ctx context.Context, cfg config.GatewayAuditConfig, cleaner RetentionCleaner) error {
	if !cfg.Enabled || cfg.RetentionDays <= 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cutoff := retentionCutoffDate(time.Now(), cfg.RetentionDays)
	if cfg.FileEnabled {
		if err := cleanupJSONL(cfg.FilePath, cutoff); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if cleaner != nil {
		if err := cleaner.CleanupAuditRetention(ctx, cutoff); err != nil {
			return err
		}
	}
	return nil
}
