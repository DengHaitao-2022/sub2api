package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"go.uber.org/zap"
)

const (
	defaultBackfillInterval  = 30 * time.Second
	defaultBackfillBatchSize = 500
)

type BackfillRepository interface {
	BatchIndexWriter
	GetAuditIndexerOffset(ctx context.Context, filePath string) (int64, error)
	UpsertAuditIndexerOffset(ctx context.Context, filePath string, nextOffset int64, lastIndexedAt time.Time) error
	CountAuditIndexByFile(ctx context.Context, filePath string) (int64, error)
}

type BackfillScanner struct {
	cfg       config.GatewayAuditConfig
	repo      BackfillRepository
	interval  time.Duration
	batchSize int

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func NewBackfillScanner(cfg config.GatewayAuditConfig, repo BackfillRepository) *BackfillScanner {
	interval := durationFromMs(cfg.BackfillIntervalMs)
	if interval <= 0 {
		interval = defaultBackfillInterval
	}
	batchSize := cfg.BackfillBatchSize
	if batchSize <= 0 {
		batchSize = defaultBackfillBatchSize
	}
	return &BackfillScanner{
		cfg:       cfg,
		repo:      repo,
		interval:  interval,
		batchSize: batchSize,
		stopCh:    make(chan struct{}),
	}
}

func (s *BackfillScanner) Start() {
	if s == nil || s.repo == nil || !s.cfg.BackfillEnabled || !s.cfg.FileEnabled {
		return
	}
	s.wg.Add(1)
	go s.run()
}

func (s *BackfillScanner) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.wg.Wait()
}

func (s *BackfillScanner) run() {
	defer s.wg.Done()
	s.scanAndLog(context.Background())

	for {
		timer := time.NewTimer(s.interval)
		select {
		case <-timer.C:
			s.scanAndLog(context.Background())
		case <-s.stopCh:
			timer.Stop()
			return
		}
	}
}

func (s *BackfillScanner) scanAndLog(ctx context.Context) {
	if err := s.ScanOnce(ctx); err != nil {
		logger.FromContext(ctx).Warn("gateway.audit.backfill_scan_failed", zap.Error(err))
	}
}

func (s *BackfillScanner) ScanOnce(ctx context.Context) error {
	if s == nil || s.repo == nil || !s.cfg.FileEnabled {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	files, err := listJSONLShards(s.cfg.FilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, path := range files {
		if err := s.scanFile(ctx, path); err != nil {
			return err
		}
	}
	return nil
}

func listJSONLShards(path string) ([]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	prefix, suffix := jsonlShardNameParts(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entries)+1)
	seen := make(map[string]struct{}, len(entries)+1)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if _, ok := jsonlShardDate(name, prefix, suffix); ok {
			full := filepath.Join(dir, name)
			files = append(files, full)
			seen[full] = struct{}{}
		}
	}
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		if _, ok := seen[path]; !ok {
			files = append(files, path)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func (s *BackfillScanner) scanFile(ctx context.Context, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.IsDir() {
		return nil
	}

	offset, err := s.repo.GetAuditIndexerOffset(ctx, path)
	if err != nil {
		return err
	}
	offset, err = s.normalizeStartOffset(ctx, path, offset, info.Size())
	if err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	reader := bufio.NewReader(f)
	nextOffset := offset
	committedOffset := offset
	lastIndexedAt := time.Time{}
	batch := make([]*IndexRecord, 0, s.batchSize)

	flush := func(forceOffset int64) error {
		indexed := len(batch)
		if indexed > 0 {
			if err := s.repo.BatchInsertAuditIndex(ctx, batch); err != nil {
				return err
			}
			metrics.backfillIndexedTotal.Add(int64(indexed))
			logger.WriteSinkEvent("info", "gateway.audit", MetricAuditBackfillIndexedTotal, map[string]any{
				"file_path": path,
				"count":     indexed,
			})
			for i := range batch {
				batch[i] = nil
			}
			batch = batch[:0]
		}
		if forceOffset != committedOffset {
			if err := s.repo.UpsertAuditIndexerOffset(ctx, path, forceOffset, lastIndexedAt); err != nil {
				return err
			}
			committedOffset = forceOffset
		}
		return nil
	}

	for {
		lineStart := nextOffset
		raw, readErr := reader.ReadBytes('\n')
		if len(raw) > 0 {
			if readErr == io.EOF && !bytes.HasSuffix(raw, []byte{'\n'}) {
				break
			}
			nextOffset += int64(len(raw))
			line := bytes.TrimSpace(raw)
			if len(line) > 0 {
				var event Event
				if err := json.Unmarshal(line, &event); err != nil {
					logger.FromContext(ctx).Warn("gateway.audit.backfill_parse_failed",
						zap.Error(err),
						zap.String("file_path", path),
						zap.Int64("file_offset", lineStart),
					)
				} else {
					if event.Timestamp.After(lastIndexedAt) {
						lastIndexedAt = event.Timestamp
					}
					batch = append(batch, buildIndexRecord(s.cfg, &event, &JSONLWriteResult{
						FilePath:   path,
						FileOffset: lineStart,
						LineBytes:  int64(len(raw)),
					}))
					if len(batch) >= s.batchSize {
						if err := flush(nextOffset); err != nil {
							return err
						}
					}
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if err := flush(nextOffset); err != nil {
		return err
	}
	s.recordLag(info, committedOffset)
	return nil
}

func (s *BackfillScanner) normalizeStartOffset(ctx context.Context, path string, offset, fileSize int64) (int64, error) {
	if offset < 0 || offset > fileSize {
		return 0, nil
	}
	if offset == 0 || fileSize == 0 {
		return offset, nil
	}
	count, err := s.repo.CountAuditIndexByFile(ctx, path)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, nil
	}
	return offset, nil
}

func (s *BackfillScanner) recordLag(info os.FileInfo, committedOffset int64) {
	if info == nil || committedOffset >= info.Size() {
		metrics.backfillLagSeconds.Store(0)
		return
	}
	lag := int64(time.Since(info.ModTime()).Seconds())
	if lag < 0 {
		lag = 0
	}
	metrics.backfillLagSeconds.Store(lag)
	if lag > 0 {
		logger.WriteSinkEvent("info", "gateway.audit", MetricAuditBackfillLagSeconds, map[string]any{
			"lag_seconds": lag,
		})
	}
}
