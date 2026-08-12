package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

func (r *gatewayAuditRepository) GetAuditIndexerOffset(ctx context.Context, filePath string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, fmt.Errorf("nil gateway audit repository")
	}
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return 0, nil
	}
	var offset int64
	err := r.db.QueryRowContext(ctx, `
SELECT next_offset
FROM gateway_audit_indexer_offsets
WHERE file_path = $1`, filePath).Scan(&offset)
	if err == nil {
		if offset < 0 {
			return 0, nil
		}
		return offset, nil
	}
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return 0, err
}

func (r *gatewayAuditRepository) UpsertAuditIndexerOffset(ctx context.Context, filePath string, nextOffset int64, lastIndexedAt time.Time) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("nil gateway audit repository")
	}
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return nil
	}
	if nextOffset < 0 {
		nextOffset = 0
	}
	_, err := r.db.ExecContext(ctx, `
INSERT INTO gateway_audit_indexer_offsets (file_path, next_offset, updated_at, last_indexed_at)
VALUES ($1, $2, NOW(), $3)
ON CONFLICT (file_path) DO UPDATE SET
  next_offset = EXCLUDED.next_offset,
  updated_at = NOW(),
  last_indexed_at = COALESCE(EXCLUDED.last_indexed_at, gateway_audit_indexer_offsets.last_indexed_at)`,
		filePath,
		nextOffset,
		auditNullTime(lastIndexedAt),
	)
	return err
}

func (r *gatewayAuditRepository) CountAuditIndexByFile(ctx context.Context, filePath string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, fmt.Errorf("nil gateway audit repository")
	}
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return 0, nil
	}
	var count int64
	if err := r.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM gateway_audit_index
WHERE file_path = $1`, filePath).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func auditNullTime(value time.Time) sql.NullTime {
	return sql.NullTime{Time: value, Valid: !value.IsZero()}
}
