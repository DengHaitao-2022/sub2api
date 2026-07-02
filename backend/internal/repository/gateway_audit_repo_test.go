package repository

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/audit"
)

func TestGatewayAuditRepositoryCleanupAuditRetention(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	cutoff := time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)
	repo := &gatewayAuditRepository{db: db}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM admin_audit_access_logs
WHERE created_at < $1
   OR audit_id IN (
     SELECT audit_id
     FROM gateway_audit_index
     WHERE created_at < $1
   )`)).
		WithArgs(cutoff).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM gateway_audit_index
WHERE created_at < $1`)).
		WithArgs(cutoff).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()

	if err := repo.CleanupAuditRetention(context.Background(), cutoff); err != nil {
		t.Fatalf("CleanupAuditRetention: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGatewayAuditRepositoryBatchInsertAuditIndex(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := &gatewayAuditRepository{db: db}
	mock.ExpectExec(`(?s)INSERT INTO gateway_audit_index \(.*\) VALUES \([^)]*\),\([^)]*\)\s+ON CONFLICT \(audit_id\) DO UPDATE SET`).
		WillReturnResult(sqlmock.NewResult(0, 2))

	err = repo.BatchInsertAuditIndex(context.Background(), []*audit.IndexRecord{
		{
			AuditID:     "aud_batch_repo_1",
			RequestID:   "req_1",
			APIKeyID:    10,
			StatusCode:  200,
			FilePath:    "/tmp/audit-2026-06-29.jsonl",
			FileOffset:  0,
			LineBytes:   100,
			CreatedAt:   time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC),
			CaptureMode: "preview/preview",
			Sampled:     true,
		},
		{
			AuditID:     "aud_batch_repo_2",
			RequestID:   "req_2",
			APIKeyID:    11,
			StatusCode:  500,
			ErrorType:   "upstream",
			FilePath:    "/tmp/audit-2026-06-29.jsonl",
			FileOffset:  100,
			LineBytes:   120,
			CreatedAt:   time.Date(2026, 6, 29, 10, 1, 0, 0, time.UTC),
			CaptureMode: "preview/preview",
			Sampled:     true,
		},
	})
	if err != nil {
		t.Fatalf("BatchInsertAuditIndex: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}

	if got := len(dedupeAuditIndexRecords([]*audit.IndexRecord{{AuditID: "x"}, {AuditID: " x "}})); got != 1 {
		t.Fatalf("dedupe records = %d, want 1", got)
	}
	if !strings.Contains(gatewayAuditIndexUpsertClause, "ON CONFLICT (audit_id) DO UPDATE") {
		t.Fatal("batch upsert clause must keep audit_id conflict update")
	}
}
