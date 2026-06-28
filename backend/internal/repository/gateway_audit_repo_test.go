package repository

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
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
